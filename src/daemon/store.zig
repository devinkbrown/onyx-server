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
    ReadOnlyStore,
    InvalidTablePlan,
    TableWorkExceeded,
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
    compaction_boundary: enum { none, after_snapshot_replace, after_snapshot_dir_sync, after_wal_replace, after_wal_dir_sync } = .none,

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

/// The authenticated Helix manifest binds a Windows WAL HANDLE to its exact
/// disk object and replay cut. FileIdInfo retains the full 128-bit file ID;
/// std.Io.File.Stat.inode alone is insufficient for this transfer.
pub const WindowsWalWitness = struct {
    file: WindowsFileIdInfo,
    parent_directory: WindowsFileIdInfo,
    name_digest: [std.crypto.hash.Blake3.digest_length]u8,
    length: u64,
};

pub const WindowsWalDescriptor = struct {
    handle: usize,
    destination_pid: u32,
    witness: WindowsWalWitness,

    /// Called by the receiving process if staging fails or is aborted. A
    /// descriptor in a different PID's handle table is never closed here.
    pub fn deinitReceived(self: *WindowsWalDescriptor) void {
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.handle != 0 and self.destination_pid == GetCurrentProcessId())
                _ = CloseHandle(self.handle);
        }
        self.handle = 0;
    }
};

/// Parent-side rollback custody until a descriptor has been sent on the
/// authenticated control channel. `release` transfers close responsibility to
/// the child; aborting earlier closes the duplicate in that process.
pub const WindowsWalTransfer = struct {
    target_process: usize,
    descriptor: WindowsWalDescriptor,

    pub fn deinit(self: *WindowsWalTransfer) void {
        if (comptime @import("builtin").os.tag == .windows) {
            if (self.descriptor.handle != 0) {
                var local: usize = 0;
                if (DuplicateHandle(self.target_process, self.descriptor.handle, GetCurrentProcess(), &local, 0, 0, windows_duplicate_same_access | windows_duplicate_close_source) != 0 and local != 0)
                    _ = CloseHandle(local);
            }
        }
        self.descriptor.handle = 0;
    }

    pub fn release(self: *WindowsWalTransfer) WindowsWalDescriptor {
        const descriptor = self.descriptor;
        self.descriptor.handle = 0;
        return descriptor;
    }
};

pub const WindowsFileIdInfo = extern struct {
    volume_serial: u64,
    file_id: [16]u8,
};
comptime {
    if (@sizeOf(WindowsFileIdInfo) != 24) @compileError("Windows FILE_ID_INFO ABI mismatch");
}
const windows_file_id_info_class: i32 = 18;
const windows_duplicate_same_access: u32 = 2;
const windows_duplicate_close_source: u32 = 1;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn CreateHardLinkW(new_name: [*:0]const u16, existing_name: [*:0]const u16, security: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetProcessId(process: usize) callconv(.winapi) u32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn SetFileInformationByHandle(handle: usize, class: i32, info: *const anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn GetVolumeInformationByHandleW(handle: usize, volume_name: ?[*]u16, volume_name_len: u32, serial: ?*u32, max_component: ?*u32, flags: ?*u32, fs_name: ?[*]u16, fs_name_len: u32) callconv(.winapi) i32;

fn windowsFileIdentity(handle: usize) !WindowsFileIdInfo {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    var info: WindowsFileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, windows_file_id_info_class, &info, @sizeOf(WindowsFileIdInfo)) == 0)
        return StoreError.SnapshotCoverageMismatch;
    return info;
}

fn windowsColdAtomicIdentity(handle: std.Io.File.Handle) !cold_identity.Identity {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    // Zig's initial Atomic handle is GENERIC_WRITE. FileIdInfo remains
    // queryable even when FileAttributeTagInfo is denied on that handle.
    const id = try windowsFileIdentity(@intFromPtr(handle));
    return .{
        .device = id.volume_serial,
        .inode = std.mem.readInt(u64, id.file_id[0..8], .little),
        .inode_high = std.mem.readInt(u64, id.file_id[8..16], .little),
    };
}

fn windowsWalWitness(io: std.Io, file: std.Io.File, dir: std.Io.Dir, name: []const u8) !WindowsWalWitness {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    const stat = try file.stat(io);
    if (stat.kind != .file) return StoreError.SnapshotCoverageMismatch;
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(name, &digest, .{});
    return .{
        .file = try windowsFileIdentity(@intFromPtr(file.handle)),
        .parent_directory = try windowsFileIdentity(@intFromPtr(dir.handle)),
        .name_digest = digest,
        .length = stat.size,
    };
}

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

const max_batch_mutations = 4;
const meta_kind_batch: u8 = 0xFB;
const meta_kind_batch_format: u8 = 0xFA;
const batch_format_version: u8 = 1;
const batch_guard_len = record_header_len + 2;
// Four payload/feed retirements per row, one table backing per family, packet.
const prepared_retirement_capacity = max_batch_mutations * 5 + 1;

/// A bounded atomic mutation group. Keys within one family must be distinct.
/// Put values are mandatory; delete values must be absent.
pub const BatchMutation = struct {
    family: Family,
    kind: MutationKind,
    key: []const u8,
    value: ?[]const u8 = null,
};

const BatchEntry = struct {
    family: Family,
    kind: MutationKind,
    key: ?[]u8 = null,
    value: ?[]u8 = null,
    change: ?OwnedMutation = null,
    old_key: ?[]u8 = null,
    old_value: ?[]u8 = null,
};

const ActiveBatch = struct {
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

fn initRetirements() [prepared_retirement_capacity]?Retirement {
    var slots: [prepared_retirement_capacity]?Retirement = undefined;
    for (&slots) |*slot| slot.* = null;
    return slots;
}

const Retirement = union(enum) {
    bytes: []u8,
    mutation: OwnedMutation,
    table_slots: []KvTable.Slot,
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

    /// Install or clear the narrow prepared-write I/O seam. Production code
    /// leaves this at `.{};` tests use it to prove ambiguous short-write,
    /// failed-write, and sync boundaries poison the store.
    pub fn setPreparedIoFault(self: *OroStore, fault: PreparedIoFault) void {
        self.prepared_io_fault = fault;
    }

    /// True after a prepared write crossed an ambiguous write/sync boundary.
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
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        if (self.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const sequence = try self.reserveSequence();

        const payload_len = try checkedPayloadLen(.put, key, value, self.cfg.max_record_bytes);
        const record_len = std.math.add(usize, record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        try self.maps[familyIndex(store_family)].map.checkRevision();
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
        self.active_prepared.?.existing = existing;
        self.active_prepared.?.old_value = map.map.get(key);

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
        self.active_prepared.?.table_plan = try map.map.prepare(&.{.{ .key = owned_key, .value = owned_value }}, std.math.maxInt(u64));
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
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        const sequence = try self.reserveSequence();
        const record_len = try recordSize(.put, key, value, self.cfg.max_record_bytes);
        try self.maps[familyIndex(store_family)].map.checkOrdinaryPut(key);
        _ = try self.preflightWalForRecord(record_len);
        try self.appendRecord(.put, store_family, key, value);
        try self.applyPut(store_family, key, value);
        try self.recordMutation(sequence, store_family, .put, key, value);
    }

    pub fn get(self: *const OroStore, store_family: Family, key: []const u8) ?[]const u8 {
        return self.maps[familyIndex(store_family)].get(key);
    }

    pub fn delete(self: *OroStore, store_family: Family, key: []const u8) !void {
        if (self.staged_read_only) return StoreError.ReadOnlyStore;
        if (self.prepared_poisoned) return StoreError.StorePoisoned;
        if (self.active_prepared != null or self.active_batch != null) return StoreError.PreparedMutationActive;
        const sequence = try self.reserveSequence();
        const record_len = try recordSize(.delete, key, "", self.cfg.max_record_bytes);
        if (self.maps[familyIndex(store_family)].map.getEntry(key) != null) try self.maps[familyIndex(store_family)].map.checkRevision();
        _ = try self.preflightWalForRecord(record_len);
        try self.appendRecord(.delete, store_family, key, "");
        try self.applyDelete(store_family, key);
        try self.recordMutation(sequence, store_family, .delete, key, null);
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
            if (self.private_windows_files) try self.secureAtomicSnapshotWindows(&snapshot);
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

    fn secureAtomicSnapshotWindows(self: *OroStore, snapshot: *std.Io.File.Atomic) !void {
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

        const table_plan = if (self.active_prepared.?.table_plan) |*plan| plan else return StoreError.InvalidTablePlan;
        const table = &self.maps[familyIndex(active.store_family)].map;
        if (table_plan.owner != table or active.key == null or active.value == null or !table_plan.matchesEdit(active.key.?, active.value)) return StoreError.InvalidTablePlan;
        try table_plan.validate();
        if (table.getEntry(active.key.?)) |old| {
            if (!active.existing or active.old_value == null or active.old_value.?.ptr != old.value_ptr.*.ptr or active.old_value.?.len != old.value_ptr.*.len) return StoreError.InvalidTablePlan;
        } else if (active.existing or active.old_value != null) return StoreError.InvalidTablePlan;
        try self.writePreparedBytes(active.record.?, active.final_wal_offset);

        // Durable publication is deliberately scalar/pointer-only. All
        // retirement slots were made available before admission, and no
        // allocator or fallible call is permitted below this line.
        var prepared = active;
        if (self.active_prepared.?.table_plan.?.publish()) |slots| self.retireTable(slots);
        if (prepared.existing) self.retireBytes(prepared.key.?);
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

/// Flush a directory handle where the platform allows it. Windows rejects
/// FlushFileBuffers on directory handles, so directory-entry durability is
/// not enforced there; the WAL file syncs on every mutation path still cover
/// file data.
fn syncDirectory(io: std.Io, directory: std.Io.File) !void {
    if (comptime @import("builtin").os.tag == .windows) return;
    try directory.sync(io);
}

const cold_identity = @import("mesh_presence_lease.zig");
const cold_runtime = @import("os_runtime.zig");
const cold_epoch_record_len = record_header_len + wal_epoch_payload_len;
const cold_posix = switch (@import("builtin").os.tag) {
    .linux, .openbsd, .freebsd => true,
    else => false,
};

pub const ColdOpenMode = enum { read_only, read_only_share_delete, read_write, directory };

/// Existing cold namespace acquisition never creates and cannot wait for a FIFO
/// peer. Force directory type for parent custody; held regular descriptors are
/// type checked before reading any application bytes.
pub fn openColdExisting(io: std.Io, dir: std.Io.Dir, path: []const u8, mode: ColdOpenMode) !std.Io.File {
    const os = @import("builtin").os.tag;
    if (comptime os == .windows) {
        const windows = std.os.windows;
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.BadPathName;
        const final_name = path[(if (std.mem.lastIndexOfAny(u8, path, "/\\")) |separator| separator + 1 else 0)..];
        if (std.mem.indexOfScalar(u8, final_name, ':') != null) return error.BadPathName;
        var path_w = try std.Io.Threaded.sliceToPrefixedFileW(dir.handle, path, .{});
        var name = path_w.string();
        const attributes: windows.OBJECT.ATTRIBUTES = .{
            .RootDirectory = if (std.Io.Dir.path.isAbsoluteWindowsWtf16(path_w.span())) null else dir.handle,
            .ObjectName = &name,
        };
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var handle: windows.HANDLE = undefined;
        const status = windows.ntdll.NtCreateFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true, .WRITE = mode == .read_write },
            },
            &attributes,
            &io_status,
            null,
            .{ .NORMAL = true },
            if (mode == .read_only_share_delete) .{ .READ = true, .DELETE = true } else .VALID_FLAGS,
            .OPEN,
            .{
                .DIRECTORY_FILE = mode == .directory,
                .NON_DIRECTORY_FILE = mode != .directory,
                .IO = .ASYNCHRONOUS,
                .OPEN_REPARSE_POINT = true,
                .OPEN_FOR_BACKUP_INTENT = mode == .directory,
            },
            null,
            0,
        );
        switch (status) {
            .SUCCESS => {},
            .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
            .OBJECT_NAME_INVALID, .OBJECT_PATH_SYNTAX_BAD => return error.BadPathName,
            .NOT_A_DIRECTORY => return error.NotDir,
            .FILE_IS_A_DIRECTORY => return error.NotRegular,
            .ACCESS_DENIED => return error.AccessDenied,
            .SHARING_VIOLATION => return error.FileBusy,
            else => return error.Unexpected,
        }
        const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = true } };
        errdefer file.close(io);
        if (mode == .directory) _ = try coldDirectoryIdentity(handle) else _ = try cold_identity.statRegular(handle);
        return file;
    }
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.Unsupported;
    if (path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.NameTooLong;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;
    const name: [:0]const u8 = buffer[0..path.len :0];
    const flags: std.posix.O = .{ .ACCMODE = if (mode == .read_write) .RDWR else .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true, .DIRECTORY = mode == .directory };
    const fd: std.posix.fd_t = while (true) {
        const result = std.posix.system.openat(dir.handle, name, flags, @as(std.posix.mode_t, 0));
        switch (std.posix.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .LOOP => return error.SymLinkLoop,
            .NOTDIR => return error.NotDir,
            .ACCES, .PERM => return error.AccessDenied,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE, .MFILE, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    };
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    if (mode == .directory) _ = try coldDirectoryIdentity(fd) else _ = try cold_identity.statRegular(fd);
    return file;
}

fn openExistingPersistenceFile(io: std.Io, dir: std.Io.Dir, path: []const u8, mode: ColdOpenMode) !std.Io.File {
    if (comptime cold_posix) return openColdExisting(io, dir, path, mode);
    var file = try dir.openFile(io, path, .{ .mode = if (mode == .read_write) .read_write else .read_only, .allow_directory = false, .follow_symlinks = false });
    if (comptime @import("builtin").os.tag == .windows) {
        // The pinned Zig Threaded backend opens no-follow Windows files for
        // asynchronous I/O, but reports them as blocking. Positional reads can
        // then return PENDING and hit an unreachable in the backend. Keep the
        // no-follow open and report the handle's actual I/O mode to Threaded.
        file.flags.nonblocking = true;
    }
    return file;
}

fn coldIdentityBits(value: anytype) u64 {
    return @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value)));
}
fn coldDirectoryIdentity(fd: std.posix.fd_t) !cold_identity.Identity {
    const os = @import("builtin").os.tag;
    if (comptime os == .windows) {
        const FileStandardInfo = extern struct {
            allocation_size: i64,
            end_of_file: i64,
            links: u32,
            delete_pending: u8,
            directory: u8,
        };
        const FileAttributeTagInfo = extern struct { attributes: u32, tag: u32 };
        comptime {
            if (@sizeOf(FileStandardInfo) != 24) @compileError("Windows FILE_STANDARD_INFO ABI mismatch");
        }
        var standard: FileStandardInfo = undefined;
        if (GetFileInformationByHandleEx(@intFromPtr(fd), 1, &standard, @sizeOf(FileStandardInfo)) == 0) return error.StatFailed;
        if (standard.directory == 0 or standard.delete_pending != 0) return error.NotDir;
        var attributes: FileAttributeTagInfo = undefined;
        if (GetFileInformationByHandleEx(@intFromPtr(fd), 9, &attributes, @sizeOf(FileAttributeTagInfo)) == 0) return error.StatFailed;
        if ((attributes.attributes & 0x400) != 0) return error.NotDir; // FILE_ATTRIBUTE_REPARSE_POINT
        const identity = try windowsFileIdentity(@intFromPtr(fd));
        return .{
            .device = identity.volume_serial,
            .inode = std.mem.readInt(u64, identity.file_id[0..8], .little),
            .inode_high = std.mem.readInt(u64, identity.file_id[8..16], .little),
        };
    } else if (comptime os == .linux) {
        var stat: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        while (true) switch (std.os.linux.errno(std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true, .INO = true }, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if (!stat.mask.TYPE or !stat.mask.INO) return error.StatFailed;
        if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) return error.NotDir;
        return .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino };
    } else if (comptime os == .openbsd or os == .freebsd) {
        var stat: std.posix.Stat = undefined;
        while (true) switch (std.posix.errno(std.posix.system.fstat(fd, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) return error.NotDir;
        return .{ .device = coldIdentityBits(stat.dev), .inode = coldIdentityBits(stat.ino) };
    } else return error.Unsupported;
}

test "Windows cold existing file modes preserve bytes on open and permit writes" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try tmp.dir.createFile(std.testing.io, "existing.wal", .{ .read = true });
    try created.writePositionalAll(std.testing.io, "before", 0);
    created.close(std.testing.io);

    const reader = try openColdExisting(std.testing.io, tmp.dir, "existing.wal", .read_only);
    defer reader.close(std.testing.io);
    try std.testing.expect(reader.flags.nonblocking);
    var bytes: [6]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 6), try reader.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("before", &bytes);

    const writer = try openColdExisting(std.testing.io, tmp.dir, "existing.wal", .read_write);
    defer writer.close(std.testing.io);
    try std.testing.expect(writer.flags.nonblocking);
    try std.testing.expectEqual(@as(u64, 6), (try writer.stat(std.testing.io)).size);
    try writer.writePositionalAll(std.testing.io, "after!", 0);
    try std.testing.expectEqual(@as(usize, 6), try reader.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("after!", &bytes);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "missing.wal", .read_write));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "missing.wal", .{}));
}

test "Windows cold directory identity is stable and types are checked" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try tmp.dir.createDir(std.testing.io, "other", .default_dir);
    const regular = try tmp.dir.createFile(std.testing.io, "plain", .{});
    regular.close(std.testing.io);
    const first = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer first.close(std.testing.io);
    const second = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer second.close(std.testing.io);
    const other = try openColdExisting(std.testing.io, tmp.dir, "other", .directory);
    defer other.close(std.testing.io);
    try std.testing.expect(first.flags.nonblocking);
    try std.testing.expectEqualDeep(try coldDirectoryIdentity(first.handle), try coldDirectoryIdentity(second.handle));
    try std.testing.expect(!std.meta.eql(try coldDirectoryIdentity(first.handle), try coldDirectoryIdentity(other.handle)));
    try std.testing.expectError(error.NotDir, openColdExisting(std.testing.io, tmp.dir, "plain", .directory));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "state", .read_only));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "state", .read_write));
}

test "Windows cold existing refuses file and directory reparse points" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    target.close(std.testing.io);
    try tmp.dir.createDir(std.testing.io, "target-dir", .default_dir);
    tmp.dir.symLink(std.testing.io, "target.wal", "file-link.wal", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "file-link.wal", .read_only));
    tmp.dir.symLink(std.testing.io, "target-dir", "dir-link", .{ .is_directory = true }) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotDir, openColdExisting(std.testing.io, tmp.dir, "dir-link", .directory));
}

test "Windows cold existing refuses hardlink alias" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const target = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    target.close(std.testing.io);
    const target_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/target.wal", .{&tmp.sub_path});
    defer std.testing.allocator.free(target_path);
    const alias_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/alias.wal", .{&tmp.sub_path});
    defer std.testing.allocator.free(alias_path);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, target_path);
    defer std.testing.allocator.free(target_w);
    const alias_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, alias_path);
    defer std.testing.allocator.free(alias_w);
    try std.testing.expect(CreateHardLinkW(alias_w.ptr, target_w.ptr, null) != 0);
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "alias.wal", .read_only));
    try std.testing.expectError(error.NotRegular, openColdExisting(std.testing.io, tmp.dir, "target.wal", .read_write));
}

test "Windows cold existing rejects alternate data streams without changing base file" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try tmp.dir.createFile(std.testing.io, "target.wal", .{});
    try created.writePositionalAll(std.testing.io, "base", 0);
    created.close(std.testing.io);
    const absolute = try tmp.dir.realPathFileAlloc(std.testing.io, "target.wal", std.testing.allocator);
    defer std.testing.allocator.free(absolute);
    const accepted = try openColdExisting(std.testing.io, .cwd(), absolute, .read_only);
    accepted.close(std.testing.io);
    const stream = try std.fmt.allocPrint(std.testing.allocator, "{s}:alternate", .{absolute});
    defer std.testing.allocator.free(stream);
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, tmp.dir, "target.wal:alternate", .read_only));
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, .cwd(), stream, .read_write));
    try std.testing.expectError(error.BadPathName, openColdExisting(std.testing.io, tmp.dir, "missing.wal:alternate", .read_write));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "missing.wal", .{}));
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "target.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("base", bytes);
}

fn coldOpenParent(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    return openColdExisting(io, dir, std.fs.path.dirname(path) orelse ".", .directory);
}
fn validateColdParent(io: std.Io, dir: std.Io.Dir, path: []const u8, held: std.Io.File, expected: cold_identity.Identity, atomic: ?*const std.Io.File.Atomic) !void {
    if (!std.meta.eql(expected, try coldDirectoryIdentity(held.handle))) return StoreError.SnapshotCoverageMismatch;
    const configured = try coldOpenParent(io, dir, path);
    defer configured.close(io);
    if (!std.meta.eql(expected, try coldDirectoryIdentity(configured.handle))) return StoreError.SnapshotCoverageMismatch;
    if (atomic) |file| {
        // Named atomics retain actual dirname+basename; anonymous O_TMPFILE
        // retains base dir+full subpath. Resolve the publication parent in both.
        const actual = try coldOpenParent(io, file.dir, file.dest_sub_path);
        defer actual.close(io);
        if (!std.meta.eql(expected, try coldDirectoryIdentity(actual.handle))) return StoreError.SnapshotCoverageMismatch;
    }
}

test "Windows cold parent validation binds held and configured directories before effects" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const held = try openColdExisting(std.testing.io, tmp.dir, "state", .directory);
    defer held.close(std.testing.io);
    const wrong = try openColdExisting(std.testing.io, tmp.dir, "foreign", .directory);
    defer wrong.close(std.testing.io);
    const expected = try coldDirectoryIdentity(held.handle);
    try validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, null);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", wrong, expected, null));
    var foreign_atomic = try tmp.dir.createFileAtomic(std.testing.io, "foreign/custody.wal", .{ .replace = true });
    defer foreign_atomic.deinit(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, &foreign_atomic));
    var wrong_high = expected;
    wrong_high.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, wrong_high, null));
    try tmp.dir.rename("state", tmp.dir, "previous", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdParent(std.testing.io, tmp.dir, "state/custody.wal", held, expected, null));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/custody.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "previous/custody.wal", .read_only));
}

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
        var batch = try store.prepareBatchAt(mutations, payload, record, end, next);
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
        if (atomic.file_exists) try makeColdAtomicReadable(store.io, &atomic);
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
        store.validateBatchTables() catch |err| switch (err) {
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
        errdefer store.poisonPreparedStore();
        if (comptime @import("builtin").os.tag == .windows) {
            try renameHeldColdAtomicWindows(store.io, &self.atomic.?, store.dir, store.wal_path, self.directory, self.directory_identity, self.atomic_identity.?, false);
        } else {
            try self.atomic.?.link(store.io);
            try self.directory.sync(store.io);
        }
        store.staged_read_only = false;
        store.publishBatch(active.generation);
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

fn coldDigest(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

// Replay only this captured immutable transcript. Parsing and receipt hashing
// share bytes, never independently reopened paths or mutable decoded caches.
const ColdTranscript = struct {
    bytes: []const u8,
    fn stat(self: ColdTranscript, _: std.Io) !struct { size: u64 } {
        return .{ .size = self.bytes.len };
    }
    fn readPositionalAll(self: ColdTranscript, _: std.Io, buffer: []u8, offset: u64) !usize {
        if (offset >= self.bytes.len) return 0;
        const take = @min(buffer.len, self.bytes.len - @as(usize, @intCast(offset)));
        @memcpy(buffer[0..take], self.bytes[@intCast(offset)..][0..take]);
        return take;
    }
};

const ColdFile = struct {
    file: std.Io.File,
    identity: cold_identity.Identity,
    bytes: []u8,
    digest: [32]u8,

    fn capture(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, limit: ?usize) !ColdFile {
        const file = try openColdExisting(io, dir, path, .read_only);
        errdefer file.close(io);
        const identity = try cold_identity.statRegular(file.handle);
        const size = std.math.cast(usize, (try file.stat(io)).size) orelse return StoreError.RecordTooLarge;
        if (limit) |maximum| if (size > maximum) return StoreError.RecordTooLarge;
        const bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);
        if (try file.readPositionalAll(io, bytes, 0) != size or (try file.stat(io)).size != size or !std.meta.eql(identity, try cold_identity.statRegular(file.handle))) return StoreError.SnapshotCoverageMismatch;
        return .{ .file = file, .identity = identity, .bytes = bytes, .digest = coldDigest(bytes) };
    }
    fn deinit(self: *ColdFile, allocator: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        allocator.free(self.bytes);
    }
    fn validate(self: *const ColdFile, io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
        const configured = try openColdExisting(io, dir, path, .read_only);
        defer configured.close(io);
        if (!std.meta.eql(self.identity, try cold_identity.statRegular(configured.handle)) or !std.meta.eql(self.identity, try cold_identity.statRegular(self.file.handle)) or (try configured.stat(io)).size != self.bytes.len or (try self.file.stat(io)).size != self.bytes.len) return StoreError.SnapshotCoverageMismatch;
        if (!std.mem.eql(u8, &self.digest, &coldDigest(self.bytes))) return StoreError.SnapshotCoverageMismatch;
        var hasher = std.crypto.hash.Blake3.init(.{});
        var scratch: [4096]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.bytes.len) {
            const take = @min(scratch.len, self.bytes.len - offset);
            if (try self.file.readPositionalAll(io, scratch[0..take], offset) != take) return StoreError.SnapshotCoverageMismatch;
            hasher.update(scratch[0..take]);
            offset += take;
        }
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        if (!std.mem.eql(u8, &digest, &self.digest)) return StoreError.SnapshotCoverageMismatch;
    }
};

fn coldEpoch(epoch: [wal_epoch_len]u8) [cold_epoch_record_len]u8 {
    var record: [cold_epoch_record_len]u8 = undefined;
    writeU32(record[0..4], wal_epoch_payload_len);
    record[record_header_len] = meta_kind_wal_epoch;
    record[record_header_len + 1 ..].* = epoch;
    writeU32(record[4..8], checksum(record[record_header_len..]));
    return record;
}

const ColdPlan = struct {
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
        owner.discardActiveBatch();
        if (self.writer_owned) self.writer.close(io);
        self.directory.close(io);
        if (self.wal_atomic) |*file| deinitColdAtomic(io, file, self.writer_identity);
        if (self.snapshot_atomic) |*file| deinitColdAtomic(io, file, self.snapshot_identity);
        if (self.snapshot_bytes) |bytes| allocator.free(bytes);
        if (self.complete_record) |bytes| allocator.free(bytes);
    }
};

/// Narrow recovery publication faults: each seam reports failure at the actual
/// source-owned syscall boundary. Prepared batch write/sync faults retain the
/// existing OroStore seam; these phases never affect generic or hot loaders.
pub const ColdPublicationFault = enum { none, snapshot_replace, snapshot_dir_sync, wal_replace, wal_dir_sync, truncate, truncate_sync };

const ColdBacking = struct {
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
        var wal = try ColdFile.capture(allocator, io, dir, path, config.max_wal_bytes);
        errdefer wal.deinit(allocator, io);
        // `ColdFile.capture` funnels through `openColdExisting`. Keep the
        // optional snapshot absent only for an actual missing namespace entry.
        var snapshot: ?ColdFile = ColdFile.capture(allocator, io, dir, snapshot_path, null) catch |err| blk: {
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
        if (snapshot) |file| _ = try store.replaySource(ColdTranscript{ .bytes = file.bytes }, .snapshot, 0);
        try store.loadWalEpochFrom(ColdTranscript{ .bytes = wal.bytes });
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
        owned.valid_end = try store.replaySource(ColdTranscript{ .bytes = wal.bytes }, .wal, owned.replay_start);
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
        // Windows cold capture is read-only until transactional temporary-file
        // publication and cleanup have their own platform custody proof.
        if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
        try self.validate();
        const owned = self.backing.?;
        const store = &owned.store;
        if (owned.plan != null or store.active_batch != null) return StoreError.PreparedMutationActive;
        if (complete_epoch and owned.valid_end != owned.wal.bytes.len) return StoreError.SnapshotCoverageMismatch;
        if (store.next_prepared_generation == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
        const payload_len = try batchPayloadLen(mutations, store.cfg.max_record_bytes);
        const record_len = std.math.add(usize, batch_guard_len + record_header_len, payload_len) catch return StoreError.RecordTooLarge;
        const projected = std.math.add(u64, owned.valid_end, record_len) catch return StoreError.RecordTooLarge;
        const rotate = complete_epoch or owned.selected_epoch != null or owned.wal.bytes.len == 0 or projected > store.cfg.max_wal_bytes or projected >= store.cfg.max_wal_bytes / 2;
        const offset: u64 = if (rotate) cold_epoch_record_len else owned.valid_end;
        const final = std.math.add(u64, offset, record_len) catch return StoreError.RecordTooLarge;
        if (final > store.cfg.max_wal_bytes) return StoreError.RecordTooLarge;
        const next = std.math.add(u64, store.next_seq, @intCast(mutations.len)) catch return StoreError.SequenceExhausted;
        var batch = try store.prepareBatchAt(mutations, payload_len, record_len, final, next);
        errdefer batch.abort();
        // Retain an independent canonical packet after publication ambiguity
        // poisons/frees the ordinary active batch. The held full successor and
        // this private witness belong to the stage until explicit cleanup.
        const complete_record: ?[]u8 = if (complete_epoch) try self.allocator.dupe(u8, store.active_batch.?.record.?) else null;
        errdefer if (complete_record) |bytes| self.allocator.free(bytes);
        var epoch = store.wal_epoch;
        if (rotate and owned.selected_epoch == null) store.io.random(&epoch);
        const record = coldEpoch(epoch);
        const rotated: CoverageSlot = .{ .covered_len = record.len, .epoch = epoch, .digest = coldDigest(&record) };
        const coverage: ?SnapshotCoverage = if (rotate and owned.selected_epoch == null and owned.wal.bytes.len != 0) .{ .count = 2, .slots = .{ .{ .covered_len = owned.valid_end, .epoch = store.wal_epoch, .digest = coldDigest(owned.wal.bytes[0..@intCast(owned.valid_end)]) }, rotated } } else null;
        const snapshot_bytes: ?[]u8 = if (coverage) |*proof| try encodeColdSnapshot(store, proof) else null;
        errdefer if (snapshot_bytes) |bytes| self.allocator.free(bytes);
        const directory = try coldOpenParent(store.io, store.dir, store.wal_path);
        errdefer directory.close(store.io);
        const directory_identity = try coldDirectoryIdentity(directory.handle);
        var snapshot_atomic: ?std.Io.File.Atomic = null;
        errdefer if (snapshot_atomic) |*file| deinitColdAtomic(store.io, file, null);
        if (snapshot_bytes) |bytes| {
            snapshot_atomic = try store.dir.createFileAtomic(store.io, store.snapshot_path, .{ .replace = true });
            try makeColdAtomicReadable(store.io, &snapshot_atomic.?);
            try snapshot_atomic.?.file.writePositionalAll(store.io, bytes, 0);
            try snapshot_atomic.?.file.sync(store.io);
        }
        var wal_atomic: ?std.Io.File.Atomic = null;
        errdefer if (wal_atomic) |*file| deinitColdAtomic(store.io, file, null);
        const writer: std.Io.File = if (rotate) block: {
            wal_atomic = try store.dir.createFileAtomic(store.io, store.wal_path, .{ .replace = true });
            try makeColdAtomicReadable(store.io, &wal_atomic.?);
            try wal_atomic.?.file.writePositionalAll(store.io, &record, 0);
            if (complete_record) |bytes| try wal_atomic.?.file.writePositionalAll(store.io, bytes, cold_epoch_record_len);
            try wal_atomic.?.file.sync(store.io);
            // Atomic.replace closes its descriptor. Reserve a duplicate now;
            // the exact same replacement OFD receives the successor batch.
            break :block .{ .handle = try cold_runtime.duplicate(wal_atomic.?.file.handle), .flags = wal_atomic.?.file.flags };
        } else try openColdExisting(store.io, store.dir, store.wal_path, .read_write);
        errdefer writer.close(store.io);
        const writer_identity = try cold_identity.statRegular(writer.handle);
        if (!rotate and !std.meta.eql(writer_identity, owned.wal.identity)) return StoreError.SnapshotCoverageMismatch;
        owned.plan = .{ .batch = batch, .writer = writer, .writer_identity = writer_identity, .directory = directory, .directory_identity = directory_identity, .wal_atomic = wal_atomic, .snapshot_atomic = snapshot_atomic, .snapshot_bytes = snapshot_bytes, .snapshot_identity = if (snapshot_atomic) |file| try cold_identity.statRegular(file.file.handle) else null, .epoch = record, .coverage = coverage, .rotate = rotate, .complete_epoch = complete_epoch, .complete_record = complete_record };
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
        owned.store.validateBatchTables() catch |err| switch (err) {
            StoreError.InvalidTablePlan => return StoreError.SnapshotCoverageMismatch,
            else => return err,
        };
        if (plan.batch.store != &owned.store or !std.mem.eql(u8, &plan.prepared_digest, &try coldPreparedDigest(owned))) return StoreError.SnapshotCoverageMismatch;
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
        errdefer store.poisonPreparedStore();
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
            store.publishBatch(active.generation);
        } else try plan.batch.commit();
        owned.committed = true;
        plan.deinit(self.stage.allocator, store.io, store);
        owned.plan = null;
    }
};

fn coldHashInt(hasher: *std.crypto.hash.Blake3, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    hasher.update(&bytes);
}
fn coldHashBytes(hasher: *std.crypto.hash.Blake3, value: []const u8) void {
    coldHashInt(hasher, value.len);
    hasher.update(value);
}
fn coldHashIdentity(hasher: *std.crypto.hash.Blake3, identity: cold_identity.Identity) void {
    coldHashInt(hasher, identity.device);
    coldHashInt(hasher, identity.inode);
    // Windows FILE_ID_INFO has 128 identifier bits. Preserve existing POSIX
    // receipt bytes while authenticating the high half on Windows.
    if (comptime @import("builtin").os.tag == .windows) coldHashInt(hasher, identity.inode_high);
}
fn coldHashCoverage(hasher: *std.crypto.hash.Blake3, coverage: ?SnapshotCoverage) !void {
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
fn coldCutDigest(owned: *const ColdBacking) ![32]u8 {
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
            coldHashInt(&item, @intFromEnum(family));
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
fn coldPreparedDigest(owned: *const ColdBacking) ![32]u8 {
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
        coldHashInt(&hash, @intFromEnum(entry.family));
        coldHashInt(&hash, @intFromEnum(entry.kind));
        coldHashBytes(&hash, entry.key orelse return StoreError.SnapshotCoverageMismatch);
        coldHashInt(&hash, @intFromBool(entry.value != null));
        if (entry.value) |value| coldHashBytes(&hash, value);
        coldHashInt(&hash, @intFromBool(entry.change != null));
        if (entry.change) |change| {
            coldHashInt(&hash, change.seq);
            coldHashInt(&hash, @intFromEnum(change.family));
            coldHashInt(&hash, @intFromEnum(change.kind));
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

fn validateColdLease(io: std.Io, dir: std.Io.Dir, lease: std.Io.File, path: []const u8, identity: cold_identity.Identity) !void {
    if (!std.meta.eql(identity, try cold_identity.statRegular(lease.handle))) return StoreError.SnapshotCoverageMismatch;
    const configured = try openColdExisting(io, dir, path, .read_only);
    defer configured.close(io);
    if (!std.meta.eql(identity, try cold_identity.statRegular(configured.handle))) return StoreError.SnapshotCoverageMismatch;
    try cold_identity.reaffirmExclusive(lease.handle);
}

test "Windows cold lease accepts only the local locked marker handle at its path" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try tmp.dir.createFile(std.testing.io, "custody.wal.lock", .{ .read = true });
    defer owner.close(std.testing.io);
    try std.testing.expect(try owner.tryLock(std.testing.io, .exclusive));
    try owner.writePositionalAll(std.testing.io, "L", 0);
    const identity = try cold_identity.statRegular(owner.handle);
    try validateColdLease(std.testing.io, tmp.dir, owner, "custody.wal.lock", identity);
    try std.testing.expectError(error.InsecurePermissions, FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", owner, .{}));
    try std.testing.expectError(error.FileNotFound, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", owner, .{}));
    const reopened = try openColdExisting(std.testing.io, tmp.dir, "custody.wal.lock", .read_write);
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, validateColdLease(std.testing.io, tmp.dir, reopened, "custody.wal.lock", identity));
    const foreign = try tmp.dir.createFile(std.testing.io, "foreign.wal.lock", .{ .read = true });
    defer foreign.close(std.testing.io);
    try foreign.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdLease(std.testing.io, tmp.dir, owner, "foreign.wal.lock", identity));
    var wrong_high = identity;
    wrong_high.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, validateColdLease(std.testing.io, tmp.dir, owner, "custody.wal.lock", wrong_high));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try owner.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows first provision init holds a private lease without publishing files" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try lease.sync(std.testing.io);
    {
        var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try std.testing.expect(stage.store.?.isReadOnly());
        try std.testing.expectError(StoreError.PreparedAlreadyConsumed, stage.commit());
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    }
    try cold_identity.reaffirmExclusive(lease.handle);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try lease.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows first provision preparation keeps bytes on a held private temp until abort" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var live = true;
    defer if (live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const atomic = stage.atomic.?;
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    const writer = stage.store.?.wal_file.?;
    try std.testing.expect(stage.store.?.isReadOnly());
    try std.testing.expectEqualDeep(stage.atomic_identity.?, try cold_identity.statRegular(writer.handle));
    try std.testing.expectEqualDeep(stage.atomic_identity.?, try cold_identity.statRegular(atomic.file.handle));
    try std.testing.expectEqual(stage.store.?.active_batch.?.final_wal_offset, (try writer.stat(std.testing.io)).size);
    var epoch: [cold_epoch_record_len]u8 = undefined;
    try std.testing.expectEqual(epoch.len, try writer.readPositionalAll(std.testing.io, &epoch, 0));
    try std.testing.expectEqualSlices(u8, &stage.epoch, &epoch);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
    stage.deinit();
    live = false;
    try cold_identity.reaffirmExclusive(lease.handle);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision commit publishes held WAL and cold recovery replays it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    failing.fail_index = failing.alloc_index;
    try stage.commit();
    failing.fail_index = std.math.maxInt(usize);
    var published = stage.takeCommittedStore();
    stage.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    try std.testing.expect(published.private_windows_files);
    try published.put(.props, "later", "still safe");
    try published.snapshotAndTruncate();
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    published.deinit();
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    var cold = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    defer cold.deinit();
    try cold.validate();
    try std.testing.expectEqualStrings("cut", cold.view().get(.props, "new").?);
    try std.testing.expectEqualStrings("still safe", cold.view().get(.props, "later").?);
}

test "Windows first provision commit refuses a raced WAL without replacing it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    const foreign = try private.createFile(std.testing.io, "first.wal", .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try std.testing.expectError(error.PathAlreadyExists, stage.commit());
    try std.testing.expect(stage.store.?.preparedWritesPoisoned());
    stage.deinit();
    const bytes = try private.readFileAlloc(std.testing.io, "first.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    orphan.close(std.testing.io);
}

test "Windows first provision commit revalidates lease and snapshot before publish" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var stage_live = true;
    errdefer if (stage_live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const reopened = try openColdExisting(std.testing.io, private, "first.wal.lock", .read_write);
    stage.lease = reopened;
    try std.testing.expectError(error.WouldBlock, stage.commit());
    stage.lease = lease;
    reopened.close(std.testing.io);
    const snapshot = try private.createFile(std.testing.io, "first.wal.snap", .{});
    snapshot.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.commit());
    try private.deleteFile(std.testing.io, "first.wal.snap");
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    try stage.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    stage.deinit();
    stage_live = false;
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
}

test "Windows first provision commit poisons on a full temp identity mismatch" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    var live = true;
    defer if (live) stage.deinit();
    try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    const temp_name = std.fmt.hex(stage.atomic.?.file_basename_hex);
    stage.atomic_identity.?.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.commit());
    try std.testing.expect(stage.store.?.preparedWritesPoisoned());
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
    stage.atomic_identity.?.inode_high ^= 1;
    stage.deinit();
    live = false;
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
}

test "Windows first provision preparation refuses a reopened lease before temp creation" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    const reopened = try openColdExisting(std.testing.io, private, "first.wal.lock", .read_write);
    defer reopened.close(std.testing.io);
    stage.lease = reopened;
    try std.testing.expectError(error.WouldBlock, stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }}));
    try std.testing.expect(stage.atomic == null);
    try std.testing.expect(stage.store.?.active_batch == null);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision preparation allocation failures are inert and retryable" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    const mutations: []const BatchMutation = &.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }};
    var control = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var successful = try FirstProvisionStage.init(control.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
    const before = control.alloc_index;
    try successful.prepareBatch(mutations);
    const allocation_count = control.alloc_index - before;
    successful.deinit();
    try std.testing.expect(allocation_count > 0);
    for (0..allocation_count) |offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
        var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        failing.fail_index = failing.alloc_index + offset;
        try std.testing.expectError(error.OutOfMemory, stage.prepareBatch(mutations));
        try std.testing.expect(stage.atomic == null);
        try std.testing.expect(stage.store.?.active_batch == null);
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        failing.fail_index = std.math.maxInt(usize);
        try stage.prepareBatch(mutations);
        try std.testing.expect(stage.atomic != null);
        stage.deinit();
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try cold_identity.reaffirmExclusive(lease.handle);
    }
}

test "Windows first provision init rejects a broad parent with a private lease" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const created = try cold_runtime.createPrivateExclusiveWindows(tmp.dir, "first.wal.lock");
    created.close(std.testing.io);
    const lease = try openColdExisting(std.testing.io, tmp.dir, "first.wal.lock", .read_write);
    defer lease.close(std.testing.io);
    try cold_runtime.requireInheritedPrivateFileWindows(lease);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.InsecurePermissions, FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, "first.wal", lease, .{}));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "first.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "first.wal.snap", .read_only));
}

test "Windows first provision init rejects unlocked lease and leaves no namespace" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try lease.writePositionalAll(std.testing.io, "L", 0);
    try std.testing.expectError(error.WouldBlock, FirstProvisionStage.init(std.testing.allocator, std.testing.io, private, "first.wal", lease, .{}));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
}

test "Windows first provision init allocation failures leave only the held marker" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const lease = try private.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var control = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    {
        var stage = try FirstProvisionStage.init(control.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 });
        stage.deinit();
    }
    for (0..control.alloc_index) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, FirstProvisionStage.init(failing.allocator(), std.testing.io, private, "first.wal", lease, .{ .changefeed_capacity = 0 }));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal", .read_only));
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "first.wal.snap", .read_only));
        try cold_identity.reaffirmExclusive(lease.handle);
    }
}

test "Windows cold lease rejects an unlocked marker without changing it" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const unlocked = try tmp.dir.createFile(std.testing.io, "unlocked.wal.lock", .{ .read = true });
    defer unlocked.close(std.testing.io);
    try unlocked.writePositionalAll(std.testing.io, "L", 0);
    const identity = try cold_identity.statRegular(unlocked.handle);
    try std.testing.expectError(error.WouldBlock, validateColdLease(std.testing.io, tmp.dir, unlocked, "unlocked.wal.lock", identity));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try unlocked.readPositionalAll(std.testing.io, &marker, 0));
    try std.testing.expectEqual(@as(u8, 'L'), marker[0]);
}

test "Windows cold recovery opens a captured read-only view and leaves preparation inert" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-read.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const before = try readWalForTest(tmp, "cold-read.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-read.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-read.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    try stage.validate();
    try std.testing.expect(stage.view().isReadOnly());
    try std.testing.expectEqualStrings("durable", stage.view().get(.props, "original").?);
    const mutation: BatchMutation = .{ .family = .props, .kind = .put, .key = "new", .value = "forbidden" };
    try std.testing.expectError(error.SkipZigTest, stage.prepareBatch(&.{mutation}));
    try std.testing.expectError(error.SkipZigTest, stage.prepareCompleteBatch(&.{mutation}));
    try std.testing.expect(stage.backing.?.plan == null);
    try std.testing.expect(stage.backing.?.store.active_batch == null);
    try stage.validate();
    const after = try readWalForTest(tmp, "cold-read.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "cold-read.wal.snap", .read_only));
}

test "Windows cold recovery detects high identity and namespace or byte tampering" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-tamper.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const original = try readWalForTest(tmp, "cold-tamper.wal");
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-tamper.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-tamper.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    const owned = stage.backing.?;
    const digest = owned.cut_digest;
    owned.wal.identity.inode_high ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &digest, &try coldCutDigest(owned)));
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    owned.wal.identity.inode_high ^= 1;
    try stage.validate();

    const writer = try openColdExisting(std.testing.io, tmp.dir, "cold-tamper.wal", .read_write);
    try writer.writePositionalAll(std.testing.io, "X", 0);
    writer.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    const restore = try openColdExisting(std.testing.io, tmp.dir, "cold-tamper.wal", .read_write);
    try restore.writePositionalAll(std.testing.io, original[0..1], 0);
    restore.close(std.testing.io);
    try stage.validate();

    try tmp.dir.rename("cold-tamper.wal", tmp.dir, "moved.wal", std.testing.io);
    const replacement = try tmp.dir.createFile(std.testing.io, "cold-tamper.wal", .{ .read = true });
    try replacement.writePositionalAll(std.testing.io, original, 0);
    replacement.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
}

test "Windows cold recovery allocation failures preserve the existing WAL" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-oom-read.wal");
        defer seed.deinit();
        try seed.put(.props, "original", "durable");
    }
    const before = try readWalForTest(tmp, "cold-oom-read.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-oom-read.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var result = ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "cold-oom-read.wal", lease, .{ .changefeed_capacity = 0 });
        if (result) |*stage| {
            defer stage.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try stage.validate();
            try std.testing.expectEqualStrings("durable", stage.view().get(.props, "original").?);
            break;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
        }
        const after = try readWalForTest(tmp, "cold-oom-read.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "cold-oom-read.wal.snap", .read_only));
    }
    try std.testing.expect(index > 0);
}

test "Windows cold recovery replays a covered snapshot and retains an unknown WAL tail" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-covered.wal");
        defer seed.deinit();
        try seed.put(.props, "covered", "snapshot state");
        try seed.snapshotAndTruncate();
        try seed.put(.props, "later", "WAL state");
    }
    const good_wal = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(good_wal);
    const writer = try openColdExisting(std.testing.io, tmp.dir, "cold-covered.wal", .read_write);
    try writer.writePositionalAll(std.testing.io, "unknown tail", good_wal.len);
    writer.close(std.testing.io);
    const before = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(before);
    const lease = try tmp.dir.createFile(std.testing.io, "cold-covered.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try std.testing.expect(try lease.tryLock(std.testing.io, .exclusive));
    try lease.writePositionalAll(std.testing.io, "L", 0);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-covered.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    try stage.validate();
    try std.testing.expectEqualStrings("snapshot state", stage.view().get(.props, "covered").?);
    try std.testing.expectEqualStrings("WAL state", stage.view().get(.props, "later").?);
    try std.testing.expectEqual(@as(u64, good_wal.len), stage.backing.?.valid_end);
    const after = try readWalForTest(tmp, "cold-covered.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    const snapshot = &stage.backing.?.snapshot.?;
    snapshot.identity.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
    snapshot.identity.inode_high ^= 1;
    try stage.validate();
    const snapshot_writer = try openColdExisting(std.testing.io, tmp.dir, "cold-covered.wal.snap", .read_write);
    try snapshot_writer.writePositionalAll(std.testing.io, "X", 0);
    snapshot_writer.close(std.testing.io);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.validate());
}

fn validateColdPreparedWal(owned: *const ColdBacking) !void {
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

fn validateColdPreparedFile(io: std.Io, file: std.Io.File, bytes: []const u8, identity: cold_identity.Identity) !void {
    if (!std.meta.eql(identity, try cold_identity.statRegular(file.handle)) or (try file.stat(io)).size != bytes.len) return StoreError.SnapshotCoverageMismatch;
    try validateColdPreparedRange(io, file, bytes, 0);
}

fn validateColdPreparedRange(io: std.Io, file: std.Io.File, bytes: []const u8, start: u64) !void {
    var buffer: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const take = @min(buffer.len, bytes.len - offset);
        if (try file.readPositionalAll(io, buffer[0..take], start + offset) != take or !std.mem.eql(u8, buffer[0..take], bytes[offset..][0..take])) return StoreError.SnapshotCoverageMismatch;
        offset += take;
    }
}

// A named atomic temporary is a namespace contribution as well as an owned
// descriptor. A correct held FD cannot authenticate a substituted rename source.
// The stable lease serializes cooperating writers; these finite checks do not
// purport to exclude privileged namespace changes after the final check.
fn validateColdAtomicName(io: std.Io, atomic: *const std.Io.File.Atomic, identity: cold_identity.Identity) !void {
    if (!atomic.file_exists) return; // Anonymous temp: link uses the held FD.
    const name = std.fmt.hex(atomic.file_basename_hex);
    const named = openColdExisting(io, atomic.dir, &name, .read_only) catch return StoreError.SnapshotCoverageMismatch;
    defer named.close(io);
    if (!std.meta.eql(identity, cold_identity.statRegular(named.handle) catch return StoreError.SnapshotCoverageMismatch)) return StoreError.SnapshotCoverageMismatch;
    // Same inode binds the exact bytes already checked through the held FD.
}

// std.Atomic.deinit unconditionally unlinks its remembered temporary name.
// On Windows delete through a verified handle; never ask std to unlink a name
// which might have been substituted while the stage was preparing.
fn deinitColdAtomic(io: std.Io, atomic: *std.Io.File.Atomic, known_identity: ?cold_identity.Identity) void {
    if (comptime @import("builtin").os.tag == .windows) {
        if (atomic.file_exists) {
            const identity = known_identity orelse if (atomic.file_open) windowsColdAtomicIdentity(atomic.file.handle) catch null else null;
            if (identity) |owned| deleteColdAtomicWindows(io, atomic, owned) catch {};
            // A failed proof or disposition leaves an owned orphan. It must
            // never fall through to std's unguarded name-based deletion.
            atomic.file_exists = false;
        }
        atomic.deinit(io);
        return;
    }
    if (atomic.file_exists) {
        const identity = known_identity orelse if (atomic.file_open) cold_identity.statRegular(atomic.file.handle) catch null else null;
        if (identity) |owned| {
            validateColdAtomicName(io, atomic, owned) catch {
                atomic.file_exists = false;
            };
        } else atomic.file_exists = false;
    }
    atomic.deinit(io);
}

fn openColdAtomicWindows(io: std.Io, atomic: *const std.Io.File.Atomic) !std.Io.File {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    _ = try cold_runtime.requirePrivateDirectoryHandleWindows(atomic.dir);
    const windows = std.os.windows;
    const name = std.fmt.hex(atomic.file_basename_hex);
    var name_w = try std.Io.Threaded.sliceToPrefixedFileW(atomic.dir.handle, &name, .{});
    var object_name = name_w.string();
    const attributes: windows.OBJECT.ATTRIBUTES = .{ .RootDirectory = atomic.dir.handle, .ObjectName = &object_name };
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var handle: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true, .RIGHTS = .{ .READ_CONTROL = true, .DELETE = true } }, .GENERIC = .{ .READ = true, .WRITE = true } },
        &attributes,
        &io_status,
        null,
        .{ .NORMAL = true },
        .{},
        .OPEN,
        .{ .NON_DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT, .OPEN_REPARSE_POINT = true, .WRITE_THROUGH = true },
        null,
        0,
    );
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .ACCESS_DENIED => return error.AccessDenied,
        .SHARING_VIOLATION => return error.FileBusy,
        else => return error.Unexpected,
    }
    const file: std.Io.File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
    errdefer file.close(io);
    _ = try cold_identity.statRegular(file.handle);
    try cold_runtime.requireInheritedPrivateFileWindows(file);
    return file;
}

fn markColdAtomicDeletedWindows(file: std.Io.File) bool {
    if (comptime @import("builtin").os.tag != .windows) return false;
    // FileDispositionInfo marks this exact held file for deletion on close.
    // The reopened atomic handle requests DELETE and excludes other openers.
    const disposition: u8 = 1;
    return SetFileInformationByHandle(@intFromPtr(file.handle), 4, &disposition, @sizeOf(u8)) != 0;
}

fn deleteColdAtomicWindows(io: std.Io, atomic: *std.Io.File.Atomic, identity: cold_identity.Identity) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    if (!atomic.file_exists) return;
    if (atomic.file_open and std.meta.eql(identity, windowsColdAtomicIdentity(atomic.file.handle) catch return StoreError.SnapshotCoverageMismatch)) {
        if (markColdAtomicDeletedWindows(atomic.file)) return;
    }
    if (atomic.file_open) {
        atomic.file.close(io);
        atomic.file_open = false;
    }
    const candidate = try openColdAtomicWindows(io, atomic);
    defer candidate.close(io);
    if (!std.meta.eql(identity, try cold_identity.statRegular(candidate.handle))) return StoreError.SnapshotCoverageMismatch;
    if (!markColdAtomicDeletedWindows(candidate)) return error.Unexpected;
}

// Zig's named Atomic default is write-only. Reacquire a readable, deletable
// handle before writing secrets, and bind it to the full original file ID.
fn makeColdAtomicReadable(io: std.Io, atomic: *std.Io.File.Atomic) !void {
    if (comptime @import("builtin").os.tag == .windows) {
        if (!atomic.file_exists or !atomic.file_open) return error.InvalidDescriptor;
        _ = try cold_runtime.requirePrivateDirectoryHandleWindows(atomic.dir);
        try cold_runtime.requireInheritedPrivateFileWindows(atomic.file);
        const original = try windowsColdAtomicIdentity(atomic.file.handle);
        atomic.file.close(io);
        atomic.file_open = false;
        errdefer {
            deleteColdAtomicWindows(io, atomic, original) catch {};
            // The caller's errdefer may lack this captured identity.
            atomic.file_exists = false;
        }
        const file = try openColdAtomicWindows(io, atomic);
        errdefer file.close(io);
        if (!std.meta.eql(original, try cold_identity.statRegular(file.handle))) return StoreError.SnapshotCoverageMismatch;
        atomic.file = file;
        atomic.file_open = true;
        return;
    }
    const name = std.fmt.hex(atomic.file_basename_hex);
    const file = try openColdExisting(io, atomic.dir, &name, .read_write);
    errdefer file.close(io);
    if (!std.meta.eql(try cold_identity.statRegular(file.handle), try cold_identity.statRegular(atomic.file.handle))) return StoreError.SnapshotCoverageMismatch;
    atomic.file.close(io);
    atomic.file = file;
}

/// Rename the exact held, no-share temporary into a verified private parent.
/// This is only a namespace primitive: callers must separately prove prepared
/// bytes, lease custody, configured reopen, and the publication cut. In
/// particular, no cold stage uses this until its whole Windows transaction is
/// available. FILE_WRITE_THROUGH requests NTFS metadata flush for the rename;
/// this does not establish power-loss durability on every filesystem.
fn requireColdWriteThroughVolumeWindows(parent: std.Io.File) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    // Windows documents rename metadata flushing for write-through requests on
    // NTFS. Reject other filesystems before treating a rename as a durable cut.
    var fs_name: [16]u16 = @splat(0);
    if (GetVolumeInformationByHandleW(@intFromPtr(parent.handle), null, 0, null, null, null, &fs_name, fs_name.len) == 0)
        return error.Unsupported;
    if (!std.mem.eql(u16, fs_name[0..5], &.{ 'N', 'T', 'F', 'S', 0 })) return error.Unsupported;
}

fn renameHeldColdAtomicWindows(
    io: std.Io,
    atomic: *std.Io.File.Atomic,
    configured_dir: std.Io.Dir,
    configured_path: []const u8,
    held_parent: std.Io.File,
    expected_parent: cold_identity.Identity,
    expected_file: cold_identity.Identity,
    replace: bool,
) !void {
    if (comptime @import("builtin").os.tag != .windows) return error.Unsupported;
    if (!atomic.file_exists or !atomic.file_open) return StoreError.SnapshotCoverageMismatch;
    const name = std.fs.path.basename(configured_path);
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
        std.mem.indexOfAny(u8, name, "/\\:\x00") != null or name[name.len - 1] == '.' or name[name.len - 1] == ' ' or
        !std.mem.eql(u8, name, std.fs.path.basename(atomic.dest_sub_path))) return StoreError.SnapshotCoverageMismatch;
    _ = try cold_runtime.requirePrivateDirectoryHandleWindows(.{ .handle = held_parent.handle });
    try requireColdWriteThroughVolumeWindows(held_parent);
    try validateColdParent(io, configured_dir, configured_path, held_parent, expected_parent, atomic);
    const windows = std.os.windows;
    var mode_status: windows.IO_STATUS_BLOCK = undefined;
    var mode: u32 = 0;
    if (windows.ntdll.NtQueryInformationFile(atomic.file.handle, &mode_status, &mode, @sizeOf(u32), .Mode) != .SUCCESS or
        (mode & 0x2) == 0) return error.Unsupported; // FILE_WRITE_THROUGH
    if (!std.meta.eql(expected_file, try cold_identity.statRegular(atomic.file.handle))) return StoreError.SnapshotCoverageMismatch;
    var name_w = try std.Io.Threaded.sliceToPrefixedFileW(held_parent.handle, name, .{});
    var info: windows.FILE.RENAME_INFORMATION = .init(.{
        .Flags = .{ .REPLACE_IF_EXISTS = replace, .POSIX_SEMANTICS = replace },
        .RootDirectory = held_parent.handle,
        .FileName = name_w.span(),
    });
    const buffer = info.toBuffer();
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    // NtSetInformationFile may have changed the namespace even if it reports a
    // failure. Deinit must never unlink a path after this boundary.
    atomic.file_exists = false;
    const status = windows.ntdll.NtSetInformationFile(atomic.file.handle, &io_status, buffer.ptr, @intCast(buffer.len), .RenameEx);
    switch (status) {
        .SUCCESS => {},
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        else => return StoreError.IoAmbiguous,
    }
}

fn encodeColdSnapshot(store: *const OroStore, coverage: *const SnapshotCoverage) ![]u8 {
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

test "cold recovery causal substituted temporary must never become authoritative snapshot" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "temp-custody.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "temp-custody.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "temp-custody.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const atomic = stage.backing.?.plan.?.snapshot_atomic.?;
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try atomic.dir.createFile(std.testing.io, "foreign", .{ .read = true });
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try atomic.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    // Refusal must precede ANY authoritative rename, not merely detect it later.
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "temp-custody.wal.snap", .{}));
    ticket.abort();
    const survivor = try atomic.dir.openFile(std.testing.io, &name, .{});
    survivor.close(std.testing.io);
}

fn coldRecoveryAllocationScenario(allocator: std.mem.Allocator, empty_covered: bool) !void {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "cold-oom.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(21);
        try seed.put(.props, "old", &large);
        if (empty_covered) {
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
    }
    const lease = try tmp.dir.createFile(std.testing.io, "cold-oom.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    const before = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const snapshot = if (empty_covered) try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal.snap", std.testing.allocator, .unlimited) else null;
    defer if (snapshot) |bytes| std.testing.allocator.free(bytes);
    coldRecoveryAttempt(allocator, tmp, lease) catch |err| {
        if (err == error.OutOfMemory) {
            const after = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            if (snapshot) |bytes| {
                const actual = try tmp.dir.readFileAlloc(std.testing.io, "cold-oom.wal.snap", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(actual);
                try std.testing.expectEqualSlices(u8, bytes, actual);
            } else try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "cold-oom.wal.snap", .{}));
            try cold_identity.reaffirmExclusive(lease.handle);
            try coldRecoveryAttempt(std.testing.allocator, tmp, lease);
        }
        return err;
    };
}

fn coldRecoveryAttempt(allocator: std.mem.Allocator, tmp: std.testing.TmpDir, lease: std.Io.File) !void {
    var stage = try ColdRecoveryStage.open(allocator, std.testing.io, tmp.dir, "cold-oom.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    const before_seq = stage.view().next_seq;
    if (stage.backing.?.selected_epoch) |chosen| {
        // Repeated compaction legitimately permits two complete epochs for
        // the SAME old maps. Preserve encoded-order FIRST valid selection.
        try std.testing.expectEqual(@as(usize, 0), chosen);
        const coverage = stage.view().snapshot_coverage.?;
        try std.testing.expectEqual(@as(usize, 2), coverage.count);
        for (coverage.slots[0..2]) |slot| {
            const epoch = coldEpoch(slot.epoch);
            try std.testing.expectEqual(@as(u64, cold_epoch_record_len), slot.covered_len);
            try std.testing.expectEqualDeep(slot.digest, coldDigest(&epoch));
        }
    }
    var plan = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
    defer plan.abort();
    const identity = stage.backing.?.plan.?.writer_identity;
    try plan.commit();
    try std.testing.expectError(error.PreparedAlreadyConsumed, plan.commit());
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqual(before_seq + 1, published.next_seq);
    try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(published.wal_file.?.handle));
    try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
    var restarted = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "cold-oom.wal", .{ .changefeed_capacity = 0 });
    defer restarted.deinit();
    try std.testing.expectEqualStrings("whole", restarted.get(.props, "new").?);
    try std.testing.expectEqualSlices(u8, published.get(.props, "old").?, restarted.get(.props, "old").?);
}

test "cold recovery exhaustive OOM retry preserves near limit and dual epoch empty cuts" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| try std.testing.checkAllAllocationFailures(std.testing.allocator, coldRecoveryAllocationScenario, .{empty});
}

test "cold recovery receipt detects same length overwrite before publication and retries" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "receipt.wal");
        defer store.deinit();
        try store.put(.props, "old", "before");
    }
    const lease = try tmp.dir.createFile(std.testing.io, "receipt.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "receipt.wal", lease, .{ .changefeed_capacity = 0 });
    defer stage.deinit();
    var plan = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "after" }});
    defer plan.abort();
    const file = try tmp.dir.openFile(std.testing.io, "receipt.wal", .{ .mode = .read_write });
    defer file.close(std.testing.io);
    var changed = try std.testing.allocator.dupe(u8, stage.backing.?.wal.bytes);
    defer std.testing.allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try file.writePositionalAll(std.testing.io, changed, 0);
    try std.testing.expectError(error.SnapshotCoverageMismatch, plan.commit());
    const observed = try tmp.dir.readFileAlloc(std.testing.io, "receipt.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(observed);
    try std.testing.expectEqualSlices(u8, changed, observed);
    try file.writePositionalAll(std.testing.io, stage.backing.?.wal.bytes, 0);
    var wrong = plan;
    wrong.generation += 1;
    try std.testing.expectError(error.PreparedAlreadyConsumed, wrong.commit());
    try plan.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("after", published.get(.props, "new").?);
}

// The S1 observation surface exports no mutable Store or original allocator.
// The closed S2 bridge below requires the canonical source-owned root protocol.
// Borrowed contexts must outlive this entire owner.
pub const SourceAccessError = error{ Busy, InvalidLease, LeaseChildren, SourceCustodyActive, IdentityExhausted, Capacity };
pub const SourceIdentity = struct { lifetime: u64, owner_revision: u64, census_revision: u64 };
/// Non-callable original std.mem.Allocator ABI/context observation. This does
/// not extend the backend object lifetime or authorize allocation/deallocation.
pub const AllocatorObservation = struct {
    context: usize,
    vtable: usize,
    fn from(a: std.mem.Allocator) AllocatorObservation {
        return .{ .context = @intFromPtr(a.ptr), .vtable = @intFromPtr(a.vtable) };
    }
};
pub const OwnedCapacityDescriptor = struct {
    source: SourceIdentity,
    kind: enum { owner_box, wal_path, snapshot_path, table_backing, live_key, live_value, feed_ring, feed_key, feed_value, retired_bytes, retired_key, retired_value, retired_table },
    locator: usize,
    requested_bytes: usize,
    alignment: usize,
    original_allocator: AllocatorObservation,
    ownership: enum { resident, retiring },
    deallocation_convention: enum { original_std_allocator } = .original_std_allocator,
};
pub const SourceCustodyView = struct {
    source: SourceIdentity,
    next_sequence: u64,
    poisoned: bool,
    owned_wal_descriptor: bool,
    owned_staged_descriptor: bool,
    borrowed_directory: @FieldType(std.Io.Dir, "handle"),
    borrowed_io_context: usize,
    borrowed_io_vtable: usize,
    // These observations do not pin the supplied directory/Io/allocator objects.
};
pub const StoreEntryView = struct { key: []const u8, value: []const u8 };

pub const StoreResourceOwner = opaque {
    pub fn borrowRead(self: *StoreResourceOwner) SourceAccessError!ReadLease {
        const b = ownerBacking(self);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        if (b.closing or b.exclusive != 0) return error.Busy;
        for (&b.reads, 0..) |*slot, i| if (slot.serial == 0) {
            const serial = try b.issue();
            slot.* = .{ .serial = serial };
            return .{ .owner = self, .lifetime = b.lifetime, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn tryAcquireExclusive(self: *StoreResourceOwner) SourceAccessError!StoreExclusive {
        const b = ownerBacking(self);
        if (!b.gate.tryLockExclusive()) return error.Busy;
        defer b.gate.unlockExclusive();
        if (b.closing or b.exclusive != 0) return error.Busy;
        for (b.reads) |slot| if (slot.serial != 0) return error.Busy;
        if (b.store.active_prepared != null or b.store.active_batch != null or b.store.staged_read_only or b.store.staged_write_file != null) return error.SourceCustodyActive;
        const serial = try b.issue();
        b.exclusive = serial;
        return .{ .owner = self, .lifetime = b.lifetime, .serial = serial };
    }
};
pub const ResourceOwner = StoreResourceOwner;

/// Slices from get/changeAt and iterator results borrow this real lease. All
/// actual users must finish before finish(); escaped slice copies are not revoked.
pub const ReadLease = struct {
    owner: *StoreResourceOwner,
    lifetime: u64,
    serial: u64,
    slot: usize,
    fn validate(self: ReadLease, b: *StoreOwnerBacking) SourceAccessError!void {
        if (b.closing or b.lifetime != self.lifetime or self.slot >= b.reads.len or self.serial == 0 or b.reads[self.slot].serial != self.serial) return error.InvalidLease;
    }
    pub fn get(self: ReadLease, family_: Family, key: []const u8) SourceAccessError!?[]const u8 {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return b.store.get(family_, key);
    }
    pub fn changeAt(self: ReadLease, index: usize) SourceAccessError!?Mutation {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return b.store.changeAt(index);
    }
    pub fn iterate(self: ReadLease, family_: Family) SourceAccessError!ReadIterator {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        for (&b.children, 0..) |*child, i| if (child.serial == 0) {
            const serial = try b.issue();
            child.* = .{ .serial = serial, .parent = self.serial, .kind = .read_iterator, .family = familyIndex(family_) };
            b.reads[self.slot].children += 1;
            return .{ .parent = self, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn finish(self: ReadLease) SourceAccessError!void {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        if (b.reads[self.slot].children != 0) return error.LeaseChildren;
        b.reads[self.slot] = .{};
    }
};
pub const ReadIterator = struct {
    parent: ReadLease,
    serial: u64,
    slot: usize,
    fn validate(self: ReadIterator, b: *StoreOwnerBacking) SourceAccessError!*StoreOwnerChild {
        try self.parent.validate(b);
        if (self.slot >= b.children.len or self.serial == 0) return error.InvalidLease;
        const child = &b.children[self.slot];
        if (child.serial != self.serial or child.parent != self.parent.serial or child.kind != .read_iterator) return error.InvalidLease;
        return child;
    }
    pub fn next(self: ReadIterator) SourceAccessError!?StoreEntryView {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const child = try self.validate(b);
        const table = &b.store.maps[child.family].map;
        while (child.index < table.slots.len) {
            const slot = table.slots[child.index];
            child.index += 1;
            if (slot.state == .used) return .{ .key = slot.key, .value = slot.value };
        }
        return null;
    }
    pub fn finish(self: ReadIterator) SourceAccessError!void {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const child = try self.validate(b);
        child.* = .{};
        b.reads[self.parent.slot].children -= 1;
    }
};
pub const StoreExclusive = struct {
    owner: *StoreResourceOwner,
    lifetime: u64,
    serial: u64,
    fn validate(self: StoreExclusive, b: *StoreOwnerBacking) SourceAccessError!void {
        if (b.closing or b.lifetime != self.lifetime or self.serial == 0 or b.exclusive != self.serial) return error.InvalidLease;
    }
    pub fn sourceState(self: StoreExclusive) SourceAccessError!SourceCustodyView {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return .{ .source = b.identity(), .next_sequence = b.store.next_seq, .poisoned = b.store.prepared_poisoned, .owned_wal_descriptor = b.store.wal_file != null, .owned_staged_descriptor = b.store.staged_write_file != null, .borrowed_directory = b.store.dir.handle, .borrowed_io_context = if (b.store.io.userdata) |ptr| @intFromPtr(ptr) else 0, .borrowed_io_vtable = @intFromPtr(b.store.io.vtable) };
    }
    pub fn catalog(self: StoreExclusive) SourceAccessError!CatalogCursor {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        for (&b.children, 0..) |*child, i| if (child.serial == 0) {
            const serial = try b.issue();
            child.* = .{ .serial = serial, .parent = self.serial, .kind = .catalog };
            b.exclusive_children += 1;
            return .{ .parent = self, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn finish(self: StoreExclusive) SourceAccessError!void {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        if (b.exclusive_children != 0) return error.LeaseChildren;
        b.exclusive = 0;
    }
};
pub const CatalogCursor = struct {
    parent: StoreExclusive,
    serial: u64,
    slot: usize,
    fn validate(self: CatalogCursor, b: *StoreOwnerBacking) SourceAccessError!*StoreOwnerChild {
        try self.parent.validate(b);
        if (self.slot >= b.children.len or self.serial == 0) return error.InvalidLease;
        const child = &b.children[self.slot];
        if (child.serial != self.serial or child.parent != self.parent.serial or child.kind != .catalog) return error.InvalidLease;
        return child;
    }
    pub fn next(self: CatalogCursor) SourceAccessError!?OwnedCapacityDescriptor {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const c = try self.validate(b);
        // Source-owned cursor advances once; a copied token cannot replay rows.
        while (true) switch (c.phase) {
            .box => {
                c.phase = .paths;
                return b.describe(.owner_box, @intFromPtr(b), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), b.metadata_allocator, .resident);
            },
            .paths => {
                const i = c.index;
                c.index += 1;
                if (i >= 2) {
                    c.phase = .tables;
                    c.index = 0;
                    continue;
                }
                const bytes = if (i == 0) b.store.wal_path else b.store.snapshot_path;
                if (bytes.len == 0) continue;
                return b.describe(if (i == 0) .wal_path else .snapshot_path, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .resident);
            },
            .tables => {
                if (c.family == family_count) {
                    c.phase = .feed_ring;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const map = &b.store.maps[c.family];
                if (c.part == 0) {
                    c.part = 1;
                    if (map.map.slots.len == 0) continue;
                    const bytes = std.math.mul(usize, map.map.slots.len, @sizeOf(KvTable.Slot)) catch return error.Capacity;
                    return b.describe(.table_backing, @intFromPtr(map.map.slots.ptr), bytes, @alignOf(KvTable.Slot), map.map.allocator, .resident);
                }
                if (c.index == map.map.slots.len) {
                    c.family += 1;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const slot = map.map.slots[c.index];
                if (slot.state != .used) {
                    c.index += 1;
                    continue;
                }
                const key = c.part == 1;
                if (key) c.part = 2 else {
                    c.part = 1;
                    c.index += 1;
                }
                const bytes = if (key) slot.key else slot.value;
                if (bytes.len == 0) continue;
                return b.describe(if (key) .live_key else .live_value, @intFromPtr(bytes.ptr), bytes.len, 1, map.allocator, .resident);
            },
            .feed_ring => {
                c.phase = .feed;
                c.index = 0;
                c.part = 0;
                const entries = b.store.changefeed.entries;
                if (entries.len == 0) continue;
                const bytes = std.math.mul(usize, entries.len, @sizeOf(?OwnedMutation)) catch return error.Capacity;
                return b.describe(.feed_ring, @intFromPtr(entries.ptr), bytes, @alignOf(?OwnedMutation), b.store.changefeed.allocator, .resident);
            },
            .feed => {
                if (c.index == b.store.changefeed.entries.len) {
                    c.phase = .retirements;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const mutation = b.store.changefeed.entries[c.index] orelse {
                    c.index += 1;
                    continue;
                };
                const key = c.part == 0;
                if (key) c.part = 1 else {
                    c.part = 0;
                    c.index += 1;
                }
                const bytes = if (key) mutation.key else mutation.value orelse continue;
                if (bytes.len == 0) continue;
                return b.describe(if (key) .feed_key else .feed_value, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.changefeed.allocator, .resident);
            },
            .retirements => {
                if (c.index == b.store.retirements.len) {
                    c.phase = .done;
                    continue;
                }
                const retired = b.store.retirements[c.index] orelse {
                    c.index += 1;
                    continue;
                };
                switch (retired) {
                    .bytes => |bytes| {
                        c.index += 1;
                        if (bytes.len == 0) continue;
                        return b.describe(.retired_bytes, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .retiring);
                    },
                    .table_slots => |slots| {
                        c.index += 1;
                        if (slots.len == 0) continue;
                        const bytes = std.math.mul(usize, slots.len, @sizeOf(KvTable.Slot)) catch return error.Capacity;
                        return b.describe(.retired_table, @intFromPtr(slots.ptr), bytes, @alignOf(KvTable.Slot), b.store.allocator, .retiring);
                    },
                    .mutation => |mutation| {
                        const key = c.part == 0;
                        if (key) c.part = 1 else {
                            c.part = 0;
                            c.index += 1;
                        }
                        const bytes = if (key) mutation.key else mutation.value orelse continue;
                        if (bytes.len == 0) continue;
                        return b.describe(if (key) .retired_key else .retired_value, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .retiring);
                    },
                }
            },
            .done => return null,
        };
    }
    pub fn finish(self: CatalogCursor) SourceAccessError!void {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const c = try self.validate(b);
        c.* = .{};
        b.exclusive_children -= 1;
    }
};

const StoreOwnerChild = struct {
    serial: u64 = 0,
    parent: u64 = 0,
    kind: enum { read_iterator, catalog } = .catalog,
    family: usize = 0,
    index: usize = 0,
    part: u8 = 0,
    phase: enum { box, paths, tables, feed_ring, feed, retirements, done } = .box,
};
const StoreOwnerBacking = struct {
    // Synchronous source reads/traversal remain under this gate; no operation
    // escapes it except slices covered by real read/child slots. No async source
    // work or caller callback exists in S1. Future work needs actual retained pins.
    gate: @import("../substrate/rwlock.zig").RwLock = .{},
    metadata_allocator: std.mem.Allocator,
    store: OroStore,
    lifetime: u64,
    owner_revision: u64 = 1,
    census_revision: u64 = 1,
    next_serial: u64 = 1,
    reads: [16]struct { serial: u64 = 0, children: usize = 0 } = @splat(.{}),
    children: [16]StoreOwnerChild = @splat(.{}),
    exclusive: u64 = 0,
    exclusive_children: usize = 0,
    closing: bool = false,
    fn identity(self: *const StoreOwnerBacking) SourceIdentity {
        return .{ .lifetime = self.lifetime, .owner_revision = self.owner_revision, .census_revision = self.census_revision };
    }
    fn issue(self: *StoreOwnerBacking) SourceAccessError!u64 {
        if (self.next_serial == std.math.maxInt(u64)) return error.IdentityExhausted;
        const serial = self.next_serial;
        self.next_serial += 1;
        return serial;
    }
    fn describe(self: *const StoreOwnerBacking, kind: @FieldType(OwnedCapacityDescriptor, "kind"), ptr: usize, len: usize, alignment: usize, a: std.mem.Allocator, ownership: @FieldType(OwnedCapacityDescriptor, "ownership")) OwnedCapacityDescriptor {
        return .{ .source = self.identity(), .kind = kind, .locator = ptr, .requested_bytes = len, .alignment = alignment, .original_allocator = AllocatorObservation.from(a), .ownership = ownership };
    }
};
var store_owner_lifetimes: std.atomic.Value(u64) = .init(1);
fn reserveStoreLifetime(counter: *std.atomic.Value(u64)) SourceAccessError!u64 {
    var current = counter.load(.monotonic);
    while (true) {
        if (current == 0 or current == std.math.maxInt(u64)) return error.IdentityExhausted;
        if (counter.cmpxchgWeak(current, current + 1, .monotonic, .monotonic)) |actual| current = actual else return current;
    }
}
fn ownerBacking(owner: *StoreResourceOwner) *StoreOwnerBacking {
    return @ptrCast(@alignCast(owner));
}
// Only this source creates the actual Store; no by-value move of an escaped Store.
fn createStoreResourceOwner(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool) !*StoreResourceOwner {
    return createStoreResourceOwnerWithCounter(metadata_allocator, store_allocator, io, dir, path, cfg, read_only, &store_owner_lifetimes);
}
fn createStoreResourceOwnerWithCounter(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool, counter: *std.atomic.Value(u64)) !*StoreResourceOwner {
    const lifetime = try reserveStoreLifetime(counter);
    return createStoreResourceOwnerReserved(metadata_allocator, store_allocator, io, dir, path, cfg, read_only, lifetime);
}
fn createStoreResourceOwnerReserved(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool, lifetime: u64) !*StoreResourceOwner {
    const b = try metadata_allocator.create(StoreOwnerBacking);
    errdefer metadata_allocator.destroy(b);
    const store = if (read_only) try OroStore.openReadOnlyWithConfig(store_allocator, io, dir, path, cfg) else try OroStore.openWithConfig(store_allocator, io, dir, path, cfg);
    b.* = .{ .metadata_allocator = metadata_allocator, .store = store, .lifetime = lifetime };
    return @ptrCast(b);
}
fn destroyStoreResourceOwner(owner: *StoreResourceOwner) SourceAccessError!void {
    const b = ownerBacking(owner);
    b.gate.lockExclusive();
    if (b.closing or b.exclusive != 0) {
        b.gate.unlockExclusive();
        return error.Busy;
    }
    for (b.reads) |slot| if (slot.serial != 0) {
        b.gate.unlockExclusive();
        return error.Busy;
    };
    if (b.store.active_prepared != null or b.store.active_batch != null or b.store.staged_write_file != null) {
        b.gate.unlockExclusive();
        return error.SourceCustodyActive;
    }
    b.closing = true;
    b.gate.unlockExclusive();
    // No public mutator/factory exists. S3 must establish real external lifetime
    // ownership before making construction/destruction reachable by live owners.
    const allocator = b.metadata_allocator;
    b.store.deinit();
    allocator.destroy(b);
}

// S2 closed source bridge. Public methods exist only for the canonical static
// Physical -> Store adapter. They never export a Store or an original backend.
pub const CreationArgs = struct {
    metadata_allocator: std.mem.Allocator,
    store_allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    config: Config,
    read_only: bool = false,
};
pub const CreationIdentity = struct {
    metadata_allocator: AllocatorObservation,
    store_allocator: AllocatorObservation,
    io_context: usize,
    io_vtable: usize,
    directory: @FieldType(std.Io.Dir, "handle"),
    path_digest: [32]u8,
    path_length: usize,
    config: Config,
    read_only: bool,
    pub fn from(args: CreationArgs) CreationIdentity {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(args.path, &digest, .{});
        return .{ .metadata_allocator = AllocatorObservation.from(args.metadata_allocator), .store_allocator = AllocatorObservation.from(args.store_allocator), .io_context = if (args.io.userdata) |p| @intFromPtr(p) else 0, .io_vtable = @intFromPtr(args.io.vtable), .directory = args.dir.handle, .path_digest = digest, .path_length = args.path.len, .config = args.config, .read_only = args.read_only };
    }
};
pub const CandidateUse = enum { packet, new_key, scratch_key, value, feed_key, feed_value, table_backing };
pub const RootKey = struct {
    pub const Position = struct { family: Family, slot: usize };
    pub const Location = union(enum) {
        bridge_box,
        owner_box,
        wal_path,
        snapshot_path,
        feed_ring,
        table_backing: Family,
        live_key: Position,
        live_value: Position,
        feed_key: usize,
        feed_value: usize,
        retired_bytes: usize,
        retired_table: usize,
        retired_key: usize,
        retired_value: usize,
    };
    source: SourceIdentity,
    location: Location,
};
pub const RootDescriptor = struct {
    key: RootKey,
    locator: usize,
    requested_bytes: usize,
    alignment: usize,
    original_allocator: AllocatorObservation,
    ownership: enum { resident, retiring },
};

pub fn ManagedBridge(comptime R: type) type {
    return struct {
        const Bridge = @This();
        const max_allocations = 1 + max_batch_mutations * 5;
        pub const Owner = opaque {
            // Captures the actual namespace, not merely aliased handle types.
            pub const ResourceNamespace = R;
            pub fn construct(c: R.StoreConstruction, args: CreationArgs) !*Owner {
                return Bridge.construct(c, args);
            }
            pub fn constructionIdentity(self: *Owner, c: R.StoreConstruction) !SourceIdentity {
                if (try R.resolveConstructingStore(c) != self) return error.InvalidLease;
                return Bridge.backing(self).sourceIdentity();
            }
            pub fn bindConstructed(self: *Owner, c: R.StoreConstruction, id: R.StoreOwnerId) !void {
                if (try R.resolveConstructingStore(c) != self or try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                const b = Bridge.backing(self);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                if (b.id != null) return error.InvalidLease;
                b.id = id;
            }
            pub fn abortConstruction(self: *Owner, c: R.StoreConstruction) !void {
                try R.beginAbortStoreConstruction(c, self);
                const b = Bridge.backing(self);
                try b.checkIdle(false);
                if (b.exclusive) |x| try x.finish();
                const a = b.metadata_allocator;
                try destroyStoreResourceOwner(b.source);
                a.destroy(b);
            }
            pub fn borrowRead(self: *Owner, id: R.StoreOwnerId) !ReadLease {
                if (try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                return Bridge.backing(self).source.borrowRead();
            }
            pub fn acquireExclusive(self: *Owner, id: R.StoreOwnerId) !Exclusive {
                if (try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                const b = Bridge.backing(self);
                const sb = ownerBacking(b.source);
                if (!sb.gate.tryLockExclusive()) return error.Busy;
                if (b.id == null or !std.meta.eql(b.id.?, id) or b.exclusive != null or b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                sb.gate.unlockExclusive();
                const x = try b.source.tryAcquireExclusive();
                sb.gate.lockExclusive();
                // The root serializes this source; another entrant still must
                // not replace a genuine exclusion after the short gate gap.
                if (b.exclusive != null) {
                    sb.gate.unlockExclusive();
                    try x.finish();
                    return error.Busy;
                }
                b.exclusive = x;
                sb.gate.unlockExclusive();
                return .{ .source = self, .id = id, .serial = x.serial, .lifetime = x.lifetime };
            }
            pub fn catalog(self: *Owner, x: Exclusive) !Catalog {
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.catalog_serial != 0 or b.operation_active or b.candidate != null) return error.Busy;
                const serial = try sb.issue();
                b.catalog_serial = serial;
                b.cursor = .{};
                return .{ .source = self, .exclusion = x, .serial = serial };
            }
            pub fn beginCandidate(self: *Owner, x: Exclusive, loan: R.ParticipantLoan) !Candidate {
                if (try R.resolveIssuedStore(loan) != self) return error.InvalidLease;
                const limit = try R.storeWorkLimit(loan);
                if (limit == 0 or limit == std.math.maxInt(u64)) return error.TableWorkExceeded;
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.operation_active or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                if (sb.store.prepared_poisoned) return error.StorePoisoned;
                if (sb.store.staged_read_only) return error.ReadOnlyStore;
                if (sb.store.active_prepared != null or sb.store.active_batch != null or sb.store.staged_write_file != null) return error.SourceCustodyActive;
                if (b.last_transaction == loan.transaction) return error.InvalidLease;
                const serial = try sb.issue();
                b.work = .{ .limit = limit };
                b.candidate = .{ .serial = serial, .loan = loan, .source = sb.identity() };
                b.last_transaction = loan.transaction;
                return .{ .source = self, .serial = serial, .lifetime = sb.lifetime, .transaction = loan.transaction, .loan = loan };
            }
            pub fn prepareBatch(self: *Owner, c: Candidate, mutations: []const BatchMutation) !void {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateCandidate(c) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.operation_active or b.candidate.?.state != .reserved) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                b.operation_active = true;
                b.candidate.?.state = .preparing;
                sb.gate.unlockExclusive();
                errdefer {
                    sb.gate.lockExclusive();
                    b.candidate.?.state = .failed;
                    b.operation_active = false;
                    sb.gate.unlockExclusive();
                }
                try b.prepare(mutations);
                sb.gate.lockExclusive();
                b.candidate.?.state = .prepared;
                b.operation_active = false;
                sb.gate.unlockExclusive();
            }
            pub fn inspectCandidate(self: *Owner, c: Candidate) !CandidateView {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active) return error.Busy;
                return .{ .source = b.sourceIdentity(), .serial = c.serial, .state = b.candidate.?.state, .allocation_count = b.candidate.?.allocation_count, .work_used = b.work.total, .work_limit = b.work.limit, .mutation_count = b.candidate.?.count };
            }
            pub fn inspectCandidateAllocation(self: *Owner, c: Candidate, index: usize) !?CandidateAllocation {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active) return error.Busy;
                if (index >= b.candidate.?.allocation_count) return null;
                const a = b.candidate.?.allocations[index];
                return .{ .use = a.use, .locator = @intFromPtr(a.bytes.ptr), .requested_bytes = a.bytes.len, .alignment = a.alignment.toByteUnits(), .id = a.id, .role = a.role };
            }
            pub fn abortPreAttempt(self: *Owner, c: Candidate) !void {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateCandidate(c) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                b.operation_active = true;
                sb.gate.unlockExclusive();
                // The root retains issued homes until this real source abort.
                // A genuine Plan abort frees through its captured private table
                // facade, which removes that exact NEW root from the ledger.
                // Other partial allocations, including binding failures, remain
                // owned until the reverse ledger cleanup below.
                const active = &b.candidate.?;
                for (&active.plans) |*p| if (p.*) |*plan| {
                    plan.abort();
                };
                var n = active.allocation_count;
                while (n != 0) {
                    n -= 1;
                    const a = active.allocations[n];
                    a.allocator.rawFree(a.bytes, a.alignment, @returnAddress());
                }
                sb.gate.lockExclusive();
                b.candidate = null;
                b.operation_active = false;
                sb.gate.unlockExclusive();
            }
            pub fn inspectQuiescence(self: *Owner, x: Exclusive) !QuiescenceView {
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.operation_active) return error.Busy;
                var readers: usize = 0;
                for (sb.reads) |slot| if (slot.serial != 0) {
                    readers += 1;
                };
                return .{ .source = sb.identity(), .candidate_active = b.candidate != null, .catalog_active = b.catalog_serial != 0, .ordinary_active = sb.store.active_prepared != null or sb.store.active_batch != null, .staged_active = sb.store.staged_read_only or sb.store.staged_write_file != null, .readers = readers, .poisoned = sb.store.prepared_poisoned };
            }
            pub fn inspectPendingFree(self: *Owner, d: R.StoreDestruction) !?RootDescriptor {
                if (try R.resolveDestroyingStore(d) != self) return error.InvalidLease;
                return Bridge.backing(self).pending_free;
            }
            pub fn destroyRegistered(self: *Owner, d: R.StoreDestruction) !void {
                try R.beginStoreDestruction(d, self);
                const b = Bridge.backing(self);
                try b.checkIdle(true);
                const sb = ownerBacking(b.source);
                // External root ownership has joined all callers/waiters. These
                // checks are source quiescence, not that external lifetime proof.
                if (b.exclusive) |x| {
                    try x.finish();
                    b.exclusive = null;
                }
                sb.gate.lockExclusive();
                if (sb.exclusive != 0 or sb.closing) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                for (sb.reads) |slot| if (slot.serial != 0) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                };
                sb.closing = true;
                sb.gate.unlockExclusive();
                if (sb.store.wal_file) |f| {
                    f.close(sb.store.io);
                    sb.store.wal_file = null;
                }
                if (sb.store.staged_write_file) |f| {
                    f.close(sb.store.io);
                    sb.store.staged_write_file = null;
                }
                // No cursor escapes; all roots still exist while descriptors
                // are derived. Destructive detach occurs only after root has
                // prevalidated this entire exact graph.
                var cursor: Cursor = .{};
                // Wrapper boxes are deliberately delayed until every payload.
                _ = b.nextRoot(&cursor); // bridge box
                _ = b.nextRoot(&cursor); // source box
                while (b.nextRoot(&cursor)) |descriptor| {
                    try b.detach(descriptor.key);
                    b.pending_free = descriptor;
                    try R.freeStoreRoot(d, self, descriptor.key);
                    b.pending_free = null;
                }
                const owner_descriptor = b.descriptor(.owner_box, @intFromPtr(sb), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), sb.metadata_allocator, .resident);
                b.pending_free = owner_descriptor;
                try R.freeStoreRoot(d, self, owner_descriptor.key);
                // No source pointer dereference follows its actual free.
                const bridge_descriptor = RootDescriptor{ .key = .{ .source = owner_descriptor.key.source, .location = .bridge_box }, .locator = @intFromPtr(b), .requested_bytes = @sizeOf(Backing), .alignment = @alignOf(Backing), .original_allocator = AllocatorObservation.from(b.metadata_allocator), .ownership = .resident };
                b.pending_free = bridge_descriptor;
                try R.freeStoreRoot(d, self, bridge_descriptor.key);
                // Both boxes have been freed; do not clear state or defer unlock.
            }
        };
        pub const Exclusive = struct {
            source: *Owner,
            id: R.StoreOwnerId,
            serial: u64,
            lifetime: u64,
            pub fn finish(self: Exclusive) !void {
                const b = try Bridge.resolveExclusive(self.source, self);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateExclusive(self) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.catalog_serial != 0 or b.candidate != null or b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                const x = b.exclusive.?;
                sb.gate.unlockExclusive();
                try x.finish();
                sb.gate.lockExclusive();
                b.exclusive = null;
                sb.gate.unlockExclusive();
            }
        };
        pub const Catalog = struct {
            source: *Owner,
            exclusion: Exclusive,
            serial: u64,
            pub fn next(self: Catalog) !?RootDescriptor {
                const b = try Bridge.resolveExclusive(self.source, self.exclusion);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(self.exclusion);
                if (b.catalog_serial != self.serial or self.serial == 0) return error.InvalidLease;
                return b.nextRoot(&b.cursor);
            }
            pub fn finish(self: Catalog) !void {
                const b = try Bridge.resolveExclusive(self.source, self.exclusion);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(self.exclusion);
                if (b.catalog_serial != self.serial or self.serial == 0) return error.InvalidLease;
                b.catalog_serial = 0;
            }
        };
        pub const Candidate = struct { source: *Owner, serial: u64, lifetime: u64, transaction: u64, loan: R.ParticipantLoan };
        pub const CandidateState = enum { reserved, preparing, prepared, failed };
        pub const CandidateView = struct { source: SourceIdentity, serial: u64, state: CandidateState, allocation_count: usize, work_used: u64, work_limit: u64, mutation_count: usize };
        pub const CandidateAllocation = struct { use: CandidateUse, locator: usize, requested_bytes: usize, alignment: usize, id: ?R.AllocationId, role: R.RoleId };
        pub const QuiescenceView = struct { source: SourceIdentity, candidate_active: bool, catalog_active: bool, ordinary_active: bool, staged_active: bool, readers: usize, poisoned: bool };
        pub const TestFixture = if (@import("builtin").is_test) struct {
            pub fn seedPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                if (b.exclusive != null or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                try seedOwnerForCensus(b.source);
            }
            pub fn seedRetirementSlotsPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                if (b.exclusive != null or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                const s = &ownerBacking(b.source).store;
                if (s.retirement_count != 0) return error.SourceCustodyActive;
                for (0..s.retirements.len) |i| switch (i % 3) {
                    0 => {
                        const bytes_ = try s.allocator.dupe(u8, "retired bytes");
                        s.retireBytes(bytes_);
                    },
                    1 => {
                        const mutation = try OwnedMutation.from(s.allocator, .{ .seq = 1, .family = .props, .kind = .put, .key = "retired key", .value = "retired value" });
                        s.retireMutation(mutation);
                    },
                    else => {
                        const slots = try s.allocator.alloc(KvTable.Slot, 8);
                        @memset(slots, .{});
                        s.retireTable(slots);
                    },
                };
            }
            pub fn poisonPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                ownerBacking(Bridge.backing(source).source).store.prepared_poisoned = true;
            }
            pub fn armOrdinaryPut(source: *Owner, c: R.StoreConstruction) !PreparedPut {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                return ownerBacking(Bridge.backing(source).source).store.preparePut(.props, "ordinary", "candidate");
            }
            pub fn requireOwnedCandidate(source: *Owner, c: Candidate, expected: []const BatchMutation) !void {
                const b = try Bridge.resolveCandidate(source, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active or b.candidate.?.state != .prepared) return error.Busy;
                const active = &b.candidate.?;
                try std.testing.expectEqual(expected.len, active.count);
                const record = active.record.?;
                const outer = record[batch_guard_len..];
                try std.testing.expectEqual(readU32(outer[4..8]), checksum(outer[record_header_len..]));
                var decoded: [max_batch_mutations]BatchMutation = undefined;
                try std.testing.expectEqual(expected.len, try decodeBatch(outer[record_header_len..], &decoded));
                for (expected, decoded[0..expected.len], active.entries[0..expected.len]) |want, wire, entry| {
                    try std.testing.expectEqual(want.family, wire.family);
                    try std.testing.expectEqual(want.kind, wire.kind);
                    try std.testing.expectEqualStrings(want.key, wire.key);
                    try std.testing.expectEqualStrings(want.key, entry.key.?);
                    if (want.value) |v| {
                        try std.testing.expectEqualStrings(v, wire.value.?);
                        try std.testing.expectEqualStrings(v, entry.value.?);
                    }
                    if (entry.change) |feed| {
                        try std.testing.expectEqualStrings(want.key, feed.key);
                        if (want.value) |v| try std.testing.expectEqualStrings(v, feed.value.?);
                    }
                }
            }
            pub fn observe(source: *Owner, id: R.StoreOwnerId) !struct { source: SourceIdentity, next_sequence: u64, wal_offset: u64, wal_epoch: [16]u8, retirement_count: usize, feed_count: usize, memory_digest: [32]u8, table_backings: [family_count]usize, table_lengths: [family_count]usize, table_revisions: [family_count]u64 } {
                if (try R.resolveStoreOwner(id) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                var h = std.crypto.hash.Blake3.init(.{});
                for (sb.store.maps) |m| for (m.map.slots) |slot| {
                    KvTable.hashNumber(&h, @intFromEnum(slot.state));
                    if (slot.state == .used) {
                        KvTable.hashSlotPointers(&h, slot);
                        h.update(slot.key);
                        h.update(slot.value);
                    }
                };
                KvTable.hashNumber(&h, sb.store.changefeed.start);
                KvTable.hashNumber(&h, sb.store.changefeed.count);
                for (sb.store.changefeed.entries) |entry| {
                    KvTable.hashNumber(&h, @intFromBool(entry != null));
                    if (entry) |m| {
                        KvTable.hashNumber(&h, m.seq);
                        KvTable.hashNumber(&h, @intFromEnum(m.family));
                        KvTable.hashNumber(&h, @intFromEnum(m.kind));
                        h.update(m.key);
                        if (m.value) |v| h.update(v);
                    }
                }
                var digest: [32]u8 = undefined;
                h.final(&digest);
                var ptrs: [family_count]usize = undefined;
                var lengths: [family_count]usize = undefined;
                var revisions: [family_count]u64 = undefined;
                for (sb.store.maps, 0..) |m, i| {
                    ptrs[i] = @intFromPtr(m.map.slots.ptr);
                    lengths[i] = m.map.slots.len;
                    revisions[i] = m.map.revision;
                }
                return .{ .source = sb.identity(), .next_sequence = sb.store.next_seq, .wal_offset = sb.store.wal_offset, .wal_epoch = sb.store.wal_epoch, .retirement_count = sb.store.retirement_count, .feed_count = sb.store.changefeed.count, .memory_digest = digest, .table_backings = ptrs, .table_lengths = lengths, .table_revisions = revisions };
            }
        } else void;
        const Cursor = struct { phase: enum { bridge, box, paths, tables, ring, feed, retiring, done } = .bridge, family: usize = 0, slot: usize = 0, part: usize = 0 };
        const Allocation = struct { use: CandidateUse, bytes: []u8, alignment: std.mem.Alignment, allocator: std.mem.Allocator, role: R.RoleId, id: ?R.AllocationId = null };
        const ManagedCandidate = struct {
            serial: u64,
            loan: R.ParticipantLoan,
            source: SourceIdentity,
            state: CandidateState = .reserved,
            entries: [max_batch_mutations]BatchEntry = undefined,
            count: usize = 0,
            record: ?[]u8 = null,
            plans: [family_count]?KvTable.Plan = @splat(null),
            allocations: [max_allocations]Allocation = undefined,
            allocation_count: usize = 0,
        };
        const Backing = struct {
            metadata_allocator: std.mem.Allocator,
            source: *StoreResourceOwner,
            id: ?R.StoreOwnerId = null,
            exclusive: ?StoreExclusive = null,
            catalog_serial: u64 = 0,
            cursor: Cursor = .{},
            candidate: ?ManagedCandidate = null,
            work: KvTable.Work = .{},
            operation_active: bool = false,
            last_transaction: u64 = 0,
            table_allocation_error: ?anyerror = null,
            pending_free: ?RootDescriptor = null,
            fn sourceIdentity(self: *Backing) SourceIdentity {
                return ownerBacking(self.source).identity();
            }
            fn validateExclusive(self: *Backing, x: Exclusive) !void {
                const saved = self.exclusive orelse return error.InvalidLease;
                if (x.serial != saved.serial or x.lifetime != saved.lifetime or self.id == null or !std.meta.eql(self.id.?, x.id)) return error.InvalidLease;
                try saved.validate(ownerBacking(self.source));
            }
            fn validateCandidate(self: *Backing, c: Candidate) !void {
                const active = if (self.candidate) |*a| a else return error.InvalidLease;
                if (c.lifetime != active.source.lifetime or c.serial != active.serial or c.transaction != active.loan.transaction or !std.meta.eql(c.loan, active.loan) or !std.meta.eql(active.source, self.sourceIdentity())) return error.InvalidLease;
            }
            fn checkIdle(self: *Backing, reject_readonly: bool) !void {
                const sb = ownerBacking(self.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                if (self.operation_active or self.candidate != null or self.catalog_serial != 0 or sb.exclusive_children != 0) return error.Busy;
                if (sb.store.active_prepared != null or sb.store.active_batch != null or (reject_readonly and sb.store.staged_read_only) or sb.store.staged_write_file != null) return error.SourceCustodyActive;
                for (sb.reads) |slot| if (slot.serial != 0) return error.Busy;
            }
            fn descriptor(self: *Backing, location: RootKey.Location, ptr: usize, len: usize, alignment: usize, a: std.mem.Allocator, ownership: @FieldType(RootDescriptor, "ownership")) RootDescriptor {
                return .{ .key = .{ .source = self.sourceIdentity(), .location = location }, .locator = ptr, .requested_bytes = len, .alignment = alignment, .original_allocator = AllocatorObservation.from(a), .ownership = ownership };
            }
            fn nextRoot(self: *Backing, cursor: *Cursor) ?RootDescriptor {
                const sb = ownerBacking(self.source);
                const s = &sb.store;
                while (true) switch (cursor.phase) {
                    .bridge => {
                        cursor.phase = .box;
                        return self.descriptor(.bridge_box, @intFromPtr(self), @sizeOf(Backing), @alignOf(Backing), self.metadata_allocator, .resident);
                    },
                    .box => {
                        cursor.phase = .paths;
                        return self.descriptor(.owner_box, @intFromPtr(sb), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), sb.metadata_allocator, .resident);
                    },
                    .paths => {
                        const n = cursor.slot;
                        cursor.slot += 1;
                        if (n >= 2) {
                            cursor.phase = .tables;
                            cursor.slot = 0;
                            continue;
                        }
                        const bytes = if (n == 0) s.wal_path else s.snapshot_path;
                        if (bytes.len != 0) return self.descriptor(if (n == 0) .wal_path else .snapshot_path, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .resident);
                    },
                    .tables => {
                        if (cursor.family == family_count) {
                            cursor.phase = .feed;
                            cursor.slot = 0;
                            cursor.part = 0;
                            continue;
                        }
                        const family_ = families[cursor.family];
                        const map = &s.maps[cursor.family];
                        if (cursor.part == 0) cursor.part = 1;
                        if (cursor.slot == map.map.slots.len) {
                            cursor.family += 1;
                            cursor.slot = 0;
                            cursor.part = 0;
                            if (map.map.slots.len != 0) return self.descriptor(.{ .table_backing = family_ }, @intFromPtr(map.map.slots.ptr), map.map.slots.len * @sizeOf(KvTable.Slot), @alignOf(KvTable.Slot), map.map.allocator, .resident);
                            continue;
                        }
                        const i = cursor.slot;
                        const slot = map.map.slots[i];
                        if (slot.state != .used) {
                            cursor.slot += 1;
                            cursor.part = 1;
                            continue;
                        }
                        const key = cursor.part == 1;
                        if (key) cursor.part = 2 else {
                            cursor.part = 1;
                            cursor.slot += 1;
                        }
                        const bytes = if (key) slot.key else slot.value;
                        if (bytes.len != 0) return self.descriptor(if (key) .{ .live_key = .{ .family = family_, .slot = i } } else .{ .live_value = .{ .family = family_, .slot = i } }, @intFromPtr(bytes.ptr), bytes.len, 1, map.allocator, .resident);
                    },
                    .ring => {
                        cursor.phase = .retiring;
                        if (s.changefeed.entries.len != 0) return self.descriptor(.feed_ring, @intFromPtr(s.changefeed.entries.ptr), s.changefeed.entries.len * @sizeOf(?OwnedMutation), @alignOf(?OwnedMutation), s.changefeed.allocator, .resident);
                    },
                    .feed => {
                        if (cursor.slot == s.changefeed.entries.len) {
                            cursor.phase = .ring;
                            cursor.slot = 0;
                            cursor.part = 0;
                            continue;
                        }
                        const i = cursor.slot;
                        const m = s.changefeed.entries[i] orelse {
                            cursor.slot += 1;
                            cursor.part = 0;
                            continue;
                        };
                        const key = cursor.part == 0;
                        if (key) cursor.part = 1 else {
                            cursor.part = 0;
                            cursor.slot += 1;
                        }
                        const bytes = if (key) m.key else m.value orelse continue;
                        if (bytes.len != 0) return self.descriptor(if (key) .{ .feed_key = i } else .{ .feed_value = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.changefeed.allocator, .resident);
                    },
                    .retiring => {
                        if (cursor.slot == s.retirements.len) {
                            cursor.phase = .done;
                            continue;
                        }
                        const i = cursor.slot;
                        const r = s.retirements[i] orelse {
                            cursor.slot += 1;
                            cursor.part = 0;
                            continue;
                        };
                        switch (r) {
                            .bytes => |bytes| {
                                cursor.slot += 1;
                                if (bytes.len != 0) return self.descriptor(.{ .retired_bytes = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .retiring);
                            },
                            .table_slots => |slots| {
                                cursor.slot += 1;
                                if (slots.len != 0) return self.descriptor(.{ .retired_table = i }, @intFromPtr(slots.ptr), slots.len * @sizeOf(KvTable.Slot), @alignOf(KvTable.Slot), s.allocator, .retiring);
                            },
                            .mutation => |m| {
                                const key = cursor.part == 0;
                                if (key) cursor.part = 1 else {
                                    cursor.part = 0;
                                    cursor.slot += 1;
                                }
                                const bytes = if (key) m.key else m.value orelse continue;
                                if (bytes.len != 0) return self.descriptor(if (key) .{ .retired_key = i } else .{ .retired_value = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .retiring);
                            },
                        }
                    },
                    .done => return null,
                };
            }
            fn detach(self: *Backing, key: RootKey) !void {
                if (!std.meta.eql(key.source, self.sourceIdentity())) return error.InvalidLease;
                const s = &ownerBacking(self.source).store;
                switch (key.location) {
                    .wal_path => s.wal_path = &.{},
                    .snapshot_path => s.snapshot_path = &.{},
                    .table_backing => |f| s.maps[familyIndex(f)].map.slots = &.{},
                    .live_key => |p| s.maps[familyIndex(p.family)].map.slots[p.slot].key = &.{},
                    .live_value => |p| s.maps[familyIndex(p.family)].map.slots[p.slot].value = &.{},
                    .feed_ring => s.changefeed.entries = &.{},
                    .feed_key => |i| s.changefeed.entries[i].?.key = &.{},
                    .feed_value => |i| s.changefeed.entries[i].?.value = null,
                    .retired_bytes, .retired_table => |i| s.retirements[i] = null,
                    .retired_key => |i| s.retirements[i].?.mutation.key = &.{},
                    .retired_value => |i| s.retirements[i].?.mutation.value = null,
                    .bridge_box, .owner_box => return error.InvalidLease,
                }
            }
            fn remember(self: *Backing, purpose: CandidateUse, bytes: []u8, alignment: std.mem.Alignment, allocator: std.mem.Allocator, binding: R.StoreAllocationBinding) !void {
                if (bytes.len == 0) return;
                const c = &self.candidate.?;
                std.debug.assert(c.allocation_count < c.allocations.len);
                const i = c.allocation_count;
                c.allocation_count += 1;
                c.allocations[i] = .{ .use = purpose, .bytes = bytes, .alignment = alignment, .allocator = allocator, .role = binding.role };
                const id = try binding.scope.allocationId(bytes, alignment);
                c.allocations[i].id = id;
                try c.loan.bindNewAllocation(id, binding.role);
            }
            fn allocateBytes(self: *Backing, purpose: CandidateUse, len: usize) ![]u8 {
                try self.work.charge(&self.work.bytes, len);
                if (len == 0) return &.{}; // No positive allocation or role is required.
                const binding = try R.storeAllocationBinding(self.candidate.?.loan, purpose);
                const allocator = try binding.scope.allocator();
                const result = try allocator.alloc(u8, len);
                try self.remember(purpose, result, .@"1", allocator, binding);
                return result;
            }
            fn copy(self: *Backing, purpose: CandidateUse, input: []const u8) ![]u8 {
                const result = try self.allocateBytes(purpose, input.len);
                try self.work.charge(&self.work.bytes, input.len);
                @memcpy(result, input);
                return result;
            }
            // Lazy PRIVATE table facade: sparse plans need no table role or
            // allocation. Growth resolves the canonical funded role only at
            // its actual allocation, after the table core charged its Work.
            fn tableAllocator(self: *Backing) std.mem.Allocator {
                return .{ .ptr = self, .vtable = &.{ .alloc = tableAlloc, .resize = tableResize, .remap = tableRemap, .free = tableFree } };
            }
            fn tableAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
                const self: *Backing = @ptrCast(@alignCast(ctx));
                const binding = R.storeAllocationBinding(self.candidate.?.loan, .table_backing) catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                const allocator = binding.scope.allocator() catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                const ptr = allocator.rawAlloc(len, alignment, ret_addr) orelse return null;
                self.remember(.table_backing, ptr[0..len], alignment, allocator, binding) catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                return ptr;
            }
            fn tableResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
                return false;
            }
            fn tableRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
                return null;
            }
            fn tableFree(ctx: *anyopaque, bytes_: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
                const self: *Backing = @ptrCast(@alignCast(ctx));
                const c = &self.candidate.?;
                for (c.allocations[0..c.allocation_count], 0..) |a, i| if (a.use == .table_backing and a.bytes.ptr == bytes_.ptr and a.bytes.len == bytes_.len and a.alignment == alignment) {
                    a.allocator.rawFree(bytes_, alignment, ret_addr);
                    c.allocation_count -= 1;
                    c.allocations[i] = c.allocations[c.allocation_count];
                    return;
                };
                unreachable; // A table may free only its source-owned backing.
            }
            fn prepare(self: *Backing, mutations: []const BatchMutation) !void {
                const c = &self.candidate.?;
                const s = &ownerBacking(self.source).store;
                if (mutations.len == 0 or mutations.len > max_batch_mutations) return error.BadRecord;
                var payload_len: usize = 3;
                for (mutations, 0..) |m, i| {
                    if ((m.kind == .put) != (m.value != null)) return error.BadRecord;
                    for (mutations[0..i]) |prior| if (m.family == prior.family and try self.work.compare(m.key, prior.key)) return error.BadRecord;
                    const part = try checkedPayloadLen(m.kind, m.key, m.value orelse "", s.cfg.max_record_bytes);
                    payload_len = std.math.add(usize, payload_len, 4 + part) catch return error.RecordTooLarge;
                    try s.maps[familyIndex(m.family)].map.checkRevision();
                }
                if (payload_len > s.cfg.max_record_bytes or payload_len > std.math.maxInt(u32)) return error.RecordTooLarge;
                _ = std.math.add(u64, s.next_seq, mutations.len) catch return error.SequenceExhausted;
                const record_len = std.math.add(usize, batch_guard_len + record_header_len, payload_len) catch return error.RecordTooLarge;
                const final_offset = std.math.add(u64, s.wal_offset, record_len) catch return error.RecordTooLarge;
                if (final_offset > s.cfg.max_wal_bytes) return error.RecordTooLarge;
                const record = try self.allocateBytes(.packet, record_len);
                c.record = record;
                try self.work.charge(&self.work.bytes, record_len);
                encodeBatchGuard(record[0..batch_guard_len]);
                const outer = record[batch_guard_len..];
                writeU32(outer[0..4], @intCast(payload_len));
                const payload = outer[record_header_len..];
                payload[0] = meta_kind_batch;
                payload[1] = batch_format_version;
                payload[2] = @intCast(mutations.len);
                var offset: usize = 3;
                for (mutations, 0..) |m, i| {
                    const part = try checkedPayloadLen(m.kind, m.key, m.value orelse "", s.cfg.max_record_bytes);
                    writeU32(payload[offset..][0..4], @intCast(part));
                    offset += 4;
                    encodeMutation(payload[offset..][0..part], m);
                    offset += part;
                    c.entries[i] = .{ .family = m.family, .kind = m.kind };
                    c.count += 1;
                    const e = &c.entries[i];
                    const table = &s.maps[familyIndex(m.family)].map;
                    const old = try table.find(m.key, &self.work);
                    if (old) |index| {
                        e.old_key = @constCast(table.slots[index].key);
                        e.old_value = table.slots[index].value;
                    }
                    e.key = try self.copy(if (m.kind == .put and old == null) .new_key else .scratch_key, m.key);
                    if (m.value) |v| e.value = try self.copy(.value, v);
                    if (s.changefeed.entries.len != 0) {
                        // Independent payload ownership, not views into FINAL.
                        e.change = .{ .seq = s.next_seq + i, .family = m.family, .kind = m.kind, .key = &.{}, .value = null };
                        e.change.?.key = try self.copy(.feed_key, m.key);
                        if (m.value) |v| e.change.?.value = try self.copy(.feed_value, v);
                    }
                }
                for (0..family_count) |f| {
                    var edits: [max_batch_mutations]KvTable.Edit = undefined;
                    var n: usize = 0;
                    for (c.entries[0..c.count]) |e| if (familyIndex(e.family) == f) {
                        edits[n] = .{ .key = e.key.?, .value = e.value };
                        n += 1;
                    };
                    if (n == 0) continue;
                    self.table_allocation_error = null;
                    c.plans[f] = s.maps[f].map.prepareWithStorage(edits[0..n], self.tableAllocator(), &self.work) catch |err| return self.table_allocation_error orelse err;
                }
                try self.work.charge(&self.work.bytes, payload.len);
                writeU32(outer[4..8], checksum(payload));
                for (&c.plans) |*p| if (p.*) |*plan| try plan.validate();
            }
        };
        fn backing(source: *Owner) *Backing {
            return @ptrCast(@alignCast(source));
        }
        pub fn construct(c: R.StoreConstruction, args: CreationArgs) !*Owner {
            try R.beginStoreConstruction(c, CreationIdentity.from(args));
            const lifetime = try reserveStoreLifetime(&store_owner_lifetimes);
            const b = try args.metadata_allocator.create(Backing);
            errdefer args.metadata_allocator.destroy(b);
            const source = try createStoreResourceOwnerReserved(args.metadata_allocator, args.store_allocator, args.io, args.dir, args.path, args.config, args.read_only, lifetime);
            b.* = .{ .metadata_allocator = args.metadata_allocator, .source = source };
            return @ptrCast(b);
        }
        fn resolveExclusive(source: *Owner, x: Exclusive) !*Backing {
            if (x.source != source or try R.resolveStoreOwner(x.id) != source) return error.InvalidLease;
            return backing(source);
        }
        fn resolveCandidate(source: *Owner, c: Candidate) !*Backing {
            if (c.source != source) return error.InvalidLease;
            // A copied token is not allowed to reinterpret an arbitrary address.
            // Resolve the actual private registered source via its original loan.
            // Candidate's root id is retained by backing; first validate known
            // owner from the public source association without following c.source.
            const known = try R.resolveIssuedStore(c.loan);
            if (known != source) return error.InvalidLease;
            return backing(source); // Candidate fields are checked under its metadata gate.
        }
    };
}

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

/// Source-owned open-addressed table. Payloads belong to KvMap/its prepared
/// owner; backing owns only slots. Deletion never relocates another key.
const KvTable = struct {
    const Self = @This();
    const max_edits = max_batch_mutations * 2;
    const State = enum(u8) { free, used, tombstone };
    const Slot = struct {
        state: State = .free,
        hash: u64 = 0,
        key: []const u8 = &.{},
        value: []u8 = &.{},
    };
    const Entry = struct { key_ptr: *[]const u8, value_ptr: *[]u8 };
    const GetOrPut = struct { key_ptr: *[]const u8, value_ptr: *[]u8, found_existing: bool };
    const Iterator = struct {
        table: *const Self,
        index: usize = 0,
        pub fn next(self: *Iterator) ?Entry {
            while (self.index < self.table.slots.len) {
                const i = self.index;
                self.index += 1;
                if (self.table.slots[i].state == .used) {
                    const slot = @constCast(&self.table.slots[i]);
                    return .{ .key_ptr = &slot.key, .value_ptr = &slot.value };
                }
            }
            return null;
        }
    };
    const Work = struct {
        probes: u64 = 0,
        comparisons: u64 = 0,
        rows: u64 = 0,
        bytes: u64 = 0,
        rebuilt_bytes: u64 = 0,
        total: u64 = 0,
        limit: u64 = std.math.maxInt(u64),
        fn charge(self: *Work, counter: *u64, n: usize) !void {
            const next = std.math.add(u64, self.total, n) catch return StoreError.TableWorkExceeded;
            if (next > self.limit) return StoreError.TableWorkExceeded;
            counter.* = std.math.add(u64, counter.*, n) catch return StoreError.TableWorkExceeded;
            self.total = next;
        }
        fn compare(self: *Work, a: []const u8, b: []const u8) !bool {
            try self.charge(&self.comparisons, 1);
            if (a.len != b.len) return false;
            try self.charge(&self.bytes, a.len);
            return std.mem.eql(u8, a, b);
        }
    };
    const Edit = struct { key: []const u8, value: ?[]u8 };
    const Patch = struct { index: usize, before: Slot, after: Slot, before_digest: [32]u8, after_digest: [32]u8 };
    /// Private bounded candidate: source owner owns all borrowed payloads. Its
    /// detached backing is freed without touching any borrowed OLD payload.
    const Plan = struct {
        owner: *Self,
        expected_slots: []Slot,
        expected_count: u32,
        expected_tombstones: u32,
        expected_revision: u64,
        patches: [max_edits]Patch = undefined,
        patch_count: usize = 0,
        replacement: ?[]Slot = null,
        replacement_digest: [32]u8 = undefined,
        final_count: u32,
        final_tombstones: u32,
        work: Work,
        shared_work: ?*Work = null,
        replacement_allocator: std.mem.Allocator,
        edits: [max_edits]Edit = undefined,
        edit_count: usize = 0,
        edit_digest: [32]u8 = undefined,
        seal: [32]u8 = undefined,
        done: bool = false,

        fn workAccount(self: *Plan) *Work {
            return self.shared_work orelse &self.work;
        }

        fn at(self: *Plan, index: usize) !Slot {
            for (self.patches[0..self.patch_count]) |patch| {
                try self.workAccount().charge(&self.workAccount().comparisons, 1);
                if (patch.index == index) return patch.after;
            }
            return self.expected_slots[index];
        }
        fn set(self: *Plan, index: usize, after: Slot) !void {
            for (self.patches[0..self.patch_count]) |*patch| {
                try self.workAccount().charge(&self.workAccount().comparisons, 1);
                if (patch.index == index) {
                    patch.after = after;
                    patch.after_digest = try slotDigest(after, self.workAccount());
                    return;
                }
            }
            if (self.patch_count == max_edits) return StoreError.InvalidTablePlan;
            const before = self.expected_slots[index];
            self.patches[self.patch_count] = .{ .index = index, .before = before, .after = after, .before_digest = try slotDigest(before, self.workAccount()), .after_digest = try slotDigest(after, self.workAccount()) };
            self.patch_count += 1;
        }
        fn insertion(self: *Plan, hash: u64, key: []const u8) !usize {
            const cap = self.expected_slots.len;
            if (cap == 0) return StoreError.InvalidTablePlan;
            var tombstone: ?usize = null;
            for (0..cap) |probe| {
                try self.workAccount().charge(&self.workAccount().probes, 1);
                const index = (@as(usize, @truncate(hash)) +% probe) & (cap - 1);
                const slot = try self.at(index);
                switch (slot.state) {
                    .free => return tombstone orelse index,
                    .tombstone => if (tombstone == null) {
                        tombstone = index;
                    },
                    .used => if (slot.hash == hash and try self.workAccount().compare(slot.key, key)) return StoreError.InvalidTablePlan,
                }
            }
            return tombstone orelse StoreError.InvalidTablePlan;
        }
        fn digest(self: *const Plan) [32]u8 {
            var h = std.crypto.hash.Blake3.init(.{});
            h.update("onyx-store-private-table-plan-v1");
            hashNumber(&h, @intFromPtr(self.owner));
            hashNumber(&h, @intFromPtr(self.expected_slots.ptr));
            hashNumber(&h, self.expected_slots.len);
            hashNumber(&h, self.expected_count);
            hashNumber(&h, self.expected_tombstones);
            hashNumber(&h, self.expected_revision);
            hashNumber(&h, self.final_count);
            hashNumber(&h, self.final_tombstones);
            hashNumber(&h, self.patch_count);
            hashNumber(&h, if (self.shared_work) |w| w.limit else self.work.limit);
            hashNumber(&h, if (self.shared_work) |w| @intFromPtr(w) else 0);
            hashNumber(&h, @intFromPtr(self.replacement_allocator.ptr));
            hashNumber(&h, @intFromPtr(self.replacement_allocator.vtable));
            hashNumber(&h, self.edit_count);
            h.update(&self.edit_digest);
            for (self.edits[0..self.edit_count]) |edit| {
                hashNumber(&h, @intFromPtr(edit.key.ptr));
                hashNumber(&h, edit.key.len);
                hashNumber(&h, if (edit.value) |value| @intFromPtr(value.ptr) else 0);
                hashNumber(&h, if (edit.value) |value| value.len else 0);
            }
            for (self.patches[0..self.patch_count]) |patch| {
                hashNumber(&h, patch.index);
                h.update(&patch.before_digest);
                h.update(&patch.after_digest);
                hashSlotPointers(&h, patch.before);
                hashSlotPointers(&h, patch.after);
            }
            if (self.replacement) |slots| {
                hashNumber(&h, @intFromPtr(slots.ptr));
                hashNumber(&h, slots.len);
                h.update(&self.replacement_digest);
            } else hashNumber(&h, 0);
            var out: [32]u8 = undefined;
            h.final(&out);
            return out;
        }
        fn validate(self: *Plan) !void {
            if (self.done or self.edit_count == 0 or self.edit_count > max_edits or self.patch_count > max_edits or self.expected_revision == std.math.maxInt(u64)) return StoreError.InvalidTablePlan;
            const table = self.owner;
            if (table.slots.ptr != self.expected_slots.ptr or table.slots.len != self.expected_slots.len or table.used != self.expected_count or table.tombstones != self.expected_tombstones or table.revision != self.expected_revision) return StoreError.InvalidTablePlan;
            const work = self.workAccount();
            try work.charge(&work.bytes, self.sealByteCount());
            if (!std.mem.eql(u8, &self.seal, &self.digest())) return StoreError.InvalidTablePlan;
            if (!std.mem.eql(u8, &self.edit_digest, &try editsDigest(self.edits[0..self.edit_count], work))) return StoreError.InvalidTablePlan;
            for (self.patches[0..self.patch_count]) |patch| {
                if (patch.index >= table.slots.len or !slotSame(table.slots[patch.index], patch.before) or !std.mem.eql(u8, &patch.before_digest, &try slotDigest(table.slots[patch.index], work)) or !std.mem.eql(u8, &patch.after_digest, &try slotDigest(patch.after, work))) return StoreError.InvalidTablePlan;
            }
            if (self.replacement) |slots| if (!std.mem.eql(u8, &self.replacement_digest, &try backingDigest(slots, work))) return StoreError.InvalidTablePlan;
        }
        fn sealByteCount(self: *const Plan) usize {
            return "onyx-store-private-table-plan-v1".len + 14 * 8 + 32 + self.edit_count * 32 + self.patch_count * 136 + (if (self.replacement != null) @as(usize, 48) else 8);
        }
        fn matchesEdit(self: *const Plan, key: []const u8, value: ?[]u8) bool {
            return self.editIndex(key, value) != null;
        }
        fn editIndex(self: *const Plan, key: []const u8, value: ?[]u8) ?usize {
            for (self.edits[0..self.edit_count], 0..) |edit, i| {
                if (edit.key.ptr != key.ptr or edit.key.len != key.len or (edit.value == null) != (value == null)) continue;
                if (edit.value) |expected| {
                    if (expected.ptr != value.?.ptr or expected.len != value.?.len) continue;
                }
                return i;
            }
            return null;
        }
        /// Caller has validated under its exclusive lane BEFORE I/O. Only
        /// fixed patches/swap/scalars below; no hash, probe, free or allocation.
        fn publish(self: *Plan) ?[]Slot {
            std.debug.assert(!self.done);
            const table = self.owner;
            var retired: ?[]Slot = null;
            if (self.replacement) |slots| {
                if (table.slots.len != 0) retired = table.slots;
                table.slots = slots;
                self.replacement = null;
            } else for (self.patches[0..self.patch_count]) |patch| table.slots[patch.index] = patch.after;
            table.used = self.final_count;
            table.tombstones = self.final_tombstones;
            table.revision = self.expected_revision + 1;
            self.done = true;
            return retired;
        }
        fn abort(self: *Plan) void {
            if (self.done) return;
            if (self.replacement) |slots| self.replacement_allocator.free(slots);
            self.replacement = null;
            self.done = true;
        }
    };

    allocator: std.mem.Allocator,
    slots: []Slot = &.{},
    used: u32 = 0,
    tombstones: u32 = 0,
    revision: u64 = 0,

    fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }
    fn deinit(self: *Self) void {
        self.allocator.free(self.slots);
        self.* = init(self.allocator);
    }
    pub fn count(self: *const Self) u32 {
        return self.used;
    }
    pub fn capacity(self: *const Self) u32 {
        return @intCast(self.slots.len);
    }
    pub fn iterator(self: *const Self) Iterator {
        return .{ .table = self };
    }
    fn keyHash(key: []const u8) u64 {
        return std.hash.Wyhash.hash(0, key);
    }
    fn maxLoad(cap: usize) usize {
        return cap - cap / 4;
    }
    fn checkRevision(self: *const Self) !void {
        if (self.revision == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
    }
    fn capacityFor(required: usize, initial: usize) !usize {
        var cap = @max(initial, 8);
        while (required > maxLoad(cap)) cap = std.math.mul(usize, cap, 2) catch return error.OutOfMemory;
        if (cap > std.math.maxInt(u32)) return error.OutOfMemory;
        return cap;
    }
    fn find(self: *const Self, key: []const u8, work: ?*Work) !?usize {
        const cap = self.slots.len;
        if (cap == 0) return null;
        if (work) |w| try w.charge(&w.bytes, key.len);
        const hash = keyHash(key);
        for (0..cap) |probe| {
            if (work) |w| try w.charge(&w.probes, 1);
            const index = (@as(usize, @truncate(hash)) +% probe) & (cap - 1);
            const slot = self.slots[index];
            if (slot.state == .free) return null;
            if (slot.state == .used and slot.hash == hash) {
                const equal = if (work) |w| try w.compare(slot.key, key) else std.mem.eql(u8, slot.key, key);
                if (equal) return index;
            }
        }
        return null;
    }
    fn getEntry(self: *const Self, key: []const u8) ?Entry {
        const index = (self.find(key, null) catch unreachable) orelse return null;
        const slot = @constCast(&self.slots[index]);
        return .{ .key_ptr = &slot.key, .value_ptr = &slot.value };
    }
    fn get(self: *const Self, key: []const u8) ?[]u8 {
        return if (self.getEntry(key)) |entry| entry.value_ptr.* else null;
    }
    fn insertDetached(slots: []Slot, slot: Slot, work: *Work) !void {
        for (0..slots.len) |probe| {
            try work.charge(&work.probes, 1);
            const index = (@as(usize, @truncate(slot.hash)) +% probe) & (slots.len - 1);
            if (slots[index].state == .free) {
                slots[index] = slot;
                return;
            }
            if (slots[index].hash == slot.hash and try work.compare(slots[index].key, slot.key)) return StoreError.InvalidTablePlan;
        }
        return StoreError.InvalidTablePlan;
    }
    fn ensureUnusedCapacity(self: *Self, additional: u32) !void {
        try self.checkRevision();
        const required = std.math.add(usize, self.used, additional) catch return error.OutOfMemory;
        const cap = try capacityFor(required, self.slots.len);
        if (cap == self.slots.len and @as(usize, self.used) + self.tombstones + additional <= maxLoad(cap)) return;
        const next = try self.allocator.alloc(Slot, cap);
        errdefer self.allocator.free(next);
        @memset(next, .{});
        var work: Work = .{};
        for (self.slots) |slot| if (slot.state == .used) try insertDetached(next, slot, &work);
        self.allocator.free(self.slots);
        self.slots = next;
        self.tombstones = 0;
        self.revision += 1;
    }
    fn checkOrdinaryPut(self: *const Self, key: []const u8) !void {
        try self.checkRevision();
        if (self.getEntry(key) == null and self.revision > std.math.maxInt(u64) - 3) return StoreError.SequenceExhausted;
    }
    fn getOrPut(self: *Self, key: []const u8) !GetOrPut {
        try self.checkRevision();
        if (self.getEntry(key)) |entry| {
            self.revision += 1;
            return .{ .key_ptr = entry.key_ptr, .value_ptr = entry.value_ptr, .found_existing = true };
        }
        // Growth, placeholder install and OOM rollback each reserve one stamp.
        if (self.revision > std.math.maxInt(u64) - 3) return StoreError.SequenceExhausted;
        try self.ensureUnusedCapacity(1);
        return self.getOrPutAssumeCapacity(key);
    }
    fn getOrPutAssumeCapacity(self: *Self, key: []const u8) GetOrPut {
        std.debug.assert(self.revision < std.math.maxInt(u64));
        self.revision += 1;
        if (self.getEntry(key)) |entry| return .{ .key_ptr = entry.key_ptr, .value_ptr = entry.value_ptr, .found_existing = true };
        const hash = keyHash(key);
        var tomb: ?usize = null;
        for (0..self.slots.len) |probe| {
            const i = (@as(usize, @truncate(hash)) +% probe) & (self.slots.len - 1);
            if (self.slots[i].state == .tombstone and tomb == null) tomb = i;
            if (self.slots[i].state == .free) {
                const index = tomb orelse i;
                if (self.slots[index].state == .tombstone) self.tombstones -= 1;
                self.slots[index] = .{ .state = .used, .hash = hash, .key = key };
                self.used += 1;
                return .{ .key_ptr = &self.slots[index].key, .value_ptr = &self.slots[index].value, .found_existing = false };
            }
        }
        unreachable; // ensureUnusedCapacity maintains a genuinely free slot.
    }
    fn removeByPtr(self: *Self, key_ptr: *[]const u8) void {
        std.debug.assert(self.revision < std.math.maxInt(u64));
        const base = @intFromPtr(self.slots.ptr) + @offsetOf(Slot, "key");
        const address = @intFromPtr(key_ptr);
        std.debug.assert(address >= base and (address - base) % @sizeOf(Slot) == 0);
        const index = (address - base) / @sizeOf(Slot);
        std.debug.assert(index < self.slots.len and self.slots[index].state == .used);
        self.slots[index] = .{ .state = .tombstone };
        self.used -= 1;
        self.tombstones += 1;
        self.revision += 1;
    }
    fn remove(self: *Self, key: []const u8) bool {
        const entry = self.getEntry(key) orelse return false;
        self.removeByPtr(entry.key_ptr);
        return true;
    }
    fn slotSame(a: Slot, b: Slot) bool {
        return a.state == b.state and a.hash == b.hash and a.key.ptr == b.key.ptr and a.key.len == b.key.len and a.value.ptr == b.value.ptr and a.value.len == b.value.len;
    }
    fn hashNumber(h: *std.crypto.hash.Blake3, n: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    fn hashSlotPointers(h: *std.crypto.hash.Blake3, slot: Slot) void {
        hashNumber(h, @intFromPtr(slot.key.ptr));
        hashNumber(h, slot.key.len);
        hashNumber(h, @intFromPtr(slot.value.ptr));
        hashNumber(h, slot.value.len);
    }
    fn slotDigest(slot: Slot, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        hashNumber(&h, @intFromEnum(slot.state));
        hashNumber(&h, slot.hash);
        try work.charge(&work.bytes, if (slot.state == .used) @as(usize, 32) else 16);
        if (slot.state == .used) {
            try work.charge(&work.bytes, slot.key.len);
            try work.charge(&work.bytes, slot.value.len);
            hashNumber(&h, slot.key.len);
            h.update(slot.key);
            hashNumber(&h, slot.value.len);
            h.update(slot.value);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    fn editsDigest(edits: []const Edit, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (edits) |edit| {
            try work.charge(&work.bytes, 24 + edit.key.len);
            hashNumber(&h, edit.key.len);
            h.update(edit.key);
            hashNumber(&h, @intFromBool(edit.value != null));
            if (edit.value) |value| {
                try work.charge(&work.bytes, value.len);
                hashNumber(&h, value.len);
                h.update(value);
            }
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    fn backingDigest(slots: []const Slot, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (slots) |slot| {
            try work.charge(&work.rows, 1);
            try work.charge(&work.bytes, 64);
            h.update(&try slotDigest(slot, work));
            hashSlotPointers(&h, slot);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    fn prepare(self: *Self, edits: []const Edit, work_limit: u64) !Plan {
        return self.prepareStorage(edits, self.allocator, null, work_limit);
    }
    fn prepareWithStorage(self: *Self, edits: []const Edit, candidate_allocator: std.mem.Allocator, shared_work: *Work) !Plan {
        return self.prepareStorage(edits, candidate_allocator, shared_work, shared_work.limit);
    }
    fn prepareStorage(self: *Self, edits: []const Edit, candidate_allocator: std.mem.Allocator, shared_work: ?*Work, work_limit: u64) !Plan {
        if (edits.len == 0 or edits.len > max_edits) return StoreError.InvalidTablePlan;
        try self.checkRevision();
        if ((self.slots.len == 0 and (self.used != 0 or self.tombstones != 0)) or (self.slots.len != 0 and (!std.math.isPowerOfTwo(self.slots.len) or self.slots.len < 8 or @as(usize, self.used) + self.tombstones > maxLoad(self.slots.len)))) return StoreError.InvalidTablePlan;
        var plan: Plan = .{ .owner = self, .expected_slots = self.slots, .expected_count = self.used, .expected_tombstones = self.tombstones, .expected_revision = self.revision, .final_count = self.used, .final_tombstones = self.tombstones, .work = .{ .limit = work_limit }, .shared_work = shared_work, .replacement_allocator = candidate_allocator };
        errdefer plan.abort();
        @memcpy(plan.edits[0..edits.len], edits);
        plan.edit_count = edits.len;
        plan.edit_digest = try editsDigest(edits, plan.workAccount());
        var final: [max_edits]Edit = undefined;
        var old: [max_edits]?usize = undefined;
        var count_final: usize = 0;
        for (edits) |edit| {
            var existing: ?usize = null;
            for (final[0..count_final], 0..) |prior, i| if (try plan.workAccount().compare(prior.key, edit.key)) {
                existing = i;
                break;
            };
            if (existing) |i| final[i] = edit else {
                final[count_final] = edit;
                count_final += 1;
            }
        }
        // Fixed <=8 insertion sort; charge key comparisons rather than hiding work.
        for (1..count_final) |i| {
            var j = i;
            while (j > 0) : (j -= 1) {
                try plan.workAccount().charge(&plan.workAccount().comparisons, 1);
                try plan.workAccount().charge(&plan.workAccount().bytes, @min(final[j].key.len, final[j - 1].key.len));
                if (std.mem.order(u8, final[j - 1].key, final[j].key) != .gt) break;
                std.mem.swap(Edit, &final[j - 1], &final[j]);
            }
        }
        for (final[0..count_final], 0..) |edit, i| {
            old[i] = try self.find(edit.key, plan.workAccount());
            if (old[i]) |index| {
                if (edit.value) |value| {
                    var after = self.slots[index];
                    after.value = value;
                    try plan.set(index, after);
                } else {
                    plan.final_count -= 1;
                    plan.final_tombstones += 1;
                    try plan.set(index, .{ .state = .tombstone });
                }
            } else if (edit.value != null) plan.final_count = std.math.add(u32, plan.final_count, 1) catch return error.OutOfMemory;
        }
        var cap = try capacityFor(plan.final_count, self.slots.len);
        var rebuild = cap != self.slots.len;
        if (!rebuild) {
            for (final[0..count_final], 0..) |edit, i| if (old[i] == null) {
                if (edit.value) |value| {
                    try plan.workAccount().charge(&plan.workAccount().bytes, edit.key.len);
                    const hash = keyHash(edit.key);
                    const index = try plan.insertion(hash, edit.key);
                    if ((try plan.at(index)).state == .tombstone) plan.final_tombstones -= 1;
                    try plan.set(index, .{ .state = .used, .hash = hash, .key = edit.key, .value = value });
                }
            };
            rebuild = @as(usize, plan.final_count) + plan.final_tombstones > maxLoad(cap);
        }
        if (rebuild) {
            // Growth/rebuild owns ONLY slots, all payloads stay with OLD/candidate.
            cap = try capacityFor(plan.final_count, self.slots.len);
            const rebuilt_bytes = std.math.mul(usize, cap, @sizeOf(Slot)) catch return StoreError.TableWorkExceeded;
            try plan.workAccount().charge(&plan.workAccount().rebuilt_bytes, rebuilt_bytes);
            const replacement = try candidate_allocator.alloc(Slot, cap);
            plan.replacement = replacement;
            @memset(replacement, .{});
            for (self.slots) |slot| {
                try plan.workAccount().charge(&plan.workAccount().rows, 1);
                if (slot.state != .used) continue;
                var next = slot;
                for (final[0..count_final]) |edit| if (try plan.workAccount().compare(edit.key, slot.key)) {
                    if (edit.value) |value| next.value = value else next.state = .tombstone;
                    break;
                };
                if (next.state == .used) try insertDetached(replacement, next, plan.workAccount());
            }
            for (final[0..count_final], 0..) |edit, i| if (old[i] == null) if (edit.value) |value| {
                try plan.workAccount().charge(&plan.workAccount().bytes, edit.key.len);
                try insertDetached(replacement, .{ .state = .used, .hash = keyHash(edit.key), .key = edit.key, .value = value }, plan.workAccount());
            };
            plan.patch_count = 0;
            plan.final_tombstones = 0;
            plan.replacement_digest = try backingDigest(replacement, plan.workAccount());
        }
        try plan.workAccount().charge(&plan.workAccount().bytes, plan.sealByteCount());
        plan.seal = plan.digest();
        return plan;
    }
};

const KvMap = struct {
    allocator: std.mem.Allocator,
    map: KvTable,

    fn init(allocator: std.mem.Allocator) KvMap {
        return .{
            .allocator = allocator,
            .map = KvTable.init(allocator),
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

fn batchPayloadLen(mutations: []const BatchMutation, limit: usize) !usize {
    if (mutations.len == 0 or mutations.len > max_batch_mutations) return StoreError.BadRecord;
    var size: usize = 3;
    for (mutations, 0..) |mutation, i| {
        if ((mutation.kind == .put) != (mutation.value != null)) return StoreError.BadRecord;
        for (mutations[0..i]) |prior| {
            if (mutation.family == prior.family and std.mem.eql(u8, mutation.key, prior.key)) return StoreError.BadRecord;
        }
        const part = try checkedPayloadLen(mutation.kind, mutation.key, mutation.value orelse "", limit);
        size = std.math.add(usize, size, 4) catch return StoreError.RecordTooLarge;
        size = std.math.add(usize, size, part) catch return StoreError.RecordTooLarge;
    }
    if (size > limit or size > std.math.maxInt(u32)) return StoreError.RecordTooLarge;
    return size;
}

fn encodeBatchGuard(record: *[batch_guard_len]u8) void {
    writeU32(record[0..4], 2);
    record[record_header_len] = meta_kind_batch_format;
    record[record_header_len + 1] = batch_format_version;
    writeU32(record[4..8], checksum(record[record_header_len..]));
}

fn encodeMutation(payload: []u8, mutation: BatchMutation) void {
    payload[0] = @intFromEnum(mutation.kind);
    payload[1] = @intFromEnum(mutation.family);
    writeU32(payload[2..6], @intCast(mutation.key.len));
    writeU32(payload[6..10], if (mutation.value) |value| @intCast(value.len) else tombstone_len);
    @memcpy(payload[payload_header_len..][0..mutation.key.len], mutation.key);
    if (mutation.value) |value| @memcpy(payload[payload_header_len + mutation.key.len ..], value);
}

fn decodeBatch(payload: []const u8, out: *[max_batch_mutations]BatchMutation) !usize {
    if (payload.len < 3 or payload[0] != meta_kind_batch or payload[1] != batch_format_version or payload[2] == 0 or payload[2] > max_batch_mutations)
        return StoreError.BadRecord;
    var offset: usize = 3;
    const count: usize = payload[2];
    for (out[0..count]) |*mutation| {
        if (payload.len - offset < 4) return StoreError.BadRecord;
        const len: usize = readU32(payload[offset..][0..4]);
        offset += 4;
        if (len < payload_header_len or len > payload.len - offset) return StoreError.BadRecord;
        const part = payload[offset..][0..len];
        const kind: MutationKind = switch (part[0]) {
            0 => .put,
            1 => .delete,
            else => return StoreError.UnknownRecordKind,
        };
        const family_value = decodeFamily(part[1]) orelse return StoreError.UnknownFamily;
        const key_len: usize = readU32(part[2..6]);
        const value_len = readU32(part[6..10]);
        if ((kind == .delete) != (value_len == tombstone_len)) return StoreError.BadRecord;
        if (key_len > len - payload_header_len) return StoreError.BadRecord;
        const remainder = len - payload_header_len - key_len;
        if (remainder != (if (kind == .delete) @as(usize, 0) else @as(usize, value_len))) return StoreError.BadRecord;
        mutation.* = .{ .family = family_value, .kind = kind, .key = part[payload_header_len..][0..key_len], .value = if (kind == .put) part[payload_header_len + key_len ..] else null };
        offset += len;
    }
    if (offset != payload.len) return StoreError.BadRecord;
    _ = try batchPayloadLen(out[0..count], std.math.maxInt(usize));
    return count;
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
    var corrupted: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.readPositionalAll(std.testing.io, &corrupted, 6));
    corrupted[0] ^= 0xFF;
    try file.writePositionalAll(std.testing.io, &corrupted, 6);
    try file.sync(std.testing.io);

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
    try std.testing.expectEqual(@as(usize, 4), store.retirement_count);
    try std.testing.expectEqualStrings("new", store.family(.accounts).get("alice").?);

    var next = try store.preparePut(.accounts, "bob", "next");
    try std.testing.expectEqual(@as(usize, 0), store.retirement_count);
    next.abort();
    prepared.deinit();
}

test "native Helix read-only store stages without disk mutations and promotes only after commit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var parent = try openTestStore(tmp, "native-stage.wal");
    defer parent.deinit();
    try parent.put(.accounts, "alice", "original");
    const before = try readWalForTest(tmp, "native-stage.wal");
    defer allocator.free(before);
    // Force the normal boot compaction threshold below the existing size.
    var staged = try OroStore.openReadOnlyWithConfig(allocator, io, tmp.dir, "native-stage.wal", .{ .max_wal_bytes = before.len + 1 });
    defer staged.deinit();
    try std.testing.expect(staged.isReadOnly());
    try std.testing.expectEqualStrings("original", staged.get(.accounts, "alice").?);
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.put(.accounts, "alice", "changed"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.delete(.accounts, "alice"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.preparePut(.accounts, "alice", "prepared"));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.snapshotAndTruncate());
    try staged.preparePromotion();
    try std.testing.expect(staged.isReadOnly());
    const still = try readWalForTest(tmp, "native-stage.wal");
    defer allocator.free(still);
    try std.testing.expectEqualSlices(u8, before, still);
    staged.promotePrepared();
    try std.testing.expect(!staged.isReadOnly());
    try staged.put(.accounts, "alice", "committed");
    var reopened = try openTestStore(tmp, "native-stage.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("committed", reopened.get(.accounts, "alice").?);
}

test "native Helix read-only store refuses torn WAL without repair and detects parent changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    var parent = try openTestStore(tmp, "native-torn.wal");
    defer parent.deinit();
    try parent.put(.accounts, "alice", "first");
    var staged = try OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "native-torn.wal", .{});
    defer staged.deinit();
    try parent.put(.accounts, "bob", "later");
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, staged.preparePromotion());
    const wal = parent.wal_file.?;
    try wal.writePositionalAll(std.testing.io, "torn", parent.wal_offset);
    const before = try readWalForTest(tmp, "native-torn.wal");
    defer allocator.free(before);
    try std.testing.expectError(StoreError.BadRecord, OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "native-torn.wal", .{}));
    const after = try readWalForTest(tmp, "native-torn.wal");
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, OroStore.openReadOnlyWithConfig(allocator, std.testing.io, tmp.dir, "absent.wal", .{}));
}

const test_policy_batch = [_]BatchMutation{
    .{ .family = .props, .kind = .put, .key = "tot\x00alice", .value = "NEWSECRET" },
    .{ .family = .props, .kind = .delete, .key = "sessiontokacct:alice" },
    .{ .family = .props, .kind = .put, .key = "new-key", .value = "new-value" },
};

fn seedPolicyBatch(store: *OroStore) !void {
    try store.put(.props, "tot\x00alice", "OLDSECRET");
    try store.put(.props, "sessiontokacct:alice", "old-token-hash");
}

fn expectPolicyBatch(store: *OroStore, committed: bool) !void {
    try std.testing.expectEqualStrings(if (committed) "NEWSECRET" else "OLDSECRET", store.get(.props, "tot\x00alice").?);
    if (committed) {
        try std.testing.expect(store.get(.props, "sessiontokacct:alice") == null);
        try std.testing.expectEqualStrings("new-value", store.get(.props, "new-key").?);
    } else {
        try std.testing.expectEqualStrings("old-token-hash", store.get(.props, "sessiontokacct:alice").?);
        try std.testing.expect(store.get(.props, "new-key") == null);
    }
}

test "STORE batch reserves OOM atomically and retries every allocation" {
    var successes: usize = 0;
    var failures: usize = 0;
    for (0..64) |fail_offset| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "batch-oom.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        const before = try readWalForTest(tmp, "batch-oom.wal");
        defer std.testing.allocator.free(before);
        const next_seq = store.next_seq;
        const offset = store.wal_offset;
        const change_count = store.changeCount();
        const secret_ptr = store.get(.props, "tot\x00alice").?.ptr;
        const token_ptr = store.get(.props, "sessiontokacct:alice").?.ptr;
        failing.fail_index = failing.alloc_index + fail_offset;
        var prepared = store.prepareBatch(&test_policy_batch) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            try expectPolicyBatch(&store, false);
            try std.testing.expectEqual(secret_ptr, store.get(.props, "tot\x00alice").?.ptr);
            try std.testing.expectEqual(token_ptr, store.get(.props, "sessiontokacct:alice").?.ptr);
            try std.testing.expectEqual(next_seq, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
            try std.testing.expectEqual(change_count, store.changeCount());
            try std.testing.expect(store.active_batch == null);
            const after = try readWalForTest(tmp, "batch-oom.wal");
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try store.prepareBatch(&test_policy_batch);
            defer retry.deinit();
            try retry.commit();
            try expectPolicyBatch(&store, true);
            continue;
        };
        defer prepared.deinit();
        const allocations = failing.alloc_index;
        const frees = failing.deallocations;
        // The first non-failing reservation must commit even with allocations
        // and frees prohibited immediately after prepare.
        failing.fail_index = failing.alloc_index;
        try prepared.commit();
        try std.testing.expectEqual(allocations, failing.alloc_index);
        try std.testing.expectEqual(frees, failing.deallocations);
        try expectPolicyBatch(&store, true);
        try std.testing.expectEqual(next_seq + test_policy_batch.len, store.next_seq);
        successes += 1;
        break;
    }
    try std.testing.expect(failures > 0);
    try std.testing.expectEqual(@as(usize, 1), successes);
}

test "STORE batch write ambiguity publishes nothing and reopen resolves the whole group" {
    const faults = [_]PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } };
    for (faults, 0..) |fault, i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var next_seq: u64 = undefined;
        {
            var store = try openTestStore(tmp, "batch-fault.wal");
            defer store.deinit();
            try seedPolicyBatch(&store);
            next_seq = store.next_seq;
            const change_count = store.changeCount();
            var prepared = try store.prepareBatch(&test_policy_batch);
            defer prepared.deinit();
            store.setPreparedIoFault(fault);
            try std.testing.expectError(StoreError.IoAmbiguous, prepared.commit());
            try std.testing.expect(store.preparedWritesPoisoned());
            try expectPolicyBatch(&store, false);
            try std.testing.expectEqual(next_seq, store.next_seq);
            try std.testing.expectEqual(change_count, store.changeCount());
            try std.testing.expectError(StoreError.StorePoisoned, store.prepareBatch(&test_policy_batch));
            try std.testing.expectError(StoreError.StorePoisoned, store.delete(.props, "tot\x00alice"));
        }
        var reopened = try openTestStore(tmp, "batch-fault.wal");
        defer reopened.deinit();
        try expectPolicyBatch(&reopened, i == 2);
        try std.testing.expectEqual(next_seq + (if (i == 2) @as(u64, test_policy_batch.len) else @as(u64, 0)), reopened.next_seq);
        if (i != 2) {
            var retry = try reopened.prepareBatch(&test_policy_batch);
            defer retry.deinit();
            try retry.commit();
            try expectPolicyBatch(&reopened, true);
        }
    }
}

test "STORE batch every torn append prefix reopens to whole prior policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var append_offset: usize = undefined;
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-complete.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        append_offset = @intCast(store.wal_offset);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-complete.wal");
    };
    defer std.testing.allocator.free(bytes);
    for (append_offset..bytes.len) |cut| {
        try rewriteTestFile(tmp, "batch-torn.wal", bytes[0..cut]);
        var reopened = try openTestStore(tmp, "batch-torn.wal");
        defer reopened.deinit();
        try expectPolicyBatch(&reopened, false);
        var retry = try reopened.prepareBatch(&test_policy_batch);
        defer retry.deinit();
        try retry.commit();
        try expectPolicyBatch(&reopened, true);
    }
}

test "STORE batch strict EOF decode rejects checksum-valid malformed components" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const original = block: {
        var store = try openTestStore(tmp, "batch-valid.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var prepared = try store.prepareBatch(&test_policy_batch);
        defer prepared.deinit();
        try prepared.commit();
        break :block try readWalForTest(tmp, "batch-valid.wal");
    };
    defer std.testing.allocator.free(original);
    const payload_start = findRecordPayloadByKind(original, meta_kind_batch).?;
    const first_part = payload_start + 3 + 4;
    const second_part = first_part + readU32(original[payload_start + 3 ..][0..4]) + 4;
    const cases = [_]struct { offset: usize, value: u8, expected: StoreError }{
        .{ .offset = payload_start + 1, .value = 2, .expected = StoreError.BadRecord },
        .{ .offset = payload_start + 2, .value = 0, .expected = StoreError.BadRecord },
        .{ .offset = payload_start + 2, .value = 4, .expected = StoreError.BadRecord },
        .{ .offset = second_part, .value = 6, .expected = StoreError.UnknownRecordKind },
        .{ .offset = second_part + 1, .value = 99, .expected = StoreError.UnknownFamily },
        .{ .offset = second_part + 6, .value = 0, .expected = StoreError.BadRecord },
    };
    for (cases) |case| {
        const damaged = try std.testing.allocator.dupe(u8, original);
        defer std.testing.allocator.free(damaged);
        damaged[case.offset] = case.value;
        refreshRecordChecksum(damaged, payload_start);
        try rewriteTestFile(tmp, "batch-bad.wal", damaged);
        try std.testing.expectError(case.expected, openTestStore(tmp, "batch-bad.wal"));
        const after = try readWalForTest(tmp, "batch-bad.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, damaged, after);
    }
}

/// The pre-batch reader accepts ordinary mutations and metadata, tolerates an
/// unknown WAL record only at exact EOF, and never tolerates snapshot errors.
fn legacyBatchFormatRejected(bytes: []const u8, snapshot: bool) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes.len - offset < record_header_len) return false;
        const len: usize = readU32(bytes[offset..][0..4]);
        const end = offset + record_header_len + len;
        if (end > bytes.len or len == 0) return false;
        const kind = bytes[offset + record_header_len];
        if (kind == meta_kind_batch_format or kind == meta_kind_batch)
            return snapshot or end != bytes.len;
        offset = end;
    }
    return false;
}

test "STORE batch mandatory format guard refuses downgrade before and after compaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-guard.wal");
    defer store.deinit();
    try seedPolicyBatch(&store);
    var prepared = try store.prepareBatch(&test_policy_batch);
    defer prepared.deinit();
    try prepared.commit();
    const wal = try readWalForTest(tmp, "batch-guard.wal");
    defer std.testing.allocator.free(wal);
    try std.testing.expect(legacyBatchFormatRejected(wal, false));
    try store.snapshotAndTruncate();
    const snapshot = try readWalForTest(tmp, "batch-guard.wal.snap");
    defer std.testing.allocator.free(snapshot);
    try std.testing.expect(legacyBatchFormatRejected(snapshot, true));
    var reopened = try openTestStore(tmp, "batch-guard.wal");
    defer reopened.deinit();
    try expectPolicyBatch(&reopened, true);
    try std.testing.expect(reopened.batch_format_required);
    try std.testing.expectEqual(store.next_seq, reopened.next_seq);
}

test "STORE batch rejects duplicate keys and capacity sequence exhaustion before I/O" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-limits.wal");
    defer store.deinit();
    const duplicate = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = "same", .value = "a" },
        .{ .family = .props, .kind = .delete, .key = "same" },
    };
    const before = try readWalForTest(tmp, "batch-limits.wal");
    defer std.testing.allocator.free(before);
    try std.testing.expectError(StoreError.BadRecord, store.prepareBatch(&duplicate));
    store.cfg.max_record_bytes = 12;
    try std.testing.expectError(StoreError.RecordTooLarge, store.prepareBatch(&test_policy_batch));
    store.cfg.max_record_bytes = default_max_record_len;
    store.next_seq = std.math.maxInt(u64) - 1;
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&test_policy_batch));
    const after = try readWalForTest(tmp, "batch-limits.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch copied reservations abort without touching newer ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-copy.wal");
    defer store.deinit();
    try seedPolicyBatch(&store);
    var first = try store.prepareBatch(&test_policy_batch);
    var copied = first;
    first.abort();
    try expectPolicyBatch(&store, false);
    var next = try store.prepareBatch(&test_policy_batch);
    defer next.deinit();
    copied.abort();
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, copied.commit());
    try std.testing.expectError(StoreError.PreparedMutationActive, store.preparePut(.props, "other", "v"));
    try std.testing.expectError(StoreError.PreparedMutationActive, store.put(.props, "other", "v"));
    try next.commit();
    try expectPolicyBatch(&store, true);
    try std.testing.expectError(StoreError.PreparedAlreadyConsumed, next.commit());
}

test "STORE batch four deletes retire bounded feed evictions without allocator work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize) });
    var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "batch-retire.wal", .{ .changefeed_capacity = 1 });
    defer store.deinit();
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .delete, .key = "a" },
        .{ .family = .props, .kind = .delete, .key = "b" },
        .{ .family = .accounts, .kind = .delete, .key = "a" },
        .{ .family = .accounts, .kind = .delete, .key = "b" },
    };
    for (operations) |operation| try store.put(operation.family, operation.key, "value");
    const seq = store.next_seq;
    var batch = try store.prepareBatch(&operations);
    defer batch.deinit();
    const allocation_count = failing.alloc_index;
    const free_count = failing.deallocations;
    failing.fail_index = allocation_count;
    try batch.commit();
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(free_count, failing.deallocations);
    try std.testing.expectEqual(@as(usize, 17), store.retirement_count);
    try std.testing.expectEqual(seq + operations.len, store.next_seq);
    try std.testing.expectEqual(seq + operations.len - 1, store.changeAt(0).?.seq);
    try std.testing.expectEqual(MutationKind.delete, store.changeAt(0).?.kind);
    for (operations) |operation| try std.testing.expect(store.get(operation.family, operation.key) == null);
    failing.fail_index = std.math.maxInt(usize);
    var retry = try store.preparePut(.props, "after-retirement", "safe");
    defer retry.deinit();
    try retry.commit();
    try std.testing.expectEqualStrings("safe", store.get(.props, "after-retirement").?);
}

test "STORE batch read-only staged replay refuses mutation without WAL change" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "batch-readonly.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
    }
    const before = try readWalForTest(tmp, "batch-readonly.wal");
    defer std.testing.allocator.free(before);
    var staged = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "batch-readonly.wal", .{});
    defer staged.deinit();
    try expectPolicyBatch(&staged, true);
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.prepareBatch(&test_policy_batch));
    const after = try readWalForTest(tmp, "batch-readonly.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch durable replay allocation failures clean up without rewriting WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "batch-replay-oom.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
    }
    const before = try readWalForTest(tmp, "batch-replay-oom.wal");
    defer std.testing.allocator.free(before);
    const ReplaySweep = struct {
        fn run(allocator: std.mem.Allocator, dir: std.testing.TmpDir) !void {
            var store = try OroStore.open(allocator, std.testing.io, dir.dir, "batch-replay-oom.wal");
            defer store.deinit();
            try expectPolicyBatch(&store, true);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ReplaySweep.run, .{tmp});
    const after = try readWalForTest(tmp, "batch-replay-oom.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "STORE batch owns caller bytes and publishes each component sequence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "batch-owned.wal");
    defer store.deinit();
    var key = [_]u8{ 'k', 'e', 'y' };
    var value = [_]u8{ 'v', 'a', 'l', 'u', 'e' };
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = &key, .value = &value },
        .{ .family = .accounts, .kind = .put, .key = "account", .value = "raw-account-row" },
        .{ .family = .props, .kind = .delete, .key = "absent" },
    };
    var batch = try store.prepareBatch(&operations);
    defer batch.deinit();
    @memset(&key, 'x');
    @memset(&value, 'x');
    try batch.commit();
    try std.testing.expectEqualStrings("value", store.get(.props, "key").?);
    for (0..operations.len) |i| {
        const change = store.changeAt(i).?;
        try std.testing.expectEqual(@as(u64, @intCast(i)) + 1, change.seq);
        try std.testing.expectEqual(operations[i].family, change.family);
        try std.testing.expectEqual(operations[i].kind, change.kind);
    }
    try std.testing.expectEqualStrings("key", store.changeAt(0).?.key);
    try std.testing.expectEqualStrings("value", store.changeAt(0).?.value.?);
    var reopened = try openTestStore(tmp, "batch-owned.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("value", reopened.get(.props, "key").?);
    try std.testing.expectEqualStrings("raw-account-row", reopened.get(.accounts, "account").?);
    try std.testing.expectEqual(@as(u64, 4), reopened.next_seq);
}

test "STORE batch replay rejects duplicate keys before applying a valid earlier component" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const operations = [_]BatchMutation{
        .{ .family = .props, .kind = .put, .key = "one", .value = "replacement" },
        .{ .family = .props, .kind = .delete, .key = "two" },
    };
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-duplicate.wal");
        defer store.deinit();
        var batch = try store.prepareBatch(&operations);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-duplicate.wal");
    };
    defer std.testing.allocator.free(bytes);
    const start = findRecordPayloadByKind(bytes, meta_kind_batch).?;
    const second = start + 3 + 4 + readU32(bytes[start + 3 ..][0..4]) + 4;
    @memcpy(bytes[second + payload_header_len ..][0..3], "one");
    refreshRecordChecksum(bytes, start);
    try rewriteTestFile(tmp, "batch-duplicate.wal", bytes);
    try std.testing.expectError(StoreError.BadRecord, openTestStore(tmp, "batch-duplicate.wal"));
    const after = try readWalForTest(tmp, "batch-duplicate.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, bytes, after);
}

fn expectMalformedBatchOuterFailsClosed(read_only: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = block: {
        var store = try openTestStore(tmp, "batch-outer.wal");
        defer store.deinit();
        try seedPolicyBatch(&store);
        var batch = try store.prepareBatch(&test_policy_batch);
        defer batch.deinit();
        try batch.commit();
        break :block try readWalForTest(tmp, "batch-outer.wal");
    };
    defer std.testing.allocator.free(bytes);
    const start = findRecordPayloadByKind(bytes, meta_kind_batch).?;
    bytes[start] = 0xFF;
    refreshRecordChecksum(bytes, start);
    try rewriteTestFile(tmp, "batch-outer.wal", bytes);
    const result = if (read_only)
        OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "batch-outer.wal", .{})
    else
        openTestStore(tmp, "batch-outer.wal");
    var opened = result catch |err| {
        try std.testing.expectEqual(StoreError.UnknownRecordKind, err);
        const after = try readWalForTest(tmp, "batch-outer.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, bytes, after);
        return;
    };
    opened.deinit();
    return error.TestUnexpectedResult;
}

test "STORE batch unknown outer kind fails ordinary reopen without rewriting WAL" {
    try expectMalformedBatchOuterFailsClosed(false);
}

test "STORE batch unknown outer kind fails read-only reopen without rewriting WAL" {
    try expectMalformedBatchOuterFailsClosed(true);
}

test "mesh presence hot promotion releases read descriptor before no IO activation" {
    // Raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var parent = try openTestStore(tmp, "hot-promotion.wal");
    defer parent.deinit();
    try parent.put(.props, "original", "retained");
    try std.testing.expectError(StoreError.ReadOnlyStore, parent.releaseReadHandleForPreparedPromotion());
    var staged = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-promotion.wal", .{});
    defer staged.deinit();
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.releaseReadHandleForPreparedPromotion());
    const read_fd = staged.wal_file.?.handle;
    try staged.preparePromotion();
    const writer_fd = staged.staged_write_file.?.handle;
    try staged.releaseReadHandleForPreparedPromotion();
    try std.testing.expect(staged.isReadOnly());
    try std.testing.expect(staged.wal_file == null);
    try std.testing.expectEqual(writer_fd, staged.staged_write_file.?.handle);
    try std.testing.expectEqual(std.posix.E.BADF, std.posix.errno(std.posix.system.fcntl(read_fd, std.posix.F.GETFD, @as(i32, 0))));
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.releaseReadHandleForPreparedPromotion());
    try std.testing.expectError(StoreError.ReadOnlyStore, staged.put(.props, "forbidden", "before barrier"));
    const before = try readWalForTest(tmp, "hot-promotion.wal");
    defer std.testing.allocator.free(before);
    staged.promotePrepared();
    try std.testing.expect(!staged.isReadOnly());
    try std.testing.expect(staged.staged_write_file == null);
    try std.testing.expectEqual(writer_fd, staged.wal_file.?.handle);
    const after = try readWalForTest(tmp, "hot-promotion.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "cold recovery refuses substituted WAL temp before snapshot and leaves foreign name on abort" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "wal-temp.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "wal-temp.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "wal-temp.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const atomic = stage.backing.?.plan.?.wal_atomic.?;
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try atomic.dir.createFile(std.testing.io, "foreign", .{ .read = true });
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try atomic.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "wal-temp.wal.snap", .{}));
    ticket.abort();
    const survivor = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(survivor);
    try std.testing.expectEqualStrings("FOREIGN", survivor);
}

test "cold recovery private receipt and prepared cut reject scalar row packet epoch coverage tampering" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "tamper.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(42);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "tamper.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tamper.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const owned = stage.backing.?;
    owned.valid_end -= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.valid_end += 1;
    owned.store.next_seq += 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.next_seq -= 1;
    owned.selected_epoch = 0;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.selected_epoch = null;
    owned.store.active_batch.?.record.?[10] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.active_batch.?.record.?[10] ^= 1;
    owned.store.active_batch.?.entries[0].value.?[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.store.active_batch.?.entries[0].value.?[0] ^= 1;
    owned.plan.?.epoch[24] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.plan.?.epoch[24] ^= 1;
    owned.plan.?.coverage.?.slots[1].digest[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    owned.plan.?.coverage.?.slots[1].digest[0] ^= 1;
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "tamper.wal.snap", .{}));
    try ticket.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
}

test "cold recovery publication faults poison owned stage and restart whole old or new cut" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        for (0..7) |fault_index| {
            if (empty and fault_index < 2) continue; // Existing snapshot has no new install.
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            {
                var seed = try openTestStore(tmp, "phases.wal");
                defer seed.deinit();
                const large: [1000]u8 = @splat(42);
                try seed.put(.props, "old", &large);
                if (empty) {
                    try seed.snapshotAndTruncate();
                    try seed.snapshotAndTruncate();
                    try seed.wal_file.?.setLength(std.testing.io, 0);
                }
            }
            const lease = try tmp.dir.createFile(std.testing.io, "phases.wal.lock", .{ .read = true });
            defer lease.close(std.testing.io);
            try cold_identity.reaffirmExclusive(lease.handle);
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "phases.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
                defer stage.deinit();
                var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
                defer ticket.abort();
                switch (fault_index) {
                    0 => stage.setPublicationFault(.snapshot_replace),
                    1 => stage.setPublicationFault(.snapshot_dir_sync),
                    2 => stage.setPublicationFault(.wal_replace),
                    3 => stage.setPublicationFault(.wal_dir_sync),
                    4 => stage.setPreparedIoFault(.{ .write = .failed }),
                    5 => stage.setPreparedIoFault(.{ .write = .short }),
                    else => stage.setPreparedIoFault(.{ .sync = true }),
                }
                try std.testing.expectError(error.IoAmbiguous, ticket.commit());
                try std.testing.expect(stage.view().preparedWritesPoisoned());
                try std.testing.expect(!stage.backing.?.committed);
                try std.testing.expectError(error.PreparedAlreadyConsumed, ticket.commit());
            }
            var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "phases.wal", lease, .{ .changefeed_capacity = 0 });
            defer restart.deinit();
            try std.testing.expectEqual(@as(u64, if (fault_index == 6) 3 else 2), restart.view().next_seq);
            if (fault_index == 6) try std.testing.expectEqualStrings("cut", restart.view().get(.props, "new").?) else try std.testing.expect(restart.view().get(.props, "new") == null);
            try std.testing.expectEqual(@as(usize, 1000), restart.view().get(.props, "old").?.len);
            var retry = try restart.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "retry", .value = "whole" }});
            defer retry.abort();
            try retry.commit();
            var published = restart.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("whole", published.get(.props, "retry").?);
        }
    }
}

test "cold recovery first provisioning commit has no allocations and refuses a raced existing WAL" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |race| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const lease = try tmp.dir.createFile(std.testing.io, "first.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var stage = try FirstProvisionStage.init(failing.allocator(), std.testing.io, tmp.dir, "first.wal", lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "initial", .value = "whole" }});
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "first.wal", .{}));
        if (race) {
            const foreign = try tmp.dir.createFile(std.testing.io, "first.wal", .{});
            defer foreign.close(std.testing.io);
            try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
        }
        failing.fail_index = failing.alloc_index;
        if (race) {
            try std.testing.expectError(error.PathAlreadyExists, stage.commit());
            const bytes = try tmp.dir.readFileAlloc(std.testing.io, "first.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(bytes);
            try std.testing.expectEqualStrings("FOREIGN", bytes);
        } else {
            try stage.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("whole", published.get(.props, "initial").?);
        }
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "cold recovery ordered epoch choice skips invalid first slot and rejects no valid slot" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |invalid_both| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "ordered.wal");
            defer seed.deinit();
            try seed.put(.props, "old", "cut");
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            var coverage = seed.snapshot_coverage.?;
            coverage.slots[0].digest[0] ^= 1;
            if (invalid_both) coverage.slots[1].digest[0] ^= 1;
            const bytes = try encodeColdSnapshot(&seed, &coverage);
            defer std.testing.allocator.free(bytes);
            const snapshot = try tmp.dir.createFile(std.testing.io, "ordered.wal.snap", .{ .truncate = true });
            defer snapshot.close(std.testing.io);
            try snapshot.writePositionalAll(std.testing.io, bytes, 0);
            try snapshot.sync(std.testing.io);
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "ordered.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        if (invalid_both) {
            try std.testing.expectError(error.SnapshotCoverageMismatch, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "ordered.wal", lease, .{ .changefeed_capacity = 0 }));
        } else {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "ordered.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            try std.testing.expectEqual(@as(usize, 1), stage.backing.?.selected_epoch.?);
            try std.testing.expectEqualStrings("cut", stage.view().get(.props, "old").?);
            var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "next", .value = "cut" }});
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("cut", published.get(.props, "next").?);
        }
    }
}

test "cold recovery tolerated tail truncate failures preserve valid predecessor and retry" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]ColdPublicationFault{ .truncate, .truncate_sync }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "tail.wal");
            defer seed.deinit();
            try seed.put(.props, "old", "cut");
            try seed.wal_file.?.writePositionalAll(std.testing.io, &.{ 0, 0, 0 }, seed.wal_offset);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "tail.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tail.wal", lease, .{ .changefeed_capacity = 0 });
            defer stage.deinit();
            var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
            defer ticket.abort();
            try std.testing.expect(!stage.backing.?.plan.?.rotate);
            stage.setPublicationFault(fault);
            if (fault == .truncate) try std.testing.expectError(error.TruncateFailed, ticket.commit()) else try std.testing.expectError(error.IoAmbiguous, ticket.commit());
            try std.testing.expect(stage.view().preparedWritesPoisoned());
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "tail.wal", lease, .{ .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("cut", restart.view().get(.props, "old").?);
        try std.testing.expect(restart.view().get(.props, "new") == null);
        var ticket = try restart.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
        defer ticket.abort();
        try ticket.commit();
        var published = restart.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
    }
}

test "cold recovery wrong owner cannot commit or abort another same generation stage" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "owner.wal");
        defer seed.deinit();
        try seed.put(.props, "old", "cut");
    }
    const lease = try tmp.dir.createFile(std.testing.io, "owner.wal.lock", .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var first = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "owner.wal", lease, .{ .changefeed_capacity = 0 });
    defer first.deinit();
    var second = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "owner.wal", lease, .{ .changefeed_capacity = 0 });
    defer second.deinit();
    var a = try first.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "a", .value = "cut" }});
    defer a.abort();
    var b = try second.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "b", .value = "cut" }});
    defer b.abort();
    try std.testing.expectEqual(a.generation, b.generation);
    a.stage = &second;
    try std.testing.expectError(error.PreparedAlreadyConsumed, a.commit());
    a.abort();
    try std.testing.expect(second.backing.?.plan != null);
    a.stage = &first;
    b.abort();
    try a.commit();
    var published = first.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("cut", published.get(.props, "a").?);
    try std.testing.expect(published.get(.props, "b") == null);
}

test "cold recovery commit performs no allocation after prepared snapshot epoch packet and maps" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var seed = try openTestStore(tmp, "noalloc.wal");
            defer seed.deinit();
            const large: [1000]u8 = @splat(42);
            try seed.put(.props, "old", &large);
            if (empty) {
                try seed.snapshotAndTruncate();
                try seed.snapshotAndTruncate();
                try seed.wal_file.?.setLength(std.testing.io, 0);
            }
        }
        const lease = try tmp.dir.createFile(std.testing.io, "noalloc.wal.lock", .{ .read = true });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var stage = try ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "noalloc.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 4 });
        defer stage.deinit();
        var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "whole" }});
        defer ticket.abort();
        const allocations = failing.allocations;
        failing.fail_index = failing.alloc_index;
        try ticket.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqual(allocations, failing.allocations);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqualStrings("whole", published.get(.props, "new").?);
        try std.testing.expectEqualStrings("new", published.changeAt(published.changeCount() - 1).?.key);
    }
}

test "cold recovery abort named provisioning temporary never unlinks a substituted foreign inode" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Named-temp behavior is used by native BSD provisioning. Exercise it on
    // Linux too rather than vacuously skipping because Linux uses O_TMPFILE.
    var atomic = try tmp.dir.createFileAtomic(std.testing.io, "initial.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    const foreign = try tmp.dir.createFile(std.testing.io, "foreign", .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    try tmp.dir.rename("foreign", atomic.dir, &name, std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, validateColdAtomicName(std.testing.io, &atomic, identity));
    deinitColdAtomic(std.testing.io, &atomic, identity);
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "initial.wal", .{}));
}

test "Windows private cold atomic becomes readable and duplicate survives original close" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "private record", 0);
    const copy = try cold_runtime.duplicateFile(atomic.file);
    try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(copy.handle));
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    var bytes: [14]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try copy.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("private record", &bytes);
    copy.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, identity);
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, &name, .{}));
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, "state.wal", .{}));
}

test "Windows cold atomic abort removes own write-only temp before readable reopen" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    deinitColdAtomic(std.testing.io, &atomic, null);
    try std.testing.expectError(error.FileNotFound, private.openFile(std.testing.io, &name, .{}));
}

test "Windows cold atomic refuses broad parent before secret bytes" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var atomic = try tmp.dir.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    try std.testing.expectError(error.InsecurePermissions, makeColdAtomicReadable(std.testing.io, &atomic));
    deinitColdAtomic(std.testing.io, &atomic, null);
    // A failed private-parent proof deliberately leaves only an empty temp;
    // std's name-based cleanup is forbidden on this path.
    const empty = try tmp.dir.openFile(std.testing.io, &name, .{});
    defer empty.close(std.testing.io);
    try std.testing.expectEqual(@as(u64, 0), (try empty.stat(std.testing.io)).size);
}

test "Windows cold atomic abort preserves a substituted foreign name" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const identity = try cold_identity.statRegular(atomic.file.handle);
    const name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    try private.rename(&name, private, "owned-away", std.testing.io);
    const foreign = try private.createFile(std.testing.io, &name, .{});
    try foreign.writePositionalAll(std.testing.io, "FOREIGN", 0);
    foreign.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, identity);
    const bytes = try private.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("FOREIGN", bytes);
}

test "Windows cold atomic nofollow reopen rejects a substituted reparse name" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const identity = try windowsColdAtomicIdentity(atomic.file.handle);
    defer deinitColdAtomic(std.testing.io, &atomic, identity);
    const name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file.close(std.testing.io);
    atomic.file_open = false;
    try private.rename(&name, private, "owned-away", std.testing.io);
    private.symLink(std.testing.io, "owned-away", &name, .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.NotRegular, openColdAtomicWindows(std.testing.io, &atomic));
    const owned = try private.openFile(std.testing.io, "owned-away", .{});
    owned.close(std.testing.io);
}

test "Windows cold atomic failed readable reopen leaves no foreign deletion" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const name = std.fmt.hex(atomic.file_basename_hex);
    const copy = try cold_runtime.duplicateFile(atomic.file);
    try std.testing.expectError(error.FileBusy, makeColdAtomicReadable(std.testing.io, &atomic));
    try std.testing.expect(!atomic.file_exists);
    copy.close(std.testing.io);
    deinitColdAtomic(std.testing.io, &atomic, null);
    const orphan = try private.openFile(std.testing.io, &name, .{});
    orphan.close(std.testing.io);
}

test "Windows held cold atomic rename publishes exact file and retains exclusive duplicate" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    const writer = try cold_runtime.duplicateFile(atomic.file);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false);
    try std.testing.expect(!atomic.file_exists);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    try writer.writePositionalAll(std.testing.io, "!", 3);
    writer.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    var bytes: [4]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try installed.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("NEW!", &bytes);
}

test "Windows held cold atomic rename requires a write-through source handle" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    const file_id = try windowsColdAtomicIdentity(atomic.file.handle);
    defer deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.Unsupported, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false));
    try std.testing.expect(atomic.file_exists);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, "state.wal", .read_only));
}

test "Windows held cold atomic replacement keeps old destination handle readable" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const old = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try old.writePositionalAll(std.testing.io, "OLD", 0);
    old.close(std.testing.io);
    const old_reader = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer old_reader.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old_reader.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    const writer = try cold_runtime.duplicateFile(atomic.file);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true);
    try std.testing.expect(!atomic.file_exists);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old_reader.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    try std.testing.expectError(error.FileBusy, openColdExisting(std.testing.io, private, "state.wal", .read_only));
    writer.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, private, &temp_name, .read_only));
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    try std.testing.expect(!std.meta.eql(old_id, try cold_identity.statRegular(installed.handle)));
    var bytes: [3]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try installed.readPositionalAll(std.testing.io, &bytes, 0));
    try std.testing.expectEqualStrings("NEW", &bytes);
}

test "Windows held cold atomic replacement refuses an exclusive old destination" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const seed = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try seed.writePositionalAll(std.testing.io, "OLD", 0);
    seed.close(std.testing.io);
    const old = try cold_runtime.openExistingPrivateWindows(private, "state.wal", .remediate);
    var old_open = true;
    defer if (old_open) old.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    var atomic_open = true;
    defer if (atomic_open) deinitColdAtomic(std.testing.io, &atomic, file_id);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    try std.testing.expectError(StoreError.IoAmbiguous, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true));
    try std.testing.expect(!atomic.file_exists);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    atomic_open = false;
    old.close(std.testing.io);
    old_open = false;
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(old_id, try cold_identity.statRegular(installed.handle));
    var new_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(new_bytes.len, try installed.readPositionalAll(std.testing.io, &new_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &new_bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}

test "Windows held cold atomic replacement accepts a read-only delete-share destination" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const seed = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try seed.writePositionalAll(std.testing.io, "OLD", 0);
    seed.close(std.testing.io);
    const old = try openColdExisting(std.testing.io, private, "state.wal", .read_only_share_delete);
    var old_open = true;
    defer if (old_open) old.close(std.testing.io);
    const old_id = try cold_identity.statRegular(old.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    var atomic_open = true;
    defer if (atomic_open) deinitColdAtomic(std.testing.io, &atomic, file_id);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try atomic.file.sync(std.testing.io);
    try renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true);
    var old_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(old_bytes.len, try old.readPositionalAll(std.testing.io, &old_bytes, 0));
    try std.testing.expectEqualStrings("OLD", &old_bytes);
    try std.testing.expect(!std.meta.eql(old_id, file_id));
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    atomic_open = false;
    old.close(std.testing.io);
    old_open = false;
    const installed = try openColdExisting(std.testing.io, private, "state.wal", .read_only);
    defer installed.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(installed.handle));
    var new_bytes: [3]u8 = undefined;
    try std.testing.expectEqual(new_bytes.len, try installed.readPositionalAll(std.testing.io, &new_bytes, 0));
    try std.testing.expectEqualStrings("NEW", &new_bytes);
}

test "Windows held cold atomic rename refuses collision and wrong preconditions" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const foreign = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "foreign");
    defer foreign.close(std.testing.io);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const wrong_parent = try openColdExisting(std.testing.io, foreign, ".", .directory);
    defer wrong_parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    const old = try private.createFile(std.testing.io, "state.wal", .{ .read = true });
    try old.writePositionalAll(std.testing.io, "OLD", 0);
    old.close(std.testing.io);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "NEW", 0);
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "wrong.wal", parent, parent_id, file_id, true));
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", wrong_parent, parent_id, file_id, true));
    var wrong_id = file_id;
    wrong_id.inode_high ^= 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, wrong_id, true));
    try std.testing.expect(atomic.file_exists);
    try std.testing.expectError(error.PathAlreadyExists, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, false));
    try std.testing.expect(!atomic.file_exists);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    const old_bytes = try private.readFileAlloc(std.testing.io, "state.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(old_bytes);
    try std.testing.expectEqualStrings("OLD", old_bytes);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}

test "Windows held cold atomic failed rename leaves safe orphan" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    try private.createDir(std.testing.io, "state.wal", .default_dir);
    const parent = try openColdExisting(std.testing.io, private, ".", .directory);
    defer parent.close(std.testing.io);
    const parent_id = try coldDirectoryIdentity(parent.handle);
    var atomic = try private.createFileAtomic(std.testing.io, "state.wal", .{ .replace = true });
    try makeColdAtomicReadable(std.testing.io, &atomic);
    const file_id = try cold_identity.statRegular(atomic.file.handle);
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    try atomic.file.writePositionalAll(std.testing.io, "SECRET", 0);
    try std.testing.expectError(StoreError.IoAmbiguous, renameHeldColdAtomicWindows(std.testing.io, &atomic, private, "state.wal", parent, parent_id, file_id, true));
    try std.testing.expect(!atomic.file_exists);
    deinitColdAtomic(std.testing.io, &atomic, file_id);
    const destination = try openColdExisting(std.testing.io, private, "state.wal", .directory);
    destination.close(std.testing.io);
    const orphan = try openColdExisting(std.testing.io, private, &temp_name, .read_only);
    defer orphan.close(std.testing.io);
    try std.testing.expectEqualDeep(file_id, try cold_identity.statRegular(orphan.handle));
}

/// testing.tmpDir owns `.zig-cache/tmp/<sub_path>` relative to the current
/// process directory. Native BSD has getcwd but no SDK descriptor-realpath
/// implementation. Derive that documented path, then prove it names the SAME
/// full directory identity as the held fixture before using it in any test.
fn coldFixtureAbsoluteDirectory(tmp: *const std.testing.TmpDir, sub_path: []const u8) ![]u8 {
    if (comptime !cold_posix) {
        const resolved = try tmp.dir.realPathFileAlloc(std.testing.io, sub_path, std.testing.allocator);
        defer std.testing.allocator.free(resolved);
        return std.testing.allocator.dupe(u8, resolved);
    }
    const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const path = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path, sub_path });
    errdefer std.testing.allocator.free(path);
    const held = try openColdExisting(std.testing.io, tmp.dir, sub_path, .directory);
    defer held.close(std.testing.io);
    const named = try openColdExisting(std.testing.io, .cwd(), path, .directory);
    defer named.close(std.testing.io);
    try std.testing.expectEqualDeep(try coldDirectoryIdentity(held.handle), try coldDirectoryIdentity(named.handle));
    return path;
}

fn coldParentDirectoryScenario(first: bool, absolute: bool) !void {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    const parent = try coldFixtureAbsoluteDirectory(&tmp, "state");
    defer std.testing.allocator.free(parent);
    const path = if (absolute) try std.mem.concat(std.testing.allocator, u8, &.{ parent, "/parent.wal" }) else try std.testing.allocator.dupe(u8, "state/parent.wal");
    defer std.testing.allocator.free(path);
    const lock_path = try std.mem.concat(std.testing.allocator, u8, &.{ path, ".lock" });
    defer std.testing.allocator.free(lock_path);
    const lease = try tmp.dir.createFile(std.testing.io, lock_path, .{ .read = true });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    if (first) {
        var stage = try FirstProvisionStage.init(std.testing.allocator, std.testing.io, tmp.dir, path, lease, .{ .changefeed_capacity = 0 });
        defer stage.deinit();
        try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
        const atomic = stage.atomic.?;
        const actual_parent = try atomic.dir.openFile(std.testing.io, std.fs.path.dirname(atomic.dest_sub_path) orelse ".", .{ .allow_directory = true });
        defer actual_parent.close(std.testing.io);
        try std.testing.expectEqualDeep(try coldDirectoryIdentity(actual_parent.handle), try coldDirectoryIdentity(stage.directory.handle));
        try stage.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    } else {
        {
            var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, path, .{ .changefeed_capacity = 0 });
            defer seed.deinit();
            const large: [1000]u8 = @splat(42);
            try seed.put(.props, "old", &large);
        }
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, path, lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
        defer stage.deinit();
        var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
        defer ticket.abort();
        const plan = stage.backing.?.plan.?;
        const actual_parent = try plan.snapshot_atomic.?.dir.openFile(std.testing.io, ".", .{ .allow_directory = true });
        defer actual_parent.close(std.testing.io);
        try std.testing.expectEqualDeep(try coldDirectoryIdentity(actual_parent.handle), try coldDirectoryIdentity(plan.directory.handle));
        try ticket.commit();
        var published = stage.takeCommittedStore();
        defer published.deinit();
        try std.testing.expectEqualStrings("cut", published.get(.props, "new").?);
    }
}
test "retained v2 causal first provisioning syncs actual relative destination parent" {
    try coldParentDirectoryScenario(true, false);
}
test "retained v2 causal first provisioning syncs actual absolute destination parent" {
    try coldParentDirectoryScenario(true, true);
}
test "retained v2 causal cold compaction syncs actual relative destination parent" {
    try coldParentDirectoryScenario(false, false);
}
test "retained v2 causal cold compaction syncs actual absolute destination parent" {
    try coldParentDirectoryScenario(false, true);
}

fn coldFifoScenario(kind: enum { wal, snapshot, temporary, revalidation, lock, parent, regular_control, temporary_control, hot_wal, hot_snapshot, promotion, snapshot_replay }) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try coldFixtureAbsoluteDirectory(&tmp, ".");
    defer std.testing.allocator.free(parent);
    var atomic: ?std.Io.File.Atomic = null;
    defer if (atomic) |*file| deinitColdAtomic(std.testing.io, file, null);
    var captured: ?ColdFile = null;
    defer if (captured) |*file| file.deinit(std.testing.allocator, std.testing.io);
    var hot_store: ?OroStore = null;
    defer if (hot_store) |*store| store.deinit();
    if (kind == .hot_snapshot or kind == .snapshot_replay or kind == .promotion) {
        var seeded = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "fifo.wal");
        try seeded.put(.props, "control", "value");
        if (kind == .snapshot_replay) {
            try seeded.snapshotAndTruncate();
            hot_store = seeded;
        } else seeded.deinit();
        if (kind == .promotion) hot_store = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "fifo.wal", .{});
    }
    var held_lease: ?std.Io.File = null;
    defer if (held_lease) |file| file.close(std.testing.io);
    var name_buffer: [16]u8 = undefined;
    const name: []const u8 = if (kind == .temporary or kind == .temporary_control) block: {
        atomic = try tmp.dir.createFileAtomic(std.testing.io, "fifo.wal", .{ .replace = true });
        name_buffer = std.fmt.hex(atomic.?.file_basename_hex);
        if (kind == .temporary) try atomic.?.dir.deleteFile(std.testing.io, &name_buffer);
        break :block &name_buffer;
    } else if (kind == .snapshot or kind == .hot_snapshot or kind == .snapshot_replay) "fifo.wal.snap" else if (kind == .lock) "fifo.wal.lock" else "fifo.wal";
    if (kind == .revalidation or kind == .lock) {
        const file = try tmp.dir.createFile(std.testing.io, name, .{ .read = true });
        if (kind == .lock) {
            held_lease = file;
            try cold_identity.reaffirmExclusive(file.handle);
        } else {
            try file.writePositionalAll(std.testing.io, "old", 0);
            file.close(std.testing.io);
            captured = try ColdFile.capture(std.testing.allocator, std.testing.io, tmp.dir, name, 1024);
        }
        try tmp.dir.deleteFile(std.testing.io, name);
    }
    if (kind == .regular_control) {
        const file = try tmp.dir.createFile(std.testing.io, name, .{ .read = true });
        try file.writePositionalAll(std.testing.io, "control", 0);
        file.close(std.testing.io);
    }
    if (kind == .promotion or kind == .snapshot_replay) try tmp.dir.deleteFile(std.testing.io, name);
    const path = try std.fs.path.join(std.testing.allocator, &.{ parent, name });
    defer std.testing.allocator.free(path);
    if (kind != .regular_control and kind != .temporary_control) {
        const made = try std.process.run(std.testing.allocator, std.testing.io, .{ .argv = &.{ "mkfifo", path } });
        defer std.testing.allocator.free(made.stdout);
        defer std.testing.allocator.free(made.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, made.term);
    }
    const pid: std.posix.pid_t = if (comptime os == .linux) block: {
        const result = std.os.linux.fork();
        if (std.os.linux.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
        break :block @intCast(result);
    } else std.posix.system.fork();
    if (pid < 0) return error.TestUnexpectedResult;
    if (pid == 0) {
        // Fresh single-threaded I/O; never inherit testing I/O worker locks.
        var child_backend: std.Io.Threaded = .init_single_threaded;
        const child_io = child_backend.io();
        const expected: anyerror = if (kind == .temporary) error.SnapshotCoverageMismatch else if (kind == .parent) error.NotDir else error.NotRegular;
        const refused = if (kind == .temporary or kind == .temporary_control) block: {
            validateColdAtomicName(child_io, &atomic.?, cold_identity.statRegular(atomic.?.file.handle) catch coldFifoExit(12)) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .revalidation) block: {
            captured.?.validate(child_io, tmp.dir, name) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .lock) block: {
            validateColdLease(child_io, tmp.dir, held_lease.?, name, cold_identity.statRegular(held_lease.?.handle) catch coldFifoExit(12)) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .parent) block: {
            const file = coldOpenParent(child_io, tmp.dir, "fifo.wal/child") catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            file.close(child_io);
            break :block false;
        } else if (kind == .hot_wal or kind == .hot_snapshot) block: {
            var store = OroStore.openReadOnlyWithConfig(std.heap.page_allocator, child_io, tmp.dir, "fifo.wal", .{ .changefeed_capacity = 0 }) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            store.deinit();
            break :block false;
        } else if (kind == .promotion) block: {
            hot_store.?.io = child_io;
            hot_store.?.preparePromotion() catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else if (kind == .snapshot_replay) block: {
            hot_store.?.io = child_io;
            _ = hot_store.?.replayFile(name, .snapshot, 0) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            break :block false;
        } else block: {
            var file = ColdFile.capture(std.heap.page_allocator, child_io, tmp.dir, name, 1024) catch |err| {
                if (err != expected) coldFifoExit(14);
                break :block true;
            };
            file.deinit(std.heap.page_allocator, child_io);
            break :block false;
        };
        const control = kind == .regular_control or kind == .temporary_control;
        coldFifoExit(if (refused != control) 0 else 13);
    }
    var status: i32 = 0;
    var reaped = false;
    defer if (!reaped) coldFifoKillReap(pid);
    var finished = false;
    for (0..100) |_| {
        const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &status, std.posix.W.NOHANG, null))) else std.posix.system.waitpid(pid, &status, std.posix.W.NOHANG);
        if (result == pid) {
            finished = true;
            reaped = true;
            break;
        }
        if (result < 0) {
            if ((if (comptime @import("builtin").os.tag == .linux) std.os.linux.errno(@bitCast(result)) else std.posix.errno(result)) == .INTR) continue;
            return error.TestUnexpectedResult;
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    }
    if (!finished) {
        coldFifoKillReap(pid);
        reaped = true;
        // Avoid cleanup reopening the hostile FIFO through the old validator.
        if (atomic) |*file| file.file_exists = false;
        return error.TestUnexpectedResult;
    }
    // On successful bounded refusal, cleanup itself must safely inspect and
    // preserve the foreign FIFO name rather than blocking or unlinking it.
    try std.testing.expectEqual(@as(i32, 0), status);
    if (kind == .temporary) {
        deinitColdAtomic(std.testing.io, &atomic.?, null);
        atomic = null;
        try std.testing.expectEqual(std.Io.File.Kind.named_pipe, (try tmp.dir.statFile(std.testing.io, name, .{ .follow_symlinks = false })).kind);
    }
}
fn coldFifoExit(code: u8) noreturn {
    if (comptime @import("builtin").os.tag == .linux) std.os.linux.exit(code);
    std.posix.system._exit(code);
}
test "retained v2 causal FIFO WAL capture is bounded" {
    try coldFifoScenario(.wal);
}
test "retained v2 causal FIFO snapshot capture is bounded" {
    try coldFifoScenario(.snapshot);
}
test "retained v2 causal FIFO substituted temporary refusal is bounded" {
    try coldFifoScenario(.temporary);
}

test "cold recovery actual directory custody rejects replaced parent before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    {
        var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "state/custody.wal", .{ .changefeed_capacity = 0 });
        defer seed.deinit();
        const large: [1000]u8 = @splat(41);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "state/custody.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "state/custody.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    try tmp.dir.rename("state", tmp.dir, "previous", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    try std.testing.expectError(error.FileNotFound, ticket.commit());
    try std.testing.expect(!stage.backing.?.consumed);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/custody.wal", .read_only));
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "previous/custody.wal.snap", .read_only));
    // Restore the exact configured parent and retry this still-owned ticket.
    try tmp.dir.deleteDir(std.testing.io, "state");
    try tmp.dir.rename("previous", tmp.dir, "state", std.testing.io);
    try ticket.commit();
    var result = stage.takeCommittedStore();
    defer result.deinit();
    try std.testing.expectEqualStrings("cut", result.get(.props, "new").?);
}

test "cold recovery held directory descriptor retarget refuses before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "retarget.wal");
        defer seed.deinit();
        const large: [1000]u8 = @splat(40);
        try seed.put(.props, "old", &large);
    }
    const lease = try tmp.dir.createFile(std.testing.io, "retarget.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "retarget.wal", lease, .{ .max_wal_bytes = 1800, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "new", .value = "cut" }});
    defer ticket.abort();
    const plan = &stage.backing.?.plan.?;
    const held = plan.directory;
    try tmp.dir.createDir(std.testing.io, "foreign", .default_dir);
    const wrong = try openColdExisting(std.testing.io, tmp.dir, "foreign", .directory);
    defer wrong.close(std.testing.io);
    plan.directory = wrong;
    errdefer if (stage.backing.?.plan) |*still_owned| {
        still_owned.directory = held;
    };
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!stage.backing.?.consumed);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "retarget.wal.snap", .read_only));
    plan.directory = held;
    try ticket.commit();
    var result = stage.takeCommittedStore();
    defer result.deinit();
    try std.testing.expectEqualStrings("cut", result.get(.props, "new").?);
}

test "retained v2 causal FIFO configured transcript revalidation is bounded" {
    try coldFifoScenario(.revalidation);
}
test "retained v2 causal FIFO configured lease revalidation is bounded" {
    try coldFifoScenario(.lock);
}
test "retained v2 causal FIFO destination parent acquisition is bounded" {
    try coldFifoScenario(.parent);
}

const PublicationSyncWitness = struct {
    expected: cold_identity.Identity,
    original: *const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void,
    seen: usize = 0,
    mismatch: bool = false,
    retarget_dir: ?std.Io.Dir = null,
    retarget_when: enum { none, snapshot_sync, directory_sync } = .none,
    retargeted: bool = false,
    failing: ?*std.testing.FailingAllocator = null,
    publication_allocs: ?usize = null,
};
threadlocal var publication_sync_witness: ?*PublicationSyncWitness = null;
fn observePublicationSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const witness = publication_sync_witness.?;
    const directory = if (coldDirectoryIdentity(file.handle)) |identity| block: {
        witness.seen += 1;
        if (witness.failing) |failing| if (witness.publication_allocs == null) {
            witness.publication_allocs = failing.alloc_index;
            failing.fail_index = failing.alloc_index;
        };
        witness.mismatch = witness.mismatch or !std.meta.eql(witness.expected, identity);
        break :block true;
    } else |_| false;
    if (!witness.retargeted and (if (directory) witness.retarget_when == .directory_sync else witness.retarget_when == .snapshot_sync)) {
        const dir = witness.retarget_dir.?;
        dir.rename("state", dir, "previous", std.testing.io) catch return error.Unexpected;
        dir.createDir(std.testing.io, "state", .default_dir) catch return error.Unexpected;
        witness.retargeted = true;
    }
    return witness.original(userdata, file);
}
fn genericCompactionParentScenario(absolute: bool) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    const parent_path = try coldFixtureAbsoluteDirectory(&tmp, "state");
    defer std.testing.allocator.free(parent_path);
    const absolute_path = try std.fs.path.join(std.testing.allocator, &.{ parent_path, "ordinary.wal" });
    defer std.testing.allocator.free(absolute_path);
    const path = if (absolute) absolute_path else "state/ordinary.wal";
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, path);
    defer store.deinit();
    try store.put(.props, "old", "cut");
    const parent = try coldOpenParent(std.testing.io, tmp.dir, path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try store.snapshotAndTruncate();
    try std.testing.expectEqual(@as(usize, 2), witness.seen);
    try std.testing.expect(!witness.mismatch);
    try std.testing.expectEqualStrings("cut", store.get(.props, "old").?);
}
test "retained v2 causal ordinary compaction syncs actual relative destination parent" {
    try genericCompactionParentScenario(false);
}
test "retained v2 causal ordinary compaction syncs actual absolute destination parent" {
    try genericCompactionParentScenario(true);
}

fn coldFifoKillReap(pid: std.posix.pid_t) void {
    const os = @import("builtin").os.tag;
    if (comptime os == .linux) {
        _ = std.os.linux.kill(pid, .KILL);
    } else {
        _ = std.posix.system.kill(pid, std.posix.SIG.KILL);
    }
    var status: i32 = 0;
    while (true) {
        const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &status, 0, null))) else std.posix.system.waitpid(pid, &status, 0);
        if (result == pid) return;
        if (result < 0 and (if (comptime @import("builtin").os.tag == .linux) std.os.linux.errno(@bitCast(result)) else std.posix.errno(result)) == .INTR) continue;
        return;
    }
}
test "retained v2 causal FIFO protocol regular child control" {
    try coldFifoScenario(.regular_control);
    try coldFifoScenario(.temporary_control);
}
test "retained v2 causal FIFO hot read only WAL refusal is bounded" {
    try coldFifoScenario(.hot_wal);
}
test "retained v2 causal FIFO hot read only snapshot refusal is bounded" {
    try coldFifoScenario(.hot_snapshot);
}
test "retained v2 causal FIFO hot prepared promotion refusal is bounded" {
    try coldFifoScenario(.promotion);
}
test "retained v2 causal FIFO snapshot replay refusal is bounded" {
    try coldFifoScenario(.snapshot_replay);
}

fn genericCompactionRetargetScenario(after_snapshot: bool) !void {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "state", .default_dir);
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "state/retarget.wal");
    defer store.deinit();
    try store.put(.props, "old", "accepted");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "state/retarget.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const parent = try coldOpenParent(std.testing.io, tmp.dir, store.wal_path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync, .retarget_dir = tmp.dir, .retarget_when = if (after_snapshot) .directory_sync else .snapshot_sync };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(if (after_snapshot) error.IoAmbiguous else error.SnapshotCoverageMismatch, store.snapshotAndTruncate());
    try std.testing.expect(witness.retargeted);
    try std.testing.expect(!witness.mismatch);
    try std.testing.expectEqual(after_snapshot, store.preparedWritesPoisoned());
    const retained_wal = try tmp.dir.readFileAlloc(std.testing.io, "previous/retarget.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(retained_wal);
    try std.testing.expectEqualSlices(u8, before, retained_wal);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "state/retarget.wal", .read_only));
    try tmp.dir.deleteDir(std.testing.io, "state");
    try tmp.dir.rename("previous", tmp.dir, "state", std.testing.io);
    store.io = std.testing.io;
    if (!after_snapshot) try store.snapshotAndTruncate();
    var reopened = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "state/retarget.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("accepted", reopened.get(.props, "old").?);
}
test "retained v2 ordinary compaction parent retarget before snapshot publication preserves WAL and retries" {
    try genericCompactionRetargetScenario(false);
}
test "retained v2 ordinary compaction parent retarget after snapshot sync preserves WAL and poisons" {
    try genericCompactionRetargetScenario(true);
}

fn liveCompactionAllocationScenario(allocator: std.mem.Allocator, existing_snapshot: bool) !void {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-oom.wal");
    defer store.deinit();
    try store.put(.props, "accepted", "before");
    if (existing_snapshot) {
        try store.snapshotAndTruncate();
        try store.put(.props, "second", "retained");
    }
    const seq = store.next_seq;
    const offset = store.wal_offset;
    const before = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const snapshot = if (existing_snapshot) try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal.snap", std.testing.allocator, .unlimited) else null;
    defer if (snapshot) |bytes| std.testing.allocator.free(bytes);
    const identity = try cold_identity.statRegular(store.wal_file.?.handle);
    store.allocator = allocator;
    defer store.allocator = std.testing.allocator;
    store.snapshotAndTruncate() catch |err| {
        store.allocator = std.testing.allocator;
        if (err == error.OutOfMemory) {
            try std.testing.expect(!store.preparedWritesPoisoned());
            try std.testing.expectEqual(seq, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
            try std.testing.expectEqualDeep(identity, try cold_identity.statRegular(store.wal_file.?.handle));
            const after = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            if (snapshot) |bytes| {
                const actual = try tmp.dir.readFileAlloc(std.testing.io, "live-oom.wal.snap", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(actual);
                try std.testing.expectEqualSlices(u8, bytes, actual);
            } else try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "live-oom.wal.snap", .read_only));
            try store.snapshotAndTruncate();
            try std.testing.expectEqual(seq, store.next_seq);
            try std.testing.expectEqualStrings("before", store.get(.props, "accepted").?);
            var reopened = try openTestStore(tmp, "live-oom.wal");
            defer reopened.deinit();
            try std.testing.expectEqual(seq, reopened.next_seq);
            try std.testing.expectEqualStrings("before", reopened.get(.props, "accepted").?);
        }
        return err;
    };
    store.allocator = std.testing.allocator;
    try std.testing.expectEqual(seq, store.next_seq);
}
test "retained v2 live atomic compaction exhaustive OOM preserves old cut and retries" {
    // Scenario is a skip-stub where cold_posix is false; checkAllAllocationFailures needs a real OOM-capable fn.
    if (comptime !cold_posix) return error.SkipZigTest;
    for ([_]bool{ false, true }) |snapshot| try std.testing.checkAllAllocationFailures(std.testing.allocator, liveCompactionAllocationScenario, .{snapshot});
}
test "retained v2 live atomic compaction allocates nothing after snapshot publication and moves exact writer" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-armed.wal");
    defer store.deinit();
    try store.put(.props, "accepted", "before");
    const old = std.Io.File{ .handle = try cold_runtime.duplicate(store.wal_file.?.handle), .flags = store.wal_file.?.flags };
    defer old.close(std.testing.io);
    const old_size = (try old.stat(std.testing.io)).size;
    const old_identity = try cold_identity.statRegular(old.handle);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const parent = try coldOpenParent(std.testing.io, tmp.dir, store.wal_path);
    defer parent.close(std.testing.io);
    var witness: PublicationSyncWitness = .{ .expected = try coldDirectoryIdentity(parent.handle), .original = std.testing.io.vtable.fileSync, .failing = &failing };
    var vtable = std.testing.io.vtable.*;
    vtable.fileSync = observePublicationSync;
    publication_sync_witness = &witness;
    defer publication_sync_witness = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    store.allocator = failing.allocator();
    defer store.allocator = std.testing.allocator;
    try store.snapshotAndTruncate();
    try std.testing.expectEqual(witness.publication_allocs.?, failing.alloc_index);
    try std.testing.expect(!std.meta.eql(old_identity, try cold_identity.statRegular(store.wal_file.?.handle)));
    try std.testing.expectEqual(@as(u64, 25), store.wal_offset);
    store.allocator = std.testing.allocator;
    store.io = std.testing.io;
    try store.put(.props, "after", "new writer");
    try std.testing.expectEqual(old_size, (try old.stat(std.testing.io)).size);
    var reopened = try openTestStore(tmp, "live-armed.wal");
    defer reopened.deinit();
    try std.testing.expectEqualStrings("new writer", reopened.get(.props, "after").?);
}
test "retained v2 live atomic compaction all publication ambiguities poison and recover exact logical cut" {
    if (comptime !cold_posix) return error.SkipZigTest;
    const Boundary = @FieldType(PreparedIoFault, "compaction_boundary");
    for ([_]Boundary{ .after_snapshot_replace, .after_snapshot_dir_sync, .after_wal_replace, .after_wal_dir_sync }) |boundary| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "live-fault.wal");
        defer store.deinit();
        try store.put(.props, "accepted", "before");
        const seq = store.next_seq;
        const old_identity = try cold_identity.statRegular(store.wal_file.?.handle);
        const old_size = store.wal_offset;
        store.setPreparedIoFault(.{ .compaction_boundary = boundary });
        try std.testing.expectError(error.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(seq, store.next_seq);
        try std.testing.expectEqualStrings("before", store.get(.props, "accepted").?);
        try std.testing.expectEqualDeep(old_identity, try cold_identity.statRegular(store.wal_file.?.handle));
        try std.testing.expectEqual(old_size, (try store.wal_file.?.stat(std.testing.io)).size);
        try std.testing.expectError(error.StorePoisoned, store.preparePut(.props, "forbidden", "append"));
        var reopened = try openTestStore(tmp, "live-fault.wal");
        defer reopened.deinit();
        try std.testing.expectEqual(seq, reopened.next_seq);
        try std.testing.expectEqualStrings("before", reopened.get(.props, "accepted").?);
        try reopened.put(.props, "retry", "valid");
    }
}

test "retained v2 hot safe acquisition refuses WAL snapshot and promotion symlinks without mutation" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "hot-links.wal");
        defer seed.deinit();
        try seed.put(.props, "accepted", "value");
        try seed.snapshotAndTruncate();
    }
    const before = try tmp.dir.readFileAlloc(std.testing.io, "hot-links.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try tmp.dir.rename("hot-links.wal", tmp.dir, "actual.wal", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.wal", "hot-links.wal", .{});
    try std.testing.expectError(error.SymLinkLoop, OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{}));
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal");
    try tmp.dir.rename("actual.wal", tmp.dir, "hot-links.wal", std.testing.io);
    try tmp.dir.rename("hot-links.wal.snap", tmp.dir, "actual.snap", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.snap", "hot-links.wal.snap", .{});
    try std.testing.expectError(error.SymLinkLoop, OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{}));
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal.snap");
    try tmp.dir.rename("actual.snap", tmp.dir, "hot-links.wal.snap", std.testing.io);
    var stage = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "hot-links.wal", .{});
    defer stage.deinit();
    try tmp.dir.rename("hot-links.wal", tmp.dir, "actual.wal", std.testing.io);
    try tmp.dir.symLink(std.testing.io, "actual.wal", "hot-links.wal", .{});
    try std.testing.expectError(error.SymLinkLoop, stage.preparePromotion());
    try std.testing.expect(stage.staged_write_file == null);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "actual.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try tmp.dir.deleteFile(std.testing.io, "hot-links.wal");
    try tmp.dir.rename("actual.wal", tmp.dir, "hot-links.wal", std.testing.io);
    try stage.preparePromotion();
}

const HotReplayRetarget = struct {
    dir: std.Io.Dir,
    original: *const fn (?*anyopaque, std.Io.File) std.Io.File.StatError!std.Io.File.Stat,
    changed: bool = false,
};
threadlocal var hot_replay_retarget: ?*HotReplayRetarget = null;
fn retargetHotWalOnFirstStat(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.StatError!std.Io.File.Stat {
    const witness = hot_replay_retarget.?;
    const stat = try witness.original(userdata, file);
    if (!witness.changed) {
        witness.dir.rename("held.wal", witness.dir, "original.wal", std.testing.io) catch return error.Unexpected;
        witness.dir.rename("foreign.wal", witness.dir, "held.wal", std.testing.io) catch return error.Unexpected;
        witness.changed = true;
    }
    return stat;
}
test "retained v2 hot replay reads original held WAL and promotion refuses namespace retarget" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var original = try openTestStore(tmp, "held.wal");
        defer original.deinit();
        try original.put(.props, "cut", "accepted");
        var foreign = try openTestStore(tmp, "foreign.wal");
        defer foreign.deinit();
        try foreign.put(.props, "cut", "foreign");
    }
    var witness: HotReplayRetarget = .{ .dir = tmp.dir, .original = std.testing.io.vtable.fileStat };
    var vtable = std.testing.io.vtable.*;
    vtable.fileStat = retargetHotWalOnFirstStat;
    hot_replay_retarget = &witness;
    defer hot_replay_retarget = null;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var stage = try OroStore.openReadOnlyWithConfig(std.testing.allocator, io, tmp.dir, "held.wal", .{});
    defer stage.deinit();
    try std.testing.expect(witness.changed);
    try std.testing.expectEqualStrings("accepted", stage.get(.props, "cut").?);
    try std.testing.expectError(error.SnapshotCoverageMismatch, stage.preparePromotion());
    try std.testing.expect(stage.staged_write_file == null);
}

const LiveTempReplacement = struct {
    original_create: *const fn (?*anyopaque, std.Io.Dir, []const u8, std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic,
    original_sync: *const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void,
    snapshot: ?std.Io.File.Atomic = null,
    snapshot_identity: ?cold_identity.Identity = null,
    substituted: bool = false,
};
threadlocal var live_temp_replacement: ?*LiveTempReplacement = null;
fn observeLiveAtomic(userdata: ?*anyopaque, dir: std.Io.Dir, path: []const u8, options: std.Io.Dir.CreateFileAtomicOptions) std.Io.Dir.CreateFileAtomicError!std.Io.File.Atomic {
    const witness = live_temp_replacement.?;
    const file = try witness.original_create(userdata, dir, path, options);
    if (std.mem.endsWith(u8, path, ".snap")) {
        witness.snapshot = file;
        witness.snapshot_identity = cold_identity.statRegular(file.file.handle) catch return error.Unexpected;
    }
    return file;
}
fn replaceLiveSnapshotTemp(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const witness = live_temp_replacement.?;
    try witness.original_sync(userdata, file);
    if (!witness.substituted and witness.snapshot != null and std.meta.eql(witness.snapshot_identity.?, cold_identity.statRegular(file.handle) catch return)) {
        const atomic = witness.snapshot.?;
        const name = std.fmt.hex(atomic.file_basename_hex);
        const foreign = atomic.dir.createFile(std.testing.io, "replacement", .{ .read = true }) catch return error.Unexpected;
        defer foreign.close(std.testing.io);
        foreign.writePositionalAll(std.testing.io, "FOREIGN", 0) catch return error.Unexpected;
        atomic.dir.rename("replacement", atomic.dir, &name, std.testing.io) catch return error.Unexpected;
        witness.substituted = true;
    }
}
test "retained v2 live compaction refuses substituted snapshot temp and preserves foreign name" {
    if (comptime !cold_posix) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "live-temp.wal");
    defer store.deinit();
    try store.put(.props, "cut", "accepted");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "live-temp.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    var witness: LiveTempReplacement = .{ .original_create = std.testing.io.vtable.dirCreateFileAtomic, .original_sync = std.testing.io.vtable.fileSync };
    var vtable = std.testing.io.vtable.*;
    vtable.dirCreateFileAtomic = observeLiveAtomic;
    vtable.fileSync = replaceLiveSnapshotTemp;
    live_temp_replacement = &witness;
    defer live_temp_replacement = null;
    store.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    try std.testing.expectError(error.SnapshotCoverageMismatch, store.snapshotAndTruncate());
    try std.testing.expect(witness.substituted);
    try std.testing.expect(!store.preparedWritesPoisoned());
    const name = std.fmt.hex(witness.snapshot.?.file_basename_hex);
    const survivor = try tmp.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(survivor);
    try std.testing.expectEqualStrings("FOREIGN", survivor);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "live-temp.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectError(error.FileNotFound, openColdExisting(std.testing.io, tmp.dir, "live-temp.wal.snap", .read_only));
}

test "STORE KvTable causal prepare growth OOM preserves OLD backing and capacity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
    var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "kvtable-growth-causal.wal");
    defer store.deinit();
    const map = &store.maps[0].map;
    try map.ensureUnusedCapacity(1);
    var index: usize = 0;
    while (index < 6) : (index += 1) {
        var buf: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buf, "old-{d}", .{index});
        try store.put(.accounts, key, "unchanged");
    }
    const old_capacity = map.capacity();
    const old_backing = map.slots.ptr;
    const old_wal = store.wal_offset;
    const old_seq = store.next_seq;
    const old_feed = store.changeCount();
    failing.fail_index = failing.alloc_index + 1;
    try std.testing.expectError(error.OutOfMemory, store.preparePut(.accounts, "new-key", "candidate"));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(u32, 6), map.count());
    try std.testing.expect(store.get(.accounts, "new-key") == null);
    index = 0;
    while (index < 6) : (index += 1) {
        var buf: [32]u8 = undefined;
        try std.testing.expectEqualStrings("unchanged", store.get(.accounts, try std.fmt.bufPrint(&buf, "old-{d}", .{index})).?);
    }
    try std.testing.expectEqual(old_wal, store.wal_offset);
    try std.testing.expectEqual(old_seq, store.next_seq);
    try std.testing.expectEqual(old_feed, store.changeCount());
    std.debug.print("KvTable actual causal capacity before={d} after={d}; backing unchanged={}\n", .{ old_capacity, map.capacity(), old_backing == map.slots.ptr });
    try std.testing.expectEqual(old_capacity, map.capacity());
    try std.testing.expect(old_backing == map.slots.ptr);
}

fn tableTestPut(table: *KvTable, key: []const u8, value: []const u8) !void {
    const gop = try table.getOrPut(key);
    gop.key_ptr.* = key;
    gop.value_ptr.* = @constCast(value);
}

fn tableTestCollisions(storage: [][32]u8, keys: [][]const u8, bucket: usize) !void {
    var trial: usize = 0;
    var found: usize = 0;
    while (found < keys.len) : (trial += 1) {
        var buffer: [32]u8 = undefined;
        const key = try std.fmt.bufPrint(&buffer, "collision-{d}", .{trial});
        if (KvTable.keyHash(key) & 7 != bucket) continue;
        @memcpy(storage[found][0..key.len], key);
        keys[found] = storage[found][0..key.len];
        found += 1;
    }
}

test "STORE KvTable private wrap collision tombstone sparse FINAL preserves surviving OLD slots" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var storage: [8][32]u8 = undefined;
    var keys: [8][]const u8 = undefined;
    try tableTestCollisions(&storage, &keys, 7);
    for (keys[0..4]) |key| try tableTestPut(&table, key, "OLD");
    const backing = table.slots.ptr;
    const survivor = table.getEntry(keys[2]).?.key_ptr;
    var plan = try table.prepare(&.{ .{ .key = keys[0], .value = null }, .{ .key = keys[3], .value = @constCast("new") }, .{ .key = keys[4], .value = @constCast("added") }, .{ .key = keys[5], .value = @constCast("last") } }, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expect(plan.patch_count <= 4);
    try std.testing.expectEqualStrings("OLD", table.get(keys[0]).?);
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expect(table.slots.ptr == backing);
    try std.testing.expect(table.getEntry(keys[2]).?.key_ptr == survivor);
    try std.testing.expect(table.get(keys[0]) == null);
    try std.testing.expectEqualStrings("added", table.get(keys[4]).?);
    try std.testing.expectEqualStrings("new", table.get(keys[3]).?);
    try std.testing.expectEqual(@as(u32, 5), table.count());
    try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
}

test "STORE KvTable private repeated key retains OLD slot and final fit avoids transient growth" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
    for (keys) |key| try tableTestPut(&table, key, "OLD");
    const old_slot = table.getEntry("a").?.key_ptr;
    var plan = try table.prepare(&.{ .{ .key = "a", .value = null }, .{ .key = "temporary", .value = @constCast("scratch") }, .{ .key = "a", .value = @constCast("FINAL") }, .{ .key = "temporary", .value = null }, .{ .key = "b", .value = @constCast("second") } }, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expectEqual(@as(u32, 6), plan.final_count);
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expect(table.getEntry("a").?.key_ptr == old_slot);
    try std.testing.expectEqualStrings("FINAL", table.get("a").?);
    try std.testing.expect(table.get("temporary") == null);
    try std.testing.expectEqual(@as(u32, 8), table.capacity());
}

test "STORE KvTable private detached growth and pressure rebuild abort exact OLD then retry" {
    for ([_]bool{ false, true }) |pressure| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
        for (keys) |key| try tableTestPut(&table, key, "OLD");
        if (pressure) for (keys[0..5]) |key| {
            _ = table.remove(key);
        };
        const old = try std.testing.allocator.dupe(KvTable.Slot, table.slots);
        defer std.testing.allocator.free(old);
        const ptr = table.slots.ptr;
        const edits = [_]KvTable.Edit{ .{ .key = "g", .value = @constCast("NEW") }, .{ .key = "h", .value = @constCast("NEW2") } };
        var plan = try table.prepare(&edits, std.math.maxInt(u64));
        try std.testing.expect(plan.replacement != null);
        try std.testing.expectEqual(@as(usize, if (pressure) 8 else 16), plan.replacement.?.len);
        plan.abort();
        try std.testing.expect(table.slots.ptr == ptr);
        for (old, table.slots) |before, after| try std.testing.expect(KvTable.slotSame(before, after));
        var retry = try table.prepare(&edits, std.math.maxInt(u64));
        defer retry.abort();
        try retry.validate();
        const retired = retry.publish().?;
        try std.testing.expect(retired.ptr == ptr);
        table.allocator.free(retired); // source-owned caller's declared finish
        try std.testing.expectEqualStrings("NEW", table.get("g").?);
        try std.testing.expectEqualStrings("OLD", table.get("f").?);
        try std.testing.expect(retry.work.probes > 0 and retry.work.rows > 0 and retry.work.rebuilt_bytes > 0);
    }
}

test "STORE KvTable private stale wrong index key value scalar and detached tamper refuse" {
    for (0..7) |kind| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        try tableTestPut(&table, "a", "OLD");
        var value = [_]u8{'X'};
        var plan = try table.prepare(&.{.{ .key = "a", .value = &value }}, std.math.maxInt(u64));
        defer plan.abort();
        switch (kind) {
            0 => plan.patches[0].index = (plan.patches[0].index + 1) % table.capacity(),
            1 => plan.final_count += 1,
            2 => value[0] = 'Y',
            3 => plan.expected_revision += 1,
            4 => plan.patches[0].after.key = "other",
            5 => {
                try tableTestPut(&table, "b", "foreign");
            },
            6 => plan.patch_count = KvTable.max_edits + 1,
            else => unreachable,
        }
        try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
    }
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var edits: [8]KvTable.Edit = undefined;
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" };
    for (keys, 0..) |key, i| edits[i] = .{ .key = key, .value = @constCast("NEW") };
    var plan = try table.prepare(&edits, std.math.maxInt(u64));
    defer plan.abort();
    for (plan.replacement.?) |*slot| if (slot.state == .used) {
        slot.hash ^= 1;
        break;
    };
    try std.testing.expectError(StoreError.InvalidTablePlan, plan.validate());
    try std.testing.expectEqual(@as(u32, 0), table.count());
}

test "STORE KvTable private work overflow malformed load and revision exhaustion are bounded" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    try tableTestPut(&table, "a", "OLD");
    const ptr = table.slots.ptr;
    try std.testing.expectError(StoreError.TableWorkExceeded, table.prepare(&.{.{ .key = "b", .value = @constCast("new") }}, 0));
    var work: KvTable.Work = .{ .total = std.math.maxInt(u64) };
    try std.testing.expectError(StoreError.TableWorkExceeded, work.charge(&work.rows, 1));
    table.tombstones = table.capacity();
    try std.testing.expectError(StoreError.InvalidTablePlan, table.prepare(&.{.{ .key = "b", .value = null }}, std.math.maxInt(u64)));
    table.tombstones = 0;
    table.revision = std.math.maxInt(u64);
    try std.testing.expectError(StoreError.SequenceExhausted, table.prepare(&.{.{ .key = "b", .value = null }}, std.math.maxInt(u64)));
    try std.testing.expect(table.slots.ptr == ptr);
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
}

fn tablePreparedOomScenario(allocator: std.mem.Allocator) !void {
    var table = KvTable.init(allocator);
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    const ptr = table.slots.ptr;
    var plan = table.prepare(&.{.{ .key = "g", .value = @constCast("NEW") }}, std.math.maxInt(u64)) catch |err| {
        try std.testing.expect(table.slots.ptr == ptr);
        try std.testing.expectEqual(@as(u32, 8), table.capacity());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
        return err;
    };
    defer plan.abort();
    try plan.validate();
    if (plan.publish()) |retired| allocator.free(retired);
    try std.testing.expectEqualStrings("NEW", table.get("g").?);
}

test "STORE KvTable private exhaustive OOM rollback and actual armed publication" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, tablePreparedOomScenario, .{});
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = KvTable.init(failing.allocator());
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    var plan = try table.prepare(&.{.{ .key = "g", .value = @constCast("NEW") }}, std.math.maxInt(u64));
    defer plan.abort();
    try plan.validate();
    const allocs = failing.alloc_index;
    const frees = failing.deallocations;
    failing.fail_index = allocs;
    const retired = plan.publish().?;
    try std.testing.expectEqual(allocs, failing.alloc_index);
    try std.testing.expectEqual(frees, failing.deallocations);
    failing.allocator().free(retired);
    try std.testing.expectEqualStrings("NEW", table.get("g").?);
}

test "STORE KvTable ordinary deterministic differential lookup delete iterator and tombstone reuse" {
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    var reference = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer reference.deinit();
    var storage: [128][32]u8 = undefined;
    var keys: [128][]const u8 = undefined;
    for (&storage, 0..) |*buffer, i| keys[i] = try std.fmt.bufPrint(buffer, "key-{d}", .{i});
    const values = [_][]const u8{ "one", "two", "three", "four" };
    var random = std.Random.DefaultPrng.init(0x5a179eb22);
    for (0..4000) |_| {
        const index = random.random().uintLessThan(usize, keys.len);
        if (random.random().boolean()) {
            const value = values[random.random().uintLessThan(usize, values.len)];
            try tableTestPut(&table, keys[index], value);
            try reference.put(keys[index], value);
        } else try std.testing.expectEqual(reference.remove(keys[index]), table.remove(keys[index]));
        try std.testing.expectEqual(reference.count(), table.count());
        var seen: usize = 0;
        var iterator = table.iterator();
        while (iterator.next()) |entry| {
            seen += 1;
            try std.testing.expectEqualStrings(reference.get(entry.key_ptr.*).?, entry.value_ptr.*);
        }
        try std.testing.expectEqual(@as(usize, table.count()), seen);
        for (keys) |key| {
            if (reference.get(key)) |value| try std.testing.expectEqualStrings(value, table.get(key).?) else try std.testing.expect(table.get(key) == null);
        }
    }
}

test "STORE KvTable private 5001 population sparse preparation has no full table census" {
    const storage = try std.testing.allocator.alloc([32]u8, 5001);
    defer std.testing.allocator.free(storage);
    var table = KvTable.init(std.testing.allocator);
    defer table.deinit();
    for (storage, 0..) |*buffer, i| try tableTestPut(&table, try std.fmt.bufPrint(buffer, "population-{d}", .{i}), "OLD");
    var target: [32]u8 = undefined;
    var plan = try table.prepare(&.{.{ .key = try std.fmt.bufPrint(&target, "population-{d}", .{2500}), .value = @constCast("FINAL") }}, std.math.maxInt(u64));
    defer plan.abort();
    try std.testing.expect(plan.replacement == null);
    try std.testing.expectEqual(@as(u64, 0), plan.work.rows);
    try std.testing.expectEqual(@as(u64, 0), plan.work.rebuilt_bytes);
    try std.testing.expect(plan.work.probes <= table.capacity());
    try plan.validate();
    try std.testing.expect(plan.publish() == null);
    try std.testing.expectEqualStrings("FINAL", table.get("population-2500").?);
    std.debug.print("KvTable5001 slot_bytes={d} backing_bytes={d} prepare probes={d} comparisons={d} rows={d} bytes={d}\n", .{ @sizeOf(KvTable.Slot), table.slots.len * @sizeOf(KvTable.Slot), plan.work.probes, plan.work.comparisons, plan.work.rows, plan.work.bytes });
}

test "STORE KvTable prepared batch all allocation failures preserve exact OLD tables and retry" {
    var fail_offset: usize = 0;
    while (fail_offset < 100) : (fail_offset += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = std.math.maxInt(usize), .resize_fail_index = 0 });
        var store = try OroStore.openWithConfig(failing.allocator(), std.testing.io, tmp.dir, "table-batch-oom.wal", .{ .changefeed_capacity = 1 });
        defer store.deinit();
        const affected_families = [_]Family{ .accounts, .nicks, .props, .vhosts };
        for (affected_families) |family| for (0..6) |i| {
            var buffer: [32]u8 = undefined;
            try store.put(family, try std.fmt.bufPrint(&buffer, "OLD-{d}", .{i}), "OLD-value");
        };
        var copies: [4][]KvTable.Slot = undefined;
        var pointers: [4][*]KvTable.Slot = undefined;
        var revisions: [4]u64 = undefined;
        for (affected_families, 0..) |family, i| {
            const table = &store.maps[familyIndex(family)].map;
            copies[i] = try std.testing.allocator.dupe(KvTable.Slot, table.slots);
            pointers[i] = table.slots.ptr;
            revisions[i] = table.revision;
        }
        defer for (copies) |copy| std.testing.allocator.free(copy);
        const old_wal = try readWalForTest(tmp, "table-batch-oom.wal");
        defer std.testing.allocator.free(old_wal);
        const old_offset = store.wal_offset;
        const old_seq = store.next_seq;
        const old_change = store.changeAt(0).?;
        var edits: [4]BatchMutation = undefined;
        for (affected_families, 0..) |family, i| edits[i] = .{ .family = family, .kind = .put, .key = "NEW", .value = "candidate" };
        failing.fail_index = failing.alloc_index + fail_offset;
        if (store.prepareBatch(&edits)) |value| {
            var prepared = value;
            defer prepared.abort();
            const allocations = failing.alloc_index;
            const deallocations = failing.deallocations;
            failing.fail_index = allocations;
            try prepared.commit();
            try std.testing.expectEqual(allocations, failing.alloc_index);
            try std.testing.expectEqual(deallocations, failing.deallocations);
            for (affected_families) |family| try std.testing.expectEqualStrings("candidate", store.get(family, "NEW").?);
            try std.testing.expectEqual(old_seq + 4, store.next_seq);
            std.debug.print("KvTable batch exhaustive candidate allocation indices={d}\n", .{fail_offset});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(store.active_batch == null);
            for (affected_families, 0..) |family, i| {
                const table = &store.maps[familyIndex(family)].map;
                try std.testing.expect(table.slots.ptr == pointers[i]);
                try std.testing.expectEqual(revisions[i], table.revision);
                try std.testing.expectEqual(@as(u32, 8), table.capacity());
                try std.testing.expectEqual(@as(u32, 6), table.count());
                for (copies[i], table.slots) |before, after| try std.testing.expect(KvTable.slotSame(before, after));
                try std.testing.expect(store.get(family, "NEW") == null);
                try std.testing.expectEqualStrings("OLD-value", store.get(family, "OLD-3").?);
            }
            try std.testing.expectEqual(old_offset, store.wal_offset);
            try std.testing.expectEqual(old_seq, store.next_seq);
            try std.testing.expectEqualStrings(old_change.key, store.changeAt(0).?.key);
            try std.testing.expectEqualStrings(old_change.value.?, store.changeAt(0).?.value.?);
            const after_wal = try readWalForTest(tmp, "table-batch-oom.wal");
            defer std.testing.allocator.free(after_wal);
            try std.testing.expectEqualSlices(u8, old_wal, after_wal);
            var retry = try store.prepareBatch(&edits);
            defer retry.abort();
            try retry.commit();
            for (affected_families) |family| try std.testing.expectEqualStrings("candidate", store.get(family, "NEW").?);
        }
    }
    return error.TestUnexpectedResult;
}

test "STORE KvTable private repeated validation consumes original finite allowance including rebuild" {
    for ([_]bool{ false, true }) |grow| {
        var table = KvTable.init(std.testing.allocator);
        defer table.deinit();
        for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
        const edits = [_]KvTable.Edit{.{ .key = if (grow) "g" else "a", .value = @constCast("candidate") }};
        var measured = try table.prepare(&edits, std.math.maxInt(u64));
        const prepared_work = measured.work.total;
        try measured.validate();
        const validate_work = measured.work.total - prepared_work;
        try std.testing.expect(validate_work > 0);
        if (grow) try std.testing.expect(measured.work.rows >= table.capacity());
        measured.abort();
        var bounded = try table.prepare(&edits, prepared_work + validate_work);
        defer bounded.abort();
        try bounded.validate();
        try std.testing.expectEqual(bounded.work.limit, bounded.work.total);
        try std.testing.expectError(StoreError.TableWorkExceeded, bounded.validate());
        try std.testing.expectEqual(@as(u32, 6), table.count());
        try std.testing.expectEqual(@as(u32, 8), table.capacity());
        try std.testing.expectEqualStrings("OLD", table.get("a").?);
    }
}

test "STORE KvTable prepared put and batch forged candidates refuse before WAL and normal retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "forged-table.wal");
    defer store.deinit();
    try store.put(.props, "OLD", "value");
    const before = try readWalForTest(tmp, "forged-table.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var put = try store.preparePut(.props, "NEW", "candidate");
    defer put.abort();
    const original = store.active_prepared.?.value.?;
    store.active_prepared.?.value = original[0 .. original.len - 1];
    try std.testing.expectError(StoreError.InvalidTablePlan, put.commit());
    store.active_prepared.?.value = original;
    const put_plan = &store.active_prepared.?.table_plan.?;
    put_plan.seal[0] ^= 1;
    try std.testing.expectError(StoreError.InvalidTablePlan, put.commit());
    put_plan.seal[0] ^= 1;
    put.abort();
    var batch = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = "candidate" }});
    defer batch.abort();
    const batch_key = store.active_batch.?.entries[0].key.?;
    store.active_batch.?.entries[0].key = batch_key[0 .. batch_key.len - 1];
    try std.testing.expectError(StoreError.InvalidTablePlan, batch.commit());
    store.active_batch.?.entries[0].key = batch_key;
    store.active_batch.?.entries[0].old_value = @constCast("forged-retirement");
    try std.testing.expectError(StoreError.InvalidTablePlan, batch.commit());
    store.active_batch.?.entries[0].old_value = null;
    const after = try readWalForTest(tmp, "forged-table.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expect(!store.preparedWritesPoisoned());
    try std.testing.expect(store.get(.props, "NEW") == null);
    try batch.commit();
    try std.testing.expectEqualStrings("candidate", store.get(.props, "NEW").?);
}

test "STORE KvTable ordinary revision exhaustion refuses mutation before WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "revision-table.wal");
    defer store.deinit();
    try store.put(.props, "OLD", "value");
    const table = &store.maps[familyIndex(.props)].map;
    const revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = revision;
    const before = try readWalForTest(tmp, "revision-table.wal");
    defer std.testing.allocator.free(before);
    try std.testing.expectError(StoreError.SequenceExhausted, store.put(.props, "NEW", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.delete(.props, "OLD"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.props, "NEW", "value"));
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&.{.{ .family = .props, .kind = .delete, .key = "OLD" }}));
    const after = try readWalForTest(tmp, "revision-table.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualStrings("value", store.get(.props, "OLD").?);
    try std.testing.expect(store.get(.props, "NEW") == null);
}

fn tableLocatorCustodyScenario(batch_mode: bool, key_mode: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "locator-custody.wal");
    defer store.deinit();
    for (0..6) |i| {
        var buffer: [16]u8 = undefined;
        try store.put(.props, try std.fmt.bufPrint(&buffer, "old-{d}", .{i}), "OLD");
    }
    const before = try readWalForTest(tmp, "locator-custody.wal");
    defer std.testing.allocator.free(before);
    var put: PreparedPut = undefined;
    var batch: PreparedBatch = undefined;
    if (batch_mode) batch = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = "candidate" }}) else put = try store.preparePut(.props, "NEW", "candidate");
    defer if (batch_mode) batch.abort() else put.abort();
    const plan = if (batch_mode) &store.active_batch.?.table_plans[familyIndex(.props)].? else &store.active_prepared.?.table_plan.?;
    var candidate: *KvTable.Slot = undefined;
    for (plan.replacement.?) |*slot| if (slot.state == .used and std.mem.eql(u8, slot.key, "NEW")) {
        candidate = slot;
        break;
    };
    const original: []const u8 = if (key_mode) candidate.key else candidate.value;
    const twin = try std.testing.allocator.dupe(u8, original);
    var transferred = false;
    defer if (!transferred) std.testing.allocator.free(twin);
    if (key_mode) candidate.key = twin else candidate.value = twin;
    const result = if (batch_mode) batch.commit() else put.commit();
    if (result) |_| {
        // OLD control really adopted the twin. Explicitly release the now-lost
        // original; Store.deinit owns the adopted twin, not the test's defer.
        transferred = true;
        std.testing.allocator.free(original);
        std.debug.print("KvTable locator causal batch={any}: equal-byte foreign pointer adopted across WAL\n", .{batch_mode});
        return error.TestUnexpectedResult;
    } else |err| {
        if (key_mode) candidate.key = original else candidate.value = @constCast(original);
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "locator-custody.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expect(store.get(.props, "NEW") == null);
    if (batch_mode) try batch.commit() else try put.commit();
    try std.testing.expectEqualStrings("candidate", store.get(.props, "NEW").?);
}

test "STORE KvTable review causal put detached equal bytes foreign locator refuses before WAL" {
    try tableLocatorCustodyScenario(false, false);
}
test "STORE KvTable review causal batch detached equal bytes foreign locator refuses before WAL" {
    try tableLocatorCustodyScenario(true, false);
}

test "STORE KvTable review causal finite rebuild budget refuses before backend allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var table = KvTable.init(failing.allocator());
    defer table.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f" }) |key| try tableTestPut(&table, key, "OLD");
    const ptr = table.slots.ptr;
    const allocations = failing.alloc_index;
    try std.testing.expectError(StoreError.TableWorkExceeded, table.prepare(&.{.{ .key = "g", .value = @constCast("candidate") }}, 128));
    try std.testing.expect(table.slots.ptr == ptr);
    try std.testing.expectEqual(@as(u32, 6), table.count());
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
    std.debug.print("KvTable budget causal beforealloc={d} afteralloc={d}\n", .{ allocations, failing.alloc_index });
    try std.testing.expectEqual(allocations, failing.alloc_index);
    var retry = try table.prepare(&.{.{ .key = "g", .value = @constCast("candidate") }}, std.math.maxInt(u64));
    defer retry.abort();
    try retry.validate();
}

fn tablePreparedRevisionBoundary(batch_mode: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "revision-boundary.wal", .{ .max_wal_bytes = 2000, .changefeed_capacity = 0 });
    defer store.deinit();
    const large: [850]u8 = @splat(42);
    const candidate: [200]u8 = @splat(17);
    try store.put(.props, "OLD", &large);
    const table = &store.maps[familyIndex(.props)].map;
    const old_revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = old_revision;
    const before = try readWalForTest(tmp, "revision-boundary.wal");
    defer std.testing.allocator.free(before);
    const epoch = store.wal_epoch;
    const offset = store.wal_offset;
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "revision-boundary.wal.snap", .{}));
    if (batch_mode) try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "NEW", .value = &candidate }})) else try std.testing.expectError(StoreError.SequenceExhausted, store.preparePut(.props, "NEW", &candidate));
    const after = try readWalForTest(tmp, "revision-boundary.wal");
    defer std.testing.allocator.free(after);
    std.debug.print("KvTable revision boundary batch={any}: WAL before={d} after={d}\n", .{ batch_mode, before.len, after.len });
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualDeep(epoch, store.wal_epoch);
    try std.testing.expectEqual(offset, store.wal_offset);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "revision-boundary.wal.snap", .{}));
}
test "STORE KvTable review causal prepared put revision exhaustion refuses before compaction" {
    try tablePreparedRevisionBoundary(false);
}
test "STORE KvTable review causal prepared batch revision exhaustion refuses before compaction" {
    try tablePreparedRevisionBoundary(true);
}

test "STORE KvTable detached put equal bytes foreign KEY locator refuses before WAL" {
    try tableLocatorCustodyScenario(false, true);
}
test "STORE KvTable detached batch equal bytes foreign KEY locator refuses before WAL" {
    try tableLocatorCustodyScenario(true, true);
}

test "STORE KvTable batch later affected family revision refuses before threshold maintenance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "later-revision.wal", .{ .max_wal_bytes = 2000, .changefeed_capacity = 0 });
    defer store.deinit();
    const large: [850]u8 = @splat(42);
    const candidate: [200]u8 = @splat(17);
    try store.put(.props, "OLD", &large);
    try store.put(.accounts, "healthy", "OLD");
    const table = &store.maps[familyIndex(.props)].map;
    const old_revision = table.revision;
    table.revision = std.math.maxInt(u64);
    defer table.revision = old_revision;
    const before = try readWalForTest(tmp, "later-revision.wal");
    defer std.testing.allocator.free(before);
    const epoch = store.wal_epoch;
    const offset = store.wal_offset;
    const seq = store.next_seq;
    const mutations = [_]BatchMutation{
        .{ .family = .accounts, .kind = .put, .key = "NEW", .value = "healthy-candidate" },
        .{ .family = .props, .kind = .put, .key = "NEW", .value = &candidate },
    };
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "later-revision.wal.snap", .{}));
    try std.testing.expectError(StoreError.SequenceExhausted, store.prepareBatch(&mutations));
    const after = try readWalForTest(tmp, "later-revision.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualDeep(epoch, store.wal_epoch);
    try std.testing.expectEqual(offset, store.wal_offset);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expect(store.active_batch == null);
    try std.testing.expect(store.get(.accounts, "NEW") == null);
    try std.testing.expect(store.get(.props, "NEW") == null);
    try std.testing.expectEqualStrings("OLD", store.get(.accounts, "healthy").?);
    try std.testing.expectEqualSlices(u8, &large, store.get(.props, "OLD").?);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "later-revision.wal.snap", .{}));
    table.revision = old_revision;
    var retry = try store.prepareBatch(&mutations);
    defer retry.abort();
    try retry.commit();
    try std.testing.expectEqualStrings("healthy-candidate", store.get(.accounts, "NEW").?);
    try std.testing.expectEqualSlices(u8, &candidate, store.get(.props, "NEW").?);
}

test "STORE KvTable selector causal changed PUT kind refuses before WAL and retirement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selector-kind.wal", .{ .changefeed_capacity = 0 });
    defer store.deinit();
    try store.put(.props, "OLD", "old-value");
    const old_key = store.maps[familyIndex(.props)].map.getEntry("OLD").?.key_ptr.*;
    const before = try readWalForTest(tmp, "selector-kind.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var ticket = try store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "OLD", .value = "new-value" }});
    defer ticket.abort();
    store.active_batch.?.entries[0].kind = .delete;
    if (ticket.commit()) |_| {
        // The OLD control leaves this table-owned key wrongly scheduled for
        // reclamation. Remove only that retirement so the real accepted commit
        // can be observed without turning the fixture into a double-free.
        var removed: usize = 0;
        var i: usize = 0;
        while (i < store.retirement_count) {
            const is_live_key = switch (store.retirements[i].?) {
                .bytes => |bytes| bytes.ptr == old_key.ptr and bytes.len == old_key.len,
                else => false,
            };
            if (is_live_key) {
                removed += 1;
                store.retirement_count -= 1;
                store.retirements[i] = store.retirements[store.retirement_count];
                store.retirements[store.retirement_count] = null;
            } else i += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), removed);
        try std.testing.expectEqualStrings("new-value", store.get(.props, "OLD").?);
        try std.testing.expectEqual(seq + 1, store.next_seq);
        std.debug.print("KvTable selector causal: changed kind committed and scheduled one live OLD key for retirement\n", .{});
        return error.TestUnexpectedResult;
    } else |err| {
        store.active_batch.?.entries[0].kind = .put;
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "selector-kind.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expectEqualStrings("old-value", store.get(.props, "OLD").?);
    try ticket.commit();
    try std.testing.expectEqualStrings("new-value", store.get(.props, "OLD").?);
}

test "STORE KvTable selector causal omitted entries refuses before WAL and feed ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selector-count.wal", .{ .changefeed_capacity = 4 });
    defer store.deinit();
    const before = try readWalForTest(tmp, "selector-count.wal");
    defer std.testing.allocator.free(before);
    const seq = store.next_seq;
    var ticket = try store.prepareBatch(&.{
        .{ .family = .accounts, .kind = .put, .key = "A", .value = "a-value" },
        .{ .family = .props, .kind = .put, .key = "B", .value = "b-value" },
    });
    defer ticket.abort();
    const changes = [_]OwnedMutation{ store.active_batch.?.entries[0].change.?, store.active_batch.?.entries[1].change.? };
    store.active_batch.?.count = 0;
    if (ticket.commit()) |_| {
        // Both map plans consumed key/value ownership. The two independent
        // event allocations were omitted entirely by the shortened selector;
        // free those exact lost allocations, leaving real map ownership intact.
        for (changes) |change| {
            var owned = change;
            owned.deinit(std.testing.allocator);
        }
        try std.testing.expectEqualStrings("a-value", store.get(.accounts, "A").?);
        try std.testing.expectEqualStrings("b-value", store.get(.props, "B").?);
        try std.testing.expectEqual(seq + 2, store.next_seq);
        try std.testing.expectEqual(@as(usize, 0), store.changeCount());
        std.debug.print("KvTable selector causal: count0 committed two rows and omitted two owned events\n", .{});
        return error.TestUnexpectedResult;
    } else |err| {
        store.active_batch.?.count = 2;
        try std.testing.expectEqual(StoreError.InvalidTablePlan, err);
    }
    const after = try readWalForTest(tmp, "selector-count.wal");
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(seq, store.next_seq);
    try std.testing.expectEqual(@as(usize, 0), store.changeCount());
    try std.testing.expect(store.get(.accounts, "A") == null);
    try std.testing.expect(store.get(.props, "B") == null);
    try ticket.commit();
    try std.testing.expectEqual(@as(usize, 2), store.changeCount());
}

test "STORE KvTable batch bounded selectors complete cross family coverage and duplicate omission refusal" {
    for (0..9) |variant| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "selectors.wal", .{ .changefeed_capacity = 4 });
        defer store.deinit();
        try store.put(.history, "D", "OLD");
        const before = try readWalForTest(tmp, "selectors.wal");
        defer std.testing.allocator.free(before);
        const seq = store.next_seq;
        var ticket = try store.prepareBatch(&.{
            .{ .family = .accounts, .kind = .put, .key = "A", .value = "a" },
            .{ .family = .props, .kind = .put, .key = "B", .value = "b" },
            .{ .family = .props, .kind = .put, .key = "C", .value = "c" },
            .{ .family = .history, .kind = .delete, .key = "D" },
        });
        defer ticket.abort();
        const entries = store.active_batch.?.entries; // All four are initialized.
        switch (variant) {
            0 => store.active_batch.?.count = 0,
            1 => store.active_batch.?.count = max_batch_mutations + 1,
            2 => store.active_batch.?.count = std.math.maxInt(usize),
            3 => store.active_batch.?.count = 3,
            4 => store.active_batch.?.entries[2] = entries[1],
            5 => store.active_batch.?.entries[3] = entries[0],
            6 => store.active_batch.?.entries[3].family = .props,
            7 => store.active_batch.?.entries[3].kind = .put,
            8 => store.active_batch.?.entries[2].kind = .delete,
            else => unreachable,
        }
        const result = ticket.commit();
        store.active_batch.?.count = max_batch_mutations;
        store.active_batch.?.entries = entries;
        try std.testing.expectError(StoreError.InvalidTablePlan, result);
        const after = try readWalForTest(tmp, "selectors.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try std.testing.expectEqual(seq, store.next_seq);
        try std.testing.expectEqual(@as(usize, 1), store.changeCount());
        try std.testing.expectEqualStrings("OLD", store.get(.history, "D").?);
        try std.testing.expect(store.get(.accounts, "A") == null);
        try std.testing.expect(store.get(.props, "B") == null);
        try std.testing.expect(store.get(.props, "C") == null);
        try std.testing.expect(!store.preparedWritesPoisoned());
        try ticket.commit();
        try std.testing.expectEqual(seq + 4, store.next_seq);
        try std.testing.expectEqual(@as(usize, 4), store.changeCount());
        try std.testing.expectEqualStrings("a", store.get(.accounts, "A").?);
        try std.testing.expectEqualStrings("b", store.get(.props, "B").?);
        try std.testing.expectEqualStrings("c", store.get(.props, "C").?);
        try std.testing.expect(store.get(.history, "D") == null);
    }
}

const StoreOwnerObserver = struct {
    const Allocation = struct { ptr: usize, len: usize, alignment: usize, seen: bool = false };
    backend: std.mem.Allocator = std.testing.allocator,
    records: [512]?Allocation = @splat(null),
    calls: usize = 0,
    frees: usize = 0,
    fail_at: usize = std.math.maxInt(usize),
    fn allocator(self: *StoreOwnerObserver) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *StoreOwnerObserver = @ptrCast(@alignCast(ctx));
        const call = self.calls;
        self.calls += 1;
        if (call == self.fail_at) return null;
        const ptr = self.backend.rawAlloc(len, alignment, address) orelse return null;
        for (&self.records) |*slot| if (slot.* == null) {
            slot.* = .{ .ptr = @intFromPtr(ptr), .len = len, .alignment = alignment.toByteUnits() };
            return ptr;
        };
        @panic("observer fixture capacity exhausted");
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *StoreOwnerObserver = @ptrCast(@alignCast(ctx));
        for (&self.records) |*slot| if (slot.*) |record| if (record.ptr == @intFromPtr(bytes.ptr)) {
            std.debug.assert(record.len == bytes.len and record.alignment == alignment.toByteUnits());
            self.backend.rawFree(bytes, alignment, address);
            slot.* = null;
            self.frees += 1;
            return;
        };
        @panic("wrong original allocator received free");
    }
    fn mark(self: *StoreOwnerObserver, d: OwnedCapacityDescriptor) !void {
        try std.testing.expectEqualDeep(AllocatorObservation.from(self.allocator()), d.original_allocator);
        for (&self.records) |*slot| if (slot.*) |*record| if (record.ptr == d.locator) {
            try std.testing.expect(!record.seen);
            try std.testing.expectEqual(record.len, d.requested_bytes);
            try std.testing.expectEqual(record.alignment, d.alignment);
            record.seen = true;
            return;
        };
        return error.MissingOriginalAllocation;
    }
    fn checkAll(self: *const StoreOwnerObserver, seen: bool) !void {
        for (self.records) |slot| if (slot) |record| {
            if (!seen) return error.LeakedOriginalAllocation;
            try std.testing.expect(record.seen);
        };
    }
};

fn seedOwnerForCensus(owner: *StoreResourceOwner) !void {
    // Source-private seed precedes every external lease. No mutation wrapper is
    // exported; S2/S3 must reserve real revisions for future source mutations.
    const s = &ownerBacking(owner).store;
    for (0..6) |i| {
        var key: [8]u8 = undefined;
        try s.put(.props, try std.fmt.bufPrint(&key, "p{d}", .{i}), "value");
    }
    try s.put(.accounts, "account", "old");
    try s.put(.history, "gone", "history");
    try s.put(.nicks, "temporary", "");
    try s.delete(.nicks, "temporary");
    var batch = try s.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = "growth", .value = "new" },
        .{ .family = .accounts, .kind = .put, .key = "account", .value = "replacement" },
        .{ .family = .history, .kind = .delete, .key = "gone" },
        .{ .family = .bans, .kind = .delete, .key = "absent" },
    });
    defer batch.abort();
    try batch.commit();
}

test "STORE source owner complete census heterogeneous original contexts and disk inert" {
    for ([_]usize{ 2, 64 }) |feed_capacity| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var meta: StoreOwnerObserver = .{};
        var payload: StoreOwnerObserver = .{};
        const owner = try createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "owner.wal", .{ .changefeed_capacity = feed_capacity }, false);
        var destroyed = false;
        defer if (!destroyed) destroyStoreResourceOwner(owner) catch unreachable;
        try seedOwnerForCensus(owner);
        const s = &ownerBacking(owner).store;
        try std.testing.expect(s.maps[familyIndex(.nicks)].map.slots.len != 0);
        try std.testing.expectEqual(@as(u32, 0), s.maps[familyIndex(.nicks)].map.count());
        try std.testing.expect(s.maps[familyIndex(.nicks)].map.tombstones != 0);
        try std.testing.expect(s.retirement_count != 0);
        if (feed_capacity == 64) try std.testing.expect(s.changefeed.count < s.changefeed.entries.len);
        const before = try readWalForTest(tmp, "owner.wal");
        defer std.testing.allocator.free(before);
        const meta_calls = meta.calls;
        const payload_calls = payload.calls;
        const meta_frees = meta.frees;
        const payload_frees = payload.frees;
        meta.fail_at = meta.calls;
        payload.fail_at = payload.calls;
        const exclusive = try owner.tryAcquireExclusive();
        const state = try exclusive.sourceState();
        try std.testing.expect(state.owned_wal_descriptor and !state.owned_staged_descriptor);
        try std.testing.expectEqual(@as(u64, 1), state.source.owner_revision);
        const cursor = try exclusive.catalog();
        try std.testing.expectError(error.LeaseChildren, exclusive.finish());
        var kinds: [@typeInfo(@FieldType(OwnedCapacityDescriptor, "kind")).@"enum".field_names.len]usize = @splat(0);
        while (try cursor.next()) |d| {
            try std.testing.expectEqualDeep(state.source, d.source);
            try std.testing.expect(d.requested_bytes > 0);
            kinds[@intFromEnum(d.kind)] += 1;
            if (std.meta.eql(d.original_allocator, AllocatorObservation.from(meta.allocator()))) try meta.mark(d) else try payload.mark(d);
        }
        try meta.checkAll(true);
        try payload.checkAll(true);
        for ([_]@FieldType(OwnedCapacityDescriptor, "kind"){ .owner_box, .wal_path, .snapshot_path, .table_backing, .live_key, .live_value, .feed_ring, .feed_key, .retired_bytes, .retired_table }) |kind| try std.testing.expect(kinds[@intFromEnum(kind)] != 0);
        if (feed_capacity == 2) {
            try std.testing.expect(kinds[@intFromEnum(@as(@FieldType(OwnedCapacityDescriptor, "kind"), .retired_key))] != 0);
            try std.testing.expect(kinds[@intFromEnum(@as(@FieldType(OwnedCapacityDescriptor, "kind"), .retired_value))] != 0);
        }
        try cursor.finish();
        try std.testing.expectError(error.InvalidLease, cursor.next());
        try exclusive.finish();
        try std.testing.expectEqual(meta_calls, meta.calls);
        try std.testing.expectEqual(payload_calls, payload.calls);
        try std.testing.expectEqual(meta_frees, meta.frees);
        try std.testing.expectEqual(payload_frees, payload.frees);
        const after = try readWalForTest(tmp, "owner.wal");
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try destroyStoreResourceOwner(owner);
        destroyed = true;
        try meta.checkAll(false);
        try payload.checkAll(false);
        // Borrowed directory/Io/backend remain independently live after teardown.
        const file = try tmp.dir.createFile(std.testing.io, "still-borrowed", .{});
        file.close(std.testing.io);
    }
}

test "STORE source owner read iterator feed real pins copied finish slot reuse and exhaustion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "pins.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    try ownerBacking(owner).store.put(.props, "key", "value");
    const a = try owner.borrowRead();
    const copied = a;
    try std.testing.expectEqualStrings("value", (try a.get(.props, "key")).?);
    try std.testing.expectEqualStrings("key", (try a.changeAt(0)).?.key);
    const iter = try a.iterate(.props);
    try std.testing.expectEqualStrings("value", (try iter.next()).?.value);
    try std.testing.expectError(error.LeaseChildren, copied.finish());
    try std.testing.expectError(error.Busy, owner.tryAcquireExclusive());
    try std.testing.expectError(error.Busy, destroyStoreResourceOwner(owner));
    try iter.finish();
    try a.finish();
    const b = try owner.borrowRead();
    try std.testing.expectEqual(a.slot, b.slot);
    try std.testing.expectError(error.InvalidLease, copied.finish());
    try std.testing.expectError(error.InvalidLease, iter.next());
    try std.testing.expectEqualStrings("value", (try b.get(.props, "key")).?);
    try b.finish();
    const x = try owner.tryAcquireExclusive();
    const xc = x;
    const c = try x.catalog();
    const cc = c;
    try std.testing.expectError(error.LeaseChildren, xc.finish());
    try std.testing.expectError(error.Busy, owner.borrowRead());
    try c.finish();
    const c2 = try x.catalog();
    try std.testing.expectEqual(c.slot, c2.slot);
    try std.testing.expectError(error.InvalidLease, cc.finish());
    try c2.finish();
    try x.finish();
    const x2 = try owner.tryAcquireExclusive();
    try std.testing.expectError(error.InvalidLease, xc.finish());
    try x2.finish();
    ownerBacking(owner).next_serial = std.math.maxInt(u64) - 1;
    const last = try owner.borrowRead();
    try std.testing.expectError(error.IdentityExhausted, last.iterate(.props));
    try std.testing.expectEqualStrings("value", (try last.get(.props, "key")).?);
    try last.finish();
    try std.testing.expectError(error.IdentityExhausted, owner.borrowRead());
    try std.testing.expectError(error.IdentityExhausted, owner.tryAcquireExclusive());
}

test "STORE source owner actual ordinary candidates and staged promotion custody preserved" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const s = &ownerBacking(owner).store;
    var put = try s.preparePut(.props, "key", "one");
    try std.testing.expectError(error.SourceCustodyActive, owner.tryAcquireExclusive());
    try std.testing.expect(s.active_prepared != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(owner));
    put.abort();
    const x = try owner.tryAcquireExclusive();
    try x.finish();
    var batch = try s.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "key", .value = "two" }});
    try std.testing.expectError(error.SourceCustodyActive, owner.tryAcquireExclusive());
    try std.testing.expect(s.active_batch != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(owner));
    try batch.commit();
    const y = try owner.tryAcquireExclusive();
    try y.finish();
    const readonly = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "custody.wal", .{}, true);
    defer destroyStoreResourceOwner(readonly) catch unreachable;
    try std.testing.expectError(error.SourceCustodyActive, readonly.tryAcquireExclusive());
    try ownerBacking(readonly).store.preparePromotion();
    try std.testing.expectError(error.SourceCustodyActive, readonly.tryAcquireExclusive());
    try std.testing.expect(ownerBacking(readonly).store.staged_write_file != null);
    try std.testing.expectError(error.SourceCustodyActive, destroyStoreResourceOwner(readonly));
    try ownerBacking(readonly).store.releaseReadHandleForPreparedPromotion();
    ownerBacking(readonly).store.promotePrepared();
    const z = try readonly.tryAcquireExclusive();
    try z.finish();
}

test "STORE source owner fresh lifetime same backing address rejects stale and cross source tokens" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [@sizeOf(StoreOwnerBacking) + @alignOf(StoreOwnerBacking)]u8 align(@alignOf(StoreOwnerBacking)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    const first = try createStoreResourceOwner(fixed.allocator(), std.testing.allocator, std.testing.io, tmp.dir, "reuse.wal", .{}, false);
    const old = try first.borrowRead();
    try old.finish();
    const ptr = @intFromPtr(first);
    try destroyStoreResourceOwner(first);
    fixed.reset();
    const next = try createStoreResourceOwner(fixed.allocator(), std.testing.allocator, std.testing.io, tmp.dir, "reuse.wal", .{}, false);
    defer destroyStoreResourceOwner(next) catch unreachable;
    try std.testing.expectEqual(ptr, @intFromPtr(next));
    const current = try next.borrowRead();
    try std.testing.expect(current.lifetime != old.lifetime);
    try std.testing.expectError(error.InvalidLease, old.finish());
    const foreign = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "foreign.wal", .{}, false);
    defer destroyStoreResourceOwner(foreign) catch unreachable;
    var wrong = current;
    wrong.owner = foreign;
    try std.testing.expectError(error.InvalidLease, wrong.finish());
    try current.finish();
    var counter: std.atomic.Value(u64) = .init(std.math.maxInt(u64) - 1);
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, try reserveStoreLifetime(&counter));
    try std.testing.expectError(error.IdentityExhausted, reserveStoreLifetime(&counter));
}

fn storeOwnerAllocationScenario(a: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Factory effects scoped separately; this existing readonly cut does no disk
    // maintenance on allocation failure, and preserves all actual original rows.
    {
        var store = try openTestStore(tmp, "owner-oom.wal");
        defer store.deinit();
        try store.put(.props, "old", "intact");
    }
    const before = try readWalForTest(tmp, "owner-oom.wal");
    defer std.testing.allocator.free(before);
    defer {
        const after = readWalForTest(tmp, "owner-oom.wal") catch unreachable;
        defer std.testing.allocator.free(after);
        std.testing.expectEqualSlices(u8, before, after) catch unreachable;
    }
    const owner = try createStoreResourceOwner(a, a, std.testing.io, tmp.dir, "owner-oom.wal", .{}, true);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const r = try owner.borrowRead();
    try std.testing.expectEqualStrings("intact", (try r.get(.props, "old")).?);
    try r.finish();
}

test "STORE source owner exhaustive constructor OOM original ownership and retry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, storeOwnerAllocationScenario, .{});
}

const StoreOwnerThreadRace = struct {
    owner: *StoreResourceOwner,
    phase: std.atomic.Value(u32) = .init(0),
    cancel: std.atomic.Value(bool) = .init(false),
    failures: std.atomic.Value(u32) = .init(0),
    fn wait(self: *StoreOwnerThreadRace, expected: u32) !void {
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (self.phase.load(.acquire) != expected) {
            if (self.cancel.load(.acquire)) return error.ThreadCancelled;
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) return error.ThreadDeadline;
            std.atomic.spinLoopHint();
        }
    }
    fn reader(self: *StoreOwnerThreadRace) void {
        var held: ?ReadLease = self.owner.borrowRead() catch blk: {
            _ = self.failures.fetchAdd(1, .monotonic);
            break :blk null;
        };
        defer if (held) |r| r.finish() catch {
            _ = self.failures.fetchAdd(1, .monotonic);
        };
        self.phase.store(1, .release);
        self.wait(2) catch return;
        if (held) |r| {
            r.finish() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
            };
            held = null;
        }
        self.phase.store(3, .release);
        self.wait(4) catch return;
        if (self.owner.borrowRead()) |unexpected| {
            _ = self.failures.fetchAdd(1, .monotonic);
            unexpected.finish() catch {
                _ = self.failures.fetchAdd(1, .monotonic);
            };
        } else |err| {
            if (err != error.Busy) _ = self.failures.fetchAdd(1, .monotonic);
        }
        self.phase.store(5, .release);
    }
};

fn storeOwnerThreadScenario(initial_refusal: bool, exclusive_refusal: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "threads.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const initial = if (initial_refusal) try owner.tryAcquireExclusive() else null;
    defer if (initial) |x| x.finish() catch unreachable;
    var race: StoreOwnerThreadRace = .{ .owner = owner };
    const thread = try std.Thread.spawn(.{}, StoreOwnerThreadRace.reader, .{&race});
    // Every test exit releases the worker from any handshake and joins BEFORE
    // source destruction. Monotonic deadline reports fixture failure only.
    defer {
        race.cancel.store(true, .release);
        thread.join();
    }
    try race.wait(1);
    const rejected = owner.tryAcquireExclusive();
    race.phase.store(2, .release);
    try race.wait(3);
    const obstructing_read = if (exclusive_refusal) try owner.borrowRead() else null;
    defer if (obstructing_read) |r| r.finish() catch unreachable;
    const accepted = owner.tryAcquireExclusive();
    defer if (accepted) |x| x.finish() catch unreachable else |_| {};
    race.phase.store(4, .release);
    try race.wait(5);
    if (race.failures.load(.acquire) != 0) return error.ThreadScenarioFailure;
    if (accepted) |_| {} else |_| return error.ThreadScenarioFailure;
    try std.testing.expectError(error.Busy, rejected);
}

test "STORE source owner synchronized real read exclusion admission across two threads" {
    try storeOwnerThreadScenario(false, false);
    try std.testing.expectError(error.ThreadScenarioFailure, storeOwnerThreadScenario(true, false));
    try std.testing.expectError(error.ThreadScenarioFailure, storeOwnerThreadScenario(false, true));
}

test "STORE source owner bounded read child slots and last exclusive cleanup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "slots.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    var reads: [16]ReadLease = undefined;
    for (&reads) |*r| r.* = try owner.borrowRead();
    try std.testing.expectError(error.Capacity, owner.borrowRead());
    var iters: [16]ReadIterator = undefined;
    for (&iters) |*it| it.* = try reads[0].iterate(.accounts);
    try std.testing.expectError(error.Capacity, reads[0].iterate(.props));
    try std.testing.expectError(error.LeaseChildren, reads[0].finish());
    for (iters) |it| try it.finish();
    for (reads) |r| try r.finish();
    ownerBacking(owner).next_serial = std.math.maxInt(u64) - 2;
    const x = try owner.tryAcquireExclusive();
    const c = try x.catalog();
    try std.testing.expectError(error.IdentityExhausted, x.catalog());
    try std.testing.expectError(error.LeaseChildren, x.finish());
    try std.testing.expect((try c.next()) != null);
    try c.finish();
    try x.finish();
}

test "STORE source owner exhausted factory refuses backend IO and observes actual cwd sentinel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var observer: StoreOwnerObserver = .{};
    var counter: std.atomic.Value(u64) = .init(std.math.maxInt(u64));
    try std.testing.expectError(error.IdentityExhausted, createStoreResourceOwnerWithCounter(observer.allocator(), observer.allocator(), std.testing.io, tmp.dir, "not-created.wal", .{}, false, &counter));
    try std.testing.expectEqual(@as(usize, 0), observer.calls);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "not-created.wal", .{}));
    const absolute = try coldFixtureAbsoluteDirectory(&tmp, ".");
    defer std.testing.allocator.free(absolute);
    const path = try std.fs.path.join(std.testing.allocator, &.{ absolute, "cwd-owner.wal" });
    defer std.testing.allocator.free(path);
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, .cwd(), path, .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    const x = try owner.tryAcquireExclusive();
    try std.testing.expectEqual(std.Io.Dir.cwd().handle, (try x.sourceState()).borrowed_directory);
    try x.finish();
}

const StoreOwnerFinishRace = struct {
    token: union(enum) { read: ReadLease, exclusive: StoreExclusive },
    ready: std.atomic.Value(u32) = .init(0),
    start: std.atomic.Value(bool) = .init(false),
    cancel: std.atomic.Value(bool) = .init(false),
    success: std.atomic.Value(u32) = .init(0),
    refused: std.atomic.Value(u32) = .init(0),
    other: std.atomic.Value(u32) = .init(0),
    fn worker(self: *StoreOwnerFinishRace) void {
        _ = self.ready.fetchAdd(1, .release);
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (!self.start.load(.acquire)) {
            if (self.cancel.load(.acquire)) return;
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) {
                _ = self.other.fetchAdd(1, .monotonic);
                return;
            }
            std.atomic.spinLoopHint();
        }
        const result = switch (self.token) {
            .read => |r| r.finish(),
            .exclusive => |x| x.finish(),
        };
        if (result) |_| {
            _ = self.success.fetchAdd(1, .monotonic);
        } else |err| {
            if (err == error.InvalidLease) _ = self.refused.fetchAdd(1, .monotonic) else _ = self.other.fetchAdd(1, .monotonic);
        }
    }
};

test "STORE source owner concurrent double finish one winner then fresh slot cannot be cleared" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try createStoreResourceOwner(std.testing.allocator, std.testing.allocator, std.testing.io, tmp.dir, "double.wal", .{}, false);
    defer destroyStoreResourceOwner(owner) catch unreachable;
    for ([_]bool{ false, true }) |exclusive| {
        var race: StoreOwnerFinishRace = .{ .token = if (exclusive) .{ .exclusive = try owner.tryAcquireExclusive() } else .{ .read = try owner.borrowRead() } };
        var threads: [2]std.Thread = undefined;
        var spawned: usize = 0;
        defer {
            race.cancel.store(true, .release);
            for (threads[0..spawned]) |t| t.join();
            // If a fixture deadline/creation failure occurred, end the original
            // source ticket explicitly; stale finish is harmless after a winner.
            switch (race.token) {
                .read => |r| r.finish() catch {},
                .exclusive => |x| x.finish() catch {},
            }
        }
        for (&threads) |*t| {
            t.* = try std.Thread.spawn(.{}, StoreOwnerFinishRace.worker, .{&race});
            spawned += 1;
        }
        const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 10 * std.time.ns_per_s;
        while (race.ready.load(.acquire) != 2) {
            if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) return error.ThreadDeadline;
            std.atomic.spinLoopHint();
        }
        race.start.store(true, .release);
        for (threads) |t| t.join();
        spawned = 0;
        try std.testing.expectEqual(@as(u32, 1), race.success.load(.acquire));
        try std.testing.expectEqual(@as(u32, 1), race.refused.load(.acquire));
        try std.testing.expectEqual(@as(u32, 0), race.other.load(.acquire));
        if (exclusive) {
            const fresh = try owner.tryAcquireExclusive();
            try std.testing.expectError(error.InvalidLease, race.token.exclusive.finish());
            try std.testing.expectError(error.Busy, owner.borrowRead());
            try fresh.finish();
        } else {
            const fresh = try owner.borrowRead();
            try std.testing.expectError(error.InvalidLease, race.token.read.finish());
            try std.testing.expectError(error.Busy, owner.tryAcquireExclusive());
            try fresh.finish();
        }
    }
}

test "STORE source owner independent metadata payload OOM observers retry with unchanged WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var seed = try openTestStore(tmp, "domains.wal");
        defer seed.deinit();
        try seed.put(.props, "old", "complete");
    }
    const before = try readWalForTest(tmp, "domains.wal");
    defer std.testing.allocator.free(before);
    for ([_]bool{ false, true }) |metadata_fail| {
        var indices: usize = 0;
        while (true) : (indices += 1) {
            var meta: StoreOwnerObserver = .{};
            var payload: StoreOwnerObserver = .{};
            if (metadata_fail) meta.fail_at = indices else payload.fail_at = indices;
            const result = createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "domains.wal", .{}, true);
            if (result) |owner| {
                try destroyStoreResourceOwner(owner);
                try meta.checkAll(false);
                try payload.checkAll(false);
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try meta.checkAll(false);
                try payload.checkAll(false);
                meta.fail_at = std.math.maxInt(usize);
                payload.fail_at = std.math.maxInt(usize);
                const retry = try createStoreResourceOwner(meta.allocator(), payload.allocator(), std.testing.io, tmp.dir, "domains.wal", .{}, true);
                const r = try retry.borrowRead();
                try std.testing.expectEqualStrings("complete", (try r.get(.props, "old")).?);
                try r.finish();
                try destroyStoreResourceOwner(retry);
                try meta.checkAll(false);
                try payload.checkAll(false);
            }
            const after = try readWalForTest(tmp, "domains.wal");
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
        }
        std.debug.print("StoreOwner constructor metadata_domain={any} exhaustive_allocation_indices={d}\n", .{ metadata_fail, indices });
        try std.testing.expect(indices != 0);
    }
}

test "STORE managed core distinct NEW origin preserves OLD growth and shared Work" {
    var old: StoreOwnerObserver = .{};
    var candidate: StoreOwnerObserver = .{};
    var table = KvTable.init(old.allocator());
    defer table.deinit();
    try table.ensureUnusedCapacity(6);
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f" };
    for (keys) |key| {
        const entry = try table.getOrPut(key);
        entry.value_ptr.* = @constCast("OLD");
    }
    const before_ptr = table.slots.ptr;
    const before_len = table.slots.len;
    const before_revision = table.revision;
    const old_calls = old.calls;
    old.fail_at = old.calls;
    var work: KvTable.Work = .{ .limit = 100_000 };
    var first = try table.prepareWithStorage(&.{.{ .key = "g", .value = @constCast("NEW") }}, candidate.allocator(), &work);
    try std.testing.expect(first.replacement != null);
    try std.testing.expectEqual(old_calls, old.calls);
    try std.testing.expectEqual(@intFromPtr(before_ptr), @intFromPtr(table.slots.ptr));
    try std.testing.expectEqual(before_len, table.slots.len);
    try std.testing.expectEqual(before_revision, table.revision);
    try std.testing.expectEqualStrings("OLD", table.get("a").?);
    const used = work.total;
    try first.validate();
    try std.testing.expect(work.total > used);
    first.abort();
    try candidate.checkAll(false);
    var second = try table.prepareWithStorage(&.{.{ .key = "h", .value = @constCast("NEXT") }}, candidate.allocator(), &work);
    try std.testing.expect(work.total > used);
    second.abort();
    try candidate.checkAll(false);
    try std.testing.expect(table.get("g") == null and table.get("h") == null);
    // Ordinary inline plans remain movable without a pointer to a dead stack.
    var ordinary = try table.prepare(&.{.{ .key = "a", .value = @constCast("UPDATE") }}, 100_000);
    try std.testing.expect(ordinary.shared_work == null);
    try ordinary.validate();
    ordinary.abort();
}

test "STORE managed core shared work cannot reset across families and OOM retry" {
    for (0..3) |fail_at| {
        var a = KvTable.init(std.testing.allocator);
        defer a.deinit();
        var b = KvTable.init(std.testing.allocator);
        defer b.deinit();
        var candidate: StoreOwnerObserver = .{ .fail_at = fail_at };
        var work: KvTable.Work = .{ .limit = 100_000 };
        var p = a.prepareWithStorage(&.{.{ .key = "a", .value = @constCast("A") }}, candidate.allocator(), &work) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try candidate.checkAll(false);
            try std.testing.expectEqual(@as(usize, 0), a.slots.len);
            candidate.fail_at = std.math.maxInt(usize);
            var retry = try a.prepareWithStorage(&.{.{ .key = "a", .value = @constCast("A") }}, candidate.allocator(), &work);
            retry.abort();
            try candidate.checkAll(false);
            continue;
        };
        var q = b.prepareWithStorage(&.{.{ .key = "b", .value = @constCast("B") }}, candidate.allocator(), &work) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            p.abort();
            try candidate.checkAll(false);
            try std.testing.expectEqual(@as(usize, 0), b.slots.len);
            candidate.fail_at = std.math.maxInt(usize);
            var retry = try b.prepareWithStorage(&.{.{ .key = "b", .value = @constCast("B") }}, candidate.allocator(), &work);
            retry.abort();
            try candidate.checkAll(false);
            continue;
        };
        const spent = work.total;
        work.limit = spent;
        try std.testing.expectError(error.TableWorkExceeded, q.validate());
        p.abort();
        q.abort();
        try candidate.checkAll(false);
        try std.testing.expectEqual(@as(usize, 0), a.slots.len);
        try std.testing.expectEqual(@as(usize, 0), b.slots.len);
    }
}

fn seedCompleteEpoch(dir: std.Io.Dir) !void {
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
    defer store.deinit();
    try store.put(.props, "old", "original durable job");
}

const complete_epoch_mutations = [_]BatchMutation{
    .{ .family = .props, .kind = .put, .key = "outcome", .value = "original failure" },
    .{ .family = .props, .kind = .put, .key = "disposition", .value = "terminal" },
};

test "cold complete epoch prepares synced full successor before publication and never rewrites after replacement" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var stage = try ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
    defer stage.deinit();
    const old_next = stage.view().next_seq;
    var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
    defer ticket.abort();
    const owned = stage.backing.?;
    const plan = owned.plan.?;
    try std.testing.expect(plan.complete_epoch and plan.rotate);
    try std.testing.expect(plan.coverage != null);
    try std.testing.expectEqual(@as(u64, cold_epoch_record_len), plan.coverage.?.slots[1].covered_len);
    try validateColdPreparedWal(owned);
    try std.testing.expectEqual(@as(u64, cold_epoch_record_len + owned.store.active_batch.?.record.?.len), (try plan.writer.stat(std.testing.io)).size);
    const before = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectEqualSlices(u8, original, before);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    // Arm the ordinary append fault AND allocator after all preparation. Any
    // post-publication append or allocation makes this actual commit fail.
    stage.setPreparedIoFault(.{ .write = .failed, .sync = true });
    failing.fail_index = failing.alloc_index;
    try ticket.commit();
    try std.testing.expect(!failing.has_induced_failure);
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqual(old_next + 2, published.next_seq);
    try std.testing.expectEqualStrings("original durable job", published.get(.props, "old").?);
    try std.testing.expectEqualStrings("original failure", published.get(.props, "outcome").?);
    try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
    var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer restart.deinit();
    try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
    try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
    try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
}

test "cold complete epoch publication errors cold-select whole OLD or whole NEW batch" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]ColdPublicationFault{ .snapshot_replace, .snapshot_dir_sync, .wal_replace, .wal_dir_sync }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var old_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer stage.deinit();
            old_next = stage.view().next_seq;
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            try validateColdPreparedWal(stage.backing.?);
            stage.setPublicationFault(fault);
            try std.testing.expectError(error.IoAmbiguous, ticket.commit());
            try std.testing.expect(stage.backing.?.consumed);
            try std.testing.expect(stage.view().preparedWritesPoisoned());
            try std.testing.expect(stage.backing.?.store.active_batch == null);
            try std.testing.expect(stage.backing.?.plan.?.complete_record != null);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
        if (fault == .wal_dir_sync) {
            try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
            try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
        } else {
            try std.testing.expect(restart.view().get(.props, "outcome") == null);
            try std.testing.expect(restart.view().get(.props, "disposition") == null);
            try std.testing.expectEqual(old_next, restart.view().next_seq);
        }
        try std.testing.expectEqual(restart.backing.?.wal.bytes.len, restart.backing.?.valid_end);
    }
}

test "cold complete epoch rejects every truncated prepared successor before namespace publication and permits exact retry" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var prefix: usize = 0;
    while (true) : (prefix += 1) {
        var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer stage.deinit();
        var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
        defer ticket.abort();
        const owned = stage.backing.?;
        const plan = &owned.plan.?;
        const packet = owned.store.active_batch.?.record.?;
        const length = cold_epoch_record_len + packet.len;
        try std.testing.expect(prefix < length);
        try plan.writer.setLength(std.testing.io, prefix);
        try plan.writer.sync(std.testing.io);
        try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
        try std.testing.expect(!owned.consumed);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, original, after);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
        if (prefix + 1 == length) {
            try plan.writer.writePositionalAll(std.testing.io, &plan.epoch, 0);
            try plan.writer.writePositionalAll(std.testing.io, packet, cold_epoch_record_len);
            try plan.writer.sync(std.testing.io);
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
            break;
        }
    }
}

test "cold complete epoch refuses unknown torn transcript without repair or temporary publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const file = try tmp.dir.openFile(std.testing.io, "complete.wal", .{ .mode = .read_write });
    defer file.close(std.testing.io);
    const size = (try file.stat(std.testing.io)).size;
    try file.writePositionalAll(std.testing.io, &.{ 0xAB, 0xCD, 0xEF }, size);
    try file.sync(std.testing.io);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer stage.deinit();
    try std.testing.expect(stage.backing.?.valid_end < stage.backing.?.wal.bytes.len);
    try std.testing.expectError(error.SnapshotCoverageMismatch, stage.prepareCompleteBatch(&complete_epoch_mutations));
    try std.testing.expect(stage.backing.?.plan == null and stage.backing.?.store.active_batch == null);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
}

test "cold complete epoch every allocation failure preserves original files and successful retry commits without allocation" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var candidate = ColdRecoveryStage.open(failing.allocator(), std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
        if (candidate) |*stage| {
            defer stage.deinit();
            if (stage.prepareCompleteBatch(&complete_epoch_mutations)) |prepared| {
                var ticket = prepared;
                defer ticket.abort();
                try std.testing.expect(!failing.has_induced_failure);
                failing.fail_index = failing.alloc_index;
                stage.setPreparedIoFault(.{ .write = .failed, .sync = true });
                try ticket.commit();
                try std.testing.expect(!failing.has_induced_failure);
                var published = stage.takeCommittedStore();
                defer published.deinit();
                try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(stage.backing.?.plan == null and stage.backing.?.store.active_batch == null);
                try std.testing.expectEqualStrings("original durable job", stage.view().get(.props, "old").?);
            }
        } else |err| try std.testing.expectEqual(error.OutOfMemory, err);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, original, after);
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    }
}

test "cold complete epoch selected empty WAL and repeated successors preserve prior rows and sequence" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        if (empty) {
            var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer store.deinit();
            try store.snapshotAndTruncate();
            try store.snapshotAndTruncate();
            try store.wal_file.?.setLength(std.testing.io, 0);
            try store.wal_file.?.sync(std.testing.io);
        }
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var original_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer stage.deinit();
            original_next = stage.view().next_seq;
            try std.testing.expectEqual(empty, stage.backing.?.selected_epoch != null);
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqual(original_next + 2, published.next_seq);
            try std.testing.expectEqualStrings("original durable job", published.get(.props, "old").?);
        }
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer stage.deinit();
            try std.testing.expectEqual(original_next + 2, stage.view().next_seq);
            try std.testing.expectEqualStrings("terminal", stage.view().get(.props, "disposition").?);
            var ticket = try stage.prepareCompleteBatch(&.{.{ .family = .props, .kind = .put, .key = "later", .value = "another actual transition" }});
            defer ticket.abort();
            try ticket.commit();
            var published = stage.takeCommittedStore();
            defer published.deinit();
            try std.testing.expectEqual(original_next + 3, published.next_seq);
            try std.testing.expectEqualStrings("later", published.changeAt(0).?.key);
        }
        var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
        defer restart.deinit();
        try std.testing.expectEqual(original_next + 3, restart.view().next_seq);
        try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
        try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
        try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
        try std.testing.expectEqualStrings("another actual transition", restart.view().get(.props, "later").?);
    }
}

test "cold complete epoch same-length private file and independent packet witness tamper refuse before publication" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try seedCompleteEpoch(tmp.dir);
    const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(original);
    const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
    defer lease.close(std.testing.io);
    try cold_identity.reaffirmExclusive(lease.handle);
    var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
    defer stage.deinit();
    var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
    defer ticket.abort();
    const owned = stage.backing.?;
    const plan = &owned.plan.?;
    const position = (try plan.writer.stat(std.testing.io)).size - 1;
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try plan.writer.readPositionalAll(std.testing.io, &byte, position));
    const saved = byte[0];
    byte[0] ^= 1;
    try plan.writer.writePositionalAll(std.testing.io, &byte, position);
    try plan.writer.sync(std.testing.io);
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!owned.consumed);
    byte[0] = saved;
    try plan.writer.writePositionalAll(std.testing.io, &byte, position);
    try plan.writer.sync(std.testing.io);
    plan.complete_record.?[0] ^= 1;
    try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
    try std.testing.expect(!owned.consumed);
    plan.complete_record.?[0] ^= 1;
    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
    try ticket.commit();
    var published = stage.takeCommittedStore();
    defer published.deinit();
    try std.testing.expectEqualStrings("terminal", published.get(.props, "disposition").?);
}

test "cold complete epoch byte identical foreign prepared names refuse before publication and preserve foreign custody" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |replace_snapshot| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        const original = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(original);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        var old_next: u64 = undefined;
        {
            var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer stage.deinit();
            old_next = stage.view().next_seq;
            var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
            defer ticket.abort();
            const atomic = if (replace_snapshot) stage.backing.?.plan.?.snapshot_atomic.? else stage.backing.?.plan.?.wal_atomic.?;
            const name = std.fmt.hex(atomic.file_basename_hex);
            const expected = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(expected);
            const original_identity = try cold_identity.statRegular(atomic.file.handle);
            const foreign = try atomic.dir.createFile(std.testing.io, "complete-foreign", .{ .read = true });
            defer foreign.close(std.testing.io);
            try foreign.writePositionalAll(std.testing.io, expected, 0);
            try foreign.sync(std.testing.io);
            const foreign_identity = try cold_identity.statRegular(foreign.handle);
            try std.testing.expect(!std.meta.eql(original_identity, foreign_identity));
            try atomic.dir.rename("complete-foreign", atomic.dir, &name, std.testing.io);
            try std.testing.expectError(error.SnapshotCoverageMismatch, ticket.commit());
            try std.testing.expect(!stage.backing.?.consumed);
            try std.testing.expect(!stage.view().preparedWritesPoisoned());
            try std.testing.expectEqual(old_next, stage.view().next_seq);
            try std.testing.expectEqual(@as(usize, 0), stage.view().changeCount());
            const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, original, after);
            try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "complete.wal.snap", .{}));
            ticket.abort();
            const survivor = try atomic.dir.openFile(std.testing.io, &name, .{});
            defer survivor.close(std.testing.io);
            try std.testing.expectEqualDeep(foreign_identity, try cold_identity.statRegular(survivor.handle));
            const actual = try atomic.dir.readFileAlloc(std.testing.io, &name, std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(actual);
            try std.testing.expectEqualSlices(u8, expected, actual);
        }
        var retry = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
        defer retry.deinit();
        var ticket = try retry.prepareCompleteBatch(&complete_epoch_mutations);
        defer ticket.abort();
        try ticket.commit();
        var result = retry.takeCommittedStore();
        defer result.deinit();
        try std.testing.expectEqual(old_next + 2, result.next_seq);
        try std.testing.expectEqual(@as(usize, 2), result.changeCount());
        try std.testing.expectEqualStrings("outcome", result.changeAt(0).?.key);
        try std.testing.expectEqualStrings("disposition", result.changeAt(1).?.key);
    }
}

test "cold complete epoch fault recovery retries OLD once and clean NEW promotion pieces never duplicate sequence or feed" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |empty| {
        for ([_]ColdPublicationFault{ .snapshot_replace, .snapshot_dir_sync, .wal_replace, .wal_dir_sync }) |fault| {
            // An empty selected epoch reuses its existing snapshot: only WAL
            // publication seams exist. Do not claim injected snapshot failures.
            if (empty and (fault == .snapshot_replace or fault == .snapshot_dir_sync)) continue;
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            try seedCompleteEpoch(tmp.dir);
            if (empty) {
                var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
                defer seed.deinit();
                try seed.snapshotAndTruncate();
                try seed.snapshotAndTruncate();
                try seed.wal_file.?.setLength(std.testing.io, 0);
                try seed.wal_file.?.sync(std.testing.io);
            }
            const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
            defer lease.close(std.testing.io);
            try cold_identity.reaffirmExclusive(lease.handle);
            var old_next: u64 = undefined;
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer stage.deinit();
                old_next = stage.view().next_seq;
                var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
                defer ticket.abort();
                stage.setPublicationFault(fault);
                try std.testing.expectError(error.IoAmbiguous, ticket.commit());
                try std.testing.expect(stage.backing.?.consumed and stage.view().preparedWritesPoisoned());
                try std.testing.expectEqual(old_next, stage.view().next_seq);
                try std.testing.expectEqual(@as(usize, 0), stage.view().changeCount());
            }
            {
                var fresh = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer fresh.deinit();
                try fresh.validate();
                try std.testing.expectEqual(fresh.backing.?.wal.bytes.len, fresh.backing.?.valid_end);
                if (fault != .wal_dir_sync) {
                    try std.testing.expectEqual(old_next, fresh.view().next_seq);
                    try std.testing.expect(fresh.view().get(.props, "outcome") == null);
                    var ticket = try fresh.prepareCompleteBatch(&complete_epoch_mutations);
                    defer ticket.abort();
                    try ticket.commit();
                    var result = fresh.takeCommittedStore();
                    defer result.deinit();
                    try std.testing.expectEqual(old_next + 2, result.next_seq);
                    try std.testing.expectEqual(@as(usize, 2), result.changeCount());
                } else {
                    // This exercises the mechanical strict-readonly/promotion
                    // pieces, not a domain-authenticated Mail adoption receipt.
                    try std.testing.expectEqual(old_next + 2, fresh.view().next_seq);
                    try std.testing.expectEqualStrings("original failure", fresh.view().get(.props, "outcome").?);
                    try std.testing.expectEqualStrings("terminal", fresh.view().get(.props, "disposition").?);
                    var clean = try OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                    defer clean.deinit();
                    try std.testing.expectEqualDeep(fresh.backing.?.wal.identity, try cold_identity.statRegular(clean.wal_file.?.handle));
                    try std.testing.expectEqual(fresh.view().next_seq, clean.next_seq);
                    try clean.preparePromotion();
                    try clean.staged_write_file.?.sync(std.testing.io);
                    const parent = try coldOpenParent(std.testing.io, tmp.dir, "complete.wal");
                    defer parent.close(std.testing.io);
                    try parent.sync(std.testing.io);
                    try fresh.validate();
                    const before_feed = clean.changeCount();
                    try clean.releaseReadHandleForPreparedPromotion();
                    clean.promotePrepared();
                    try std.testing.expect(!clean.isReadOnly());
                    try std.testing.expectEqual(old_next + 2, clean.next_seq);
                    try std.testing.expectEqual(before_feed, clean.changeCount());
                    const after = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
                    defer std.testing.allocator.free(after);
                    try std.testing.expectEqualSlices(u8, fresh.backing.?.wal.bytes, after);
                    const snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
                    defer std.testing.allocator.free(snapshot);
                    try std.testing.expectEqualSlices(u8, fresh.backing.?.snapshot.?.bytes, snapshot);
                }
            }
            var verify = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer verify.deinit();
            try std.testing.expectEqual(old_next + 2, verify.view().next_seq);
            try std.testing.expectEqualStrings("original durable job", verify.view().get(.props, "old").?);
            try std.testing.expectEqualStrings("original failure", verify.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", verify.view().get(.props, "disposition").?);
        }
    }
}

test "cold complete epoch empty capture skips invalid coverage slot and rejects unauthenticated epoch without effects" {
    // Cold custody needs POSIX fds; Windows handles cannot compile here.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    for ([_]bool{ false, true }) |invalid_both| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try seedCompleteEpoch(tmp.dir);
        var old_next: u64 = undefined;
        {
            var seed = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", .{ .max_wal_bytes = 8192, .changefeed_capacity = 0 });
            defer seed.deinit();
            old_next = seed.next_seq;
            try seed.snapshotAndTruncate();
            try seed.snapshotAndTruncate();
            var coverage = seed.snapshot_coverage.?;
            coverage.slots[0].digest[0] ^= 1;
            if (invalid_both) coverage.slots[1].digest[0] ^= 1;
            const bytes = try encodeColdSnapshot(&seed, &coverage);
            defer std.testing.allocator.free(bytes);
            const snapshot = try tmp.dir.createFile(std.testing.io, "complete.wal.snap", .{ .truncate = true });
            defer snapshot.close(std.testing.io);
            try snapshot.writePositionalAll(std.testing.io, bytes, 0);
            try snapshot.sync(std.testing.io);
            try seed.wal_file.?.setLength(std.testing.io, 0);
            try seed.wal_file.?.sync(std.testing.io);
        }
        const original_snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(original_snapshot);
        const lease = try tmp.dir.createFile(std.testing.io, "complete.wal.lock", .{ .read = true, .truncate = false });
        defer lease.close(std.testing.io);
        try cold_identity.reaffirmExclusive(lease.handle);
        if (invalid_both) {
            try std.testing.expectError(error.SnapshotCoverageMismatch, ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 }));
            const wal = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(wal);
            try std.testing.expectEqual(@as(usize, 0), wal.len);
        } else {
            {
                var stage = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
                defer stage.deinit();
                try std.testing.expectEqual(@as(usize, 1), stage.backing.?.selected_epoch.?);
                var ticket = try stage.prepareCompleteBatch(&complete_epoch_mutations);
                defer ticket.abort();
                try std.testing.expect(stage.backing.?.plan.?.snapshot_atomic == null);
                try ticket.commit();
                var result = stage.takeCommittedStore();
                defer result.deinit();
                try std.testing.expectEqual(old_next + 2, result.next_seq);
                try std.testing.expectEqual(@as(usize, 2), result.changeCount());
            }
            var restart = try ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", lease, .{ .max_wal_bytes = 8192, .changefeed_capacity = 4 });
            defer restart.deinit();
            try std.testing.expectEqual(old_next + 2, restart.view().next_seq);
            try std.testing.expectEqualStrings("original durable job", restart.view().get(.props, "old").?);
            try std.testing.expectEqualStrings("original failure", restart.view().get(.props, "outcome").?);
            try std.testing.expectEqualStrings("terminal", restart.view().get(.props, "disposition").?);
        }
        const after_snapshot = try tmp.dir.readFileAlloc(std.testing.io, "complete.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after_snapshot);
        try std.testing.expectEqualSlices(u8, original_snapshot, after_snapshot);
    }
}

test "Windows private account store rejects broad parent before creating WAL" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "broad", .default_dir);
    // A normal temp directory inherits the ordinary user profile ACL. Give
    // the gate an explicit private SDDL in the positive test below.
    const result = OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "broad/accounts.wal", .{});
    if (result) |store| {
        var unexpected = store;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.InsecurePermissions, err);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "broad/accounts.wal", .{}));
}

test "Windows private directory handle pins file creation across path replacement" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    const pinned = try cold_runtime.openPrivateDirectoryWindows(std.testing.io, tmp.dir, "private");
    defer pinned.close(std.testing.io);
    try tmp.dir.rename("private", tmp.dir, "moved", std.testing.io);
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    const file = try pinned.createFile(std.testing.io, "bound.txt", .{});
    file.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "private/bound.txt", .{}));
    const bound = try tmp.dir.openFile(std.testing.io, "moved/bound.txt", .{});
    bound.close(std.testing.io);
}

test "Windows private account store protects WAL and compacted snapshot across restart" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Match production setup: the private inheritable DACL is present at
    // directory creation, which can yield a child DACL without the AI flag.
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    try cold_runtime.requirePrivateDirectoryWindows(std.testing.io, tmp.dir, "private/accounts.wal");
    {
        const broad_snapshot = try tmp.dir.createFile(std.testing.io, "broad.snap", .{ .read = true });
        broad_snapshot.close(std.testing.io);
    }
    try tmp.dir.rename("broad.snap", tmp.dir, "private/accounts.wal.snap", std.testing.io);

    {
        var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
        defer store.deinit();
        try store.put(.accounts, "alice", "secret account state");
        try store.snapshotAndTruncate();
        const backup_bytes = try store.readPrivateSnapshotAllocWindows(std.testing.allocator, 512 * 1024 * 1024);
        defer std.testing.allocator.free(backup_bytes);
        try std.testing.expect(std.mem.indexOf(u8, backup_bytes, "secret account state") != null);
    }
    {
        const wal = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal", .verify_only);
        wal.close(std.testing.io);
        const snapshot = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal.snap", .verify_only);
        snapshot.close(std.testing.io);
    }
    var recovered = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer recovered.deinit();
    try std.testing.expectEqualStrings("secret account state", recovered.get(.accounts, "alice").?);
    try recovered.put(.accounts, "bob", "second persisted account");
}

test "Windows private compaction publishes snapshot before injected WAL refusal" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    {
        var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
        defer store.deinit();
        try store.put(.accounts, "alice", "retained");
        const length: usize = @intCast(store.wal_offset);
        const before = try std.testing.allocator.alloc(u8, length);
        defer std.testing.allocator.free(before);
        try std.testing.expectEqual(length, try store.wal_file.?.readPositionalAll(std.testing.io, before, 0));
        store.setPreparedIoFault(.{ .wal_sync = true });
        try std.testing.expectError(StoreError.IoAmbiguous, store.snapshotAndTruncate());
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(@as(u64, length), (try store.wal_file.?.stat(std.testing.io)).size);
        const after = try std.testing.allocator.alloc(u8, length);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqual(length, try store.wal_file.?.readPositionalAll(std.testing.io, after, 0));
        try std.testing.expectEqualSlices(u8, before, after);
    }
    var reopened = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer reopened.deinit();
    try std.testing.expectEqualStrings("retained", reopened.get(.accounts, "alice").?);
}

test "Windows private held WAL replay returns exact row and rejects a torn tail" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/mail.wal", .{});
    defer store.deinit();
    try store.put(.props, "baseline", "snapshot row");
    try store.snapshotAndTruncate();
    try store.put(.props, "mailfail:1", "ConnectFailed recipient");
    const exact = (try store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "mailfail:1")) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(exact);
    try std.testing.expectEqualStrings("ConnectFailed recipient", exact);
    const baseline = (try store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "baseline")) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(baseline);
    try std.testing.expectEqualStrings("snapshot row", baseline);
    try store.wal_file.?.writePositionalAll(std.testing.io, &.{ 1, 2, 3 }, store.wal_offset);
    try std.testing.expectError(StoreError.BadRecord, store.replayHeldPrivateWindowsValueAlloc(std.testing.allocator, .props, "mailfail:1"));
}

test "Windows private account store refuses a retained reader before ACL remediation" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    {
        const broad = try tmp.dir.createFile(std.testing.io, "broad.wal", .{ .read = true });
        broad.close(std.testing.io);
    }
    try tmp.dir.rename("broad.wal", tmp.dir, "private/accounts.wal", std.testing.io);
    const reader = try tmp.dir.openFile(std.testing.io, "private/accounts.wal", .{ .mode = .read_only });
    try std.testing.expectError(error.FileBusy, OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}));
    reader.close(std.testing.io);
    var store = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    store.deinit();
    const secured = try cold_runtime.openExistingPrivateWindows(tmp.dir, "private/accounts.wal", .verify_only);
    secured.close(std.testing.io);
}

test "Windows private account store rejects a WAL file reparse point" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "private", .default_dir);
    try cold_runtime.protectEmptyDirectoryWindows(std.testing.io, tmp.dir, "private");
    const target = try tmp.dir.createFile(std.testing.io, "broad.wal", .{});
    target.close(std.testing.io);
    tmp.dir.symLink(std.testing.io, "../broad.wal", "private/accounts.wal", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectError(error.InsecurePermissions, OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}));
}

test "Windows transferred private WAL stages read-only and promotes the held HANDLE after parent release" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    var parent_live = true;
    defer if (parent_live) parent.deinit();
    try parent.put(.accounts, "alice", "retained");

    var transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer transfer.deinit();
    var descriptor = transfer.release();
    defer descriptor.deinitReceived();
    var stage = try OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &descriptor);
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    try std.testing.expectEqual(@as(usize, 0), descriptor.handle);
    try std.testing.expect(stage.isReadOnly());
    try std.testing.expectEqualStrings("retained", stage.get(.accounts, "alice").?);
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.put(.accounts, "alice", "too early"));
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.preparePut(.accounts, "alice", "too early"));
    try stage.preparePromotion();
    try stage.releaseReadHandleForPreparedPromotion();
    try std.testing.expect(stage.isReadOnly());
    try std.testing.expectError(StoreError.ReadOnlyStore, stage.put(.accounts, "alice", "still early"));

    parent.deinit();
    parent_live = false;
    stage.promotePrepared();
    try stage.put(.accounts, "bob", "after commit");
    stage.deinit();
    stage_live = false;
    var recovered = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer recovered.deinit();
    try std.testing.expectEqualStrings("retained", recovered.get(.accounts, "alice").?);
    try std.testing.expectEqualStrings("after commit", recovered.get(.accounts, "bob").?);
}

test "Windows transferred private WAL rejects wrong file, directory, length, and aborts without changing parent" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    const other = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "other");
    other.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer parent.deinit();
    try parent.put(.accounts, "alice", "before");
    var foreign = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/foreign.wal", .{});
    defer foreign.deinit();
    try foreign.put(.accounts, "mallory", "foreign");

    var wrong_file_transfer = try foreign.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_file_transfer.deinit();
    var wrong_file = wrong_file_transfer.release();
    defer wrong_file.deinitReceived();
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &wrong_file));
    try std.testing.expectEqual(@as(usize, 0), wrong_file.handle);

    var wrong_dir_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_dir_transfer.deinit();
    var wrong_dir = wrong_dir_transfer.release();
    defer wrong_dir.deinitReceived();
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "other/accounts.wal", .{}, &wrong_dir));
    try std.testing.expectEqual(@as(usize, 0), wrong_dir.handle);

    var wrong_length_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer wrong_length_transfer.deinit();
    var wrong_length = wrong_length_transfer.release();
    defer wrong_length.deinitReceived();
    wrong_length.witness.length += 1;
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &wrong_length));
    try std.testing.expectEqual(@as(usize, 0), wrong_length.handle);

    var read_only_handle: usize = 0;
    const process = GetCurrentProcess();
    try std.testing.expect(DuplicateHandle(process, @intFromPtr(parent.wal_file.?.handle), process, &read_only_handle, 0x8000_0000, 0, 0) != 0);
    var read_only = WindowsWalDescriptor{ .handle = read_only_handle, .destination_pid = GetCurrentProcessId(), .witness = try windowsWalWitness(std.testing.io, parent.wal_file.?, parent.dir, parent.wal_path) };
    defer read_only.deinitReceived();
    try std.testing.expectError(error.PermissionDenied, OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &read_only));
    try std.testing.expectEqual(@as(usize, 0), read_only.handle);

    var abort_transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer abort_transfer.deinit();
    var abort_descriptor = abort_transfer.release();
    defer abort_descriptor.deinitReceived();
    var stage = try OroStore.openTransferredPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{}, &abort_descriptor);
    try parent.put(.accounts, "bob", "parent survived");
    try std.testing.expectError(StoreError.SnapshotCoverageMismatch, stage.preparePromotion());
    stage.deinit();
    try parent.put(.accounts, "charlie", "still writing");
    try std.testing.expectEqualStrings("still writing", parent.get(.accounts, "charlie").?);
}

test "Windows transferred private WAL allocation failures close candidate custody and leave parent bytes intact" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try cold_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var parent = try OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer parent.deinit();
    try parent.put(.accounts, "alice", "unchanged");
    const size: usize = @intCast(parent.wal_offset);
    const before = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(before);
    const after = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqual(size, try parent.wal_file.?.readPositionalAll(std.testing.io, before, 0));

    var completed = false;
    for (0..128) |fail_index| {
        var transfer = try parent.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
        defer transfer.deinit();
        var descriptor = transfer.release();
        defer descriptor.deinitReceived();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        const result = OroStore.openTransferredPrivateWindowsWithConfig(failing.allocator(), std.testing.io, tmp.dir, "private/accounts.wal", .{}, &descriptor);
        if (result) |opened| {
            var stage = opened;
            try std.testing.expect(stage.isReadOnly());
            try std.testing.expectEqualStrings("unchanged", stage.get(.accounts, "alice").?);
            stage.deinit();
            completed = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
        try std.testing.expectEqual(@as(usize, 0), descriptor.handle);
        try std.testing.expectEqual(@as(u64, size), parent.wal_offset);
        try std.testing.expectEqual(size, try parent.wal_file.?.readPositionalAll(std.testing.io, after, 0));
        try std.testing.expectEqualSlices(u8, before, after);
        if (completed) break;
    }
    try std.testing.expect(completed);
    try parent.put(.accounts, "bob", "parent remained writable");
}
