// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Record constants and typed persistence contracts shared by the store leaves.

const std = @import("std");
const toml = @import("../../proto/toml.zig");

pub const record_header_len = 8;

pub const payload_header_len = 10;

pub const default_max_record_len = 16 * 1024 * 1024;

pub const default_max_wal_len = 256 * 1024 * 1024;

pub const default_changefeed_capacity = 64;

pub const tombstone_len = std.math.maxInt(u32);

pub const meta_kind_next_seq: u8 = 0xFE;

pub const meta_next_seq_payload_len = 9;

pub const meta_kind_snapshot_coverage: u8 = 0xFD;

pub const meta_kind_wal_epoch: u8 = 0xFC;

pub const snapshot_coverage_version: u8 = 2;

pub const wal_epoch_len = 16;

pub const snapshot_coverage_slot_len = 8 + wal_epoch_len + std.crypto.hash.Blake3.digest_length;

pub const snapshot_coverage_v1_payload_len = 1 + 1 + 1 + 8 + wal_epoch_len + std.crypto.hash.Blake3.digest_length;

pub const snapshot_coverage_payload_len = 1 + 1 + 1 + 2 * snapshot_coverage_slot_len;

pub const wal_epoch_payload_len = 1 + wal_epoch_len;

pub const legacy_wal_epoch = std.mem.zeroes([wal_epoch_len]u8);

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

/// Narrow fault-injection seam shared by ordinary and prepared writes. Kept on
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

/// Large enough for an atomic account-drop cut: 16 certfp rows + their index,
/// 16 WebAuthn rows + their index, two session-token rows, and six account,
/// SCRAM, MFA, recovery, verification, and audit rows.
pub const max_batch_mutations = 42;

pub const meta_kind_batch: u8 = 0xFB;

pub const meta_kind_batch_format: u8 = 0xFA;

pub const batch_format_version: u8 = 1;

pub const batch_guard_len = record_header_len + 2;

// Five payload/feed retirements per row, one table backing per family, packet.
pub const prepared_retirement_capacity = max_batch_mutations * 5 + 1;

/// A bounded atomic mutation group. Keys within one family must be distinct.
/// Put values are mandatory; delete values must be absent.
pub const BatchMutation = struct {
    family: Family,
    kind: MutationKind,
    key: []const u8,
    value: ?[]const u8 = null,
};

pub const SnapshotCoverage = struct {
    slots: [2]CoverageSlot,
    count: usize,
};

pub const CoverageSlot = struct {
    covered_len: u64,
    epoch: [wal_epoch_len]u8,
    digest: [std.crypto.hash.Blake3.digest_length]u8,
};

pub const cold_epoch_record_len = record_header_len + wal_epoch_payload_len;

pub const family_count = @typeInfo(Family).@"enum".field_names.len;

pub const families = std.enums.values(Family);

pub fn familyIndex(store_family: Family) usize {
    return @backingInt(store_family);
}

pub fn decodeFamily(value: u8) ?Family {
    return std.enums.fromInt(Family, value);
}
