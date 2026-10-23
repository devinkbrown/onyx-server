// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment delivery types, owned records, and capacity limits.

const std = @import("std");

/// The same flat physical attachment id as `sessions.ClientId`. Keeping the
/// alias local leaves this authority independently testable while remaining
/// assignment-compatible with the session registry's public `u64` id.
pub const ClientId = u64;

pub const EventId = [16]u8;

pub const default_max_records: usize = 8192;

pub const default_max_attachments: usize = 4096;

pub const default_max_total_bytes: usize = 16 * 1024 * 1024;

pub const default_max_record_bytes: usize = 8192;

pub const hard_max_records: usize = 65_536;

pub const hard_max_attachments: usize = 65_536;

pub const hard_max_total_bytes: usize = 64 * 1024 * 1024;

pub const hard_max_record_bytes: usize = 64 * 1024;

pub const hard_max_checkpoint_bytes: usize = 128 * 1024 * 1024;

pub const Config = struct {
    max_attachments: usize = default_max_attachments,
    max_records: usize = default_max_records,
    max_total_bytes: usize = default_max_total_bytes,
    max_record_bytes: usize = default_max_record_bytes,
};

pub const InitError = error{InvalidConfig};

pub const ReserveError = std.mem.Allocator.Error || error{
    CapacityExceeded,
    InvalidRecord,
    Equivocation,
};

pub const TransferError = std.mem.Allocator.Error || error{Equivocation};

pub const AttachmentRemap = struct {
    old_client: ClientId,
    new_client: ClientId,
};

pub const RemapError = std.mem.Allocator.Error || error{
    CapacityExceeded,
    MissingMapping,
    DuplicateSource,
    Equivocation,
};

pub const RemapResult = struct {
    records_remapped: usize,
    exact_duplicates_merged: usize,
    attachment_count: usize,
};

pub const CheckpointError = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    InvalidConfig,
    ConfigMismatch,
    InvalidField,
    InvalidRecord,
    CapacityExceeded,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateEntry,
    CheckpointTooLarge,
    InvalidState,
    NonCanonicalOrder,
};

/// One already-rendered, attachment-specific record to reserve. `bytes` must be
/// exactly one control-free IRC record ending in CRLF.
pub const BatchRecord = struct {
    client: ClientId,
    event_id: EventId,
    bytes: []const u8,
};

/// Caller-owned rendered body. `prepareOwnedBatch` / `reserveOwnedBatch` either
/// leave every body with the caller (on error) or take ownership of the bodies
/// they insert. Exact duplicates stay with the caller. Adopted slices are
/// replaced with an empty slice so the caller can free whatever remains.
pub const OwnedBatchRecord = struct {
    client: ClientId,
    event_id: EventId,
    bytes: []u8,
};

pub const ReserveResult = struct {
    inserted: usize,
    exact_duplicates: usize,
};

/// Borrowed pending work. The view remains valid until the spool is mutated.
/// A caller must copy/accept `bytes` into the exact client's SendQ before calling
/// `commitHeadToSendq(client, sequence, event_id)`.
///
/// `sequence` is an incarnation-local opaque compare-and-commit token. It is not
/// client-visible or externally persisted. Helix checkpoint capture must occur at
/// a quiescent delivery-authority boundary where no borrowed `PendingRecord` can
/// survive exec/restore; FIFO, event id, attachment id, and rendered bytes are the
/// persisted authority.
pub const PendingRecord = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []const u8,
};

pub const TransferResult = struct {
    transferred: usize,
    exact_duplicates_merged: usize,
};

pub const DiscardResult = struct {
    discarded_records: usize,
    discarded_bytes: usize,
};

pub const Entry = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []u8,
};

pub const AttachmentTransferPlan = struct {
    client: ClientId,
    keep: bool = true,
};
