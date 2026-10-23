// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment delivery spool facade. Prepared ownership and fair delivery
//! remain together; record policy and strict checkpoint validation are leaves.

pub const ClientId = @import("attachment_delivery_spool/model.zig").ClientId;
pub const EventId = @import("attachment_delivery_spool/model.zig").EventId;
pub const default_max_records = @import("attachment_delivery_spool/model.zig").default_max_records;
pub const default_max_attachments = @import("attachment_delivery_spool/model.zig").default_max_attachments;
pub const default_max_total_bytes = @import("attachment_delivery_spool/model.zig").default_max_total_bytes;
pub const default_max_record_bytes = @import("attachment_delivery_spool/model.zig").default_max_record_bytes;
pub const hard_max_records = @import("attachment_delivery_spool/model.zig").hard_max_records;
pub const hard_max_attachments = @import("attachment_delivery_spool/model.zig").hard_max_attachments;
pub const hard_max_total_bytes = @import("attachment_delivery_spool/model.zig").hard_max_total_bytes;
pub const hard_max_record_bytes = @import("attachment_delivery_spool/model.zig").hard_max_record_bytes;
pub const hard_max_checkpoint_bytes = @import("attachment_delivery_spool/model.zig").hard_max_checkpoint_bytes;
pub const Config = @import("attachment_delivery_spool/model.zig").Config;
pub const InitError = @import("attachment_delivery_spool/model.zig").InitError;
pub const ReserveError = @import("attachment_delivery_spool/model.zig").ReserveError;
pub const TransferError = @import("attachment_delivery_spool/model.zig").TransferError;
pub const AttachmentRemap = @import("attachment_delivery_spool/model.zig").AttachmentRemap;
pub const RemapError = @import("attachment_delivery_spool/model.zig").RemapError;
pub const RemapResult = @import("attachment_delivery_spool/model.zig").RemapResult;
pub const CheckpointError = @import("attachment_delivery_spool/model.zig").CheckpointError;
pub const BatchRecord = @import("attachment_delivery_spool/model.zig").BatchRecord;
pub const OwnedBatchRecord = @import("attachment_delivery_spool/model.zig").OwnedBatchRecord;
pub const ReserveResult = @import("attachment_delivery_spool/model.zig").ReserveResult;
pub const PendingRecord = @import("attachment_delivery_spool/model.zig").PendingRecord;
pub const TransferResult = @import("attachment_delivery_spool/model.zig").TransferResult;
pub const DiscardResult = @import("attachment_delivery_spool/model.zig").DiscardResult;
pub const PreparedAttachmentTransfer = @import("attachment_delivery_spool/engine.zig").PreparedAttachmentTransfer;
pub const PreparedBatch = @import("attachment_delivery_spool/engine.zig").PreparedBatch;
pub const Spool = @import("attachment_delivery_spool/engine.zig").Spool;
pub const CheckpointMeta = @import("attachment_delivery_spool/checkpoint.zig").CheckpointMeta;
pub const isCheckpoint = @import("attachment_delivery_spool/checkpoint.zig").isCheckpoint;
pub const validateCheckpoint = @import("attachment_delivery_spool/checkpoint.zig").validateCheckpoint;

test {
    _ = @import("attachment_delivery_spool/tests_batch.zig");
    _ = @import("attachment_delivery_spool/tests_fairness.zig");
    _ = @import("attachment_delivery_spool/tests_transfer.zig");
    _ = @import("attachment_delivery_spool/tests_remap.zig");
    _ = @import("attachment_delivery_spool/tests_identity.zig");
    _ = @import("attachment_delivery_spool/tests_checkpoint.zig");
}
