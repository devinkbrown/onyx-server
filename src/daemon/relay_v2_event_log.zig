// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded durable accepted-event authority for MESSAGE_V2 anti-entropy.
//!
//! Each row retains the exact canonical origin-signed wire and the sorted set
//! of nodes known to have durably accepted it. There is deliberately no TTL or
//! capacity eviction: until an authoritative membership epoch can prove that a
//! node is retired, forgetting a row could permanently partition a late peer.
//! Callers therefore reserve here before local publication or ACK emission and
//! fail closed when the configured bound is exhausted.
//!
//! The event-time required-node snapshot is supplied by the secured membership
//! authority and must contain the accepting node plus at least one explicitly
//! configured peer. Empty trust-root/TOFU configuration is not converted into a
//! local-only fallback. Once every required node confirms, the full wire retires;
//! RVG2 remains the mandatory retained replay/equivocation authority for that ID.

const store = @import("relay_v2_event_log/store.zig");

pub const RelayId = store.RelayId;
pub const default_max_rows = store.default_max_rows;
pub const default_max_confirmed_nodes_per_row = store.default_max_confirmed_nodes_per_row;
pub const default_max_cursor_nodes = store.default_max_cursor_nodes;
pub const default_max_wire_bytes = store.default_max_wire_bytes;
pub const default_max_aggregate_bytes = store.default_max_aggregate_bytes;
pub const hard_max_rows = store.hard_max_rows;
pub const hard_max_confirmed_nodes_per_row = store.hard_max_confirmed_nodes_per_row;
pub const hard_max_cursor_nodes = store.hard_max_cursor_nodes;
pub const hard_max_wire_bytes = store.hard_max_wire_bytes;
pub const hard_max_aggregate_bytes = store.hard_max_aggregate_bytes;
pub const hard_max_checkpoint_bytes = store.hard_max_checkpoint_bytes;
pub const Config = store.Config;
pub const ReserveOutcome = store.ReserveOutcome;
pub const Error = store.Error;
pub const RowView = store.RowView;
pub const PageItem = store.PageItem;
pub const PrepareAcceptedResult = store.PrepareAcceptedResult;
pub const PreparedAccepted = store.PreparedAccepted;
pub const ConfirmationOutcome = store.ConfirmationOutcome;
pub const PreparedConfirmation = store.PreparedConfirmation;
pub const NodeRetirementResult = store.NodeRetirementResult;
pub const PreparedNodeRetirement = store.PreparedNodeRetirement;
pub const EventLog = store.EventLog;
pub const CheckpointMeta = store.CheckpointMeta;
pub const isCheckpoint = store.isCheckpoint;
pub const validateCheckpoint = store.validateCheckpoint;

test {
    _ = @import("relay_v2_event_log/tests.zig");
}
