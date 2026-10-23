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

const std = @import("std");
const message_relay_v2 = @import("../../substrate/undertow/message_relay_v2.zig");

const checkpoint_codec = @import("checkpoint_wire.zig");
const row_storage = @import("rows.zig");
const magic = checkpoint_codec.magic;
const checkpoint_version = checkpoint_codec.checkpoint_version;
const checkpoint_header_len = checkpoint_codec.checkpoint_header_len;
const row_origin_pubkey_offset = checkpoint_codec.row_origin_pubkey_offset;
const row_origin_node_offset = checkpoint_codec.row_origin_node_offset;
const row_hlc_offset = checkpoint_codec.row_hlc_offset;
const row_wire_len_offset = checkpoint_codec.row_wire_len_offset;
const row_confirmed_count_offset = checkpoint_codec.row_confirmed_count_offset;
const row_required_count_offset = checkpoint_codec.row_required_count_offset;
const row_excluded_count_offset = checkpoint_codec.row_excluded_count_offset;
const row_prefix_len = checkpoint_codec.row_prefix_len;
const cursor_entry_len = checkpoint_codec.cursor_entry_len;
const checksum_len = checkpoint_codec.checksum_len;
const checkpoint_checksum_domain = checkpoint_codec.checkpoint_checksum_domain;
const checkpointChecksum = checkpoint_codec.checkpointChecksum;
const readU32 = checkpoint_codec.readU32;
const readU64 = checkpoint_codec.readU64;
const writeU32 = checkpoint_codec.writeU32;
const writeU64 = checkpoint_codec.writeU64;
const Row = row_storage.Row;
const CursorEntry = row_storage.CursorEntry;
const rowMissingForTarget = row_storage.rowMissingForTarget;
const pubkeyLess = row_storage.pubkeyLess;
const originEqual = row_storage.originEqual;
const headLess = row_storage.headLess;
const nextOriginHead = row_storage.nextOriginHead;
const greatestMissingOrigin = row_storage.greatestMissingOrigin;
const greatestOrigin = row_storage.greatestOrigin;
const containsOrigin = row_storage.containsOrigin;
const idsEqual = row_storage.idsEqual;
const idLess = row_storage.idLess;
const lowerBoundRows = row_storage.lowerBoundRows;
const lowerBoundNodes = row_storage.lowerBoundNodes;
const lowerBoundCursors = row_storage.lowerBoundCursors;
const containsNode = row_storage.containsNode;
const nodeIndex = row_storage.nodeIndex;
const insertNodeAssumeCapacity = row_storage.insertNodeAssumeCapacity;
const insertCursorAssumeCapacity = row_storage.insertCursorAssumeCapacity;
const removeNodeAt = row_storage.removeNodeAt;
const removeRowSlot = row_storage.removeRowSlot;
const removeCursorSlot = row_storage.removeCursorSlot;

pub const RelayId = message_relay_v2.RelayId;

pub const default_max_rows: usize = 8192;
pub const default_max_confirmed_nodes_per_row: usize = 256;
pub const default_max_cursor_nodes: usize = 256;
pub const default_max_wire_bytes: usize = 1024 * 1024;
pub const default_max_aggregate_bytes: usize = 32 * 1024 * 1024;
pub const hard_max_rows: usize = 65_536;
pub const hard_max_confirmed_nodes_per_row: usize = 4096;
pub const hard_max_cursor_nodes: usize = 4096;
pub const hard_max_wire_bytes: usize = 1024 * 1024;
pub const hard_max_aggregate_bytes: usize = 64 * 1024 * 1024;
pub const hard_max_checkpoint_bytes: usize = 64 * 1024 * 1024;

pub const Config = struct {
    max_rows: usize = default_max_rows,
    max_confirmed_nodes_per_row: usize = default_max_confirmed_nodes_per_row,
    max_cursor_nodes: usize = default_max_cursor_nodes,
    max_wire_bytes: usize = default_max_wire_bytes,
    max_aggregate_bytes: usize = default_max_aggregate_bytes,

    fn valid(self: Config) bool {
        return self.max_rows > 0 and self.max_rows <= hard_max_rows and
            self.max_confirmed_nodes_per_row > 0 and
            self.max_confirmed_nodes_per_row <= hard_max_confirmed_nodes_per_row and
            self.max_cursor_nodes > 0 and self.max_cursor_nodes <= hard_max_cursor_nodes and
            self.max_wire_bytes > 0 and self.max_wire_bytes <= hard_max_wire_bytes and
            self.max_aggregate_bytes > 0 and
            self.max_aggregate_bytes <= hard_max_aggregate_bytes;
    }

    fn eql(a: Config, b: Config) bool {
        return a.max_rows == b.max_rows and
            a.max_confirmed_nodes_per_row == b.max_confirmed_nodes_per_row and
            a.max_cursor_nodes == b.max_cursor_nodes and
            a.max_wire_bytes == b.max_wire_bytes and
            a.max_aggregate_bytes == b.max_aggregate_bytes;
    }
};

pub const ReserveOutcome = enum {
    inserted,
    exact_duplicate,
    conflict,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
    InvalidMembership,
    InvalidWire,
    RelayIdMismatch,
    NotFound,
    NodeNotRequired,
    PreparedMutationActive,
    CapacityExceeded,
    BadMagic,
    UnsupportedVersion,
    UnknownFlags,
    ConfigMismatch,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateEntry,
    DuplicateNode,
    NonCanonicalOrder,
    CheckpointTooLarge,
    CounterMismatch,
    CursorTargetMissing,
    InvalidState,
};

pub const RowView = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []const u8,
    required_nodes: []const u64,
    confirmed_nodes: []const u64,
    excluded_once_nodes: []const u64,
};

pub const PageItem = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []const u8,
};

pub const PrepareAcceptedResult = union(enum) {
    ready: PreparedAccepted,
    conflict,
};

const AcceptedAction = union(enum) {
    no_op,
    insert: Row,
    add_exclusion: struct {
        row_index: usize,
        insert_index: usize,
        node: u64,
    },
};

/// Fully allocated accepted-event change waiting to join replay, Lotus, outbox,
/// and attachment-spool preparation. `commit` is allocation-free and cannot
/// fail. Keep one mutable value and always install `defer plan.deinit()`.
pub const PreparedAccepted = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    outcome_value: ReserveOutcome,
    action: AcceptedAction,
    state: State = .prepared,

    pub fn outcome(self: *const PreparedAccepted) ReserveOutcome {
        return self.outcome_value;
    }

    pub fn commit(self: *PreparedAccepted) ReserveOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        switch (self.action) {
            .no_op => {},
            .insert => |row| {
                const index = lowerBoundRows(self.log.rows.items, row.relay_id);
                self.log.rows.appendAssumeCapacity(undefined);
                var cursor = self.log.rows.items.len - 1;
                while (cursor > index) : (cursor -= 1)
                    self.log.rows.items[cursor] = self.log.rows.items[cursor - 1];
                self.log.rows.items[index] = row;
                self.log.aggregate_bytes += rowAggregateBytes(row);
                self.log.checkpoint_body_bytes += rowBodyBytes(row);
                self.action = .no_op;
            },
            .add_exclusion => |add| {
                const row = &self.log.rows.items[add.row_index];
                insertNodeAssumeCapacity(&row.excluded_once_nodes, add.insert_index, add.node);
                self.log.aggregate_bytes += @sizeOf(u64);
                self.log.checkpoint_body_bytes += @sizeOf(u64);
            },
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    pub fn abort(self: *PreparedAccepted) void {
        if (self.state != .prepared) return;
        switch (self.action) {
            .insert => |*row| row.deinit(self.log.allocator),
            else => {},
        }
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedAccepted) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const ConfirmationOutcome = enum {
    already_confirmed,
    confirmed,
    confirmed_and_retired,
};

const ConfirmationAction = union(enum) {
    no_op,
    add: struct {
        row_index: usize,
        confirmed_index: usize,
        excluded_index: ?usize,
        node: u64,
    },
    retire_row: usize,
};

/// Prepared authenticated durable-ACK consequence. Authentication and binding
/// of `confirmed_node` to the secured peer happen above this leaf.
pub const PreparedConfirmation = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    outcome_value: ConfirmationOutcome,
    action: ConfirmationAction,
    state: State = .prepared,

    pub fn outcome(self: *const PreparedConfirmation) ConfirmationOutcome {
        return self.outcome_value;
    }

    pub fn commit(self: *PreparedConfirmation) ConfirmationOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        switch (self.action) {
            .no_op => {},
            .add => |add| {
                const row = &self.log.rows.items[add.row_index];
                if (add.excluded_index) |excluded_index| {
                    removeNodeAt(&row.excluded_once_nodes, excluded_index);
                } else {
                    self.log.aggregate_bytes += @sizeOf(u64);
                    self.log.checkpoint_body_bytes += @sizeOf(u64);
                }
                insertNodeAssumeCapacity(&row.confirmed_nodes, add.confirmed_index, add.node);
            },
            .retire_row => |row_index| self.log.removeRowAt(row_index),
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    pub fn abort(self: *PreparedConfirmation) void {
        if (self.state != .prepared) return;
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedConfirmation) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const NodeRetirementResult = struct {
    rows_changed: usize,
    rows_retired: usize,
    cursor_removed: bool,
};

/// Explicit configuration-authorized membership retirement. This leaf cannot
/// authenticate configuration; callers must prepare this only after validating
/// a signed/configured removal, never from liveness or a TTL.
pub const PreparedNodeRetirement = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    node: u64,
    state: State = .prepared,

    pub fn commit(self: *PreparedNodeRetirement) NodeRetirementResult {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        var result: NodeRetirementResult = .{
            .rows_changed = 0,
            .rows_retired = 0,
            .cursor_removed = false,
        };
        var row_index: usize = 0;
        while (row_index < self.log.rows.items.len) {
            const row = &self.log.rows.items[row_index];
            const required_index = lowerBoundNodes(row.required_nodes.items, self.node);
            if (required_index == row.required_nodes.items.len or
                row.required_nodes.items[required_index] != self.node)
            {
                row_index += 1;
                continue;
            }
            removeNodeAt(&row.required_nodes, required_index);
            self.log.aggregate_bytes -= @sizeOf(u64);
            self.log.checkpoint_body_bytes -= @sizeOf(u64);
            if (nodeIndex(row.confirmed_nodes.items, self.node)) |index| {
                removeNodeAt(&row.confirmed_nodes, index);
                self.log.aggregate_bytes -= @sizeOf(u64);
                self.log.checkpoint_body_bytes -= @sizeOf(u64);
            }
            if (nodeIndex(row.excluded_once_nodes.items, self.node)) |index| {
                removeNodeAt(&row.excluded_once_nodes, index);
                self.log.aggregate_bytes -= @sizeOf(u64);
                self.log.checkpoint_body_bytes -= @sizeOf(u64);
            }
            result.rows_changed += 1;
            if (rowCovered(row.*)) {
                self.log.removeRowAt(row_index);
                result.rows_retired += 1;
            } else {
                row_index += 1;
            }
        }
        const cursor_index = lowerBoundCursors(self.log.cursors.items, self.node);
        if (cursor_index < self.log.cursors.items.len and
            self.log.cursors.items[cursor_index].node == self.node)
        {
            removeCursorSlot(&self.log.cursors, cursor_index);
            self.log.aggregate_bytes -= cursor_entry_len;
            self.log.checkpoint_body_bytes -= cursor_entry_len;
            result.cursor_removed = true;
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return result;
    }

    pub fn abort(self: *PreparedNodeRetirement) void {
        if (self.state != .prepared) return;
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedNodeRetirement) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const EventLog = struct {
    allocator: std.mem.Allocator,
    config: Config,
    frozen_config: Config,
    rows: std.ArrayListUnmanaged(Row) = .empty,
    cursors: std.ArrayListUnmanaged(CursorEntry) = .empty,
    aggregate_bytes: usize = 0,
    checkpoint_body_bytes: usize = 0,
    mutation_epoch: u64 = 0,
    prepared_active: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) error{InvalidConfig}!EventLog {
        if (!config.valid()) return error.InvalidConfig;
        return .{ .allocator = allocator, .config = config, .frozen_config = config };
    }

    pub fn deinit(self: *EventLog) void {
        for (self.rows.items) |*row| row.deinit(self.allocator);
        self.rows.deinit(self.allocator);
        self.cursors.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const EventLog) usize {
        return self.rows.items.len;
    }

    pub fn viewAt(self: *const EventLog, index: usize) RowView {
        const row = &self.rows.items[index];
        return .{
            .relay_id = row.relay_id,
            .origin_pubkey = row.origin_pubkey,
            .origin_node = row.origin_node,
            .hlc = row.hlc,
            .wire = row.wire,
            .required_nodes = row.required_nodes.items,
            .confirmed_nodes = row.confirmed_nodes.items,
            .excluded_once_nodes = row.excluded_once_nodes.items,
        };
    }

    pub fn contains(self: *const EventLog, relay_id: RelayId) bool {
        const index = lowerBoundRows(self.rows.items, relay_id);
        return index < self.rows.items.len and idsEqual(self.rows.items[index].relay_id, relay_id);
    }

    /// Return the retained row for `relay_id`, or null when this log has no
    /// such accepted-event authority. Every slice in the view aliases the log
    /// and remains valid only until the next mutation or `deinit`.
    pub fn viewFor(self: *const EventLog, relay_id: RelayId) ?RowView {
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return null;
        return self.viewAt(index);
    }

    /// Return the exact canonical wire retained for `relay_id`, or null when
    /// this log has no such accepted-event authority. The slice aliases the
    /// log and remains valid only until the next mutation or `deinit`.
    pub fn wireFor(self: *const EventLog, relay_id: RelayId) ?[]const u8 {
        return if (self.viewFor(relay_id)) |row| row.wire else null;
    }

    pub fn isConfirmedBy(self: *const EventLog, relay_id: RelayId, node: u64) bool {
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return false;
        return containsNode(self.rows.items[index].confirmed_nodes.items, node);
    }

    fn beginPrepare(self: *EventLog) Error!u64 {
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        self.prepared_active = true;
        return self.mutation_epoch;
    }

    fn bumpEpoch(self: *EventLog) void {
        self.mutation_epoch +%= 1;
    }

    fn validateLiveConfig(self: *const EventLog) Error!void {
        if (!self.config.valid()) return error.InvalidConfig;
        if (!Config.eql(self.config, self.frozen_config)) return error.ConfigMismatch;
        if (self.rows.items.len > self.config.max_rows or
            self.cursors.items.len > self.config.max_cursor_nodes)
            return error.CapacityExceeded;
    }

    /// Prepare exact accepted MESSAGE_V2 authority. `accepting_node` is the
    /// local node whose durable acceptance this commit publishes. `ingress_node`
    /// is merely a one-sweep loop exclusion and is never treated as a durable
    /// confirmation. `required_nodes` is the sorted authoritative membership
    /// snapshot for this event; later joins do not modify an existing row.
    pub fn prepareAccepted(
        self: *EventLog,
        relay_id: RelayId,
        wire: []const u8,
        accepting_node: u64,
        ingress_node: ?u64,
        required_nodes: []const u64,
    ) Error!PrepareAcceptedResult {
        if (accepting_node == 0) return error.InvalidNode;
        if (ingress_node) |node| if (node == 0) return error.InvalidNode;
        try validateRequiredMembership(required_nodes, accepting_node, self.config.max_confirmed_nodes_per_row);
        const expected_epoch = try self.beginPrepare();
        errdefer self.prepared_active = false;
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index < self.rows.items.len and idsEqual(self.rows.items[index].relay_id, relay_id)) {
            const row = &self.rows.items[index];
            if (!std.mem.eql(u8, row.wire, wire)) {
                self.prepared_active = false;
                return .conflict;
            }
            if (ingress_node) |node| {
                if (containsNode(row.required_nodes.items, node) and
                    !containsNode(row.confirmed_nodes.items, node) and
                    !containsNode(row.excluded_once_nodes.items, node))
                {
                    if (row.excluded_once_nodes.items.len >= self.config.max_confirmed_nodes_per_row)
                        return error.CapacityExceeded;
                    try self.ensureProspectiveCapacity(@sizeOf(u64), @sizeOf(u64));
                    const excluded_index = lowerBoundNodes(row.excluded_once_nodes.items, node);
                    try row.excluded_once_nodes.ensureUnusedCapacity(self.allocator, 1);
                    return .{ .ready = .{
                        .log = self,
                        .expected_epoch = expected_epoch,
                        .outcome_value = .exact_duplicate,
                        .action = .{ .add_exclusion = .{
                            .row_index = index,
                            .insert_index = excluded_index,
                            .node = node,
                        } },
                    } };
                }
            }
            return .{ .ready = .{
                .log = self,
                .expected_epoch = expected_epoch,
                .outcome_value = .exact_duplicate,
                .action = .no_op,
            } };
        }

        if (self.rows.items.len >= self.config.max_rows) return error.CapacityExceeded;
        const excluded_count: usize = if (ingress_node != null and
            ingress_node.? != accepting_node and
            containsNode(required_nodes, ingress_node.?)) 1 else 0;
        const added_aggregate = std.math.add(usize, wire.len, (required_nodes.len + 1 + excluded_count) * @sizeOf(u64)) catch
            return error.CapacityExceeded;
        const added_body = std.math.add(usize, row_prefix_len, added_aggregate) catch
            return error.CapacityExceeded;
        try self.ensureProspectiveCapacity(added_aggregate, added_body);
        const wire_meta = try validateWireAndId(self.allocator, self.config, relay_id, wire);
        if (self.hasOriginHlc(wire_meta.origin_pubkey, wire_meta.hlc))
            return error.DuplicateEntry;

        var staged = Row{
            .relay_id = relay_id,
            .origin_pubkey = wire_meta.origin_pubkey,
            .origin_node = wire_meta.origin_node,
            .hlc = wire_meta.hlc,
            .wire = try self.allocator.dupe(u8, wire),
        };
        errdefer staged.deinit(self.allocator);
        try staged.required_nodes.ensureTotalCapacity(self.allocator, required_nodes.len);
        staged.required_nodes.appendSliceAssumeCapacity(required_nodes);
        try staged.confirmed_nodes.ensureTotalCapacity(self.allocator, 1);
        staged.confirmed_nodes.appendAssumeCapacity(accepting_node);
        if (ingress_node) |node| if (node != accepting_node and containsNode(required_nodes, node)) {
            try staged.excluded_once_nodes.ensureTotalCapacity(self.allocator, 1);
            staged.excluded_once_nodes.appendAssumeCapacity(node);
        };
        try self.rows.ensureUnusedCapacity(self.allocator, 1);
        return .{ .ready = .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .inserted,
            .action = .{ .insert = staged },
        } };
    }

    pub fn reserveAccepted(
        self: *EventLog,
        relay_id: RelayId,
        wire: []const u8,
        accepting_node: u64,
        ingress_node: ?u64,
        required_nodes: []const u64,
    ) Error!ReserveOutcome {
        var result = try self.prepareAccepted(relay_id, wire, accepting_node, ingress_node, required_nodes);
        return switch (result) {
            .conflict => .conflict,
            .ready => |*prepared| blk: {
                defer prepared.deinit();
                break :blk prepared.commit();
            },
        };
    }

    pub fn prepareAuthenticatedDurableAck(
        self: *EventLog,
        relay_id: RelayId,
        confirmed_node: u64,
    ) Error!PreparedConfirmation {
        if (confirmed_node == 0) return error.InvalidNode;
        const expected_epoch = try self.beginPrepare();
        errdefer self.prepared_active = false;
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return error.NotFound;
        const row = &self.rows.items[index];
        if (!containsNode(row.required_nodes.items, confirmed_node)) return error.NodeNotRequired;
        if (containsNode(row.confirmed_nodes.items, confirmed_node)) return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .already_confirmed,
            .action = .no_op,
        };
        if (coverageAfterConfirmation(row.*, confirmed_node)) return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .confirmed_and_retired,
            .action = .{ .retire_row = index },
        };
        const excluded_index = nodeIndex(row.excluded_once_nodes.items, confirmed_node);
        if (excluded_index == null) try self.ensureProspectiveCapacity(@sizeOf(u64), @sizeOf(u64));
        const confirmed_index = lowerBoundNodes(row.confirmed_nodes.items, confirmed_node);
        try row.confirmed_nodes.ensureUnusedCapacity(self.allocator, 1);
        return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .confirmed,
            .action = .{ .add = .{
                .row_index = index,
                .confirmed_index = confirmed_index,
                .excluded_index = excluded_index,
                .node = confirmed_node,
            } },
        };
    }

    pub fn confirmAuthenticatedDurableAck(
        self: *EventLog,
        relay_id: RelayId,
        confirmed_node: u64,
    ) Error!ConfirmationOutcome {
        var prepared = try self.prepareAuthenticatedDurableAck(relay_id, confirmed_node);
        defer prepared.deinit();
        return prepared.commit();
    }

    pub fn prepareConfiguredNodeRetirement(self: *EventLog, node: u64) Error!PreparedNodeRetirement {
        if (node == 0) return error.InvalidNode;
        const expected_epoch = try self.beginPrepare();
        return .{ .log = self, .expected_epoch = expected_epoch, .node = node };
    }

    fn hasOriginHlc(
        self: *const EventLog,
        origin_pubkey: [message_relay_v2.pubkey_len]u8,
        hlc: u64,
    ) bool {
        for (self.rows.items) |row| {
            if (row.hlc == hlc and std.mem.eql(u8, &row.origin_pubkey, &origin_pubkey))
                return true;
        }
        return false;
    }

    /// Fill `out` with exact wires required by `target_node` and not durably
    /// confirmed there. At most the lowest missing HLC for each origin is
    /// exposed: a higher event can never overtake a lower unconfirmed event and
    /// be retired by RVG2's greatest-W watermark. The durable per-target cursor
    /// rotates origins for fairness; it never advances within an origin. Ingress
    /// exclusion consumes one head sweep, then the same head becomes eligible.
    pub fn collectPageForNode(
        self: *EventLog,
        target_node: u64,
        out: []PageItem,
    ) Error!usize {
        if (target_node == 0) return error.InvalidNode;
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        if (self.rows.items.len == 0 or out.len == 0) return 0;
        var has_missing = false;
        for (self.rows.items) |row| if (rowMissingForTarget(row, target_node)) {
            has_missing = true;
            break;
        };
        if (!has_missing) return 0;

        var cursor_index = lowerBoundCursors(self.cursors.items, target_node);
        if (cursor_index == self.cursors.items.len or self.cursors.items[cursor_index].node != target_node) {
            if (self.cursors.items.len >= self.config.max_cursor_nodes) return error.CapacityExceeded;
            try self.ensureProspectiveCapacity(cursor_entry_len, cursor_entry_len);
            try self.cursors.ensureUnusedCapacity(self.allocator, 1);
            insertCursorAssumeCapacity(&self.cursors, cursor_index, .{
                .node = target_node,
                // Starting after the greatest origin wraps the first page to
                // the canonical minimum while keeping the cursor referentially
                // strict in checkpoints.
                .after_origin_pubkey = greatestMissingOrigin(self.rows.items, target_node).?,
            });
            self.aggregate_bytes += cursor_entry_len;
            self.checkpoint_body_bytes += cursor_entry_len;
            self.bumpEpoch();
        }
        cursor_index = lowerBoundCursors(self.cursors.items, target_node);
        const wrap_at = self.cursors.items[cursor_index].after_origin_pubkey;
        var after: ?[message_relay_v2.pubkey_len]u8 = wrap_at;
        var upper: ?[message_relay_v2.pubkey_len]u8 = null;
        var wrapped = false;
        var written: usize = 0;
        while (written < out.len) {
            const head_index = nextOriginHead(self.rows.items, target_node, after, upper) orelse {
                if (wrapped) break;
                wrapped = true;
                after = null;
                upper = wrap_at;
                continue;
            };
            const row = &self.rows.items[head_index];
            after = row.origin_pubkey;
            if (!std.mem.eql(
                u8,
                &self.cursors.items[cursor_index].after_origin_pubkey,
                &row.origin_pubkey,
            )) {
                self.cursors.items[cursor_index].after_origin_pubkey = row.origin_pubkey;
                self.bumpEpoch();
            }
            if (nodeIndex(row.excluded_once_nodes.items, target_node)) |excluded_index| {
                removeNodeAt(&row.excluded_once_nodes, excluded_index);
                self.aggregate_bytes -= @sizeOf(u64);
                self.checkpoint_body_bytes -= @sizeOf(u64);
                self.bumpEpoch();
                continue;
            }
            out[written] = .{
                .relay_id = row.relay_id,
                .origin_pubkey = row.origin_pubkey,
                .origin_node = row.origin_node,
                .hlc = row.hlc,
                .wire = row.wire,
            };
            written += 1;
        }
        return written;
    }

    fn ensureProspectiveCapacity(
        self: *const EventLog,
        added_aggregate: usize,
        added_body: usize,
    ) Error!void {
        const aggregate = std.math.add(usize, self.aggregate_bytes, added_aggregate) catch
            return error.CapacityExceeded;
        if (aggregate > self.config.max_aggregate_bytes) return error.CapacityExceeded;
        const body = std.math.add(usize, self.checkpoint_body_bytes, added_body) catch
            return error.CapacityExceeded;
        if (body > hard_max_checkpoint_bytes - checkpoint_header_len - checksum_len)
            return error.CapacityExceeded;
    }

    fn removeRowAt(self: *EventLog, index: usize) void {
        const removed_origin = self.rows.items[index].origin_pubkey;
        const aggregate = rowAggregateBytes(self.rows.items[index]);
        const body = rowBodyBytes(self.rows.items[index]);
        self.rows.items[index].deinit(self.allocator);
        removeRowSlot(&self.rows, index);
        self.aggregate_bytes -= aggregate;
        self.checkpoint_body_bytes -= body;
        if (self.rows.items.len == 0) {
            const cursor_bytes = self.cursors.items.len * cursor_entry_len;
            self.cursors.clearRetainingCapacity();
            self.aggregate_bytes -= cursor_bytes;
            self.checkpoint_body_bytes -= cursor_bytes;
            return;
        }
        if (!containsOrigin(self.rows.items, removed_origin)) {
            const fallback = greatestOrigin(self.rows.items).?;
            for (self.cursors.items) |*cursor| {
                if (std.mem.eql(u8, &cursor.after_origin_pubkey, &removed_origin))
                    cursor.after_origin_pubkey = fallback;
            }
        }
    }

    pub fn encodeCheckpoint(self: *const EventLog, allocator: std.mem.Allocator) Error![]u8 {
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        var body_len: usize = 0;
        var aggregate: usize = 0;
        var previous_id: ?RelayId = null;
        for (self.rows.items) |row| {
            if (row.wire.len == 0 or row.wire.len > self.config.max_wire_bytes)
                return error.InvalidWire;
            if (row.required_nodes.items.len == 0 or
                row.required_nodes.items.len > self.config.max_confirmed_nodes_per_row or
                row.confirmed_nodes.items.len > row.required_nodes.items.len or
                row.excluded_once_nodes.items.len > self.config.max_confirmed_nodes_per_row)
                return error.CapacityExceeded;
            if (previous_id) |previous| {
                if (idsEqual(previous, row.relay_id)) return error.DuplicateEntry;
                if (!idLess(previous, row.relay_id)) return error.NonCanonicalOrder;
            }
            previous_id = row.relay_id;
            try validateRowNodes(row);
            const node_count = row.required_nodes.items.len + row.confirmed_nodes.items.len + row.excluded_once_nodes.items.len;
            const nodes_bytes = std.math.mul(usize, node_count, @sizeOf(u64)) catch
                return error.CheckpointTooLarge;
            aggregate = std.math.add(usize, aggregate, row.wire.len + nodes_bytes) catch
                return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, row_prefix_len + row.wire.len + nodes_bytes) catch
                return error.CheckpointTooLarge;
        }
        if (self.rows.items.len > self.config.max_rows or
            self.cursors.items.len > self.config.max_cursor_nodes)
            return error.CapacityExceeded;
        var previous_cursor_node: ?u64 = null;
        for (self.cursors.items) |cursor| {
            if (cursor.node == 0) return error.InvalidNode;
            if (previous_cursor_node) |previous| {
                if (cursor.node == previous) return error.DuplicateNode;
                if (cursor.node < previous) return error.NonCanonicalOrder;
            }
            if (!containsOrigin(self.rows.items, cursor.after_origin_pubkey))
                return error.CursorTargetMissing;
            previous_cursor_node = cursor.node;
            aggregate = std.math.add(usize, aggregate, cursor_entry_len) catch return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, cursor_entry_len) catch return error.CheckpointTooLarge;
        }
        if (aggregate > self.config.max_aggregate_bytes) return error.CapacityExceeded;
        if (aggregate != self.aggregate_bytes or body_len != self.checkpoint_body_bytes)
            return error.CounterMismatch;
        const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes or body_len > std.math.maxInt(u64))
            return error.CheckpointTooLarge;

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..magic.len], &magic);
        out[4] = checkpoint_version;
        out[5] = 0;
        writeU32(out[6..10], @intCast(self.config.max_rows));
        writeU32(out[10..14], @intCast(self.config.max_confirmed_nodes_per_row));
        writeU32(out[14..18], @intCast(self.config.max_wire_bytes));
        writeU64(out[18..26], @intCast(self.config.max_aggregate_bytes));
        writeU32(out[26..30], @intCast(self.config.max_cursor_nodes));
        writeU32(out[30..34], @intCast(self.rows.items.len));
        writeU32(out[34..38], @intCast(self.cursors.items.len));
        writeU64(out[38..46], @intCast(body_len));
        var pos: usize = checkpoint_header_len;
        for (self.rows.items) |row| {
            @memcpy(out[pos..][0..@sizeOf(RelayId)], &row.relay_id);
            pos += @sizeOf(RelayId);
            @memcpy(out[pos..][0..message_relay_v2.pubkey_len], &row.origin_pubkey);
            pos += message_relay_v2.pubkey_len;
            writeU64(out[pos..][0..8], row.origin_node);
            pos += 8;
            writeU64(out[pos..][0..8], row.hlc);
            pos += 8;
            writeU32(out[pos..][0..4], @intCast(row.wire.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.confirmed_nodes.items.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.required_nodes.items.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.excluded_once_nodes.items.len));
            pos += 4;
            @memcpy(out[pos..][0..row.wire.len], row.wire);
            pos += row.wire.len;
            for (row.required_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
            for (row.confirmed_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
            for (row.excluded_once_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
        }
        for (self.cursors.items) |cursor| {
            writeU64(out[pos..][0..8], cursor.node);
            pos += 8;
            @memcpy(out[pos..][0..message_relay_v2.pubkey_len], &cursor.after_origin_pubkey);
            pos += message_relay_v2.pubkey_len;
        }
        std.debug.assert(pos == prefix_len);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    /// Strict-current transactional restore. The returned log is fully staged;
    /// callers may swap it into Helix state only after every sibling capsule
    /// has also validated. No legacy fallback belongs on this path.
    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) Error!EventLog {
        const meta = try validateCheckpoint(bytes);
        if (!Config.eql(meta.config, expected_config)) return error.ConfigMismatch;
        var out = try EventLog.init(allocator, expected_config);
        errdefer out.deinit();
        try out.rows.ensureTotalCapacity(allocator, meta.row_count);
        var pos: usize = checkpoint_header_len;
        for (0..meta.row_count) |_| {
            const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
            pos += @sizeOf(RelayId);
            const origin_pubkey: [message_relay_v2.pubkey_len]u8 = bytes[pos..][0..message_relay_v2.pubkey_len].*;
            pos += message_relay_v2.pubkey_len;
            const origin_node = readU64(bytes[pos..][0..8]);
            pos += 8;
            const hlc = readU64(bytes[pos..][0..8]);
            pos += 8;
            const wire_len: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const node_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const required_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const excluded_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const row = try decodeRow(
                allocator,
                expected_config,
                relay_id,
                origin_pubkey,
                origin_node,
                hlc,
                bytes[pos..][0..wire_len],
                bytes[pos + wire_len ..],
                required_count,
                node_count,
                excluded_count,
            );
            pos += wire_len + (required_count + node_count + excluded_count) * @sizeOf(u64);
            for (out.rows.items) |existing| {
                if (existing.hlc == row.hlc and originEqual(existing.origin_pubkey, row.origin_pubkey)) {
                    var invalid = row;
                    invalid.deinit(allocator);
                    return error.DuplicateEntry;
                }
            }
            out.rows.appendAssumeCapacity(row);
        }
        try out.cursors.ensureTotalCapacity(allocator, meta.cursor_count);
        for (0..meta.cursor_count) |_| {
            const node = readU64(bytes[pos..][0..8]);
            pos += 8;
            const after_origin_pubkey: [message_relay_v2.pubkey_len]u8 = bytes[pos..][0..message_relay_v2.pubkey_len].*;
            pos += message_relay_v2.pubkey_len;
            if (!containsOrigin(out.rows.items, after_origin_pubkey))
                return error.CursorTargetMissing;
            out.cursors.appendAssumeCapacity(.{ .node = node, .after_origin_pubkey = after_origin_pubkey });
        }
        out.aggregate_bytes = meta.aggregate_bytes;
        out.checkpoint_body_bytes = meta.body_len;
        if (recomputeAggregateBytes(out.rows.items, out.cursors.items) != out.aggregate_bytes or
            recomputeBodyBytes(out.rows.items, out.cursors.items) != out.checkpoint_body_bytes)
            return error.CounterMismatch;
        return out;
    }
};

pub const CheckpointMeta = struct {
    config: Config,
    row_count: usize,
    cursor_count: usize,
    body_len: usize,
    aggregate_bytes: usize,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

/// Allocation-free structural validation. Cryptographic wire and derived-id
/// validation is completed by `EventLog.decodeCheckpoint` before publication.
pub fn validateCheckpoint(bytes: []const u8) Error!CheckpointMeta {
    if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (bytes[5] != 0) return error.UnknownFlags;
    const config = Config{
        .max_rows = readU32(bytes[6..10]),
        .max_confirmed_nodes_per_row = readU32(bytes[10..14]),
        .max_wire_bytes = readU32(bytes[14..18]),
        .max_aggregate_bytes = std.math.cast(usize, readU64(bytes[18..26])) orelse
            return error.InvalidConfig,
        .max_cursor_nodes = readU32(bytes[26..30]),
    };
    if (!config.valid()) return error.InvalidConfig;
    const row_count: usize = readU32(bytes[30..34]);
    const cursor_count: usize = readU32(bytes[34..38]);
    const body_len = std.math.cast(usize, readU64(bytes[38..46])) orelse
        return error.CheckpointTooLarge;
    if (row_count > config.max_rows) return error.CapacityExceeded;
    if (cursor_count > config.max_cursor_nodes) return error.CapacityExceeded;
    if (row_count == 0 and cursor_count != 0) return error.InvalidState;
    const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
        return error.CheckpointTooLarge;
    const total_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < total_len) return error.Truncated;
    if (bytes.len > total_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos: usize = checkpoint_header_len;
    var previous_id: ?RelayId = null;
    var aggregate: usize = 0;
    for (0..row_count) |_| {
        if (pos > prefix_len or prefix_len - pos < row_prefix_len) return error.Truncated;
        const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
        pos += @sizeOf(RelayId);
        if (previous_id) |previous| {
            if (idsEqual(previous, relay_id)) return error.DuplicateEntry;
            if (!idLess(previous, relay_id)) return error.NonCanonicalOrder;
        }
        previous_id = relay_id;
        pos += message_relay_v2.pubkey_len;
        const origin_node = readU64(bytes[pos..][0..8]);
        pos += 8;
        if (origin_node == 0) return error.InvalidNode;
        pos += 8; // HLC; canonical MESSAGE_V2 semantics are checked on decode.
        const wire_len: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const node_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const required_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const excluded_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        if (wire_len == 0 or wire_len > config.max_wire_bytes) return error.InvalidWire;
        if (required_count == 0 or required_count > config.max_confirmed_nodes_per_row or
            node_count > required_count or excluded_count > config.max_confirmed_nodes_per_row)
            return error.CapacityExceeded;
        const total_node_count = std.math.add(usize, required_count, node_count) catch
            return error.CheckpointTooLarge;
        const all_node_count = std.math.add(usize, total_node_count, excluded_count) catch
            return error.CheckpointTooLarge;
        const nodes_bytes = std.math.mul(usize, all_node_count, @sizeOf(u64)) catch
            return error.CheckpointTooLarge;
        const row_bytes = std.math.add(usize, wire_len, nodes_bytes) catch
            return error.CheckpointTooLarge;
        if (pos > prefix_len or row_bytes > prefix_len - pos) return error.Truncated;
        aggregate = std.math.add(usize, aggregate, row_bytes) catch
            return error.CheckpointTooLarge;
        if (aggregate > config.max_aggregate_bytes) return error.CapacityExceeded;
        pos += wire_len;
        const required_bytes = bytes[pos..][0 .. required_count * @sizeOf(u64)];
        pos += required_bytes.len;
        const confirmed_bytes = bytes[pos..][0 .. node_count * @sizeOf(u64)];
        pos += confirmed_bytes.len;
        const excluded_bytes = bytes[pos..][0 .. excluded_count * @sizeOf(u64)];
        pos += excluded_bytes.len;
        try validateEncodedNodeOrder(required_bytes, required_count);
        try validateEncodedNodeOrder(confirmed_bytes, node_count);
        try validateEncodedNodeOrder(excluded_bytes, excluded_count);
        if (!encodedSubset(confirmed_bytes, node_count, required_bytes, required_count) or
            !encodedSubset(excluded_bytes, excluded_count, required_bytes, required_count) or
            !encodedDisjoint(confirmed_bytes, node_count, excluded_bytes, excluded_count))
            return error.InvalidMembership;
        if (node_count == required_count) return error.InvalidState;
    }
    var previous_cursor_node: ?u64 = null;
    for (0..cursor_count) |_| {
        if (pos > prefix_len or prefix_len - pos < cursor_entry_len) return error.Truncated;
        const node = readU64(bytes[pos..][0..8]);
        pos += 8;
        pos += message_relay_v2.pubkey_len;
        if (node == 0) return error.InvalidNode;
        if (previous_cursor_node) |previous| {
            if (node == previous) return error.DuplicateNode;
            if (node < previous) return error.NonCanonicalOrder;
        }
        previous_cursor_node = node;
        aggregate = std.math.add(usize, aggregate, cursor_entry_len) catch
            return error.CheckpointTooLarge;
        if (aggregate > config.max_aggregate_bytes) return error.CapacityExceeded;
    }
    if (pos < prefix_len) return error.TrailingBytes;
    if (pos > prefix_len) return error.Truncated;
    return .{
        .config = config,
        .row_count = row_count,
        .cursor_count = cursor_count,
        .body_len = body_len,
        .aggregate_bytes = aggregate,
    };
}

fn decodeRow(
    allocator: std.mem.Allocator,
    config: Config,
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire_bytes: []const u8,
    node_bytes: []const u8,
    required_count: usize,
    node_count: usize,
    excluded_count: usize,
) Error!Row {
    const wire_meta = try validateWireAndId(allocator, config, relay_id, wire_bytes);
    if (!originEqual(origin_pubkey, wire_meta.origin_pubkey) or
        origin_node != wire_meta.origin_node or hlc != wire_meta.hlc)
        return error.InvalidWire;
    var row = Row{
        .relay_id = relay_id,
        .origin_pubkey = origin_pubkey,
        .origin_node = origin_node,
        .hlc = hlc,
        .wire = try allocator.dupe(u8, wire_bytes),
    };
    errdefer row.deinit(allocator);
    var offset: usize = 0;
    try row.required_nodes.ensureTotalCapacity(allocator, required_count);
    for (0..required_count) |_| {
        row.required_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    try row.confirmed_nodes.ensureTotalCapacity(allocator, node_count);
    for (0..node_count) |_| {
        row.confirmed_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    try row.excluded_once_nodes.ensureTotalCapacity(allocator, excluded_count);
    for (0..excluded_count) |_| {
        row.excluded_once_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    return row;
}

const WireMeta = struct {
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
};

fn validateWireAndId(
    allocator: std.mem.Allocator,
    config: Config,
    expected_id: RelayId,
    wire: []const u8,
) Error!WireMeta {
    if (wire.len == 0 or wire.len > config.max_wire_bytes) return error.InvalidWire;
    var owned = message_relay_v2.decode(allocator, wire) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer owned.deinit(allocator);
    const derived = switch (try message_relay_v2.verifyAndRelayId(allocator, owned.msg)) {
        .verified => |id| id,
        else => return error.InvalidWire,
    };
    if (!idsEqual(derived, expected_id)) return error.RelayIdMismatch;
    const canonical = message_relay_v2.encode(allocator, owned.msg) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, wire)) return error.InvalidWire;
    return .{
        .origin_pubkey = owned.msg.origin_pubkey[0..message_relay_v2.pubkey_len].*,
        .origin_node = owned.msg.origin_node,
        .hlc = owned.msg.hlc,
    };
}

fn validateNodeOrder(nodes: []const u64) Error!void {
    var previous: ?u64 = null;
    for (nodes) |node| {
        if (node == 0) return error.InvalidNode;
        if (previous) |prior| {
            if (node == prior) return error.DuplicateNode;
            if (node < prior) return error.NonCanonicalOrder;
        }
        previous = node;
    }
}

fn validateRequiredMembership(nodes: []const u64, accepting_node: u64, maximum: usize) Error!void {
    if (nodes.len < 2 or nodes.len > maximum) return error.InvalidMembership;
    try validateNodeOrder(nodes);
    if (!containsNode(nodes, accepting_node)) return error.InvalidMembership;
}

fn validateRowNodes(row: Row) Error!void {
    try validateNodeOrder(row.required_nodes.items);
    try validateNodeOrder(row.confirmed_nodes.items);
    try validateNodeOrder(row.excluded_once_nodes.items);
    for (row.confirmed_nodes.items) |node| {
        if (!containsNode(row.required_nodes.items, node) or
            containsNode(row.excluded_once_nodes.items, node))
            return error.InvalidMembership;
    }
    for (row.excluded_once_nodes.items) |node|
        if (!containsNode(row.required_nodes.items, node)) return error.InvalidMembership;
    if (rowCovered(row)) return error.InvalidState;
}

fn rowCovered(row: Row) bool {
    return row.confirmed_nodes.items.len == row.required_nodes.items.len;
}

fn coverageAfterConfirmation(row: Row, node: u64) bool {
    std.debug.assert(containsNode(row.required_nodes.items, node));
    std.debug.assert(!containsNode(row.confirmed_nodes.items, node));
    return row.confirmed_nodes.items.len + 1 == row.required_nodes.items.len;
}

fn rowAggregateBytes(row: Row) usize {
    return row.wire.len +
        (row.required_nodes.items.len + row.confirmed_nodes.items.len + row.excluded_once_nodes.items.len) * @sizeOf(u64);
}

fn rowBodyBytes(row: Row) usize {
    return row_prefix_len + rowAggregateBytes(row);
}

fn recomputeAggregateBytes(rows: []const Row, cursors: []const CursorEntry) usize {
    var total = cursors.len * cursor_entry_len;
    for (rows) |row| total += rowAggregateBytes(row);
    return total;
}

fn recomputeBodyBytes(rows: []const Row, cursors: []const CursorEntry) usize {
    var total = cursors.len * cursor_entry_len;
    for (rows) |row| total += rowBodyBytes(row);
    return total;
}

fn validateEncodedNodeOrder(bytes: []const u8, count: usize) Error!void {
    var previous: ?u64 = null;
    for (0..count) |index| {
        const node = readU64(bytes[index * 8 ..][0..8]);
        if (node == 0) return error.InvalidNode;
        if (previous) |prior| {
            if (node == prior) return error.DuplicateNode;
            if (node < prior) return error.NonCanonicalOrder;
        }
        previous = node;
    }
}

fn encodedSubset(
    subset: []const u8,
    subset_count: usize,
    superset: []const u8,
    superset_count: usize,
) bool {
    var sub_index: usize = 0;
    var super_index: usize = 0;
    while (sub_index < subset_count and super_index < superset_count) {
        const sub = readU64(subset[sub_index * 8 ..][0..8]);
        const super = readU64(superset[super_index * 8 ..][0..8]);
        if (super < sub) {
            super_index += 1;
        } else if (super == sub) {
            sub_index += 1;
            super_index += 1;
        } else return false;
    }
    return sub_index == subset_count;
}

fn encodedDisjoint(
    a: []const u8,
    a_count: usize,
    b: []const u8,
    b_count: usize,
) bool {
    var a_index: usize = 0;
    var b_index: usize = 0;
    while (a_index < a_count and b_index < b_count) {
        const av = readU64(a[a_index * 8 ..][0..8]);
        const bv = readU64(b[b_index * 8 ..][0..8]);
        if (av < bv) a_index += 1 else if (bv < av) b_index += 1 else return false;
    }
    return true;
}
