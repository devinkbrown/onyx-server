// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable rendered-record authority for physical reusable-session attachments.
//!
//! A mesh/message admission lane renders the exact IRC record for every physical
//! attachment (after capability/tag filtering) and reserves the whole recipient
//! batch here before publishing node acceptance or returning a mesh ACK.  A slow
//! connection therefore retains its own immutable record while healthy siblings
//! continue draining.  Records are removed only after the caller has accepted the
//! exact record into that attachment's connection SendQ; the SendQ is separately
//! carried by Helix.
//!
//! This type is intentionally lock-free.  The daemon must serialize reservation,
//! collection, SendQ acknowledgement, attachment transfer, and checkpoint capture
//! under the delivery-authority mutation lane.

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

pub const TransferError = std.mem.Allocator.Error || error{ Equivocation, PendingPhysicalCustody };

pub const BarrierError = std.mem.Allocator.Error || error{ CapacityExceeded, InvalidBarrier };

pub const AttachmentRemap = struct {
    old_client: ClientId,
    new_client: ClientId,
};

pub const RemapError = std.mem.Allocator.Error || error{
    PendingPhysicalCustody,
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
pub const OutputEncoding = enum { irc_record, plaintext, preframed_secure };

/// Owned output awaiting WS/TLS encoding. These entries share the ADS sequence
/// lane but are not ADS1 records and cannot be checkpointed as that old format.
pub const OutputRecord = struct {
    client: ClientId,
    bytes: []const u8,
    encoding: OutputEncoding = .plaintext,
};

pub const PendingRecord = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []const u8,
    encoding: OutputEncoding = .irc_record,
};

pub const TransferResult = struct {
    transferred: usize,
    exact_duplicates_merged: usize,
};

pub const DiscardResult = struct {
    discarded_records: usize,
    discarded_bytes: usize,
};

const Entry = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []u8,
    encoding: OutputEncoding = .irc_record,
};

const AttachmentTransferPlan = struct {
    client: ClientId,
    keep: bool = true,
};

/// Fully checked attachment transfer waiting to join the caller's larger
/// resume transaction. Preparation owns the only allocation and does not
/// mutate the spool. `commit` only frees merged duplicates and compacts the
/// existing list, so it is allocation-free and cannot fail. Logically
/// non-copyable: keep one mutable value and always install
/// `defer prepared.deinit()` immediately.
pub const PreparedAttachmentTransfer = struct {
    const State = enum { prepared, committed, aborted };

    spool: *Spool,
    plans: []AttachmentTransferPlan,
    result: TransferResult,
    final_total_bytes: usize,
    final_attachment_count: usize,
    reset_fair_cursor: bool,
    expected_len: usize,
    expected_total_bytes: usize,
    expected_attachment_count: usize,
    expected_next_sequence: u64,
    expected_fair_cursor: usize,
    state: State = .prepared,

    pub fn commit(self: *PreparedAttachmentTransfer) TransferResult {
        std.debug.assert(self.state == .prepared);
        // The integration lane must remain serialized from prepare through the
        // joint no-fail publication with the session registry.
        std.debug.assert(self.spool.entries.items.len == self.expected_len);
        std.debug.assert(self.spool.total_bytes == self.expected_total_bytes);
        std.debug.assert(self.spool.attachment_count == self.expected_attachment_count);
        std.debug.assert(self.spool.next_sequence == self.expected_next_sequence);
        std.debug.assert(self.spool.fair_cursor == self.expected_fair_cursor);
        std.debug.assert(self.plans.len == self.spool.entries.items.len);

        var write_index: usize = 0;
        for (self.spool.entries.items, self.plans) |entry, plan| {
            if (!plan.keep) {
                self.spool.allocator.free(entry.bytes);
                continue;
            }
            var retained = entry;
            retained.client = plan.client;
            self.spool.entries.items[write_index] = retained;
            write_index += 1;
        }
        self.spool.entries.items.len = write_index;
        self.spool.total_bytes = self.final_total_bytes;
        self.spool.attachment_count = self.final_attachment_count;
        if (self.reset_fair_cursor) self.spool.fair_cursor = 0;

        const result = self.result;
        self.spool.allocator.free(self.plans);
        self.state = .committed;
        return result;
    }

    pub fn abort(self: *PreparedAttachmentTransfer) void {
        if (self.state != .prepared) return;
        self.spool.allocator.free(self.plans);
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedAttachmentTransfer) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

/// Fully allocated delivery reservation waiting to join the caller's larger
/// replay/history/event-log transaction. Preparation never publishes authority;
/// `commit` is allocation-free and cannot fail. Logically non-copyable: keep one
/// mutable value and always install `defer prepared.deinit()` immediately.
pub const PreparedBatch = struct {
    const State = enum { prepared, committed, aborted };

    spool: *Spool,
    staged: []Entry,
    new_bytes: usize,
    new_attachments: usize,
    exact_duplicates: usize,
    expected_len: usize,
    expected_total_bytes: usize,
    expected_attachment_count: usize,
    expected_next_sequence: u64,
    state: State = .prepared,

    pub fn commit(self: *PreparedBatch) ReserveResult {
        std.debug.assert(self.state == .prepared);
        // The integration lane must remain serialized from prepare through the
        // joint no-fail publication with replay/history authorities.
        std.debug.assert(self.spool.entries.items.len == self.expected_len);
        std.debug.assert(self.spool.total_bytes == self.expected_total_bytes);
        std.debug.assert(self.spool.attachment_count == self.expected_attachment_count);
        std.debug.assert(self.spool.next_sequence == self.expected_next_sequence);
        for (self.staged) |entry| self.spool.entries.appendAssumeCapacity(entry);
        self.spool.total_bytes += self.new_bytes;
        self.spool.attachment_count += self.new_attachments;
        self.spool.next_sequence += @intCast(self.staged.len);
        const result = ReserveResult{
            .inserted = self.staged.len,
            .exact_duplicates = self.exact_duplicates,
        };
        self.spool.allocator.free(self.staged);
        self.state = .committed;
        return result;
    }

    pub fn abort(self: *PreparedBatch) void {
        if (self.state != .prepared) return;
        for (self.staged) |entry| self.spool.allocator.free(entry.bytes);
        self.spool.allocator.free(self.staged);
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedBatch) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

/// An owner-funded ordering gate, not a fake IRC record. Existing ADS sequences
/// precede its cutoff. Records admitted later remain owned here but cannot be
/// collected until that exact image owner releases the oldest gate.
const OutputBarrier = struct {
    owner: u64,
    cutoff: u64,
    next: ?*OutputBarrier = null,
    block: *OutputBarrierBlock,
};
const OutputBarrierLane = struct { first: *OutputBarrier, last: *OutputBarrier };
const OutputBarrierBlock = struct {
    nodes: []OutputBarrier,
    remaining: usize,
};

/// Caller holds the same serialized delivery cut from prepare through commit.
/// All node and lane capacity is paid before the image/recipient joint commit.
pub const PreparedOutputBarriers = struct {
    spool: *Spool,
    clients: []ClientId,
    block: ?*OutputBarrierBlock,
    expected_count: usize,
    expected_sequence: u64,
    expected_entries: usize,
    state: enum { prepared, committed, aborted } = .prepared,

    pub fn commit(self: *@This()) void {
        std.debug.assert(self.state == .prepared);
        const spool = self.spool;
        std.debug.assert(spool.output_barrier_count == self.expected_count and
            spool.next_sequence == self.expected_sequence and spool.entries.items.len == self.expected_entries);
        if (self.block) |block| for (self.clients, block.nodes) |client, *node| {
            if (spool.output_barriers.getPtr(client)) |lane| {
                lane.last.next = node;
                lane.last = node;
            } else spool.output_barriers.putAssumeCapacityNoClobber(client, .{ .first = node, .last = node });
        };
        spool.output_barrier_count += self.clients.len;
        spool.allocator.free(self.clients);
        self.clients = &.{};
        self.state = .committed;
    }

    pub fn abort(self: *@This()) void {
        if (self.state != .prepared) return;
        if (self.block) |block| {
            self.spool.allocator.free(block.nodes);
            self.spool.allocator.destroy(block);
        }
        self.spool.allocator.free(self.clients);
        self.clients = &.{};
        self.block = null;
        self.state = .aborted;
    }
    pub fn deinit(self: *@This()) void {
        self.abort();
        self.* = undefined;
    }
};

pub const Spool = struct {
    allocator: std.mem.Allocator,
    config: Config,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    output_barriers: std.AutoHashMapUnmanaged(ClientId, OutputBarrierLane) = .empty,
    output_barrier_count: usize = 0,
    total_bytes: usize = 0,
    /// Exact physical attachment cardinality. Mutations maintain this eagerly so
    /// admission never rescans the full record list merely to enforce the cap.
    attachment_count: usize = 0,
    /// Strictly greater than every published record sequence. Zero is invalid;
    /// exhaustion rejects a new batch before mutation.
    next_sequence: u64 = 1,
    /// Scheduling hint only. It is deliberately absent from the checkpoint.
    fair_cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Spool {
        try validateConfig(config);
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Spool) void {
        for (self.entries.items) |entry| self.allocator.free(entry.bytes);
        self.entries.deinit(self.allocator);
        var lanes = self.output_barriers.valueIterator();
        while (lanes.next()) |lane| {
            var node: ?*OutputBarrier = lane.first;
            while (node) |current| {
                node = current.next;
                self.retireBarrierNode(current);
            }
        }
        self.output_barriers.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn outputBarrierCount(self: *const Spool) usize {
        return self.output_barrier_count;
    }
    pub fn hasOutputBarrier(self: *const Spool, client: ClientId) bool {
        return self.output_barriers.contains(client);
    }

    pub fn prepareOutputBarriers(self: *Spool, owner: u64, clients: []const ClientId, max_barriers: usize) BarrierError!PreparedOutputBarriers {
        if (owner == 0) return error.InvalidBarrier;
        const count = std.math.add(usize, self.output_barrier_count, clients.len) catch return error.CapacityExceeded;
        if (count > max_barriers) return error.CapacityExceeded;
        const lane_capacity = std.math.cast(u32, clients.len) orelse return error.CapacityExceeded;
        for (clients, 0..) |client, i| {
            if (client == std.math.maxInt(u64)) return error.InvalidBarrier;
            for (clients[0..i]) |prior| if (prior == client) return error.InvalidBarrier;
            if (self.output_barriers.get(client)) |lane| {
                var node: ?*OutputBarrier = lane.first;
                while (node) |current| : (node = current.next) if (current.owner == owner) return error.InvalidBarrier;
            }
        }
        const owned = try self.allocator.dupe(ClientId, clients);
        errdefer self.allocator.free(owned);
        var block: ?*OutputBarrierBlock = null;
        if (clients.len != 0) {
            const allocated = try self.allocator.create(OutputBarrierBlock);
            errdefer self.allocator.destroy(allocated);
            allocated.* = .{ .nodes = try self.allocator.alloc(OutputBarrier, clients.len), .remaining = clients.len };
            errdefer self.allocator.free(allocated.nodes);
            for (allocated.nodes) |*node| node.* = .{ .owner = owner, .cutoff = self.next_sequence, .block = allocated };
            try self.output_barriers.ensureUnusedCapacity(self.allocator, lane_capacity);
            block = allocated;
        }
        return .{ .spool = self, .clients = owned, .block = block, .expected_count = self.output_barrier_count, .expected_sequence = self.next_sequence, .expected_entries = self.entries.items.len };
    }

    /// An image may append to SendQ only after the older ADS prefix and every
    /// earlier image for THIS exact physical generation has completed.
    pub fn outputBarrierReady(self: *const Spool, client: ClientId, owner: u64) bool {
        const lane = self.output_barriers.get(client) orelse return false;
        if (lane.first.owner != owner) return false;
        for (self.entries.items) |entry| if (entry.client == client and entry.sequence < lane.first.cutoff) return false;
        return true;
    }

    pub fn releaseOutputBarrier(self: *Spool, client: ClientId, owner: u64) bool {
        if (!self.outputBarrierReady(client, owner)) return false;
        const lane = self.output_barriers.getPtr(client).?;
        const node = lane.first;
        if (node.next) |next| lane.first = next else _ = self.output_barriers.remove(client);
        self.output_barrier_count -= 1;
        self.retireBarrierNode(node);
        return true;
    }

    fn retireBarrierNode(self: *Spool, node: *OutputBarrier) void {
        const block = node.block;
        std.debug.assert(block.remaining != 0);
        block.remaining -= 1;
        if (block.remaining == 0) {
            self.allocator.free(block.nodes);
            self.allocator.destroy(block);
        }
    }

    /// Exact physical close only, never a reusable-token logical transfer.
    pub fn discardOutputBarriers(self: *Spool, client: ClientId) usize {
        const lane = self.output_barriers.fetchRemove(client) orelse return 0;
        var count: usize = 0;
        var node: ?*OutputBarrier = lane.value.first;
        while (node) |current| {
            node = current.next;
            self.retireBarrierNode(current);
            count += 1;
        }
        self.output_barrier_count -= count;
        return count;
    }

    pub fn len(self: *const Spool) usize {
        return self.entries.items.len;
    }

    pub fn totalBytes(self: *const Spool) usize {
        return self.total_bytes;
    }

    pub fn contains(self: *const Spool, client: ClientId, event_id: EventId) bool {
        return self.indexOf(client, event_id) != null;
    }

    pub fn pendingCountFor(self: *const Spool, client: ClientId) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| if (entry.client == client) {
            count += 1;
        };
        return count;
    }

    pub fn attachmentCount(self: *const Spool) usize {
        return self.attachmentCountWithWork(null);
    }

    /// Collect each physical attachment with pending delivery exactly once, in
    /// first-record FIFO order. The caller receives all clients when `out` has
    /// at least `attachmentCount()` elements; a shorter output returns the
    /// stable prefix. This query allocates nothing and does not advance the
    /// delivery fairness cursor.
    pub fn collectAttachmentClients(self: *const Spool, out: []ClientId) []ClientId {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            var already_collected = false;
            for (out[0..count]) |client| {
                if (client == entry.client) {
                    already_collected = true;
                    break;
                }
            }
            if (already_collected) continue;
            if (count == out.len) break;
            out[count] = entry.client;
            count += 1;
        }
        std.debug.assert(count <= self.attachment_count);
        return out[0..count];
    }

    fn attachmentCountWithWork(self: *const Spool, work: ?*usize) usize {
        if (work) |steps| steps.* += 1;
        return self.attachment_count;
    }

    pub fn hasUncheckpointedOutput(self: *const Spool) bool {
        if (self.output_barrier_count != 0) return true;
        for (self.entries.items) |entry| if (entry.encoding != .irc_record) return true;
        return false;
    }

    /// Exact physical terminal retirement, never a queue reset or handoff.
    pub fn discardUncheckpointedOutput(self: *Spool, client: ClientId) usize {
        var retired: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (entry.client == client and entry.encoding != .irc_record) {
                self.removeAt(index);
                retired += 1;
            } else index += 1;
        }
        return retired;
    }

    pub fn hasPendingOutput(self: *const Spool, client: ClientId) bool {
        return self.hasClient(client);
    }

    /// Stage exact already-rendered output before any semantic/frontier commit.
    /// The input is plaintext (or explicitly WS-framed plaintext), never TLS
    /// ciphertext. Allocation/pressure refusal leaves every sequence unchanged.
    pub fn prepareOutputBatch(self: *Spool, batch: []const OutputRecord) ReserveError!PreparedBatch {
        var bytes: usize = 0;
        var attachments: usize = 0;
        for (batch, 0..) |record, index| {
            if (record.client == std.math.maxInt(ClientId) or record.bytes.len == 0 or record.encoding == .irc_record)
                return error.InvalidRecord;
            bytes = std.math.add(usize, bytes, record.bytes.len) catch return error.CapacityExceeded;
            if (!self.hasClient(record.client)) {
                var earlier = false;
                for (batch[0..index]) |prior| if (prior.client == record.client) {
                    earlier = true;
                    break;
                };
                if (!earlier) attachments += 1;
            }
        }
        if (self.entries.items.len > self.config.max_records or batch.len > self.config.max_records - self.entries.items.len or
            self.total_bytes > self.config.max_total_bytes or bytes > self.config.max_total_bytes - self.total_bytes or
            self.attachment_count > self.config.max_attachments or attachments > self.config.max_attachments - self.attachment_count or
            batch.len > std.math.maxInt(u64) - self.next_sequence) return error.CapacityExceeded;
        const staged = try self.allocator.alloc(Entry, batch.len);
        errdefer self.allocator.free(staged);
        var initialized: usize = 0;
        errdefer for (staged[0..initialized]) |entry| self.allocator.free(entry.bytes);
        for (batch, 0..) |record, index| {
            const sequence = self.next_sequence + @as(u64, @intCast(index));
            var number: [16]u8 = undefined;
            std.mem.writeInt(u64, number[0..8], record.client, .little);
            std.mem.writeInt(u64, number[8..16], sequence, .little);
            var hash = std.crypto.hash.Blake3.init(.{});
            hash.update("onyx-physical-output-chunk-v1\x00");
            hash.update(&number);
            var digest: [32]u8 = undefined;
            hash.final(&digest);
            const event = digest[0..16].*;
            if (self.indexOf(record.client, event) != null) return error.Equivocation;
            staged[index] = .{ .client = record.client, .sequence = sequence, .event_id = event, .bytes = try self.allocator.dupe(u8, record.bytes), .encoding = record.encoding };
            initialized += 1;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, batch.len);
        return .{
            .spool = self,
            .staged = staged,
            .new_bytes = bytes,
            .new_attachments = attachments,
            .exact_duplicates = 0,
            .expected_len = self.entries.items.len,
            .expected_total_bytes = self.total_bytes,
            .expected_attachment_count = self.attachment_count,
            .expected_next_sequence = self.next_sequence,
        };
    }

    /// Prepare an all-or-nothing batch without publishing it. The returned plan
    /// owns every rendered body and the live list capacity needed by `commit`.
    pub fn prepareBatch(self: *Spool, batch: []const BatchRecord) ReserveError!PreparedBatch {
        if (batch.len > self.config.max_records) return error.CapacityExceeded;

        var new_count: usize = 0;
        var new_bytes: usize = 0;
        var new_attachments: usize = 0;
        var duplicate_count: usize = 0;
        for (batch, 0..) |record, index| {
            if (!validRenderedRecord(record.bytes) or record.bytes.len > self.config.max_record_bytes)
                return error.InvalidRecord;

            if (self.indexOf(record.client, record.event_id)) |existing_index| {
                if (self.entries.items[existing_index].encoding != .irc_record or !std.mem.eql(u8, self.entries.items[existing_index].bytes, record.bytes))
                    return error.Equivocation;
                duplicate_count += 1;
                continue;
            }

            var prior_duplicate = false;
            for (batch[0..index]) |prior| {
                if (prior.client != record.client or
                    !std.mem.eql(u8, &prior.event_id, &record.event_id)) continue;
                if (!std.mem.eql(u8, prior.bytes, record.bytes)) return error.Equivocation;
                prior_duplicate = true;
                break;
            }
            if (prior_duplicate) {
                duplicate_count += 1;
                continue;
            }
            new_count += 1;
            new_bytes = std.math.add(usize, new_bytes, record.bytes.len) catch
                return error.CapacityExceeded;
            if (!self.hasClient(record.client)) {
                var prior_new_client = false;
                for (batch[0..index]) |prior| if (prior.client == record.client) {
                    prior_new_client = true;
                    break;
                };
                if (!prior_new_client) new_attachments += 1;
            }
        }

        if (new_count > self.config.max_records - self.entries.items.len)
            return error.CapacityExceeded;
        if (new_attachments > self.config.max_attachments - self.attachment_count)
            return error.CapacityExceeded;
        if (new_bytes > self.config.max_total_bytes - self.total_bytes)
            return error.CapacityExceeded;
        if (new_count > std.math.maxInt(u64) - self.next_sequence)
            return error.CapacityExceeded;
        const staged = try self.allocator.alloc(Entry, new_count);
        errdefer self.allocator.free(staged);
        var staged_len: usize = 0;
        errdefer for (staged[0..staged_len]) |entry| self.allocator.free(entry.bytes);

        for (batch, 0..) |record, index| {
            if (self.indexOf(record.client, record.event_id) != null) continue;
            var prior_duplicate = false;
            for (batch[0..index]) |prior| {
                if (prior.client == record.client and
                    std.mem.eql(u8, &prior.event_id, &record.event_id))
                {
                    prior_duplicate = true;
                    break;
                }
            }
            if (prior_duplicate) continue;
            staged[staged_len] = .{
                .client = record.client,
                .sequence = self.next_sequence + @as(u64, @intCast(staged_len)),
                .event_id = record.event_id,
                .bytes = try self.allocator.dupe(u8, record.bytes),
            };
            staged_len += 1;
        }
        std.debug.assert(staged_len == new_count);

        // This is the last fallible operation. Every owned body already exists,
        // so a later commit publishes the complete batch with no failure point.
        try self.entries.ensureUnusedCapacity(self.allocator, staged_len);
        return .{
            .spool = self,
            .staged = staged,
            .new_bytes = new_bytes,
            .new_attachments = new_attachments,
            .exact_duplicates = duplicate_count,
            .expected_len = self.entries.items.len,
            .expected_total_bytes = self.total_bytes,
            .expected_attachment_count = self.attachment_count,
            .expected_next_sequence = self.next_sequence,
        };
    }

    /// Convenience transaction when this spool is the only authority involved.
    /// Mesh/server integration should instead prepare, stage its replay/history
    /// candidates, and call `PreparedBatch.commit` in the joint no-fail section.
    pub fn reserveBatch(self: *Spool, batch: []const BatchRecord) ReserveError!ReserveResult {
        var prepared = try self.prepareBatch(batch);
        defer prepared.deinit();
        return prepared.commit();
    }

    /// Same all-or-nothing admission as `prepareBatch`, without copying bodies.
    /// Inserted buffers become spool property. A failure adopts nothing.
    pub fn prepareOwnedBatch(self: *Spool, batch: []OwnedBatchRecord) ReserveError!PreparedBatch {
        if (batch.len > self.config.max_records) return error.CapacityExceeded;

        const kind = try self.allocator.alloc(u8, batch.len);
        defer self.allocator.free(kind);

        var new_count: usize = 0;
        var new_bytes: usize = 0;
        var new_attachments: usize = 0;
        var duplicate_count: usize = 0;
        for (batch, 0..) |record, index| {
            switch (try self.ownedDisposition(batch, index)) {
                .duplicate => {
                    kind[index] = 0;
                    duplicate_count += 1;
                },
                .insert => {
                    kind[index] = 1;
                    new_count += 1;
                    new_bytes = std.math.add(usize, new_bytes, record.bytes.len) catch
                        return error.CapacityExceeded;
                    if (!self.hasClient(record.client)) {
                        var prior_new_client = false;
                        for (batch[0..index]) |prior| {
                            if (prior.client == record.client) {
                                prior_new_client = true;
                                break;
                            }
                        }
                        if (!prior_new_client) new_attachments += 1;
                    }
                },
            }
        }

        if (new_count > self.config.max_records - self.entries.items.len)
            return error.CapacityExceeded;
        if (new_attachments > self.config.max_attachments - self.attachment_count)
            return error.CapacityExceeded;
        if (new_bytes > self.config.max_total_bytes - self.total_bytes)
            return error.CapacityExceeded;
        if (new_count > std.math.maxInt(u64) - self.next_sequence)
            return error.CapacityExceeded;

        const staged = try self.allocator.alloc(Entry, new_count);
        errdefer self.allocator.free(staged);
        try self.entries.ensureUnusedCapacity(self.allocator, staged.len);

        var staged_len: usize = 0;
        for (batch, kind) |*record, flag| {
            if (flag == 0) continue;
            staged[staged_len] = .{
                .client = record.client,
                .sequence = self.next_sequence + @as(u64, @intCast(staged_len)),
                .event_id = record.event_id,
                .bytes = record.bytes,
            };
            record.bytes = &.{};
            staged_len += 1;
        }
        std.debug.assert(staged_len == new_count);

        return .{
            .spool = self,
            .staged = staged,
            .new_bytes = new_bytes,
            .new_attachments = new_attachments,
            .exact_duplicates = duplicate_count,
            .expected_len = self.entries.items.len,
            .expected_total_bytes = self.total_bytes,
            .expected_attachment_count = self.attachment_count,
            .expected_next_sequence = self.next_sequence,
        };
    }

    /// Adopt `batch` in one transaction. See `prepareOwnedBatch` for ownership.
    pub fn reserveOwnedBatch(self: *Spool, batch: []OwnedBatchRecord) ReserveError!ReserveResult {
        var prepared = try self.prepareOwnedBatch(batch);
        defer prepared.deinit();
        return prepared.commit();
    }

    const OwnedDisposition = enum { insert, duplicate };

    fn ownedDisposition(self: *const Spool, batch: []const OwnedBatchRecord, index: usize) ReserveError!OwnedDisposition {
        const record = batch[index];
        if (!validRenderedRecord(record.bytes) or record.bytes.len > self.config.max_record_bytes)
            return error.InvalidRecord;
        if (self.indexOf(record.client, record.event_id)) |existing| {
            if (!std.mem.eql(u8, self.entries.items[existing].bytes, record.bytes))
                return error.Equivocation;
            return .duplicate;
        }
        for (batch[0..index]) |prior| {
            if (prior.client != record.client or !std.mem.eql(u8, &prior.event_id, &record.event_id)) continue;
            if (!std.mem.eql(u8, prior.bytes, record.bytes)) return error.Equivocation;
            return .duplicate;
        }
        return .insert;
    }

    /// Return at most one oldest record per physical client, starting after the
    /// previous collection point. This prevents one slow attachment's backlog
    /// from consuming the whole drain budget while preserving strict per-client
    /// record order. Returned byte slices are borrowed until the next mutation.
    pub fn collectPending(self: *Spool, out: []PendingRecord) []PendingRecord {
        if (out.len == 0 or self.entries.items.len == 0) return out[0..0];
        const total = self.entries.items.len;
        var index = self.fair_cursor % total;
        var scanned: usize = 0;
        var emitted: usize = 0;
        while (scanned < total and emitted < out.len) {
            const current = index;
            index = (index + 1) % total;
            scanned += 1;
            if (!self.isOldestForClient(current)) continue;
            const entry = self.entries.items[current];
            if (self.output_barriers.get(entry.client)) |lane| if (entry.sequence >= lane.first.cutoff) continue;
            var client_already_emitted = false;
            for (out[0..emitted]) |prior| if (prior.client == entry.client) {
                client_already_emitted = true;
                break;
            };
            if (client_already_emitted) continue;
            out[emitted] = .{
                .client = entry.client,
                .sequence = entry.sequence,
                .event_id = entry.event_id,
                .bytes = entry.bytes,
                .encoding = entry.encoding,
            };
            emitted += 1;
        }
        self.fair_cursor = index;
        return out[0..emitted];
    }

    /// Retire one exact record only after the caller accepted that same borrowed
    /// record into the exact client's SendQ. Wrong-client/stale acknowledgements
    /// are harmless and cannot retire another attachment's copy.
    pub fn commitHeadToSendq(
        self: *Spool,
        client: ClientId,
        sequence: u64,
        event_id: EventId,
    ) bool {
        const index = self.indexOf(client, event_id) orelse return false;
        if (self.output_barriers.get(client)) |lane| if (self.entries.items[index].sequence >= lane.first.cutoff) return false;
        if (!self.isOldestForClient(index) or self.entries.items[index].sequence != sequence)
            return false;
        self.removeAt(index);
        return true;
    }

    /// Retire one caller-owned obligation at an explicit terminal boundary.
    /// Unrelated records for this attachment retain FIFO order and custody.
    /// The caller proves event ownership; this is not a SendQ acknowledgement.
    pub fn discardRecord(self: *Spool, client: ClientId, event_id: EventId) bool {
        const index = self.indexOf(client, event_id) orelse return false;
        self.removeAt(index);
        return true;
    }

    /// Allocation-free retirement for an attachment whose exact session is being
    /// intentionally destroyed. This never transfers rendered rows across token
    /// authorities; it frees every matching body and compacts unrelated FIFO rows
    /// in place. The operation cannot fail.
    pub fn discardAttachment(self: *Spool, client: ClientId) DiscardResult {
        _ = self.discardOutputBarriers(client);
        var write_index: usize = 0;
        var discarded_records: usize = 0;
        var discarded_bytes: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.client == client) {
                discarded_records += 1;
                discarded_bytes += entry.bytes.len;
                self.allocator.free(entry.bytes);
                continue;
            }
            self.entries.items[write_index] = entry;
            write_index += 1;
        }
        if (discarded_records == 0) return .{
            .discarded_records = 0,
            .discarded_bytes = 0,
        };
        self.entries.items.len = write_index;
        self.total_bytes -= discarded_bytes;
        self.attachment_count -= 1;
        self.fair_cursor = 0;
        return .{
            .discarded_records = discarded_records,
            .discarded_bytes = discarded_bytes,
        };
    }

    /// Same intentional attachment retirement, preserving records owned by a
    /// different typed custody domain. Caller holds the spool mutation lane.
    pub fn discardAttachmentExcept(self: *Spool, client: ClientId, context: anytype, comptime preserve: anytype) DiscardResult {
        var written: usize = 0;
        var records: usize = 0;
        var bytes: usize = 0;
        var client_remains = false;
        for (self.entries.items) |entry| {
            if (entry.client == client and entry.encoding == .irc_record and !preserve(context, client, entry.event_id)) {
                records += 1;
                bytes += entry.bytes.len;
                self.allocator.free(entry.bytes);
                continue;
            }
            if (entry.client == client) client_remains = true;
            self.entries.items[written] = entry;
            written += 1;
        }
        if (records != 0) {
            self.entries.items.len = written;
            self.total_bytes -= bytes;
            if (!client_remains) self.attachment_count -= 1;
            self.fair_cursor = 0;
        }
        return .{ .discarded_records = records, .discarded_bytes = bytes };
    }

    /// Prepare an exact old-to-new attachment transfer without publishing any
    /// change. Equal destination rows are preplanned as one retained earlier
    /// event; differing bytes reject the entire plan. The returned ticket owns
    /// all memory required by its allocation-free/no-fail commit.
    pub fn prepareAttachmentTransfer(
        self: *Spool,
        old_client: ClientId,
        new_client: ClientId,
    ) TransferError!PreparedAttachmentTransfer {
        if (self.hasOutputBarrier(old_client) or self.hasOutputBarrier(new_client)) return error.PendingPhysicalCustody;
        for (self.entries.items) |entry| if ((entry.client == old_client or entry.client == new_client) and entry.encoding != .irc_record)
            return error.PendingPhysicalCustody;
        const plans = try self.allocator.alloc(AttachmentTransferPlan, self.entries.items.len);
        errdefer self.allocator.free(plans);
        for (self.entries.items, plans) |entry, *plan| plan.* = .{ .client = entry.client };

        const old_exists = self.hasClient(old_client);
        const new_exists = self.hasClient(new_client);
        var transferred: usize = 0;
        var merged: usize = 0;
        var discarded_bytes: usize = 0;

        if (old_client != new_client) {
            for (self.entries.items, 0..) |old, index| {
                if (old.client != old_client) continue;
                transferred += 1;
                const destination_index = self.indexOf(new_client, old.event_id) orelse {
                    plans[index].client = new_client;
                    continue;
                };
                const destination = self.entries.items[destination_index];
                if (!std.mem.eql(u8, old.bytes, destination.bytes)) return error.Equivocation;

                merged += 1;
                if (destination_index < index) {
                    plans[index].keep = false;
                    discarded_bytes += old.bytes.len;
                } else {
                    plans[destination_index].keep = false;
                    discarded_bytes += destination.bytes.len;
                    plans[index].client = new_client;
                }
            }
        } else {
            transferred = self.pendingCountFor(old_client);
        }

        return .{
            .spool = self,
            .plans = plans,
            .result = .{
                .transferred = transferred,
                .exact_duplicates_merged = merged,
            },
            .final_total_bytes = self.total_bytes - discarded_bytes,
            .final_attachment_count = self.attachment_count -
                @as(usize, @intFromBool(old_client != new_client and old_exists and new_exists)),
            .reset_fair_cursor = old_client != new_client,
            .expected_len = self.entries.items.len,
            .expected_total_bytes = self.total_bytes,
            .expected_attachment_count = self.attachment_count,
            .expected_next_sequence = self.next_sequence,
            .expected_fair_cursor = self.fair_cursor,
        };
    }

    /// Convenience transaction when this spool is the only authority involved.
    /// Resume integration should instead hold its external mutation lock from
    /// `prepareAttachmentTransfer` through the joint session/spool commit.
    pub fn transferAttachment(
        self: *Spool,
        old_client: ClientId,
        new_client: ClientId,
    ) TransferError!TransferResult {
        var prepared = try self.prepareAttachmentTransfer(old_client, new_client);
        defer prepared.deinit();
        return prepared.commit();
    }

    /// Simultaneously replace every live attachment id through one complete
    /// old-to-new map. Mappings are interpreted against the pre-call state, so
    /// cycles never alias sequentially. Extra mappings are permitted, but every
    /// live client must have exactly one source row. Destination key collisions
    /// merge only when their rendered bytes are identical. All allocation and
    /// conflict checks finish before the no-fail mutation phase.
    pub fn remapAttachments(
        self: *Spool,
        mappings: []const AttachmentRemap,
    ) RemapError!RemapResult {
        if (self.hasUncheckpointedOutput()) return error.PendingPhysicalCustody;
        if (mappings.len > hard_max_attachments) return error.CapacityExceeded;
        if (mappings.len == 0) {
            if (self.entries.items.len != 0) return error.MissingMapping;
            return .{
                .records_remapped = 0,
                .exact_duplicates_merged = 0,
                .attachment_count = self.attachment_count,
            };
        }
        const sorted_mappings = try self.allocator.dupe(AttachmentRemap, mappings);
        defer self.allocator.free(sorted_mappings);
        std.mem.sort(AttachmentRemap, sorted_mappings, {}, struct {
            fn lessThan(_: void, a: AttachmentRemap, b: AttachmentRemap) bool {
                if (a.old_client != b.old_client) return a.old_client < b.old_client;
                return a.new_client < b.new_client;
            }
        }.lessThan);
        for (sorted_mappings[1..], 1..) |mapping, index| {
            if (sorted_mappings[index - 1].old_client == mapping.old_client)
                return error.DuplicateSource;
        }
        if (self.entries.items.len == 0) return .{
            .records_remapped = 0,
            .exact_duplicates_merged = 0,
            .attachment_count = self.attachment_count,
        };

        const Plan = struct {
            new_client: ClientId,
            keep: bool = true,
        };
        const plans = try self.allocator.alloc(Plan, self.entries.items.len);
        defer self.allocator.free(plans);
        const order = try self.allocator.alloc(usize, self.entries.items.len);
        defer self.allocator.free(order);

        var records_remapped: usize = 0;
        for (self.entries.items, plans, order, 0..) |entry, *plan, *ordered_index, index| {
            const new_client = mappedClient(sorted_mappings, entry.client) orelse
                return error.MissingMapping;
            plan.* = .{ .new_client = new_client };
            ordered_index.* = index;
            records_remapped += @intFromBool(entry.client != new_client);
        }
        const SortContext = struct {
            entries: []const Entry,
            plans: []const Plan,

            fn lessThan(context: @This(), a_index: usize, b_index: usize) bool {
                const a = context.entries[a_index];
                const b = context.entries[b_index];
                const key_order = compareEntryKey(
                    context.plans[a_index].new_client,
                    a.event_id,
                    context.plans[b_index].new_client,
                    b.event_id,
                );
                if (key_order != .eq) return key_order == .lt;
                return a.sequence < b.sequence;
            }
        };
        std.mem.sort(
            usize,
            order,
            SortContext{ .entries = self.entries.items, .plans = plans },
            SortContext.lessThan,
        );

        var merged: usize = 0;
        for (order[1..], 1..) |index, ordered_pos| {
            const prior_index = order[ordered_pos - 1];
            const current = self.entries.items[index];
            const prior = self.entries.items[prior_index];
            if (compareEntryKey(
                plans[prior_index].new_client,
                prior.event_id,
                plans[index].new_client,
                current.event_id,
            ) != .eq) continue;
            if (!std.mem.eql(u8, prior.bytes, current.bytes)) return error.Equivocation;
            plans[index].keep = false;
            merged += 1;
        }

        var final_attachment_count: usize = 0;
        var previous_client: ClientId = 0;
        var have_previous_client = false;
        for (order) |index| {
            if (!plans[index].keep) continue;
            const client = plans[index].new_client;
            if (!have_previous_client or previous_client != client) {
                final_attachment_count += 1;
                previous_client = client;
                have_previous_client = true;
            }
        }
        std.debug.assert(final_attachment_count <= self.config.max_attachments);

        // No operation below this point can fail. Compacting in runtime sequence
        // order preserves the earliest equivalent row and every surviving FIFO.
        var write_index: usize = 0;
        var new_total_bytes = self.total_bytes;
        for (self.entries.items, plans) |entry, plan| {
            if (!plan.keep) {
                new_total_bytes -= entry.bytes.len;
                self.allocator.free(entry.bytes);
                continue;
            }
            var remapped = entry;
            remapped.client = plan.new_client;
            self.entries.items[write_index] = remapped;
            write_index += 1;
        }
        self.entries.items.len = write_index;
        self.total_bytes = new_total_bytes;
        self.attachment_count = final_attachment_count;
        self.fair_cursor = 0;
        return .{
            .records_remapped = records_remapped,
            .exact_duplicates_merged = merged,
            .attachment_count = final_attachment_count,
        };
    }

    pub fn encodeCheckpoint(self: *const Spool, allocator: std.mem.Allocator) CheckpointError![]u8 {
        if (self.output_barrier_count != 0) return error.InvalidState;
        for (self.entries.items) |entry| if (entry.encoding != .irc_record) return error.InvalidState;
        try validateConfig(self.config);
        if (self.entries.items.len > self.config.max_records or
            self.attachment_count > self.config.max_attachments or
            self.total_bytes > self.config.max_total_bytes or
            self.next_sequence == 0) return error.InvalidState;

        const order = try allocator.alloc(usize, self.entries.items.len);
        defer allocator.free(order);
        for (order, 0..) |*ordered_index, index| ordered_index.* = index;
        const SortContext = struct {
            entries: []const Entry,

            fn lessThan(context: @This(), a_index: usize, b_index: usize) bool {
                const a = context.entries[a_index];
                const b = context.entries[b_index];
                return compareEntryKey(a.client, a.event_id, b.client, b.event_id) == .lt;
            }
        };
        std.mem.sort(
            usize,
            order,
            SortContext{ .entries = self.entries.items },
            SortContext.lessThan,
        );

        var measured_bytes: usize = 0;
        var body_len: usize = 0;
        var previous_sequence: u64 = 0;
        for (self.entries.items) |entry| {
            if (!validRenderedRecord(entry.bytes) or entry.bytes.len > self.config.max_record_bytes)
                return error.InvalidState;
            if (entry.sequence == 0 or entry.sequence >= self.next_sequence or
                entry.sequence <= previous_sequence) return error.InvalidState;
            previous_sequence = entry.sequence;
            measured_bytes = std.math.add(usize, measured_bytes, entry.bytes.len) catch
                return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, entry_prefix_len + entry.bytes.len) catch
                return error.CheckpointTooLarge;
        }
        if (measured_bytes != self.total_bytes) return error.InvalidState;
        var measured_attachments: usize = 0;
        for (order, 0..) |entry_index, ordered_pos| {
            const entry = self.entries.items[entry_index];
            if (ordered_pos != 0) {
                const prior = self.entries.items[order[ordered_pos - 1]];
                const key_order = compareEntryKey(
                    prior.client,
                    prior.event_id,
                    entry.client,
                    entry.event_id,
                );
                if (key_order != .lt) return error.InvalidState;
                if (prior.client == entry.client) continue;
            }
            measured_attachments += 1;
        }
        if (measured_attachments != self.attachment_count) return error.InvalidState;
        const prefix_len = std.math.add(usize, header_len, body_len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..checkpoint_magic.len], &checkpoint_magic);
        out[4] = checkpoint_version;
        out[5] = 0;
        writeU32(out[6..10], @intCast(self.config.max_attachments));
        writeU32(out[10..14], @intCast(self.config.max_records));
        writeU64(out[14..22], @intCast(self.config.max_total_bytes));
        writeU32(out[22..26], @intCast(self.config.max_record_bytes));
        writeU32(out[26..30], @intCast(self.entries.items.len));
        writeU64(out[30..38], @intCast(body_len));
        // Checkpoints normalize incarnation-local opaque sequences into a bounded
        // FIFO rank. This makes the rank set strictly and allocation-freely
        // verifiable while decode reconstructs the exact pending runtime order.
        writeU64(out[38..46], @as(u64, @intCast(self.entries.items.len)) + 1);
        var pos: usize = header_len;
        for (order) |entry_index| {
            const entry = self.entries.items[entry_index];
            writeU64(out[pos..][0..8], entry.client);
            pos += 8;
            writeU64(out[pos..][0..8], @as(u64, @intCast(entry_index)) + 1);
            pos += 8;
            @memcpy(out[pos..][0..event_id_len], &entry.event_id);
            pos += event_id_len;
            writeU32(out[pos..][0..4], @intCast(entry.bytes.len));
            pos += 4;
            @memcpy(out[pos..][0..entry.bytes.len], entry.bytes);
            pos += entry.bytes.len;
        }
        std.debug.assert(pos == prefix_len);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Spool {
        try validateConfig(expected_config);
        const meta = try validateCheckpoint(bytes);
        if (!configsEqual(meta.config, expected_config)) return error.ConfigMismatch;

        var out = try Spool.init(allocator, expected_config);
        errdefer out.deinit();
        try out.entries.ensureTotalCapacity(allocator, meta.count);
        out.next_sequence = meta.next_sequence;
        out.attachment_count = meta.attachment_count;
        var pos: usize = header_len;
        for (0..meta.count) |_| {
            const view = try parseEntry(bytes, &pos, expected_config.max_record_bytes);
            out.entries.appendAssumeCapacity(.{
                .client = view.client,
                .sequence = view.sequence,
                .event_id = view.event_id,
                .bytes = try allocator.dupe(u8, view.bytes),
            });
            out.total_bytes += view.bytes.len;
        }
        std.debug.assert(pos == header_len + meta.body_len);
        std.mem.sort(Entry, out.entries.items, {}, struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                return a.sequence < b.sequence;
            }
        }.lessThan);
        for (out.entries.items, 0..) |entry, index| {
            if (entry.sequence != @as(u64, @intCast(index)) + 1)
                return error.InvalidField;
        }
        return out;
    }

    /// Failure-atomic live restore. Corruption, config mismatch, capacity, and
    /// OOM leave the current authority untouched.
    pub fn replaceFromCheckpoint(self: *Spool, bytes: []const u8) CheckpointError!void {
        var replacement = try Spool.decodeCheckpoint(self.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }

    fn indexOf(self: *const Spool, client: ClientId, event_id: EventId) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.client == client and std.mem.eql(u8, &entry.event_id, &event_id))
                return index;
        }
        return null;
    }

    fn hasClient(self: *const Spool, client: ClientId) bool {
        for (self.entries.items) |entry| if (entry.client == client) return true;
        return false;
    }

    fn isOldestForClient(self: *const Spool, index: usize) bool {
        const client = self.entries.items[index].client;
        for (self.entries.items[0..index]) |prior| if (prior.client == client) return false;
        return true;
    }

    fn removeAt(self: *Spool, index: usize) void {
        const removes_attachment = self.pendingCountFor(self.entries.items[index].client) == 1;
        const removed = self.entries.orderedRemove(index);
        self.total_bytes -= removed.bytes.len;
        self.attachment_count -= @intFromBool(removes_attachment);
        self.allocator.free(removed.bytes);
        if (self.entries.items.len == 0) {
            self.fair_cursor = 0;
        } else {
            if (self.fair_cursor > index) self.fair_cursor -= 1;
            if (self.fair_cursor >= self.entries.items.len) self.fair_cursor = 0;
        }
    }
};

pub const CheckpointMeta = struct {
    config: Config,
    count: usize,
    attachment_count: usize,
    body_len: usize,
    total_record_bytes: usize,
    next_sequence: u64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and
        std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Allocation-free strict whole-image validation used by Helix relation checks.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!CheckpointMeta {
    return validateCheckpointImpl(bytes, null);
}

fn validateCheckpointImpl(
    bytes: []const u8,
    validation_steps: ?*usize,
) CheckpointError!CheckpointMeta {
    if (validation_steps) |steps| steps.* = 0;
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (bytes[5] != 0) return error.InvalidField;
    const config = Config{
        .max_attachments = readU32(bytes[6..10]),
        .max_records = readU32(bytes[10..14]),
        .max_total_bytes = readU64(bytes[14..22]),
        .max_record_bytes = readU32(bytes[22..26]),
    };
    try validateConfig(config);
    const count: usize = readU32(bytes[26..30]);
    const body_len: usize = std.math.cast(usize, readU64(bytes[30..38])) orelse
        return error.CheckpointTooLarge;
    const next_sequence = readU64(bytes[38..46]);
    if (count > config.max_records) return error.CapacityExceeded;
    if (next_sequence != @as(u64, @intCast(count)) + 1) return error.InvalidField;
    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos: usize = header_len;
    var total_record_bytes: usize = 0;
    var attachment_count: usize = 0;
    var previous_client: ClientId = 0;
    var previous_event_id: EventId = @splat(0);
    var have_previous = false;
    var rank_bitmap: [hard_max_records / 8]u8 = @splat(0);
    for (0..count) |_| {
        if (validation_steps) |steps| steps.* += 1;
        const current = try parseEntry(bytes, &pos, config.max_record_bytes);
        total_record_bytes = std.math.add(usize, total_record_bytes, current.bytes.len) catch
            return error.CapacityExceeded;
        if (total_record_bytes > config.max_total_bytes) return error.CapacityExceeded;
        if (current.sequence == 0 or current.sequence > count) return error.InvalidField;
        const rank_index: usize = @intCast(current.sequence - 1);
        const rank_mask: u8 = @as(u8, 1) << @intCast(rank_index & 7);
        if (rank_bitmap[rank_index / 8] & rank_mask != 0) return error.InvalidField;
        rank_bitmap[rank_index / 8] |= rank_mask;

        if (have_previous) {
            switch (compareEntryKey(
                previous_client,
                previous_event_id,
                current.client,
                current.event_id,
            )) {
                .eq => return error.DuplicateEntry,
                .gt => return error.NonCanonicalOrder,
                .lt => {},
            }
        }
        if (!have_previous or previous_client != current.client) {
            attachment_count += 1;
            if (attachment_count > config.max_attachments) return error.CapacityExceeded;
        }
        previous_client = current.client;
        previous_event_id = current.event_id;
        have_previous = true;
    }
    if (pos < prefix_len) return error.InvalidField;
    if (pos > prefix_len) return error.Truncated;
    return .{
        .config = config,
        .count = count,
        .attachment_count = attachment_count,
        .body_len = body_len,
        .total_record_bytes = total_record_bytes,
        .next_sequence = next_sequence,
    };
}

const EntryView = struct {
    client: ClientId,
    sequence: u64,
    event_id: EventId,
    bytes: []const u8,
};

fn parseEntry(bytes: []const u8, pos: *usize, max_record_bytes: usize) CheckpointError!EntryView {
    const payload_end = bytes.len - checksum_len;
    if (pos.* > payload_end or payload_end - pos.* < entry_prefix_len) return error.Truncated;
    const client = readU64(bytes[pos.*..][0..8]);
    pos.* += 8;
    const sequence = readU64(bytes[pos.*..][0..8]);
    pos.* += 8;
    const event_id: EventId = bytes[pos.*..][0..event_id_len].*;
    pos.* += event_id_len;
    const record_len: usize = readU32(bytes[pos.*..][0..4]);
    pos.* += 4;
    if (record_len > max_record_bytes) return error.CapacityExceeded;
    if (record_len > payload_end - pos.*) return error.Truncated;
    const record = bytes[pos.*..][0..record_len];
    pos.* += record_len;
    if (!validRenderedRecord(record)) return error.InvalidRecord;
    return .{ .client = client, .sequence = sequence, .event_id = event_id, .bytes = record };
}

fn compareEntryKey(
    a_client: ClientId,
    a_event_id: EventId,
    b_client: ClientId,
    b_event_id: EventId,
) std.math.Order {
    if (a_client < b_client) return .lt;
    if (a_client > b_client) return .gt;
    return std.mem.order(u8, &a_event_id, &b_event_id);
}

fn mappedClient(mappings: []const AttachmentRemap, old_client: ClientId) ?ClientId {
    var low: usize = 0;
    var high = mappings.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (mappings[middle].old_client < old_client) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low == mappings.len or mappings[low].old_client != old_client) return null;
    return mappings[low].new_client;
}

fn validateConfig(config: Config) InitError!void {
    if (config.max_attachments == 0 or config.max_attachments > hard_max_attachments or
        config.max_records == 0 or config.max_records > hard_max_records or
        config.max_attachments > config.max_records or
        config.max_total_bytes == 0 or config.max_total_bytes > hard_max_total_bytes or
        config.max_record_bytes == 0 or config.max_record_bytes > hard_max_record_bytes or
        config.max_record_bytes > config.max_total_bytes) return error.InvalidConfig;
}

fn configsEqual(a: Config, b: Config) bool {
    return a.max_attachments == b.max_attachments and
        a.max_records == b.max_records and
        a.max_total_bytes == b.max_total_bytes and
        a.max_record_bytes == b.max_record_bytes;
}

fn validRenderedRecord(bytes: []const u8) bool {
    if (bytes.len < 2 or !std.mem.endsWith(u8, bytes, "\r\n")) return false;
    for (bytes[0 .. bytes.len - 2]) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return false;
    }
    return true;
}

const checkpoint_magic = [_]u8{ 'A', 'D', 'S', '1' };
const checkpoint_version: u8 = 1;
const header_len: usize = 46;
const event_id_len: usize = @sizeOf(EventId);
const entry_prefix_len: usize = 8 + 8 + event_id_len + 4;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const checkpoint_checksum_domain = "onyx-attachment-delivery-spool-v1";

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(checkpoint_checksum_domain);
    hash.update(prefix);
    hash.final(out);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}

fn eventId(byte: u8) EventId {
    var id: EventId = @splat(0);
    id[id.len - 1] = byte;
    return id;
}

const testing = std.testing;

test "attachment delivery spool batch reservation is atomic under OOM and capacity" {
    const config = Config{ .max_attachments = 3, .max_records = 3, .max_total_bytes = 32, .max_record_bytes = 16 };
    const batch = [_]BatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "two\r\n" },
    };

    const OomSweep = struct {
        fn run(allocator: std.mem.Allocator, records: []const BatchRecord) !void {
            var spool = try Spool.init(allocator, config);
            defer spool.deinit();
            const result = try spool.reserveBatch(records);
            try testing.expectEqual(@as(usize, 2), result.inserted);
            try testing.expectEqual(@as(usize, 2), spool.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, OomSweep.run, .{batch[0..]});

    // Every individual preparation allocation failure leaves the live authority
    // byte-identical, not merely empty after teardown.
    var reached_success = false;
    for (0..8) |fail_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var candidate = try Spool.init(failing.allocator(), config);
        defer {
            failing.fail_index = std.math.maxInt(usize);
            candidate.deinit();
        }
        const candidate_before = try candidate.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(candidate_before);
        failing.fail_index = failing.alloc_index + fail_offset;
        const attempt = candidate.reserveBatch(&batch);
        if (attempt) |result| {
            try testing.expectEqual(@as(usize, 2), result.inserted);
            reached_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            const candidate_after = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(candidate_after);
            try testing.expectEqualSlices(u8, candidate_before, candidate_after);
        }
    }
    try testing.expect(reached_success);

    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(batch[0..]);
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.CapacityExceeded, spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(2), .bytes = "three\r\n" },
        .{ .client = 4, .event_id = eventId(3), .bytes = "four\r\n" },
    }));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "attachment delivery spool prepared batch abort is byte exact and commit cannot fail" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    var aborted = try spool.prepareBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "prepared\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "different-caps\r\n" },
    });
    defer aborted.deinit();
    const while_prepared = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(while_prepared);
    try testing.expectEqualSlices(u8, before, while_prepared);
    aborted.abort();
    const after_abort = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());

    var committed = try spool.prepareBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "prepared\r\n" },
        .{ .client = 2, .event_id = eventId(1), .bytes = "different-caps\r\n" },
    });
    defer committed.deinit();
    const result = committed.commit();
    try testing.expectEqual(@as(usize, 2), result.inserted);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
}

test "attachment delivery spool retains a slow client while healthy clients drain fairly" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "slow-one\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "healthy-one\r\n" },
        .{ .client = 10, .event_id = eventId(3), .bytes = "slow-two\r\n" },
    });

    var pending_buf: [4]PendingRecord = undefined;
    const first = spool.collectPending(&pending_buf);
    try testing.expectEqual(@as(usize, 2), first.len);
    try testing.expectEqual(@as(ClientId, 10), first[0].client);
    try testing.expectEqualStrings("slow-one\r\n", first[0].bytes);
    try testing.expectEqual(@as(ClientId, 20), first[1].client);
    // A later record for the slow client cannot overtake its retained head.
    try testing.expect(!spool.commitHeadToSendq(10, 3, eventId(3)));
    try testing.expect(spool.commitHeadToSendq(20, first[1].sequence, eventId(2)));
    try testing.expect(!spool.commitHeadToSendq(20, first[1].sequence, eventId(2)));
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(10));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 20, .event_id = eventId(4), .bytes = "healthy-two\r\n" },
    });
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
    const second = spool.collectPending(&pending_buf);
    try testing.expectEqual(@as(usize, 2), second.len);
    var saw_slow = false;
    var saw_healthy = false;
    for (second) |pending| {
        if (pending.client == 10) {
            saw_slow = true;
            try testing.expectEqualStrings("slow-one\r\n", pending.bytes);
        }
        if (pending.client == 20) {
            saw_healthy = true;
            try testing.expectEqualStrings("healthy-two\r\n", pending.bytes);
        }
    }
    try testing.expect(saw_slow and saw_healthy);
    for (second) |pending| if (pending.client == 20) {
        try testing.expect(spool.commitHeadToSendq(20, pending.sequence, eventId(4)));
        break;
    };
    try testing.expectEqual(@as(usize, 2), spool.len());
}

test "attachment delivery spool fair page reaches client thirty three" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 40,
        .max_records = 40,
        .max_total_bytes = 1024,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    var batch: [33]BatchRecord = undefined;
    for (&batch, 0..) |*record, index| record.* = .{
        .client = @intCast(index + 1),
        .event_id = eventId(1),
        .bytes = "pending\r\n",
    };
    _ = try spool.reserveBatch(&batch);
    var page: [32]PendingRecord = undefined;
    try testing.expectEqual(@as(usize, 32), spool.collectPending(&page).len);
    var last: [1]PendingRecord = undefined;
    const next = spool.collectPending(&last);
    try testing.expectEqual(@as(usize, 1), next.len);
    try testing.expectEqual(@as(ClientId, 33), next[0].client);
}

test "attachment delivery spool transfers detached resume atomically" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "old-one\r\n" },
        .{ .client = 1, .event_id = eventId(2), .bytes = "shared\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "shared\r\n" },
    });
    const transfer = try spool.transferAttachment(1, 2);
    try testing.expectEqual(@as(usize, 2), transfer.transferred);
    try testing.expectEqual(@as(usize, 1), transfer.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(2));
    try testing.expectEqual(@as(usize, 0), spool.pendingCountFor(1));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(9), .bytes = "source\r\n" },
        .{ .client = 4, .event_id = eventId(9), .bytes = "conflict\r\n" },
    });
    try testing.expectEqual(@as(usize, 3), spool.attachmentCount());
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.Equivocation, spool.transferAttachment(3, 4));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer abort leaves spool byte-identical" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "two\r\n" },
    });
    var page: [1]PendingRecord = undefined;
    _ = spool.collectPending(&page);
    const fair_cursor_before = spool.fair_cursor;
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    var prepared = try spool.prepareAttachmentTransfer(10, 30);
    prepared.abort();
    prepared.deinit();

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);
}

test "prepared attachment transfer conflict leaves spool byte-identical" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "source\r\n" },
        .{ .client = 20, .event_id = eventId(1), .bytes = "conflict\r\n" },
    });
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    try testing.expectError(error.Equivocation, spool.prepareAttachmentTransfer(10, 20));

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer OOM leaves spool byte-identical" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var spool = try Spool.init(failing.allocator(), .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer {
        failing.fail_index = std.math.maxInt(usize);
        spool.deinit();
    }
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "source\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "other\r\n" },
    });
    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, spool.prepareAttachmentTransfer(10, 30));
    failing.fail_index = std.math.maxInt(usize);

    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "prepared attachment transfer commit moves old rows to new exactly" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 30, .event_id = eventId(3), .bytes = "other\r\n" },
        .{ .client = 10, .event_id = eventId(2), .bytes = "two\r\n" },
    });

    var prepared = try spool.prepareAttachmentTransfer(10, 20);
    defer prepared.deinit();
    try testing.expect(spool.contains(10, eventId(1)));
    try testing.expect(!spool.contains(20, eventId(1)));
    const result = prepared.commit();

    try testing.expectEqual(@as(usize, 2), result.transferred);
    try testing.expectEqual(@as(usize, 0), result.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 0), spool.pendingCountFor(10));
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(20));
    try testing.expectEqual(@as(usize, 1), spool.pendingCountFor(30));
    try testing.expectEqual(@as(ClientId, 20), spool.entries.items[0].client);
    try testing.expectEqual(@as(u64, 1), spool.entries.items[0].sequence);
    try testing.expectEqualStrings("one\r\n", spool.entries.items[0].bytes);
    try testing.expectEqual(@as(ClientId, 30), spool.entries.items[1].client);
    try testing.expectEqual(@as(u64, 2), spool.entries.items[1].sequence);
    try testing.expectEqual(@as(ClientId, 20), spool.entries.items[2].client);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[2].sequence);
    try testing.expectEqualStrings("two\r\n", spool.entries.items[2].bytes);
}

test "prepared attachment transfer merges one duplicate event exactly once" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 8,
        .max_total_bytes = 128,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "shared\r\n" },
        .{ .client = 20, .event_id = eventId(1), .bytes = "shared\r\n" },
        .{ .client = 10, .event_id = eventId(2), .bytes = "unique\r\n" },
    });

    var prepared = try spool.prepareAttachmentTransfer(10, 20);
    defer prepared.deinit();
    const result = prepared.commit();

    try testing.expectEqual(@as(usize, 2), result.transferred);
    try testing.expectEqual(@as(usize, 1), result.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.pendingCountFor(20));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());
    try testing.expectEqual(@as(u64, 1), spool.entries.items[0].sequence);
    try testing.expectEqual(eventId(1), spool.entries.items[0].event_id);
    try testing.expectEqualStrings("shared\r\n", spool.entries.items[0].bytes);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[1].sequence);
    try testing.expectEqual(eventId(2), spool.entries.items[1].event_id);
    try testing.expectEqualStrings("unique\r\n", spool.entries.items[1].bytes);
}

test "attachment delivery spool discard is no-fail complete and preserves unrelated FIFO" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 64, .max_record_bytes = 16 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();

    const empty = spool.discardAttachment(7);
    try testing.expectEqual(@as(usize, 0), empty.discarded_records);
    try testing.expectEqual(@as(usize, 0), empty.discarded_bytes);
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());

    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "a\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "b\r\n" },
        .{ .client = 1, .event_id = eventId(3), .bytes = "c\r\n" },
        .{ .client = 3, .event_id = eventId(4), .bytes = "d\r\n" },
    });
    try testing.expectEqual(@as(usize, 3), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 12), spool.totalBytes());

    var page: [1]PendingRecord = undefined;
    _ = spool.collectPending(&page);
    const discarded = spool.discardAttachment(1);
    try testing.expectEqual(@as(usize, 2), discarded.discarded_records);
    try testing.expectEqual(@as(usize, 6), discarded.discarded_bytes);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 6), spool.totalBytes());
    try testing.expect(!spool.contains(1, eventId(1)));
    try testing.expect(!spool.contains(1, eventId(3)));

    var pending: [2]PendingRecord = undefined;
    const remaining = spool.collectPending(&pending);
    try testing.expectEqual(@as(usize, 2), remaining.len);
    try testing.expectEqual(@as(ClientId, 2), remaining[0].client);
    try testing.expectEqual(@as(ClientId, 3), remaining[1].client);

    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const meta = try validateCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), meta.count);
    try testing.expectEqual(@as(usize, 2), meta.attachment_count);
    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.attachmentCount());

    const before_missing = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before_missing);
    _ = spool.discardAttachment(99);
    const after_missing = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_missing);
    try testing.expectEqualSlices(u8, before_missing, after_missing);

    _ = spool.discardAttachment(2);
    _ = spool.discardAttachment(3);
    try testing.expectEqual(@as(usize, 0), spool.len());
    try testing.expectEqual(@as(usize, 0), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 0), spool.totalBytes());
}

test "attachment delivery spool collects unique clients without advancing fairness" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 64, .max_record_bytes = 16 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 3, .event_id = eventId(1), .bytes = "a\r\n" },
        .{ .client = 1, .event_id = eventId(2), .bytes = "b\r\n" },
        .{ .client = 3, .event_id = eventId(3), .bytes = "c\r\n" },
        .{ .client = 2, .event_id = eventId(4), .bytes = "d\r\n" },
        .{ .client = 1, .event_id = eventId(5), .bytes = "e\r\n" },
    });

    var pending_page: [2]PendingRecord = undefined;
    _ = spool.collectPending(&pending_page);
    const fair_cursor_before = spool.fair_cursor;

    var all_buffer: [3]ClientId = undefined;
    const all = spool.collectAttachmentClients(&all_buffer);
    try testing.expectEqual(@as(usize, spool.attachmentCount()), all.len);
    try testing.expectEqualSlices(ClientId, &.{ 3, 1, 2 }, all);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);

    var truncated_buffer: [2]ClientId = undefined;
    const truncated = spool.collectAttachmentClients(&truncated_buffer);
    try testing.expectEqualSlices(ClientId, &.{ 3, 1 }, truncated);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);

    var empty_buffer: [0]ClientId = .{};
    try testing.expectEqual(@as(usize, 0), spool.collectAttachmentClients(&empty_buffer).len);
    try testing.expectEqual(fair_cursor_before, spool.fair_cursor);
}

test "attachment delivery spool empty remap is a no-op only for empty authority" {
    const config = Config{ .max_attachments = 2, .max_records = 4, .max_total_bytes = 64, .max_record_bytes = 16 };
    var empty = try Spool.init(testing.allocator, config);
    defer empty.deinit();

    const no_mappings = try empty.remapAttachments(&.{});
    try testing.expectEqual(@as(usize, 0), no_mappings.records_remapped);
    try testing.expectEqual(@as(usize, 0), no_mappings.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 0), no_mappings.attachment_count);

    const unused_mapping = try empty.remapAttachments(&.{
        .{ .old_client = 9, .new_client = 10 },
    });
    try testing.expectEqual(@as(usize, 0), unused_mapping.records_remapped);
    try testing.expectEqual(@as(usize, 0), unused_mapping.attachment_count);

    _ = try empty.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "a\r\n" },
    });
    try testing.expectError(error.MissingMapping, empty.remapAttachments(&.{}));
    try testing.expect(empty.contains(1, eventId(1)));
}

test "attachment delivery spool simultaneous remap supports two and three cycles" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var two_cycle = try Spool.init(testing.allocator, config);
    defer two_cycle.deinit();
    _ = try two_cycle.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "from-one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "from-two\r\n" },
    });
    const two = try two_cycle.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 2 },
        .{ .old_client = 2, .new_client = 1 },
    });
    try testing.expectEqual(@as(usize, 2), two.records_remapped);
    try testing.expectEqual(@as(usize, 0), two.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), two.attachment_count);
    try testing.expect(two_cycle.contains(2, eventId(1)));
    try testing.expect(two_cycle.contains(1, eventId(2)));
    try testing.expect(!two_cycle.contains(1, eventId(1)));
    try testing.expect(!two_cycle.contains(2, eventId(2)));

    var three_cycle = try Spool.init(testing.allocator, config);
    defer three_cycle.deinit();
    _ = try three_cycle.reserveBatch(&.{
        .{ .client = 10, .event_id = eventId(1), .bytes = "ten\r\n" },
        .{ .client = 20, .event_id = eventId(2), .bytes = "twenty\r\n" },
        .{ .client = 30, .event_id = eventId(3), .bytes = "thirty\r\n" },
    });
    const three = try three_cycle.remapAttachments(&.{
        .{ .old_client = 10, .new_client = 20 },
        .{ .old_client = 20, .new_client = 30 },
        .{ .old_client = 30, .new_client = 10 },
    });
    try testing.expectEqual(@as(usize, 3), three.records_remapped);
    try testing.expectEqual(@as(usize, 3), three_cycle.attachmentCount());
    try testing.expect(three_cycle.contains(20, eventId(1)));
    try testing.expect(three_cycle.contains(30, eventId(2)));
    try testing.expect(three_cycle.contains(10, eventId(3)));
}

test "attachment delivery spool remap merges equivalents and rejects incomplete conflicting maps atomically" {
    const config = Config{ .max_attachments = 6, .max_records = 12, .max_total_bytes = 256, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(9), .bytes = "same\r\n" },
        .{ .client = 2, .event_id = eventId(9), .bytes = "same\r\n" },
        .{ .client = 3, .event_id = eventId(3), .bytes = "other\r\n" },
    });
    const merged = try spool.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 7 },
        .{ .old_client = 2, .new_client = 7 },
        .{ .old_client = 3, .new_client = 8 },
        .{ .old_client = 999, .new_client = 1000 },
    });
    try testing.expectEqual(@as(usize, 3), merged.records_remapped);
    try testing.expectEqual(@as(usize, 1), merged.exact_duplicates_merged);
    try testing.expectEqual(@as(usize, 2), merged.attachment_count);
    try testing.expectEqual(@as(usize, 2), spool.len());
    try testing.expect(spool.contains(7, eventId(9)));
    try testing.expect(spool.contains(8, eventId(3)));
    try testing.expect(!spool.hasClient(1));
    try testing.expect(!spool.hasClient(2));
    try testing.expect(!spool.hasClient(3));

    var conflicting = try Spool.init(testing.allocator, config);
    defer conflicting.deinit();
    _ = try conflicting.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(5), .bytes = "left\r\n" },
        .{ .client = 2, .event_id = eventId(5), .bytes = "right\r\n" },
    });
    const before = try conflicting.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.Equivocation, conflicting.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 9 },
        .{ .old_client = 2, .new_client = 9 },
    }));
    try testing.expectError(error.MissingMapping, conflicting.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 9 },
    }));
    try testing.expectError(error.DuplicateSource, conflicting.remapAttachments(&.{
        .{ .old_client = 1, .new_client = 9 },
        .{ .old_client = 1, .new_client = 10 },
        .{ .old_client = 2, .new_client = 11 },
    }));
    const after = try conflicting.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "attachment delivery spool remap OOM is byte exact" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    const records = [_]BatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = "one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "two\r\n" },
    };
    const mappings = [_]AttachmentRemap{
        .{ .old_client = 1, .new_client = 2 },
        .{ .old_client = 2, .new_client = 1 },
    };

    var reached_success = false;
    for (0..6) |fail_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var candidate = try Spool.init(failing.allocator(), config);
        defer {
            failing.fail_index = std.math.maxInt(usize);
            candidate.deinit();
        }
        _ = try candidate.reserveBatch(&records);
        const before = try candidate.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(before);
        failing.fail_index = failing.alloc_index + fail_offset;
        const attempt = candidate.remapAttachments(&mappings);
        if (attempt) |result| {
            try testing.expectEqual(@as(usize, 2), result.records_remapped);
            reached_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            const after = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(after);
            try testing.expectEqualSlices(u8, before, after);
        }
    }
    try testing.expect(reached_success);
}

test "attachment delivery spool duplicate is idempotent and differing bytes equivocate" {
    var spool = try Spool.init(testing.allocator, .{
        .max_attachments = 4,
        .max_records = 4,
        .max_total_bytes = 64,
        .max_record_bytes = 32,
    });
    defer spool.deinit();
    const first = BatchRecord{ .client = 7, .event_id = eventId(7), .bytes = "same\r\n" };
    _ = try spool.reserveBatch(&.{first});
    const duplicate = try spool.reserveBatch(&.{ first, first });
    try testing.expectEqual(@as(usize, 0), duplicate.inserted);
    try testing.expectEqual(@as(usize, 2), duplicate.exact_duplicates);
    try testing.expectEqual(@as(usize, 1), spool.len());
    try testing.expectError(error.Equivocation, spool.reserveBatch(&.{
        .{ .client = 7, .event_id = eventId(7), .bytes = "different\r\n" },
    }));
    try testing.expectEqual(@as(usize, 1), spool.len());
    try testing.expectError(error.InvalidRecord, spool.reserveBatch(&.{
        .{ .client = 8, .event_id = eventId(8), .bytes = "two\r\nlines\r\n" },
    }));
}

test "attachment delivery spool checkpoint round trip corruption and OOM are strict" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 9, .event_id = eventId(1), .bytes = "first\r\n" },
        .{ .client = 8, .event_id = eventId(2), .bytes = "second\r\n" },
    });
    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const meta = try validateCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), meta.count);
    try testing.expectEqual(spool.totalBytes(), meta.total_record_bytes);

    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.attachmentCount());
    const reencoded = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, checkpoint, reencoded);

    var replaced = try Spool.init(testing.allocator, config);
    defer replaced.deinit();
    try replaced.replaceFromCheckpoint(checkpoint);
    try testing.expectEqual(@as(usize, 2), replaced.attachmentCount());
    const replaced_checkpoint = try replaced.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(replaced_checkpoint);
    try testing.expectEqualSlices(u8, checkpoint, replaced_checkpoint);

    var corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[header_len] ^= 0x80;
    try testing.expectError(error.ChecksumMismatch, validateCheckpoint(corrupt));
    try testing.expectError(error.Truncated, validateCheckpoint(checkpoint[0 .. checkpoint.len - 1]));
    var trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));
    var unknown_flags = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unknown_flags);
    unknown_flags[5] = 1;
    try testing.expectError(error.InvalidField, validateCheckpoint(unknown_flags));

    var duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    var duplicate_pos: usize = header_len;
    const first_view = try parseEntry(duplicate, &duplicate_pos, config.max_record_bytes);
    const second_start = duplicate_pos;
    writeU64(duplicate[second_start..][0..8], first_view.client);
    @memcpy(
        duplicate[second_start + 16 ..][0..event_id_len],
        &first_view.event_id,
    );
    checkpointChecksum(
        duplicate[0 .. duplicate.len - checksum_len],
        duplicate[duplicate.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(error.DuplicateEntry, validateCheckpoint(duplicate));

    var bad_order = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_order);
    var order_pos: usize = header_len;
    const first_order = try parseEntry(bad_order, &order_pos, config.max_record_bytes);
    writeU64(bad_order[order_pos + 8 ..][0..8], first_order.sequence);
    checkpointChecksum(
        bad_order[0 .. bad_order.len - checksum_len],
        bad_order[bad_order.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(error.InvalidField, validateCheckpoint(bad_order));

    try testing.expectError(error.ConfigMismatch, Spool.decodeCheckpoint(testing.allocator, .{
        .max_attachments = config.max_attachments,
        .max_records = 7,
        .max_total_bytes = config.max_total_bytes,
        .max_record_bytes = config.max_record_bytes,
    }, checkpoint));

    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try Spool.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            try testing.expectEqual(@as(usize, 2), candidate.len());
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        DecodeSweep.run,
        .{ config, checkpoint },
    );

    const before = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.ChecksumMismatch, spool.replaceFromCheckpoint(corrupt));
    const after = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "attachment delivery spool checkpoint normalizes sequence gaps but preserves authority" {
    const config = Config{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "retired-one\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "retired-two\r\n" },
        .{ .client = 1, .event_id = eventId(3), .bytes = "live-three\r\n" },
        .{ .client = 2, .event_id = eventId(4), .bytes = "live-four\r\n" },
    });
    try testing.expect(spool.commitHeadToSendq(1, 1, eventId(1)));
    try testing.expect(spool.commitHeadToSendq(2, 2, eventId(2)));
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(5), .bytes = "live-five\r\n" },
    });
    try testing.expectEqual(@as(u64, 6), spool.next_sequence);
    try testing.expectEqual(@as(u64, 3), spool.entries.items[0].sequence);

    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 4), restored.next_sequence);
    try testing.expectEqual(@as(usize, 3), restored.len());
    try testing.expectEqual(@as(ClientId, 1), restored.entries.items[0].client);
    try testing.expectEqual(eventId(3), restored.entries.items[0].event_id);
    try testing.expectEqualStrings("live-three\r\n", restored.entries.items[0].bytes);
    try testing.expectEqual(@as(ClientId, 2), restored.entries.items[1].client);
    try testing.expectEqual(eventId(4), restored.entries.items[1].event_id);
    try testing.expectEqualStrings("live-four\r\n", restored.entries.items[1].bytes);
    try testing.expectEqual(@as(ClientId, 1), restored.entries.items[2].client);
    try testing.expectEqual(eventId(5), restored.entries.items[2].event_id);
    try testing.expectEqualStrings("live-five\r\n", restored.entries.items[2].bytes);

    // Both a retired tuple and a tuple borrowed from the predecessor incarnation
    // fail closed. A fresh post-restore tuple remains able to retire the head.
    try testing.expect(!restored.commitHeadToSendq(1, 1, eventId(1)));
    try testing.expect(!restored.commitHeadToSendq(1, 3, eventId(3)));
    const reencoded = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, checkpoint, reencoded);
    try testing.expect(restored.commitHeadToSendq(1, 1, eventId(3)));
    try testing.expectEqual(eventId(4), restored.entries.items[0].event_id);
    try testing.expectEqual(eventId(5), restored.entries.items[1].event_id);
}

test "attachment delivery spool large canonical checkpoint validation is linear" {
    const count: usize = 4096;
    const config = Config{
        .max_attachments = count,
        .max_records = count,
        .max_total_bytes = count * 3,
        .max_record_bytes = 3,
    };
    var spool = try Spool.init(testing.allocator, config);
    defer spool.deinit();
    try spool.entries.ensureTotalCapacity(testing.allocator, count);
    for (0..count) |index| {
        // Reverse client order ensures wire-key order differs maximally from FIFO.
        const owned = try testing.allocator.dupe(u8, "x\r\n");
        spool.entries.appendAssumeCapacity(.{
            .client = @intCast(count - index),
            .sequence = @as(u64, @intCast(index)) + 10,
            .event_id = eventId(1),
            .bytes = owned,
        });
        spool.total_bytes += owned.len;
    }
    spool.attachment_count = count;
    spool.next_sequence = @as(u64, @intCast(count)) + 10;

    var count_steps: usize = 0;
    try testing.expectEqual(count, spool.attachmentCountWithWork(&count_steps));
    try testing.expectEqual(@as(usize, 1), count_steps);

    const checkpoint = try spool.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var validation_steps: usize = 0;
    const meta = try validateCheckpointImpl(checkpoint, &validation_steps);
    try testing.expectEqual(count, meta.count);
    try testing.expectEqual(count, meta.attachment_count);
    try testing.expectEqual(count, validation_steps);

    var restored = try Spool.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(ClientId, count), restored.entries.items[0].client);
    try testing.expectEqual(@as(ClientId, 1), restored.entries.items[count - 1].client);
    try testing.expectEqual(count, restored.attachmentCount());
    const reencoded = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, checkpoint, reencoded);

    var duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    var pos: usize = header_len;
    const first = try parseEntry(duplicate, &pos, config.max_record_bytes);
    const second_start = pos;
    writeU64(duplicate[second_start..][0..8], first.client);
    @memcpy(duplicate[second_start + 16 ..][0..event_id_len], &first.event_id);
    checkpointChecksum(
        duplicate[0 .. duplicate.len - checksum_len],
        duplicate[duplicate.len - checksum_len ..][0..checksum_len],
    );
    validation_steps = 0;
    try testing.expectError(error.DuplicateEntry, validateCheckpointImpl(duplicate, &validation_steps));
    try testing.expectEqual(@as(usize, 2), validation_steps);

    var noncanonical = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(noncanonical);
    writeU64(noncanonical[second_start..][0..8], 0);
    checkpointChecksum(
        noncanonical[0 .. noncanonical.len - checksum_len],
        noncanonical[noncanonical.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(error.NonCanonicalOrder, validateCheckpoint(noncanonical));
}

test "owned attachment batch adopts inserted bodies and adopts nothing on failure" {
    var spool = try Spool.init(testing.allocator, .{});
    defer spool.deinit();

    const first = try testing.allocator.dupe(u8, "one\r\n");
    const first_ptr = first.ptr;
    var adopted = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = first },
    };
    const inserted = try spool.reserveOwnedBatch(&adopted);
    try testing.expectEqual(@as(usize, 1), inserted.inserted);
    try testing.expectEqual(@as(usize, 0), adopted[0].bytes.len);
    try testing.expectEqual(first_ptr, spool.entries.items[0].bytes.ptr);

    const duplicate = try testing.allocator.dupe(u8, "one\r\n");
    var again = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = duplicate },
    };
    const dup = try spool.reserveOwnedBatch(&again);
    try testing.expectEqual(@as(usize, 0), dup.inserted);
    try testing.expectEqual(@as(usize, 1), dup.exact_duplicates);
    try testing.expectEqual(duplicate.ptr, again[0].bytes.ptr);
    testing.allocator.free(again[0].bytes);
    try testing.expectEqual(@as(usize, 1), spool.len());

    const conflict = try testing.allocator.dupe(u8, "two\r\n");
    var bad = [_]OwnedBatchRecord{
        .{ .client = 7, .event_id = eventId(3), .bytes = conflict },
    };
    try testing.expectError(error.Equivocation, spool.reserveOwnedBatch(&bad));
    try testing.expectEqual(conflict.ptr, bad[0].bytes.ptr);
    testing.allocator.free(bad[0].bytes);
    try testing.expectEqualStrings("one\r\n", spool.entries.items[0].bytes);

    var limited = try Spool.init(testing.allocator, .{
        .max_attachments = 1,
        .max_records = 1,
        .max_total_bytes = 64,
        .max_record_bytes = 32,
    });
    defer limited.deinit();
    const keep = try testing.allocator.dupe(u8, "keep\r\n");
    const drop = try testing.allocator.dupe(u8, "drop\r\n");
    var overflow = [_]OwnedBatchRecord{
        .{ .client = 1, .event_id = eventId(1), .bytes = keep },
        .{ .client = 2, .event_id = eventId(1), .bytes = drop },
    };
    try testing.expectError(error.CapacityExceeded, limited.reserveOwnedBatch(&overflow));
    try testing.expectEqual(keep.ptr, overflow[0].bytes.ptr);
    try testing.expectEqual(drop.ptr, overflow[1].bytes.ptr);
    testing.allocator.free(overflow[0].bytes);
    testing.allocator.free(overflow[1].bytes);
    try testing.expectEqual(@as(usize, 0), limited.len());

    const left = try testing.allocator.dupe(u8, "left\r\n");
    const right = try testing.allocator.dupe(u8, "right\r\n");
    var pending = [_]OwnedBatchRecord{
        .{ .client = 4, .event_id = eventId(8), .bytes = left },
        .{ .client = 5, .event_id = eventId(8), .bytes = right },
    };
    var prepared = try spool.prepareOwnedBatch(&pending);
    try testing.expectEqual(@as(usize, 0), pending[0].bytes.len);
    try testing.expectEqual(@as(usize, 0), pending[1].bytes.len);
    try testing.expectEqual(left.ptr, prepared.staged[0].bytes.ptr);
    prepared.deinit();
    try testing.expectEqual(@as(usize, 1), spool.len());
}

test "attachment delivery spool exact typed retirement preserves chat and unrelated FIFO" {
    var spool = try Spool.init(testing.allocator, .{ .max_attachments = 4, .max_records = 8, .max_total_bytes = 128, .max_record_bytes = 32 });
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 1, .event_id = eventId(1), .bytes = "host\r\n" },
        .{ .client = 2, .event_id = eventId(2), .bytes = "other\r\n" },
        .{ .client = 1, .event_id = eventId(3), .bytes = "chat\r\n" },
    });
    const Preserve = struct {
        fn host(_: void, physical: ClientId, event: EventId) bool {
            return physical == 1 and std.mem.eql(u8, &event, &@as(EventId, eventId(1)));
        }
    };
    const result = spool.discardAttachmentExcept(1, {}, Preserve.host);
    try testing.expectEqual(@as(usize, 1), result.discarded_records);
    try testing.expectEqual(@as(usize, 6), result.discarded_bytes);
    try testing.expect(spool.contains(1, eventId(1)));
    try testing.expect(!spool.contains(1, eventId(3)));
    try testing.expectEqual(@as(usize, 2), spool.attachmentCount());
    var page: [2]PendingRecord = undefined;
    const before = spool.collectPending(&page);
    try testing.expectEqual(@as(usize, 2), before.len);
    try testing.expectEqualSlices(u8, "host\r\n", before[0].bytes);
    try testing.expectEqualSlices(u8, "other\r\n", before[1].bytes);
    try testing.expect(!spool.discardRecord(2, eventId(1)));
    try testing.expect(spool.discardRecord(1, eventId(1)));
    try testing.expect(!spool.discardRecord(1, eventId(1)));
    try testing.expectEqual(@as(usize, 1), spool.attachmentCount());
    try testing.expectEqual(@as(usize, 7), spool.totalBytes());
    const remaining = spool.collectPending(&page);
    try testing.expectEqual(@as(usize, 1), remaining.len);
    try testing.expectEqual(@as(ClientId, 2), remaining[0].client);
    try testing.expectEqualSlices(u8, "other\r\n", remaining[0].bytes);
}

test "output barrier cutoff keeps old ADS ahead and every later record behind its funded owner" {
    const a = std.testing.allocator;
    var spool = try Spool.init(a, .{});
    defer spool.deinit();
    const first: EventId = @splat(1);
    const later: EventId = @splat(2);
    _ = try spool.reserveBatch(&.{.{ .client = 0, .event_id = first, .bytes = ":s NOTICE n :old\r\n" }});
    var gate = try spool.prepareOutputBarriers(7, &.{ 0, 9 }, 2);
    defer gate.deinit();
    try std.testing.expectEqual(@as(usize, 0), spool.outputBarrierCount());
    gate.commit();
    _ = try spool.reserveBatch(&.{
        .{ .client = 0, .event_id = later, .bytes = ":s NOTICE n :later\r\n" },
        .{ .client = 10, .event_id = later, .bytes = ":s NOTICE other :independent\r\n" },
    });
    try std.testing.expect(!spool.outputBarrierReady(0, 7));
    try std.testing.expect(spool.outputBarrierReady(9, 7));
    try std.testing.expect(!spool.releaseOutputBarrier(0, 7));
    var pending: [8]PendingRecord = undefined;
    const before = spool.collectPending(&pending);
    try std.testing.expectEqual(@as(usize, 2), before.len);
    for (before) |record| {
        if (record.client == 0) try std.testing.expectEqual(first, record.event_id);
        try std.testing.expect(spool.commitHeadToSendq(record.client, record.sequence, record.event_id));
    }
    try std.testing.expectEqual(@as(usize, 0), spool.collectPending(&pending).len);
    try std.testing.expect(spool.outputBarrierReady(0, 7));
    try std.testing.expectError(error.InvalidState, spool.encodeCheckpoint(a));
    try std.testing.expectError(error.PendingPhysicalCustody, spool.prepareAttachmentTransfer(0, 8));
    try std.testing.expectError(error.PendingPhysicalCustody, spool.remapAttachments(&.{.{ .old_client = 0, .new_client = 8 }}));
    // Owner mismatch is not a release receipt.
    try std.testing.expect(!spool.releaseOutputBarrier(0, 8));
    try std.testing.expect(spool.releaseOutputBarrier(0, 7));
    const after = spool.collectPending(&pending);
    try std.testing.expectEqual(@as(usize, 1), after.len);
    try std.testing.expectEqual(later, after[0].event_id);
    try std.testing.expectEqualStrings(":s NOTICE n :later\r\n", after[0].bytes);
    try std.testing.expect(spool.commitHeadToSendq(after[0].client, after[0].sequence, after[0].event_id));
    try std.testing.expect(spool.releaseOutputBarrier(9, 7));
    try std.testing.expectEqual(@as(usize, 0), spool.outputBarrierCount());
    const wire = try spool.encodeCheckpoint(a);
    defer a.free(wire);
}

test "output barrier image ordering includes intervening ADS and exact generation retirement" {
    const a = std.testing.allocator;
    var spool = try Spool.init(a, .{});
    defer spool.deinit();
    const old_generation: ClientId = 0x100000001;
    const replacement_generation: ClientId = 0x200000001;
    var first = try spool.prepareOutputBarriers(1, &.{old_generation}, 4);
    defer first.deinit();
    first.commit();
    const event: EventId = @splat(3);
    _ = try spool.reserveBatch(&.{.{ .client = old_generation, .event_id = event, .bytes = ":s NOTICE n :between images\r\n" }});
    var second = try spool.prepareOutputBarriers(2, &.{ old_generation, replacement_generation }, 4);
    defer second.deinit();
    second.commit();
    try std.testing.expect(!spool.outputBarrierReady(old_generation, 2));
    try std.testing.expect(spool.releaseOutputBarrier(old_generation, 1));
    try std.testing.expect(!spool.outputBarrierReady(old_generation, 2));
    var pending: [2]PendingRecord = undefined;
    const middle = spool.collectPending(&pending);
    try std.testing.expectEqual(@as(usize, 1), middle.len);
    try std.testing.expectEqualStrings(":s NOTICE n :between images\r\n", middle[0].bytes);
    try std.testing.expect(spool.commitHeadToSendq(old_generation, middle[0].sequence, event));
    try std.testing.expect(spool.outputBarrierReady(old_generation, 2));
    // Closing one full ClientId cannot touch the next generation's gate.
    _ = spool.discardAttachment(old_generation);
    try std.testing.expect(!spool.hasOutputBarrier(old_generation));
    try std.testing.expect(spool.hasOutputBarrier(replacement_generation));
    try std.testing.expectEqual(@as(usize, 1), spool.outputBarrierCount());
    try std.testing.expect(spool.releaseOutputBarrier(replacement_generation, 2));
    try std.testing.expectEqual(@as(usize, 0), spool.outputBarrierCount());
    try std.testing.expectError(error.InvalidBarrier, spool.prepareOutputBarriers(0, &.{7}, 2));
    try std.testing.expectError(error.InvalidBarrier, spool.prepareOutputBarriers(1, &.{ 7, 7 }, 2));
    try std.testing.expectError(error.InvalidBarrier, spool.prepareOutputBarriers(1, &.{std.math.maxInt(u64)}, 2));
}

test "output barrier prepare allocation cuts leave old FIFO and credits exact" {
    const a = std.testing.allocator;
    var failures: usize = 0;
    var succeeded = false;
    for (0..64) |index| {
        var spool = try Spool.init(a, .{});
        defer spool.deinit();
        const event: EventId = @splat(4);
        _ = try spool.reserveBatch(&.{.{ .client = 1, .event_id = event, .bytes = ":s NOTICE n :existing\r\n" }});
        const before = try spool.encodeCheckpoint(a);
        defer a.free(before);
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        spool.allocator = failing.allocator();
        const attempt = spool.prepareOutputBarriers(1, &.{ 1, 2, 3 }, 3);
        if (attempt) |prepared| {
            var plan = prepared;
            try std.testing.expect(!failing.has_induced_failure);
            plan.abort();
            plan.abort();
            plan.deinit();
            succeeded = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            failures += 1;
        }
        spool.allocator = a;
        try std.testing.expectEqual(@as(usize, 0), spool.outputBarrierCount());
        try std.testing.expect(!spool.hasOutputBarrier(1));
        try std.testing.expectEqual(@as(usize, 1), spool.len());
        const after = try spool.encodeCheckpoint(a);
        defer a.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        if (succeeded) break;
    }
    try std.testing.expect(failures != 0);
    try std.testing.expect(succeeded);
}

test "output barrier plaintext chunks preserve CRLF fragments framing type and strict checkpoint refusal" {
    const a = std.testing.allocator;
    var spool = try Spool.init(a, .{});
    defer spool.deinit();
    _ = try spool.reserveBatch(&.{.{ .client = 1, .event_id = @splat(1), .bytes = ":old NOTICE one :before\r\n" }});
    var gates = try spool.prepareOutputBarriers(1, &.{1}, 2);
    defer gates.deinit();
    gates.commit();
    var output = try spool.prepareOutputBatch(&.{
        .{ .client = 1, .bytes = ":new NOTICE one :frag" },
        .{ .client = 1, .bytes = "ment\r\nsecond\r\n" },
        .{ .client = 2, .bytes = "\x81\x01X", .encoding = .preframed_secure },
    });
    defer output.deinit();
    _ = output.commit();
    var pending: [4]PendingRecord = undefined;
    const first = spool.collectPending(&pending);
    try std.testing.expectEqual(@as(usize, 2), first.len);
    for (first) |row| {
        if (row.client == 1) {
            try std.testing.expectEqual(OutputEncoding.irc_record, row.encoding);
            try std.testing.expectEqualStrings(":old NOTICE one :before\r\n", row.bytes);
        } else {
            try std.testing.expectEqual(OutputEncoding.preframed_secure, row.encoding);
            try std.testing.expectEqualSlices(u8, "\x81\x01X", row.bytes);
        }
        try std.testing.expect(spool.commitHeadToSendq(row.client, row.sequence, row.event_id));
    }
    try std.testing.expectEqual(@as(usize, 0), spool.collectPending(&pending).len);
    try std.testing.expect(spool.releaseOutputBarrier(1, 1));
    try std.testing.expectError(error.InvalidState, spool.encodeCheckpoint(a));
    try std.testing.expectError(error.PendingPhysicalCustody, spool.prepareAttachmentTransfer(1, 3));
    try std.testing.expectError(error.PendingPhysicalCustody, spool.remapAttachments(&.{.{ .old_client = 1, .new_client = 3 }}));
    const head = spool.collectPending(&pending)[0];
    try std.testing.expectEqual(OutputEncoding.plaintext, head.encoding);
    try std.testing.expectEqualStrings(":new NOTICE one :frag", head.bytes);
    try std.testing.expect(spool.commitHeadToSendq(head.client, head.sequence, head.event_id));
    const tail = spool.collectPending(&pending)[0];
    try std.testing.expectEqualStrings("ment\r\nsecond\r\n", tail.bytes);
    try std.testing.expect(spool.commitHeadToSendq(tail.client, tail.sequence, tail.event_id));
    try std.testing.expect(!spool.hasUncheckpointedOutput());
    const empty = try spool.encodeCheckpoint(a);
    a.free(empty);
}

test "output barrier plaintext prepare allocation cuts leave sequence bytes and physical retirement exact" {
    const a = std.testing.allocator;
    var saw_failure = false;
    for (0..32) |cut| {
        var fault = std.testing.FailingAllocator.init(a, .{ .fail_index = cut });
        var spool = try Spool.init(fault.allocator(), .{});
        defer spool.deinit();
        const attempted = spool.prepareOutputBatch(&.{
            .{ .client = 0, .bytes = "first fragment" },
            .{ .client = 0x100000000, .bytes = "other generation\r\n" },
        });
        if (attempted) |value| {
            var prepared = value;
            defer prepared.deinit();
            _ = prepared.commit();
            try std.testing.expectEqual(@as(usize, 2), spool.len());
            try std.testing.expectEqual(@as(usize, 1), spool.discardUncheckpointedOutput(0));
            try std.testing.expect(!spool.hasPendingOutput(0));
            try std.testing.expect(spool.hasPendingOutput(0x100000000));
            try std.testing.expectEqual(@as(usize, 1), spool.discardUncheckpointedOutput(0x100000000));
            try std.testing.expectEqual(@as(usize, 0), spool.totalBytes());
            try std.testing.expect(saw_failure);
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            saw_failure = true;
            try std.testing.expectEqual(@as(usize, 0), spool.len());
            try std.testing.expectEqual(@as(usize, 0), spool.totalBytes());
            try std.testing.expectEqual(@as(u64, 1), spool.next_sequence);
            try std.testing.expectEqual(@as(usize, 0), spool.attachmentCount());
        }
    }
    return error.TestUnexpectedResult;
}
