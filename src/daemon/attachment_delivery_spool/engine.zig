// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transactional attachment spool, prepared ownership, and fair delivery.

const std = @import("std");
const testing = std.testing;
const ClientId = @import("model.zig").ClientId;
const EventId = @import("model.zig").EventId;
const hard_max_attachments = @import("model.zig").hard_max_attachments;
const hard_max_checkpoint_bytes = @import("model.zig").hard_max_checkpoint_bytes;
const Config = @import("model.zig").Config;
const InitError = @import("model.zig").InitError;
const ReserveError = @import("model.zig").ReserveError;
const TransferError = @import("model.zig").TransferError;
const AttachmentRemap = @import("model.zig").AttachmentRemap;
const RemapError = @import("model.zig").RemapError;
const RemapResult = @import("model.zig").RemapResult;
const CheckpointError = @import("model.zig").CheckpointError;
const BatchRecord = @import("model.zig").BatchRecord;
const OwnedBatchRecord = @import("model.zig").OwnedBatchRecord;
const ReserveResult = @import("model.zig").ReserveResult;
const PendingRecord = @import("model.zig").PendingRecord;
const TransferResult = @import("model.zig").TransferResult;
const DiscardResult = @import("model.zig").DiscardResult;
const Entry = @import("model.zig").Entry;
const AttachmentTransferPlan = @import("model.zig").AttachmentTransferPlan;
const mappedClient = @import("policy.zig").mappedClient;
const validateConfig = @import("policy.zig").validateConfig;
const configsEqual = @import("policy.zig").configsEqual;
const validRenderedRecord = @import("policy.zig").validRenderedRecord;
const validateCheckpoint = @import("checkpoint.zig").validateCheckpoint;
const validateCheckpointImpl = @import("checkpoint.zig").validateCheckpointImpl;
const parseEntry = @import("checkpoint.zig").parseEntry;
const compareEntryKey = @import("checkpoint.zig").compareEntryKey;
const checkpoint_magic = @import("checkpoint.zig").checkpoint_magic;
const checkpoint_version = @import("checkpoint.zig").checkpoint_version;
const header_len = @import("checkpoint.zig").header_len;
const event_id_len = @import("checkpoint.zig").event_id_len;
const entry_prefix_len = @import("checkpoint.zig").entry_prefix_len;
const checksum_len = @import("checkpoint.zig").checksum_len;
const checkpointChecksum = @import("checkpoint.zig").checkpointChecksum;
const writeU32 = @import("checkpoint.zig").writeU32;
const writeU64 = @import("checkpoint.zig").writeU64;

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

pub const Spool = struct {
    allocator: std.mem.Allocator,
    config: Config,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
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
        self.* = undefined;
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
                if (!std.mem.eql(u8, self.entries.items[existing_index].bytes, record.bytes))
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
        if (!self.isOldestForClient(index) or self.entries.items[index].sequence != sequence)
            return false;
        self.removeAt(index);
        return true;
    }

    /// Allocation-free retirement for an attachment whose exact session is being
    /// intentionally destroyed. This never transfers rendered rows across token
    /// authorities; it frees every matching body and compacts unrelated FIFO rows
    /// in place. The operation cannot fail.
    pub fn discardAttachment(self: *Spool, client: ClientId) DiscardResult {
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

    /// Prepare an exact old-to-new attachment transfer without publishing any
    /// change. Equal destination rows are preplanned as one retained earlier
    /// event; differing bytes reject the entire plan. The returned ticket owns
    /// all memory required by its allocation-free/no-fail commit.
    pub fn prepareAttachmentTransfer(
        self: *Spool,
        old_client: ClientId,
        new_client: ClientId,
    ) TransferError!PreparedAttachmentTransfer {
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

pub fn eventId(byte: u8) EventId {
    var id: EventId = @splat(0);
    id[id.len - 1] = byte;
    return id;
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
