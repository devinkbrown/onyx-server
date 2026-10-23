// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded history rings, exact-once retention, and transactional checkpoint adoption.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const types = @import("types.zig");
const retained = @import("retained_message.zig");
const checkpoint = @import("checkpoint_wire.zig");

pub fn Lotus(comptime params: types.Params) type {
    comptime validateParams(params);

    return struct {
        const Self = @This();

        const TargetLog = struct {
            entries: []retained.StoredMessage,
            start: usize,
            len: usize,

            fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!TargetLog {
                return .{
                    .entries = try allocator.alloc(retained.StoredMessage, params.max_per_target),
                    .start = 0,
                    .len = 0,
                };
            }

            fn deinit(self: *TargetLog, allocator: std.mem.Allocator) void {
                var index: usize = 0;
                while (index < self.len) : (index += 1) {
                    self.entryMut(index).deinit(allocator);
                }
                allocator.free(self.entries);
                self.* = .{ .entries = &.{}, .start = 0, .len = 0 };
            }

            fn appendTake(self: *TargetLog, allocator: std.mem.Allocator, msg: retained.StoredMessage) bool {
                if (self.len == params.max_per_target) {
                    self.entries[self.start].deinit(allocator);
                    self.entries[self.start] = msg;
                    self.start = (self.start + 1) % params.max_per_target;
                    return true;
                }

                const write_index = self.slot(self.len);
                self.entries[write_index] = msg;
                self.len += 1;
                return false;
            }

            fn slot(self: *const TargetLog, logical_index: usize) usize {
                return (self.start + logical_index) % params.max_per_target;
            }

            fn entry(self: *const TargetLog, logical_index: usize) *const retained.StoredMessage {
                return &self.entries[self.slot(logical_index)];
            }

            fn entryMut(self: *TargetLog, logical_index: usize) *retained.StoredMessage {
                return &self.entries[self.slot(logical_index)];
            }

            fn removeAt(self: *TargetLog, allocator: std.mem.Allocator, logical_index: usize) void {
                std.debug.assert(logical_index < self.len);
                self.entryMut(logical_index).deinit(allocator);
                var index = logical_index;
                while (index + 1 < self.len) : (index += 1) {
                    self.entries[self.slot(index)] = self.entries[self.slot(index + 1)];
                }
                self.len -= 1;
            }
        };

        const QueryBound = union(enum) {
            before: u64,
        };

        const EvictionCandidate = struct {
            target: []const u8,
            index: usize,
        };

        pub const DeterministicEntry = struct {
            target: []const u8,
            message: types.Message,
        };

        /// Allocation-free canonical traversal: targets are byte-sorted and
        /// each ring is visited oldest-to-newest, including tombstones. A search
        /// index can rebuild exactly by indexing only entries whose tombstone is
        /// false. Borrowed views remain valid until the next store mutation.
        pub const DeterministicIterator = struct {
            store: *const Self,
            target_keys: [params.max_targets][]const u8,
            target_count: usize,
            target_index: usize = 0,
            message_index: usize = 0,

            pub fn next(self: *DeterministicIterator) ?DeterministicEntry {
                while (self.target_index < self.target_count) {
                    const target = self.target_keys[self.target_index];
                    const log = self.store.targets.get(target).?;
                    if (self.message_index < log.len) {
                        const message = log.entry(self.message_index).view();
                        self.message_index += 1;
                        return .{ .target = target, .message = message };
                    }
                    self.target_index += 1;
                    self.message_index = 0;
                }
                return null;
            }
        };

        allocator: std.mem.Allocator,
        targets: std.StringHashMap(TargetLog),
        /// Canonical checkpoint body bytes for the currently retained state.
        /// Kept incrementally so normal ingestion does not need to rescan every
        /// ring merely to enforce the aggregate durable-state budget.
        checkpoint_body_len: usize,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .targets = std.StringHashMap(TargetLog).init(allocator),
                .checkpoint_body_len = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
                self.allocator.free(entry.key_ptr.*);
            }
            self.targets.deinit();
            self.* = undefined;
        }

        /// Insert a globally new msgid, accept a byte-exact retained replay, or
        /// reject reuse of that msgid for different state. Classification is
        /// allocation-free and spans every retained target, so a msgid reused
        /// for another target is equivocation. Duplicate and equivocation
        /// outcomes leave the complete store byte-for-byte unchanged.
        ///
        /// Server wiring contract: hold the history/projection mutation lock,
        /// call this method before fanout, and update SearchIndex plus fanout
        /// only for `.inserted`. `.exact_duplicate` has no side effects and
        /// `.equivocation` is rejected. SearchIndex remains a projection, not
        /// an identity authority; never call its replacing `index` operation
        /// for either non-insert outcome. Exact-once memory is intentionally
        /// bounded by the Lotus rings: an evicted msgid is new if seen again.
        pub fn ingestExactOnce(self: *Self, target: []const u8, msg: types.ExactInputMessage) types.Error!types.ExactOnceResult {
            try validateTargetForParams(target);
            const input = types.exactInput(msg);
            try validateMessage(input);

            var found_exact = false;
            var targets = self.targets.iterator();
            while (targets.next()) |target_entry| {
                const existing_target = target_entry.key_ptr.*;
                const log = target_entry.value_ptr;
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    const existing = log.entry(index);
                    if (!std.mem.eql(u8, existing.msgid, msg.msgid)) continue;
                    if (!std.mem.eql(u8, existing_target, target) or
                        !storedMatchesExact(existing, msg))
                    {
                        return .equivocation;
                    }
                    found_exact = true;
                }
            }
            if (found_exact) return .exact_duplicate;

            return .{ .inserted = try self.appendState(target, input, msg.tombstone) };
        }

        /// Legacy append deliberately preserves its original behavior,
        /// including allowing repeated msgids.
        pub fn append(self: *Self, target: []const u8, msg: types.InputMessage) types.Error!types.AppendResult {
            try validateTargetForParams(target);
            try validateMessage(msg);
            return self.appendState(target, msg, false);
        }

        fn appendState(self: *Self, target: []const u8, msg: types.InputMessage, tombstone: bool) types.Error!types.AppendResult {
            if (self.targets.get(target) == null and self.targets.count() >= params.max_targets)
                return error.TargetLimitExceeded;
            const new_entry_len = try checkpoint.checkpointEntryBodyLen(msg);
            const minimum_body_len = try checkpoint.checkpointBodyLenAdd(checkpoint.checkpoint_target_prefix_len + target.len, new_entry_len);
            if (!checkpoint.checkpointBodyFits(minimum_body_len, params.max_checkpoint_bytes))
                return error.CheckpointCapacityExceeded;
            var stored = try retained.StoredMessage.init(self.allocator, msg);
            errdefer stored.deinit(self.allocator);
            stored.tombstone = tombstone;

            if (self.targets.get(target) != null) {
                var evicted = false;
                {
                    const log = self.targets.getPtr(target).?;
                    if (log.len == params.max_per_target) {
                        self.checkpoint_body_len -= checkpoint.checkpointStoredEntryBodyLen(log.entry(0));
                        log.removeAt(self.allocator, 0);
                        evicted = true;
                    }
                }
                while (!self.appendFitsCheckpoint(target, new_entry_len)) {
                    // Aggregate pressure is store-wide: retain the newest
                    // history fairly across targets by evicting the same
                    // deterministic global oldest candidate used for a newly
                    // inserted target. Per-target ring eviction above remains
                    // bounded by the configured 256-entry ring.
                    self.evictGlobalOldest(target);
                    evicted = true;
                }
                const log = self.targets.getPtr(target).?;
                _ = log.appendTake(self.allocator, stored);
                self.checkpoint_body_len += new_entry_len;
                return .{ .evicted = evicted, .target_len = log.len };
            }

            const owned_target = try self.allocator.dupe(u8, target);
            errdefer self.allocator.free(owned_target);

            var log = try TargetLog.init(self.allocator);
            errdefer log.deinit(self.allocator);

            // No allocation may follow global eviction: a failed insert must
            // never turn a valid append into history loss.
            try self.targets.ensureTotalCapacity(self.targets.count() + 1);
            var evicted = false;
            while (!self.appendFitsCheckpoint(target, new_entry_len)) {
                self.evictGlobalOldest(target);
                evicted = true;
            }
            self.targets.putAssumeCapacity(owned_target, log);
            const inserted = self.targets.getPtr(owned_target).?;
            _ = inserted.appendTake(self.allocator, stored);
            self.checkpoint_body_len += checkpoint.checkpoint_target_prefix_len + target.len + new_entry_len;
            return .{ .evicted = evicted, .target_len = inserted.len };
        }

        pub fn latest(self: *const Self, target: []const u8, n: usize, out: []types.Message) types.Error![]const types.Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectNewest(&log, n, out, null);
        }

        pub fn before(
            self: *const Self,
            target: []const u8,
            timestamp: u64,
            n: usize,
            out: []types.Message,
        ) types.Error![]const types.Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectNewest(&log, n, out, .{ .before = timestamp });
        }

        /// Return visible entries after `timestamp`, oldest first for replay.
        pub fn after(
            self: *const Self,
            target: []const u8,
            timestamp: u64,
            n: usize,
            out: []types.Message,
        ) types.Error![]const types.Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectAfter(&log, timestamp, n, out);
        }

        pub fn redact(self: *Self, target: []const u8, msgid: []const u8) types.Error!void {
            const entry = try self.findNewest(target, msgid);
            entry.tombstone = true;
        }

        pub fn edit(self: *Self, target: []const u8, msgid: []const u8, new_text: []const u8) types.Error!void {
            try validateText(new_text);
            const entry = try self.findNewest(target, msgid);
            const new_body_len = try self.bodyLenAfterEdit(entry, new_text.len);
            const owned_text = try self.allocator.dupe(u8, new_text);
            self.allocator.free(entry.text);
            entry.text = owned_text;
            entry.hash = retained.hashText(new_text);
            self.checkpoint_body_len = new_body_len;
        }

        /// Resolve a message's server timestamp by its msgid within `target`, or
        /// null when no such message exists. Translates CHATHISTORY msgid
        /// selectors into the timestamp bounds the paging queries operate on.
        pub fn timestampOf(self: *Self, target: []const u8, msgid: []const u8) ?u64 {
            const found = self.findNewest(target, msgid) catch return null;
            return found.timestamp;
        }

        /// Oldest retained row on `target` at or before `cutoff`, tombstones
        /// included. The borrowed view dies at the next store mutation.
        pub fn oldestNotAfter(self: *const Self, target: []const u8, cutoff: u64) ?types.Message {
            const log = self.targets.get(target) orelse return null;
            var index: usize = 0;
            while (index < log.len) : (index += 1) {
                const entry = log.entry(index);
                if (entry.timestamp <= cutoff) return entry.view();
            }
            return null;
        }

        /// Remove one row and its checkpoint bytes. An empty ring drops the
        /// target. This frees the slot; `redact` only sets a tombstone.
        pub fn forget(self: *Self, target: []const u8, msgid: []const u8) types.Error!void {
            try validateTarget(target);
            const log = self.targets.getPtr(target) orelse return error.NotFound;
            var logical: ?usize = null;
            var scanned: usize = 0;
            while (scanned < log.len) : (scanned += 1) {
                const logical_index = log.len - 1 - scanned;
                if (std.mem.eql(u8, log.entry(logical_index).msgid, msgid)) {
                    logical = logical_index;
                    break;
                }
            }
            const index = logical orelse return error.NotFound;
            self.checkpoint_body_len -= checkpoint.checkpointStoredEntryBodyLen(log.entry(index));
            log.removeAt(self.allocator, index);
            if (log.len != 0) return;

            var removed = self.targets.fetchRemove(target).?;
            self.checkpoint_body_len -= checkpoint.checkpoint_target_prefix_len + removed.key.len;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
        }

        /// Borrowed target names. The callback must not mutate the store.
        pub fn forEachTarget(self: *const Self, context: anytype, comptime callback: anytype) void {
            var it = self.targets.iterator();
            while (it.next()) |entry| callback(context, entry.key_ptr.*);
        }

        pub fn storedCount(self: *const Self, target: []const u8) types.Error!usize {
            try validateTarget(target);
            const log = self.targets.get(target) orelse return 0;
            return log.len;
        }

        pub fn targetCount(self: *const Self) usize {
            return self.targets.count();
        }

        pub fn totalStoredCount(self: *const Self) usize {
            var total: usize = 0;
            var it = self.targets.iterator();
            while (it.next()) |entry| total += entry.value_ptr.len;
            return total;
        }

        pub fn tombstoneCount(self: *const Self) usize {
            var total: usize = 0;
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                const log = entry.value_ptr;
                var i: usize = 0;
                while (i < log.len) : (i += 1) {
                    if (log.entry(i).tombstone) total += 1;
                }
            }
            return total;
        }

        pub fn deterministicIterator(self: *const Self) DeterministicIterator {
            var iterator = DeterministicIterator{
                .store = self,
                .target_keys = undefined,
                .target_count = 0,
            };
            var targets = self.targets.iterator();
            while (targets.next()) |entry| {
                iterator.target_keys[iterator.target_count] = entry.key_ptr.*;
                iterator.target_count += 1;
            }
            std.mem.sort(
                []const u8,
                iterator.target_keys[0..iterator.target_count],
                {},
                bytesLessThan,
            );
            return iterator;
        }

        /// Encode every retained ring slot, including tombstones and nullable
        /// client tags, into one canonical bounded checkpoint. The caller owns
        /// the returned bytes.
        pub fn encodeCheckpoint(self: *const Self, allocator: std.mem.Allocator) types.CheckpointError![]u8 {
            var canonical = self.deterministicIterator();
            var body_len: usize = 0;
            for (canonical.target_keys[0..canonical.target_count]) |target| {
                const log = self.targets.get(target).?;
                if (log.len == 0 or log.len > params.max_per_target) return error.InvalidField;
                body_len = try checkpoint.checkpointLenAdd(body_len, checkpoint.checkpoint_target_prefix_len, params.max_checkpoint_bytes);
                body_len = try checkpoint.checkpointLenAdd(body_len, target.len, params.max_checkpoint_bytes);
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    const message = log.entry(index);
                    try validateCheckpointStoredMessage(message);
                    body_len = try checkpoint.checkpointLenAdd(body_len, checkpoint.checkpoint_entry_prefix_len, params.max_checkpoint_bytes);
                    body_len = try checkpoint.checkpointLenAdd(body_len, message.msgid.len, params.max_checkpoint_bytes);
                    body_len = try checkpoint.checkpointLenAdd(body_len, message.sender.len, params.max_checkpoint_bytes);
                    body_len = try checkpoint.checkpointLenAdd(body_len, message.text.len, params.max_checkpoint_bytes);
                    body_len = try checkpoint.checkpointLenAdd(body_len, message.command.len, params.max_checkpoint_bytes);
                    body_len = try checkpoint.checkpointLenAdd(body_len, if (message.client_tags) |tags| tags.len else 0, params.max_checkpoint_bytes);
                }
            }
            // Append and edit admission maintain this exact value. Keeping the
            // check here makes corruption fail closed as well, without changing
            // the v1 wire format.
            if (body_len != self.checkpoint_body_len) return error.InvalidField;
            const prefix_len = try checkpoint.checkpointLenAdd(checkpoint.checkpoint_header_len, body_len, params.max_checkpoint_bytes);
            const total_len = try checkpoint.checkpointLenAdd(prefix_len, checkpoint.checkpoint_checksum_len, params.max_checkpoint_bytes);
            const out = try allocator.alloc(u8, total_len);
            errdefer allocator.free(out);

            @memcpy(out[0..checkpoint.checkpoint_magic.len], &checkpoint.checkpoint_magic);
            out[4] = checkpoint.checkpoint_version;
            out[5] = 0;
            checkpoint.writeU16(out[6..8], 0);
            checkpoint.writeU32(out[8..12], @intCast(params.max_targets));
            checkpoint.writeU32(out[12..16], @intCast(params.max_per_target));
            checkpoint.writeU32(out[16..20], @intCast(params.max_text));
            checkpoint.writeU32(out[20..24], @intCast(params.max_target));
            checkpoint.writeU32(out[24..28], @intCast(params.max_msgid));
            checkpoint.writeU32(out[28..32], @intCast(params.max_sender));
            checkpoint.writeU32(out[32..36], @intCast(params.max_command));
            checkpoint.writeU32(out[36..40], @intCast(params.max_client_tags));
            checkpoint.writeU32(out[40..44], @intCast(canonical.target_count));
            checkpoint.writeU32(out[44..48], @intCast(self.totalStoredCount()));
            checkpoint.writeU32(out[48..52], @intCast(body_len));

            var pos: usize = checkpoint.checkpoint_header_len;
            for (canonical.target_keys[0..canonical.target_count]) |target| {
                const log = self.targets.get(target).?;
                checkpoint.writeU32(out[pos..][0..4], @intCast(target.len));
                pos += 4;
                checkpoint.writeU32(out[pos..][0..4], @intCast(log.len));
                pos += 4;
                @memcpy(out[pos..][0..target.len], target);
                pos += target.len;
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    const message = log.entry(index);
                    var flags: u8 = if (message.tombstone) checkpoint.checkpoint_flag_tombstone else 0;
                    if (message.client_tags != null) flags |= checkpoint.checkpoint_flag_has_tags;
                    out[pos] = flags;
                    pos += 1;
                    checkpoint.writeU64(out[pos..][0..8], message.timestamp);
                    pos += 8;
                    @memcpy(out[pos..][0..@sizeOf(types.ContentHash)], &message.hash);
                    pos += @sizeOf(types.ContentHash);
                    const tags = message.client_tags orelse "";
                    checkpoint.writeU32(out[pos..][0..4], @intCast(message.msgid.len));
                    pos += 4;
                    checkpoint.writeU32(out[pos..][0..4], @intCast(message.sender.len));
                    pos += 4;
                    checkpoint.writeU32(out[pos..][0..4], @intCast(message.text.len));
                    pos += 4;
                    checkpoint.writeU32(out[pos..][0..4], @intCast(message.command.len));
                    pos += 4;
                    checkpoint.writeU32(out[pos..][0..4], @intCast(tags.len));
                    pos += 4;
                    for ([_][]const u8{ message.msgid, message.sender, message.text, message.command, tags }) |field| {
                        @memcpy(out[pos..][0..field.len], field);
                        pos += field.len;
                    }
                }
            }
            std.debug.assert(pos == prefix_len);
            checkpoint.checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checkpoint.checkpoint_checksum_len]);
            return out;
        }

        /// Decode without publishing any state. Resource authority must match
        /// this concrete Lotus instantiation exactly, except that an older
        /// positive text ceiling may be restored into a larger current store.
        /// This preserves v1 checkpoint framing while allowing a history text
        /// capacity increase without stranding existing checkpoints.
        pub fn decodeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) types.CheckpointError!Self {
            if (bytes.len > params.max_checkpoint_bytes) return error.CheckpointTooLarge;
            if (bytes.len < checkpoint.checkpoint_header_len + checkpoint.checkpoint_checksum_len) return error.Truncated;
            if (!std.mem.eql(u8, bytes[0..checkpoint.checkpoint_magic.len], &checkpoint.checkpoint_magic)) return error.BadMagic;
            if (bytes[4] != checkpoint.checkpoint_version) return error.UnsupportedVersion;
            if (bytes[5] != 0 or checkpoint.readU16(bytes[6..8]) != 0) return error.InvalidField;
            const encoded_max_text: usize = checkpoint.readU32(bytes[16..20]);
            if (checkpoint.readU32(bytes[8..12]) != params.max_targets or
                checkpoint.readU32(bytes[12..16]) != params.max_per_target or
                encoded_max_text == 0 or encoded_max_text > params.max_text or
                checkpoint.readU32(bytes[20..24]) != params.max_target or
                checkpoint.readU32(bytes[24..28]) != params.max_msgid or
                checkpoint.readU32(bytes[28..32]) != params.max_sender or
                checkpoint.readU32(bytes[32..36]) != params.max_command or
                checkpoint.readU32(bytes[36..40]) != params.max_client_tags)
                return error.ConfigMismatch;

            const target_count: usize = checkpoint.readU32(bytes[40..44]);
            const declared_total: usize = checkpoint.readU32(bytes[44..48]);
            const body_len: usize = checkpoint.readU32(bytes[48..52]);
            if (target_count > params.max_targets or
                declared_total > params.max_targets * params.max_per_target)
                return error.CapacityExceeded;
            const prefix_len = try checkpoint.checkpointLenAdd(checkpoint.checkpoint_header_len, body_len, params.max_checkpoint_bytes);
            const expected_len = try checkpoint.checkpointLenAdd(prefix_len, checkpoint.checkpoint_checksum_len, params.max_checkpoint_bytes);
            if (bytes.len < expected_len) return error.Truncated;
            if (bytes.len > expected_len) return error.TrailingBytes;
            var actual_checksum: [checkpoint.checkpoint_checksum_len]u8 = undefined;
            checkpoint.checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
            if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

            var restored = Self.init(allocator);
            errdefer restored.deinit();
            var reader = checkpoint.CheckpointReader{ .bytes = bytes, .pos = checkpoint.checkpoint_header_len, .end = prefix_len };
            var previous_target: ?[]const u8 = null;
            var actual_total: usize = 0;
            for (0..target_count) |_| {
                const target_len: usize = try reader.takeU32();
                const entry_count: usize = try reader.takeU32();
                if (target_len == 0 or target_len > params.max_target or
                    entry_count == 0 or entry_count > params.max_per_target)
                    return error.CapacityExceeded;
                const target = try reader.readBytes(target_len);
                if (previous_target) |previous| {
                    if (!std.mem.lessThan(u8, previous, target)) return error.NonCanonicalOrder;
                }
                previous_target = target;

                for (0..entry_count) |_| {
                    const flags = try reader.takeU8();
                    if (flags & ~(checkpoint.checkpoint_flag_tombstone | checkpoint.checkpoint_flag_has_tags) != 0)
                        return error.InvalidField;
                    const timestamp = try reader.takeU64();
                    const encoded_hash: types.ContentHash = (try reader.readBytes(@sizeOf(types.ContentHash)))[0..@sizeOf(types.ContentHash)].*;
                    const msgid_len: usize = try reader.takeU32();
                    const sender_len: usize = try reader.takeU32();
                    const text_len: usize = try reader.takeU32();
                    const command_len: usize = try reader.takeU32();
                    const tags_len: usize = try reader.takeU32();
                    if (msgid_len > params.max_msgid or sender_len > params.max_sender or
                        text_len > encoded_max_text or text_len > params.max_text or command_len > params.max_command or
                        tags_len > params.max_client_tags)
                        return error.CapacityExceeded;
                    const has_tags = flags & checkpoint.checkpoint_flag_has_tags != 0;
                    if (!has_tags and tags_len != 0) return error.InvalidField;
                    const msgid = try reader.readBytes(msgid_len);
                    const sender = try reader.readBytes(sender_len);
                    const text = try reader.readBytes(text_len);
                    const command = try reader.readBytes(command_len);
                    const tags = try reader.readBytes(tags_len);
                    const computed_hash = retained.hashText(text);
                    if (!std.mem.eql(u8, &encoded_hash, &computed_hash)) return error.InvalidHash;

                    _ = restored.append(target, .{
                        .msgid = msgid,
                        .sender = sender,
                        .text = text,
                        .timestamp = timestamp,
                        .command = command,
                        .client_tags = if (has_tags) tags else null,
                    }) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.InvalidField,
                    };
                    const log = restored.targets.getPtr(target).?;
                    log.entryMut(log.len - 1).tombstone = flags & checkpoint.checkpoint_flag_tombstone != 0;
                    actual_total += 1;
                }
            }
            if (reader.pos != reader.end) return error.TrailingBytes;
            if (actual_total != declared_total) return error.InvalidField;
            return restored;
        }

        /// Transactional live replacement. Decode and allocate the complete new
        /// image first; malformed input or OOM leaves `self` byte-for-byte intact.
        pub fn replaceFromCheckpoint(self: *Self, bytes: []const u8) types.CheckpointError!void {
            const replacement = try Self.decodeCheckpoint(self.allocator, bytes);
            var old = self.*;
            self.* = replacement;
            old.deinit();
        }

        fn validateCheckpointStoredMessage(message: *const retained.StoredMessage) types.CheckpointError!void {
            if (message.msgid.len > params.max_msgid or message.sender.len > params.max_sender or
                message.text.len > params.max_text or message.command.len > params.max_command)
                return error.CapacityExceeded;
            if (message.client_tags) |tags| {
                if (tags.len > params.max_client_tags) return error.CapacityExceeded;
            }
            const expected_hash = retained.hashText(message.text);
            if (!std.mem.eql(u8, &message.hash, &expected_hash)) return error.InvalidHash;
        }

        fn storedMatchesExact(existing: *const retained.StoredMessage, incoming: types.ExactInputMessage) bool {
            const expected_hash = retained.hashText(incoming.text);
            return std.mem.eql(u8, existing.sender, incoming.sender) and
                std.mem.eql(u8, existing.text, incoming.text) and
                existing.timestamp == incoming.timestamp and
                std.mem.eql(u8, existing.command, incoming.command) and
                optionalBytesEqual(existing.client_tags, incoming.client_tags) and
                existing.tombstone == incoming.tombstone and
                std.mem.eql(u8, &existing.hash, &expected_hash);
        }

        pub fn root(self: *const Self) types.ContentHash {
            var keys: [params.max_targets][]const u8 = undefined;
            var count: usize = 0;
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                keys[count] = entry.key_ptr.*;
                count += 1;
            }
            std.mem.sort([]const u8, keys[0..count], {}, bytesLessThan);

            var hasher = Blake3.init(.{});
            hasher.update("onyx_server.lotus.root.v1");
            retained.updateLen(&hasher, count);
            for (keys[0..count]) |target| {
                const log = self.targets.get(target).?;
                retained.updateBytes(&hasher, target);
                retained.updateLen(&hasher, log.len);
                var i: usize = 0;
                while (i < log.len) : (i += 1) {
                    retained.updateStoredMessage(&hasher, log.entry(i));
                }
            }

            var out: types.ContentHash = undefined;
            hasher.final(&out);
            return out;
        }

        fn findNewest(self: *Self, target: []const u8, msgid: []const u8) types.Error!*retained.StoredMessage {
            try validateTarget(target);
            const log = self.targets.getPtr(target) orelse return error.NotFound;

            var scanned: usize = 0;
            while (scanned < log.len) : (scanned += 1) {
                const logical_index = log.len - 1 - scanned;
                const entry = log.entryMut(logical_index);
                if (std.mem.eql(u8, entry.msgid, msgid)) return entry;
            }
            return error.NotFound;
        }

        fn validateText(text: []const u8) types.Error!void {
            if (text.len > params.max_text) return error.TextTooLong;
        }

        fn validateTargetForParams(target: []const u8) types.Error!void {
            try validateTarget(target);
            if (target.len > params.max_target) return error.TargetTooLong;
        }

        fn validateMessage(msg: types.InputMessage) types.Error!void {
            try validateText(msg.text);
            if (msg.msgid.len > params.max_msgid) return error.MsgidTooLong;
            if (msg.sender.len > params.max_sender) return error.SenderTooLong;
            if (msg.command.len > params.max_command) return error.CommandTooLong;
            if (msg.client_tags) |tags| {
                if (tags.len > params.max_client_tags) return error.ClientTagsTooLong;
            }
        }

        fn appendFitsCheckpoint(self: *const Self, target: []const u8, new_entry_len: usize) bool {
            var body_len = self.checkpoint_body_len;
            if (self.targets.get(target) == null) {
                body_len = std.math.add(usize, body_len, checkpoint.checkpoint_target_prefix_len) catch return false;
                body_len = std.math.add(usize, body_len, target.len) catch return false;
            }
            body_len = std.math.add(usize, body_len, new_entry_len) catch return false;
            return checkpoint.checkpointBodyFits(body_len, params.max_checkpoint_bytes);
        }

        fn evictGlobalOldest(self: *Self, incoming_target: []const u8) void {
            const candidate = self.globalOldest() orelse unreachable;
            const log = self.targets.getPtr(candidate.target).?;
            self.checkpoint_body_len -= checkpoint.checkpointStoredEntryBodyLen(log.entry(candidate.index));
            log.removeAt(self.allocator, candidate.index);
            if (log.len != 0 or std.mem.eql(u8, candidate.target, incoming_target)) return;

            var removed = self.targets.fetchRemove(candidate.target).?;
            self.checkpoint_body_len -= checkpoint.checkpoint_target_prefix_len + removed.key.len;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
        }

        fn globalOldest(self: *const Self) ?EvictionCandidate {
            var oldest: ?EvictionCandidate = null;
            var targets = self.targets.iterator();
            while (targets.next()) |target_entry| {
                const target = target_entry.key_ptr.*;
                const log = target_entry.value_ptr;
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    if (oldest) |current| {
                        const current_entry = self.targets.get(current.target).?.entry(current.index);
                        const entry = log.entry(index);
                        if (!isOlder(target, index, entry, current.target, current.index, current_entry)) continue;
                    }
                    oldest = .{ .target = target, .index = index };
                }
            }
            return oldest;
        }

        fn bodyLenAfterEdit(self: *const Self, entry: *const retained.StoredMessage, new_text_len: usize) types.Error!usize {
            const old_entry_len = checkpoint.checkpointStoredEntryBodyLen(entry);
            const without_old = std.math.sub(usize, self.checkpoint_body_len, old_entry_len) catch return error.CheckpointCapacityExceeded;
            const new_entry_len = try checkpoint.checkpointEntryBodyLenFromLengths(
                entry.msgid.len,
                entry.sender.len,
                new_text_len,
                entry.command.len,
                if (entry.client_tags) |tags| tags.len else 0,
            );
            const body_len = try checkpoint.checkpointBodyLenAdd(without_old, new_entry_len);
            try checkpoint.validateCheckpointBodyBudget(body_len, params.max_checkpoint_bytes);
            return body_len;
        }

        fn collectNewest(log: *const TargetLog, n: usize, out: []types.Message, bound: ?QueryBound) []const types.Message {
            var count: usize = 0;
            var scanned: usize = 0;
            while (scanned < log.len and count < n) : (scanned += 1) {
                const logical_index = log.len - 1 - scanned;
                const entry = log.entry(logical_index);
                if (entry.tombstone) continue;
                if (bound) |query_bound| switch (query_bound) {
                    .before => |timestamp| if (entry.timestamp >= timestamp) continue,
                };
                out[count] = entry.view();
                count += 1;
            }
            return out[0..count];
        }

        fn collectAfter(log: *const TargetLog, timestamp: u64, n: usize, out: []types.Message) []const types.Message {
            var count: usize = 0;
            var index: usize = 0;
            while (index < log.len and count < n) : (index += 1) {
                const entry = log.entry(index);
                if (entry.tombstone) continue;
                if (entry.timestamp <= timestamp) continue;
                out[count] = entry.view();
                count += 1;
            }
            return out[0..count];
        }
    };
}

pub fn HistoryStore(comptime params: types.Params) type {
    return Lotus(params);
}

fn isOlder(
    target: []const u8,
    index: usize,
    entry: *const retained.StoredMessage,
    other_target: []const u8,
    other_index: usize,
    other: *const retained.StoredMessage,
) bool {
    if (entry.timestamp != other.timestamp) return entry.timestamp < other.timestamp;
    switch (std.mem.order(u8, target, other_target)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (std.mem.order(u8, entry.msgid, other.msgid)) {
        .lt => return true,
        .gt => return false,
        .eq => return index < other_index,
    }
}

fn validateParams(comptime params: types.Params) void {
    if (params.max_targets == 0) @compileError("Lotus requires at least one target");
    if (params.max_per_target == 0) @compileError("Lotus requires at least one message per target");
    if (params.max_target == 0) @compileError("Lotus requires non-zero target capacity");
    if (params.max_checkpoint_bytes < checkpoint.checkpoint_header_len + checkpoint.checkpoint_checksum_len)
        @compileError("Lotus checkpoint byte limit cannot hold its header");
    inline for (.{
        params.max_targets,
        params.max_per_target,
        params.max_text,
        params.max_target,
        params.max_msgid,
        params.max_sender,
        params.max_command,
        params.max_client_tags,
        params.max_checkpoint_bytes,
    }) |limit| {
        if (limit > std.math.maxInt(u32)) @compileError("Lotus limits must fit checkpoint u32 fields");
    }
    _ = std.math.mul(usize, params.max_targets, params.max_per_target) catch
        @compileError("Lotus aggregate capacity overflows usize");
}

fn validateTarget(target: []const u8) types.Error!void {
    if (target.len == 0) return error.InvalidTarget;
}

fn validateOutput(n: usize, out: []types.Message) types.Error!void {
    if (out.len < n) return error.OutputTooSmall;
}

fn optionalBytesEqual(lhs: ?[]const u8, rhs: ?[]const u8) bool {
    if (lhs) |left| {
        const right = rhs orelse return false;
        return std.mem.eql(u8, left, right);
    }
    return rhs == null;
}

fn bytesLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}
