// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lotus: pure in-memory IRC message history rings.
//!
//! This module performs no I/O. It owns duplicated target keys and message
//! strings, bounds target count and per-target history length at comptime, and
//! returns borrowed read views that remain valid until the next mutation.
const std = @import("std");

const Blake3 = std.crypto.hash.Blake3;

pub const ContentHash = [Blake3.digest_length]u8;

pub const Params = struct {
    max_targets: usize,
    max_per_target: usize,
    max_text: usize,
    max_target: usize = 1024,
    max_msgid: usize = 1024,
    max_sender: usize = 1024,
    max_command: usize = 64,
    max_client_tags: usize = 8 * 1024,
    max_checkpoint_bytes: usize = 64 * 1024 * 1024,
};

pub const InputMessage = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    /// IRC command this history entry replays as. "PRIVMSG"/"NOTICE" are ordinary
    /// messages; anything else (e.g. "TOPIC") is a draft/event-playback event,
    /// replayed only to clients that negotiated `event-playback`. The store
    /// owns a duplicate, so restored checkpoint commands never borrow the
    /// checkpoint buffer.
    command: []const u8 = "PRIVMSG",
    /// Sanitized client-only tag segment for TAGMSG history replay, without the
    /// leading '@'. Null for entries that do not carry client tags.
    client_tags: ?[]const u8 = null,
};

/// Complete retained state used by conflict-aware mesh ingestion. `text` is
/// the current text after any edit and `tombstone` is the current redaction
/// state; both therefore participate in exact-duplicate classification.
pub const ExactInputMessage = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    command: []const u8 = "PRIVMSG",
    client_tags: ?[]const u8 = null,
    tombstone: bool = false,

    fn input(self: ExactInputMessage) InputMessage {
        return .{
            .msgid = self.msgid,
            .sender = self.sender,
            .text = self.text,
            .timestamp = self.timestamp,
            .command = self.command,
            .client_tags = self.client_tags,
        };
    }
};

pub const Message = struct {
    hash: ContentHash = @splat(0),
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    tombstone: bool,
    command: []const u8 = "PRIVMSG",
    client_tags: ?[]const u8 = null,
};

pub const AppendResult = struct {
    evicted: bool,
    target_len: usize,
};

pub const ExactOnceResult = union(enum) {
    inserted: AppendResult,
    exact_duplicate,
    equivocation,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidTarget,
    TargetLimitExceeded,
    TargetTooLong,
    MsgidTooLong,
    SenderTooLong,
    CommandTooLong,
    ClientTagsTooLong,
    /// Retaining this mutation would make the canonical checkpoint exceed the
    /// concrete store's configured byte limit. The store is unchanged.
    CheckpointCapacityExceeded,
    TextTooLong,
    OutputTooSmall,
    NotFound,
};

pub const CheckpointError = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    ConfigMismatch,
    CapacityExceeded,
    CheckpointTooLarge,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    NonCanonicalOrder,
    InvalidField,
    InvalidHash,
};

const checkpoint_magic = [4]u8{ 'L', 'T', 'H', 'C' };
const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 52;
const checkpoint_checksum_len: usize = Blake3.digest_length;
const checkpoint_target_prefix_len: usize = 8;
const checkpoint_entry_prefix_len: usize = 1 + 8 + Blake3.digest_length + 5 * 4;
const checkpoint_flag_tombstone: u8 = 1 << 0;
const checkpoint_flag_has_tags: u8 = 1 << 1;

pub fn Lotus(comptime params: Params) type {
    comptime validateParams(params);

    return struct {
        const Self = @This();

        const TargetLog = struct {
            entries: []StoredMessage,
            start: usize,
            len: usize,

            fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!TargetLog {
                return .{
                    .entries = try allocator.alloc(StoredMessage, params.max_per_target),
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

            fn appendTake(self: *TargetLog, allocator: std.mem.Allocator, msg: StoredMessage) bool {
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

            fn entry(self: *const TargetLog, logical_index: usize) *const StoredMessage {
                return &self.entries[self.slot(logical_index)];
            }

            fn entryMut(self: *TargetLog, logical_index: usize) *StoredMessage {
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
            message: Message,
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
        pub fn ingestExactOnce(self: *Self, target: []const u8, msg: ExactInputMessage) Error!ExactOnceResult {
            try validateTargetForParams(target);
            const input = msg.input();
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
        pub fn append(self: *Self, target: []const u8, msg: InputMessage) Error!AppendResult {
            try validateTargetForParams(target);
            try validateMessage(msg);
            return self.appendState(target, msg, false);
        }

        fn appendState(self: *Self, target: []const u8, msg: InputMessage, tombstone: bool) Error!AppendResult {
            if (self.targets.get(target) == null and self.targets.count() >= params.max_targets)
                return error.TargetLimitExceeded;
            const new_entry_len = try checkpointEntryBodyLen(msg);
            const minimum_body_len = try checkpointBodyLenAdd(checkpoint_target_prefix_len + target.len, new_entry_len);
            if (!checkpointBodyFits(minimum_body_len, params.max_checkpoint_bytes))
                return error.CheckpointCapacityExceeded;
            var stored = try StoredMessage.init(self.allocator, msg);
            errdefer stored.deinit(self.allocator);
            stored.tombstone = tombstone;

            if (self.targets.get(target) != null) {
                var evicted = false;
                {
                    const log = self.targets.getPtr(target).?;
                    if (log.len == params.max_per_target) {
                        self.checkpoint_body_len -= checkpointStoredEntryBodyLen(log.entry(0));
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
            self.checkpoint_body_len += checkpoint_target_prefix_len + target.len + new_entry_len;
            return .{ .evicted = evicted, .target_len = inserted.len };
        }

        pub fn latest(self: *const Self, target: []const u8, n: usize, out: []Message) Error![]const Message {
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
            out: []Message,
        ) Error![]const Message {
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
            out: []Message,
        ) Error![]const Message {
            try validateTarget(target);
            try validateOutput(n, out);
            const log = self.targets.get(target) orelse return out[0..0];
            return collectAfter(&log, timestamp, n, out);
        }

        pub fn redact(self: *Self, target: []const u8, msgid: []const u8) Error!void {
            const entry = try self.findNewest(target, msgid);
            entry.tombstone = true;
        }

        pub fn edit(self: *Self, target: []const u8, msgid: []const u8, new_text: []const u8) Error!void {
            try validateText(new_text);
            const entry = try self.findNewest(target, msgid);
            const new_body_len = try self.bodyLenAfterEdit(entry, new_text.len);
            const owned_text = try self.allocator.dupe(u8, new_text);
            self.allocator.free(entry.text);
            entry.text = owned_text;
            entry.hash = hashText(new_text);
            self.checkpoint_body_len = new_body_len;
        }

        /// Resolve a message's server timestamp by its msgid within `target`, or
        /// null when no such message exists. Translates CHATHISTORY msgid
        /// selectors into the timestamp bounds the paging queries operate on.
        pub fn timestampOf(self: *Self, target: []const u8, msgid: []const u8) ?u64 {
            const found = self.findNewest(target, msgid) catch return null;
            return found.timestamp;
        }

        pub fn storedCount(self: *const Self, target: []const u8) Error!usize {
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
        pub fn encodeCheckpoint(self: *const Self, allocator: std.mem.Allocator) CheckpointError![]u8 {
            var canonical = self.deterministicIterator();
            var body_len: usize = 0;
            for (canonical.target_keys[0..canonical.target_count]) |target| {
                const log = self.targets.get(target).?;
                if (log.len == 0 or log.len > params.max_per_target) return error.InvalidField;
                body_len = try checkpointLenAdd(body_len, checkpoint_target_prefix_len, params.max_checkpoint_bytes);
                body_len = try checkpointLenAdd(body_len, target.len, params.max_checkpoint_bytes);
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    const message = log.entry(index);
                    try validateCheckpointStoredMessage(message);
                    body_len = try checkpointLenAdd(body_len, checkpoint_entry_prefix_len, params.max_checkpoint_bytes);
                    body_len = try checkpointLenAdd(body_len, message.msgid.len, params.max_checkpoint_bytes);
                    body_len = try checkpointLenAdd(body_len, message.sender.len, params.max_checkpoint_bytes);
                    body_len = try checkpointLenAdd(body_len, message.text.len, params.max_checkpoint_bytes);
                    body_len = try checkpointLenAdd(body_len, message.command.len, params.max_checkpoint_bytes);
                    body_len = try checkpointLenAdd(body_len, if (message.client_tags) |tags| tags.len else 0, params.max_checkpoint_bytes);
                }
            }
            // Append and edit admission maintain this exact value. Keeping the
            // check here makes corruption fail closed as well, without changing
            // the v1 wire format.
            if (body_len != self.checkpoint_body_len) return error.InvalidField;
            const prefix_len = try checkpointLenAdd(checkpoint_header_len, body_len, params.max_checkpoint_bytes);
            const total_len = try checkpointLenAdd(prefix_len, checkpoint_checksum_len, params.max_checkpoint_bytes);
            const out = try allocator.alloc(u8, total_len);
            errdefer allocator.free(out);

            @memcpy(out[0..checkpoint_magic.len], &checkpoint_magic);
            out[4] = checkpoint_version;
            out[5] = 0;
            writeU16(out[6..8], 0);
            writeU32(out[8..12], @intCast(params.max_targets));
            writeU32(out[12..16], @intCast(params.max_per_target));
            writeU32(out[16..20], @intCast(params.max_text));
            writeU32(out[20..24], @intCast(params.max_target));
            writeU32(out[24..28], @intCast(params.max_msgid));
            writeU32(out[28..32], @intCast(params.max_sender));
            writeU32(out[32..36], @intCast(params.max_command));
            writeU32(out[36..40], @intCast(params.max_client_tags));
            writeU32(out[40..44], @intCast(canonical.target_count));
            writeU32(out[44..48], @intCast(self.totalStoredCount()));
            writeU32(out[48..52], @intCast(body_len));

            var pos: usize = checkpoint_header_len;
            for (canonical.target_keys[0..canonical.target_count]) |target| {
                const log = self.targets.get(target).?;
                writeU32(out[pos..][0..4], @intCast(target.len));
                pos += 4;
                writeU32(out[pos..][0..4], @intCast(log.len));
                pos += 4;
                @memcpy(out[pos..][0..target.len], target);
                pos += target.len;
                var index: usize = 0;
                while (index < log.len) : (index += 1) {
                    const message = log.entry(index);
                    var flags: u8 = if (message.tombstone) checkpoint_flag_tombstone else 0;
                    if (message.client_tags != null) flags |= checkpoint_flag_has_tags;
                    out[pos] = flags;
                    pos += 1;
                    writeU64(out[pos..][0..8], message.timestamp);
                    pos += 8;
                    @memcpy(out[pos..][0..@sizeOf(ContentHash)], &message.hash);
                    pos += @sizeOf(ContentHash);
                    const tags = message.client_tags orelse "";
                    writeU32(out[pos..][0..4], @intCast(message.msgid.len));
                    pos += 4;
                    writeU32(out[pos..][0..4], @intCast(message.sender.len));
                    pos += 4;
                    writeU32(out[pos..][0..4], @intCast(message.text.len));
                    pos += 4;
                    writeU32(out[pos..][0..4], @intCast(message.command.len));
                    pos += 4;
                    writeU32(out[pos..][0..4], @intCast(tags.len));
                    pos += 4;
                    for ([_][]const u8{ message.msgid, message.sender, message.text, message.command, tags }) |field| {
                        @memcpy(out[pos..][0..field.len], field);
                        pos += field.len;
                    }
                }
            }
            std.debug.assert(pos == prefix_len);
            checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checkpoint_checksum_len]);
            return out;
        }

        /// Decode without publishing any state. Resource authority must match
        /// this concrete Lotus instantiation exactly, except that an older
        /// positive text ceiling may be restored into a larger current store.
        /// This preserves v1 checkpoint framing while allowing a history text
        /// capacity increase without stranding existing checkpoints.
        pub fn decodeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) CheckpointError!Self {
            if (bytes.len > params.max_checkpoint_bytes) return error.CheckpointTooLarge;
            if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
            if (!std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic)) return error.BadMagic;
            if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
            if (bytes[5] != 0 or readU16(bytes[6..8]) != 0) return error.InvalidField;
            const encoded_max_text: usize = readU32(bytes[16..20]);
            if (readU32(bytes[8..12]) != params.max_targets or
                readU32(bytes[12..16]) != params.max_per_target or
                encoded_max_text == 0 or encoded_max_text > params.max_text or
                readU32(bytes[20..24]) != params.max_target or
                readU32(bytes[24..28]) != params.max_msgid or
                readU32(bytes[28..32]) != params.max_sender or
                readU32(bytes[32..36]) != params.max_command or
                readU32(bytes[36..40]) != params.max_client_tags)
                return error.ConfigMismatch;

            const target_count: usize = readU32(bytes[40..44]);
            const declared_total: usize = readU32(bytes[44..48]);
            const body_len: usize = readU32(bytes[48..52]);
            if (target_count > params.max_targets or
                declared_total > params.max_targets * params.max_per_target)
                return error.CapacityExceeded;
            const prefix_len = try checkpointLenAdd(checkpoint_header_len, body_len, params.max_checkpoint_bytes);
            const expected_len = try checkpointLenAdd(prefix_len, checkpoint_checksum_len, params.max_checkpoint_bytes);
            if (bytes.len < expected_len) return error.Truncated;
            if (bytes.len > expected_len) return error.TrailingBytes;
            var actual_checksum: [checkpoint_checksum_len]u8 = undefined;
            checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
            if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

            var restored = Self.init(allocator);
            errdefer restored.deinit();
            var reader = CheckpointReader{ .bytes = bytes, .pos = checkpoint_header_len, .end = prefix_len };
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
                    if (flags & ~(checkpoint_flag_tombstone | checkpoint_flag_has_tags) != 0)
                        return error.InvalidField;
                    const timestamp = try reader.takeU64();
                    const encoded_hash: ContentHash = (try reader.readBytes(@sizeOf(ContentHash)))[0..@sizeOf(ContentHash)].*;
                    const msgid_len: usize = try reader.takeU32();
                    const sender_len: usize = try reader.takeU32();
                    const text_len: usize = try reader.takeU32();
                    const command_len: usize = try reader.takeU32();
                    const tags_len: usize = try reader.takeU32();
                    if (msgid_len > params.max_msgid or sender_len > params.max_sender or
                        text_len > encoded_max_text or text_len > params.max_text or command_len > params.max_command or
                        tags_len > params.max_client_tags)
                        return error.CapacityExceeded;
                    const has_tags = flags & checkpoint_flag_has_tags != 0;
                    if (!has_tags and tags_len != 0) return error.InvalidField;
                    const msgid = try reader.readBytes(msgid_len);
                    const sender = try reader.readBytes(sender_len);
                    const text = try reader.readBytes(text_len);
                    const command = try reader.readBytes(command_len);
                    const tags = try reader.readBytes(tags_len);
                    const computed_hash = hashText(text);
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
                    log.entryMut(log.len - 1).tombstone = flags & checkpoint_flag_tombstone != 0;
                    actual_total += 1;
                }
            }
            if (reader.pos != reader.end) return error.TrailingBytes;
            if (actual_total != declared_total) return error.InvalidField;
            return restored;
        }

        /// Transactional live replacement. Decode and allocate the complete new
        /// image first; malformed input or OOM leaves `self` byte-for-byte intact.
        pub fn replaceFromCheckpoint(self: *Self, bytes: []const u8) CheckpointError!void {
            const replacement = try Self.decodeCheckpoint(self.allocator, bytes);
            var old = self.*;
            self.* = replacement;
            old.deinit();
        }

        fn validateCheckpointStoredMessage(message: *const StoredMessage) CheckpointError!void {
            if (message.msgid.len > params.max_msgid or message.sender.len > params.max_sender or
                message.text.len > params.max_text or message.command.len > params.max_command)
                return error.CapacityExceeded;
            if (message.client_tags) |tags| {
                if (tags.len > params.max_client_tags) return error.CapacityExceeded;
            }
            const expected_hash = hashText(message.text);
            if (!std.mem.eql(u8, &message.hash, &expected_hash)) return error.InvalidHash;
        }

        fn storedMatchesExact(existing: *const StoredMessage, incoming: ExactInputMessage) bool {
            const expected_hash = hashText(incoming.text);
            return std.mem.eql(u8, existing.sender, incoming.sender) and
                std.mem.eql(u8, existing.text, incoming.text) and
                existing.timestamp == incoming.timestamp and
                std.mem.eql(u8, existing.command, incoming.command) and
                optionalBytesEqual(existing.client_tags, incoming.client_tags) and
                existing.tombstone == incoming.tombstone and
                std.mem.eql(u8, &existing.hash, &expected_hash);
        }

        pub fn root(self: *const Self) ContentHash {
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
            updateLen(&hasher, count);
            for (keys[0..count]) |target| {
                const log = self.targets.get(target).?;
                updateBytes(&hasher, target);
                updateLen(&hasher, log.len);
                var i: usize = 0;
                while (i < log.len) : (i += 1) {
                    updateStoredMessage(&hasher, log.entry(i));
                }
            }

            var out: ContentHash = undefined;
            hasher.final(&out);
            return out;
        }

        fn findNewest(self: *Self, target: []const u8, msgid: []const u8) Error!*StoredMessage {
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

        fn validateText(text: []const u8) Error!void {
            if (text.len > params.max_text) return error.TextTooLong;
        }

        fn validateTargetForParams(target: []const u8) Error!void {
            try validateTarget(target);
            if (target.len > params.max_target) return error.TargetTooLong;
        }

        fn validateMessage(msg: InputMessage) Error!void {
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
                body_len = std.math.add(usize, body_len, checkpoint_target_prefix_len) catch return false;
                body_len = std.math.add(usize, body_len, target.len) catch return false;
            }
            body_len = std.math.add(usize, body_len, new_entry_len) catch return false;
            return checkpointBodyFits(body_len, params.max_checkpoint_bytes);
        }

        fn evictGlobalOldest(self: *Self, incoming_target: []const u8) void {
            const candidate = self.globalOldest() orelse unreachable;
            const log = self.targets.getPtr(candidate.target).?;
            self.checkpoint_body_len -= checkpointStoredEntryBodyLen(log.entry(candidate.index));
            log.removeAt(self.allocator, candidate.index);
            if (log.len != 0 or std.mem.eql(u8, candidate.target, incoming_target)) return;

            var removed = self.targets.fetchRemove(candidate.target).?;
            self.checkpoint_body_len -= checkpoint_target_prefix_len + removed.key.len;
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

        fn bodyLenAfterEdit(self: *const Self, entry: *const StoredMessage, new_text_len: usize) Error!usize {
            const old_entry_len = checkpointStoredEntryBodyLen(entry);
            const without_old = std.math.sub(usize, self.checkpoint_body_len, old_entry_len) catch return error.CheckpointCapacityExceeded;
            const new_entry_len = try checkpointEntryBodyLenFromLengths(
                entry.msgid.len,
                entry.sender.len,
                new_text_len,
                entry.command.len,
                if (entry.client_tags) |tags| tags.len else 0,
            );
            const body_len = try checkpointBodyLenAdd(without_old, new_entry_len);
            try validateCheckpointBodyBudget(body_len, params.max_checkpoint_bytes);
            return body_len;
        }

        fn collectNewest(log: *const TargetLog, n: usize, out: []Message, bound: ?QueryBound) []const Message {
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

        fn collectAfter(log: *const TargetLog, timestamp: u64, n: usize, out: []Message) []const Message {
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

pub fn HistoryStore(comptime params: Params) type {
    return Lotus(params);
}

const StoredMessage = struct {
    hash: ContentHash,
    msgid: []u8,
    sender: []u8,
    text: []u8,
    timestamp: u64,
    tombstone: bool,
    command: []u8,
    client_tags: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator, msg: InputMessage) std.mem.Allocator.Error!StoredMessage {
        var stored = StoredMessage{
            .hash = hashText(msg.text),
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = msg.timestamp,
            .tombstone = false,
            .command = &.{},
            .client_tags = null,
        };
        errdefer stored.deinit(allocator);

        stored.msgid = try allocator.dupe(u8, msg.msgid);
        stored.sender = try allocator.dupe(u8, msg.sender);
        stored.text = try allocator.dupe(u8, msg.text);
        stored.command = try allocator.dupe(u8, msg.command);
        if (msg.client_tags) |tags| stored.client_tags = try allocator.dupe(u8, tags);
        return stored;
    }

    fn deinit(self: *StoredMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.msgid);
        allocator.free(self.sender);
        allocator.free(self.text);
        allocator.free(self.command);
        if (self.client_tags) |tags| allocator.free(tags);
        self.* = .{
            .hash = @splat(0),
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = 0,
            .tombstone = false,
            .command = &.{},
            .client_tags = null,
        };
    }

    fn view(self: *const StoredMessage) Message {
        return .{
            .hash = self.hash,
            .msgid = self.msgid,
            .sender = self.sender,
            .text = self.text,
            .timestamp = self.timestamp,
            .tombstone = self.tombstone,
            .command = self.command,
            .client_tags = self.client_tags,
        };
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize,
    end: usize,

    fn takeU8(self: *CheckpointReader) CheckpointError!u8 {
        const bytes = try self.readBytes(1);
        return bytes[0];
    }

    fn takeU32(self: *CheckpointReader) CheckpointError!u32 {
        return readU32(try self.readBytes(4));
    }

    fn takeU64(self: *CheckpointReader) CheckpointError!u64 {
        return readU64(try self.readBytes(8));
    }

    fn readBytes(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (self.pos > self.end or len > self.end - self.pos) return error.Truncated;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
};

fn checkpointLenAdd(current: usize, additional: usize, max: usize) CheckpointError!usize {
    const result = std.math.add(usize, current, additional) catch return error.CheckpointTooLarge;
    if (result > max or result > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    return result;
}

fn checkpointBodyLenAdd(current: usize, additional: usize) Error!usize {
    return std.math.add(usize, current, additional) catch error.CheckpointCapacityExceeded;
}

fn checkpointEntryBodyLen(msg: InputMessage) Error!usize {
    return checkpointEntryBodyLenFromLengths(
        msg.msgid.len,
        msg.sender.len,
        msg.text.len,
        msg.command.len,
        if (msg.client_tags) |tags| tags.len else 0,
    );
}

fn checkpointStoredEntryBodyLen(message: *const StoredMessage) usize {
    return checkpoint_entry_prefix_len + message.msgid.len + message.sender.len + message.text.len + message.command.len + if (message.client_tags) |tags| tags.len else 0;
}

fn checkpointEntryBodyLenFromLengths(msgid_len: usize, sender_len: usize, text_len: usize, command_len: usize, tags_len: usize) Error!usize {
    var len = checkpoint_entry_prefix_len;
    len = try checkpointBodyLenAdd(len, msgid_len);
    len = try checkpointBodyLenAdd(len, sender_len);
    len = try checkpointBodyLenAdd(len, text_len);
    len = try checkpointBodyLenAdd(len, command_len);
    return checkpointBodyLenAdd(len, tags_len);
}

fn validateCheckpointBodyBudget(body_len: usize, max_checkpoint_bytes: usize) Error!void {
    const with_header = std.math.add(usize, checkpoint_header_len, body_len) catch return error.CheckpointCapacityExceeded;
    const total = std.math.add(usize, with_header, checkpoint_checksum_len) catch return error.CheckpointCapacityExceeded;
    if (total > max_checkpoint_bytes or total > std.math.maxInt(u32)) return error.CheckpointCapacityExceeded;
}

fn checkpointBodyFits(body_len: usize, max_checkpoint_bytes: usize) bool {
    const with_header = std.math.add(usize, checkpoint_header_len, body_len) catch return false;
    const total = std.math.add(usize, with_header, checkpoint_checksum_len) catch return false;
    return total <= max_checkpoint_bytes and total <= std.math.maxInt(u32);
}

fn isOlder(
    target: []const u8,
    index: usize,
    entry: *const StoredMessage,
    other_target: []const u8,
    other_index: usize,
    other: *const StoredMessage,
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

fn checkpointChecksum(prefix: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = Blake3.init(.{});
    hasher.update("onyx_server.lotus.checkpoint.v1");
    hasher.update(prefix);
    hasher.final(out);
}

fn rewriteCheckpointChecksum(bytes: []u8) void {
    if (bytes.len < checkpoint_checksum_len) return;
    const prefix_len = bytes.len - checkpoint_checksum_len;
    checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checkpoint_checksum_len]);
}

fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

fn writeU64(out: []u8, value: u64) void {
    std.mem.writeInt(u64, out[0..8], value, .big);
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn readU64(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .big);
}

fn validateParams(comptime params: Params) void {
    if (params.max_targets == 0) @compileError("Lotus requires at least one target");
    if (params.max_per_target == 0) @compileError("Lotus requires at least one message per target");
    if (params.max_target == 0) @compileError("Lotus requires non-zero target capacity");
    if (params.max_checkpoint_bytes < checkpoint_header_len + checkpoint_checksum_len)
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

fn validateTarget(target: []const u8) Error!void {
    if (target.len == 0) return error.InvalidTarget;
}

fn validateOutput(n: usize, out: []Message) Error!void {
    if (out.len < n) return error.OutputTooSmall;
}

fn hashText(text: []const u8) ContentHash {
    var out: ContentHash = undefined;
    Blake3.hash(text, &out, .{});
    return out;
}

fn optionalBytesEqual(lhs: ?[]const u8, rhs: ?[]const u8) bool {
    if (lhs) |left| {
        const right = rhs orelse return false;
        return std.mem.eql(u8, left, right);
    }
    return rhs == null;
}

fn updateLen(hasher: anytype, len: usize) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, @intCast(len), .little);
    hasher.update(&buf);
}

fn updateU64(hasher: anytype, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    hasher.update(&buf);
}

fn updateBytes(hasher: anytype, bytes: []const u8) void {
    updateLen(hasher, bytes.len);
    hasher.update(bytes);
}

fn updateStoredMessage(hasher: anytype, entry: *const StoredMessage) void {
    hasher.update("entry");
    updateBytes(hasher, entry.msgid);
    updateBytes(hasher, entry.sender);
    updateBytes(hasher, entry.command);
    updateBytes(hasher, entry.client_tags orelse "");
    updateU64(hasher, entry.timestamp);
    hasher.update(if (entry.tombstone) "t" else "l");
    hasher.update(&entry.hash);
}

fn bytesLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

test "append evicts oldest and latest returns newest first" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    const result = try store.append("#lotus", .{
        .msgid = "m4",
        .sender = "alice",
        .text = "four",
        .timestamp = 4,
    });

    try std.testing.expect(result.evicted);
    try std.testing.expectEqual(@as(usize, 3), result.target_len);

    var out: [3]Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try expectMsg(got[0], "m4", 4, "four");
    try expectMsg(got[1], "m3", 3, "three");
    try expectMsg(got[2], "m2", 2, "two");
}

test "latest before and after page visible messages correctly" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 5, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try appendForTest(&store, "#lotus", "m4", 4, "four");
    try appendForTest(&store, "#lotus", "m5", 5, "five");

    var latest_out: [3]Message = undefined;
    const latest_page = try store.latest("#lotus", 3, &latest_out);
    try expectIds(latest_page, &.{ "m5", "m4", "m3" });

    var before_out: [2]Message = undefined;
    const before_page = try store.before("#lotus", 4, 2, &before_out);
    try expectIds(before_page, &.{ "m3", "m2" });

    var after_out: [3]Message = undefined;
    const after_page = try store.after("#lotus", 2, 3, &after_out);
    try expectIds(after_page, &.{ "m3", "m4", "m5" });
}

test "between window composes after() with an upper-bound filter" {
    // Mirrors the CHATHISTORY BETWEEN wiring in the daemon: collect oldest-first
    // after the low bound, then keep only those strictly before the high bound.
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 8, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try appendForTest(&store, "#lotus", "m4", 4, "four");
    try appendForTest(&store, "#lotus", "m5", 5, "five");

    // BETWEEN (1, 5): strictly between -> m2, m3, m4.
    var buf: [8]Message = undefined;
    const raw = try store.after("#lotus", 1, buf.len, &buf);
    var k: usize = 0;
    for (raw) |m| {
        if (m.timestamp < 5) {
            buf[k] = m;
            k += 1;
        }
    }
    try expectIds(buf[0..k], &.{ "m2", "m3", "m4" });
}

test "timestampOf resolves a msgid to its timestamp" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 4, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try appendForTest(&store, "#lotus", "m1", 11, "one");
    try appendForTest(&store, "#lotus", "m2", 22, "two");

    try std.testing.expectEqual(@as(?u64, 22), store.timestampOf("#lotus", "m2"));
    try std.testing.expectEqual(@as(?u64, 11), store.timestampOf("#lotus", "m1"));
    try std.testing.expectEqual(@as(?u64, null), store.timestampOf("#lotus", "nope"));
    try std.testing.expectEqual(@as(?u64, null), store.timestampOf("#absent", "m1"));
}

test "around window composes before() reversed + after() at the pivot" {
    // Mirrors the CHATHISTORY AROUND wiring: ~half strictly before the pivot
    // (reversed to chronological), then the pivot and later, oldest-first.
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 8, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try appendForTest(&store, "#lotus", "m4", 4, "four");
    try appendForTest(&store, "#lotus", "m5", 5, "five");

    // AROUND pivot=3, limit=4 -> half=2 before (m1,m2) + pivot/after (m3,m4).
    const center: u64 = 3;
    const total: usize = 4;
    const half = total / 2;
    var before_buf: [8]Message = undefined;
    var after_buf: [8]Message = undefined;
    const before_part = try store.before("#lotus", center, half, before_buf[0..half]);
    const remaining = total - before_part.len;
    const after_part = try store.after("#lotus", center - 1, remaining, after_buf[0..remaining]);
    var out: [8]Message = undefined;
    var k: usize = 0;
    var i: usize = before_part.len;
    while (i > 0) {
        i -= 1;
        out[k] = before_part[i];
        k += 1;
    }
    for (after_part) |m| {
        out[k] = m;
        k += 1;
    }
    try expectIds(out[0..k], &.{ "m1", "m2", "m3", "m4" });
}

test "redact hides reads but keeps slot" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#lotus", "m1", 1, "one");
    try appendForTest(&store, "#lotus", "m2", 2, "two");
    try appendForTest(&store, "#lotus", "m3", 3, "three");
    try store.redact("#lotus", "m2");

    try std.testing.expectEqual(@as(usize, 3), try store.storedCount("#lotus"));

    var out: [3]Message = undefined;
    const got = try store.latest("#lotus", 3, &out);
    try expectIds(got, &.{ "m3", "m1" });
}

test "aggregate counts expose targets entries and tombstones" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "#a", "a1", 1, "one");
    try appendForTest(&store, "#a", "a2", 2, "two");
    try appendForTest(&store, "#b", "b1", 3, "three");
    try store.redact("#a", "a1");

    try std.testing.expectEqual(@as(usize, 2), store.targetCount());
    try std.testing.expectEqual(@as(usize, 3), store.totalStoredCount());
    try std.testing.expectEqual(@as(usize, 1), store.tombstoneCount());
}

test "root is deterministic and changes on edits and tombstones" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 3, .max_text = 32 });
    var first = Store.init(std.testing.allocator);
    defer first.deinit();
    var second = Store.init(std.testing.allocator);
    defer second.deinit();

    try appendForTest(&first, "#b", "b1", 3, "three");
    try appendForTest(&first, "#a", "a1", 1, "one");
    try appendForTest(&first, "#a", "a2", 2, "two");

    try appendForTest(&second, "#a", "a1", 1, "one");
    try appendForTest(&second, "#a", "a2", 2, "two");
    try appendForTest(&second, "#b", "b1", 3, "three");

    const before = first.root();
    try std.testing.expectEqualSlices(u8, &before, &second.root());

    try first.edit("#a", "a2", "two-edited");
    const edited = first.root();
    try std.testing.expect(!std.mem.eql(u8, &before, &edited));

    try first.redact("#a", "a1");
    const redacted = first.root();
    try std.testing.expect(!std.mem.eql(u8, &edited, &redacted));
}

test "edit replaces message text" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try appendForTest(&store, "kain", "m1", 1, "before");
    try store.edit("kain", "m1", "after");

    var out: [1]Message = undefined;
    const got = try store.latest("kain", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try expectMsg(got[0], "m1", 1, "after");
    const after_hash = hashText("after");
    const before_hash = hashText("before");
    try std.testing.expectEqualSlices(u8, &after_hash, &got[0].hash);
    try std.testing.expect(!std.mem.eql(u8, &before_hash, &got[0].hash));
}

test "client tags are retained for TAGMSG entries" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.append("#lotus", .{
        .msgid = "m1",
        .sender = "alice",
        .text = "",
        .timestamp = 1,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/reply=m0;+draft/react=ok",
    });

    var out: [1]Message = undefined;
    const got = try store.latest("#lotus", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), got.len);
    try std.testing.expectEqualStrings("TAGMSG", got[0].command);
    try std.testing.expectEqualStrings("+typing=active;+draft/reply=m0;+draft/react=ok", got[0].client_tags.?);
}

test "exact-once ingestion classifies every retained identity field without mutation" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 4, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const original = ExactInputMessage{
        .msgid = "mesh-1",
        .sender = "alice",
        .text = "hello",
        .timestamp = 11,
        .command = "NOTICE",
        .client_tags = "+draft/reply=mesh-0",
    };
    switch (try store.ingestExactOnce("#lotus", original)) {
        .inserted => |result| {
            try std.testing.expect(!result.evicted);
            try std.testing.expectEqual(@as(usize, 1), result.target_len);
        },
        else => return error.TestUnexpectedResult,
    }

    const before = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(before);
    switch (try store.ingestExactOnce("#lotus", original)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }

    const conflicts = [_]ExactInputMessage{
        .{ .msgid = "mesh-1", .sender = "mallory", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "changed", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 12, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "PRIVMSG", .client_tags = "+draft/reply=mesh-0" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = null },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "" },
        .{ .msgid = "mesh-1", .sender = "alice", .text = "hello", .timestamp = 11, .command = "NOTICE", .client_tags = "+draft/reply=mesh-0", .tombstone = true },
    };
    for (conflicts) |conflict| {
        switch (try store.ingestExactOnce("#lotus", conflict)) {
            .equivocation => {},
            else => return error.TestUnexpectedResult,
        }
        const after_conflict = try store.encodeCheckpoint(std.testing.allocator);
        defer std.testing.allocator.free(after_conflict);
        try std.testing.expectEqualSlices(u8, before, after_conflict);
    }

    // A msgid is global within the retained Lotus window, not target-scoped.
    switch (try store.ingestExactOnce("#other", original)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), store.targetCount());
    const after = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "exact-once ingestion tracks edited and redacted retained state" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 3, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const original = ExactInputMessage{
        .msgid = "mesh-edit",
        .sender = "alice",
        .text = "before",
        .timestamp = 20,
    };
    switch (try store.ingestExactOnce("#lotus", original)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    try store.edit("#lotus", original.msgid, "after");

    switch (try store.ingestExactOnce("#lotus", original)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const edited = ExactInputMessage{
        .msgid = original.msgid,
        .sender = original.sender,
        .text = "after",
        .timestamp = original.timestamp,
    };
    switch (try store.ingestExactOnce("#lotus", edited)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }

    try store.redact("#lotus", original.msgid);
    const before = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(before);
    switch (try store.ingestExactOnce("#lotus", edited)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const redacted = ExactInputMessage{
        .msgid = original.msgid,
        .sender = original.sender,
        .text = "after",
        .timestamp = original.timestamp,
        .tombstone = true,
    };
    switch (try store.ingestExactOnce("#lotus", redacted)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    const after = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "exact-once ingestion preserves eviction boundaries and legacy append semantics" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 2, .max_text = 32 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const first = ExactInputMessage{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 };
    const second = ExactInputMessage{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 };
    const third = ExactInputMessage{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 };
    switch (try store.ingestExactOnce("#lotus", first)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#lotus", second)) {
        .inserted => {},
        else => return error.TestUnexpectedResult,
    }
    const full_root = store.root();
    switch (try store.ingestExactOnce("#lotus", first)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#lotus", .{ .msgid = "m1", .sender = "alice", .text = "conflict", .timestamp = 1 })) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualSlices(u8, &full_root, &store.root());

    switch (try store.ingestExactOnce("#lotus", third)) {
        .inserted => |result| try std.testing.expect(result.evicted),
        else => return error.TestUnexpectedResult,
    }
    // Once m1 has left the bounded retained window it can be inserted again.
    switch (try store.ingestExactOnce("#lotus", first)) {
        .inserted => |result| try std.testing.expect(result.evicted),
        else => return error.TestUnexpectedResult,
    }
    var out: [2]Message = undefined;
    try expectIds(try store.latest("#lotus", 2, &out), &.{ "m1", "m3" });

    // The existing append API still accepts a repeated msgid by design.
    var legacy = Store.init(std.testing.allocator);
    defer legacy.deinit();
    _ = try legacy.append("#lotus", first.input());
    _ = try legacy.append("#lotus", .{ .msgid = "m1", .sender = "alice", .text = "different", .timestamp = 2 });
    try std.testing.expectEqual(@as(usize, 2), legacy.totalStoredCount());
}

test "exact-once ingestion is atomic across allocation failures and non-inserts allocate nothing" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 2, .max_text = 32 });
    const FullRingSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 });
            const before = store.root();
            const outcome = store.ingestExactOnce("#a", .{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 }) catch |err| {
                try std.testing.expectEqualSlices(u8, &before, &store.root());
                try std.testing.expectEqual(@as(usize, 2), store.totalStoredCount());
                return err;
            };
            switch (outcome) {
                .inserted => |result| try std.testing.expect(result.evicted),
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, FullRingSweep.run, .{});

    const NewTargetSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.ingestExactOnce("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
            const before = store.root();
            const outcome = store.ingestExactOnce("#b", .{
                .msgid = "m2",
                .sender = "bob",
                .text = "two",
                .timestamp = 2,
                .command = "TAGMSG",
                .client_tags = "+typing=active",
            }) catch |err| {
                try std.testing.expectEqualSlices(u8, &before, &store.root());
                try std.testing.expectEqual(@as(usize, 1), store.totalStoredCount());
                try std.testing.expectEqual(@as(usize, 1), store.targetCount());
                return err;
            };
            switch (outcome) {
                .inserted => |result| try std.testing.expect(!result.evicted),
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, NewTargetSweep.run, .{});

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var store = Store.init(failing.allocator());
    defer store.deinit();
    const exact = ExactInputMessage{ .msgid = "stable", .sender = "alice", .text = "body", .timestamp = 10 };
    _ = try store.ingestExactOnce("#a", exact);
    const before = store.root();
    failing.fail_index = failing.alloc_index;
    switch (try store.ingestExactOnce("#a", exact)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.ingestExactOnce("#a", .{ .msgid = "stable", .sender = "alice", .text = "other", .timestamp = 10 })) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &before, &store.root());
}

test "exact-once ingestion classifies repeated msgids restored from legacy append checkpoints" {
    const Store = Lotus(.{ .max_targets = 1, .max_per_target = 4, .max_text = 32 });
    const exact = ExactInputMessage{
        .msgid = "legacy-id",
        .sender = "alice",
        .text = "same",
        .timestamp = 10,
        .command = "NOTICE",
        .client_tags = "+x=1",
    };

    var legacy_exact = Store.init(std.testing.allocator);
    defer legacy_exact.deinit();
    _ = try legacy_exact.append("#lotus", exact.input());
    _ = try legacy_exact.append("#lotus", exact.input());
    const exact_wire = try legacy_exact.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(exact_wire);
    var restored_exact = try Store.decodeCheckpoint(std.testing.allocator, exact_wire);
    defer restored_exact.deinit();
    switch (try restored_exact.ingestExactOnce("#lotus", exact)) {
        .exact_duplicate => {},
        else => return error.TestUnexpectedResult,
    }
    const exact_after = try restored_exact.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(exact_after);
    try std.testing.expectEqualSlices(u8, exact_wire, exact_after);
    try std.testing.expectEqual(@as(usize, 2), restored_exact.totalStoredCount());

    var legacy_conflict = Store.init(std.testing.allocator);
    defer legacy_conflict.deinit();
    _ = try legacy_conflict.append("#lotus", exact.input());
    _ = try legacy_conflict.append("#lotus", .{
        .msgid = exact.msgid,
        .sender = exact.sender,
        .text = "different",
        .timestamp = exact.timestamp,
        .command = exact.command,
        .client_tags = exact.client_tags,
    });
    const conflict_wire = try legacy_conflict.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(conflict_wire);
    var restored_conflict = try Store.decodeCheckpoint(std.testing.allocator, conflict_wire);
    defer restored_conflict.deinit();
    switch (try restored_conflict.ingestExactOnce("#lotus", exact)) {
        .equivocation => {},
        else => return error.TestUnexpectedResult,
    }
    const conflict_after = try restored_conflict.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(conflict_after);
    try std.testing.expectEqualSlices(u8, conflict_wire, conflict_after);
    try std.testing.expectEqual(@as(usize, 2), restored_conflict.totalStoredCount());
}

test "ownership remains leak free across fills evictions edits and deinit" {
    const Store = Lotus(.{ .max_targets = 2, .max_per_target = 4, .max_text = 64 });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var i: usize = 0;
    while (i < 24) : (i += 1) {
        var msgid_buf: [16]u8 = undefined;
        var text_buf: [32]u8 = undefined;
        const msgid = try std.fmt.bufPrint(&msgid_buf, "m{d}", .{i});
        const text = try std.fmt.bufPrint(&text_buf, "body-{d}", .{i});
        const target: []const u8 = if (i % 2 == 0) "#a" else "#b";
        _ = try store.append(target, .{
            .msgid = msgid,
            .sender = "alice",
            .text = text,
            .timestamp = @intCast(i),
        });
    }

    try store.edit("#a", "m22", "edited-body");
    try store.redact("#b", "m23");

    var out: [4]Message = undefined;
    const got = try store.latest("#a", 4, &out);
    try std.testing.expect(got.len > 0);
    try expectMsg(got[0], "m22", 22, "edited-body");
}

test "checkpoint round trip is canonical exact and independently owned" {
    const Store = Lotus(.{
        .max_targets = 3,
        .max_per_target = 4,
        .max_text = 64,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 32,
        .max_command = 16,
        .max_client_tags = 128,
    });
    var first = Store.init(std.testing.allocator);
    defer first.deinit();
    var reordered = Store.init(std.testing.allocator);
    defer reordered.deinit();

    _ = try first.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "bee", .timestamp = 4, .command = "NOTICE" });
    _ = try first.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try first.append("#a", .{
        .msgid = "a2",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/react=ok",
    });
    _ = try first.append("#a", .{ .msgid = "a3", .sender = "services", .text = "new topic", .timestamp = 3, .command = "TOPIC" });
    _ = try first.append("#b", .{ .msgid = "b2", .sender = "bob", .text = "", .timestamp = 5, .command = "TAGMSG", .client_tags = "" });
    try first.redact("#a", "a2");
    try first.edit("#a", "a3", "edited topic");

    _ = try reordered.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try reordered.append("#a", .{
        .msgid = "a2",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/react=ok",
    });
    _ = try reordered.append("#a", .{ .msgid = "a3", .sender = "services", .text = "edited topic", .timestamp = 3, .command = "TOPIC" });
    try reordered.redact("#a", "a2");
    _ = try reordered.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "bee", .timestamp = 4, .command = "NOTICE" });
    _ = try reordered.append("#b", .{ .msgid = "b2", .sender = "bob", .text = "", .timestamp = 5, .command = "TAGMSG", .client_tags = "" });

    const first_wire = try first.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(first_wire);
    const reordered_wire = try reordered.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reordered_wire);
    try std.testing.expectEqualSlices(u8, first_wire, reordered_wire);

    const checkpoint_copy = try std.testing.allocator.dupe(u8, first_wire);
    var restored = Store.decodeCheckpoint(std.testing.allocator, checkpoint_copy) catch |err| {
        std.testing.allocator.free(checkpoint_copy);
        return err;
    };
    @memset(checkpoint_copy, 0xa5);
    std.testing.allocator.free(checkpoint_copy);
    defer restored.deinit();
    const restored_wire = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(restored_wire);
    try std.testing.expectEqualSlices(u8, first_wire, restored_wire);
    const source_root = first.root();
    const restored_root = restored.root();
    try std.testing.expectEqualSlices(u8, &source_root, &restored_root);
    try std.testing.expectEqual(@as(usize, 2), restored.targetCount());
    try std.testing.expectEqual(@as(usize, 5), restored.totalStoredCount());
    try std.testing.expectEqual(@as(usize, 1), restored.tombstoneCount());

    var iterator = restored.deterministicIterator();
    const expected_targets = [_][]const u8{ "#a", "#a", "#a", "#b", "#b" };
    const expected_ids = [_][]const u8{ "a1", "a2", "a3", "b1", "b2" };
    const expected_commands = [_][]const u8{ "PRIVMSG", "TAGMSG", "TOPIC", "NOTICE", "TAGMSG" };
    for (expected_targets, expected_ids, expected_commands, 0..) |target, id, command, index| {
        const entry = iterator.next() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(target, entry.target);
        try std.testing.expectEqualStrings(id, entry.message.msgid);
        try std.testing.expectEqualStrings(command, entry.message.command);
        try std.testing.expectEqual(index == 1, entry.message.tombstone);
        if (index == 1)
            try std.testing.expectEqualStrings("+typing=active;+draft/react=ok", entry.message.client_tags.?);
        if (index == 4) {
            try std.testing.expect(entry.message.client_tags != null);
            try std.testing.expectEqual(@as(usize, 0), entry.message.client_tags.?.len);
        }
    }
    try std.testing.expect(iterator.next() == null);
}

test "checkpoint restores an older smaller text ceiling into a larger Lotus" {
    const Older = Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 512,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });
    const Current = Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 4096,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });
    const Smaller = Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 256,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });

    var older = Older.init(std.testing.allocator);
    defer older.deinit();
    var ciphertext: [512]u8 = @splat('x');
    _ = try older.append("#secure", .{
        .msgid = "cipher",
        .sender = "alice",
        .text = &ciphertext,
        .timestamp = 1,
        .command = "PRIVMSG",
    });
    _ = try older.append("#secure", .{
        .msgid = "typing",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active",
    });
    try older.redact("#secure", "typing");

    const wire = try older.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try Current.decodeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();

    var iterator = restored.deterministicIterator();
    const first = iterator.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("#secure", first.target);
    try std.testing.expectEqualStrings("cipher", first.message.msgid);
    try std.testing.expectEqualSlices(u8, &ciphertext, first.message.text);
    try std.testing.expect(!first.message.tombstone);
    const second = iterator.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("typing", second.message.msgid);
    try std.testing.expect(second.message.tombstone);
    try std.testing.expectEqualStrings("+typing=active", second.message.client_tags.?);
    try std.testing.expect(iterator.next() == null);

    try std.testing.expectError(error.ConfigMismatch, Smaller.decodeCheckpoint(std.testing.allocator, wire));

    const zero_text_limit = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(zero_text_limit);
    writeU32(zero_text_limit[16..20], 0);
    rewriteCheckpointChecksum(zero_text_limit);
    try std.testing.expectError(error.ConfigMismatch, Current.decodeCheckpoint(std.testing.allocator, zero_text_limit));

    var current = Current.init(std.testing.allocator);
    defer current.deinit();
    var large_ciphertext: [4096]u8 = @splat('z');
    _ = try current.append("#secure", .{
        .msgid = "large",
        .sender = "alice",
        .text = &large_ciphertext,
        .timestamp = 3,
    });
    const inconsistent_wire = try current.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(inconsistent_wire);
    writeU32(inconsistent_wire[16..20], 512);
    rewriteCheckpointChecksum(inconsistent_wire);
    try std.testing.expectError(error.CapacityExceeded, Current.decodeCheckpoint(std.testing.allocator, inconsistent_wire));
}

test "checkpoint decoder rejects truncation corruption bounds and trailing bytes" {
    const Store = Lotus(.{
        .max_targets = 2,
        .max_per_target = 2,
        .max_text = 32,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 16,
        .max_command = 8,
        .max_client_tags = 32,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{
        .msgid = "a1",
        .sender = "alice",
        .text = "one",
        .timestamp = 1,
        .command = "TAGMSG",
        .client_tags = "+x=1",
    });
    _ = try source.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "two", .timestamp = 2 });
    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);

    for (0..wire.len) |len| {
        if (Store.decodeCheckpoint(std.testing.allocator, wire[0..len])) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0xa5;
    try std.testing.expectError(error.TrailingBytes, Store.decodeCheckpoint(std.testing.allocator, trailing));

    const bad_magic = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 0xff;
    try std.testing.expectError(error.BadMagic, Store.decodeCheckpoint(std.testing.allocator, bad_magic));

    const bad_version = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    rewriteCheckpointChecksum(bad_version);
    try std.testing.expectError(error.UnsupportedVersion, Store.decodeCheckpoint(std.testing.allocator, bad_version));

    const bad_checksum = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_checksum);
    bad_checksum[wire.len - checkpoint_checksum_len - 1] ^= 0x80;
    try std.testing.expectError(error.ChecksumMismatch, Store.decodeCheckpoint(std.testing.allocator, bad_checksum));

    const first_entry = firstCheckpointEntryOffset(wire);
    const bad_flags = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_flags);
    bad_flags[first_entry] = 0x80;
    rewriteCheckpointChecksum(bad_flags);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, bad_flags));

    const missing_tag_flag = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(missing_tag_flag);
    missing_tag_flag[first_entry] &= ~checkpoint_flag_has_tags;
    rewriteCheckpointChecksum(missing_tag_flag);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, missing_tag_flag));

    const bad_hash = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_hash);
    bad_hash[first_entry + 1 + 8] ^= 1;
    rewriteCheckpointChecksum(bad_hash);
    try std.testing.expectError(error.InvalidHash, Store.decodeCheckpoint(std.testing.allocator, bad_hash));

    const zero_target = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(zero_target);
    writeU32(zero_target[checkpoint_header_len..][0..4], 0);
    rewriteCheckpointChecksum(zero_target);
    try std.testing.expectError(error.CapacityExceeded, Store.decodeCheckpoint(std.testing.allocator, zero_target));

    const excess_entries = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(excess_entries);
    writeU32(excess_entries[checkpoint_header_len + 4 ..][0..4], 3);
    rewriteCheckpointChecksum(excess_entries);
    try std.testing.expectError(error.CapacityExceeded, Store.decodeCheckpoint(std.testing.allocator, excess_entries));

    const wrong_total = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(wrong_total);
    writeU32(wrong_total[44..48], 1);
    rewriteCheckpointChecksum(wrong_total);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, wrong_total));

    const noncanonical = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(noncanonical);
    const second_target = nextCheckpointTargetOffset(noncanonical, checkpoint_header_len);
    try std.testing.expectEqual(@as(u32, 2), readU32(noncanonical[second_target..][0..4]));
    @memcpy(noncanonical[second_target + checkpoint_target_prefix_len ..][0..2], "#a");
    rewriteCheckpointChecksum(noncanonical);
    try std.testing.expectError(error.NonCanonicalOrder, Store.decodeCheckpoint(std.testing.allocator, noncanonical));

    const authenticated_trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(authenticated_trailing);
    const old_prefix_len = wire.len - checkpoint_checksum_len;
    @memcpy(authenticated_trailing[0..old_prefix_len], wire[0..old_prefix_len]);
    authenticated_trailing[old_prefix_len] = 0x5a;
    writeU32(authenticated_trailing[48..52], readU32(wire[48..52]) + 1);
    rewriteCheckpointChecksum(authenticated_trailing);
    try std.testing.expectError(error.TrailingBytes, Store.decodeCheckpoint(std.testing.allocator, authenticated_trailing));

    const Other = Lotus(.{
        .max_targets = 3,
        .max_per_target = 2,
        .max_text = 32,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 16,
        .max_command = 8,
        .max_client_tags = 32,
    });
    try std.testing.expectError(error.ConfigMismatch, Other.decodeCheckpoint(std.testing.allocator, wire));
}

test "checkpoint replacement is atomic across every allocation failure" {
    const Store = Lotus(.{
        .max_targets = 3,
        .max_per_target = 3,
        .max_text = 32,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 64,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try source.append("#a", .{ .msgid = "a2", .sender = "alice", .text = "", .timestamp = 2, .command = "TAGMSG", .client_tags = "+x=1" });
    _ = try source.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "two", .timestamp = 3, .command = "NOTICE" });

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, state: *const Store) !void {
            const bytes = try state.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expect(bytes.len > checkpoint_header_len + checkpoint_checksum_len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});

    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try Store.decodeCheckpoint(allocator, bytes);
            defer decoded.deinit();
            try std.testing.expectEqual(@as(usize, 3), decoded.totalStoredCount());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, DecodeSweep.run, .{wire});

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var target = Store.init(allocator);
            defer target.deinit();
            _ = try target.append("#old", .{ .msgid = "old", .sender = "sentinel", .text = "keep", .timestamp = 99 });
            const before = target.root();
            target.replaceFromCheckpoint(bytes) catch |err| {
                const after = target.root();
                try std.testing.expectEqualSlices(u8, &before, &after);
                try std.testing.expectEqual(@as(usize, 1), target.totalStoredCount());
                return err;
            };
            try std.testing.expectEqual(@as(usize, 3), target.totalStoredCount());
            try std.testing.expectEqual(@as(usize, 2), target.targetCount());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ReplaceSweep.run, .{wire});

    var target = Store.init(std.testing.allocator);
    defer target.deinit();
    _ = try target.append("#old", .{ .msgid = "old", .sender = "sentinel", .text = "keep", .timestamp = 99 });
    const before = target.root();
    const corrupt = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(corrupt);
    corrupt[0] ^= 1;
    try std.testing.expectError(error.BadMagic, target.replaceFromCheckpoint(corrupt));
    const after = target.root();
    try std.testing.expectEqualSlices(u8, &before, &after);
}

test "checkpoint preserves wrapped ring chronology exactly" {
    const Store = Lotus(.{
        .max_targets = 1,
        .max_per_target = 3,
        .max_text = 16,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 8,
        .max_command = 8,
        .max_client_tags = 8,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try source.append("#a", .{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 });
    _ = try source.append("#a", .{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 });
    _ = try source.append("#a", .{ .msgid = "m4", .sender = "alice", .text = "", .timestamp = 4, .command = "TAGMSG", .client_tags = "" });
    _ = try source.append("#a", .{ .msgid = "m5", .sender = "alice", .text = "five", .timestamp = 5, .command = "NOTICE" });
    try source.redact("#a", "m3");

    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try Store.decodeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();
    const reencoded = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);

    var iterator = restored.deterministicIterator();
    const expected_ids = [_][]const u8{ "m3", "m4", "m5" };
    for (expected_ids, 0..) |expected_id, index| {
        const entry = iterator.next() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("#a", entry.target);
        try std.testing.expectEqualStrings(expected_id, entry.message.msgid);
        try std.testing.expectEqual(index == 0, entry.message.tombstone);
    }
    try std.testing.expect(iterator.next() == null);
}

test "checkpoint and append bounds fail closed" {
    const Store = Lotus(.{
        .max_targets = 1,
        .max_per_target = 1,
        .max_text = 3,
        .max_target = 3,
        .max_msgid = 2,
        .max_sender = 3,
        .max_command = 8,
        .max_client_tags = 4,
        .max_checkpoint_bytes = 128,
    });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.TargetTooLong, store.append("#abc", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.MsgidTooLong, store.append("#a", .{ .msgid = "mid", .sender = "a", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.SenderTooLong, store.append("#a", .{ .msgid = "m", .sender = "long", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.TextTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "long", .timestamp = 1 }));
    try std.testing.expectError(error.CommandTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1, .command = "LONG-CMD-X" }));
    try std.testing.expectError(error.ClientTagsTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1, .client_tags = "+x=12" }));
    try std.testing.expectError(error.CheckpointCapacityExceeded, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "xxx", .timestamp = 1 }));
    try std.testing.expectEqual(@as(usize, 0), store.totalStoredCount());
    const empty_wire = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(empty_wire);
    try std.testing.expect(empty_wire.len <= 128);
}

test "aggregate checkpoint retention evicts the deterministic global oldest entry" {
    // This deliberately uses 256 rows and the production 4096-byte text
    // ceiling. The smaller test budget reaches the aggregate boundary without
    // allocating a 64 MiB fixture; the same incremental accounting is used by
    // the production 64 MiB Lotus instantiation.
    const Store = Lotus(.{
        .max_targets = 512,
        .max_per_target = 256,
        .max_text = 4096,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 16,
        .max_checkpoint_bytes = 1_070_000,
    });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    const payload: [4096]u8 = @splat('x');
    var msgid_buf: [16]u8 = undefined;

    for (0..256) |index| {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "a-{d}", .{index});
        _ = try store.append("#a", .{ .msgid = msgid, .sender = "a", .text = &payload, .timestamp = index });
    }
    try std.testing.expectEqual(@as(usize, 256), try store.storedCount("#a"));

    const appended = try store.append("#b", .{ .msgid = "b-0", .sender = "b", .text = &payload, .timestamp = 256 });
    try std.testing.expect(appended.evicted);
    try std.testing.expectEqual(@as(usize, 255), try store.storedCount("#a"));
    try std.testing.expectEqual(@as(usize, 1), try store.storedCount("#b"));
    var oldest = store.deterministicIterator();
    const first = oldest.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("#a", first.target);
    try std.testing.expectEqualStrings("a-1", first.message.msgid);

    // Exercise aggregate pressure on an existing target. The stale row lives
    // elsewhere, so target-local eviction would incorrectly discard newer #a.
    _ = try store.append("#c", .{ .msgid = "c-old", .sender = "c", .text = &payload, .timestamp = 0 });
    try std.testing.expectEqual(@as(usize, 1), try store.storedCount("#c"));
    _ = try store.append("#a", .{ .msgid = "a-new", .sender = "a", .text = &payload, .timestamp = 999 });
    try std.testing.expectEqual(@as(usize, 0), try store.storedCount("#c"));
    var newest_a_buf: [1]Message = undefined;
    const newest_a = try store.latest("#a", 1, &newest_a_buf);
    try std.testing.expectEqualStrings("a-new", newest_a[0].msgid);

    try std.testing.expectEqual(
        ExactOnceResult.exact_duplicate,
        try store.ingestExactOnce("#b", .{ .msgid = "b-0", .sender = "b", .text = &payload, .timestamp = 256 }),
    );
    try std.testing.expectEqual(
        ExactOnceResult.equivocation,
        try store.ingestExactOnce("#b", .{ .msgid = "b-0", .sender = "b", .text = "different", .timestamp = 256 }),
    );

    const wire = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    try std.testing.expect(wire.len <= 1_070_000);
}

fn firstCheckpointEntryOffset(bytes: []const u8) usize {
    const target_len: usize = readU32(bytes[checkpoint_header_len..][0..4]);
    return checkpoint_header_len + checkpoint_target_prefix_len + target_len;
}

fn nextCheckpointTargetOffset(bytes: []const u8, target_offset: usize) usize {
    const target_len: usize = readU32(bytes[target_offset..][0..4]);
    const entry_count: usize = readU32(bytes[target_offset + 4 ..][0..4]);
    var pos = target_offset + checkpoint_target_prefix_len + target_len;
    for (0..entry_count) |_| {
        const lengths_offset = pos + 1 + 8 + @sizeOf(ContentHash);
        var payload_len: usize = 0;
        for (0..5) |index| {
            payload_len += readU32(bytes[lengths_offset + index * 4 ..][0..4]);
        }
        pos += checkpoint_entry_prefix_len + payload_len;
    }
    return pos;
}

fn appendForTest(store: anytype, target: []const u8, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    _ = try store.append(target, .{
        .msgid = msgid,
        .sender = "alice",
        .text = text,
        .timestamp = timestamp,
    });
}

fn expectMsg(msg: Message, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    try std.testing.expectEqualStrings(msgid, msg.msgid);
    try std.testing.expectEqual(timestamp, msg.timestamp);
    try std.testing.expectEqualStrings(text, msg.text);
    try std.testing.expect(!msg.tombstone);
}

fn expectIds(messages: []const Message, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, messages.len);
    for (expected, 0..) |msgid, index| {
        try std.testing.expectEqualStrings(msgid, messages[index].msgid);
    }
}
