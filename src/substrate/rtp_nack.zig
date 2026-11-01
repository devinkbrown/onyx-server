// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTP Generic NACK helpers and a bounded sender retransmit buffer.
//!
//! Generic NACK is the RTP Feedback Control Information format from RFC 4585:
//! every four-byte block contains a Packet ID (PID) and a 16-bit bitmask of
//! the following packets (BLP). This module is self-contained and std-only so
//! it can be tested in isolation:
//!
//!     zig test src/substrate/rtp_nack.zig

const std = @import("std");

const Allocator = std.mem.Allocator;
const seq_modulus: i64 = 1 << 16;
/// A cached retransmission is useful strictly before this age.
pub const retransmit_max_age_ms: i64 = 1000;
pub fn retransmitFresh(sent_ms: i64, now_ms: i64) bool {
    return sent_ms > 0 and now_ms >= sent_ms and now_ms - sent_ms < retransmit_max_age_ms;
}
pub const FreshPacket = struct { bytes: []const u8, sent_ms: i64 };

/// Joint NACK/FEC-style recovery choice for one missing packet.
pub const RecoveryDecision = enum { retransmit, recover_locally, drop_late };

/// Deadline in packet-age milliseconds derived from a caller-supplied
/// playout budget minus a jitter guard. The result is bounded to
/// `[0, retransmit_max_age_ms]` so no budget can extend retransmit
/// usefulness past the existing freshness bound.
pub fn retransmitDeadlineMs(playout_budget_ms: i64, jitter_ms: i64) i64 {
    const budget = std.math.clamp(playout_budget_ms, 0, retransmit_max_age_ms);
    const jitter = std.math.clamp(jitter_ms, 0, retransmit_max_age_ms);
    return @max(0, budget - jitter);
}

/// Pure joint recovery decision over bounded inputs. A retransmit is
/// useful strictly before `deadline_ms` (exactly at the deadline is
/// late, matching `retransmitFresh`); lateness overrides local
/// recovery. Exactly one missing packet prefers FEC-style local
/// recovery only when `prefer_local_single_missing` is set. Negative
/// age, a non-positive deadline, or zero missing packets fail closed
/// as `drop_late`.
pub fn decideRecovery(packet_age_ms: i64, deadline_ms: i64, missing_count: usize, prefer_local_single_missing: bool) RecoveryDecision {
    const deadline = std.math.clamp(deadline_ms, 0, retransmit_max_age_ms);
    if (packet_age_ms < 0 or deadline <= 0 or packet_age_ms >= deadline) return .drop_late;
    if (missing_count == 0) return .drop_late;
    if (missing_count == 1 and prefer_local_single_missing) return .recover_locally;
    return .retransmit;
}

/// Caller-owned joint recovery policy. `decide` keeps the pure
/// `decideRecovery` rule and counts every late drop it returns;
/// `dropped_late` saturates instead of wrapping.
pub const RecoveryPolicy = struct {
    playout_budget_ms: i64,
    jitter_ms: i64 = 0,
    prefer_local_single_missing: bool = false,
    dropped_late: u64 = 0,

    pub fn deadlineMs(self: RecoveryPolicy) i64 {
        return retransmitDeadlineMs(self.playout_budget_ms, self.jitter_ms);
    }

    pub fn decide(self: *RecoveryPolicy, packet_age_ms: i64, missing_count: usize) RecoveryDecision {
        const decision = decideRecovery(packet_age_ms, self.deadlineMs(), missing_count, self.prefer_local_single_missing);
        if (decision == .drop_late) self.dropped_late +|= 1;
        return decision;
    }
};

pub const NackError = error{
    InvalidFciLength,
};

pub const NackBlock = struct {
    pid: u16,
    blp: u16 = 0,

    pub fn contains(self: NackBlock, seq: u16) bool {
        if (seq == self.pid) return true;
        const delta = seqDistanceForward(self.pid, seq);
        if (delta == 0 or delta > 16) return false;
        const bit: u4 = @intCast(delta - 1);
        return (self.blp & (@as(u16, 1) << bit)) != 0;
    }

    pub fn missingCount(self: NackBlock) usize {
        return 1 + @popCount(self.blp);
    }
};

pub const Receiver = struct {
    allocator: Allocator,
    received: std.AutoHashMap(i64, void),
    missing: std.AutoHashMap(i64, void),
    max_ext_seq: ?i64 = null,
    blocks: std.ArrayList(NackBlock) = .empty,
    ext_scratch: std.ArrayList(i64) = .empty,
    fci_scratch: std.ArrayList(u8) = .empty,

    pub fn init(allocator: Allocator) Receiver {
        return .{
            .allocator = allocator,
            .received = std.AutoHashMap(i64, void).init(allocator),
            .missing = std.AutoHashMap(i64, void).init(allocator),
        };
    }

    pub fn deinit(self: *Receiver) void {
        self.received.deinit();
        self.missing.deinit();
        self.blocks.deinit(self.allocator);
        self.ext_scratch.deinit(self.allocator);
        self.fci_scratch.deinit(self.allocator);
        self.* = undefined;
    }

    /// Records a received RTP sequence number and returns the current Generic
    /// NACK blocks for packets missing up to the highest packet seen.
    pub fn onReceived(self: *Receiver, seq: u16) Allocator.Error![]const NackBlock {
        const ext_seq = if (self.max_ext_seq) |max| extendSeq(seq, max) else @as(i64, seq);
        try self.received.put(ext_seq, {});
        _ = self.missing.remove(ext_seq);

        if (self.max_ext_seq) |max| {
            if (ext_seq > max) {
                var missing_seq = max + 1;
                while (missing_seq < ext_seq) : (missing_seq += 1) {
                    if (!self.received.contains(missing_seq)) {
                        try self.missing.put(missing_seq, {});
                    }
                }
                self.max_ext_seq = ext_seq;
            }
        } else {
            self.max_ext_seq = ext_seq;
        }

        return self.currentNacks();
    }

    pub fn currentNacks(self: *Receiver) Allocator.Error![]const NackBlock {
        self.ext_scratch.clearRetainingCapacity();
        var iter = self.missing.keyIterator();
        while (iter.next()) |seq| {
            try self.ext_scratch.append(self.allocator, seq.*);
        }
        std.mem.sort(i64, self.ext_scratch.items, {}, std.sort.asc(i64));
        return buildBlocksFromExt(self.allocator, self.ext_scratch.items, &self.blocks);
    }

    pub fn currentFci(self: *Receiver) Allocator.Error![]const u8 {
        const nacks = try self.currentNacks();
        self.fci_scratch.clearRetainingCapacity();
        try appendNackFci(self.allocator, &self.fci_scratch, nacks);
        return self.fci_scratch.items;
    }
};

pub const RetransmitBuffer = struct {
    allocator: Allocator,
    capacity: usize,
    packets: std.ArrayList(StoredPacket) = .empty,
    newest_ext_seq: ?i64 = null,

    /// An owned, pointer-free description of this source's retained packet
    /// history. The allocator is cleanup custody, never a wire field. Capture
    /// requires the media owner to have stopped concurrent packet admission.
    pub const Snapshot = struct {
        allocator: Allocator,
        capacity: usize,
        packets: []Packet,
        newest_ext_seq: ?i64,

        pub const Packet = struct {
            seq: u16,
            ext_seq: i64,
            sent_ms: i64 = 0,
            bytes: []u8,
        };

        pub fn deinit(self: *Snapshot) void {
            for (self.packets) |packet| {
                std.crypto.secureZero(u8, packet.bytes);
                self.allocator.free(packet.bytes);
            }
            self.allocator.free(self.packets);
            self.* = undefined;
        }

        pub fn validate(self: *const Snapshot, expected_capacity: usize, max_bytes: usize) !void {
            if (self.capacity != expected_capacity or self.packets.len > self.capacity) return error.InvalidSnapshot;
            if (self.packets.len != 0 and self.newest_ext_seq == null) return error.InvalidSnapshot;
            var bytes: usize = 0;
            var previous: ?i64 = null;
            for (self.packets) |packet| {
                if (packet.sent_ms < 0) return error.InvalidSnapshot;
                if (previous) |p| if (packet.ext_seq <= p) return error.InvalidSnapshot;
                const seq: u16 = @truncate(@as(u64, @bitCast(packet.ext_seq)));
                if (packet.seq != seq or packet.ext_seq > self.newest_ext_seq.?) return error.InvalidSnapshot;
                bytes = std.math.add(usize, bytes, packet.bytes.len) catch return error.Capacity;
                if (bytes > max_bytes) return error.Capacity;
                previous = packet.ext_seq;
            }
        }
    };

    pub fn capture(self: *const RetransmitBuffer, allocator: Allocator, max_bytes: usize) !Snapshot {
        // Validate the actual source before allocating any snapshot backing.
        if (self.packets.items.len > self.capacity) return error.InvalidSnapshot;
        var bytes: usize = 0;
        var previous: ?i64 = null;
        for (self.packets.items) |packet| {
            if (packet.sent_ms < 0) return error.InvalidSnapshot;
            if (previous) |p| if (packet.ext_seq <= p) return error.InvalidSnapshot;
            if (self.newest_ext_seq == null or packet.ext_seq > self.newest_ext_seq.? or
                packet.seq != @as(u16, @truncate(@as(u64, @bitCast(packet.ext_seq))))) return error.InvalidSnapshot;
            bytes = std.math.add(usize, bytes, packet.bytes.len) catch return error.Capacity;
            if (bytes > max_bytes) return error.Capacity;
            previous = packet.ext_seq;
        }
        const packets = try allocator.alloc(Snapshot.Packet, self.packets.items.len);
        var initialized: usize = 0;
        errdefer {
            for (packets[0..initialized]) |packet| {
                std.crypto.secureZero(u8, packet.bytes);
                allocator.free(packet.bytes);
            }
            allocator.free(packets);
        }
        for (self.packets.items, 0..) |packet, i| {
            packets[i] = .{ .seq = packet.seq, .ext_seq = packet.ext_seq, .sent_ms = packet.sent_ms, .bytes = try allocator.dupe(u8, packet.bytes) };
            initialized += 1;
        }
        return .{ .allocator = allocator, .capacity = self.capacity, .packets = packets, .newest_ext_seq = self.newest_ext_seq };
    }

    /// Returns a detached owned candidate. No live source changes, packet
    /// replay, sequence extension or NEW index assignment occurs here. The
    /// aggregate must authenticate its capsule/configuration before using it.
    pub fn prepareRestore(allocator: Allocator, snapshot: *const Snapshot, expected_capacity: usize, max_bytes: usize) !RetransmitBuffer {
        try snapshot.validate(expected_capacity, max_bytes);
        var candidate = init(allocator, expected_capacity);
        errdefer candidate.deinit();
        try candidate.packets.ensureTotalCapacity(allocator, snapshot.packets.len);
        for (snapshot.packets) |packet| {
            const bytes = try allocator.dupe(u8, packet.bytes);
            candidate.packets.appendAssumeCapacity(.{ .seq = packet.seq, .ext_seq = packet.ext_seq, .sent_ms = packet.sent_ms, .bytes = bytes });
        }
        candidate.newest_ext_seq = snapshot.newest_ext_seq;
        return candidate;
    }

    pub fn init(allocator: Allocator, capacity: usize) RetransmitBuffer {
        return .{
            .allocator = allocator,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *RetransmitBuffer) void {
        for (self.packets.items) |packet| {
            std.crypto.secureZero(u8, packet.bytes);
            self.allocator.free(packet.bytes);
        }
        self.packets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn onSent(self: *RetransmitBuffer, seq: u16, bytes: []const u8) Allocator.Error!void {
        return self.onSentAt(seq, bytes, 0);
    }
    pub fn onSentAt(self: *RetransmitBuffer, seq: u16, bytes: []const u8, sent_ms: i64) Allocator.Error!void {
        if (self.capacity == 0) return;

        const ext_seq = if (self.newest_ext_seq) |newest| extendSeq(seq, newest) else @as(i64, seq);
        const copied = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copied);

        if (self.findExt(ext_seq)) |index| {
            self.allocator.free(self.packets.items[index].bytes);
            self.packets.items[index].bytes = copied;
            self.newest_ext_seq = maxOptionalI64(self.newest_ext_seq, ext_seq);
            return;
        }

        var index: usize = 0;
        while (index < self.packets.items.len and self.packets.items[index].ext_seq < ext_seq) : (index += 1) {}
        try self.packets.insert(self.allocator, index, .{
            .seq = seq,
            .ext_seq = ext_seq,
            .sent_ms = @max(0, sent_ms),
            .bytes = copied,
        });
        self.newest_ext_seq = maxOptionalI64(self.newest_ext_seq, ext_seq);

        while (self.packets.items.len > self.capacity) {
            const old = self.packets.orderedRemove(0);
            self.allocator.free(old.bytes);
        }
    }

    /// Detached storage for source owners that publish under exclusion. All
    /// backend calls happen here or in deinit after the cut; commit is pure.
    /// Existing ordinary onSent semantics remain separately available.
    pub fn prepareSent(self: *RetransmitBuffer, seq: u16, bytes: []const u8) Allocator.Error!*PreparedSent {
        return self.prepareSentAt(seq, bytes, 0);
    }
    pub fn prepareSentAt(self: *RetransmitBuffer, seq: u16, bytes: []const u8, sent_ms: i64) Allocator.Error!*PreparedSent {
        const p = try self.allocator.create(SentPlan);
        p.* = .{ .owner = self, .allocator = self.allocator, .old_ptr = @intFromPtr(self.packets.items.ptr), .old_len = self.packets.items.len, .old_capacity = self.packets.capacity, .old_newest = self.newest_ext_seq, .limit = self.capacity, .old_digest = sentDigest(self), .next_newest = self.newest_ext_seq };
        errdefer self.allocator.destroy(p);
        errdefer {
            if (p.copied) |owned| self.allocator.free(owned);
            p.rows.deinit(self.allocator);
        }
        if (self.capacity == 0) return @ptrCast(p);
        const extended = if (self.newest_ext_seq) |old| extendSeq(seq, old) else @as(i64, seq);
        p.next_newest = maxOptionalI64(self.newest_ext_seq, extended);
        // Replacing the same extended identity never renews its lifetime,
        // including when the original clock reading was unknown.
        const original_sent_ms = if (self.findExt(extended)) |index| self.packets.items[index].sent_ms else @max(0, sent_ms);
        const copied = try self.allocator.dupe(u8, bytes);
        p.copied = copied;
        try p.rows.ensureTotalCapacity(self.allocator, self.packets.items.len + 1);
        var inserted = false;
        for (self.packets.items) |row| {
            if (!inserted and row.ext_seq >= extended) {
                p.rows.appendAssumeCapacity(.{ .seq = seq, .ext_seq = extended, .sent_ms = original_sent_ms, .bytes = copied });
                inserted = true;
            }
            if (row.ext_seq == extended) {
                p.retired = row.bytes;
                continue;
            }
            p.rows.appendAssumeCapacity(row);
        }
        if (!inserted) p.rows.appendAssumeCapacity(.{ .seq = seq, .ext_seq = extended, .sent_ms = original_sent_ms, .bytes = copied });
        if (p.rows.items.len > self.capacity) {
            std.debug.assert(p.retired == null);
            p.retired = p.rows.orderedRemove(0).bytes;
        }
        return @ptrCast(p);
    }

    pub fn lookup(self: RetransmitBuffer, seq: u16) ?[]const u8 {
        var index = self.packets.items.len;
        while (index > 0) {
            index -= 1;
            const packet = self.packets.items[index];
            if (packet.seq == seq) return packet.bytes;
        }
        return null;
    }

    /// Clock-domain discontinuity or unknown send time is a miss, never a fresh packet.
    pub fn lookupFreshPacket(self: RetransmitBuffer, seq: u16, now_ms: i64) ?FreshPacket {
        var index = self.packets.items.len;
        while (index > 0) {
            index -= 1;
            const packet = self.packets.items[index];
            if (packet.seq != seq) continue;
            if (!retransmitFresh(packet.sent_ms, now_ms)) return null;
            return .{ .bytes = packet.bytes, .sent_ms = packet.sent_ms };
        }
        return null;
    }
    pub fn lookupFresh(self: RetransmitBuffer, seq: u16, now_ms: i64) ?[]const u8 {
        return if (self.lookupFreshPacket(seq, now_ms)) |packet| packet.bytes else null;
    }

    pub fn len(self: RetransmitBuffer) usize {
        return self.packets.items.len;
    }

    fn findExt(self: RetransmitBuffer, ext_seq: i64) ?usize {
        for (self.packets.items, 0..) |packet, index| {
            if (packet.ext_seq == ext_seq) return index;
        }
        return null;
    }
};

const StoredPacket = struct {
    seq: u16,
    ext_seq: i64,
    sent_ms: i64 = 0,
    bytes: []u8,
};

const SentPlan = struct {
    owner: *RetransmitBuffer,
    allocator: Allocator,
    old_ptr: usize,
    old_len: usize,
    old_capacity: usize,
    old_newest: ?i64,
    limit: usize,
    old_digest: [32]u8,
    next_newest: ?i64,
    rows: std.ArrayList(StoredPacket) = .empty,
    copied: ?[]u8 = null,
    retired: ?[]u8 = null,
    validated: bool = false,
    committed: bool = false,
};
fn sentDigest(owner: *const RetransmitBuffer) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (owner.packets.items) |row| {
        std.hash.autoHash(&hash, row.seq);
        std.hash.autoHash(&hash, row.ext_seq);
        std.hash.autoHash(&hash, row.sent_ms);
        std.hash.autoHash(&hash, @intFromPtr(row.bytes.ptr));
        std.hash.autoHash(&hash, row.bytes.len);
        hash.update(row.bytes);
    }
    return hash.finalResult();
}
fn sentPlan(plan: *PreparedSent) *SentPlan {
    return @ptrCast(@alignCast(plan));
}
pub const PreparedSent = opaque {
    pub fn validate(self: *PreparedSent) error{StaleCandidate}!void {
        const p = sentPlan(self);
        const owner = p.owner;
        if (p.allocator.ptr != owner.allocator.ptr or p.allocator.vtable != owner.allocator.vtable or p.committed or p.old_ptr != @intFromPtr(owner.packets.items.ptr) or p.old_len != owner.packets.items.len or p.old_capacity != owner.packets.capacity or !std.meta.eql(p.old_newest, owner.newest_ext_seq) or p.limit != owner.capacity or !std.mem.eql(u8, &p.old_digest, &sentDigest(owner))) return error.StaleCandidate;
        p.validated = true;
    }
    pub fn commitRetainingMetadata(self: *PreparedSent) void {
        const p = sentPlan(self);
        std.debug.assert(p.validated and !p.committed);
        if (p.limit != 0) {
            std.mem.swap(std.ArrayList(StoredPacket), &p.owner.packets, &p.rows);
            p.owner.newest_ext_seq = p.next_newest;
        }
        p.committed = true;
    }
    pub fn deinit(self: *PreparedSent) void {
        const p = sentPlan(self);
        if (p.committed) {
            if (p.retired) |bytes| {
                std.crypto.secureZero(u8, bytes);
                p.allocator.free(bytes);
            }
        } else if (p.copied) |bytes| {
            std.crypto.secureZero(u8, bytes);
            p.allocator.free(bytes);
        }
        // Array backing is owned; its retained packet payloads are borrowed.
        p.rows.deinit(p.allocator);
        p.allocator.destroy(p);
    }
};

pub fn buildNackBlocks(allocator: Allocator, missing_seqs: []const u16) Allocator.Error![]NackBlock {
    var ext: std.ArrayList(i64) = .empty;
    defer ext.deinit(allocator);

    try ext.ensureTotalCapacity(allocator, missing_seqs.len);
    for (missing_seqs, 0..) |seq, index| {
        const ext_seq = if (index == 0) @as(i64, seq) else extendSeq(seq, ext.items[index - 1]);
        ext.appendAssumeCapacity(ext_seq);
    }
    std.mem.sort(i64, ext.items, {}, std.sort.asc(i64));

    var blocks: std.ArrayList(NackBlock) = .empty;
    errdefer blocks.deinit(allocator);
    _ = try buildBlocksFromExt(allocator, ext.items, &blocks);
    return blocks.toOwnedSlice(allocator);
}

pub fn encodeNackFci(allocator: Allocator, blocks: []const NackBlock) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendNackFci(allocator, &out, blocks);
    return out.toOwnedSlice(allocator);
}

pub fn parseNackFci(allocator: Allocator, fci: []const u8) (Allocator.Error || NackError)![]u16 {
    if (fci.len % 4 != 0) return error.InvalidFciLength;

    var out: std.ArrayList(u16) = .empty;
    errdefer out.deinit(allocator);

    var offset: usize = 0;
    while (offset < fci.len) : (offset += 4) {
        const block = NackBlock{
            .pid = readU16(fci[offset .. offset + 2]),
            .blp = readU16(fci[offset + 2 .. offset + 4]),
        };
        try out.append(allocator, block.pid);
        var bit: u5 = 0;
        while (bit < 16) : (bit += 1) {
            if ((block.blp & (@as(u16, 1) << @as(u4, @intCast(bit)))) != 0) {
                try out.append(allocator, wrapAdd(block.pid, @as(u16, bit) + 1));
            }
        }
    }

    return out.toOwnedSlice(allocator);
}

fn buildBlocksFromExt(
    allocator: Allocator,
    missing_ext: []const i64,
    blocks: *std.ArrayList(NackBlock),
) Allocator.Error![]const NackBlock {
    blocks.clearRetainingCapacity();
    if (missing_ext.len == 0) return blocks.items;

    var index: usize = 0;
    while (index < missing_ext.len) {
        const pid_ext = missing_ext[index];
        var block = NackBlock{ .pid = seqFromExt(pid_ext), .blp = 0 };
        index += 1;

        while (index < missing_ext.len) {
            const delta = missing_ext[index] - pid_ext;
            if (delta == 0) {
                index += 1;
                continue;
            }
            if (delta < 1 or delta > 16) break;
            const bit: u4 = @intCast(delta - 1);
            block.blp |= @as(u16, 1) << bit;
            index += 1;
        }

        try blocks.append(allocator, block);
    }

    return blocks.items;
}

fn appendNackFci(allocator: Allocator, out: *std.ArrayList(u8), blocks: []const NackBlock) Allocator.Error!void {
    try out.ensureUnusedCapacity(allocator, blocks.len * 4);
    for (blocks) |block| {
        var bytes: [4]u8 = undefined;
        writeU16(bytes[0..2], block.pid);
        writeU16(bytes[2..4], block.blp);
        out.appendSliceAssumeCapacity(&bytes);
    }
}

fn extendSeq(seq: u16, reference: i64) i64 {
    const base_cycle = @divFloor(reference, seq_modulus);
    var best = @as(i64, seq) + base_cycle * seq_modulus;
    var best_distance = absI64(best - reference);

    const candidates = [_]i64{
        best - seq_modulus,
        best + seq_modulus,
    };
    for (candidates) |candidate| {
        const distance = absI64(candidate - reference);
        if (distance < best_distance or (distance == best_distance and candidate > best)) {
            best = candidate;
            best_distance = distance;
        }
    }
    return best;
}

fn seqFromExt(ext_seq: i64) u16 {
    const wrapped = @mod(ext_seq, seq_modulus);
    return @intCast(wrapped);
}

fn wrapAdd(seq: u16, delta: u16) u16 {
    return @intCast((@as(u32, seq) + @as(u32, delta)) & 0xffff);
}

fn seqDistanceForward(from: u16, to: u16) u16 {
    return @intCast((@as(u32, to) -% @as(u32, from)) & 0xffff);
}

fn readU16(bytes: []const u8) u16 {
    std.debug.assert(bytes.len == 2);
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16(bytes: []u8, value: u16) void {
    std.debug.assert(bytes.len == 2);
    bytes[0] = @intCast(value >> 8);
    bytes[1] = @intCast(value & 0xff);
}

fn absI64(value: i64) i64 {
    return if (value < 0) -value else value;
}

fn maxOptionalI64(current: ?i64, value: i64) ?i64 {
    if (current) |existing| return @max(existing, value);
    return value;
}

test "gap detection produces one PID plus BLP block" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    try std.testing.expectEqual(@as(usize, 0), (try receiver.onReceived(100)).len);
    const blocks = try receiver.onReceived(104);

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqual(@as(u16, 101), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0b0000_0000_0000_0011), blocks[0].blp);
    try std.testing.expect(blocks[0].contains(101));
    try std.testing.expect(blocks[0].contains(102));
    try std.testing.expect(blocks[0].contains(103));
    try std.testing.expect(!blocks[0].contains(104));
}

test "gap detection spanning more than 17 packets produces multiple FCI blocks" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    _ = try receiver.onReceived(1000);
    const blocks = try receiver.onReceived(1022);

    try std.testing.expectEqual(@as(usize, 2), blocks.len);
    try std.testing.expectEqual(@as(u16, 1001), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0xffff), blocks[0].blp);
    try std.testing.expectEqual(@as(u16, 1018), blocks[1].pid);
    try std.testing.expectEqual(@as(u16, 0b0000_0000_0000_0111), blocks[1].blp);
}

test "encode and parse Generic NACK FCI deterministically" {
    const allocator = std.testing.allocator;
    const missing = [_]u16{ 10, 11, 12, 30, 31, 65535, 0 };

    const blocks = try buildNackBlocks(allocator, &missing);
    defer allocator.free(blocks);
    try std.testing.expectEqual(@as(usize, 2), blocks.len);

    const fci = try encodeNackFci(allocator, blocks);
    defer allocator.free(fci);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xff, 0xff, 0x1c, 0x01,
        0x00, 0x1e, 0x00, 0x01,
    }, fci);

    const parsed = try parseNackFci(allocator, fci);
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 65535, 0, 10, 11, 12, 30, 31 }, parsed);
}

test "parse rejects malformed FCI length" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidFciLength, parseNackFci(allocator, &[_]u8{ 1, 2, 3 }));
}

test "retransmit buffer returns stored packets and evicts beyond capacity" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 3);
    defer buffer.deinit();

    try buffer.onSent(7, "pkt7");
    try buffer.onSent(8, "pkt8");
    try buffer.onSent(9, "pkt9");
    try std.testing.expectEqualSlices(u8, "pkt8", buffer.lookup(8).?);

    try buffer.onSent(10, "pkt10");
    try std.testing.expectEqual(@as(usize, 3), buffer.len());
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(7));
    try std.testing.expectEqualSlices(u8, "pkt10", buffer.lookup(10).?);
}

test "retransmit buffer replaces duplicate extended sequence packet" {
    const allocator = std.testing.allocator;
    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();

    try buffer.onSent(42, "old");
    try buffer.onSent(42, "new");
    try std.testing.expectEqual(@as(usize, 1), buffer.len());
    try std.testing.expectEqualSlices(u8, "new", buffer.lookup(42).?);
}

test "joint recovery retransmit on-time retransmit allowed" {
    // Deadline is the playout budget minus the jitter guard: 200 - 30 = 170.
    try std.testing.expectEqual(@as(i64, 170), retransmitDeadlineMs(200, 30));
    try std.testing.expectEqual(RecoveryDecision.retransmit, decideRecovery(50, 170, 3, true));
    try std.testing.expectEqual(RecoveryDecision.retransmit, decideRecovery(169, 170, 3, false));
}

test "joint recovery retransmit late retransmit dropped and counted" {
    var policy = RecoveryPolicy{ .playout_budget_ms = 200, .jitter_ms = 30 };
    try std.testing.expectEqual(RecoveryDecision.drop_late, policy.decide(171, 3));
    try std.testing.expectEqual(RecoveryDecision.drop_late, policy.decide(1_000, 3));
    try std.testing.expectEqual(@as(u64, 2), policy.dropped_late);
    // On-time decisions do not inflate the late counter.
    try std.testing.expectEqual(RecoveryDecision.retransmit, policy.decide(10, 3));
    try std.testing.expectEqual(@as(u64, 2), policy.dropped_late);
}

test "joint recovery retransmit single-missing prefers local recovery when policy says so" {
    try std.testing.expectEqual(RecoveryDecision.recover_locally, decideRecovery(50, 170, 1, true));
    // Same inputs without the preference fall back to a retransmit.
    try std.testing.expectEqual(RecoveryDecision.retransmit, decideRecovery(50, 170, 1, false));
    // Local preference never resurrects a late packet.
    try std.testing.expectEqual(RecoveryDecision.drop_late, decideRecovery(500, 170, 1, true));
    // Multi-missing loss is not single-missing local recovery.
    try std.testing.expectEqual(RecoveryDecision.retransmit, decideRecovery(50, 170, 2, true));
}

test "joint recovery retransmit exactly at deadline is dropped" {
    // Useful strictly before the deadline, matching retransmitFresh.
    try std.testing.expectEqual(RecoveryDecision.drop_late, decideRecovery(170, 170, 3, false));
    try std.testing.expectEqual(RecoveryDecision.retransmit, decideRecovery(169, 170, 3, false));
    var policy = RecoveryPolicy{ .playout_budget_ms = 200, .jitter_ms = 30 };
    try std.testing.expectEqual(RecoveryDecision.drop_late, policy.decide(170, 1));
    try std.testing.expectEqual(@as(u64, 1), policy.dropped_late);
}

test "joint recovery retransmit bounded and invalid inputs drop late" {
    try std.testing.expectEqual(RecoveryDecision.drop_late, decideRecovery(-1, 170, 3, false));
    try std.testing.expectEqual(RecoveryDecision.drop_late, decideRecovery(10, 170, 0, true));
    try std.testing.expectEqual(RecoveryDecision.drop_late, decideRecovery(10, 0, 3, false));
    // Budget is capped by the existing retransmit freshness bound and the
    // jitter guard cannot make the deadline negative.
    try std.testing.expectEqual(retransmit_max_age_ms, retransmitDeadlineMs(60_000, 0));
    try std.testing.expectEqual(@as(i64, 0), retransmitDeadlineMs(20, 30));
    try std.testing.expectEqual(@as(i64, 0), retransmitDeadlineMs(-5, 0));
}

test "sequence wrap gaps and retransmit lookup are deterministic" {
    const allocator = std.testing.allocator;
    var receiver = Receiver.init(allocator);
    defer receiver.deinit();

    _ = try receiver.onReceived(65534);
    const blocks = try receiver.onReceived(1);
    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqual(@as(u16, 65535), blocks[0].pid);
    try std.testing.expectEqual(@as(u16, 0x0001), blocks[0].blp);

    const fci = try receiver.currentFci();
    const parsed = try parseNackFci(allocator, fci);
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 65535, 0 }, parsed);

    var buffer = RetransmitBuffer.init(allocator, 2);
    defer buffer.deinit();
    try buffer.onSent(65535, "last");
    try buffer.onSent(0, "zero");
    try buffer.onSent(1, "one");
    try std.testing.expectEqual(@as(?[]const u8, null), buffer.lookup(65535));
    try std.testing.expectEqualSlices(u8, "zero", buffer.lookup(0).?);
    try std.testing.expectEqualSlices(u8, "one", buffer.lookup(1).?);
}

fn restoreRetransmitAllocation(allocator: Allocator, source: *const RetransmitBuffer) !void {
    const old_ptr = source.packets.items.ptr;
    const old_newest = source.newest_ext_seq;
    const old_first_ptr = source.packets.items[0].bytes.ptr;
    defer {
        std.testing.expectEqual(old_ptr, source.packets.items.ptr) catch @panic("OLD packet backing changed");
        std.testing.expectEqual(old_newest, source.newest_ext_seq) catch @panic("OLD sequence changed");
        std.testing.expectEqual(old_first_ptr, source.packets.items[0].bytes.ptr) catch @panic("OLD payload moved");
        std.testing.expectEqualStrings("last", source.lookup(65535).?) catch @panic("OLD packet changed");
    }
    var snapshot = try source.capture(allocator, 32);
    defer snapshot.deinit();
    var candidate = try RetransmitBuffer.prepareRestore(allocator, &snapshot, 4, 32);
    defer candidate.deinit();
    try std.testing.expectEqual(source.newest_ext_seq, candidate.newest_ext_seq);
    try std.testing.expectEqualStrings("last", candidate.lookup(65535).?);
    try std.testing.expectEqualStrings("zero", candidate.lookup(0).?);
    try std.testing.expectEqualStrings("one", candidate.lookup(1).?);
}

test "active media DTO retransmit preserves actual wrap reorder duplicate bytes and complete OOM rollback" {
    var source = RetransmitBuffer.init(std.testing.allocator, 4);
    defer source.deinit();
    try source.onSent(65535, "last");
    try source.onSent(1, "old-one");
    try source.onSent(0, "zero");
    try source.onSent(1, "one");
    try std.testing.checkAllAllocationFailures(std.testing.allocator, restoreRetransmitAllocation, .{&source});
    var snapshot = try source.capture(std.testing.allocator, 32);
    defer snapshot.deinit();
    var candidate = try RetransmitBuffer.prepareRestore(std.testing.allocator, &snapshot, 4, 32);
    defer candidate.deinit();
    // Caller may dispose of its snapshot and OLD packet history independently.
    snapshot.packets[0].bytes[0] ^= 1;
    try std.testing.expectEqualStrings("last", candidate.lookup(65535).?);
    try candidate.onSent(2, "two");
    try candidate.onSent(3, "three");
    try std.testing.expect(candidate.lookup(65535) == null);
    try std.testing.expectEqualStrings("last", source.lookup(65535).?);
    try std.testing.expectEqualStrings("zero", candidate.lookup(0).?);
}

test "active media DTO retransmit strict sequence order capacity and preallocation byte admission" {
    var source = RetransmitBuffer.init(std.testing.allocator, 4);
    defer source.deinit();
    try source.onSent(65535, "last");
    try source.onSent(0, "zero");
    var snapshot = try source.capture(std.testing.allocator, 8);
    defer snapshot.deinit();
    var failure = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.Capacity, RetransmitBuffer.prepareRestore(failure.allocator(), &snapshot, 4, 7));
    try std.testing.expectEqual(@as(usize, 0), failure.alloc_index);
    try std.testing.expectError(error.InvalidSnapshot, RetransmitBuffer.prepareRestore(failure.allocator(), &snapshot, 3, 8));
    snapshot.packets[1].seq = 1;
    try std.testing.expectError(error.InvalidSnapshot, RetransmitBuffer.prepareRestore(failure.allocator(), &snapshot, 4, 8));
    snapshot.packets[1].seq = 0;
    const ext = snapshot.packets[1].ext_seq;
    snapshot.packets[1].ext_seq = snapshot.packets[0].ext_seq;
    try std.testing.expectError(error.InvalidSnapshot, snapshot.validate(4, 8));
    snapshot.packets[1].ext_seq = ext;
    snapshot.newest_ext_seq = null;
    try std.testing.expectError(error.InvalidSnapshot, snapshot.validate(4, 8));
    snapshot.newest_ext_seq = source.newest_ext_seq;
    var candidate = try RetransmitBuffer.prepareRestore(std.testing.allocator, &snapshot, 4, 8);
    defer candidate.deinit();
    try std.testing.expectEqualStrings("zero", candidate.lookup(0).?);
}

fn preparedSentAllocationSweep(seq: u16, expected_old: ?[]const u8) !void {
    var refused: usize = 0;
    var observed_success = false;
    for (0..8) |fault| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var source = RetransmitBuffer.init(failing.allocator(), 3);
        defer source.deinit();
        try source.onSent(65535, "last");
        try source.onSent(0, "zero");
        try source.onSent(1, "one");
        const original_ptr = @intFromPtr(source.packets.items.ptr);
        const original_capacity = source.packets.capacity;
        const original_newest = source.newest_ext_seq;
        const original_digest = sentDigest(&source);
        failing.fail_index = failing.alloc_index + fault;
        const prepared = source.prepareSent(seq, "candidate") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            refused += 1;
            try std.testing.expectEqual(original_ptr, @intFromPtr(source.packets.items.ptr));
            try std.testing.expectEqual(original_capacity, source.packets.capacity);
            try std.testing.expectEqual(original_newest, source.newest_ext_seq);
            try std.testing.expectEqualSlices(u8, &original_digest, &sentDigest(&source));
            if (expected_old) |old| try std.testing.expectEqualStrings(old, source.lookup(seq).?);
            failing.fail_index = std.math.maxInt(usize);
            const retry = try source.prepareSent(seq, "candidate");
            defer retry.deinit();
            try retry.validate();
            retry.commitRetainingMetadata();
            try std.testing.expectEqualStrings("candidate", source.lookup(seq).?);
            continue;
        };
        defer prepared.deinit();
        try std.testing.expectEqualSlices(u8, &original_digest, &sentDigest(&source));
        try prepared.validate();
        // Every allocation is already owned. Actual publication makes no new
        // backend call even when the original allocator is armed at its next.
        failing.fail_index = failing.alloc_index;
        const calls_before = failing.alloc_index;
        prepared.commitRetainingMetadata();
        try std.testing.expectEqual(calls_before, failing.alloc_index);
        try std.testing.expectEqualStrings("candidate", source.lookup(seq).?);
        try std.testing.expectEqualStrings("zero", source.lookup(0).?);
        try std.testing.expectEqual(@as(usize, 3), source.len());
        observed_success = true;
        break;
    }
    try std.testing.expectEqual(@as(usize, 3), refused);
    try std.testing.expect(observed_success);
}

test "physical media retransmit prepared allocation sweep retains exact OLD backing payloads and retries" {
    try preparedSentAllocationSweep(1, "one");
    try preparedSentAllocationSweep(2, null);
}

test "physical media retransmit prepared abort stale refusal and too-old insert preserve live history" {
    var source = RetransmitBuffer.init(std.testing.allocator, 2);
    defer source.deinit();
    try source.onSent(100, "hundred");
    try source.onSent(101, "one-oh-one");
    const before = sentDigest(&source);
    {
        const aborted = try source.prepareSent(102, "abort-owned");
        defer aborted.deinit();
        try aborted.validate();
    }
    try std.testing.expectEqualSlices(u8, &before, &sentDigest(&source));
    const stale = try source.prepareSent(102, "stale-owned");
    defer stale.deinit();
    try source.onSent(101, "new-101");
    try std.testing.expectError(error.StaleCandidate, stale.validate());
    try std.testing.expectEqualStrings("new-101", source.lookup(101).?);
    {
        const too_old = try source.prepareSent(99, "discard-owned");
        defer too_old.deinit();
        try too_old.validate();
        too_old.commitRetainingMetadata();
        try std.testing.expect(source.lookup(99) == null);
        try std.testing.expectEqualStrings("hundred", source.lookup(100).?);
        try std.testing.expectEqualStrings("new-101", source.lookup(101).?);
        try std.testing.expectEqual(@as(?i64, 101), source.newest_ext_seq);
    }
    var disabled = RetransmitBuffer.init(std.testing.allocator, 0);
    defer disabled.deinit();
    const empty = try disabled.prepareSent(10, "no-cache");
    defer empty.deinit();
    try empty.validate();
    empty.commitRetainingMetadata();
    try std.testing.expectEqual(@as(usize, 0), disabled.len());
    try std.testing.expect(disabled.newest_ext_seq == null);
}

/// Physical ingress histories are scoped to sender SSRC. Each stable cell owns
/// its independent extended-sequence cache; no live stream is recycled to admit
/// another. All allocation and retirement happens outside routing exclusion.
pub const PerSsrcRetransmitBuffer = struct {
    allocator: Allocator,
    packet_capacity: usize,
    stream_capacity: usize,
    streams: StreamMap = .empty,
    revision: u64 = 1,
    const Cell = struct { cache: RetransmitBuffer };
    const StreamMap = std.AutoHashMapUnmanaged(u32, *Cell);

    /// Exact owned retransmit history for one physical WebRTC publisher. The
    /// caller excludes packet admission while capturing; no live cell or packet
    /// storage is borrowed by the result. Stream IDs are sorted so duplicate or
    /// missing ownership cannot be hidden by hash-map iteration order.
    pub const Snapshot = struct {
        allocator: Allocator,
        packet_capacity: usize,
        stream_capacity: usize,
        revision: u64,
        streams: []Stream,

        pub const Stream = struct {
            ssrc: u32,
            cache: RetransmitBuffer.Snapshot,
        };

        pub fn deinit(self: *Snapshot) void {
            for (self.streams) |*stream| stream.cache.deinit();
            self.allocator.free(self.streams);
            self.* = undefined;
        }

        /// `max_bytes` covers the DTO and every retained packet, not just the
        /// RTP payloads. The aggregate chooses its own bound before decoding.
        pub fn validate(self: *const Snapshot, expected_packet_capacity: usize, expected_stream_capacity: usize, max_bytes: usize) !void {
            if (self.packet_capacity != expected_packet_capacity or self.stream_capacity != expected_stream_capacity or
                self.revision == 0 or self.streams.len > self.stream_capacity)
                return error.InvalidSnapshot;
            var bytes = try snapshotBaseBytes(self.streams.len);
            for (self.streams, 0..) |*stream, index| {
                if (index != 0 and self.streams[index - 1].ssrc >= stream.ssrc) return error.InvalidSnapshot;
                try stream.cache.validate(self.packet_capacity, max_bytes);
                for (stream.cache.packets) |packet| {
                    if (!matchesPacket(packet.bytes, stream.ssrc, packet.seq)) return error.InvalidSnapshot;
                    bytes = std.math.add(usize, bytes, @sizeOf(RetransmitBuffer.Snapshot.Packet)) catch return error.Capacity;
                    bytes = std.math.add(usize, bytes, packet.bytes.len) catch return error.Capacity;
                }
            }
            if (bytes > max_bytes) return error.Capacity;
        }
    };

    fn snapshotBaseBytes(streams: usize) !usize {
        return std.math.add(usize, @sizeOf(Snapshot), std.math.mul(usize, streams, @sizeOf(Snapshot.Stream)) catch return error.Capacity) catch return error.Capacity;
    }

    pub fn capture(self: *const @This(), allocator: Allocator, max_bytes: usize) !Snapshot {
        if (self.revision == 0 or self.streams.count() > self.stream_capacity) return error.InvalidSnapshot;
        var bytes = try snapshotBaseBytes(self.streams.count());
        var preflight = self.streams.iterator();
        while (preflight.next()) |entry| {
            const cache = &entry.value_ptr.*.cache;
            if (cache.capacity != self.packet_capacity or cache.packets.items.len > cache.capacity) return error.InvalidSnapshot;
            for (cache.packets.items) |packet| {
                if (!matchesPacket(packet.bytes, entry.key_ptr.*, packet.seq)) return error.InvalidSnapshot;
                bytes = std.math.add(usize, bytes, @sizeOf(RetransmitBuffer.Snapshot.Packet)) catch return error.Capacity;
                bytes = std.math.add(usize, bytes, packet.bytes.len) catch return error.Capacity;
            }
        }
        if (bytes > max_bytes) return error.Capacity;

        const streams = try allocator.alloc(Snapshot.Stream, self.streams.count());
        var initialized: usize = 0;
        errdefer {
            for (streams[0..initialized]) |*stream| stream.cache.deinit();
            allocator.free(streams);
        }
        var remaining = max_bytes - try snapshotBaseBytes(streams.len);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const cache = try entry.value_ptr.*.cache.capture(allocator, remaining);
            streams[initialized] = .{ .ssrc = entry.key_ptr.*, .cache = cache };
            initialized += 1;
            for (cache.packets) |packet| {
                remaining -= @sizeOf(RetransmitBuffer.Snapshot.Packet) + packet.bytes.len;
            }
        }
        std.mem.sort(Snapshot.Stream, streams, {}, struct {
            fn less(_: void, a: Snapshot.Stream, b: Snapshot.Stream) bool {
                return a.ssrc < b.ssrc;
            }
        }.less);
        const snapshot: Snapshot = .{ .allocator = allocator, .packet_capacity = self.packet_capacity, .stream_capacity = self.stream_capacity, .revision = self.revision, .streams = streams };
        try snapshot.validate(self.packet_capacity, self.stream_capacity, max_bytes);
        return snapshot;
    }

    /// Build a private candidate. The caller joins it with the physical owner
    /// and routing graph before a no-fail publication; failure leaves source
    /// history and retransmit sequence extension unchanged.
    pub fn prepareRestore(allocator: Allocator, snapshot: *const Snapshot, expected_packet_capacity: usize, expected_stream_capacity: usize, max_bytes: usize) !@This() {
        try snapshot.validate(expected_packet_capacity, expected_stream_capacity, max_bytes);
        var candidate = init(allocator, expected_packet_capacity, expected_stream_capacity);
        errdefer candidate.deinit();
        try candidate.streams.ensureTotalCapacity(allocator, @intCast(snapshot.streams.len));
        for (snapshot.streams) |stream| {
            const cell = try allocator.create(Cell);
            errdefer allocator.destroy(cell);
            cell.* = .{ .cache = try RetransmitBuffer.prepareRestore(allocator, &stream.cache, expected_packet_capacity, max_bytes) };
            candidate.streams.putAssumeCapacity(stream.ssrc, cell);
        }
        candidate.revision = snapshot.revision;
        return candidate;
    }

    pub fn init(allocator: Allocator, packet_capacity: usize, stream_capacity: usize) @This() {
        return .{ .allocator = allocator, .packet_capacity = packet_capacity, .stream_capacity = stream_capacity };
    }
    pub fn deinit(self: *@This()) void {
        var it = self.streams.valueIterator();
        while (it.next()) |cell| {
            cell.*.cache.deinit();
            self.allocator.destroy(cell.*);
        }
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn lookup(self: *const @This(), ssrc: u32, seq: u16) ?[]const u8 {
        const cell = self.streams.get(ssrc) orelse return null;
        const bytes = cell.cache.lookup(seq) orelse return null;
        if (!matchesPacket(bytes, ssrc, seq)) return null;
        return bytes;
    }
    pub fn lookupFreshPacket(self: *const @This(), ssrc: u32, seq: u16, now_ms: i64) ?FreshPacket {
        const cell = self.streams.get(ssrc) orelse return null;
        const packet = cell.cache.lookupFreshPacket(seq, now_ms) orelse return null;
        if (!matchesPacket(packet.bytes, ssrc, seq)) return null;
        return packet;
    }
    pub fn lookupFresh(self: *const @This(), ssrc: u32, seq: u16, now_ms: i64) ?[]const u8 {
        return if (self.lookupFreshPacket(ssrc, seq, now_ms)) |packet| packet.bytes else null;
    }
    pub fn len(self: *const @This(), ssrc: u32) usize {
        const cell = self.streams.get(ssrc) orelse return 0;
        return cell.cache.len();
    }
    fn matchesPacket(bytes: []const u8, ssrc: u32, seq: u16) bool {
        return bytes.len >= 12 and bytes[0] >> 6 == 2 and std.mem.readInt(u16, bytes[2..4], .big) == seq and std.mem.readInt(u32, bytes[8..12], .big) == ssrc;
    }
    pub fn prepareSent(self: *@This(), ssrc: u32, seq: u16, bytes: []const u8) !*PreparedPerSsrcSent {
        return self.prepareSentAt(ssrc, seq, bytes, 0);
    }
    pub fn prepareSentAt(self: *@This(), ssrc: u32, seq: u16, bytes: []const u8, sent_ms: i64) !*PreparedPerSsrcSent {
        if (!matchesPacket(bytes, ssrc, seq)) return error.InvalidPacket;
        if (self.revision == 0 or self.revision == std.math.maxInt(u64)) return error.SequenceExhausted;
        const old = self.streams.get(ssrc);
        if (old == null and self.streams.count() >= self.stream_capacity) return error.StreamCapacity;
        const plan = try self.allocator.create(PerSsrcPlan);
        plan.* = .{ .owner = self, .allocator = self.allocator, .ssrc = ssrc, .seq = seq, .old = old, .revision = self.revision, .count = self.streams.count(), .capacity = self.streams.capacity(), .metadata = if (self.streams.metadata) |ptr| @intFromPtr(ptr) else 0 };
        errdefer self.allocator.destroy(plan);
        // One function-wide owner covers every later allocation boundary.
        errdefer {
            if (plan.inner) |inner| inner.deinit();
            if (plan.growth) |*map| map.deinit(self.allocator);
            if (plan.created) |cell| {
                cell.cache.deinit();
                self.allocator.destroy(cell);
            }
        }
        const cell = old orelse create: {
            const new = try self.allocator.create(Cell);
            new.* = .{ .cache = RetransmitBuffer.init(self.allocator, self.packet_capacity) };
            plan.created = new;
            if (self.streams.available == 0) {
                plan.growth = .empty;
                try plan.growth.?.ensureTotalCapacity(self.allocator, self.streams.count() + 1);
            }
            break :create new;
        };
        plan.inner = try cell.cache.prepareSentAt(seq, bytes, sent_ms);
        return @ptrCast(plan);
    }
    /// Allocation-free identity observation; it is never an ownership grant.
    pub fn observationDigest(self: *const @This()) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        std.hash.autoHash(&hash, self.revision);
        std.hash.autoHash(&hash, self.packet_capacity);
        std.hash.autoHash(&hash, self.stream_capacity);
        std.hash.autoHash(&hash, self.streams.count());
        std.hash.autoHash(&hash, self.streams.capacity());
        std.hash.autoHash(&hash, if (self.streams.metadata) |ptr| @intFromPtr(ptr) else @as(usize, 0));
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            std.hash.autoHash(&hash, entry.key_ptr.*);
            std.hash.autoHash(&hash, @intFromPtr(entry.value_ptr.*));
            hash.update(&sentDigest(&entry.value_ptr.*.cache));
        }
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
};
const PerSsrcPlan = struct {
    owner: *PerSsrcRetransmitBuffer,
    allocator: Allocator,
    ssrc: u32,
    seq: u16,
    old: ?*PerSsrcRetransmitBuffer.Cell,
    created: ?*PerSsrcRetransmitBuffer.Cell = null,
    growth: ?PerSsrcRetransmitBuffer.StreamMap = null,
    inner: ?*PreparedSent = null,
    revision: u64,
    count: u32,
    capacity: u32,
    metadata: usize,
    validated: bool = false,
    committed: bool = false,
};
fn perSsrcPlan(candidate: *PreparedPerSsrcSent) *PerSsrcPlan {
    return @ptrCast(@alignCast(candidate));
}
pub const PreparedPerSsrcSent = opaque {
    pub fn validate(self: *@This()) !void {
        const plan = perSsrcPlan(self);
        const owner = plan.owner;
        if (plan.committed or owner.revision != plan.revision or owner.streams.get(plan.ssrc) != plan.old or owner.streams.count() != plan.count or owner.streams.capacity() != plan.capacity or (if (owner.streams.metadata) |ptr| @intFromPtr(ptr) else @as(usize, 0)) != plan.metadata or owner.allocator.ptr != plan.allocator.ptr or owner.allocator.vtable != plan.allocator.vtable) return error.StaleCandidate;
        try plan.inner.?.validate();
        plan.validated = true;
    }
    pub fn commitRetainingMetadata(self: *@This()) void {
        const plan = perSsrcPlan(self);
        const owner = plan.owner;
        std.debug.assert(plan.validated and !plan.committed and owner.revision == plan.revision);
        if (plan.growth) |*growth| {
            var it = owner.streams.iterator();
            while (it.next()) |entry| growth.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
            std.mem.swap(PerSsrcRetransmitBuffer.StreamMap, &owner.streams, growth);
        }
        plan.inner.?.commitRetainingMetadata();
        if (plan.created) |cell| owner.streams.putAssumeCapacity(plan.ssrc, cell);
        owner.revision += 1;
        plan.committed = true;
    }
    pub fn deinit(self: *@This()) void {
        const plan = perSsrcPlan(self);
        const allocator = plan.allocator;
        if (plan.inner) |inner| inner.deinit();
        if (plan.growth) |*map| map.deinit(allocator);
        if (!plan.committed) if (plan.created) |cell| {
            cell.cache.deinit();
            allocator.destroy(cell);
        };
        allocator.destroy(plan);
    }
};

fn perSsrcPacketTest(ssrc: u32, seq: u16, label: u8) [13]u8 {
    var packet: [13]u8 = .{ 0x80, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, label };
    std.mem.writeInt(u16, packet[2..4], seq, .big);
    std.mem.writeInt(u32, packet[8..12], ssrc, .big);
    return packet;
}
fn perSsrcStore(source: *PerSsrcRetransmitBuffer, ssrc: u32, seq: u16, label: u8) !void {
    const packet = perSsrcPacketTest(ssrc, seq, label);
    const plan = try source.prepareSent(ssrc, seq, &packet);
    defer plan.deinit();
    try plan.validate();
    plan.commitRetainingMetadata();
}
test "physical media per-SSRC owned snapshot restores packet and rollover authority" {
    const testing = std.testing;
    var source = PerSsrcRetransmitBuffer.init(testing.allocator, 3, 2);
    defer source.deinit();
    try perSsrcStore(&source, 7, 65535, 'a');
    try perSsrcStore(&source, 9, 42, 'b');
    try perSsrcStore(&source, 7, 0, 'c');
    const old = source.observationDigest();

    var snapshot = try source.capture(testing.allocator, 4096);
    defer snapshot.deinit();
    try testing.expectEqual(@as(u32, 7), snapshot.streams[0].ssrc);
    try testing.expectEqual(@as(u32, 9), snapshot.streams[1].ssrc);
    try testing.expectEqual(@as(?i64, 65536), snapshot.streams[0].cache.newest_ext_seq);
    var restored = try PerSsrcRetransmitBuffer.prepareRestore(testing.allocator, &snapshot, 3, 2, 4096);
    defer restored.deinit();
    try testing.expectEqual(source.revision, restored.revision);
    try testing.expectEqualSlices(u8, source.lookup(7, 65535).?, restored.lookup(7, 65535).?);
    try testing.expectEqualSlices(u8, source.lookup(7, 0).?, restored.lookup(7, 0).?);
    try testing.expectEqualSlices(u8, source.lookup(9, 42).?, restored.lookup(9, 42).?);
    try testing.expectEqualSlices(u8, &old, &source.observationDigest());

    // The next packet extends the same SSRC sequence cycle in both owners.
    try perSsrcStore(&source, 7, 1, 'd');
    try perSsrcStore(&restored, 7, 1, 'd');
    var next = try restored.capture(testing.allocator, 4096);
    defer next.deinit();
    try testing.expectEqual(@as(?i64, 65537), next.streams[0].cache.newest_ext_seq);
    try testing.expectEqualSlices(u8, source.lookup(7, 1).?, restored.lookup(7, 1).?);
}

test "physical media per-SSRC snapshot rejects missing index packet substitution and truncated budget" {
    const testing = std.testing;
    var source = PerSsrcRetransmitBuffer.init(testing.allocator, 2, 2);
    defer source.deinit();
    try perSsrcStore(&source, 7, 1, 'a');
    try perSsrcStore(&source, 9, 1, 'b');
    var snapshot = try source.capture(testing.allocator, 4096);
    defer snapshot.deinit();
    const old = source.observationDigest();

    try testing.expectError(error.InvalidSnapshot, PerSsrcRetransmitBuffer.prepareRestore(testing.allocator, &snapshot, 2, 1, 4096));
    try testing.expectError(error.Capacity, PerSsrcRetransmitBuffer.prepareRestore(testing.allocator, &snapshot, 2, 2, 16));
    std.mem.swap(PerSsrcRetransmitBuffer.Snapshot.Stream, &snapshot.streams[0], &snapshot.streams[1]);
    try testing.expectError(error.InvalidSnapshot, snapshot.validate(2, 2, 4096));
    std.mem.swap(PerSsrcRetransmitBuffer.Snapshot.Stream, &snapshot.streams[0], &snapshot.streams[1]);
    snapshot.streams[0].cache.packets[0].bytes[8] ^= 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate(2, 2, 4096));
    snapshot.streams[0].cache.packets[0].bytes[8] ^= 1;
    snapshot.streams[0].cache.newest_ext_seq = null;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate(2, 2, 4096));
    snapshot.streams[0].cache.newest_ext_seq = 1;
    snapshot.revision = 0;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate(2, 2, 4096));
    snapshot.revision = source.revision;
    try snapshot.validate(2, 2, 4096);
    try testing.expectEqualSlices(u8, &old, &source.observationDigest());
}

fn perSsrcSnapshotAllocationSweep(allocator: Allocator) !void {
    var source = PerSsrcRetransmitBuffer.init(allocator, 2, 2);
    defer source.deinit();
    try perSsrcStore(&source, 7, 65535, 'a');
    try perSsrcStore(&source, 7, 0, 'b');
    try perSsrcStore(&source, 9, 2, 'c');
    const before = source.observationDigest();
    var snapshot = source.capture(allocator, 4096) catch |err| {
        try std.testing.expectEqualSlices(u8, &before, &source.observationDigest());
        return err;
    };
    defer snapshot.deinit();
    var restored = PerSsrcRetransmitBuffer.prepareRestore(allocator, &snapshot, 2, 2, 4096) catch |err| {
        try std.testing.expectEqualSlices(u8, &before, &source.observationDigest());
        return err;
    };
    defer restored.deinit();
    try std.testing.expectEqualSlices(u8, source.lookup(7, 0).?, restored.lookup(7, 0).?);
    try std.testing.expectEqualSlices(u8, &before, &source.observationDigest());
}
test "physical media per-SSRC snapshot allocation failures leave source and retries exact" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, perSsrcSnapshotAllocationSweep, .{});
}
test "physical media per-SSRC cache retains independent equal sequence rollover and bounded stream custody" {
    var source = PerSsrcRetransmitBuffer.init(std.testing.allocator, 3, 2);
    defer source.deinit();
    for ([_]struct { ssrc: u32, seq: u16, label: u8 }{ .{ .ssrc = 1, .seq = 65535, .label = 'a' }, .{ .ssrc = 2, .seq = 65535, .label = 'b' }, .{ .ssrc = 1, .seq = 0, .label = 'c' }, .{ .ssrc = 2, .seq = 65534, .label = 'd' } }) |entry| {
        const packet = perSsrcPacketTest(entry.ssrc, entry.seq, entry.label);
        const candidate = try source.prepareSent(entry.ssrc, entry.seq, &packet);
        defer candidate.deinit();
        try candidate.validate();
        candidate.commitRetainingMetadata();
    }
    try std.testing.expectEqual(@as(u8, 'a'), source.lookup(1, 65535).?[12]);
    try std.testing.expectEqual(@as(u8, 'b'), source.lookup(2, 65535).?[12]);
    try std.testing.expectEqual(@as(u8, 'c'), source.lookup(1, 0).?[12]);
    try std.testing.expectEqual(@as(u8, 'd'), source.lookup(2, 65534).?[12]);
    const old = source.observationDigest();
    const packet = perSsrcPacketTest(3, 1, 'x');
    try std.testing.expectError(error.StreamCapacity, source.prepareSent(3, 1, &packet));
    try std.testing.expectEqualSlices(u8, &old, &source.observationDigest());
    try std.testing.expectError(error.InvalidPacket, source.prepareSent(2, 1, &packet));
}
fn perSsrcCacheAllocationSweep(allocator: Allocator) !void {
    var source = PerSsrcRetransmitBuffer.init(allocator, 2, 8);
    defer source.deinit();
    for ([_]u32{ 1, 2, 3, 4, 5, 6 }) |ssrc| {
        const packet = perSsrcPacketTest(ssrc, 7, @intCast(ssrc));
        const old = source.observationDigest();
        const candidate = source.prepareSent(ssrc, 7, &packet) catch |err| {
            try std.testing.expectEqualSlices(u8, &old, &source.observationDigest());
            return err;
        };
        defer candidate.deinit();
        try candidate.validate();
        candidate.commitRetainingMetadata();
    }
    const replacement = perSsrcPacketTest(1, 8, 9);
    const old = source.observationDigest();
    const candidate = source.prepareSent(1, 8, &replacement) catch |err| {
        try std.testing.expectEqualSlices(u8, &old, &source.observationDigest());
        return err;
    };
    defer candidate.deinit();
    try candidate.validate();
    candidate.commitRetainingMetadata();
    for ([_]u32{ 1, 2, 3, 4, 5, 6 }) |ssrc| try std.testing.expectEqual(@as(u8, @intCast(ssrc)), source.lookup(ssrc, 7).?[12]);
}
test "physical media per-SSRC cache allocation sweep covers created cells growth existing histories and exact unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, perSsrcCacheAllocationSweep, .{});
}

fn perSsrcRetryBoundaryTest(existing: bool, growth: bool) !void {
    var refused: usize = 0;
    var completed = false;
    for (0..16) |index| {
        var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var source = PerSsrcRetransmitBuffer.init(fail.allocator(), 2, 32);
        defer source.deinit();
        if (existing or growth) {
            var ssrc: u32 = 1;
            while (true) : (ssrc += 1) {
                const packet = perSsrcPacketTest(ssrc, 65535, @intCast(ssrc));
                const seed = try source.prepareSent(ssrc, 65535, &packet);
                {
                    defer seed.deinit();
                    try seed.validate();
                    seed.commitRetainingMetadata();
                }
                if (!growth or source.streams.available == 0) break;
                try std.testing.expect(ssrc < 32);
            }
        }
        const ssrc: u32 = if (existing) 1 else 31;
        const packet = perSsrcPacketTest(ssrc, 0, 'z');
        const before = source.observationDigest();
        fail.fail_index = fail.alloc_index + index;
        const candidate = source.prepareSent(ssrc, 0, &packet) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqualSlices(u8, &before, &source.observationDigest());
            refused += 1;
            fail.fail_index = std.math.maxInt(usize);
            const retry = try source.prepareSent(ssrc, 0, &packet);
            defer retry.deinit();
            try retry.validate();
            retry.commitRetainingMetadata();
            try std.testing.expectEqualSlices(u8, &packet, source.lookup(ssrc, 0).?);
            if (existing) try std.testing.expectEqual(@as(u8, 1), source.lookup(1, 65535).?[12]);
            continue;
        };
        defer candidate.deinit();
        try candidate.validate();
        fail.fail_index = fail.alloc_index;
        const before_calls = fail.alloc_index;
        candidate.commitRetainingMetadata();
        try std.testing.expectEqual(before_calls, fail.alloc_index);
        try std.testing.expectEqualSlices(u8, &packet, source.lookup(ssrc, 0).?);
        completed = true;
        break;
    }
    try std.testing.expect(refused > 0 and completed);
}
test "physical media per-SSRC cache every new existing growth allocation refusal retains exact source and same-owner retry" {
    try perSsrcRetryBoundaryTest(false, false);
    try perSsrcRetryBoundaryTest(true, false);
    try perSsrcRetryBoundaryTest(false, true);
}

test "retransmit age boundary wrap and snapshot preserve original deadline" {
    const a = std.testing.allocator;
    var source = RetransmitBuffer.init(a, 2);
    defer source.deinit();
    try source.onSentAt(65535, "before-wrap", 100);
    try source.onSentAt(0, "after-wrap", 101);
    try std.testing.expectEqualStrings("before-wrap", source.lookupFresh(65535, 1099).?);
    try std.testing.expect(source.lookupFresh(65535, 1100) == null);
    try std.testing.expect(source.lookupFresh(0, 100) == null);
    try std.testing.expectEqualStrings("after-wrap", source.lookupFresh(0, 1100).?);
    try std.testing.expect(source.lookupFresh(0, 1101) == null);
    var snap = try source.capture(a, 4096);
    defer snap.deinit();
    var restored = try RetransmitBuffer.prepareRestore(a, &snap, 2, 4096);
    defer restored.deinit();
    try std.testing.expectEqual(@as(i64, 100), snap.packets[0].sent_ms);
    try std.testing.expectEqualStrings("before-wrap", restored.lookupFresh(65535, 1099).?);
    try std.testing.expect(restored.lookupFresh(65535, 1100) == null);
    try std.testing.expect(restored.lookupFresh(0, std.math.maxInt(i64)) == null);
    try source.onSentAt(1, "unknown-time", 0);
    try std.testing.expect(source.lookupFresh(1, 1) == null);
}

fn ageAllocationCuts(a: Allocator) !void {
    var source = RetransmitBuffer.init(a, 2);
    defer source.deinit();
    try source.onSentAt(10, "old", 100);
    const old = source.newest_ext_seq;
    const plan = source.prepareSentAt(11, "new", 101) catch |err| {
        std.debug.assert(source.newest_ext_seq == old);
        std.debug.assert(source.lookupFresh(10, 101) != null);
        return err;
    };
    defer plan.deinit();
    try plan.validate();
    plan.commitRetainingMetadata();
    var snapshot = try source.capture(a, 4096);
    defer snapshot.deinit();
    var restored = try RetransmitBuffer.prepareRestore(a, &snapshot, 2, 4096);
    defer restored.deinit();
    try std.testing.expectEqualStrings("new", restored.lookupFresh(11, 1100).?);
    try std.testing.expect(restored.lookupFresh(11, 1101) == null);
}
test "retransmit age prepare and snapshot allocation cuts remain atomic" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ageAllocationCuts, .{});
}

test "retransmit stale pressure remains a bounded miss without changing retained fresh packets" {
    const a = std.testing.allocator;
    var source = RetransmitBuffer.init(a, 2);
    defer source.deinit();
    try source.onSentAt(10, "old", 100);
    try source.onSentAt(11, "fresh", 1099);
    for (0..512) |_| try std.testing.expect(source.lookupFresh(10, 1100) == null);
    try std.testing.expectEqual(@as(usize, 2), source.len());
    try std.testing.expectEqualStrings("fresh", source.lookupFresh(11, 1100).?);
    try std.testing.expect(source.lookupFresh(11, 99) == null);
}

test "retransmit duplicate keeps original lifetime in ordinary and prepared caches" {
    const a = std.testing.allocator;
    var ordinary = RetransmitBuffer.init(a, 4);
    defer ordinary.deinit();
    try ordinary.onSentAt(65535, "old", 100);
    try ordinary.onSentAt(65535, "replacement", 1099);
    try std.testing.expectEqualStrings("replacement", ordinary.lookupFresh(65535, 1099).?);
    try std.testing.expect(ordinary.lookupFresh(65535, 1100) == null);
    try ordinary.onSentAt(0, "new-cycle", 1100);
    try std.testing.expectEqualStrings("new-cycle", ordinary.lookupFresh(0, 1100).?);
    var snap = try ordinary.capture(a, 4096);
    defer snap.deinit();
    try std.testing.expectEqual(@as(i64, 100), snap.packets[0].sent_ms);
    try std.testing.expectEqual(@as(i64, 1100), snap.packets[1].sent_ms);
    var restored = try RetransmitBuffer.prepareRestore(a, &snap, 4, 4096);
    defer restored.deinit();
    try std.testing.expect(restored.lookupFresh(65535, 1100) == null);
    try std.testing.expectEqualStrings("new-cycle", restored.lookupFresh(0, 1100).?);
    try ordinary.onSentAt(1, "unknown", 0);
    try ordinary.onSentAt(1, "unknown-replaced", 1200);
    try std.testing.expect(ordinary.lookupFresh(1, 1200) == null);
    var prepared = RetransmitBuffer.init(a, 2);
    defer prepared.deinit();
    try prepared.onSentAt(9, "old", 100);
    const plan = try prepared.prepareSentAt(9, "replacement", 1099);
    defer plan.deinit();
    try plan.validate();
    plan.commitRetainingMetadata();
    try std.testing.expectEqualStrings("replacement", prepared.lookupFresh(9, 1099).?);
    try std.testing.expect(prepared.lookupFresh(9, 1100) == null);
    var copy = try prepared.capture(a, 4096);
    defer copy.deinit();
    try std.testing.expectEqual(@as(i64, 100), copy.packets[0].sent_ms);
    var unknown = RetransmitBuffer.init(a, 1);
    defer unknown.deinit();
    try unknown.onSentAt(3, "unknown", 0);
    const unknown_plan = try unknown.prepareSentAt(3, "replacement", 1200);
    defer unknown_plan.deinit();
    try unknown_plan.validate();
    unknown_plan.commitRetainingMetadata();
    try std.testing.expect(unknown.lookupFresh(3, 1200) == null);
}

fn duplicateOrdinaryAllocationSweep(a: Allocator) !void {
    var cache = RetransmitBuffer.init(a, 2);
    defer cache.deinit();
    try cache.onSentAt(9, "old", 100);
    const original = cache.lookup(9).?;
    const ptr = original.ptr;
    cache.onSentAt(9, "replacement", 1099) catch |err| {
        std.debug.assert(cache.lookup(9).?.ptr == ptr);
        std.debug.assert(std.mem.eql(u8, cache.lookupFresh(9, 1099).?, "old"));
        std.debug.assert(cache.lookupFresh(9, 1100) == null);
        return err;
    };
    try std.testing.expectEqualStrings("replacement", cache.lookupFresh(9, 1099).?);
    try std.testing.expect(cache.lookupFresh(9, 1100) == null);
}
test "retransmit ordinary duplicate allocation rollback preserves original lifetime" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, duplicateOrdinaryAllocationSweep, .{});
}

fn duplicatePerSsrcAllocationSweep(a: Allocator) !void {
    var cache = PerSsrcRetransmitBuffer.init(a, 2, 2);
    defer cache.deinit();
    var packet: [13]u8 = @splat(0);
    packet[0] = 0x80;
    std.mem.writeInt(u16, packet[2..4], 9, .big);
    std.mem.writeInt(u32, packet[8..12], 7, .big);
    packet[12] = 'a';
    const first = try cache.prepareSentAt(7, 9, &packet, 100);
    defer first.deinit();
    try first.validate();
    first.commitRetainingMetadata();
    const before = cache.observationDigest();
    packet[12] = 'b';
    const duplicate = cache.prepareSentAt(7, 9, &packet, 1099) catch |err| {
        std.debug.assert(std.mem.eql(u8, &before, &cache.observationDigest()));
        std.debug.assert(cache.lookupFresh(7, 9, 1099).?[12] == 'a');
        return err;
    };
    defer duplicate.deinit();
    try duplicate.validate();
    duplicate.commitRetainingMetadata();
    try std.testing.expectEqual(@as(u8, 'b'), cache.lookupFresh(7, 9, 1099).?[12]);
    try std.testing.expect(cache.lookupFresh(7, 9, 1100) == null);
    var snapshot = try cache.capture(a, 4096);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(i64, 100), snapshot.streams[0].cache.packets[0].sent_ms);
    var restored = try PerSsrcRetransmitBuffer.prepareRestore(a, &snapshot, 2, 2, 4096);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u8, 'b'), restored.lookupFresh(7, 9, 1099).?[12]);
    try std.testing.expect(restored.lookupFresh(7, 9, 1100) == null);
}
test "retransmit per-SSRC duplicate lifetime and all allocation cuts" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, duplicatePerSsrcAllocationSweep, .{});
}
