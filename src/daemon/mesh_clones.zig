// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-wide clone aggregation, IP-keyed via a salted hash.
//!
//! Each node tracks its LOCAL concurrent-connection count per salted-IP-hash and
//! learns peers' per-hash counts through gossip. The network-wide count for a
//! hash is `local + Σ remote[node]`, maintained incrementally so the hot-path
//! lookup at registration is O(1).
//!
//! Raw client IPs NEVER appear here or on the wire: callers pass a precomputed
//! `u64` produced by `hashIp` (a keyed SipHash over the address bytes using a key
//! derived from the shared mesh secret, so the same IP maps to the same hash on
//! every node). This keeps a true per-IP network clone cap without gossiping
//! addresses. Pure: no clock, no I/O.

const std = @import("std");

pub const max_checkpoint_bytes: usize = @import("helix/live.zig").max_arena_bytes;
pub const max_checkpoint_entries: usize = 1_048_576;
pub const checkpoint_magic = [_]u8{ 'M', 'C', 'L', 'N' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4 + 4 + 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_domain = "onyx-mesh-clones-checkpoint-v1";

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Allocation-free structural validation for the Helix relation pass.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const local_count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    const remote_count: usize = std.mem.readInt(u32, bytes[16..20], .little);
    if (local_count > max_checkpoint_entries or remote_count > max_checkpoint_entries) return error.CheckpointTooLarge;
    const local_bytes = std.math.mul(usize, local_count, 12) catch return error.CheckpointTooLarge;
    const remote_bytes = std.math.mul(usize, remote_count, 20) catch return error.CheckpointTooLarge;
    const expected_body_len = std.math.add(usize, local_bytes, remote_bytes) catch return error.CheckpointTooLarge;
    if (body_len != expected_body_len) return error.InvalidField;
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved_digest: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved_digest)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[checkpoint_header_len .. bytes.len - checkpoint_checksum_len] };
    var previous_local: ?u64 = null;
    for (0..local_count) |_| {
        const hash = try reader.readU64();
        const count = try reader.readU32();
        if (count == 0) return error.InvalidField;
        if (previous_local) |previous| if (hash <= previous) return error.NonCanonicalOrder;
        previous_local = hash;
    }
    var previous_remote: ?RemoteRow = null;
    for (0..remote_count) |_| {
        const hash = try reader.readU64();
        const node = try reader.readU64();
        const count = try reader.readU32();
        if (count == 0) return error.InvalidField;
        const row = RemoteRow{ .key = .{ .hash = hash, .node = node }, .count = count };
        if (previous_remote) |previous| if (!remoteLess({}, previous, row)) return error.NonCanonicalOrder;
        previous_remote = row;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

const RemoteRow = struct {
    key: MeshClones.RemoteKey,
    count: u32,
};

fn localLess(_: void, a: Entry, b: Entry) bool {
    return a.hash < b.hash;
}

fn remoteLess(_: void, a: RemoteRow, b: RemoteRow) bool {
    if (a.key.hash != b.key.hash) return a.key.hash < b.key.hash;
    return a.key.node < b.key.node;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
};

/// Hash an address's raw bytes with the mesh-wide `key` (16 bytes). Stable across
/// nodes that share the secret, so a given IP collapses to one hash network-wide.
pub fn hashIp(key: [16]u8, ip_bytes: []const u8) u64 {
    return std.hash.SipHash64(1, 3).toInt(ip_bytes, &key);
}

pub const MeshClones = struct {
    allocator: std.mem.Allocator,
    /// iphash -> this node's live connection count.
    local: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// {node, iphash} -> that peer's last-gossiped count.
    remote: std.AutoHashMapUnmanaged(RemoteKey, u32) = .empty,
    /// iphash -> Σ over peers of `remote`, kept in step with `remote` so
    /// `networkCount` is O(1).
    remote_total: std.AutoHashMapUnmanaged(u64, u32) = .empty,

    pub const RemoteKey = struct { node: u64, hash: u64 };

    pub fn init(allocator: std.mem.Allocator) MeshClones {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MeshClones) void {
        self.local.deinit(self.allocator);
        self.remote.deinit(self.allocator);
        self.remote_total.deinit(self.allocator);
        self.* = undefined;
    }

    /// Record one new local connection for `hash`; returns the new local count.
    pub fn addLocal(self: *MeshClones, hash: u64) std.mem.Allocator.Error!u32 {
        const gop = try self.local.getOrPut(self.allocator, hash);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        return gop.value_ptr.*;
    }

    /// Release one local connection for `hash`; returns the remaining local count.
    /// A zero count removes the entry. Releasing an untracked hash is a no-op.
    pub fn removeLocal(self: *MeshClones, hash: u64) u32 {
        const e = self.local.getPtr(hash) orelse return 0;
        if (e.* <= 1) {
            _ = self.local.remove(hash);
            return 0;
        }
        e.* -= 1;
        return e.*;
    }

    pub fn localCount(self: *const MeshClones, hash: u64) u32 {
        return self.local.get(hash) orelse 0;
    }

    /// Apply a peer's authoritative count for `(node, hash)`. A `0` count clears
    /// the entry. Both maps reserve space before either is changed, so OOM
    /// leaves the admitted counts untouched. Saturated totals are recomputed
    /// when a peer lowers its contribution, recovering the true remaining sum.
    pub fn setRemote(self: *MeshClones, node: u64, hash: u64, count: u32) std.mem.Allocator.Error!void {
        const key = RemoteKey{ .node = node, .hash = hash };
        const old: u32 = self.remote.get(key) orelse 0;
        if (count == old) return;
        const total = self.totalAfterRemoteUpdate(key, old, count);
        if (old == 0 and count != 0) try self.remote.ensureUnusedCapacity(self.allocator, 1);
        if (total != 0 and self.remote_total.get(hash) == null)
            try self.remote_total.ensureUnusedCapacity(self.allocator, 1);

        if (count == 0) {
            _ = self.remote.remove(key);
        } else {
            self.remote.putAssumeCapacity(key, count);
        }
        if (total == 0) {
            _ = self.remote_total.remove(hash);
        } else {
            self.remote_total.putAssumeCapacity(hash, total);
        }
    }

    /// Drop every contribution from `node` (on link-down / SQUIT) so a vanished
    /// peer's connections stop counting toward the network total.
    pub fn dropNode(self: *MeshClones, node: u64) void {
        // Collect this node's keys first (removing during iteration is unsafe),
        // then unwind each from `remote` and `remote_total`.
        var it = self.remote.iterator();
        var batch: [256]RemoteKey = undefined;
        while (true) {
            var n: usize = 0;
            it = self.remote.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.node != node) continue;
                batch[n] = entry.key_ptr.*;
                n += 1;
                if (n == batch.len) break;
            }
            if (n == 0) break;
            for (batch[0..n]) |k| {
                // In a consistent live map, a removal cannot allocate: the
                // aggregate key is already present, or its result is zero.
                // On a previously inconsistent map, retain a contribution if
                // its correction cannot be represented under OOM.
                self.setRemote(k.node, k.hash, 0) catch return;
            }
        }
    }

    /// Network-wide live count for `hash`: this node plus every peer's last
    /// gossiped count. O(1).
    pub fn networkCount(self: *const MeshClones, hash: u64) u32 {
        return (self.local.get(hash) orelse 0) +| (self.remote_total.get(hash) orelse 0);
    }

    /// Iterate this node's local (hash, count) pairs — for an anti-entropy burst
    /// to a freshly linked peer.
    pub fn localIterator(self: *const MeshClones) std.AutoHashMapUnmanaged(u64, u32).Iterator {
        return self.local.iterator();
    }

    /// Serialize local and per-peer counts in canonical order. The cached
    /// aggregate is checked against those rows before sealing; an inconsistent
    /// live aggregate must abort the upgrade rather than change admission on
    /// restore. The caller owns the returned bytes.
    pub fn exportUpgradeCheckpoint(self: *const MeshClones, allocator: std.mem.Allocator) CheckpointError![]u8 {
        const local_count = self.local.count();
        const remote_count = self.remote.count();
        if (local_count > max_checkpoint_entries or remote_count > max_checkpoint_entries or
            self.remote_total.count() > max_checkpoint_entries)
            return error.CheckpointTooLarge;

        const locals = try allocator.alloc(Entry, local_count);
        defer allocator.free(locals);
        const remotes = try allocator.alloc(RemoteRow, remote_count);
        defer allocator.free(remotes);
        var local_it = self.local.iterator();
        var n: usize = 0;
        while (local_it.next()) |entry| : (n += 1) {
            if (n >= locals.len) return error.InvalidField;
            locals[n] = .{ .hash = entry.key_ptr.*, .count = entry.value_ptr.* };
        }
        if (n != locals.len) return error.InvalidField;
        std.mem.sort(Entry, locals, {}, localLess);
        for (locals) |row| if (row.count == 0) return error.InvalidField;

        var remote_it = self.remote.iterator();
        n = 0;
        while (remote_it.next()) |entry| : (n += 1) {
            if (n >= remotes.len) return error.InvalidField;
            remotes[n] = .{ .key = entry.key_ptr.*, .count = entry.value_ptr.* };
        }
        if (n != remotes.len) return error.InvalidField;
        std.mem.sort(RemoteRow, remotes, {}, remoteLess);
        var previous_hash: ?u64 = null;
        var sum: u64 = 0;
        var total_count: usize = 0;
        for (remotes) |row| {
            if (row.count == 0) return error.InvalidField;
            if (previous_hash) |hash| {
                if (row.key.hash != hash) {
                    if (self.remote_total.get(hash) != @as(u32, @intCast(@min(sum, std.math.maxInt(u32)))))
                        return error.InvalidField;
                    total_count += 1;
                    sum = 0;
                }
            }
            sum += row.count;
            previous_hash = row.key.hash;
        }
        if (previous_hash) |hash| {
            if (self.remote_total.get(hash) != @as(u32, @intCast(@min(sum, std.math.maxInt(u32)))))
                return error.InvalidField;
            total_count += 1;
        }
        if (total_count != self.remote_total.count()) return error.InvalidField;

        const local_bytes = std.math.mul(usize, local_count, 12) catch return error.CheckpointTooLarge;
        const remote_bytes = std.math.mul(usize, remote_count, 20) catch return error.CheckpointTooLarge;
        const body_len = std.math.add(usize, local_bytes, remote_bytes) catch return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
        if (total_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(body_len));
        writer.writeU32(@intCast(local_count));
        writer.writeU32(@intCast(remote_count));
        for (locals) |row| {
            writer.writeU64(row.hash);
            writer.writeU32(row.count);
        }
        for (remotes) |row| {
            writer.writeU64(row.key.hash);
            writer.writeU64(row.key.node);
            writer.writeU32(row.count);
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        return out;
    }

    /// Decode into a fresh object so the caller can stage it before COMMIT.
    /// remote_total is rebuilt only from canonical, nonzero per-peer rows.
    pub fn restoreUpgradeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) CheckpointError!MeshClones {
        try validateUpgradeCheckpoint(bytes);
        const local_count: usize = std.mem.readInt(u32, bytes[12..16], .little);
        const remote_count: usize = std.mem.readInt(u32, bytes[16..20], .little);

        var restored = MeshClones.init(allocator);
        errdefer restored.deinit();
        var reader = CheckpointReader{ .bytes = bytes[checkpoint_header_len .. bytes.len - checkpoint_checksum_len] };
        var previous_local: ?u64 = null;
        for (0..local_count) |_| {
            const hash = try reader.readU64();
            const count = try reader.readU32();
            if (count == 0) return error.InvalidField;
            if (previous_local) |previous| if (hash <= previous) return error.NonCanonicalOrder;
            try restored.local.put(allocator, hash, count);
            previous_local = hash;
        }
        var previous_remote: ?RemoteRow = null;
        for (0..remote_count) |_| {
            const hash = try reader.readU64();
            const node = try reader.readU64();
            const count = try reader.readU32();
            if (count == 0) return error.InvalidField;
            const row = RemoteRow{ .key = .{ .hash = hash, .node = node }, .count = count };
            if (previous_remote) |previous| if (!remoteLess({}, previous, row)) return error.NonCanonicalOrder;
            try restored.setRemote(node, hash, count);
            previous_remote = row;
        }
        if (reader.remaining() != 0) return error.TrailingBytes;
        return restored;
    }

    /// Replace this map only after the complete staged decode succeeds.
    pub fn replaceFromUpgradeCheckpoint(self: *MeshClones, bytes: []const u8) CheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, bytes);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }

    fn totalAfterRemoteUpdate(self: *const MeshClones, key: RemoteKey, old: u32, new: u32) u32 {
        const cached = self.remote_total.get(key.hash) orelse 0;
        if (cached >= old and (cached != std.math.maxInt(u32) or new >= old)) {
            const next = @as(u64, cached - old) + new;
            return @intCast(@min(next, std.math.maxInt(u32)));
        }

        // A saturated aggregate loses the excess above u32. On a decrease,
        // derive the true sum from all peers instead of subtracting from the
        // saturated value. This also repairs an older missing/low cache entry.
        var sum: u128 = new;
        var it = self.remote.iterator();
        while (it.next()) |entry| {
            const other = entry.key_ptr.*;
            if (other.hash == key.hash and other.node != key.node) sum += entry.value_ptr.*;
        }
        return @intCast(@min(sum, std.math.maxInt(u32)));
    }
};

// -- Wire codec --------------------------------------------------------------
// A clone-count gossip frame payload is a bounded batch of (hash, count) pairs
// in a fixed little-endian binary layout — no text, no escaping, no allocation.
// The originating node is NOT in the payload: the receiver attributes the counts
// to the authenticated S2S link's node id, so a peer cannot spoof another node's
// counts. Layout: `u32 n` then `n × (u64 hash, u32 count)`.

/// Cap on entries per frame, bounding both encode size and decode work.
pub const max_entries_per_frame: usize = 2048;
/// Bytes per (hash, count) entry.
pub const entry_bytes: usize = 12;

pub const Entry = struct { hash: u64, count: u32 };

pub const CodecError = error{ Truncated, TooManyEntries, ShortBuffer };

/// Bytes needed to encode `n` entries.
pub fn encodedLen(n: usize) usize {
    return 4 + n * entry_bytes;
}

/// Encode `entries` into `out`; returns the written slice.
pub fn encodeCounts(out: []u8, entries: []const Entry) CodecError![]u8 {
    if (entries.len > max_entries_per_frame) return error.TooManyEntries;
    const need = encodedLen(entries.len);
    if (out.len < need) return error.ShortBuffer;
    std.mem.writeInt(u32, out[0..4], @intCast(entries.len), .little);
    var off: usize = 4;
    for (entries) |e| {
        std.mem.writeInt(u64, out[off..][0..8], e.hash, .little);
        std.mem.writeInt(u32, out[off + 8 ..][0..4], e.count, .little);
        off += entry_bytes;
    }
    return out[0..need];
}

/// A validated, non-owning view over a decoded counts payload. `get(i)` for
/// `i < n` is bounds-safe because `decodeCounts` proved the body length.
pub const CountsView = struct {
    n: u32,
    body: []const u8,

    pub fn get(self: CountsView, i: u32) Entry {
        const off = @as(usize, i) * entry_bytes;
        return .{
            .hash = std.mem.readInt(u64, self.body[off..][0..8], .little),
            .count = std.mem.readInt(u32, self.body[off + 8 ..][0..4], .little),
        };
    }
};

/// Decode a counts payload, rejecting truncated input and over-long batches.
/// Never allocates and never reads out of bounds.
pub fn decodeCounts(payload: []const u8) CodecError!CountsView {
    if (payload.len < 4) return error.Truncated;
    const n = std.mem.readInt(u32, payload[0..4], .little);
    if (n > max_entries_per_frame) return error.TooManyEntries;
    const need = encodedLen(n);
    if (payload.len < need) return error.Truncated;
    return .{ .n = n, .body = payload[4..need] };
}

// -- Tests -------------------------------------------------------------------

test "counts codec round-trips a batch" {
    var buf: [256]u8 = undefined;
    const entries = [_]Entry{
        .{ .hash = 0x0102030405060708, .count = 3 },
        .{ .hash = 0xdeadbeefcafef00d, .count = 1 },
        .{ .hash = 0, .count = 0 },
    };
    const wire = try encodeCounts(&buf, &entries);
    try std.testing.expectEqual(encodedLen(entries.len), wire.len);

    const view = try decodeCounts(wire);
    try std.testing.expectEqual(@as(u32, 3), view.n);
    for (entries, 0..) |e, i| {
        const got = view.get(@intCast(i));
        try std.testing.expectEqual(e.hash, got.hash);
        try std.testing.expectEqual(e.count, got.count);
    }
}

test "counts codec rejects malformed input" {
    // Empty / too-short header.
    try std.testing.expectError(error.Truncated, decodeCounts(&[_]u8{}));
    try std.testing.expectError(error.Truncated, decodeCounts(&[_]u8{ 1, 0 }));
    // Header claims 2 entries but the body is short.
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 2, .little);
    try std.testing.expectError(error.Truncated, decodeCounts(buf[0..6]));
    // Absurd entry count is rejected before any body read.
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, 999_999, .little);
    try std.testing.expectError(error.TooManyEntries, decodeCounts(&hdr));
    // Encode guards the output buffer + entry cap.
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.ShortBuffer, encodeCounts(&small, &[_]Entry{.{ .hash = 1, .count = 1 }}));
}

test "hashIp is stable and IP-distinct under a shared key" {
    const key = @as([16]u8, @splat(0x5a));
    const a = hashIp(key, &[_]u8{ 192, 0, 2, 1 });
    const b = hashIp(key, &[_]u8{ 192, 0, 2, 1 });
    const c = hashIp(key, &[_]u8{ 192, 0, 2, 2 });
    try std.testing.expectEqual(a, b); // same IP, same key -> same hash
    try std.testing.expect(a != c); // different IP -> (almost surely) different hash
    // A different key yields a different hash for the same IP (salting works).
    const key2 = @as([16]u8, @splat(0x17));
    try std.testing.expect(hashIp(key2, &[_]u8{ 192, 0, 2, 1 }) != a);
}

test "local add/remove counts and removal at zero" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    try std.testing.expectEqual(@as(u32, 1), try mc.addLocal(7));
    try std.testing.expectEqual(@as(u32, 2), try mc.addLocal(7));
    try std.testing.expectEqual(@as(u32, 2), mc.localCount(7));
    try std.testing.expectEqual(@as(u32, 1), mc.removeLocal(7));
    try std.testing.expectEqual(@as(u32, 0), mc.removeLocal(7));
    try std.testing.expectEqual(@as(u32, 0), mc.localCount(7));
    try std.testing.expectEqual(@as(u32, 0), mc.removeLocal(7)); // untracked no-op
}

test "networkCount aggregates local plus all peer contributions" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    _ = try mc.addLocal(99); // local = 1
    try mc.setRemote(1001, 99, 2); // node 1001 -> 2
    try mc.setRemote(1002, 99, 3); // node 1002 -> 3
    try std.testing.expectEqual(@as(u32, 6), mc.networkCount(99));

    // A peer revising its count down updates the total by the delta.
    try mc.setRemote(1001, 99, 0); // node 1001 leaves this hash
    try std.testing.expectEqual(@as(u32, 4), mc.networkCount(99));
    // An unrelated hash is independent.
    try std.testing.expectEqual(@as(u32, 0), mc.networkCount(12345));
}

test "dropNode removes exactly that node's contributions" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();

    _ = try mc.addLocal(5);
    try mc.setRemote(1, 5, 4);
    try mc.setRemote(2, 5, 1);
    try mc.setRemote(1, 8, 9); // node 1 also contributes to a different hash
    try std.testing.expectEqual(@as(u32, 6), mc.networkCount(5));
    try std.testing.expectEqual(@as(u32, 9), mc.networkCount(8));

    mc.dropNode(1); // node 1 vanishes
    try std.testing.expectEqual(@as(u32, 2), mc.networkCount(5)); // local 1 + node2 1
    try std.testing.expectEqual(@as(u32, 0), mc.networkCount(8)); // only node 1 was here
}

test "remote updates remain atomic on OOM" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var mc = MeshClones.init(allocator);
            defer mc.deinit();
            mc.setRemote(1, 9, 4) catch |err| {
                try std.testing.expectEqual(@as(usize, 0), mc.remote.count());
                try std.testing.expectEqual(@as(usize, 0), mc.remote_total.count());
                return err;
            };
            try std.testing.expectEqual(@as(u32, 4), mc.networkCount(9));
            try std.testing.expectEqual(@as(u32, 4), mc.remote.get(.{ .node = 1, .hash = 9 }).?);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "lowering a saturated remote total restores remaining peer contributions" {
    var mc = MeshClones.init(std.testing.allocator);
    defer mc.deinit();
    try mc.setRemote(1, 9, std.math.maxInt(u32));
    try mc.setRemote(2, 9, 1);
    try std.testing.expectEqual(std.math.maxInt(u32), mc.networkCount(9));
    try mc.setRemote(1, 9, 0);
    try std.testing.expectEqual(@as(u32, 1), mc.networkCount(9));
    const wire = try mc.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try MeshClones.restoreUpgradeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u32, 1), restored.networkCount(9));
    restored.dropNode(2);
    try std.testing.expectEqual(@as(u32, 0), restored.networkCount(9));

    try mc.setRemote(1, 9, std.math.maxInt(u32));
    try mc.setRemote(3, 9, std.math.maxInt(u32));
    mc.dropNode(1);
    try std.testing.expectEqual(std.math.maxInt(u32), mc.networkCount(9));
    mc.dropNode(3);
    try std.testing.expectEqual(@as(u32, 1), mc.networkCount(9));
}

test "mesh clones checkpoint preserves each peer and derived totals" {
    var source = MeshClones.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.addLocal(9);
    _ = try source.addLocal(9);
    _ = try source.addLocal(4);
    try source.setRemote(7, 9, 3);
    try source.setRemote(2, 9, 5);
    try source.setRemote(7, 4, 1);
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    try validateUpgradeCheckpoint(wire);
    var restored = try MeshClones.restoreUpgradeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u32, 10), restored.networkCount(9));
    try std.testing.expectEqual(@as(u32, 2), restored.networkCount(4));
    try std.testing.expectEqual(@as(u32, 3), restored.remote.get(.{ .node = 7, .hash = 9 }).?);
    try std.testing.expectEqual(@as(u32, 5), restored.remote.get(.{ .node = 2, .hash = 9 }).?);
    const reencoded = try restored.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    restored.dropNode(7);
    try std.testing.expectEqual(@as(u32, 7), restored.networkCount(9));
    try std.testing.expectEqual(@as(u32, 1), restored.networkCount(4));

    var reverse = MeshClones.init(std.testing.allocator);
    defer reverse.deinit();
    try reverse.setRemote(7, 4, 1);
    try reverse.setRemote(2, 9, 5);
    try reverse.setRemote(7, 9, 3);
    _ = try reverse.addLocal(4);
    _ = try reverse.addLocal(9);
    _ = try reverse.addLocal(9);
    const reverse_wire = try reverse.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reverse_wire);
    try std.testing.expectEqualSlices(u8, wire, reverse_wire);
}

test "mesh clones checkpoint rejects malformed order, counts and stale total" {
    var source = MeshClones.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.addLocal(9);
    try source.setRemote(2, 9, 5);
    try source.setRemote(7, 9, 3);
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    for (0..wire.len) |n| {
        try std.testing.expectError(error.Truncated, MeshClones.restoreUpgradeCheckpoint(std.testing.allocator, wire[0..n]));
    }
    var damaged = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(damaged);
    damaged[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateUpgradeCheckpoint(damaged));
    damaged[4] = checkpoint_version;
    damaged[checkpoint_header_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u32, damaged[checkpoint_header_len + 8 ..][0..4], 0, .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    // Two remote rows share hash 9; making their node ids equal duplicates a key.
    const second_node_offset = checkpoint_header_len + 12 + 20 + 8;
    std.mem.writeInt(u64, damaged[second_node_offset..][0..8], 2, .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.NonCanonicalOrder, validateUpgradeCheckpoint(damaged));

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, validateUpgradeCheckpoint(trailing));

    source.remote_total.getPtr(9).?.* = 1;
    try std.testing.expectError(error.InvalidField, source.exportUpgradeCheckpoint(std.testing.allocator));
}

test "mesh clones checkpoint allocation failures never publish partial state" {
    var source = MeshClones.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.addLocal(1);
    try source.setRemote(2, 1, 3);
    try source.setRemote(3, 5, 2);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, mc: *const MeshClones) !void {
            const bytes = try mc.exportUpgradeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expectEqual(@as(u32, 4), mc.networkCount(1));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});
    const wire = try source.exportUpgradeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var target = MeshClones.init(allocator);
            defer target.deinit();
            _ = try target.addLocal(77);
            target.replaceFromUpgradeCheckpoint(bytes) catch |err| {
                try std.testing.expectEqual(@as(u32, 1), target.networkCount(77));
                return err;
            };
            try std.testing.expectEqual(@as(u32, 4), target.networkCount(1));
            try std.testing.expectEqual(@as(u32, 2), target.networkCount(5));
            try std.testing.expectEqual(@as(u32, 0), target.networkCount(77));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, RestoreSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
