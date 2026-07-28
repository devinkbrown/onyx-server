// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-global replay and equivocation authority for secure relay v2.
//!
//! The per-link relay cache suppresses immediate reflections; this guard is the
//! durable correctness boundary. State is keyed by the origin's full Ed25519
//! public key, not its truncated mesh handle. Each origin retains the greatest
//! W `(hlc, relay_id)` pairs in ascending HLC order. Before a retained entry is
//! evicted, its HLC advances a permanent `retired_through_hlc` watermark, so a
//! delayed capture at or below that boundary can never become live again.
//!
//! Checkpoints are canonical, bounded, and BLAKE3-checksummed. Restore builds a
//! complete replacement before swapping it into a live guard, making corruption,
//! capacity failure, and OOM transactional.

const std = @import("std");

const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");

pub const PublicKey = [message_relay_v2.pubkey_len]u8;
pub const RelayId = message_relay_v2.RelayId;

pub const default_window_size: usize = 64;
pub const default_max_origins: usize = 4096;
pub const hard_max_window_size: usize = 4096;
pub const hard_max_origins: usize = 65_536;
pub const hard_max_checkpoint_bytes: usize = 64 * 1024 * 1024;

pub const Config = struct {
    window_size: usize = default_window_size,
    max_origins: usize = default_max_origins,

    fn valid(self: Config) bool {
        return self.window_size > 0 and self.window_size <= hard_max_window_size and
            self.max_origins > 0 and self.max_origins <= hard_max_origins;
    }

    fn eql(a: Config, b: Config) bool {
        return a.window_size == b.window_size and a.max_origins == b.max_origins;
    }
};

/// `retired` covers both a replay at/below the durable watermark and a newly
/// observed event too old to enter a full greatest-W window. In the latter case
/// the watermark advances through that HLC before the rejection is returned.
pub const Decision = enum {
    accepted,
    duplicate,
    equivocation,
    retired,
    origin_capacity,
};

/// One origin-verification and replay-admission result for a complete immutable
/// MESSAGE_V2 object. Only `accepted` exposes an identity, and that identity is
/// derived from the same authenticated transcript that advanced the guard.
/// Delivery, Lotus history, msgid rendering, and re-forwarding must use this
/// exact payload rather than calling `relayId` independently.
pub const Admission = union(enum) {
    accepted: RelayId,
    duplicate: RelayId,
    equivocation,
    retired,
    origin_capacity,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

/// Read-only authentication and replay-authority lookup. This is deliberately
/// separate from `Admission`: receivers use it to re-ack an exact retained
/// duplicate before consulting mutable routing or policy state, while an
/// unseen message must still complete all first-admission checks before the
/// guard is mutated.
pub const Probe = union(enum) {
    unseen: RelayId,
    duplicate: RelayId,
    equivocation,
    retired: RelayId,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

/// Allocation-free identity lookup against the greatest-W window / watermark.
/// Does not authenticate, admit, or mutate. `duplicate` proves the RelayId is
/// still retained in the live window. `retired` is not accept-proof (covers
/// never-admitted too-old events). Pending-exact beyond-window proof is owned
/// by higher layers (E2EEGROUP), not RVG2.
pub const IdentityLookup = enum {
    unseen,
    duplicate,
    equivocation,
    retired,
};

pub const InitError = error{InvalidConfig};

pub const CheckpointError = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    InvalidConfig,
    ConfigMismatch,
    CapacityExceeded,
    CheckpointTooLarge,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateOrigin,
    DuplicateHlc,
    NonCanonicalOrder,
    InvalidWatermark,
    InvalidField,
};

/// Unambiguous family selector only. A true result still requires the complete
/// strict `validateCheckpoint` pass before the capsule is accepted.
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

/// Allocation-free strict-current validation for checkpoint selectors and
/// whole-handoff relation checks. Returns the encoded authority configuration;
/// the eventual owner must still compare it with its operator-owned expected
/// configuration when staging through `Guard.decodeCheckpoint`.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!Config {
    if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != checkpoint_version) return error.UnsupportedVersion;
    const encoded_config = Config{
        .window_size = readU16(bytes[5..7]),
        .max_origins = readU32(bytes[7..11]),
    };
    if (!encoded_config.valid()) return error.InvalidConfig;
    const origin_count: usize = readU32(bytes[11..15]);
    const body_len: usize = readU32(bytes[15..19]);
    if (origin_count > encoded_config.max_origins) return error.CapacityExceeded;
    if (body_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual_sum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_sum);
    if (!std.mem.eql(u8, &actual_sum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos: usize = checkpoint_header_len;
    var previous_pubkey: ?PublicKey = null;
    for (0..origin_count) |_| {
        if (pos > prefix_len or prefix_len - pos < origin_prefix_len) return error.Truncated;
        const pubkey: PublicKey = bytes[pos..][0..@sizeOf(PublicKey)].*;
        pos += @sizeOf(PublicKey);
        if (previous_pubkey) |previous| {
            if (std.mem.eql(u8, &previous, &pubkey)) return error.DuplicateOrigin;
            if (!std.mem.lessThan(u8, &previous, &pubkey)) return error.NonCanonicalOrder;
        }
        previous_pubkey = pubkey;
        const retired_present = bytes[pos];
        pos += 1;
        if (retired_present > 1) return error.InvalidField;
        const retired_raw = readU64(bytes[pos..][0..8]);
        pos += 8;
        if (retired_present == 0 and retired_raw != 0) return error.InvalidWatermark;
        const retired: ?u64 = if (retired_present == 1) retired_raw else null;
        const entry_count: usize = readU16(bytes[pos..][0..2]);
        pos += 2;
        if (entry_count == 0 or entry_count > encoded_config.window_size)
            return error.CapacityExceeded;
        const entries_bytes = std.math.mul(usize, entry_count, checkpoint_entry_len) catch
            return error.CheckpointTooLarge;
        if (pos > prefix_len or entries_bytes > prefix_len - pos) return error.Truncated;
        var previous_hlc: ?u64 = null;
        for (0..entry_count) |_| {
            const hlc = readU64(bytes[pos..][0..8]);
            pos += 8 + @sizeOf(RelayId);
            if (retired) |watermark| if (hlc <= watermark) return error.InvalidWatermark;
            if (previous_hlc) |previous| {
                if (hlc == previous) return error.DuplicateHlc;
                if (hlc < previous) return error.NonCanonicalOrder;
            }
            previous_hlc = hlc;
        }
    }
    if (pos < prefix_len) return error.TrailingBytes;
    if (pos > prefix_len) return error.Truncated;
    return encoded_config;
}

const Entry = struct {
    hlc: u64,
    relay_id: RelayId,
};

const OriginState = struct {
    retired_through_hlc: ?u64 = null,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    fn deinit(self: *OriginState, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.* = undefined;
    }
};

pub const Guard = struct {
    /// Intentionally lock-free: the daemon owner must serialize `admit`,
    /// checkpoint replacement, and deinit under its global/world write lane.
    allocator: std.mem.Allocator,
    config: Config,
    origins: std.AutoHashMapUnmanaged(PublicKey, OriginState) = .empty,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Guard {
        if (!config.valid()) return error.InvalidConfig;
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Guard) void {
        var values = self.origins.valueIterator();
        while (values.next()) |origin| origin.deinit(self.allocator);
        self.origins.deinit(self.allocator);
        self.* = undefined;
    }

    /// Admit one already-verified origin event. The only error is allocation
    /// failure; every rejection is a decision and leaves retained facts intact.
    /// All fallible reservations complete before the first state mutation.
    pub fn admit(self: *Guard, pubkey: PublicKey, hlc: u64, relay_id: RelayId) std.mem.Allocator.Error!Decision {
        if (self.origins.getPtr(pubkey)) |origin| {
            return self.admitKnown(origin, hlc, relay_id);
        }
        if (self.origins.count() >= self.config.max_origins) return .origin_capacity;

        var staged = OriginState{};
        errdefer staged.deinit(self.allocator);
        try staged.entries.ensureTotalCapacity(self.allocator, 1);
        staged.entries.appendAssumeCapacity(.{ .hlc = hlc, .relay_id = relay_id });
        try self.origins.ensureUnusedCapacity(self.allocator, 1);
        self.origins.putAssumeCapacityNoClobber(pubkey, staged);
        return .accepted;
    }

    /// Allocation-free greatest-W / watermark lookup. Never mutates.
    pub fn probeIdentity(
        self: *const Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) IdentityLookup {
        const origin = self.origins.get(pubkey) orelse return .unseen;
        if (origin.retired_through_hlc) |watermark| {
            if (hlc <= watermark) return .retired;
        }
        const index = lowerBound(origin.entries.items, hlc);
        if (index < origin.entries.items.len and origin.entries.items[index].hlc == hlc) {
            return if (std.mem.eql(u8, &origin.entries.items[index].relay_id, &relay_id))
                .duplicate
            else
                .equivocation;
        }
        return .unseen;
    }

    /// Ordered origin public keys (canonical RVG2 checkpoint order).
    pub fn orderedOriginPubkeys(
        self: *const Guard,
        allocator: std.mem.Allocator,
    ) CheckpointError![]PublicKey {
        const count = self.origins.count();
        var keys = try allocator.alloc(PublicKey, count);
        errdefer allocator.free(keys);
        var it = self.origins.keyIterator();
        var index: usize = 0;
        while (it.next()) |key| : (index += 1) keys[index] = key.*;
        std.mem.sort(PublicKey, keys, {}, struct {
            fn less(_: void, a: PublicKey, b: PublicKey) bool {
                return std.mem.lessThan(u8, &a, &b);
            }
        }.less);
        return keys;
    }

    /// Verify the immutable author and derive its relay identity exactly once,
    /// then enter that identity into durable replay authority. Invalid origin
    /// objects cannot mutate the guard or poison a later valid message.
    pub fn admitMessage(
        self: *Guard,
        msg: message_relay_v2.RelayMessage,
    ) std.mem.Allocator.Error!Admission {
        const relay_id = switch (try message_relay_v2.verifyAndRelayId(self.allocator, msg)) {
            .verified => |id| id,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        const pubkey: PublicKey = msg.origin_pubkey[0..@sizeOf(PublicKey)].*;
        return switch (try self.admit(pubkey, msg.hlc, relay_id)) {
            .accepted => .{ .accepted = relay_id },
            .duplicate => .{ .duplicate = relay_id },
            .equivocation => .equivocation,
            .retired => .retired,
            .origin_capacity => .origin_capacity,
        };
    }

    /// Verify the complete immutable message and query retained replay facts
    /// without changing them. A duplicate result is proof that this exact
    /// RelayId was accepted previously; `retired` is intentionally not such a
    /// proof because the watermark also covers never-admitted too-old events.
    pub fn probeMessage(
        self: *const Guard,
        msg: message_relay_v2.RelayMessage,
    ) std.mem.Allocator.Error!Probe {
        const relay_id = switch (try message_relay_v2.verifyAndRelayId(self.allocator, msg)) {
            .verified => |id| id,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        const pubkey: PublicKey = msg.origin_pubkey[0..@sizeOf(PublicKey)].*;
        return switch (self.probeIdentity(pubkey, msg.hlc, relay_id)) {
            .unseen => .{ .unseen = relay_id },
            .duplicate => .{ .duplicate = relay_id },
            .equivocation => .equivocation,
            .retired => .{ .retired = relay_id },
        };
    }

    /// Canonical deterministic checkpoint. The caller owns the returned bytes.
    pub fn encodeCheckpoint(self: *const Guard, allocator: std.mem.Allocator) CheckpointError![]u8 {
        const origin_count = self.origins.count();
        if (origin_count > self.config.max_origins) return error.CapacityExceeded;

        const OrderedOrigin = struct {
            pubkey: PublicKey,
            state: *const OriginState,
        };
        var ordered = try allocator.alloc(OrderedOrigin, origin_count);
        defer allocator.free(ordered);
        var it = self.origins.iterator();
        var index: usize = 0;
        var body_len: usize = 0;
        while (it.next()) |entry| : (index += 1) {
            if (entry.value_ptr.entries.items.len == 0 or
                entry.value_ptr.entries.items.len > self.config.window_size) return error.InvalidField;
            const entry_bytes = std.math.mul(usize, entry.value_ptr.entries.items.len, checkpoint_entry_len) catch
                return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, origin_prefix_len + entry_bytes) catch
                return error.CheckpointTooLarge;
            if (body_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
            ordered[index] = .{ .pubkey = entry.key_ptr.*, .state = entry.value_ptr };
        }
        std.mem.sort(OrderedOrigin, ordered, {}, struct {
            fn less(_: void, a: OrderedOrigin, b: OrderedOrigin) bool {
                return std.mem.lessThan(u8, &a.pubkey, &b.pubkey);
            }
        }.less);

        const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);

        @memcpy(out[0..magic.len], &magic);
        out[magic.len] = checkpoint_version;
        writeU16(out[5..7], @intCast(self.config.window_size));
        writeU32(out[7..11], @intCast(self.config.max_origins));
        writeU32(out[11..15], @intCast(origin_count));
        writeU32(out[15..19], @intCast(body_len));

        var pos: usize = checkpoint_header_len;
        for (ordered) |origin| {
            @memcpy(out[pos..][0..@sizeOf(PublicKey)], &origin.pubkey);
            pos += @sizeOf(PublicKey);
            out[pos] = @intFromBool(origin.state.retired_through_hlc != null);
            pos += 1;
            writeU64(out[pos..][0..8], origin.state.retired_through_hlc orelse 0);
            pos += 8;
            writeU16(out[pos..][0..2], @intCast(origin.state.entries.items.len));
            pos += 2;
            for (origin.state.entries.items) |retained| {
                writeU64(out[pos..][0..8], retained.hlc);
                pos += 8;
                @memcpy(out[pos..][0..@sizeOf(RelayId)], &retained.relay_id);
                pos += @sizeOf(RelayId);
            }
        }
        std.debug.assert(pos == prefix_len);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    /// Decode a checkpoint using an operator-owned expected configuration. The
    /// encoded limits must match exactly; a checkpoint cannot silently widen its
    /// own memory authority.
    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Guard {
        if (!expected_config.valid()) return error.InvalidConfig;
        if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
        if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
        if (bytes[magic.len] != checkpoint_version) return error.UnsupportedVersion;

        const encoded_config = Config{
            .window_size = readU16(bytes[5..7]),
            .max_origins = readU32(bytes[7..11]),
        };
        if (!encoded_config.valid()) return error.InvalidConfig;
        if (!Config.eql(encoded_config, expected_config)) return error.ConfigMismatch;
        const origin_count: usize = readU32(bytes[11..15]);
        const body_len: usize = readU32(bytes[15..19]);
        if (origin_count > expected_config.max_origins) return error.CapacityExceeded;
        if (body_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;

        const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
            return error.CheckpointTooLarge;
        const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (expected_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
        if (bytes.len < expected_len) return error.Truncated;
        if (bytes.len > expected_len) return error.TrailingBytes;
        var actual_sum: [checksum_len]u8 = undefined;
        checkpointChecksum(bytes[0..prefix_len], &actual_sum);
        if (!std.mem.eql(u8, &actual_sum, bytes[prefix_len..])) return error.ChecksumMismatch;

        var restored = try Guard.init(allocator, expected_config);
        errdefer restored.deinit();
        try restored.origins.ensureTotalCapacity(allocator, @intCast(origin_count));

        var pos: usize = checkpoint_header_len;
        var previous_pubkey: ?PublicKey = null;
        for (0..origin_count) |_| {
            if (prefix_len - pos < origin_prefix_len) return error.Truncated;
            const pubkey: PublicKey = bytes[pos..][0..@sizeOf(PublicKey)].*;
            pos += @sizeOf(PublicKey);
            if (previous_pubkey) |previous| {
                if (std.mem.eql(u8, &previous, &pubkey)) return error.DuplicateOrigin;
                if (!std.mem.lessThan(u8, &previous, &pubkey)) return error.NonCanonicalOrder;
            }
            previous_pubkey = pubkey;

            const retired_present = bytes[pos];
            pos += 1;
            if (retired_present > 1) return error.InvalidField;
            const retired_raw = readU64(bytes[pos..][0..8]);
            pos += 8;
            if (retired_present == 0 and retired_raw != 0) return error.InvalidWatermark;
            const retired: ?u64 = if (retired_present == 1) retired_raw else null;
            const entry_count: usize = readU16(bytes[pos..][0..2]);
            pos += 2;
            if (entry_count == 0 or entry_count > expected_config.window_size)
                return error.CapacityExceeded;
            const entries_bytes = std.math.mul(usize, entry_count, checkpoint_entry_len) catch
                return error.CheckpointTooLarge;
            if (entries_bytes > prefix_len - pos) return error.Truncated;

            var origin = OriginState{ .retired_through_hlc = retired };
            errdefer origin.deinit(allocator);
            try origin.entries.ensureTotalCapacity(allocator, entry_count);
            var previous_hlc: ?u64 = null;
            for (0..entry_count) |_| {
                const hlc = readU64(bytes[pos..][0..8]);
                pos += 8;
                const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
                pos += @sizeOf(RelayId);
                if (retired) |watermark| {
                    if (hlc <= watermark) return error.InvalidWatermark;
                }
                if (previous_hlc) |previous| {
                    if (hlc == previous) return error.DuplicateHlc;
                    if (hlc < previous) return error.NonCanonicalOrder;
                }
                previous_hlc = hlc;
                origin.entries.appendAssumeCapacity(.{ .hlc = hlc, .relay_id = relay_id });
            }
            restored.origins.putAssumeCapacityNoClobber(pubkey, origin);
        }
        if (pos < prefix_len) return error.TrailingBytes;
        if (pos > prefix_len) return error.Truncated;
        return restored;
    }

    /// Atomically replace a live guard from a checkpoint. The encoded config is
    /// required to equal this guard's config. Any error leaves `self` unchanged.
    pub fn replaceFromCheckpoint(self: *Guard, bytes: []const u8) CheckpointError!void {
        var replacement = try decodeCheckpoint(self.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }

    fn admitKnown(self: *Guard, origin: *OriginState, hlc: u64, relay_id: RelayId) std.mem.Allocator.Error!Decision {
        if (origin.retired_through_hlc) |watermark| {
            if (hlc <= watermark) return .retired;
        }

        const index = lowerBound(origin.entries.items, hlc);
        if (index < origin.entries.items.len and origin.entries.items[index].hlc == hlc) {
            return if (std.mem.eql(u8, &origin.entries.items[index].relay_id, &relay_id))
                .duplicate
            else
                .equivocation;
        }

        if (origin.entries.items.len < self.config.window_size) {
            try origin.entries.ensureUnusedCapacity(self.allocator, 1);
            insertAssumeCapacity(&origin.entries, index, .{ .hlc = hlc, .relay_id = relay_id });
            return .accepted;
        }

        if (index == 0) {
            advanceWatermark(origin, hlc);
            return .retired;
        }

        // No fallible operation follows. Advance the durable rejection boundary
        // before removing the oldest retained event.
        advanceWatermark(origin, origin.entries.items[0].hlc);
        const items = origin.entries.items;
        std.mem.copyForwards(Entry, items[0 .. items.len - 1], items[1..]);
        const insert_at = index - 1;
        var cursor = items.len - 1;
        while (cursor > insert_at) : (cursor -= 1) items[cursor] = items[cursor - 1];
        items[insert_at] = .{ .hlc = hlc, .relay_id = relay_id };
        return .accepted;
    }
};

const magic = [_]u8{ 'R', 'V', 'G', '2' };
const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 19;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const origin_prefix_len: usize = @sizeOf(PublicKey) + 1 + 8 + 2;
const checkpoint_entry_len: usize = 8 + @sizeOf(RelayId);
const checkpoint_checksum_domain = "onyx-relay-v2-replay-checkpoint-v1";

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checkpoint_checksum_domain);
    h.update(prefix);
    h.final(out);
}

fn advanceWatermark(origin: *OriginState, hlc: u64) void {
    if (origin.retired_through_hlc == null or hlc > origin.retired_through_hlc.?)
        origin.retired_through_hlc = hlc;
}

fn lowerBound(entries: []const Entry, hlc: u64) usize {
    var lo: usize = 0;
    var hi = entries.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (entries[mid].hlc < hlc)
            lo = mid + 1
        else
            hi = mid;
    }
    return lo;
}

fn insertAssumeCapacity(entries: *std.ArrayListUnmanaged(Entry), index: usize, entry: Entry) void {
    const old_len = entries.items.len;
    entries.appendAssumeCapacity(undefined);
    var cursor = old_len;
    while (cursor > index) : (cursor -= 1) entries.items[cursor] = entries.items[cursor - 1];
    entries.items[index] = entry;
}

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .big);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

fn writeU16(bytes: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, bytes, value, .big);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

fn testKey(byte: u8) PublicKey {
    return @splat(byte);
}

fn testId(byte: u8) RelayId {
    return @splat(byte);
}

fn testSignedMessage(
    kp: *const sign.KeyPair,
    hlc: u64,
    text: []const u8,
    pubkey: *[message_relay_v2.pubkey_len]u8,
    signature: *[message_relay_v2.sig_len]u8,
) !message_relay_v2.RelayMessage {
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = "#mesh",
        .source_prefix = "alice!u@mesh.test",
        .account = "alice",
        .text = text,
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(testing.allocator, &msg, kp, pubkey, signature);
    return msg;
}

fn expectAdmission(expected: std.meta.Tag(Admission), admission: Admission) !void {
    try testing.expectEqual(expected, std.meta.activeTag(admission));
}

fn rewriteCheckpointChecksum(bytes: []u8) void {
    const prefix_len = bytes.len - checksum_len;
    checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checksum_len]);
}

fn expectOrigin(
    guard: *const Guard,
    pubkey: PublicKey,
    retired: ?u64,
    expected_hlcs: []const u64,
) !void {
    const origin = guard.origins.get(pubkey) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(retired, origin.retired_through_hlc);
    try testing.expectEqual(expected_hlcs.len, origin.entries.items.len);
    for (origin.entries.items, expected_hlcs) |entry, hlc| try testing.expectEqual(hlc, entry.hlc);
}

test "relay v2 replay admission verifies once and returns the authoritative accepted identity" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x91)));
    defer kp.deinit();
    var pk_a: [message_relay_v2.pubkey_len]u8 = undefined;
    var sig_a: [message_relay_v2.sig_len]u8 = undefined;
    const first = try testSignedMessage(&kp, 10, "first", &pk_a, &sig_a);
    const expected_id = switch (try message_relay_v2.verifyAndRelayId(testing.allocator, first)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };

    var guard = try Guard.init(testing.allocator, .{ .window_size = 1, .max_origins = 1 });
    defer guard.deinit();
    switch (try guard.probeMessage(first)) {
        .unseen => |id| try testing.expectEqualSlices(u8, &expected_id, &id),
        else => return error.TestUnexpectedResult,
    }
    switch (try guard.admitMessage(first)) {
        .accepted => |id| try testing.expectEqualSlices(u8, &expected_id, &id),
        else => return error.TestUnexpectedResult,
    }
    const before_probe = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before_probe);
    switch (try guard.probeMessage(first)) {
        .duplicate => |id| try testing.expectEqualSlices(u8, &expected_id, &id),
        else => return error.TestUnexpectedResult,
    }
    const after_probe = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_probe);
    try testing.expectEqualSlices(u8, before_probe, after_probe);
    try expectAdmission(.duplicate, try guard.admitMessage(first));

    var pk_conflict: [message_relay_v2.pubkey_len]u8 = undefined;
    var sig_conflict: [message_relay_v2.sig_len]u8 = undefined;
    const conflict = try testSignedMessage(&kp, 10, "different", &pk_conflict, &sig_conflict);
    try testing.expectEqual(
        std.meta.Tag(Probe).equivocation,
        std.meta.activeTag(try guard.probeMessage(conflict)),
    );
    try expectAdmission(.equivocation, try guard.admitMessage(conflict));

    var pk_new: [message_relay_v2.pubkey_len]u8 = undefined;
    var sig_new: [message_relay_v2.sig_len]u8 = undefined;
    const newer = try testSignedMessage(&kp, 11, "newer", &pk_new, &sig_new);
    try expectAdmission(.accepted, try guard.admitMessage(newer));
    try testing.expectEqual(
        std.meta.Tag(Probe).retired,
        std.meta.activeTag(try guard.probeMessage(first)),
    );
    try expectAdmission(.retired, try guard.admitMessage(first));

    // Invalid semantic and invalid proof paths never disturb the valid origin.
    var invalid = newer;
    invalid.target = "not-a-channel";
    try expectAdmission(.invalid_semantic, try guard.admitMessage(invalid));
    var bad_sig = newer;
    var corrupt_signature = sig_new;
    corrupt_signature[0] ^= 1;
    bad_sig.origin_sig = &corrupt_signature;
    try expectAdmission(.bad_signature, try guard.admitMessage(bad_sig));
    try expectAdmission(.duplicate, try guard.admitMessage(newer));

    var other_kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x92)));
    defer other_kp.deinit();
    var other_pk: [message_relay_v2.pubkey_len]u8 = undefined;
    var other_sig: [message_relay_v2.sig_len]u8 = undefined;
    const other = try testSignedMessage(&other_kp, 1, "other", &other_pk, &other_sig);
    try expectAdmission(.origin_capacity, try guard.admitMessage(other));
}

test "relay v2 replay message admission is failure-atomic across every allocation failure" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x93)));
    defer kp.deinit();
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    const msg = try testSignedMessage(&kp, 50, "allocation sweep", &pubkey, &signature);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, message: message_relay_v2.RelayMessage) !void {
            var guard = try Guard.init(allocator, .{ .window_size = 2, .max_origins = 2 });
            defer guard.deinit();
            const result = guard.admitMessage(message) catch |err| {
                try testing.expectEqual(@as(usize, 0), guard.origins.count());
                return err;
            };
            switch (result) {
                .accepted => {},
                else => return error.TestUnexpectedResult,
            }
            try testing.expectEqual(@as(usize, 1), guard.origins.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{msg});
}

test "relay v2 replay guard isolates full origin keys and detects duplicates and equivocation" {
    try testing.expectError(error.InvalidConfig, Guard.init(testing.allocator, .{ .window_size = 0 }));
    try testing.expectError(error.InvalidConfig, Guard.init(testing.allocator, .{ .max_origins = 0 }));
    try testing.expectError(
        error.InvalidConfig,
        Guard.init(testing.allocator, .{ .window_size = hard_max_window_size + 1 }),
    );

    var guard = try Guard.init(testing.allocator, .{ .window_size = 3, .max_origins = 2 });
    defer guard.deinit();
    const alice = testKey(0x11);
    const bob = testKey(0x12);
    const third = testKey(0x13);

    try testing.expectEqual(Decision.accepted, try guard.admit(alice, 20, testId(2)));
    try testing.expectEqual(Decision.accepted, try guard.admit(alice, 10, testId(1)));
    try testing.expectEqual(Decision.duplicate, try guard.admit(alice, 20, testId(2)));
    try testing.expectEqual(Decision.equivocation, try guard.admit(alice, 20, testId(9)));
    try expectOrigin(&guard, alice, null, &.{ 10, 20 });
    try testing.expectEqualSlices(u8, &testId(2), &guard.origins.get(alice).?.entries.items[1].relay_id);

    // Allocation-free probeIdentity is window/watermark-only (no exact history).
    try testing.expectEqual(IdentityLookup.duplicate, guard.probeIdentity(alice, 20, testId(2)));
    try testing.expectEqual(IdentityLookup.equivocation, guard.probeIdentity(alice, 20, testId(9)));
    try testing.expectEqual(IdentityLookup.unseen, guard.probeIdentity(alice, 15, testId(5)));
    try testing.expectEqual(IdentityLookup.unseen, guard.probeIdentity(third, 1, testId(1)));

    // The same HLC and RelayId under a different full key is an independent
    // origin, even if a future truncated node handle were to collide.
    try testing.expectEqual(Decision.accepted, try guard.admit(bob, 20, testId(2)));
    try testing.expectEqual(Decision.origin_capacity, try guard.admit(third, 1, testId(1)));
    try testing.expectEqual(@as(usize, 2), guard.origins.count());
}

test "relay v2 replay guard probeIdentity is non-mutating across unseen duplicate equivocation retired" {
    var guard = try Guard.init(testing.allocator, .{ .window_size = 1, .max_origins = 1 });
    defer guard.deinit();
    const key = testKey(0x31);
    try testing.expectEqual(IdentityLookup.unseen, guard.probeIdentity(key, 10, testId(1)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(1)));
    try testing.expectEqual(IdentityLookup.duplicate, guard.probeIdentity(key, 10, testId(1)));
    try testing.expectEqual(IdentityLookup.equivocation, guard.probeIdentity(key, 10, testId(2)));

    const before = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    _ = guard.probeIdentity(key, 10, testId(1));
    _ = guard.probeIdentity(key, 5, testId(5));
    const after = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 20, testId(2)));
    // Evicted HLC is watermark-retired only — not accept-proof without higher layers.
    try testing.expectEqual(IdentityLookup.retired, guard.probeIdentity(key, 10, testId(1)));
    try testing.expectEqual(IdentityLookup.duplicate, guard.probeIdentity(key, 20, testId(2)));
}

test "relay v2 replay guard keeps greatest W and permanently retires every eviction" {
    var guard = try Guard.init(testing.allocator, .{ .window_size = 3, .max_origins = 1 });
    defer guard.deinit();
    const key = testKey(0x21);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 30, testId(3)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(1)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 20, testId(2)));
    try expectOrigin(&guard, key, null, &.{ 10, 20, 30 });

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 40, testId(4)));
    try expectOrigin(&guard, key, 10, &.{ 20, 30, 40 });
    try testing.expectEqual(Decision.retired, try guard.admit(key, 5, testId(5)));
    try expectOrigin(&guard, key, 10, &.{ 20, 30, 40 });

    // A sparse event between the floor and retained minimum is itself outside
    // greatest-W. Retire it before rejecting so it can never return after restart.
    try testing.expectEqual(Decision.retired, try guard.admit(key, 15, testId(6)));
    try expectOrigin(&guard, key, 15, &.{ 20, 30, 40 });
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 25, testId(7)));
    try expectOrigin(&guard, key, 20, &.{ 25, 30, 40 });
    try testing.expectEqual(Decision.retired, try guard.admit(key, 20, testId(2)));
    try testing.expectEqual(Decision.equivocation, try guard.admit(key, 30, testId(0xee)));
    try expectOrigin(&guard, key, 20, &.{ 25, 30, 40 });

    try testing.expectEqual(Decision.accepted, try guard.admit(key, std.math.maxInt(u64), testId(8)));
    try expectOrigin(&guard, key, 25, &.{ 30, 40, std.math.maxInt(u64) });
}

test "relay v2 replay guard checkpoint is deterministic and preserves authority" {
    const cfg = Config{ .window_size = 3, .max_origins = 3 };
    const alice = testKey(0x31);
    const bob = testKey(0x32);
    var first = try Guard.init(testing.allocator, cfg);
    defer first.deinit();
    var second = try Guard.init(testing.allocator, cfg);
    defer second.deinit();

    for ([_]u64{ 10, 20, 30, 40 }) |hlc|
        try testing.expectEqual(Decision.accepted, try first.admit(alice, hlc, testId(@intCast(hlc))));
    try testing.expectEqual(Decision.accepted, try first.admit(bob, 5, testId(5)));

    try testing.expectEqual(Decision.accepted, try second.admit(bob, 5, testId(5)));
    for ([_]u64{ 40, 30, 20 }) |hlc|
        try testing.expectEqual(Decision.accepted, try second.admit(alice, hlc, testId(@intCast(hlc))));
    try testing.expectEqual(Decision.retired, try second.admit(alice, 10, testId(10)));

    const first_wire = try first.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(first_wire);
    try testing.expect(isCheckpoint(first_wire));
    try testing.expect(Config.eql(cfg, try validateCheckpoint(first_wire)));
    const second_wire = try second.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(second_wire);
    try testing.expectEqualSlices(u8, first_wire, second_wire);

    var restored = try Guard.decodeCheckpoint(testing.allocator, cfg, first_wire);
    defer restored.deinit();
    const restored_wire = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(restored_wire);
    try testing.expectEqualSlices(u8, first_wire, restored_wire);
    try expectOrigin(&restored, alice, 10, &.{ 20, 30, 40 });
    try testing.expectEqual(Decision.retired, try restored.admit(alice, 10, testId(10)));
    try testing.expectEqual(Decision.duplicate, try restored.admit(alice, 20, testId(20)));
    try testing.expectEqual(Decision.equivocation, try restored.admit(alice, 20, testId(0xff)));
}

test "relay v2 replay guard checkpoint represents empty state and retired HLC zero exactly" {
    const empty_cfg = Config{ .window_size = 2, .max_origins = 2 };
    var empty = try Guard.init(testing.allocator, empty_cfg);
    defer empty.deinit();
    const empty_wire = try empty.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(empty_wire);
    try testing.expectEqual(checkpoint_header_len + checksum_len, empty_wire.len);
    var empty_restored = try Guard.decodeCheckpoint(testing.allocator, empty_cfg, empty_wire);
    defer empty_restored.deinit();
    try testing.expectEqual(@as(usize, 0), empty_restored.origins.count());

    const zero_cfg = Config{ .window_size = 1, .max_origins = 1 };
    const key = testKey(0x39);
    var zero = try Guard.init(testing.allocator, zero_cfg);
    defer zero.deinit();
    try testing.expectEqual(Decision.accepted, try zero.admit(key, 0, testId(0)));
    try testing.expectEqual(Decision.accepted, try zero.admit(key, 1, testId(1)));
    try expectOrigin(&zero, key, 0, &.{1});
    const zero_wire = try zero.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(zero_wire);
    var zero_restored = try Guard.decodeCheckpoint(testing.allocator, zero_cfg, zero_wire);
    defer zero_restored.deinit();
    try expectOrigin(&zero_restored, key, 0, &.{1});
    try testing.expectEqual(Decision.retired, try zero_restored.admit(key, 0, testId(0)));
}

test "relay v2 replay guard checkpoint rejects corruption bounds duplicates and noncanonical state" {
    const cfg = Config{ .window_size = 2, .max_origins = 2 };
    const alice = testKey(0x41);
    const bob = testKey(0x42);
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    _ = try source.admit(alice, 10, testId(1));
    _ = try source.admit(alice, 20, testId(2));
    _ = try source.admit(alice, 30, testId(3));
    _ = try source.admit(bob, 5, testId(4));
    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);

    try testing.expectError(
        error.Truncated,
        Guard.decodeCheckpoint(testing.allocator, cfg, checkpoint[0 .. checkpoint.len - 1]),
    );
    try testing.expectError(error.Truncated, validateCheckpoint(checkpoint[0 .. checkpoint.len - 1]));
    const trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, Guard.decodeCheckpoint(testing.allocator, cfg, trailing));
    try testing.expectError(error.TrailingBytes, validateCheckpoint(trailing));

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[checkpoint_header_len + origin_prefix_len] ^= 1;
    try testing.expectError(error.ChecksumMismatch, Guard.decodeCheckpoint(testing.allocator, cfg, corrupt));
    try testing.expectError(error.ChecksumMismatch, validateCheckpoint(corrupt));
    try testing.expectError(
        error.ConfigMismatch,
        Guard.decodeCheckpoint(testing.allocator, .{ .window_size = 3, .max_origins = 2 }, checkpoint),
    );
    const invalid_config = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(invalid_config);
    writeU16(invalid_config[5..7], 0);
    rewriteCheckpointChecksum(invalid_config);
    try testing.expectError(error.InvalidConfig, validateCheckpoint(invalid_config));
    try testing.expectError(
        error.InvalidConfig,
        Guard.decodeCheckpoint(testing.allocator, cfg, invalid_config),
    );

    const bad_magic = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try testing.expect(!isCheckpoint(bad_magic));
    try testing.expectError(error.BadMagic, Guard.decodeCheckpoint(testing.allocator, cfg, bad_magic));
    try testing.expectError(error.BadMagic, validateCheckpoint(bad_magic));
    const bad_version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_version);
    bad_version[magic.len] +%= 1;
    try testing.expectError(error.UnsupportedVersion, Guard.decodeCheckpoint(testing.allocator, cfg, bad_version));
    try testing.expect(isCheckpoint(bad_version));
    try testing.expectError(error.UnsupportedVersion, validateCheckpoint(bad_version));

    // First origin is W-full: prefix + two entries. Point the second origin at
    // the same full public key and authenticate the malformed state.
    const second_origin = checkpoint_header_len + origin_prefix_len + 2 * checkpoint_entry_len;
    const duplicate_origin = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate_origin);
    @memcpy(
        duplicate_origin[second_origin .. second_origin + @sizeOf(PublicKey)],
        duplicate_origin[checkpoint_header_len .. checkpoint_header_len + @sizeOf(PublicKey)],
    );
    rewriteCheckpointChecksum(duplicate_origin);
    try testing.expectError(
        error.DuplicateOrigin,
        Guard.decodeCheckpoint(testing.allocator, cfg, duplicate_origin),
    );
    try testing.expectError(error.DuplicateOrigin, validateCheckpoint(duplicate_origin));

    const unsorted_origins = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unsorted_origins);
    @memset(unsorted_origins[checkpoint_header_len .. checkpoint_header_len + @sizeOf(PublicKey)], 0xfe);
    rewriteCheckpointChecksum(unsorted_origins);
    try testing.expectError(
        error.NonCanonicalOrder,
        Guard.decodeCheckpoint(testing.allocator, cfg, unsorted_origins),
    );

    const first_entry = checkpoint_header_len + origin_prefix_len;
    const second_entry = first_entry + checkpoint_entry_len;
    const duplicate_hlc = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate_hlc);
    @memcpy(duplicate_hlc[second_entry .. second_entry + 8], duplicate_hlc[first_entry .. first_entry + 8]);
    rewriteCheckpointChecksum(duplicate_hlc);
    try testing.expectError(error.DuplicateHlc, Guard.decodeCheckpoint(testing.allocator, cfg, duplicate_hlc));
    try testing.expectError(error.DuplicateHlc, validateCheckpoint(duplicate_hlc));

    const unsorted_hlc = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unsorted_hlc);
    writeU64(unsorted_hlc[second_entry .. second_entry + 8], 19);
    rewriteCheckpointChecksum(unsorted_hlc);
    try testing.expectError(error.NonCanonicalOrder, Guard.decodeCheckpoint(testing.allocator, cfg, unsorted_hlc));

    const invalid_watermark = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(invalid_watermark);
    const watermark_offset = checkpoint_header_len + @sizeOf(PublicKey) + 1;
    writeU64(
        invalid_watermark[watermark_offset .. watermark_offset + 8],
        readU64(invalid_watermark[first_entry .. first_entry + 8]),
    );
    rewriteCheckpointChecksum(invalid_watermark);
    try testing.expectError(
        error.InvalidWatermark,
        Guard.decodeCheckpoint(testing.allocator, cfg, invalid_watermark),
    );

    const invalid_flag = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(invalid_flag);
    invalid_flag[checkpoint_header_len + @sizeOf(PublicKey)] = 2;
    rewriteCheckpointChecksum(invalid_flag);
    try testing.expectError(error.InvalidField, Guard.decodeCheckpoint(testing.allocator, cfg, invalid_flag));

    const missing_flag = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(missing_flag);
    missing_flag[checkpoint_header_len + @sizeOf(PublicKey)] = 0;
    rewriteCheckpointChecksum(missing_flag);
    try testing.expectError(error.InvalidWatermark, Guard.decodeCheckpoint(testing.allocator, cfg, missing_flag));

    const over_window = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(over_window);
    const entry_count_offset = checkpoint_header_len + @sizeOf(PublicKey) + 1 + 8;
    writeU16(over_window[entry_count_offset .. entry_count_offset + 2], 3);
    rewriteCheckpointChecksum(over_window);
    try testing.expectError(error.CapacityExceeded, Guard.decodeCheckpoint(testing.allocator, cfg, over_window));

    // Authenticate one extra body byte and increase the declared body length.
    // All declared origins decode, then strict EOF rejects the hidden extension.
    const authenticated_trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(authenticated_trailing);
    const old_prefix_len = checkpoint.len - checksum_len;
    @memcpy(authenticated_trailing[0..old_prefix_len], checkpoint[0..old_prefix_len]);
    authenticated_trailing[old_prefix_len] = 0xa5;
    writeU32(
        authenticated_trailing[15..19],
        readU32(checkpoint[15..19]) + 1,
    );
    rewriteCheckpointChecksum(authenticated_trailing);
    try testing.expectError(
        error.TrailingBytes,
        Guard.decodeCheckpoint(testing.allocator, cfg, authenticated_trailing),
    );
    try testing.expectError(error.TrailingBytes, validateCheckpoint(authenticated_trailing));
}

test "relay v2 replay guard admission is unchanged on allocation failure and retry succeeds" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var guard = try Guard.init(failing.allocator(), .{ .window_size = 64, .max_origins = 4 });
    defer guard.deinit();
    const key = testKey(0x51);
    var next_hlc: u64 = 1;
    try testing.expectEqual(Decision.accepted, try guard.admit(key, next_hlc, testId(1)));
    next_hlc += 1;
    const state = guard.origins.getPtr(key).?;
    while (state.entries.items.len < state.entries.capacity) : (next_hlc += 1) {
        try testing.expectEqual(Decision.accepted, try guard.admit(key, next_hlc, testId(@intCast(next_hlc))));
    }
    const before = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, guard.admit(key, next_hlc, testId(0xee)));
    failing.fail_index = std.math.maxInt(usize);
    const after = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    try testing.expectEqual(Decision.accepted, try guard.admit(key, next_hlc, testId(0xee)));
}

test "relay v2 replay guard checkpoint allocation sweeps are leak-free and replacement is atomic" {
    const cfg = Config{ .window_size = 4, .max_origins = 4 };
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    _ = try source.admit(testKey(0x61), 1, testId(1));
    _ = try source.admit(testKey(0x61), 2, testId(2));
    _ = try source.admit(testKey(0x62), 3, testId(3));

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, guard: *const Guard) !void {
            const bytes = try guard.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try testing.expect(bytes.len > checkpoint_header_len + checksum_len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});

    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !void {
            var restored = try Guard.decodeCheckpoint(allocator, config, bytes);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 2), restored.origins.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ cfg, checkpoint });

    const AdmitSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config) !void {
            var guard = try Guard.init(allocator, config);
            defer guard.deinit();
            try testing.expectEqual(Decision.accepted, try guard.admit(testKey(0x63), 1, testId(1)));
            const before = try guard.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            _ = guard.admit(testKey(0x64), 2, testId(2)) catch |err| {
                const after = try guard.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, AdmitSweep.run, .{cfg});

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !void {
            const sentinel = testKey(0x7f);
            var target = try Guard.init(allocator, config);
            defer target.deinit();
            try testing.expectEqual(Decision.accepted, try target.admit(sentinel, 99, testId(99)));
            const before = try target.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            target.replaceFromCheckpoint(bytes) catch |err| {
                const after = try target.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
            try testing.expect(target.origins.get(sentinel) == null);
            try testing.expectEqual(@as(usize, 2), target.origins.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ReplaceSweep.run, .{ cfg, checkpoint });
}
