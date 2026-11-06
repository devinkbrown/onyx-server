// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable, bounded state for mesh enrollment: consumed ticket ids (replay
//! guard) and revocation (ticket ids, issuer keys, a monotonic epoch floor).
//!
//! `../proto/mesh_enrollment.zig`'s `review()` is pure and only *reads* this
//! state through the duck-typed `ledger_view` parameter (`isConsumed`,
//! `isTicketRevoked`, `isIssuerRevoked`, `revokedEpochFloor`, all satisfied
//! directly by `Ledger`). `redeem()` is the production entry point: it runs
//! `review()` against this ledger and then the strict check-and-insert
//! `consume()` in one synchronous call, so two redemptions of the same ticket
//! id can never both succeed. The ledger is owned by one thread (reactor 0
//! in the daemon); it has no internal locking.
//!
//! Scope: this state is node-local and is not replicated. Mesh-wide single
//! use and ticket revocation rely on `review()` admitting a ticket only on
//! the node named by its signed `audience_pubkey`; every other node fails it
//! `WrongAudience`, so this ledger is the only one that can ever redeem,
//! replay-check, or revoke that ticket. `revokeIssuer()` and
//! `raiseRevocationEpochFloor()` likewise apply only here; operators apply
//! them on every admitting node.
//!
//! Capacity is hard-bounded. When the consumed set (or a revocation set) is
//! full, the corresponding operation fails with `error.LedgerFull` and never
//! evicts an unexpired entry — growth pressure degrades to closed, not to
//! silently dropped replay protection. `prune()` is the only path that frees
//! consumed-set capacity, and only for entries whose `expiry_ms + skew_ms`
//! is strictly before the prune clock. `prune()` also raises the monotonic
//! `pruned_through_ms` clock floor, and `redeem()` reviews at
//! `max(now_ms, pruned_through_ms)`; a ticket forgotten by `prune()` is
//! therefore always `Expired` on a later redemption, even if the wall clock
//! regresses or the node restarts from a checkpoint, so pruning never
//! reopens a redemption window.
//!
//! Publication order for callers (fail-closed): `redeem()` → persist
//! `encodeCheckpoint()` durably → `mesh_enrollment.issueMeshPass()` → send.
//! If persistence fails the pass must not be published; the ticket stays
//! consumed in memory (burned), never rolled back to redeemable.
//!
//! Checkpoints are canonical (fields emitted in a fixed order, entries
//! sorted ascending by id), BLAKE3-checksummed, and restore builds a complete
//! replacement `Ledger` before anything is swapped into a live one — making
//! corruption, capacity overflow, and allocation failure during restore
//! transactional: either `self` ends up fully replaced, or it is untouched.
const std = @import("std");

const mesh_enrollment = @import("../proto/mesh_enrollment.zig");

pub const TicketId = mesh_enrollment.TicketId;
pub const PublicKeyBytes = mesh_enrollment.PublicKeyBytes;

pub const default_max_consumed: usize = 8192;
pub const hard_max_consumed: usize = 65_536;
pub const default_max_revoked_tickets: usize = 4096;
pub const hard_max_revoked_tickets: usize = 65_536;
pub const default_max_revoked_issuers: usize = 1024;
pub const hard_max_revoked_issuers: usize = 65_536;
pub const hard_max_checkpoint_bytes: usize = 16 * 1024 * 1024;

pub const Config = struct {
    max_consumed: usize = default_max_consumed,
    max_revoked_tickets: usize = default_max_revoked_tickets,
    max_revoked_issuers: usize = default_max_revoked_issuers,
    skew_ms: u64 = mesh_enrollment.default_skew_ms,

    fn valid(self: Config) bool {
        return self.max_consumed > 0 and self.max_consumed <= hard_max_consumed and
            self.max_revoked_tickets > 0 and self.max_revoked_tickets <= hard_max_revoked_tickets and
            self.max_revoked_issuers > 0 and self.max_revoked_issuers <= hard_max_revoked_issuers;
    }

    fn eql(a: Config, b: Config) bool {
        return a.max_consumed == b.max_consumed and
            a.max_revoked_tickets == b.max_revoked_tickets and
            a.max_revoked_issuers == b.max_revoked_issuers and
            a.skew_ms == b.skew_ms;
    }
};

pub const ConsumeResult = enum { consumed, replayed };

pub const InitError = error{InvalidConfig};
pub const LedgerFullError = error{LedgerFull};
pub const ConsumeError = std.mem.Allocator.Error || LedgerFullError;
pub const RevokeError = std.mem.Allocator.Error || LedgerFullError;
pub const RedeemError = mesh_enrollment.ReviewError || ConsumeError;

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
    DuplicateId,
    NonCanonicalOrder,
};

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    config: Config,
    consumed: std.AutoHashMapUnmanaged(TicketId, u64) = .empty,
    revoked_tickets: std.AutoHashMapUnmanaged(TicketId, void) = .empty,
    revoked_issuers: std.AutoHashMapUnmanaged(PublicKeyBytes, void) = .empty,
    revoked_epoch_floor: u64 = 0,
    /// Highest clock ever passed to `prune()`. Monotonic.
    pruned_through_ms: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Ledger {
        if (!config.valid()) return error.InvalidConfig;
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Ledger) void {
        self.consumed.deinit(self.allocator);
        self.revoked_tickets.deinit(self.allocator);
        self.revoked_issuers.deinit(self.allocator);
        self.* = undefined;
    }

    // -- read-only `ledger_view` surface consumed by `mesh_enrollment.review` --

    pub fn isConsumed(self: *const Ledger, ticket_id: TicketId) bool {
        return self.consumed.contains(ticket_id);
    }

    pub fn isTicketRevoked(self: *const Ledger, ticket_id: TicketId) bool {
        return self.revoked_tickets.contains(ticket_id);
    }

    pub fn isIssuerRevoked(self: *const Ledger, issuer_pubkey: PublicKeyBytes) bool {
        return self.revoked_issuers.contains(issuer_pubkey);
    }

    pub fn revokedEpochFloor(self: *const Ledger) u64 {
        return self.revoked_epoch_floor;
    }

    // -- mutation --

    /// Review `signed_ticket` + `signed_request` against `policy` and this
    /// ledger, then consume the ticket id. On any error the ledger is
    /// unchanged (review is pure; consume is a single map insert that either
    /// fully happens or not at all), so a caller may retry after
    /// `OutOfMemory`. The returned admission's realm aliases `policy.realm`.
    pub fn redeem(
        self: *Ledger,
        policy: mesh_enrollment.Policy,
        signed_ticket: mesh_enrollment.SignedTicket,
        signed_request: mesh_enrollment.SignedJoinRequest,
        now_ms: u64,
    ) RedeemError!mesh_enrollment.ReviewedAdmission {
        const effective_now = @max(now_ms, self.pruned_through_ms);
        const admission = try mesh_enrollment.review(policy, signed_ticket, signed_request, self, effective_now);
        return switch (try self.consume(admission.ticket_id, signed_ticket.ticket.expiry_ms)) {
            .consumed => admission,
            .replayed => error.Replayed,
        };
    }

    /// Strict check-and-insert: the first caller for a given `ticket_id`
    /// gets `.consumed`; every later caller gets `.replayed`. `expiry_ms`
    /// only sets the stored prune deadline (`expiry_ms + config.skew_ms`);
    /// admission timing is decided by `review()`. Prefer `redeem()`.
    pub fn consume(self: *Ledger, ticket_id: TicketId, expiry_ms: u64) ConsumeError!ConsumeResult {
        if (self.consumed.contains(ticket_id)) return .replayed;
        if (self.consumed.count() >= self.config.max_consumed) return error.LedgerFull;
        const deadline = expiry_ms +| self.config.skew_ms;
        try self.consumed.put(self.allocator, ticket_id, deadline);
        return .consumed;
    }

    /// Remove every consumed entry whose prune deadline is strictly before
    /// `now_ms`, then raise `pruned_through_ms`. Collects victims before
    /// removing any of them, so an allocation failure here leaves every
    /// entry and the clock floor exactly as they were.
    pub fn prune(self: *Ledger, now_ms: u64) std.mem.Allocator.Error!void {
        var victims: std.ArrayListUnmanaged(TicketId) = .empty;
        defer victims.deinit(self.allocator);

        var it = self.consumed.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* < now_ms) try victims.append(self.allocator, entry.key_ptr.*);
        }
        for (victims.items) |ticket_id| _ = self.consumed.remove(ticket_id);
        if (now_ms > self.pruned_through_ms) self.pruned_through_ms = now_ms;
    }

    pub fn revokeTicket(self: *Ledger, ticket_id: TicketId) RevokeError!void {
        if (self.revoked_tickets.contains(ticket_id)) return;
        if (self.revoked_tickets.count() >= self.config.max_revoked_tickets) return error.LedgerFull;
        try self.revoked_tickets.put(self.allocator, ticket_id, {});
    }

    pub fn revokeIssuer(self: *Ledger, issuer_pubkey: PublicKeyBytes) RevokeError!void {
        if (self.revoked_issuers.contains(issuer_pubkey)) return;
        if (self.revoked_issuers.count() >= self.config.max_revoked_issuers) return error.LedgerFull;
        try self.revoked_issuers.put(self.allocator, issuer_pubkey, {});
    }

    /// Raise the revocation-epoch floor. Monotonic: a lower epoch is ignored
    /// so a stale/racing operator command can never relax revocation.
    pub fn raiseRevocationEpochFloor(self: *Ledger, epoch: u64) void {
        if (epoch > self.revoked_epoch_floor) self.revoked_epoch_floor = epoch;
    }

    // -- checkpoint --

    pub fn encodeCheckpoint(self: *const Ledger, allocator: std.mem.Allocator) CheckpointError![]u8 {
        const consumed_ids = try orderedKeys(TicketId, u64, allocator, &self.consumed);
        defer allocator.free(consumed_ids);
        const revoked_ticket_ids = try orderedKeys(TicketId, void, allocator, &self.revoked_tickets);
        defer allocator.free(revoked_ticket_ids);
        const revoked_issuer_ids = try orderedKeys(PublicKeyBytes, void, allocator, &self.revoked_issuers);
        defer allocator.free(revoked_issuer_ids);

        const body_len = std.math.add(
            usize,
            std.math.mul(usize, consumed_ids.len, consumed_entry_len) catch return error.CheckpointTooLarge,
            std.math.add(
                usize,
                std.math.mul(usize, revoked_ticket_ids.len, id_entry_len) catch return error.CheckpointTooLarge,
                std.math.mul(usize, revoked_issuer_ids.len, id_entry_len) catch return error.CheckpointTooLarge,
            ) catch return error.CheckpointTooLarge,
        ) catch return error.CheckpointTooLarge;
        const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);

        @memcpy(out[0..magic.len], &magic);
        out[magic.len] = checkpoint_version;
        var pos: usize = magic.len + 1;
        writeU32(out, &pos, @intCast(self.config.max_consumed));
        writeU32(out, &pos, @intCast(self.config.max_revoked_tickets));
        writeU32(out, &pos, @intCast(self.config.max_revoked_issuers));
        writeU64(out, &pos, self.config.skew_ms);
        writeU64(out, &pos, self.revoked_epoch_floor);
        writeU64(out, &pos, self.pruned_through_ms);
        writeU32(out, &pos, @intCast(consumed_ids.len));
        writeU32(out, &pos, @intCast(revoked_ticket_ids.len));
        writeU32(out, &pos, @intCast(revoked_issuer_ids.len));
        writeU32(out, &pos, @intCast(body_len));
        std.debug.assert(pos == checkpoint_header_len);

        for (consumed_ids) |ticket_id| {
            copyBytes(out, &pos, &ticket_id);
            writeU64(out, &pos, self.consumed.get(ticket_id).?);
        }
        for (revoked_ticket_ids) |ticket_id| copyBytes(out, &pos, &ticket_id);
        for (revoked_issuer_ids) |pubkey| copyBytes(out, &pos, &pubkey);
        std.debug.assert(pos == prefix_len);

        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Ledger {
        if (!expected_config.valid()) return error.InvalidConfig;
        if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
        if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
        if (bytes[magic.len] != checkpoint_version) return error.UnsupportedVersion;

        var pos: usize = magic.len + 1;
        const encoded_config = Config{
            .max_consumed = readU32(bytes, &pos),
            .max_revoked_tickets = readU32(bytes, &pos),
            .max_revoked_issuers = readU32(bytes, &pos),
            .skew_ms = readU64(bytes, &pos),
        };
        const revoked_epoch_floor = readU64(bytes, &pos);
        const pruned_through_ms = readU64(bytes, &pos);
        const consumed_count: usize = readU32(bytes, &pos);
        const revoked_ticket_count: usize = readU32(bytes, &pos);
        const revoked_issuer_count: usize = readU32(bytes, &pos);
        const body_len: usize = readU32(bytes, &pos);
        std.debug.assert(pos == checkpoint_header_len);

        if (!encoded_config.valid()) return error.InvalidConfig;
        if (!Config.eql(encoded_config, expected_config)) return error.ConfigMismatch;
        if (consumed_count > expected_config.max_consumed) return error.CapacityExceeded;
        if (revoked_ticket_count > expected_config.max_revoked_tickets) return error.CapacityExceeded;
        if (revoked_issuer_count > expected_config.max_revoked_issuers) return error.CapacityExceeded;
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

        const declared_body = std.math.add(
            usize,
            std.math.mul(usize, consumed_count, consumed_entry_len) catch return error.CheckpointTooLarge,
            std.math.add(
                usize,
                std.math.mul(usize, revoked_ticket_count, id_entry_len) catch return error.CheckpointTooLarge,
                std.math.mul(usize, revoked_issuer_count, id_entry_len) catch return error.CheckpointTooLarge,
            ) catch return error.CheckpointTooLarge,
        ) catch return error.CheckpointTooLarge;
        if (declared_body != body_len) return error.Truncated;

        var restored = try Ledger.init(allocator, expected_config);
        errdefer restored.deinit();
        restored.revoked_epoch_floor = revoked_epoch_floor;
        restored.pruned_through_ms = pruned_through_ms;

        try restored.consumed.ensureTotalCapacity(allocator, @intCast(consumed_count));
        var previous_ticket_id: ?TicketId = null;
        for (0..consumed_count) |_| {
            const ticket_id: TicketId = bytes[pos..][0..@sizeOf(TicketId)].*;
            pos += @sizeOf(TicketId);
            const deadline = readU64(bytes, &pos);
            try requireCanonicalOrder(TicketId, &previous_ticket_id, ticket_id);
            restored.consumed.putAssumeCapacityNoClobber(ticket_id, deadline);
        }

        try restored.revoked_tickets.ensureTotalCapacity(allocator, @intCast(revoked_ticket_count));
        var previous_revoked_ticket: ?TicketId = null;
        for (0..revoked_ticket_count) |_| {
            const ticket_id: TicketId = bytes[pos..][0..@sizeOf(TicketId)].*;
            pos += @sizeOf(TicketId);
            try requireCanonicalOrder(TicketId, &previous_revoked_ticket, ticket_id);
            restored.revoked_tickets.putAssumeCapacityNoClobber(ticket_id, {});
        }

        try restored.revoked_issuers.ensureTotalCapacity(allocator, @intCast(revoked_issuer_count));
        var previous_issuer: ?PublicKeyBytes = null;
        for (0..revoked_issuer_count) |_| {
            const pubkey: PublicKeyBytes = bytes[pos..][0..@sizeOf(PublicKeyBytes)].*;
            pos += @sizeOf(PublicKeyBytes);
            try requireCanonicalOrder(PublicKeyBytes, &previous_issuer, pubkey);
            restored.revoked_issuers.putAssumeCapacityNoClobber(pubkey, {});
        }

        std.debug.assert(pos == prefix_len);
        return restored;
    }

    /// Replace a live ledger from a checkpoint. On any error, `self` is
    /// completely unchanged.
    pub fn replaceFromCheckpoint(self: *Ledger, bytes: []const u8) CheckpointError!void {
        var replacement = try decodeCheckpoint(self.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }
};

const magic = [_]u8{ 'M', 'E', 'N', 'R' };
const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 4 + 4 + 4 + 8 + 8 + 8 + 4 + 4 + 4 + 4;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const consumed_entry_len: usize = @sizeOf(TicketId) + 8;
const id_entry_len: usize = @sizeOf(TicketId); // also equals @sizeOf(PublicKeyBytes)
const checkpoint_checksum_domain = "onyx-mesh-enrollment-ledger-checkpoint-v1";

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checkpoint_checksum_domain);
    h.update(prefix);
    h.final(out);
}

fn requireCanonicalOrder(comptime T: type, previous: *?T, current: T) CheckpointError!void {
    if (previous.*) |prior| {
        if (std.mem.eql(u8, &prior, &current)) return error.DuplicateId;
        if (!std.mem.lessThan(u8, &prior, &current)) return error.NonCanonicalOrder;
    }
    previous.* = current;
}

fn orderedKeys(
    comptime K: type,
    comptime V: type,
    allocator: std.mem.Allocator,
    map: *const std.AutoHashMapUnmanaged(K, V),
) std.mem.Allocator.Error![]K {
    const keys = try allocator.alloc(K, map.count());
    errdefer allocator.free(keys);
    var it = map.keyIterator();
    var index: usize = 0;
    while (it.next()) |key| : (index += 1) keys[index] = key.*;
    std.mem.sort(K, keys, {}, struct {
        fn less(_: void, a: K, b: K) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.less);
    return keys;
}

fn copyBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}

fn writeU64(out: []u8, pos: *usize, value: u64) void {
    std.mem.writeInt(u64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}

fn readU32(bytes: []const u8, pos: *usize) u32 {
    const v = std.mem.readInt(u32, bytes[pos.*..][0..4], .big);
    pos.* += 4;
    return v;
}

fn readU64(bytes: []const u8, pos: *usize) u64 {
    const v = std.mem.readInt(u64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
    return v;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const meshpass = @import("../proto/meshpass.zig");
const Ed25519 = std.crypto.sign.Ed25519;

fn testId(byte: u8) TicketId {
    return @splat(byte);
}

fn testKey(byte: u8) PublicKeyBytes {
    return @splat(byte);
}

/// One issuer, one joining node, one ticket and its proof-of-possession
/// request, all valid at `now_ms = 1_500` against `policy`.
const Fixture = struct {
    issuer: Ed25519.KeyPair,
    node: Ed25519.KeyPair,
    admitter: Ed25519.KeyPair,
    issuers: [1]mesh_enrollment.Issuer,
    network_id: mesh_enrollment.NetworkId,
    ticket: mesh_enrollment.EnrollmentTicket,

    const realm = "mesh-realm";
    const now_ms: u64 = 1_500;

    fn init() !Fixture {
        const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x31)));
        const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x32)));
        const admitter = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x34)));
        const network_id = mesh_enrollment.networkId(realm, issuer.public_key.toBytes());
        return .{
            .issuer = issuer,
            .node = node,
            .admitter = admitter,
            .issuers = .{.{
                .pubkey = issuer.public_key.toBytes(),
                .authorized_roles = meshpass.roles(&.{ .relay, .witness }),
            }},
            .network_id = network_id,
            .ticket = .{
                .network_id = network_id,
                .realm = realm,
                .ticket_id = @splat(0x41),
                .issuer_pubkey = issuer.public_key.toBytes(),
                .audience_pubkey = admitter.public_key.toBytes(),
                .allowed_roles = meshpass.roles(&.{.relay}),
                .allowed_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
                .max_fanout = 8,
                .issued_ms = 1_000,
                .expiry_ms = 11_000,
                .revocation_epoch = 2,
            },
        };
    }

    /// The audience node's policy. Opts into unbound tickets so the replay
    /// and revocation paths are exercised in the most permissive mode.
    fn policy(self: *const Fixture) mesh_enrollment.Policy {
        return .{
            .network_id = self.network_id,
            .realm = realm,
            .issuers = &self.issuers,
            .admitter_pubkey = self.admitter.public_key.toBytes(),
            .require_bound_node = false,
            .max_ticket_ttl_ms = 60_000,
            .skew_ms = 1_000,
            .min_revocation_epoch = 1,
            .current_revocation_epoch = 2,
            .pass_ttl_ms = 10_000,
        };
    }

    fn signedTicket(self: *const Fixture) !mesh_enrollment.SignedTicket {
        return mesh_enrollment.signTicket(self.issuer, self.ticket);
    }

    fn signedRequest(self: *const Fixture, request_ms: u64) !mesh_enrollment.SignedJoinRequest {
        return mesh_enrollment.signJoinRequest(self.node, .{
            .ticket_id = self.ticket.ticket_id,
            .network_id = self.network_id,
            .node_pubkey = self.node.public_key.toBytes(),
            .requested_roles = meshpass.roles(&.{.relay}),
            .requested_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
            .request_ms = request_ms,
        });
    }
};

test "mesh enrollment ledger: consume is a strict check-and-insert; replay fails" {
    var ledger = try Ledger.init(testing.allocator, .{ .skew_ms = 1_000 });
    defer ledger.deinit();
    const id = testId(1);

    try testing.expectEqual(ConsumeResult.consumed, try ledger.consume(id, 10_000));
    try testing.expect(ledger.isConsumed(id));
    try testing.expectEqual(ConsumeResult.replayed, try ledger.consume(id, 10_000));
    try testing.expectEqual(ConsumeResult.replayed, try ledger.consume(id, 99_999));
    try testing.expectEqual(@as(u64, 11_000), ledger.consumed.get(id).?);
}

test "mesh enrollment: second redemption of same ticket_id fails Replayed (ledger consume is atomic)" {
    const fx = try Fixture.init();
    var ledger = try Ledger.init(testing.allocator, .{});
    defer ledger.deinit();
    const signed_ticket = try fx.signedTicket();
    const signed_request = try fx.signedRequest(Fixture.now_ms);

    const admission = try ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms);
    try testing.expectEqual(fx.ticket.ticket_id, admission.ticket_id);
    try testing.expect(ledger.isConsumed(fx.ticket.ticket_id));
    try testing.expectError(
        error.Replayed,
        ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms),
    );
    // A fresh proof (new request_ms, still in skew) is the same ticket: still replayed.
    try testing.expectError(
        error.Replayed,
        ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms + 1), Fixture.now_ms + 1),
    );
    try testing.expectEqual(@as(u32, 1), ledger.consumed.count());

    // The redeemed admission mints a MeshPass that binds for relay + control/sync/mooring.
    const issuing_key = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x33)));
    const pass = try mesh_enrollment.issueMeshPass(issuing_key, admission);
    var buf: [meshpass.max_token_len]u8 = undefined;
    const decoded = try meshpass.decode(buf[0..try meshpass.encode(&buf, pass)]);
    const fields = try meshpass.bindDecodedToken(
        decoded,
        meshpass.TrustRoot{ .public_key = issuing_key.public_key.toBytes(), .realm = Fixture.realm, .min_revocation_epoch = 1 },
        Fixture.now_ms,
        fx.node.public_key.toBytes(),
        meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
    );
    try testing.expect(meshpass.hasRole(fields, .relay));
}

test "mesh enrollment: two node-local ledgers cannot both redeem one ticket, and revocation on the audience node is mesh-complete" {
    const fx = try Fixture.init();
    const node_y = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x35)));
    const other_admitter = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x36)));
    const signed_ticket = try fx.signedTicket();
    const req_x = try fx.signedRequest(Fixture.now_ms);
    const req_y = try mesh_enrollment.signJoinRequest(node_y, .{
        .ticket_id = fx.ticket.ticket_id,
        .network_id = fx.network_id,
        .node_pubkey = node_y.public_key.toBytes(),
        .requested_roles = meshpass.roles(&.{.relay}),
        .requested_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
        .request_ms = Fixture.now_ms,
    });
    const policy_a = fx.policy();
    var policy_b = policy_a;
    policy_b.admitter_pubkey = other_admitter.public_key.toBytes();

    var ledger_a = try Ledger.init(testing.allocator, .{});
    defer ledger_a.deinit();
    var ledger_b = try Ledger.init(testing.allocator, .{});
    defer ledger_b.deinit();

    // Under the default binding policy an unbound ticket is refused everywhere.
    var default_a = policy_a;
    default_a.require_bound_node = true;
    var default_b = policy_b;
    default_b.require_bound_node = true;
    try testing.expectError(error.UnboundTicket, ledger_a.redeem(default_a, signed_ticket, req_x, Fixture.now_ms));
    try testing.expectError(error.WrongAudience, ledger_b.redeem(default_b, signed_ticket, req_y, Fixture.now_ms));

    // Explicitly opted-in unbound enrollment: A admits X once; B never admits Y.
    _ = try ledger_a.redeem(policy_a, signed_ticket, req_x, Fixture.now_ms);
    try testing.expectError(error.WrongAudience, ledger_b.redeem(policy_b, signed_ticket, req_y, Fixture.now_ms));
    try testing.expectError(error.Replayed, ledger_a.redeem(policy_a, signed_ticket, req_y, Fixture.now_ms));
    try testing.expectEqual(@as(u32, 0), ledger_b.consumed.count());

    // Revoking a leaked ticket on its audience node leaves no node that admits it.
    var fresh_a = try Ledger.init(testing.allocator, .{});
    defer fresh_a.deinit();
    try fresh_a.revokeTicket(fx.ticket.ticket_id);
    try testing.expectError(error.Revoked, fresh_a.redeem(policy_a, signed_ticket, req_y, Fixture.now_ms));
    try testing.expectError(error.WrongAudience, ledger_b.redeem(policy_b, signed_ticket, req_y, Fixture.now_ms));
    try testing.expectEqual(@as(u32, 0), fresh_a.consumed.count());
}

test "mesh enrollment: a future-epoch ticket fails EpochFromFuture without consuming it" {
    var fx = try Fixture.init();
    fx.ticket.revocation_epoch = std.math.maxInt(u64);
    var ledger = try Ledger.init(testing.allocator, .{});
    defer ledger.deinit();
    try testing.expectError(
        error.EpochFromFuture,
        ledger.redeem(fx.policy(), try fx.signedTicket(), try fx.signedRequest(Fixture.now_ms), Fixture.now_ms),
    );
    try testing.expect(!ledger.isConsumed(fx.ticket.ticket_id));
}

test "mesh enrollment: replay after ledger prune still fails (Expired)" {
    const fx = try Fixture.init();
    var ledger = try Ledger.init(testing.allocator, .{ .skew_ms = 500 });
    defer ledger.deinit();
    const signed_ticket = try fx.signedTicket();
    const id = fx.ticket.ticket_id;

    _ = try ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms), Fixture.now_ms);

    const deadline = fx.ticket.expiry_ms + 500;
    try ledger.prune(deadline); // exactly at deadline: still retained
    try testing.expect(ledger.isConsumed(id));
    try ledger.prune(deadline + 1);
    try testing.expect(!ledger.isConsumed(id));
    try testing.expectEqual(deadline + 1, ledger.pruned_through_ms);

    // Same clock: expired.
    try testing.expectError(
        error.Expired,
        ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(deadline + 1), deadline + 1),
    );
    // Wall clock regressed into the ticket's validity window: the ledger's
    // monotonic prune floor still makes it Expired, never redeemable.
    try testing.expectError(
        error.Expired,
        ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms), Fixture.now_ms),
    );

    // The floor survives a checkpoint restore (restart after prune).
    const checkpoint = try ledger.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try Ledger.decodeCheckpoint(testing.allocator, ledger.config, checkpoint);
    defer restored.deinit();
    try testing.expectError(
        error.Expired,
        restored.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms), Fixture.now_ms),
    );
    try testing.expectEqual(@as(u32, 0), restored.consumed.count());
}

test "mesh enrollment: revoked ticket_id, revoked issuer key, and stale revocation_epoch each fail Revoked via the ledger" {
    const fx = try Fixture.init();
    const signed_ticket = try fx.signedTicket();
    const signed_request = try fx.signedRequest(Fixture.now_ms);

    {
        var ledger = try Ledger.init(testing.allocator, .{});
        defer ledger.deinit();
        try ledger.revokeTicket(fx.ticket.ticket_id);
        try testing.expectError(error.Revoked, ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms));
        try testing.expect(!ledger.isConsumed(fx.ticket.ticket_id));
    }
    {
        var ledger = try Ledger.init(testing.allocator, .{});
        defer ledger.deinit();
        try ledger.revokeIssuer(fx.issuer.public_key.toBytes());
        try testing.expectError(error.Revoked, ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms));
        try testing.expect(!ledger.isConsumed(fx.ticket.ticket_id));
    }
    {
        var ledger = try Ledger.init(testing.allocator, .{});
        defer ledger.deinit();
        ledger.raiseRevocationEpochFloor(fx.ticket.revocation_epoch + 1);
        try testing.expectError(error.Revoked, ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms));
        try testing.expect(!ledger.isConsumed(fx.ticket.ticket_id));
    }
}

test "mesh enrollment: rejected redemptions never consume the ticket id" {
    const fx = try Fixture.init();
    var ledger = try Ledger.init(testing.allocator, .{});
    defer ledger.deinit();
    const signed_ticket = try fx.signedTicket();

    // Wrong network policy, then a stale proof: neither burns the ticket.
    var wrong_policy = fx.policy();
    wrong_policy.network_id = mesh_enrollment.networkId("other-realm", fx.issuer.public_key.toBytes());
    try testing.expectError(
        error.WrongNetwork,
        ledger.redeem(wrong_policy, signed_ticket, try fx.signedRequest(Fixture.now_ms), Fixture.now_ms),
    );
    try testing.expectError(
        error.RequestStale,
        ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms + 5_000), Fixture.now_ms),
    );
    try testing.expectEqual(@as(u32, 0), ledger.consumed.count());

    // The legitimate redemption still succeeds afterwards.
    _ = try ledger.redeem(fx.policy(), signed_ticket, try fx.signedRequest(Fixture.now_ms), Fixture.now_ms);
}

test "mesh enrollment ledger: revocation sets and epoch floor are idempotent and monotonic" {
    var ledger = try Ledger.init(testing.allocator, .{});
    defer ledger.deinit();
    const ticket_id = testId(3);
    const issuer = testKey(4);

    try testing.expect(!ledger.isTicketRevoked(ticket_id));
    try ledger.revokeTicket(ticket_id);
    try testing.expect(ledger.isTicketRevoked(ticket_id));
    try ledger.revokeTicket(ticket_id); // idempotent, no error

    try testing.expect(!ledger.isIssuerRevoked(issuer));
    try ledger.revokeIssuer(issuer);
    try testing.expect(ledger.isIssuerRevoked(issuer));

    try testing.expectEqual(@as(u64, 0), ledger.revokedEpochFloor());
    ledger.raiseRevocationEpochFloor(7);
    try testing.expectEqual(@as(u64, 7), ledger.revokedEpochFloor());
    ledger.raiseRevocationEpochFloor(3); // monotonic: lower epoch ignored
    try testing.expectEqual(@as(u64, 7), ledger.revokedEpochFloor());
}

test "mesh enrollment ledger: capacity full returns LedgerFull without evicting unexpired entries" {
    var ledger = try Ledger.init(testing.allocator, .{ .max_consumed = 2, .max_revoked_tickets = 1, .max_revoked_issuers = 1, .skew_ms = 0 });
    defer ledger.deinit();

    try testing.expectEqual(ConsumeResult.consumed, try ledger.consume(testId(1), 10_000));
    try testing.expectEqual(ConsumeResult.consumed, try ledger.consume(testId(2), 10_000));
    try testing.expectError(error.LedgerFull, ledger.consume(testId(3), 10_000));
    try testing.expect(ledger.isConsumed(testId(1)));
    try testing.expect(ledger.isConsumed(testId(2)));
    try testing.expect(!ledger.isConsumed(testId(3)));
    // A replay of a stored id is still reported as replayed, not LedgerFull.
    try testing.expectEqual(ConsumeResult.replayed, try ledger.consume(testId(1), 10_000));

    try ledger.revokeTicket(testId(10));
    try testing.expectError(error.LedgerFull, ledger.revokeTicket(testId(11)));
    try testing.expect(ledger.isTicketRevoked(testId(10)));
    try testing.expect(!ledger.isTicketRevoked(testId(11)));

    try ledger.revokeIssuer(testKey(20));
    try testing.expectError(error.LedgerFull, ledger.revokeIssuer(testKey(21)));
    try testing.expect(ledger.isIssuerRevoked(testKey(20)));
    try testing.expect(!ledger.isIssuerRevoked(testKey(21)));

    // Pruning past the deadline frees capacity.
    try ledger.prune(10_001);
    try testing.expectEqual(ConsumeResult.consumed, try ledger.consume(testId(3), 20_000));
}

test "mesh enrollment ledger: init and decode reject invalid capacity config" {
    try testing.expectError(error.InvalidConfig, Ledger.init(testing.allocator, .{ .max_consumed = 0 }));
    try testing.expectError(error.InvalidConfig, Ledger.init(testing.allocator, .{ .max_consumed = hard_max_consumed + 1 }));
    try testing.expectError(error.InvalidConfig, Ledger.init(testing.allocator, .{ .max_revoked_tickets = 0 }));
    try testing.expectError(error.InvalidConfig, Ledger.init(testing.allocator, .{ .max_revoked_issuers = 0 }));
}

test "mesh enrollment ledger: checkpoint round-trip preserves consumed and revoked sets" {
    const cfg = Config{ .max_consumed = 8, .max_revoked_tickets = 8, .max_revoked_issuers = 8, .skew_ms = 250 };
    var ledger = try Ledger.init(testing.allocator, cfg);
    defer ledger.deinit();

    _ = try ledger.consume(testId(1), 10_000);
    _ = try ledger.consume(testId(2), 20_000);
    try ledger.revokeTicket(testId(3));
    try ledger.revokeIssuer(testKey(9));
    ledger.raiseRevocationEpochFloor(5);
    try ledger.prune(100);

    const checkpoint = try ledger.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);

    var restored = try Ledger.decodeCheckpoint(testing.allocator, cfg, checkpoint);
    defer restored.deinit();

    try testing.expect(restored.isConsumed(testId(1)));
    try testing.expect(restored.isConsumed(testId(2)));
    try testing.expect(!restored.isConsumed(testId(3)));
    try testing.expect(restored.isTicketRevoked(testId(3)));
    try testing.expect(restored.isIssuerRevoked(testKey(9)));
    try testing.expectEqual(@as(u64, 5), restored.revokedEpochFloor());
    try testing.expectEqual(@as(u64, 100), restored.pruned_through_ms);

    const restored_checkpoint = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(restored_checkpoint);
    try testing.expectEqualSlices(u8, checkpoint, restored_checkpoint);

    // Replay-after-restore is still rejected.
    try testing.expectEqual(ConsumeResult.replayed, try restored.consume(testId(1), 10_000));
}

test "mesh enrollment ledger: a corrupt, truncated, or non-canonical checkpoint fails closed" {
    const cfg = Config{};
    var ledger = try Ledger.init(testing.allocator, cfg);
    defer ledger.deinit();
    _ = try ledger.consume(testId(1), 10_000);
    _ = try ledger.consume(testId(4), 10_000);
    try ledger.revokeTicket(testId(2));

    const checkpoint = try ledger.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);

    try testing.expectError(error.Truncated, Ledger.decodeCheckpoint(testing.allocator, cfg, checkpoint[0 .. checkpoint.len - 1]));
    try testing.expectError(error.Truncated, Ledger.decodeCheckpoint(testing.allocator, cfg, checkpoint[0..3]));

    const trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, Ledger.decodeCheckpoint(testing.allocator, cfg, trailing));

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[checkpoint_header_len] ^= 1;
    try testing.expectError(error.ChecksumMismatch, Ledger.decodeCheckpoint(testing.allocator, cfg, corrupt));

    const bad_magic = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try testing.expectError(error.BadMagic, Ledger.decodeCheckpoint(testing.allocator, cfg, bad_magic));

    const bad_version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_version);
    bad_version[magic.len] +%= 1;
    try testing.expectError(error.UnsupportedVersion, Ledger.decodeCheckpoint(testing.allocator, cfg, bad_version));

    try testing.expectError(
        error.ConfigMismatch,
        Ledger.decodeCheckpoint(testing.allocator, .{ .max_consumed = cfg.max_consumed + 1 }, checkpoint),
    );

    // Swap the two consumed entries and re-checksum: canonical order is enforced
    // independently of the checksum.
    const swapped = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(swapped);
    const first = checkpoint_header_len;
    const second = first + consumed_entry_len;
    @memcpy(swapped[first..][0..consumed_entry_len], checkpoint[second..][0..consumed_entry_len]);
    @memcpy(swapped[second..][0..consumed_entry_len], checkpoint[first..][0..consumed_entry_len]);
    const prefix_len = checkpoint.len - checksum_len;
    checkpointChecksum(swapped[0..prefix_len], swapped[prefix_len..][0..checksum_len]);
    try testing.expectError(error.NonCanonicalOrder, Ledger.decodeCheckpoint(testing.allocator, cfg, swapped));

    // Duplicate entry (second copied over the first) is rejected too.
    const duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    @memcpy(duplicate[second..][0..consumed_entry_len], checkpoint[first..][0..consumed_entry_len]);
    checkpointChecksum(duplicate[0..prefix_len], duplicate[prefix_len..][0..checksum_len]);
    try testing.expectError(error.DuplicateId, Ledger.decodeCheckpoint(testing.allocator, cfg, duplicate));

    // A live ledger replaced from a bad checkpoint is untouched.
    try testing.expectError(error.ChecksumMismatch, ledger.replaceFromCheckpoint(corrupt));
    try testing.expect(ledger.isConsumed(testId(1)));
    try testing.expect(ledger.isConsumed(testId(4)));
    try testing.expect(ledger.isTicketRevoked(testId(2)));
}

test "mesh enrollment ledger: allocation-failure sweeps leave the ledger consistent and retryable" {
    const RedeemSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const fx = try Fixture.init();
            var ledger = try Ledger.init(allocator, .{});
            defer ledger.deinit();
            const signed_ticket = try fx.signedTicket();
            const signed_request = try fx.signedRequest(Fixture.now_ms);
            _ = ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms) catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                // Nothing consumed, so the identical redemption is not burned.
                try testing.expectEqual(@as(u32, 0), ledger.consumed.count());
                try testing.expect(!ledger.isConsumed(fx.ticket.ticket_id));
                return err;
            };
            try testing.expect(ledger.isConsumed(fx.ticket.ticket_id));
            try testing.expectError(
                error.Replayed,
                ledger.redeem(fx.policy(), signed_ticket, signed_request, Fixture.now_ms),
            );
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RedeemSweep.run, .{});

    const PruneSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var ledger = try Ledger.init(allocator, .{ .skew_ms = 0 });
            defer ledger.deinit();
            _ = try ledger.consume(testId(1), 10);
            _ = try ledger.consume(testId(2), 1_000);
            ledger.prune(500) catch |err| {
                try testing.expect(ledger.isConsumed(testId(1)));
                try testing.expect(ledger.isConsumed(testId(2)));
                try testing.expectEqual(@as(u64, 0), ledger.pruned_through_ms);
                return err;
            };
            try testing.expect(!ledger.isConsumed(testId(1)));
            try testing.expect(ledger.isConsumed(testId(2)));
            try testing.expectEqual(@as(u64, 500), ledger.pruned_through_ms);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, PruneSweep.run, .{});

    const CheckpointRoundTrip = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var ledger = try Ledger.init(allocator, .{});
            defer ledger.deinit();
            _ = try ledger.consume(testId(5), 10_000);
            try ledger.revokeTicket(testId(6));
            try ledger.revokeIssuer(testKey(7));

            const bytes = try ledger.encodeCheckpoint(allocator);
            defer allocator.free(bytes);

            var restored = try Ledger.decodeCheckpoint(allocator, ledger.config, bytes);
            defer restored.deinit();
            try testing.expect(restored.isConsumed(testId(5)));
            try testing.expect(restored.isTicketRevoked(testId(6)));
            try testing.expect(restored.isIssuerRevoked(testKey(7)));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, CheckpointRoundTrip.run, .{});

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8, config: Config) !void {
            const sentinel = testId(0x7f);
            var target = try Ledger.init(allocator, config);
            defer target.deinit();
            _ = try target.consume(sentinel, 99);
            target.replaceFromCheckpoint(bytes) catch |err| {
                try testing.expect(target.isConsumed(sentinel));
                try testing.expect(!target.isConsumed(testId(9)));
                return err;
            };
            try testing.expect(!target.isConsumed(sentinel));
            try testing.expect(target.isConsumed(testId(9)));
        }
    };
    var source = try Ledger.init(testing.allocator, .{});
    defer source.deinit();
    _ = try source.consume(testId(9), 500);
    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    try testing.checkAllAllocationFailures(testing.allocator, ReplaceSweep.run, .{ checkpoint, source.config });
}
