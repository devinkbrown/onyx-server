// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Permanent group-denial facts in the existing private account OroStore.
//! The caller validates configured origin trust and prepares the in-memory
//! fence before persist; only durable success permits acceptance/publication.
const std = @import("std");
const store_mod = @import("store.zig");
const replica = @import("helix/session_replica.zig");
const sign = @import("../crypto/sign.zig");
pub const retired_policy = @import("session_group_retired_policy.zig");

pub const namespace = "onyx/session-group-revoke/v1/";
pub const key_len = namespace.len + 64;
pub const Trust = struct {
    ctx: *const anyopaque,
    allows: *const fn (*const anyopaque, sign.PublicKey, u64) bool,
    allows_retired: ?*const fn (*const anyopaque, sign.PublicKey, u64, retired_policy.Digest, retired_policy.Digest) bool = null,
    /// Same immutable canonical list used by allows_retired; required groups
    /// are derived from it, never a second mutable authority registry.
    required_grants: []const retired_policy.Grant = &.{},
};

pub fn requiresColdReopen(err: anyerror) bool {
    return err == error.IoAmbiguous or err == error.StorePoisoned;
}

fn checked(wire: []const u8) !replica.SignedOffer {
    const signed = try replica.decodeOffer(wire);
    try replica.verifyOffer(signed);
    if (signed.offer.operation != .group_revoke) return error.InvalidGroupRevoke;
    return signed;
}

pub const fact_digest_domain = "onyx-session-group-revoke-retirement-v1\x00";

/// Hash only exact canonical signed operation-4 bytes after authentication.
pub fn factDigest(wire: []const u8) retired_policy.Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(fact_digest_domain);
    hasher.update(wire);
    var digest: retired_policy.Digest = undefined;
    hasher.final(&digest);
    return digest;
}

pub fn groupKeyFor(token: replica.Token) retired_policy.Digest {
    var hash: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(namespace);
    hasher.update(&token);
    hasher.final(&hash);
    return hash;
}

pub fn keyFor(token: replica.Token) [key_len]u8 {
    return keyForGroup(groupKeyFor(token));
}

fn keyForGroup(group: retired_policy.Digest) [key_len]u8 {
    var key: [key_len]u8 = undefined;
    @memcpy(key[0..namespace.len], namespace);
    key[namespace.len..].* = std.fmt.bytesToHex(group, .lower);
    return key;
}

/// Write-once terminal facts. A later valid signed denial of the same folded
/// account/token is equivalent; retain the first canonical fact unchanged.
/// This function never deletes a fence or rotates it based on expiry/revision.
/// IoAmbiguous/StorePoisoned MUST trigger fail-closed admission and cold reopen;
/// an error at that boundary is not proof that no durable record was written.
pub fn persist(db: *store_mod.OroStore, wire: []const u8) !void {
    if (db.preparedWritesPoisoned()) return error.StorePoisoned;
    const signed = try checked(wire);
    const key = keyFor(signed.offer.token);
    if (db.get(.props, &key)) |existing| {
        const old = try checked(existing);
        if (!std.mem.eql(u8, &old.offer.token, &signed.offer.token) or
            !std.ascii.eqlIgnoreCase(old.offer.account, signed.offer.account)) return error.AccountMismatch;
        return;
    }
    var prepared = try db.preparePut(.props, &key, wire);
    defer prepared.deinit();
    try prepared.commit();
}

fn record(key: []const u8, wire: []const u8, trust: Trust) !replica.SignedOffer {
    const signed = try checked(wire);
    const expected = keyFor(signed.offer.token);
    if (!std.mem.eql(u8, key, &expected)) return error.BadRecord;
    try authorizeVerified(signed, wire, trust);
    return signed;
}

fn authorizeVerified(signed: replica.SignedOffer, wire: []const u8, trust: Trust) !void {
    // Finish borrowed-wire reads before invoking caller-owned trust callbacks.
    const group = groupKeyFor(signed.offer.token);
    const fact = factDigest(wire);
    if (trust.allows(trust.ctx, signed.signer, signed.offer.revision.origin_node)) return;
    const allows_retired = trust.allows_retired orelse return error.UntrustedOrigin;
    if (!allows_retired(trust.ctx, signed.signer, signed.offer.revision.origin_node, group, fact)) return error.UntrustedOrigin;
}

/// Operation-4 ONLY network replay authorization. This predicate must never be
/// used for peer admission, inventory, lease, resume or ACK coverage authority.
pub fn authorizeFence(wire: []const u8, trust: Trust) !replica.SignedOffer {
    const signed = try checked(wire);
    try authorizeVerified(signed, wire, trust);
    return signed;
}

fn verifyRequiredGroups(db: *const store_mod.OroStore, trust: Trust) !void {
    try retired_policy.validateCanonical(trust.required_grants);
    var previous: ?retired_policy.Digest = null;
    for (trust.required_grants) |grant| {
        if (previous) |group| if (std.mem.eql(u8, &group, &grant.group_key)) continue;
        const key = keyForGroup(grant.group_key);
        // Every namespace row has already passed record() and, for Helix,
        // database-to-checkpoint inclusion. One verified alternative suffices.
        if (db.get(.props, &key) == null) return error.MissingRequiredFence;
        previous = grant.group_key;
    }
}

/// Cold bootstrap only. Reject populated targets instead of cloning a
/// checkpoint that intentionally omits their live, derived routing state.
/// Every record is validated into a detached Store before one no-fail swap.
pub fn restoreInto(db: *const store_mod.OroStore, target: *replica.Store, now_ms: i64, trust: Trust) !usize {
    if (db.preparedWritesPoisoned()) return error.StorePoisoned;
    if (target.entries.count() != 0 or target.attachment_leases.count() != 0 or
        target.routes.count() != 0 or target.tombstones.count() != 0 or
        target.quarantines.count() != 0 or target.group_revocations.count() != 0 or
        target.account_index.count() != 0) return error.NonPristineStore;
    try retired_policy.validateCanonical(trust.required_grants);
    const cut = db.next_seq;
    var staged = replica.Store.initWithConfig(target.allocator, target.cfg);
    defer staged.deinit();
    var iterator = db.maps[@backingInt(store_mod.Family.props)].map.iterator();
    var count: usize = 0;
    while (iterator.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, namespace)) continue;
        if (count == retired_policy.max_grants) return error.TooManyFences;
        const signed = try record(entry.key_ptr.*, entry.value_ptr.*, trust);
        if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
        var ticket = try staged.prepareGroupRevoke(signed, now_ms);
        defer ticket.deinit();
        _ = ticket.commit();
        count += 1;
    }
    try verifyRequiredGroups(db, trust);
    if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
    std.mem.swap(replica.Store, target, &staged);
    return count;
}

/// Helix verification is read-only: its already-staged strict checkpoint must
/// retain every durable denial. Never silently merge into an adopted live cut.
pub fn verifyRetained(db: *const store_mod.OroStore, target: *const replica.Store, trust: Trust) !usize {
    if (db.preparedWritesPoisoned()) return error.StorePoisoned;
    try retired_policy.validateCanonical(trust.required_grants);
    const cut = db.next_seq;
    var iterator = db.maps[@backingInt(store_mod.Family.props)].map.iterator();
    var count: usize = 0;
    while (iterator.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, namespace)) continue;
        if (count == retired_policy.max_grants) return error.TooManyFences;
        const signed = try record(entry.key_ptr.*, entry.value_ptr.*, trust);
        if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
        const retained = target.groupRevokeForToken(signed.offer.token) orelse return error.MissingDurableFence;
        const retained_signed = try authorizeFence(retained.wire, trust);
        if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
        if (!std.mem.eql(u8, &retained_signed.offer.token, &signed.offer.token) or
            !std.ascii.eqlIgnoreCase(retained_signed.offer.account, signed.offer.account) or
            !target.isGroupRevoked(signed.offer.account, signed.offer.token)) return error.MissingDurableFence;
        count += 1;
    }
    try verifyRequiredGroups(db, trust);
    if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
    return count;
}

/// Caller holds the database's exclusive ownership/mutation guard throughout.
/// Verify one complete bounded cut before preparing any publishable output.
/// The returned bytes contain only public issuer keys and opaque group/fact
/// digests. The caller must publish them create-only to an owner-private file.
pub fn prepareExport(allocator: std.mem.Allocator, db: *const store_mod.OroStore, trust: Trust, selected_active_issuer: sign.PublicKey) ![]u8 {
    if (db.preparedWritesPoisoned()) return error.StorePoisoned;
    try retired_policy.validateCanonical(trust.required_grants);
    const cut = db.next_seq;
    if (!trust.allows(trust.ctx, selected_active_issuer, @import("../substrate/undertow/signed_frame.zig").originShortId(selected_active_issuer))) return error.IssuerNotActive;
    if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
    var count: usize = 0;
    var selected: usize = 0;
    var iterator = db.maps[@backingInt(store_mod.Family.props)].map.iterator();
    while (iterator.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, namespace)) continue;
        if (count == retired_policy.max_grants) return error.TooManyFences;
        const signed = try record(entry.key_ptr.*, entry.value_ptr.*, trust);
        if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
        count += 1;
        if (std.crypto.timing_safe.eql(sign.PublicKey, signed.signer, selected_active_issuer)) selected += 1;
    }
    try verifyRequiredGroups(db, trust);
    const grants = try allocator.alloc(retired_policy.Grant, selected);
    defer allocator.free(grants);
    var written: usize = 0;
    iterator = db.maps[@backingInt(store_mod.Family.props)].map.iterator();
    while (iterator.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, namespace)) continue;
        // Already authenticated above under the same exclusive stable cut.
        const signed = try replica.decodeOffer(entry.value_ptr.*);
        if (!std.crypto.timing_safe.eql(sign.PublicKey, signed.signer, selected_active_issuer)) continue;
        if (written == grants.len) return error.StoreChanged;
        grants[written] = .{ .group_key = groupKeyFor(signed.offer.token), .issuer_key = signed.signer, .fact_digest = factDigest(entry.value_ptr.*) };
        written += 1;
    }
    if (written != grants.len or db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
    std.mem.sort(retired_policy.Grant, grants, {}, struct {
        fn lessThan(_: void, a: retired_policy.Grant, b: retired_policy.Grant) bool {
            return retired_policy.compare(a, b) == .lt;
        }
    }.lessThan);
    try retired_policy.validateCanonical(grants);
    const row_format = "[[mesh.retired_session_group_fences]]\ngroup_key = \"{s}\"\nissuer_key = \"{s}\"\nfact_digest = \"{s}\"\n\n";
    const zero_hex: [64]u8 = @splat('0');
    const row_len = std.fmt.count(row_format, .{ zero_hex, zero_hex, zero_hex });
    const out = try allocator.alloc(u8, row_len * grants.len);
    errdefer allocator.free(out);
    var offset: usize = 0;
    for (grants) |grant| {
        const group_hex = std.fmt.bytesToHex(grant.group_key, .lower);
        const issuer_hex = std.fmt.bytesToHex(grant.issuer_key, .lower);
        const fact_hex = std.fmt.bytesToHex(grant.fact_digest, .lower);
        const row = try std.fmt.bufPrint(out[offset..], row_format, .{ group_hex, issuer_hex, fact_hex });
        offset += row.len;
    }
    std.debug.assert(offset == out.len);
    if (db.next_seq != cut or db.preparedWritesPoisoned()) return error.StoreChanged;
    return out;
}

const testing = std.testing;
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

fn testWire(allocator: std.mem.Allocator, kp: *const sign.KeyPair, token: u8, account: []const u8) ![]u8 {
    return replica.encodeOffer(allocator, .{
        .operation = .group_revoke,
        .token = @splat(token),
        .revision = .{ .epoch = 1000, .sequence = 1000 << 16, .origin_node = signed_frame.originShortId(kp.public_key) },
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
        .account = account,
    }, kp);
}

fn testTrust(key: *const sign.PublicKey) Trust {
    return .{ .ctx = key, .allows = struct {
        fn allows(ctx: *const anyopaque, candidate: sign.PublicKey, origin: u64) bool {
            const expected: *const sign.PublicKey = @ptrCast(@alignCast(ctx));
            return std.mem.eql(u8, expected, &candidate) and origin == signed_frame.originShortId(candidate);
        }
    }.allows };
}

test "group revoke durable facts survive reopen and never overwrite account authority" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var kp = try sign.KeyPair.fromSeed(@splat(31));
    defer kp.deinit();
    const wire = try testWire(testing.allocator, &kp, 7, "Alice");
    defer testing.allocator.free(wire);
    const folded = try testWire(testing.allocator, &kp, 7, "ALICE");
    defer testing.allocator.free(folded);
    const foreign = try testWire(testing.allocator, &kp, 7, "Mallory");
    defer testing.allocator.free(foreign);
    {
        var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "revoke.wal");
        defer db.deinit();
        try persist(&db, wire);
        const sequence = db.next_seq;
        try persist(&db, folded);
        try testing.expectEqual(sequence, db.next_seq);
        try testing.expectError(error.AccountMismatch, persist(&db, foreign));
        const key = keyFor(@splat(7));
        try testing.expectEqualSlices(u8, wire, db.get(.props, &key).?);
    }
    var reopened = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "revoke.wal");
    defer reopened.deinit();
    var target = replica.Store.init(testing.allocator);
    defer target.deinit();
    try testing.expectError(error.MissingDurableFence, verifyRetained(&reopened, &target, testTrust(&kp.public_key)));
    try testing.expectEqual(@as(usize, 1), try restoreInto(&reopened, &target, 5000, testTrust(&kp.public_key)));
    try testing.expect(target.isGroupRevoked("alice", @splat(7)));
    try testing.expectEqual(@as(usize, 1), try verifyRetained(&reopened, &target, testTrust(&kp.public_key)));
    try testing.expectError(error.NonPristineStore, restoreInto(&reopened, &target, 5000, testTrust(&kp.public_key)));
}

test "group revoke durable restore refuses untrusted malformed and missing facts atomically" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var kp = try sign.KeyPair.fromSeed(@splat(32));
    defer kp.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(33));
    defer other.deinit();
    const wire = try testWire(testing.allocator, &kp, 8, "Alice");
    defer testing.allocator.free(wire);
    var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "invalid.wal");
    defer db.deinit();
    try persist(&db, wire);
    var target = replica.Store.init(testing.allocator);
    defer target.deinit();
    try testing.expectError(error.UntrustedOrigin, restoreInto(&db, &target, 5000, testTrust(&other.public_key)));
    try testing.expect(!target.isGroupRevoked("alice", @splat(8)));
    try db.put(.props, namespace ++ "bad-key", wire);
    try testing.expectError(error.BadRecord, restoreInto(&db, &target, 5000, testTrust(&kp.public_key)));
    try testing.expect(!target.isGroupRevoked("alice", @splat(8)));
}

test "group revoke durable ambiguity requires cold reopen instead of rollback claims" {
    for ([_]store_mod.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } }) |fault| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var kp = try sign.KeyPair.fromSeed(@splat(34));
        defer kp.deinit();
        const wire = try testWire(testing.allocator, &kp, 9, "Alice");
        defer testing.allocator.free(wire);
        {
            var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "fault.wal");
            defer db.deinit();
            db.setPreparedIoFault(fault);
            try testing.expectError(error.IoAmbiguous, persist(&db, wire));
            try testing.expect(db.preparedWritesPoisoned());
            try testing.expectError(error.StorePoisoned, persist(&db, wire));
            try testing.expect(requiresColdReopen(error.IoAmbiguous));
            try testing.expect(requiresColdReopen(error.StorePoisoned));
            try testing.expect(!requiresColdReopen(error.OutOfMemory));
        }
        var reopened = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "fault.wal");
        defer reopened.deinit();
        var target = replica.Store.init(testing.allocator);
        defer target.deinit();
        const count = try restoreInto(&reopened, &target, 5000, testTrust(&kp.public_key));
        // A complete write with an uncertain sync has a recoverable fact;
        // failed/short writes do not. Only reopening establishes the result.
        try testing.expectEqual(@as(usize, if (fault.sync) 1 else 0), count);
        try testing.expectEqual(fault.sync, target.isGroupRevoked("alice", @splat(9)));
    }
}

fn allocationRestore(allocator: std.mem.Allocator, db: *const store_mod.OroStore, trust: Trust) !void {
    var target = replica.Store.init(allocator);
    defer target.deinit();
    _ = restoreInto(db, &target, 5000, trust) catch |err| {
        try testing.expect(!target.isGroupRevoked("alice", @splat(10)));
        try testing.expectEqual(@as(usize, 0), target.group_revocations.count());
        return err;
    };
    try testing.expect(target.isGroupRevoked("alice", @splat(10)));
}

test "group revoke durable restore allocation failures preserve cold target and retry" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var kp = try sign.KeyPair.fromSeed(@splat(35));
    defer kp.deinit();
    const wire = try testWire(testing.allocator, &kp, 10, "Alice");
    defer testing.allocator.free(wire);
    var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "allocation.wal");
    defer db.deinit();
    try persist(&db, wire);
    var relocating = testing.FailingAllocator.init(testing.allocator, .{ .resize_fail_index = 0 });
    try testing.checkAllAllocationFailures(relocating.allocator(), allocationRestore, .{ &db, testTrust(&kp.public_key) });
    try allocationRestore(testing.allocator, &db, testTrust(&kp.public_key));
}

const RetirementTestContext = struct {
    active: sign.PublicKey,
    grants: []const retired_policy.Grant,
    calls: std.atomic.Value(usize) = .init(0),

    fn allows(raw: *const anyopaque, key: sign.PublicKey, origin: u64) bool {
        const self: *const @This() = @ptrCast(@alignCast(raw));
        _ = @constCast(&self.calls).fetchAdd(1, .monotonic);
        return origin == signed_frame.originShortId(key) and std.crypto.timing_safe.eql(sign.PublicKey, self.active, key);
    }
    fn retired(raw: *const anyopaque, key: sign.PublicKey, origin: u64, group: retired_policy.Digest, fact: retired_policy.Digest) bool {
        const self: *const @This() = @ptrCast(@alignCast(raw));
        _ = @constCast(&self.calls).fetchAdd(1, .monotonic);
        return origin == signed_frame.originShortId(key) and retired_policy.allows(self.grants, key, group, fact);
    }
    fn trust(self: *const @This()) Trust {
        return .{ .ctx = self, .allows = allows, .allows_retired = retired, .required_grants = self.grants };
    }
};

fn testGrant(wire: []const u8) !retired_policy.Grant {
    const signed = try checked(wire);
    return .{ .group_key = groupKeyFor(signed.offer.token), .issuer_key = signed.signer, .fact_digest = factDigest(wire) };
}

test "group revoke retirement exact pins retain alternatives without granting retired signing authority" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var old = try sign.KeyPair.fromSeed(@splat(41));
    defer old.deinit();
    var active = try sign.KeyPair.fromSeed(@splat(42));
    defer active.deinit();
    const wire = try testWire(testing.allocator, &old, 31, "Alice");
    defer testing.allocator.free(wire);
    const alternative = try testWire(testing.allocator, &active, 31, "ALICE");
    defer testing.allocator.free(alternative);
    const grants = try retired_policy.canonicalize(testing.allocator, &.{ try testGrant(wire), try testGrant(alternative) });
    defer testing.allocator.free(grants);
    var ctx: RetirementTestContext = .{ .active = active.public_key, .grants = grants };
    var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "retired.wal");
    defer db.deinit();
    try persist(&db, wire);
    var target = replica.Store.init(testing.allocator);
    defer target.deinit();
    try testing.expectEqual(@as(usize, 1), try restoreInto(&db, &target, 5000, ctx.trust()));
    try testing.expectEqual(@as(usize, 1), try verifyRetained(&db, &target, ctx.trust()));
    try testing.expect(target.isGroupRevoked("alice", @splat(31)));
    try testing.expect(!RetirementTestContext.allows(&ctx, old.public_key, signed_frame.originShortId(old.public_key)));
    _ = try authorizeFence(wire, ctx.trust());
    // A newly signed denial from that same retired key for the same token and
    // account is still a different fact, even when it only changes revision.
    var reissued = (try replica.decodeOffer(wire)).offer;
    reissued.revision.epoch += 1;
    reissued.revision.sequence = reissued.revision.epoch << 16;
    const new_wire = try replica.encodeOffer(testing.allocator, reissued, &old);
    defer testing.allocator.free(new_wire);
    try testing.expectError(error.UntrustedOrigin, authorizeFence(new_wire, ctx.trust()));
    const foreign = try testWire(testing.allocator, &old, 31, "Mallory");
    defer testing.allocator.free(foreign);
    try testing.expectError(error.UntrustedOrigin, authorizeFence(foreign, ctx.trust()));
    const other_group = try testWire(testing.allocator, &old, 32, "Alice");
    defer testing.allocator.free(other_group);
    try testing.expectError(error.UntrustedOrigin, authorizeFence(other_group, ctx.trust()));
    const changed = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    ctx.calls.store(0, .monotonic);
    try testing.expectError(error.BadSignature, authorizeFence(changed, ctx.trust()));
    try testing.expectEqual(@as(usize, 0), ctx.calls.load(.monotonic));
    var wrong_key = keyFor(@splat(31));
    wrong_key[wrong_key.len - 1] = if (wrong_key[wrong_key.len - 1] == '0') '1' else '0';
    try testing.expectError(error.BadRecord, record(&wrong_key, wire, ctx.trust()));
    try testing.expectEqual(@as(usize, 0), ctx.calls.load(.monotonic));
    const upsert = try replica.encodeOffer(testing.allocator, .{
        .operation = .upsert,
        .token = @splat(31),
        .revision = reissued.revision,
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
        .account = "Alice",
        .nick = "Alice",
        .snapshot = "private",
    }, &old);
    defer testing.allocator.free(upsert);
    try testing.expectError(error.InvalidGroupRevoke, authorizeFence(upsert, ctx.trust()));
    try testing.expectEqual(@as(usize, 0), ctx.calls.load(.monotonic));
    // Either immutable first fact can satisfy the same required group.
    var alternative_db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "alternative.wal");
    defer alternative_db.deinit();
    try persist(&alternative_db, alternative);
    var alternative_target = replica.Store.init(testing.allocator);
    defer alternative_target.deinit();
    try testing.expectEqual(@as(usize, 1), try restoreInto(&alternative_db, &alternative_target, 5000, ctx.trust()));
    try testing.expectEqual(@as(usize, 1), try verifyRetained(&alternative_db, &alternative_target, ctx.trust()));
    // A different authorized first fact for the same account/token is valid;
    // an arbitrary self-signed checkpoint fact must not inherit DB authority.
    try testing.expectEqual(@as(usize, 1), try verifyRetained(&db, &alternative_target, ctx.trust()));
    var unknown = try sign.KeyPair.fromSeed(@splat(48));
    defer unknown.deinit();
    const unknown_wire = try testWire(testing.allocator, &unknown, 31, "Alice");
    defer testing.allocator.free(unknown_wire);
    var untrusted_target = replica.Store.init(testing.allocator);
    defer untrusted_target.deinit();
    _ = try untrusted_target.applySignedOffer(try replica.decodeOffer(unknown_wire), 0, 5000);
    const checkpoint = try untrusted_target.encodeUpgradeCheckpoint(testing.allocator, 5000);
    defer testing.allocator.free(checkpoint);
    var inherited = try replica.Store.restoreCurrentUpgradeCheckpoint(testing.allocator, .{}, checkpoint, 5000);
    defer inherited.deinit();
    try testing.expectError(error.UntrustedOrigin, verifyRetained(&db, &inherited, ctx.trust()));
    const after_verification = try inherited.encodeUpgradeCheckpoint(testing.allocator, 5000);
    defer testing.allocator.free(after_verification);
    try testing.expectEqualSlices(u8, checkpoint, after_verification);
}

test "group revoke retirement required groups missing from both database and Helix fail closed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var old = try sign.KeyPair.fromSeed(@splat(43));
    defer old.deinit();
    var active = try sign.KeyPair.fromSeed(@splat(44));
    defer active.deinit();
    const wire = try testWire(testing.allocator, &old, 33, "Alice");
    defer testing.allocator.free(wire);
    const grants = try retired_policy.canonicalize(testing.allocator, &.{try testGrant(wire)});
    defer testing.allocator.free(grants);
    var ctx: RetirementTestContext = .{ .active = active.public_key, .grants = grants };
    var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "missing.wal");
    defer db.deinit();
    var target = replica.Store.init(testing.allocator);
    defer target.deinit();
    const before = try target.encodeUpgradeCheckpoint(testing.allocator, 5000);
    defer testing.allocator.free(before);
    try testing.expectError(error.MissingRequiredFence, restoreInto(&db, &target, 5000, ctx.trust()));
    try testing.expectError(error.MissingRequiredFence, verifyRetained(&db, &target, ctx.trust()));
    try testing.expectError(error.MissingRequiredFence, prepareExport(testing.allocator, &db, ctx.trust(), active.public_key));
    const after = try target.encodeUpgradeCheckpoint(testing.allocator, 5000);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    try persist(&db, wire);
    try testing.expectError(error.MissingDurableFence, verifyRetained(&db, &target, ctx.trust()));
    try testing.expectEqual(@as(usize, 1), try restoreInto(&db, &target, 5000, ctx.trust()));
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, source: *const store_mod.OroStore, trust: Trust) !void {
            var staged = replica.Store.init(allocator);
            defer staged.deinit();
            const checkpoint = try staged.encodeUpgradeCheckpoint(testing.allocator, 5000);
            defer testing.allocator.free(checkpoint);
            _ = restoreInto(source, &staged, 5000, trust) catch |err| {
                const failed = try staged.encodeUpgradeCheckpoint(testing.allocator, 5000);
                defer testing.allocator.free(failed);
                try testing.expectEqualSlices(u8, checkpoint, failed);
                return err;
            };
            try testing.expect(staged.isGroupRevoked("Alice", @splat(33)));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ &db, ctx.trust() });
}

test "group revoke retirement export is stable composable bounded and atomic on failure" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var old = try sign.KeyPair.fromSeed(@splat(45));
    defer old.deinit();
    var active = try sign.KeyPair.fromSeed(@splat(46));
    defer active.deinit();
    var unknown = try sign.KeyPair.fromSeed(@splat(47));
    defer unknown.deinit();
    const retired = try testWire(testing.allocator, &old, 34, "PriorPrivateAccount");
    defer testing.allocator.free(retired);
    const current_a = try testWire(testing.allocator, &active, 35, "CurrentPrivateAccount");
    defer testing.allocator.free(current_a);
    const current_b = try testWire(testing.allocator, &active, 36, "OtherPrivateAccount");
    defer testing.allocator.free(current_b);
    const grants = try retired_policy.canonicalize(testing.allocator, &.{try testGrant(retired)});
    defer testing.allocator.free(grants);
    var ctx: RetirementTestContext = .{ .active = active.public_key, .grants = grants };
    var db = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "export.wal");
    defer db.deinit();
    try persist(&db, current_b);
    try persist(&db, retired);
    try persist(&db, current_a);
    const sequence = db.next_seq;
    const exported = try prepareExport(testing.allocator, &db, ctx.trust(), active.public_key);
    defer testing.allocator.free(exported);
    try testing.expectEqual(sequence, db.next_seq);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, exported, "[[mesh.retired_session_group_fences]]"));
    try testing.expect(std.mem.indexOf(u8, exported, "PrivateAccount") == null);
    const retired_hex = std.fmt.bytesToHex(old.public_key, .lower);
    try testing.expect(std.mem.indexOf(u8, exported, &retired_hex) == null);
    const a_hex = std.fmt.bytesToHex(factDigest(current_a), .lower);
    const b_hex = std.fmt.bytesToHex(factDigest(current_b), .lower);
    try testing.expect(std.mem.indexOf(u8, exported, &a_hex) != null and std.mem.indexOf(u8, exported, &b_hex) != null);
    try testing.expectError(error.IssuerNotActive, prepareExport(testing.allocator, &db, ctx.trust(), old.public_key));
    // Same complete cut, different map insertion order, identical canonical output.
    var reverse = try store_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "reverse.wal");
    defer reverse.deinit();
    try persist(&reverse, current_a);
    try persist(&reverse, current_b);
    try persist(&reverse, retired);
    const second = try prepareExport(testing.allocator, &reverse, ctx.trust(), active.public_key);
    defer testing.allocator.free(second);
    try testing.expectEqualSlices(u8, exported, second);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, source: *const store_mod.OroStore, trust: Trust, key: sign.PublicKey, expected: []const u8) !void {
            const cut = source.next_seq;
            const bytes = try prepareExport(allocator, source, trust, key);
            defer allocator.free(bytes);
            try testing.expectEqualSlices(u8, expected, bytes);
            try testing.expectEqual(cut, source.next_seq);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ &db, ctx.trust(), active.public_key, exported });
    const untrusted = try testWire(testing.allocator, &unknown, 37, "UntrustedPrivateAccount");
    defer testing.allocator.free(untrusted);
    try persist(&db, untrusted);
    try testing.expectError(error.UntrustedOrigin, prepareExport(testing.allocator, &db, ctx.trust(), active.public_key));
    // No returned buffer exists when any record is invalid, even after valid
    // selected records. The private-file publisher receives bytes only on success.
    const retired_key = keyFor(@splat(34));
    try testing.expectEqualSlices(u8, retired, db.get(.props, &retired_key).?);
}
