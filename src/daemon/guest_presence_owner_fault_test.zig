// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! External owner fault campaign. Parent-owned World lock, no production hooks.
const std = @import("std");
const testing = std.testing;
const world_mod = @import("world.zig");
const owner_mod = @import("guest_presence_owner.zig");
const presence = @import("../proto/mesh_presence_v3.zig");
const assembly = @import("../substrate/guest_membership_assembly.zig");
const sign = @import("../crypto/sign.zig");

fn limits() owner_mod.Limits {
    return .{ .subjects = 8, .prepared = 4, .pending = 8, .dependency_records = 16, .roots = 4, .retained_bytes = 1 << 20, .peak_bytes = 4 << 20, .work_per_operation = 1 << 20, .signature_attempts = 32, .clock = .{ .max_lifetime_ms = 5000, .max_future_skew_ms = 100 } };
}
fn record(origin: sign.PublicKey) presence.Record {
    return .{ .operation = .present, .origin = origin, .guest = presence.guestId(.{ .epoch = 1, .counter = 1 }) catch unreachable, .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 1, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "a.example", .realname = "Guest", .server = "origin.test", .description = "Origin", .membership_revision = 1, .manifest_id = @splat(4) };
}
const SourceProbe = struct {
    subject: assembly.Subject,
    expected: ?[]const u8,
    fn run(self: *@This(), source: assembly.CurrentPresenceSource) !void {
        const found = source.read_fn(source.context, self.subject, 1500);
        if (self.expected) |expected| {
            try testing.expect(found != null);
            try testing.expectEqualSlices(u8, expected, found.?.wire);
        } else try testing.expect(found == null);
    }
};
const InitialCtx = struct {
    wire: []const u8,
    subject: assembly.Subject,
    stale: ?owner_mod.PreparedId = null,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        const id = try cut.prepareInbound(self.wire, 7, 1500);
        try cut.validate(id, 1500);
        _ = try cut.commit(id, 1500);
        try testing.expectError(error.StalePrepared, cut.commit(id, 1500));
        try testing.expectError(error.StalePrepared, cut.abort(id));
        self.stale = id;
        const retained = (try cut.retainedWire(self.subject)) orelse return error.ExpectedRetainedOriginal;
        try testing.expectEqualSlices(u8, self.wire, retained);
        var probe = SourceProbe{ .subject = self.subject, .expected = self.wire };
        try cut.withCurrentSource(&probe, SourceProbe.run);
    }
};
const StaleCtx = struct {
    wire: []const u8,
    stale: owner_mod.PreparedId,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        const next = try cut.prepareInbound(self.wire, 7, 1500);
        // Even if an implementation reuses the same slot, the old ID cannot
        // validate, commit or abort the new candidate.
        try testing.expectError(error.StalePrepared, cut.validate(self.stale, 1500));
        try testing.expectError(error.StalePrepared, cut.commit(self.stale, 1500));
        try testing.expectError(error.StalePrepared, cut.abort(self.stale));
        try cut.abort(next);
    }
};
const ProbeCtx = struct {
    subject: assembly.Subject,
    expected: ?[]const u8,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        var p = SourceProbe{ .subject = self.subject, .expected = self.expected };
        try cut.withCurrentSource(&p, SourceProbe.run);
    }
};

const RemoveRootsCtx = struct {
    subject: assembly.Subject,
    wire: []const u8,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        const id = try cut.prepareRoots(&.{});
        try cut.validate(id, 1500);
        _ = try cut.commit(id, 1500);
        var probe = SourceProbe{ .subject = self.subject, .expected = null };
        try cut.withCurrentSource(&probe, SourceProbe.run);
        try testing.expectError(error.UnapprovedOrigin, cut.prepareInbound(self.wire, 7, 1500));
    }
};

test "owner current source honors actual World nick shadow and stale IDs across cuts" {
    var key = try sign.KeyPair.fromSeed(@splat(0x51));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x52));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, limits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    const r = record(key.public_key);
    var storage: [presence.max_wire_len]u8 = undefined;
    const wire = try presence.encode(r, &key, &storage);
    const subject: assembly.Subject = .{ .origin = r.origin, .guest = r.guest };
    var initial = InitialCtx{ .wire = wire, .subject = subject };
    world.lockWrite();
    owner.withCut(&initial, InitialCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
    var stale = StaleCtx{ .wire = wire, .stale = initial.stale.? };
    world.lockWrite();
    owner.withCut(&stale, StaleCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    const cid: world_mod.ClientId = .{ .shard = 0, .slot = 9, .gen = 1 };
    world.registerNick("gUeSt", cid) catch |err| {
        world.unlockWrite();
        return err;
    };
    var blocked = ProbeCtx{ .subject = subject, .expected = null };
    owner.withCut(&blocked, ProbeCtx.run) catch |err| {
        world.unregisterNick(cid);
        world.unlockWrite();
        return err;
    };
    world.unregisterNick(cid);
    world.unlockWrite();
    world.lockWrite();
    const local_subject: assembly.Subject = .{ .origin = local.public_key, .guest = r.guest };
    var local_probe = ProbeCtx{ .subject = local_subject, .expected = null };
    owner.withCut(&local_probe, ProbeCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    var restored = ProbeCtx{ .subject = subject, .expected = wire };
    owner.withCut(&restored, ProbeCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    var removal = RemoveRootsCtx{ .subject = subject, .wire = wire };
    owner.withCut(&removal, RemoveRootsCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

fn expectDependency(actual: owner_mod.Dependency, r: presence.Record) !void {
    try testing.expectEqualSlices(u8, &r.origin, &actual.subject.origin);
    try testing.expectEqualSlices(u8, &r.guest, &actual.subject.guest);
    try testing.expectEqual(r.claim_hlc, actual.claim_hlc);
    try testing.expectEqual(r.claim_revision, actual.claim_revision);
    try testing.expectEqual(r.routing_class, actual.routing_class);
    try testing.expectEqual(r.class_revision, actual.class_revision);
    try testing.expectEqual(r.membership_revision, actual.membership_revision);
    try testing.expectEqualSlices(u8, &r.manifest_id, &actual.manifest_id);
}

const FifoCtx = struct {
    a: []const u8,
    b: []const u8,
    c: []const u8,
    subject: assembly.Subject,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.a, self.b, self.c }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        try testing.expectEqual(@as(usize, 2), try cut.pendingCount());
        const ab = (try cut.pendingAt(0)) orelse return error.ExpectedPending;
        const bc = (try cut.pendingAt(1)) orelse return error.ExpectedPending;
        try testing.expectEqualSlices(u8, self.a, ab.old_wire);
        try testing.expectEqualSlices(u8, self.b, ab.new_wire);
        try testing.expectEqualSlices(u8, self.b, bc.old_wire);
        try testing.expectEqualSlices(u8, self.c, bc.new_wire);
        try expectDependency(ab.old_dependency, (try presence.decode(self.a)).record);
        try expectDependency(ab.new_dependency, (try presence.decode(self.b)).record);
        try expectDependency(bc.old_dependency, (try presence.decode(self.b)).record);
        try expectDependency(bc.new_dependency, (try presence.decode(self.c)).record);
        var p = SourceProbe{ .subject = self.subject, .expected = self.c };
        try cut.withCurrentSource(&p, SourceProbe.run);
    }
};

test "owner preserves FIFO signed originals across A B C transitions" {
    var key = try sign.KeyPair.fromSeed(@splat(0x53));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x54));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, limits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    var r = record(key.public_key);
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &b_buf);
    r.revision = 3;
    r.host = "c.example";
    const c = try presence.encode(r, &key, &c_buf);
    var ctx = FifoCtx{ .a = a, .b = b, .c = c, .subject = .{ .origin = r.origin, .guest = r.guest } };
    world.lockWrite();
    owner.withCut(&ctx, FifoCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

const ConflictCtx = struct {
    first: []const u8,
    second: []const u8,
    conflict: []const u8,
    subject: assembly.Subject,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.first, self.second }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        const held = try cut.prepareInbound(self.second, 7, 1500);
        const before = try cut.usage();
        try testing.expectEqual(@as(usize, 1), before.active_prepared);
        try testing.expectEqual(@as(usize, 1), before.pending_count);
        try testing.expectError(error.Quarantined, cut.prepareInbound(self.conflict, 7, 1500));
        const after = try cut.usage();
        try testing.expectEqual(before.active_prepared, after.active_prepared);
        try testing.expectEqual(before.pending_count, after.pending_count);
        try testing.expectEqual(before.live_payload, after.live_payload);
        try testing.expectEqual(before.reserved_payload, after.reserved_payload);
        try testing.expect(after.security_revision > before.security_revision);
        const pending = (try cut.pendingAt(0)) orelse return error.ExpectedPending;
        try testing.expectEqualSlices(u8, self.first, pending.old_wire);
        try testing.expectEqualSlices(u8, self.second, pending.new_wire);
        var p = SourceProbe{ .subject = self.subject, .expected = null };
        try cut.withCurrentSource(&p, SourceProbe.run);
        try testing.expectError(error.StalePrepared, cut.validate(held, 1500));
        try cut.abort(held);
    }
};

test "verified equivocation revokes with nonzero prepared and pending budgets exhausted" {
    var key = try sign.KeyPair.fromSeed(@splat(0x55));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x56));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    var cap = limits();
    cap.prepared = 1;
    cap.pending = 1;
    cap.dependency_records = 2;
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, cap);
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    var r = record(key.public_key);
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &b_buf);
    r.host = "conflict.example";
    const conflict = try presence.encode(r, &key, &c_buf);
    var ctx = ConflictCtx{ .first = a, .second = b, .conflict = conflict, .subject = .{ .origin = r.origin, .guest = r.guest } };
    world.lockWrite();
    owner.withCut(&ctx, ConflictCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

const BudgetCtx = struct {
    a: []const u8,
    b: []const u8,
    c: []const u8,
    subject: assembly.Subject,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.a, self.b }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        try testing.expectEqual(@as(usize, 1), try cut.pendingCount());
        const before = try cut.usage();
        try testing.expectError(error.BudgetExceeded, cut.prepareInbound(self.c, 7, 1500));
        try testing.expectEqualDeep(before, try cut.usage());
        try testing.expectEqual(@as(usize, 1), try cut.pendingCount());
        const pending = (try cut.pendingAt(0)) orelse return error.ExpectedPending;
        try testing.expectEqualSlices(u8, self.a, pending.old_wire);
        try testing.expectEqualSlices(u8, self.b, pending.new_wire);
        const retained = (try cut.retainedWire(self.subject)) orelse return error.ExpectedRetainedOriginal;
        try testing.expectEqualSlices(u8, self.b, retained);
        var p = SourceProbe{ .subject = self.subject, .expected = self.b };
        try cut.withCurrentSource(&p, SourceProbe.run);
    }
};

test "owner refuses A B C transition before publishing when pending budget is full" {
    var key = try sign.KeyPair.fromSeed(@splat(0x57));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x58));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    var cap = limits();
    cap.pending = 1;
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, cap);
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    var r = record(key.public_key);
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &b_buf);
    r.revision = 3;
    r.host = "c.example";
    const c = try presence.encode(r, &key, &c_buf);
    var ctx = BudgetCtx{ .a = a, .b = b, .c = c, .subject = .{ .origin = r.origin, .guest = r.guest } };
    world.lockWrite();
    owner.withCut(&ctx, BudgetCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

const FailedCommitCtx = struct {
    wire: []const u8,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        const before = try cut.usage();
        const id = try cut.prepareInbound(self.wire, 7, 1500);
        try cut.validate(id, 1500);
        try testing.expectError(error.Expired, cut.commit(id, 2001));
        const held = try cut.usage();
        try testing.expectEqual(before.active_prepared + 1, held.active_prepared);
        try testing.expect(held.reserved_payload > before.reserved_payload);
        try cut.abort(id);
        const released = try cut.usage();
        try testing.expectEqual(before.active_prepared, released.active_prepared);
        try testing.expectEqual(before.reserved_payload, released.reserved_payload);
    }
};

test "owner failed commit keeps prepared credit until abort" {
    var key = try sign.KeyPair.fromSeed(@splat(0x59));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x5a));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, limits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    const r = record(key.public_key);
    var buffer: [presence.max_wire_len]u8 = undefined;
    var ctx = FailedCommitCtx{ .wire = try presence.encode(r, &key, &buffer) };
    world.lockWrite();
    owner.withCut(&ctx, FailedCommitCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

const InterruptedCtx = struct {
    a: []const u8,
    b: []const u8,
    c: []const u8,
    subject: assembly.Subject,
    id: ?owner_mod.PreparedId = null,
    before: ?owner_mod.Usage = null,
    fn stage(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.a, self.b }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        self.before = try cut.usage();
        self.id = try cut.prepareInbound(self.c, 7, 1500);
    }
    fn stale(self: *@This(), cut: *owner_mod.Cut) !void {
        try testing.expectError(error.ExclusiveAcquisitionChanged, cut.validate(self.id.?, 1500));
        try testing.expectError(error.ExclusiveAcquisitionChanged, cut.abort(self.id.?));
        const held = try cut.usage();
        try testing.expectEqual(self.before.?.active_prepared + 1, held.active_prepared);
        try testing.expect(held.reserved_payload > self.before.?.reserved_payload);
    }
    fn after(self: *@This(), cut: *owner_mod.Cut) !void {
        try testing.expectEqualDeep(self.before.?, try cut.usage());
        const pending = (try cut.pendingAt(0)) orelse return error.ExpectedPending;
        try testing.expectEqualSlices(u8, self.a, pending.old_wire);
        try testing.expectEqualSlices(u8, self.b, pending.new_wire);
        const head = (try cut.retainedWire(self.subject)) orelse return error.ExpectedRetainedOriginal;
        try testing.expectEqualSlices(u8, self.b, head);
        var p = SourceProbe{ .subject = self.subject, .expected = self.b };
        try cut.withCurrentSource(&p, SourceProbe.run);
    }
};

test "later actual World acquisition reclaims interrupted unpublished plans only" {
    var key = try sign.KeyPair.fromSeed(@splat(0x5b));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x5c));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, limits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    var r = record(key.public_key);
    var abuf: [presence.max_wire_len]u8 = undefined;
    var bbuf: [presence.max_wire_len]u8 = undefined;
    var cbuf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &abuf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &bbuf);
    r.revision = 3;
    r.host = "c.example";
    const c = try presence.encode(r, &key, &cbuf);
    var ctx = InterruptedCtx{ .a = a, .b = b, .c = c, .subject = .{ .origin = r.origin, .guest = r.guest } };
    world.lockWrite();
    owner.withCut(&ctx, InterruptedCtx.stage) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
    world.lockWrite();
    owner.withCut(&ctx, InterruptedCtx.stale) catch |err| {
        world.unlockWrite();
        return err;
    };
    owner.reclaimInterrupted() catch |err| {
        world.unlockWrite();
        return err;
    };
    owner.withCut(&ctx, InterruptedCtx.after) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

fn expectTransition(cut: *owner_mod.Cut, index: usize, old: []const u8, new: []const u8) !void {
    const pending = (try cut.pendingAt(index)) orelse return error.ExpectedPending;
    try testing.expectEqualSlices(u8, old, pending.old_wire);
    try testing.expectEqualSlices(u8, new, pending.new_wire);
    try expectDependency(pending.old_dependency, (try presence.decode(old)).record);
    try expectDependency(pending.new_dependency, (try presence.decode(new)).record);
}
fn expectHead(cut: *owner_mod.Cut, subject: assembly.Subject, expected: []const u8) !void {
    const head = (try cut.retainedWire(subject)) orelse return error.ExpectedRetainedOriginal;
    try testing.expectEqualSlices(u8, expected, head);
    var probe = SourceProbe{ .subject = subject, .expected = expected };
    try cut.withCurrentSource(&probe, SourceProbe.run);
}
const OomCtx = struct {
    failing: *testing.FailingAllocator,
    index: usize,
    a: []const u8,
    b: []const u8,
    c: []const u8,
    subject: assembly.Subject,
    induced: bool = false,
    fn checkCommitted(self: *@This(), cut: *owner_mod.Cut) !void {
        try expectHead(cut, self.subject, self.c);
        try testing.expectEqual(@as(usize, 2), try cut.pendingCount());
        try expectTransition(cut, 0, self.a, self.b);
        try expectTransition(cut, 1, self.b, self.c);
        try testing.expectEqual(@as(usize, 0), (try cut.usage()).active_prepared);
        try testing.expectEqual(@as(usize, 0), (try cut.usage()).reserved_payload);
    }
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.a, self.b }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        const before = try cut.usage();
        try expectHead(cut, self.subject, self.b);
        try testing.expectEqual(@as(usize, 1), try cut.pendingCount());
        try expectTransition(cut, 0, self.a, self.b);
        self.failing.fail_index = self.failing.alloc_index + self.index;
        const next = cut.prepareInbound(self.c, 7, 1500) catch |err| {
            self.failing.fail_index = std.math.maxInt(usize);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(self.failing.has_induced_failure);
            try testing.expectEqualDeep(before, try cut.usage());
            try expectHead(cut, self.subject, self.b);
            try testing.expectEqual(@as(usize, 1), try cut.pendingCount());
            try expectTransition(cut, 0, self.a, self.b);
            const retry = try cut.prepareInbound(self.c, 7, 1500);
            try cut.validate(retry, 1500);
            _ = try cut.commit(retry, 1500);
            try self.checkCommitted(cut);
            self.induced = true;
            return;
        };
        self.failing.fail_index = std.math.maxInt(usize);
        try testing.expect(!self.failing.has_induced_failure);
        try cut.validate(next, 1500);
        _ = try cut.commit(next, 1500);
        try self.checkCommitted(cut);
    }
};

test "owner transition allocation failures preserve A B FIFO and retry C" {
    var key = try sign.KeyPair.fromSeed(@splat(0x5d));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x5e));
    defer local.deinit();
    var r = record(key.public_key);
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &b_buf);
    r.revision = 3;
    r.host = "c.example";
    const c = try presence.encode(r, &key, &c_buf);
    var failures: usize = 0;
    var complete = false;
    for (0..64) |n| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var world = world_mod.World.init(testing.allocator);
        defer world.deinit();
        const owner = try owner_mod.Owner.create(failing.allocator(), &world, local.public_key, &.{key.public_key}, limits());
        var ctx = OomCtx{ .failing = &failing, .index = n, .a = a, .b = b, .c = c, .subject = .{ .origin = r.origin, .guest = r.guest } };
        world.lockWrite();
        const result = owner.withCut(&ctx, OomCtx.run);
        owner.reclaimInterrupted() catch |err| {
            world.unlockWrite();
            return err;
        };
        owner.destroyQuiescent() catch |err| {
            world.unlockWrite();
            return err;
        };
        world.unlockWrite();
        try result;
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (ctx.induced) {
            try testing.expect(failing.has_induced_failure);
            failures += 1;
        } else {
            try testing.expect(!failing.has_induced_failure);
            complete = true;
            break;
        }
    }
    try testing.expect(complete and failures >= 3);
}

const FixedCtx = struct {
    fixed: usize = 0,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        self.fixed = (try cut.usage()).fixed;
    }
};
const ByteBudgetCtx = struct {
    a: []const u8,
    b: []const u8,
    other: []const u8,
    conflict: []const u8,
    subject: assembly.Subject,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        for ([_][]const u8{ self.a, self.b }) |wire| {
            const id = try cut.prepareInbound(wire, 7, 1500);
            try cut.validate(id, 1500);
            _ = try cut.commit(id, 1500);
        }
        const before = try cut.usage();
        try testing.expectError(error.BudgetExceeded, cut.prepareInbound(self.other, 7, 1500));
        try testing.expectEqualDeep(before, try cut.usage());
        try testing.expectError(error.Quarantined, cut.prepareInbound(self.conflict, 7, 1500));
        const after = try cut.usage();
        try testing.expectEqual(before.live_payload, after.live_payload);
        try testing.expectEqual(before.pending_count, after.pending_count);
        try testing.expect(after.security_revision > before.security_revision);
        const pending = (try cut.pendingAt(0)) orelse return error.ExpectedPending;
        try testing.expectEqualSlices(u8, self.a, pending.old_wire);
        try testing.expectEqualSlices(u8, self.b, pending.new_wire);
        var p = SourceProbe{ .subject = self.subject, .expected = null };
        try cut.withCurrentSource(&p, SourceProbe.run);
    }
};

test "verified conflict cuts authority even when byte budget refuses ordinary admission" {
    var key = try sign.KeyPair.fromSeed(@splat(0x5f));
    defer key.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(0x60));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    var r = record(key.public_key);
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    var other_buf: [presence.max_wire_len]u8 = undefined;
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.example";
    const b = try presence.encode(r, &key, &b_buf);
    r.host = "conflict.example";
    const conflict = try presence.encode(r, &key, &c_buf);
    r.guest = try presence.guestId(.{ .epoch = 1, .counter = 2 });
    r.nick = "OtherGuest";
    r.host = "other-long-visible.example";
    const other = try presence.encode(r, &key, &other_buf);
    var cap = limits();
    const probe_owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, cap);
    var fixed = FixedCtx{};
    world.lockWrite();
    probe_owner.withCut(&fixed, FixedCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    probe_owner.destroyQuiescent() catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
    cap.retained_bytes = fixed.fixed + 2 * a.len + 2 * b.len;
    cap.peak_bytes = cap.retained_bytes;
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{key.public_key}, cap);
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    const original = (try presence.decode(a)).record;
    var ctx = ByteBudgetCtx{ .a = a, .b = b, .other = other, .conflict = conflict, .subject = .{ .origin = original.origin, .guest = original.guest } };
    world.lockWrite();
    owner.withCut(&ctx, ByteBudgetCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}

const LocalOriginCtx = struct {
    wire: []const u8,
    subject: assembly.Subject,
    fn run(self: *@This(), cut: *owner_mod.Cut) !void {
        const id = try cut.prepareInbound(self.wire, 7, 1500);
        try cut.validate(id, 1500);
        try testing.expectEqual(owner_mod.Disposition.inserted, try cut.commit(id, 1500));
        const retained = (try cut.retainedWire(self.subject)) orelse return error.ExpectedRetainedOriginal;
        try testing.expectEqualSlices(u8, self.wire, retained);
        var probe = SourceProbe{ .subject = self.subject, .expected = null };
        try cut.withCurrentSource(&probe, SourceProbe.run);
    }
};

test "admitted signed local-origin head never becomes remote current source" {
    var local = try sign.KeyPair.fromSeed(@splat(0x61));
    defer local.deinit();
    var world = world_mod.World.init(testing.allocator);
    defer world.deinit();
    const owner = try owner_mod.Owner.create(testing.allocator, &world, local.public_key, &.{local.public_key}, limits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner not quiescent");
        world.unlockWrite();
    }
    var r = record(local.public_key);
    r.nick = "LocalGuest";
    var buffer: [presence.max_wire_len]u8 = undefined;
    const wire = try presence.encode(r, &local, &buffer);
    var ctx = LocalOriginCtx{ .wire = wire, .subject = .{ .origin = r.origin, .guest = r.guest } };
    world.lockWrite();
    owner.withCut(&ctx, LocalOriginCtx.run) catch |err| {
        world.unlockWrite();
        return err;
    };
    world.unlockWrite();
}
