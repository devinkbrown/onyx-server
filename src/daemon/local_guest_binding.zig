// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unpublished local physical guest bindings. No presence or network authority.
//! The caller supplies an operator-controlled state directory and keeps Core
//! alive for this owner's entire lifetime and every operation. Callers must hold
//! neither shared nor exclusive World/SessionStore locks across create, reserve,
//! or destroy. The local guard detects only this thread's exclusive acquisitions;
//! it cannot establish that no shared lock is held. No disk work occurs in a
//! World/SessionStore witness cut.
const std = @import("std");
const server = @import("server.zig");
const client = @import("client.zig");
const issuer_mod = @import("mesh_presence_issuer.zig");
const lease = @import("mesh_presence_lease.zig");
const presence = @import("../proto/mesh_presence.zig");
const rwlock = @import("../substrate/rwlock.zig");
const Core = server.LinuxServer;
const carry = @import("helix/local_guest_binding_snapshot.zig");

/// `retained_bytes` bounds this owner's backing, binding/ticket arrays and path
/// only. It excludes issuer/WAL resources and the independently owned key clone.
pub const Limits = struct { bindings: usize, tickets: usize, retained_bytes: usize };
pub const RevisionKind = enum { presence, membership };
pub const TicketId = struct { incarnation: u64, slot: usize, generation: u64 };
/// This is a returned value, not a bearer credential or admission witness.
pub const BindingRef = struct { physical: client.ClientId, origin: [32]u8, guest: presence.GuestId };
pub const Error = error{ Busy, InvalidLimits, BudgetExceeded, AlreadyBound, AlreadyPreparing, StaleTicket, TicketExhausted, NotCaptured, NotReserved, FactsChanged, OriginMismatch, ActiveTickets, MissingNodeIdentity, SignerUnavailable, LeaseLost, RevisionAdvanced, HandoffFrozen };

const Binding = struct {
    occupied: bool = false,
    physical: client.ClientId = .invalid,
    origin: [32]u8 = @splat(0),
    guest: presence.GuestId = @splat(0),
    facts: ?Core.PublicFacts = null,
    presence_revision: u64 = 0,
    membership_revision: u64 = 0,
    // Reserved for a future publisher; publication must set this under the
    // same lane before any network-visible authority can escape.
    published: bool = false,
};
const Ticket = struct {
    active: bool = false,
    generation: u64 = 0,
    physical: client.ClientId = .invalid,
    facts: ?Core.PublicFacts = null,
    reserved: ?presence.GuestId = null,
    issuer_incarnation: u64 = 0,
};
var incarnation_source: std.atomic.Value(u64) = .init(1);
fn freshIncarnation() Error!u64 {
    while (true) {
        const value = incarnation_source.load(.monotonic);
        if (value == std.math.maxInt(u64)) return error.TicketExhausted;
        if (incarnation_source.cmpxchgWeak(value, value + 1, .monotonic, .monotonic) == null) return value;
    }
}

const Backing = struct {
    allocator: std.mem.Allocator,
    core: *Core,
    issuer: issuer_mod.Issuer,
    directory: std.Io.Dir,
    path: []u8,
    lease_identity: lease.Identity,
    incarnation: u64,
    issuer_incarnation: u64,
    lease_faulted: bool = false,
    handoff: enum { active, frozen, retired } = .active,
    lock: rwlock.RwLock = .{},
    rows: []Binding,
    tickets: []Ticket,
};
fn backing(owner: *Bindings) *Backing {
    return @ptrCast(@alignCast(owner));
}
fn requireNoCoreCut(core: *Core) Error!void {
    if (core.world.lock.requireExclusiveHeldByCurrentThread()) |_| return error.Busy else |_| {}
    if (core.sessions.lock.requireExclusiveHeldByCurrentThread()) |_| return error.Busy else |_| {}
}
fn snapshotFacts(f: *const Core.PublicFacts) !carry.Facts {
    if (f.nick_len > f.nick_bytes.len or f.username_len > f.username_bytes.len or f.public_host_len > f.public_host_bytes.len or f.realname_len > f.realname_bytes.len or f.server_len > f.server_bytes.len or f.description_len > f.description_bytes.len) return error.FactsChanged;
    return .{ .nick = f.nick(), .username = f.username(), .host = f.publicHost(), .realname = f.realname(), .server = f.serverName(), .description = f.description() };
}
fn restoreFacts(f: carry.Facts, physical: client.ClientId, origin: [32]u8) Core.PublicFacts {
    var out: Core.PublicFacts = .{ .physical = physical, .origin = origin };
    out.nick_len = f.nick.len;
    @memcpy(out.nick_bytes[0..f.nick.len], f.nick);
    out.username_len = f.username.len;
    @memcpy(out.username_bytes[0..f.username.len], f.username);
    out.public_host_len = f.host.len;
    @memcpy(out.public_host_bytes[0..f.host.len], f.host);
    out.realname_len = f.realname.len;
    @memcpy(out.realname_bytes[0..f.realname.len], f.realname);
    out.server_len = f.server.len;
    @memcpy(out.server_bytes[0..f.server.len], f.server);
    out.description_len = f.description.len;
    @memcpy(out.description_bytes[0..f.description.len], f.description);
    return out;
}
fn reserveCarriedIncarnation(value: u64) !void {
    if (value == 0 or value == std.math.maxInt(u64)) return error.TicketExhausted;
    while (true) {
        const next = incarnation_source.load(.monotonic);
        if (next > value) return error.IncarnationCollision;
        if (incarnation_source.cmpxchgWeak(next, value + 1, .monotonic, .monotonic) == null) return;
    }
}
/// The relation is supplied by Core after full independently authenticated
/// physical owner validation; neither callback nor stored IDs grant authority.
pub const PhysicalMapper = struct {
    ctx: *anyopaque,
    map_fn: *const fn (*anyopaque, client.ClientId) anyerror!client.ClientId,
};
pub const Bindings = opaque {
    /// Explicit provisioning only; never falls back to initializing on open.
    /// Caller holds no shared or exclusive World/SessionStore lock.
    pub fn initialize(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, core: *Core, limits: Limits, now_ms: i64) !*Bindings {
        return create(a, io, dir, path, core, limits, now_ms, true);
    }
    /// Cold replay advances the durable epoch; this is not a Helix restore.
    /// Caller holds no shared or exclusive World/SessionStore lock.
    pub fn openCold(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, core: *Core, limits: Limits, now_ms: i64) !*Bindings {
        return create(a, io, dir, path, core, limits, now_ms, false);
    }
    fn create(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, core: *Core, limits: Limits, now_ms: i64, provision_new: bool) !*Bindings {
        try requireNoCoreCut(core);
        if (limits.bindings == 0 or limits.tickets == 0 or path.len == 0) return error.InvalidLimits;
        const rows_bytes = std.math.mul(usize, limits.bindings, @sizeOf(Binding)) catch return error.BudgetExceeded;
        const tickets_bytes = std.math.mul(usize, limits.tickets, @sizeOf(Ticket)) catch return error.BudgetExceeded;
        var fixed = std.math.add(usize, @sizeOf(Backing), rows_bytes) catch return error.BudgetExceeded;
        fixed = std.math.add(usize, fixed, tickets_bytes) catch return error.BudgetExceeded;
        fixed = std.math.add(usize, fixed, path.len) catch return error.BudgetExceeded;
        if (fixed > limits.retained_bytes) return error.BudgetExceeded;
        const owner = try a.create(Backing);
        errdefer a.destroy(owner);
        const rows = try a.alloc(Binding, limits.bindings);
        errdefer a.free(rows);
        const tickets = try a.alloc(Ticket, limits.tickets);
        errdefer a.free(tickets);
        const owned_path = try a.dupe(u8, path);
        errdefer a.free(owned_path);
        @memset(rows, .{});
        @memset(tickets, .{});
        const incarnation = try freshIncarnation();
        // Own an independent sealed key page; release World before issuer I/O.
        var key = blk: {
            core.world.lockWrite();
            defer core.world.unlockWrite();
            const origin = try core.ordinaryGuestOrigin();
            break :blk try core.cloneOrdinaryGuestSigner(origin);
        };
        defer key.deinit();
        var durable = if (provision_new)
            try issuer_mod.Issuer.initialize(a, io, dir, path, &key, now_ms)
        else
            try issuer_mod.Issuer.openCold(a, io, dir, path, &key, now_ms);
        errdefer durable.deinit();
        const identity = try lease.statRegular(durable.lease.handle);
        try durable.requireOwnedReady(dir, owned_path, key.public_key, identity);
        owner.* = .{ .allocator = a, .core = core, .issuer = durable, .directory = dir, .path = owned_path, .lease_identity = identity, .incarnation = incarnation, .issuer_incarnation = incarnation, .rows = rows, .tickets = tickets };
        return @ptrCast(owner);
    }

    /// Caller serializes this owner and its Core connection latches. The
    /// checkpoint carries data only; Core owns authenticated capsule/FD binding.
    pub const HotCapture = struct {
        owner: *Bindings,
        issuer_checkpoint: *issuer_mod.Issuer.HotCheckpoint,
        bytes: []u8,
        allocator: std.mem.Allocator,
        done: bool = false,
        pub fn issuerImage(self: *const HotCapture) !issuer_mod.Issuer.HotTransferImage {
            return issuer_mod.Issuer.hotTransferImage(self.issuer_checkpoint);
        }
        /// Duplicate the frozen owner's actual locked description for the
        /// authenticated Core FD capsule; caller owns and closes the result.
        /// Caller holds neither World nor SessionStore lock.
        pub fn duplicateLease(self: *const HotCapture) !struct { file: std.Io.File, identity: lease.Identity } {
            if (self.done) return error.StaleHandoff;
            const b = backing(self.owner);
            if (!b.lock.tryLockExclusive()) return error.Busy;
            defer b.lock.unlockExclusive();
            if (b.handoff != .frozen) return error.StaleHandoff;
            try requireNoCoreCut(b.core);
            _ = try issuer_mod.Issuer.hotTransferImage(self.issuer_checkpoint);
            _ = try lease.validateInherited(b.allocator, b.issuer.io, b.directory, b.path, b.issuer.lease, b.lease_identity);
            const duplicate = try @import("os_runtime.zig").duplicateFile(b.issuer.lease);
            return .{ .file = duplicate, .identity = b.lease_identity };
        }
        pub fn abort(self: *HotCapture) !void {
            if (self.done) return error.StaleHandoff;
            const b = backing(self.owner);
            if (!b.lock.tryLockExclusive()) return error.Busy;
            defer b.lock.unlockExclusive();
            if (b.handoff != .frozen) return error.StaleHandoff;
            try b.issuer.abortHotHandoff(self.issuer_checkpoint.generation());
            b.handoff = .active;
            self.done = true;
        }
        /// Core performs authenticated COMMIT and fences all old users first.
        pub fn retire(self: *HotCapture) !void {
            if (self.done) return error.StaleHandoff;
            const b = backing(self.owner);
            if (!b.lock.tryLockExclusive()) return error.Busy;
            defer b.lock.unlockExclusive();
            if (b.handoff != .frozen) return error.StaleHandoff;
            try b.issuer.retireHotHandoff(self.issuer_checkpoint.generation());
            b.handoff = .retired;
            self.done = true;
        }
        /// Call only after abort or retire; source and owner lane stay alive.
        pub fn deinit(self: *HotCapture) void {
            std.debug.assert(self.done);
            self.issuer_checkpoint.deinit();
            self.allocator.free(self.bytes);
            self.* = undefined;
        }
    };
    pub fn freezeForHotHandoff(handle: *Bindings, limits: carry.Limits) !HotCapture {
        const b = backing(handle);
        if (!b.lock.tryLockExclusive()) return error.Busy;
        defer b.lock.unlockExclusive();
        if (b.handoff != .active) return error.HandoffFrozen;
        try requireNoCoreCut(b.core);
        if (b.lease_faulted) return error.LeaseLost;
        const rows = try b.allocator.alloc(carry.Row, b.rows.len);
        defer b.allocator.free(rows);
        const tickets = try b.allocator.alloc(carry.Ticket, b.tickets.len);
        defer b.allocator.free(tickets);
        var count: usize = 0;
        for (b.rows) |*row| if (row.occupied) {
            if (row.published or row.presence_revision != 0 or row.membership_revision != 0) return error.RevisionAdvanced;
            const facts = if (row.facts) |*f| f else return error.FactsChanged;
            if (!facts.physical.eql(row.physical) or !std.mem.eql(u8, &facts.origin, &row.origin) or !std.mem.eql(u8, &row.origin, &b.issuer.metadata.origin)) return error.FactsChanged;
            rows[count] = .{ .physical = @bitCast(row.physical), .origin = row.origin, .guest = row.guest, .facts = try snapshotFacts(facts) };
            count += 1;
        };
        std.mem.sort(carry.Row, rows[0..count], {}, struct {
            fn less(_: void, x: carry.Row, y: carry.Row) bool {
                return x.physical < y.physical;
            }
        }.less);
        for (b.tickets, 0..) |*ticket, i| {
            tickets[i] = .{ .generation = ticket.generation };
            if (ticket.active) {
                tickets[i].physical = @as(u64, @bitCast(ticket.physical));
                tickets[i].issuer_incarnation = ticket.issuer_incarnation;
                if (ticket.facts) |*facts| {
                    if (!facts.physical.eql(ticket.physical) or !std.mem.eql(u8, &facts.origin, &b.issuer.metadata.origin)) return error.FactsChanged;
                    tickets[i].facts = try snapshotFacts(facts);
                }
                tickets[i].reserved = ticket.reserved;
            }
        }
        const bytes = try carry.encode(b.allocator, .{ .incarnation = b.incarnation, .issuer_incarnation = b.issuer_incarnation, .rows = rows[0..count], .tickets = tickets }, limits);
        errdefer b.allocator.free(bytes);
        const checkpoint = try b.issuer.freezeForHotHandoff(b.directory, b.path, b.issuer.metadata.origin, b.lease_identity);
        b.handoff = .frozen;
        return .{ .owner = handle, .issuer_checkpoint = checkpoint, .bytes = bytes, .allocator = b.allocator };
    }

    pub const StagedHotBindings = struct {
        owner: ?*Backing,
        issuer: issuer_mod.Issuer.TransferredHotIssuer,
        pub fn deinit(self: *StagedHotBindings) void {
            self.issuer.deinit();
            if (self.owner) |b| {
                const a = b.allocator;
                a.free(b.rows);
                a.free(b.tickets);
                a.free(b.path);
                a.destroy(b);
            }
            self.owner = null;
        }
        /// Core proves authenticated COMMIT, physical/latch references and
        /// retired predecessor before this no-allocation, no-I/O publication.
        pub fn activateAfterCoreCommit(self: *StagedHotBindings) *Bindings {
            const b = self.owner orelse unreachable;
            b.issuer = self.issuer.activateAfterCoreCommit();
            b.handoff = .active;
            self.owner = null;
            return @ptrCast(b);
        }
    };
    /// Stages data and issuer only; inherited lease is consumed on all paths.
    /// Core validates capsule, live source and descriptor binding beforehand.
    /// Source state and active latches remain Core-owned until COMMIT.
    pub fn stageHotAdoption(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, core: *Core, limits: Limits, wire_limits: carry.Limits, wire: []const u8, issuer_image: issuer_mod.Issuer.HotTransferImage, inherited: std.Io.File, mapper: PhysicalMapper) !StagedHotBindings {
        var lease_consumed = false;
        errdefer if (!lease_consumed) inherited.close(io);
        try requireNoCoreCut(core);
        if (limits.bindings == 0 or limits.tickets == 0 or path.len == 0) return error.InvalidLimits;
        var image = try carry.decodeOwned(a, wire, wire_limits);
        defer image.deinit();
        if (image.image.rows.len > limits.bindings or image.image.tickets.len != limits.tickets) return error.BudgetExceeded;
        const rows_bytes = std.math.mul(usize, limits.bindings, @sizeOf(Binding)) catch return error.BudgetExceeded;
        const tickets_bytes = std.math.mul(usize, limits.tickets, @sizeOf(Ticket)) catch return error.BudgetExceeded;
        const size = std.math.add(usize, @sizeOf(Backing), rows_bytes) catch return error.BudgetExceeded;
        const size2 = std.math.add(usize, size, tickets_bytes) catch return error.BudgetExceeded;
        if ((std.math.add(usize, size2, path.len) catch return error.BudgetExceeded) > limits.retained_bytes) return error.BudgetExceeded;
        const origin = blk: {
            core.world.lockWrite();
            defer core.world.unlockWrite();
            break :blk try core.ordinaryGuestOrigin();
        };
        if (!std.mem.eql(u8, &origin, &issuer_image.metadata.origin)) return error.OriginMismatch;
        const b = try a.create(Backing);
        errdefer a.destroy(b);
        const rows = try a.alloc(Binding, limits.bindings);
        errdefer a.free(rows);
        @memset(rows, .{});
        const tickets = try a.alloc(Ticket, limits.tickets);
        errdefer a.free(tickets);
        @memset(tickets, .{});
        const owned_path = try a.dupe(u8, path);
        errdefer a.free(owned_path);
        var old_seen = std.AutoHashMap(u64, void).init(a);
        defer old_seen.deinit();
        var new_seen = std.AutoHashMap(u64, void).init(a);
        defer new_seen.deinit();
        var guest_seen = std.AutoHashMap(presence.GuestId, void).init(a);
        defer guest_seen.deinit();
        for (image.image.rows, 0..) |row, i| {
            if (!std.mem.eql(u8, &row.origin, &origin)) return error.OriginMismatch;
            const subject = try presence.subject(row.guest);
            if (subject.epoch != issuer_image.metadata.epoch or subject.counter > issuer_image.metadata.issued_through or (try guest_seen.getOrPut(row.guest)).found_existing) return error.InvalidGuestReservation;
            const old: client.ClientId = @bitCast(row.physical);
            const next = try mapper.map_fn(mapper.ctx, old);
            if (next.isNone()) return error.InvalidPhysicalMapping;
            if ((try old_seen.getOrPut(row.physical)).found_existing or (try new_seen.getOrPut(@bitCast(next))).found_existing) return error.InvalidPhysicalMapping;
            rows[i] = .{ .occupied = true, .physical = next, .origin = origin, .guest = row.guest, .facts = restoreFacts(row.facts, next, origin) };
        }
        var active: usize = 0;
        for (image.image.tickets, 0..) |ticket, i| {
            tickets[i].generation = ticket.generation;
            if (ticket.physical) |physical| {
                const next = try mapper.map_fn(mapper.ctx, @bitCast(physical));
                if (next.isNone()) return error.InvalidPhysicalMapping;
                if ((try old_seen.getOrPut(physical)).found_existing or (try new_seen.getOrPut(@bitCast(next))).found_existing) return error.InvalidPhysicalMapping;
                if (ticket.reserved) |guest| {
                    const subject = try presence.subject(guest);
                    if (subject.epoch != issuer_image.metadata.epoch or subject.counter > issuer_image.metadata.issued_through or (try guest_seen.getOrPut(guest)).found_existing) return error.InvalidGuestReservation;
                }
                tickets[i] = .{ .active = true, .generation = ticket.generation, .physical = next, .issuer_incarnation = ticket.issuer_incarnation, .reserved = ticket.reserved };
                if (ticket.facts) |facts| tickets[i].facts = restoreFacts(facts, next, origin);
                active += 1;
            }
        }
        if (active > limits.bindings - image.image.rows.len) return error.BudgetExceeded;
        lease_consumed = true;
        var staged_issuer = try issuer_mod.Issuer.stageTransferredHot(a, io, dir, path, inherited, issuer_image, origin);
        errdefer staged_issuer.deinit();
        // Reserve only after fallible staging. An aborted successful stage burns
        // this namespace in the successor; retry requires a fresh successor.
        try reserveCarriedIncarnation(image.image.incarnation);
        b.* = .{ .allocator = a, .core = core, .issuer = undefined, .directory = dir, .path = owned_path, .lease_identity = issuer_image.lease_identity, .incarnation = image.image.incarnation, .issuer_incarnation = image.image.issuer_incarnation, .rows = rows, .tickets = tickets, .handoff = .frozen };
        return .{ .owner = b, .issuer = staged_issuer };
    }

    /// Only after Core's authenticated transfer retirement and capture deinit.
    /// No reserved number is refunded and no successor state is touched. Lease
    /// release closes only this owner's description, never an explicit unlock.
    pub fn reclaimRetired(handle: *Bindings) !void {
        const b = backing(handle);
        if (!b.lock.tryLockExclusive()) return error.Busy;
        if (b.handoff != .retired) {
            b.lock.unlockExclusive();
            return error.NotRetired;
        }
        requireNoCoreCut(b.core) catch |err| {
            b.lock.unlockExclusive();
            return err;
        };
        const a = b.allocator;
        b.issuer.deinit();
        a.free(b.path);
        a.free(b.rows);
        a.free(b.tickets);
        b.lock.unlockExclusive();
        a.destroy(b);
    }

    /// Caller quiesces all users and holds no shared or exclusive World/Store
    /// lock. Active unpublished tickets block teardown.
    pub fn destroyQuiescent(handle: *Bindings) !void {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        if (self.handoff == .frozen) {
            self.lock.unlockExclusive();
            return error.HandoffFrozen;
        }
        for (self.tickets) |slot| if (slot.active) {
            self.lock.unlockExclusive();
            return error.ActiveTickets;
        };
        for (self.rows) |row| if (row.occupied and (row.published or row.presence_revision != 0 or row.membership_revision != 0)) {
            self.lock.unlockExclusive();
            return error.RevisionAdvanced;
        };
        requireNoCoreCut(self.core) catch |err| {
            self.lock.unlockExclusive();
            return err;
        };
        // This owner has no publisher or network-admitted bindings. Future
        // publication must add negative obligations before allowing teardown.
        const a = self.allocator;
        self.issuer.deinit();
        a.free(self.path);
        a.free(self.rows);
        a.free(self.tickets);
        self.lock.unlockExclusive();
        a.destroy(self);
    }

    pub fn begin(handle: *Bindings, physical: client.ClientId) !TicketId {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        if (physical.isNone()) return error.StaleTicket;
        for (self.rows) |row| if (row.occupied and row.physical.eql(physical)) return error.AlreadyBound;
        for (self.tickets) |slot| if (slot.active and slot.physical.eql(physical)) return error.AlreadyPreparing;
        // Reserve row capacity for every outstanding ticket before issuance.
        var free_rows: usize = 0;
        for (self.rows) |row| if (!row.occupied) {
            free_rows += 1;
        };
        var active: usize = 0;
        for (self.tickets) |slot| if (slot.active) {
            active += 1;
        };
        if (active >= free_rows) return error.BudgetExceeded;
        for (self.tickets, 0..) |*ticket, n| if (!ticket.active) {
            if (ticket.generation == std.math.maxInt(u64)) continue;
            const generation = ticket.generation + 1;
            ticket.* = .{ .active = true, .generation = generation, .physical = physical, .issuer_incarnation = self.issuer_incarnation };
            return .{ .incarnation = self.incarnation, .slot = n, .generation = generation };
        };
        return error.BudgetExceeded;
    }
    /// Called only within the actual Core witness callback. No I/O, allocation,
    /// or signing; copied facts are not themselves classification authority.
    pub fn capture(handle: *Bindings, id: TicketId, witness: *const Core.OrdinaryGuestWitness) !void {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        const slot = try requireTicket(self, id);
        var facts: Core.PublicFacts = .{};
        try witness.copyPublicFactsInto(self.core, slot.physical, &facts);
        if (!std.mem.eql(u8, &facts.origin, &self.issuer.metadata.origin)) return error.OriginMismatch;
        if (slot.facts) |old| {
            if (!Core.PublicFacts.sameIdentity(&old, &facts)) return error.FactsChanged;
        } else slot.facts = facts;
    }
    /// Caller holds neither shared nor exclusive World/SessionStore lock.
    /// Same-ticket retry returns the same already-durable reservation; abandon
    /// never returns a number to the WAL.
    pub fn reserve(handle: *Bindings, id: TicketId) !void {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        try requireNoCoreCut(self.core);
        const slot = try requireTicket(self, id);
        const facts = slot.facts orelse return error.NotCaptured;
        if (slot.issuer_incarnation != self.issuer_incarnation) return error.StaleTicket;
        if (self.lease_faulted) return error.LeaseLost;
        self.issuer.requireOwnedReady(self.directory, self.path, facts.origin, self.lease_identity) catch |err| {
            switch (err) {
                error.IdentityMismatch, error.NotRegular, error.WouldBlock, error.FileNotFound => self.lease_faulted = true,
                else => {},
            }
            return err;
        };
        if (slot.reserved != null) return;
        const subject = try self.issuer.reserveSubject();
        const guest = try presence.guestId(subject);
        slot.reserved = guest;
    }
    /// Fresh actual witness + original owned reservation; all operations after
    /// successful checks are no-fail RAM updates while both ownership cuts hold.
    pub fn commit(handle: *Bindings, id: TicketId, witness: *const Core.OrdinaryGuestWitness) !BindingRef {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        const slot = try requireTicket(self, id);
        const prior = slot.facts orelse return error.NotCaptured;
        const guest = slot.reserved orelse return error.NotReserved;
        if (slot.issuer_incarnation != self.issuer_incarnation) return error.StaleTicket;
        var fresh: Core.PublicFacts = .{};
        try witness.copyPublicFactsInto(self.core, slot.physical, &fresh);
        if (!Core.PublicFacts.sameIdentity(&prior, &fresh)) return error.FactsChanged;
        if (self.lease_faulted) return error.LeaseLost;
        try self.issuer.requireOwnedReadyNoIo(fresh.origin);
        for (self.rows) |row| if (row.occupied and row.physical.eql(slot.physical)) return error.AlreadyBound;
        for (self.rows) |*row| if (!row.occupied) {
            const result: BindingRef = .{ .physical = slot.physical, .origin = fresh.origin, .guest = guest };
            row.* = .{ .occupied = true, .physical = slot.physical, .origin = fresh.origin, .guest = guest, .facts = fresh };
            const generation = slot.generation;
            slot.* = .{ .generation = generation };
            return result;
        };
        return error.BudgetExceeded; // Defensive: begin funded this slot.
    }
    /// Retire only a never-published exact physical binding. This is a RAM-only
    /// cleanup: the issuer's durable counter remains burned. A later publisher
    /// must establish retained negative obligations before removing its rows.
    pub fn retireUnpublished(handle: *Bindings, physical: client.ClientId) !bool {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        for (self.tickets) |slot| if (slot.active and slot.physical.eql(physical)) return error.ActiveTickets;
        for (self.rows) |*row| if (row.occupied and row.physical.eql(physical)) {
            if (row.published or row.presence_revision != 0 or row.membership_revision != 0) return error.RevisionAdvanced;
            row.* = .{};
            return true;
        };
        return false;
    }
    /// Read-only identity value, never classification or remote authority.
    pub fn lookup(handle: *Bindings, physical: client.ClientId) !?BindingRef {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        for (self.rows) |row| if (row.occupied and row.physical.eql(physical))
            return .{ .physical = row.physical, .origin = row.origin, .guest = row.guest };
        return null;
    }
    /// Reserve only an unpublished revision. A future publisher must fund its
    /// own output and acquire a new witness before any authority is visible.
    pub fn nextUnpublishedRevision(handle: *Bindings, physical: client.ClientId, kind: RevisionKind, witness: *const Core.OrdinaryGuestWitness) !u64 {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        for (self.rows) |*row| if (row.occupied and row.physical.eql(physical)) {
            var fresh: Core.PublicFacts = .{};
            try witness.copyPublicFactsInto(self.core, physical, &fresh);
            const old = row.facts orelse return error.FactsChanged;
            if (!Core.PublicFacts.sameIdentity(&old, &fresh)) return error.FactsChanged;
            if (self.lease_faulted) return error.LeaseLost;
            try self.issuer.requireOwnedReadyNoIo(fresh.origin);
            const counter = switch (kind) {
                .presence => &row.presence_revision,
                .membership => &row.membership_revision,
            };
            const next = std.math.add(u64, counter.*, 1) catch return error.TicketExhausted;
            counter.* = next;
            return next;
        };
        return error.StaleTicket;
    }
    /// Frees only unpublished ticket state; any durable reservation stays burned.
    pub fn abandon(handle: *Bindings, id: TicketId) !void {
        const self = backing(handle);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        if (self.handoff != .active) return error.HandoffFrozen;
        const slot = try requireTicket(self, id);
        const generation = slot.generation;
        slot.* = .{ .generation = generation };
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn withContendedOwner(owner: *Bindings, context: anytype, comptime callback: anytype) !void {
        const self = backing(owner);
        if (!self.lock.tryLockExclusive()) return error.Busy;
        defer self.lock.unlockExclusive();
        try callback(context);
    }
} else struct {};
fn requireTicket(self: *Backing, id: TicketId) Error!*Ticket {
    if (id.incarnation != self.incarnation or id.slot >= self.tickets.len) return error.StaleTicket;
    const result = &self.tickets[id.slot];
    if (!result.active or result.generation != id.generation) return error.StaleTicket;
    return result;
}

test "local guest binding opens real issuer and funds bounded tickets before reservation" {
    if (comptime @import("builtin").os.tag != .linux and @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var identity = try @import("node_identity.zig").fromSeed(@splat(0x91), "binding-test");
    defer identity.deinit();
    var core = Core.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0, .node_identity = &identity, .crypto_io = std.testing.io }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer core.deinit();
    const cap: Limits = .{ .bindings = 1, .tickets = 2, .retained_bytes = 128 * 1024 };
    const owner = try Bindings.initialize(std.testing.allocator, std.testing.io, temporary.dir, "binding.wal", &core, cap, 1000);
    const first: client.ClientId = .{ .shard = 0, .slot = 7, .gen = 1 };
    const later: client.ClientId = .{ .shard = 0, .slot = 7, .gen = 2 };
    const ticket1 = try owner.begin(first);
    try std.testing.expectError(error.ActiveTickets, owner.retireUnpublished(first));
    try std.testing.expectError(error.AlreadyPreparing, owner.begin(first));
    try std.testing.expectError(error.BudgetExceeded, owner.begin(later));
    try std.testing.expectError(error.NotCaptured, owner.reserve(ticket1));
    try std.testing.expectEqual(@as(u64, 0), backing(owner).issuer.metadata.issued_through);
    try std.testing.expectError(error.ActiveTickets, owner.destroyQuiescent());
    try owner.abandon(ticket1);
    try std.testing.expectError(error.StaleTicket, owner.abandon(ticket1));
    const ticket2 = try owner.begin(later);
    try std.testing.expect(ticket2.generation != ticket1.generation);
    try owner.abandon(ticket2);
    // White-box retirement test only: the real issuer reserves the counter;
    // real witness-driven publication is separately tested at the Core seam.
    const issued = try backing(owner).issuer.reserveSubject();
    const guest = try presence.guestId(issued);
    backing(owner).rows[0] = .{ .occupied = true, .physical = first, .origin = identity.sign_kp.public_key, .guest = guest };
    try std.testing.expect(!try owner.retireUnpublished(later));
    backing(owner).rows[0].presence_revision = 1;
    try std.testing.expectError(error.RevisionAdvanced, owner.retireUnpublished(first));
    try std.testing.expectError(error.RevisionAdvanced, owner.destroyQuiescent());
    backing(owner).rows[0].presence_revision = 0;
    backing(owner).rows[0].membership_revision = 1;
    try std.testing.expectError(error.RevisionAdvanced, owner.retireUnpublished(first));
    backing(owner).rows[0].membership_revision = 0;
    backing(owner).rows[0].published = true;
    try std.testing.expectError(error.RevisionAdvanced, owner.retireUnpublished(first));
    backing(owner).rows[0].published = false;
    try std.testing.expect(try owner.retireUnpublished(first));
    try std.testing.expectEqual(issued.counter, backing(owner).issuer.metadata.issued_through);
    try std.testing.expect(!try owner.retireUnpublished(first));
    try owner.destroyQuiescent();
    const reopened = try Bindings.openCold(std.testing.allocator, std.testing.io, temporary.dir, "binding.wal", &core, cap, 1001);
    try std.testing.expectEqual(@as(u64, 2), backing(reopened).issuer.metadata.epoch);
    try reopened.destroyQuiescent();
    try std.testing.expectError(error.AlreadyInitialized, Bindings.initialize(std.testing.allocator, std.testing.io, temporary.dir, "binding.wal", &core, cap, 1002));
}

test "local guest binding budget failure precedes issuer I/O" {
    if (comptime @import("builtin").os.tag != .linux and @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var identity = try @import("node_identity.zig").fromSeed(@splat(0x92), "binding-budget");
    defer identity.deinit();
    var core = Core.init(std.testing.allocator, .{ .host = "127.0.0.1", .port = 0, .node_identity = &identity, .crypto_io = std.testing.io }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer core.deinit();
    const cap: Limits = .{ .bindings = 1, .tickets = 1, .retained_bytes = 1 };
    try std.testing.expectError(error.BudgetExceeded, Bindings.initialize(std.testing.allocator, std.testing.io, temporary.dir, "no-write.wal", &core, cap, 1000));
    if (temporary.dir.openFile(std.testing.io, "no-write.wal", .{})) |file| {
        file.close(std.testing.io);
        return error.UnexpectedIssuerFile;
    } else |err| try std.testing.expectEqual(error.FileNotFound, err);
    // The owner, both capacity arrays, and path are funded before the issuer
    // opens its WAL. These four failures cover only pre-I/O funding, not all
    // issuer, durable-write, witness, retry or post-reservation failure cuts.
    const funded: Limits = .{ .bindings = 1, .tickets = 1, .retained_bytes = 128 * 1024 };
    for (0..4) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, Bindings.initialize(failing.allocator(), std.testing.io, temporary.dir, "no-write.wal", &core, funded, 1000));
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (temporary.dir.openFile(std.testing.io, "no-write.wal", .{})) |file| {
            file.close(std.testing.io);
            return error.UnexpectedIssuerFile;
        } else |err| try std.testing.expectEqual(error.FileNotFound, err);
    }
}

test "local guest hot capture preserves live ticket and inactive generations" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var identity = try @import("node_identity.zig").fromSeed(@splat(0xdd), "binding-test");
    defer identity.deinit();
    var core = Core.init(a, .{ .host = "127.0.0.1", .port = 0, .node_identity = &identity, .crypto_io = std.testing.io }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer core.deinit();
    const owner = try Bindings.initialize(a, std.testing.io, tmp.dir, "binding.wal", &core, .{ .bindings = 2, .tickets = 2, .retained_bytes = 128 * 1024 }, 1000);
    defer owner.destroyQuiescent() catch unreachable;
    const id: client.ClientId = .{ .shard = 0, .slot = 7, .gen = 1 };
    const first = try owner.begin(id);
    try owner.abandon(first);
    const second = try owner.begin(id);
    const limits: carry.Limits = .{ .rows = 2, .tickets = 2, .wire_bytes = 4096 };
    var capture = try owner.freezeForHotHandoff(limits);
    defer capture.deinit();
    try std.testing.expectError(error.HandoffFrozen, owner.abandon(second));
    var decoded = try carry.decodeOwned(a, capture.bytes, limits);
    defer decoded.deinit();
    try std.testing.expectEqual(second.generation, decoded.image.tickets[second.slot].generation);
    try std.testing.expectEqual(@as(?u64, @as(u64, @bitCast(id))), decoded.image.tickets[second.slot].physical);
    try std.testing.expectEqual(@as(usize, 2), decoded.image.tickets.len);
    _ = try capture.issuerImage();
    try capture.abort();
    try owner.abandon(second);
    try std.testing.expectError(error.StaleTicket, owner.abandon(first));
}

test "local guest hot staging rejects aliased physical owners before publication" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const Mapper = struct {
        fn map(_: *anyopaque, _: client.ClientId) !client.ClientId {
            return .{ .shard = 0, .slot = 42, .gen = 1 };
        }
    };
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var identity = try @import("node_identity.zig").fromSeed(@splat(0xde), "binding-test");
    defer identity.deinit();
    var core = Core.init(a, .{ .host = "127.0.0.1", .port = 0, .node_identity = &identity, .crypto_io = std.testing.io }) catch |err| switch (err) {
        error.Unsupported, error.PermissionDenied, error.SocketUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer core.deinit();
    const limits: Limits = .{ .bindings = 2, .tickets = 2, .retained_bytes = 128 * 1024 };
    const owner = try Bindings.initialize(a, std.testing.io, tmp.dir, "binding.wal", &core, limits, 1000);
    defer owner.destroyQuiescent() catch unreachable;
    const first = try owner.begin(.{ .shard = 0, .slot = 7, .gen = 1 });
    const second = try owner.begin(.{ .shard = 0, .slot = 8, .gen = 1 });
    const wire_limits: carry.Limits = .{ .rows = 2, .tickets = 2, .wire_bytes = 4096 };
    var capture = try owner.freezeForHotHandoff(wire_limits);
    defer capture.deinit();
    const issuer_image = try capture.issuerImage();
    const source = backing(owner);
    const duplicate: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.issuer.lease.handle), .flags = source.issuer.lease.flags };
    const descriptor = duplicate.handle;
    var ctx: u8 = 0;
    try std.testing.expectError(error.InvalidPhysicalMapping, Bindings.stageHotAdoption(a, std.testing.io, tmp.dir, "binding.wal", &core, limits, wire_limits, capture.bytes, issuer_image, duplicate, .{ .ctx = &ctx, .map_fn = Mapper.map }));
    try std.testing.expect(!@import("os_runtime.zig").fdValid(descriptor));
    try std.testing.expect(@import("os_runtime.zig").fdValid(source.issuer.lease.handle));
    try capture.abort();
    try owner.abandon(first);
    try owner.abandon(second);
}
