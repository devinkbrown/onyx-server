//! Unadvertised v3 admission owner. No transport, producer, recipient proof or Helix adapter.
//! Cut/source/record views are lexical borrows. Prepared IDs carry no pointers.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const presence = @import("../proto/mesh_presence_v3.zig");
const assembly = @import("../substrate/guest_membership_assembly.zig");
const world_module = @import("world.zig");
const World = world_module.World;

pub const Subject = assembly.Subject;
pub const Limits = struct {
    subjects: usize,
    prepared: usize,
    pending: usize,
    dependency_records: usize,
    roots: usize,
    retained_bytes: usize,
    peak_bytes: usize,
    work_per_operation: usize,
    signature_attempts: usize,
    clock: presence.ClockPolicy,
};
pub const Disposition = enum { inserted, updated, duplicate, obsolete };
pub const PreparedId = struct { incarnation: u64, sequence: u128, slot: usize };
pub const Dependency = struct {
    subject: Subject,
    claim_hlc: u64,
    claim_revision: u64,
    routing_class: presence.RoutingClass,
    class_revision: u64,
    membership_revision: u64,
    manifest_id: presence.ManifestID,
};
/// Both dependency obligations are unresolved. IDs alone prove no membership,
/// completed assembly, pinned body/chunks or actual World recipient cut.
pub const PendingView = struct {
    old_wire: []const u8,
    new_wire: []const u8,
    old_dependency: Dependency,
    new_dependency: Dependency,
};
pub const Usage = struct {
    fixed: usize,
    live_payload: usize,
    reserved_payload: usize,
    pending_count: usize,
    active_prepared: usize,
    generation: u64,
    security_revision: u64,
    policy_revision: u64,
    terminal: bool,
};
pub const Error = presence.Error || std.mem.Allocator.Error || error{
    InvalidLimits,
    InvalidClaim,
    Overflow,
    BudgetExceeded,
    Quarantined,
    BadIngress,
    Busy,
    StalePrepared,
    WrongCaller,
    BindingMismatch,
    GenerationExhausted,
    ExclusiveLockNotHeldByCaller,
    ExclusiveAcquisitionExhausted,
    ExclusiveAcquisitionChanged,
    InvalidExclusiveAcquisition,
    ExclusiveAcquisitionNotInterrupted,
};

var incarnation_counter: std.atomic.Value(u64) = .init(1);
fn nextIncarnation() Error!u64 {
    while (true) {
        const value = incarnation_counter.load(.monotonic);
        if (value == std.math.maxInt(u64)) return error.GenerationExhausted;
        if (incarnation_counter.cmpxchgWeak(value, value + 1, .monotonic, .monotonic) == null) return value;
    }
}
fn add(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.Overflow;
}
fn mul(a: usize, b: usize) Error!usize {
    return std.math.mul(usize, a, b) catch error.Overflow;
}
// Match mesh_presence_store.validateClaim's inclusive future-skew policy.
// ClockPolicy validates NOW first; checked subtraction also fails closed if
// a future caller violates that sequencing contract.
fn validateClaim(r: presence.Record, now: i64, future_skew: i64) Error!void {
    const claim_ms: i64 = @intCast(r.claim_hlc >> 16);
    if (claim_ms > now) {
        const distance = std.math.sub(i64, claim_ms, now) catch return error.InvalidClaim;
        if (distance > future_skew) return error.InvalidClaim;
    }
}
fn sameSubject(a: Subject, b: Subject) bool {
    return std.mem.eql(u8, &a.origin, &b.origin) and std.mem.eql(u8, &a.guest, &b.guest);
}
fn subject(r: presence.Record) Subject {
    return .{ .origin = r.origin, .guest = r.guest };
}
fn precedes(a: presence.Record, b: presence.Record) bool {
    const order = std.mem.order(u8, &a.origin, &b.origin);
    return order == .lt or (order == .eq and std.mem.order(u8, &a.guest, &b.guest) == .lt);
}
fn dependency(r: presence.Record) Dependency {
    return .{ .subject = subject(r), .claim_hlc = r.claim_hlc, .claim_revision = r.claim_revision, .routing_class = r.routing_class, .class_revision = r.class_revision, .membership_revision = r.membership_revision, .manifest_id = r.manifest_id };
}
fn bodyHash(wire: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(wire[0 .. wire.len - sign.signature_len], &result, .{});
    return result;
}
const Entry = struct {
    wire: []u8 = &.{},
    ingress: u64 = 0,
    quarantined: bool = false,
    witnesses: [2][32]u8 = @splat(@splat(0)),
};
const Pending = struct {
    old_wire: []u8,
    new_wire: []u8,
    old_dependency: Dependency,
    new_dependency: Dependency,
    fn deinit(self: *Pending, a: std.mem.Allocator) void {
        a.free(self.old_wire);
        a.free(self.new_wire);
    }
    fn view(self: *const Pending) PendingView {
        return .{ .old_wire = self.old_wire, .new_wire = self.new_wire, .old_dependency = self.old_dependency, .new_dependency = self.new_dependency };
    }
};
const Admission = struct {
    wire: []u8,
    index: usize,
    inserting: bool,
    disposition: Disposition,
    old_shadow: ?world_module.ClientId,
    new_shadow: ?world_module.ClientId,
    transition: ?Pending = null,
};
const Payload = union(enum) { noop: Disposition, admission: Admission, roots: []sign.PublicKey };
const Slot = struct {
    active: bool = false,
    failed: bool = false,
    sequence: u128 = 0,
    creator: std.Thread.Id = 0,
    acquisition: u64 = 0,
    ingress: u64 = 0,
    generation: u64 = 0,
    security_revision: u64 = 0,
    policy_revision: u64 = 0,
    credit: usize = 0,
    insertion_reserved: bool = false,
    pending_reserved: bool = false,
    payload: Payload = .{ .noop = .duplicate },
};
const Backing = struct {
    allocator: std.mem.Allocator,
    world: *World,
    local_origin: sign.PublicKey,
    limits: Limits,
    incarnation: u64,
    next_sequence: u128 = 1,
    generation: u64 = 1,
    security_revision: u64 = 1,
    policy_revision: u64 = 1,
    terminal: bool = false,
    entries: []Entry,
    entry_count: usize = 0,
    slots: []Slot,
    pending: []Pending,
    pending_count: usize = 0,
    roots: []sign.PublicKey,
    root_count: usize,
    fixed: usize,
    live_payload: usize = 0,
    reserved_payload: usize = 0,
    active_prepared: usize = 0,
    reserved_insertions: usize = 0,
    reserved_pending: usize = 0,
    active_cut: ?*CutBacking = null,

    fn rootsView(self: *const Backing) []const sign.PublicKey {
        return self.roots[0..self.root_count];
    }
    fn approved(self: *const Backing, origin: sign.PublicKey) bool {
        for (self.rootsView()) |root| if (std.mem.eql(u8, &root, &origin)) return true;
        return false;
    }
    fn find(self: *const Backing, key: Subject) ?usize {
        for (self.entries[0..self.entry_count], 0..) |entry, n| {
            const r = (presence.decode(entry.wire) catch unreachable).record;
            if (sameSubject(subject(r), key)) return n;
        }
        return null;
    }
    /// O(1) conservative preflight precedes signature attempts, owner/slot scans
    /// and actual World nick lookups. Fixed capacities include allocator capacity.
    fn work(self: *const Backing, input: usize, signatures: usize) Error!void {
        if (signatures > self.limits.signature_attempts) return error.BudgetExceeded;
        const per_entry = try add(try mul(presence.max_wire_len, 8), try mul(self.root_count, 32 * 8));
        var total = try add(input, try mul(self.entry_count, per_entry));
        total = try add(total, try mul(self.slots.len, @sizeOf(Slot)));
        total = try add(total, try mul(self.world.nicks.count(), 4 * 256));
        total = try add(total, try mul(self.root_count, 32));
        if (total > self.limits.work_per_operation) return error.BudgetExceeded;
    }
    fn normalReady(self: *const Backing) Error!void {
        if (self.terminal or self.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
    }
    fn eligible(self: *const Backing, r: presence.Record, now: i64) bool {
        if (self.terminal or r.operation != .present or r.routing_class != .true_guest or
            std.mem.eql(u8, &r.origin, &self.local_origin) or !self.approved(r.origin)) return false;
        self.limits.clock.validate(r, now) catch return false;
        validateClaim(r, now, self.limits.clock.max_future_skew_ms) catch return false;
        return true;
    }
    fn visible(self: *Backing, r: presence.Record, replacement: ?usize, now: i64) bool {
        if (!self.eligible(r, now) or self.world.findNick(r.nick) != null) return false;
        for (self.entries[0..self.entry_count], 0..) |entry, n| {
            if (replacement != null and replacement.? == n) continue;
            if (entry.quarantined) continue;
            const other = (presence.decode(entry.wire) catch unreachable).record;
            if (!self.eligible(other, now) or !std.ascii.eqlIgnoreCase(other.nick, r.nick)) continue;
            if (precedes(other, r)) return false;
        }
        return true;
    }
    fn needsTransition(self: *Backing, index: usize, next: presence.Record, now: i64) bool {
        const entry = self.entries[index];
        if (entry.quarantined) return false;
        const old = (presence.decode(entry.wire) catch unreachable).record;
        return std.mem.eql(u8, old.nick, next.nick) and
            (!std.mem.eql(u8, old.username, next.username) or !std.mem.eql(u8, old.host, next.host)) and
            self.visible(old, index, now) and self.visible(next, index, now);
    }
    fn current(self: *Backing, key: Subject, now: i64) ?assembly.CurrentPresence {
        self.work(0, 0) catch return null;
        const index = self.find(key) orelse return null;
        const entry = self.entries[index];
        if (entry.quarantined) return null;
        const r = (presence.decode(entry.wire) catch unreachable).record;
        if (!self.visible(r, index, now)) return null;
        return .{ .wire = entry.wire, .generation = self.generation };
    }
    /// Original admission pre-funds inline witnesses. No allocator or ordinary
    /// generation/slot budget can prevent this negative authority cut.
    fn quarantine(self: *Backing, index: usize, incoming: []const u8) void {
        const entry = &self.entries[index];
        var hashes: [3][32]u8 = .{ if (entry.quarantined) entry.witnesses[0] else bodyHash(entry.wire), if (entry.quarantined) entry.witnesses[1] else bodyHash(entry.wire), bodyHash(incoming) };
        for (0..hashes.len) |a| for (a + 1..hashes.len) |b| {
            if (std.mem.order(u8, &hashes[a], &hashes[b]) == .gt) std.mem.swap([32]u8, &hashes[a], &hashes[b]);
        };
        var second = hashes[0];
        for (hashes[1..]) |hash| if (!std.mem.eql(u8, &hash, &hashes[0])) {
            second = hash;
            break;
        };
        const changed = !entry.quarantined or !std.mem.eql(u8, &entry.witnesses[0], &hashes[0]) or
            !std.mem.eql(u8, &entry.witnesses[1], &second);
        entry.quarantined = true;
        entry.witnesses = .{ hashes[0], second };
        if (changed) {
            if (self.security_revision == std.math.maxInt(u64)) self.terminal = true else self.security_revision += 1;
        }
    }
    fn reserve(self: *Backing, credit: usize, inserting: bool, transitioning: bool) Error!usize {
        try self.normalReady();
        if (self.next_sequence == std.math.maxInt(u128)) return error.GenerationExhausted;
        if (self.active_prepared >= self.slots.len) return error.BudgetExceeded;
        if (inserting and try add(self.entry_count, self.reserved_insertions) >= self.entries.len) return error.BudgetExceeded;
        if (transitioning) {
            const count = try add(self.pending_count, self.reserved_pending);
            if (count >= self.pending.len or try mul(try add(count, 1), 2) > self.limits.dependency_records) return error.BudgetExceeded;
        }
        const retained = try add(try add(self.fixed, self.live_payload), credit);
        const peak = try add(retained, self.reserved_payload);
        if (retained > self.limits.retained_bytes or peak > self.limits.peak_bytes) return error.BudgetExceeded;
        for (self.slots, 0..) |*slot, n| if (!slot.active) {
            slot.* = .{ .active = true, .sequence = self.next_sequence, .credit = credit, .insertion_reserved = inserting, .pending_reserved = transitioning };
            self.next_sequence += 1;
            self.active_prepared += 1;
            self.reserved_payload += credit;
            self.reserved_insertions += @intFromBool(inserting);
            self.reserved_pending += @intFromBool(transitioning);
            return n;
        };
        unreachable;
    }
    fn release(self: *Backing, slot: *Slot) void {
        switch (slot.payload) {
            .noop => {},
            .roots => |keys| self.allocator.free(keys),
            .admission => |*a| {
                self.allocator.free(a.wire);
                if (a.transition) |*transition| transition.deinit(self.allocator);
            },
        }
        self.reserved_payload -= slot.credit;
        self.active_prepared -= 1;
        self.reserved_insertions -= @intFromBool(slot.insertion_reserved);
        self.reserved_pending -= @intFromBool(slot.pending_reserved);
        slot.* = .{};
    }
};
fn backing(owner: *Owner) *Backing {
    return @ptrCast(@alignCast(owner));
}
const CutBacking = struct {
    owner: *Backing,
    creator: std.Thread.Id,
    acquisition: u64,
    active: bool = true,
    fn ready(self: *CutBacking) Error!void {
        if (self.creator != std.Thread.getCurrentId()) return error.WrongCaller;
        if (!self.active or self.owner.active_cut != self) return error.StalePrepared;
        try self.owner.world.lock.requireExclusiveAcquisitionByCurrentThread(self.acquisition);
    }
    fn slot(self: *CutBacking, id: PreparedId) Error!*Slot {
        try self.ready();
        const o = self.owner;
        if (id.incarnation != o.incarnation or id.slot >= o.slots.len) return error.StalePrepared;
        const result = &o.slots[id.slot];
        if (!result.active or result.sequence != id.sequence) return error.StalePrepared;
        if (result.creator != self.creator) return error.WrongCaller;
        if (result.acquisition != self.acquisition) return error.ExclusiveAcquisitionChanged;
        return result;
    }
    fn stampSlot(self: *CutBacking, index: usize) PreparedId {
        const o = self.owner;
        const s = &o.slots[index];
        s.creator = self.creator;
        s.acquisition = self.acquisition;
        s.generation = o.generation;
        s.security_revision = o.security_revision;
        s.policy_revision = o.policy_revision;
        return .{ .incarnation = o.incarnation, .sequence = s.sequence, .slot = index };
    }
};
fn cutBacking(cut: *Cut) *CutBacking {
    return @ptrCast(@alignCast(cut));
}

pub const Owner = opaque {
    pub fn create(a: std.mem.Allocator, world: *World, local_origin: sign.PublicKey, roots: []const sign.PublicKey, limits: Limits) Error!*Owner {
        if (limits.subjects == 0 or limits.prepared == 0 or roots.len > limits.roots or
            limits.clock.max_lifetime_ms <= 0 or limits.clock.max_future_skew_ms < 0) return error.InvalidLimits;
        var fixed = try add(@sizeOf(Backing), try mul(limits.subjects, @sizeOf(Entry)));
        fixed = try add(fixed, try mul(limits.prepared, @sizeOf(Slot)));
        fixed = try add(fixed, try mul(limits.pending, @sizeOf(Pending)));
        fixed = try add(fixed, try mul(limits.roots, @sizeOf(sign.PublicKey)));
        if (fixed > limits.retained_bytes or fixed > limits.peak_bytes or
            try mul(try mul(roots.len, roots.len), 32) > limits.work_per_operation) return error.BudgetExceeded;
        for (roots, 0..) |key, n| for (roots[0..n]) |prior| {
            if (std.mem.eql(u8, &key, &prior)) return error.InvalidLimits;
        };
        const incarnation = try nextIncarnation();
        const self = try a.create(Backing);
        errdefer a.destroy(self);
        const entries = try a.alloc(Entry, limits.subjects);
        errdefer a.free(entries);
        const slots = try a.alloc(Slot, limits.prepared);
        errdefer a.free(slots);
        const pending = try a.alloc(Pending, limits.pending);
        errdefer a.free(pending);
        const policy = try a.alloc(sign.PublicKey, limits.roots);
        @memset(entries, .{});
        @memset(slots, .{});
        @memcpy(policy[0..roots.len], roots);
        self.* = .{ .allocator = a, .world = world, .local_origin = local_origin, .limits = limits, .incarnation = incarnation, .entries = entries, .slots = slots, .pending = pending, .roots = policy, .root_count = roots.len, .fixed = fixed };
        return @ptrCast(self);
    }
    /// No acquiring/reentrant lock: caller retains this exact actual World write
    /// acquisition. Cut/source pointers and all borrowed views MUST NOT escape.
    pub fn withCut(self: *Owner, context: anytype, comptime callback: anytype) anyerror!void {
        const o = backing(self);
        const acquisition = try o.world.lock.captureExclusiveAcquisitionForCurrentThread();
        if (o.active_cut != null) return error.Busy;
        var cut: CutBacking = .{ .owner = o, .creator = std.Thread.getCurrentId(), .acquisition = acquisition };
        o.active_cut = &cut;
        defer {
            cut.active = false;
            o.active_cut = null;
        }
        try callback(context, @as(*Cut, @ptrCast(&cut)));
    }
    /// Explicit cold cleanup of UNPUBLISHED plans only. A real later acquisition
    /// and original creator prove interruption; accepted entries/FIFO survive.
    pub fn reclaimInterrupted(self: *Owner) Error!void {
        const o = backing(self);
        try o.world.lock.requireExclusiveHeldByCurrentThread();
        if (o.active_cut != null) return error.Busy;
        for (o.slots) |slot| if (slot.active) {
            if (slot.creator != std.Thread.getCurrentId()) return error.WrongCaller;
            try o.world.lock.requireExclusiveAcquisitionInterruptedByCurrentThread(slot.acquisition);
        };
        for (o.slots) |*slot| if (slot.active) o.release(slot);
    }
    /// Final owner lifetime teardown, never an effect settlement/ACK. Caller
    /// proves all lexical borrowers and dependent assembler handles are gone;
    /// no prepared aliases retain custody. No assembler is attached by this leaf.
    pub fn destroyQuiescent(self: *Owner) Error!void {
        const o = backing(self);
        try o.world.lock.requireExclusiveHeldByCurrentThread();
        if (o.active_cut != null or o.active_prepared != 0) return error.Busy;
        const a = o.allocator;
        for (o.entries[0..o.entry_count]) |entry| a.free(entry.wire);
        for (o.pending[0..o.pending_count]) |*pending| pending.deinit(a);
        a.free(o.entries);
        a.free(o.slots);
        a.free(o.pending);
        a.free(o.roots);
        a.destroy(o);
    }
};

pub const Cut = opaque {
    pub fn prepareInbound(self: *Cut, original: []const u8, ingress: u64, now: i64) Error!PreparedId {
        const cut = cutBacking(self);
        try cut.ready();
        const o = cut.owner;
        if (ingress == 0) return error.BadIngress;
        try o.work(original.len, 1);
        const decoded = try presence.decode(original);
        try decoded.verify(o.rootsView());
        const r = decoded.record;
        const found = o.find(subject(r));
        var disposition: Disposition = .inserted;
        if (found) |index| {
            const entry = &o.entries[index];
            if (entry.quarantined) {
                o.quarantine(index, original);
                return error.Quarantined;
            }
            const old = try presence.decode(entry.wire);
            switch (try presence.comparePresence(old, decoded)) {
                .quarantined => {
                    o.quarantine(index, original);
                    return error.Quarantined;
                },
                .duplicate => disposition = .duplicate,
                .obsolete => disposition = .obsolete,
                .updated => disposition = .updated,
            }
        }
        // Signature-authenticated contradictions revoke even when incoming time
        // is invalid; normal publication still requires strict current clock.
        try o.limits.clock.validate(r, now);
        try validateClaim(r, now, o.limits.clock.max_future_skew_ms);
        try o.normalReady();
        if (disposition == .duplicate or disposition == .obsolete) {
            const n = try o.reserve(0, false, false);
            o.slots[n].payload = .{ .noop = disposition };
            return cut.stampSlot(n);
        }
        const transitioning = if (found) |index| o.needsTransition(index, r, now) else false;
        var credit = original.len;
        if (transitioning) credit = try add(credit, try add(o.entries[found.?].wire.len, original.len));
        const n = try o.reserve(credit, found == null, transitioning);
        errdefer o.release(&o.slots[n]);
        const wire = try o.allocator.dupe(u8, original);
        o.slots[n].payload = .{ .admission = .{ .wire = wire, .index = found orelse o.entry_count, .inserting = found == null, .disposition = disposition, .old_shadow = null, .new_shadow = o.world.findNick(r.nick) } };
        const admission = &o.slots[n].payload.admission;
        if (found) |index| {
            const old = (try presence.decode(o.entries[index].wire)).record;
            admission.old_shadow = o.world.findNick(old.nick);
            if (transitioning) {
                const before = try o.allocator.dupe(u8, o.entries[index].wire);
                errdefer o.allocator.free(before);
                const after = try o.allocator.dupe(u8, original);
                admission.transition = .{ .old_wire = before, .new_wire = after, .old_dependency = dependency(old), .new_dependency = dependency(r) };
            }
        }
        // Ingress is provenance, never origin approval. It becomes entry state
        // only at commit; slots retain the exact proposed ingress separately.
        o.slots[n].ingress = ingress;
        return cut.stampSlot(n);
    }
    pub fn prepareRoots(self: *Cut, roots: []const sign.PublicKey) Error!PreparedId {
        const cut = cutBacking(self);
        try cut.ready();
        const o = cut.owner;
        if (roots.len > o.roots.len) return error.BudgetExceeded;
        try o.work(try mul(try mul(roots.len, roots.len), 32), 0);
        try o.normalReady();
        if (o.policy_revision == std.math.maxInt(u64)) return error.GenerationExhausted;
        for (roots, 0..) |key, n| for (roots[0..n]) |prior| {
            if (std.mem.eql(u8, &key, &prior)) return error.InvalidLimits;
        };
        const n = try o.reserve(try mul(roots.len, @sizeOf(sign.PublicKey)), false, false);
        errdefer o.release(&o.slots[n]);
        o.slots[n].payload = .{ .roots = try o.allocator.dupe(sign.PublicKey, roots) };
        return cut.stampSlot(n);
    }
    pub fn validate(self: *Cut, id: PreparedId, now: i64) Error!void {
        const cut = cutBacking(self);
        const slot = try cut.slot(id);
        const o = cut.owner;
        if (slot.failed or o.terminal or slot.generation != o.generation or
            slot.security_revision != o.security_revision or slot.policy_revision != o.policy_revision) return error.StalePrepared;
        try o.normalReady();
        try o.work(0, 0);
        switch (slot.payload) {
            .noop => {},
            .roots => if (o.policy_revision == std.math.maxInt(u64)) return error.GenerationExhausted,
            .admission => |admission| {
                const next = (try presence.decode(admission.wire)).record;
                try o.limits.clock.validate(next, now);
                try validateClaim(next, now, o.limits.clock.max_future_skew_ms);
                if (!o.approved(next.origin) or !std.meta.eql(admission.new_shadow, o.world.findNick(next.nick))) return error.BindingMismatch;
                if (!admission.inserting) {
                    const old = (try presence.decode(o.entries[admission.index].wire)).record;
                    if (!std.meta.eql(admission.old_shadow, o.world.findNick(old.nick)) or
                        (admission.transition != null) != o.needsTransition(admission.index, next, now)) return error.BindingMismatch;
                }
            },
        }
    }
    /// Validation may fail, but accepted publication is a single allocation-free
    /// cut. A failed attempt remains abortable; its credit is not prematurely refunded.
    pub fn commit(self: *Cut, id: PreparedId, now: i64) Error!Disposition {
        const cut = cutBacking(self);
        const slot = try cut.slot(id);
        const o = cut.owner;
        self.validate(id, now) catch |err| {
            slot.failed = true;
            return err;
        };
        var result: Disposition = .updated;
        switch (slot.payload) {
            .noop => |disposition| result = disposition,
            .roots => |keys| {
                @memcpy(o.roots[0..keys.len], keys);
                o.root_count = keys.len;
                o.policy_revision += 1;
                o.generation += 1;
            },
            .admission => |admission| {
                const old: []u8 = if (admission.inserting) &.{} else o.entries[admission.index].wire;
                o.entries[admission.index] = .{ .wire = admission.wire, .ingress = slot.ingress };
                if (admission.inserting) o.entry_count += 1;
                if (admission.transition) |transition| {
                    o.pending[o.pending_count] = transition;
                    o.pending_count += 1;
                }
                // Move funded storage before releasing the replaced original.
                o.reserved_payload -= slot.credit;
                o.live_payload += slot.credit;
                slot.credit = 0;
                o.allocator.free(old);
                o.live_payload -= old.len;
                result = admission.disposition;
                slot.payload = .{ .noop = .duplicate };
                o.generation += 1;
            },
        }
        o.release(slot);
        return result;
    }
    pub fn abort(self: *Cut, id: PreparedId) Error!void {
        const cut = cutBacking(self);
        const slot = try cut.slot(id);
        cut.owner.release(slot);
    }
    pub fn retainedWire(self: *Cut, key: Subject) Error!?[]const u8 {
        const cut = cutBacking(self);
        try cut.ready();
        try cut.owner.work(0, 0);
        const index = cut.owner.find(key) orelse return null;
        return cut.owner.entries[index].wire;
    }
    pub fn pendingCount(self: *Cut) Error!usize {
        const cut = cutBacking(self);
        try cut.ready();
        return cut.owner.pending_count;
    }
    pub fn pendingAt(self: *Cut, index: usize) Error!?PendingView {
        const cut = cutBacking(self);
        try cut.ready();
        if (index >= cut.owner.pending_count) return null;
        return cut.owner.pending[index].view();
    }
    pub fn usage(self: *Cut) Error!Usage {
        const cut = cutBacking(self);
        try cut.ready();
        const o = cut.owner;
        return .{ .fixed = o.fixed, .live_payload = o.live_payload, .reserved_payload = o.reserved_payload, .pending_count = o.pending_count, .active_prepared = o.active_prepared, .generation = o.generation, .security_revision = o.security_revision, .policy_revision = o.policy_revision, .terminal = o.terminal };
    }
    /// The callback MUST NOT retain the source/context in assembler state,
    /// Prepared IDs, another callback, or external storage. No source is returned.
    pub fn withCurrentSource(self: *Cut, context: anytype, comptime callback: anytype) anyerror!void {
        const cut = cutBacking(self);
        try cut.ready();
        try callback(context, assembly.CurrentPresenceSource{ .context = cut, .read_fn = readCurrent });
    }
};
fn readCurrent(context: *anyopaque, key: Subject, now: i64) ?assembly.CurrentPresence {
    const cut: *CutBacking = @ptrCast(@alignCast(context));
    cut.ready() catch return null;
    return cut.owner.current(key, now);
}

fn testLimits() Limits {
    return .{ .subjects = 8, .prepared = 4, .pending = 8, .dependency_records = 16, .roots = 4, .retained_bytes = 4 * 1024 * 1024, .peak_bytes = 8 * 1024 * 1024, .work_per_operation = 16 * 1024 * 1024, .signature_attempts = 1, .clock = .{ .max_lifetime_ms = 120_000, .max_future_skew_ms = 30_000 } };
}
fn testRecord(key: *const sign.KeyPair) presence.Record {
    return .{ .origin = key.public_key, .guest = presence.guestId(.{ .epoch = 4, .counter = 7 }) catch unreachable, .operation = .present, .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 50, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 5000, .nick = "Guest", .username = "public-user", .host = "a.public", .realname = "Guest identity", .server = "origin.example", .description = "Origin", .membership_revision = 1, .manifest_id = @splat(1) };
}
fn acceptForTest(cut: *Cut, wire: []const u8) !Disposition {
    const id = try cut.prepareInbound(wire, 9, 1000);
    errdefer cut.abort(id) catch {};
    return cut.commit(id, 1000);
}
fn currentForTest(cut: *Cut, key: Subject, now: i64) !?assembly.CurrentPresence {
    const Probe = struct {
        key: Subject,
        now: i64,
        result: ?assembly.CurrentPresence = null,
        fn run(self: *@This(), source: assembly.CurrentPresenceSource) !void {
            self.result = source.read_fn(source.context, self.key, self.now);
        }
    };
    var probe = Probe{ .key = key, .now = now };
    try cut.withCurrentSource(&probe, Probe.run);
    return probe.result;
}
const PeakAllocator = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    allocations: usize = 0,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const result = self.child.rawAlloc(len, alignment, ra) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        self.allocations += 1;
        return result;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.live -= bytes.len;
        self.child.rawFree(bytes, alignment, ra);
    }
};
fn exactUsageForTest(cut: *Cut, tracker: *PeakAllocator) !Usage {
    const usage = try cut.usage();
    try std.testing.expectEqual(usage.fixed + usage.live_payload + usage.reserved_payload, tracker.live);
    try std.testing.expect(tracker.peak <= cutBacking(cut).owner.limits.peak_bytes);
    return usage;
}

test "guest owner authenticated current source rechecks real local World roots subject class lease and quit" {
    var key = try sign.KeyPair.fromSeed(@splat(61));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var buffer: [presence.max_wire_len]u8 = undefined;
    const r = testRecord(&key);
    const wire = try presence.encode(r, &key, &buffer);
    const Context = struct {
        world: *World,
        key: *const sign.KeyPair,
        wire: []const u8,
        fn run(self: *@This(), cut: *Cut) !void {
            const r1 = (try presence.decode(self.wire)).record;
            try std.testing.expectEqual(Disposition.inserted, try acceptForTest(cut, self.wire));
            const current = (try currentForTest(cut, subject(r1), 1000)).?;
            try std.testing.expectEqualSlices(u8, self.wire, current.wire);
            try std.testing.expect(current.generation != 0);
            var wrong = subject(r1);
            wrong.guest[15] +%= 1;
            try std.testing.expect((try currentForTest(cut, wrong, 1000)) == null);
            try std.testing.expect((try currentForTest(cut, subject(r1), 5000)) == null);
            const local_id: world_module.ClientId = .{ .shard = 0, .slot = 3, .gen = 4 };
            try self.world.registerNick("gUeSt", local_id);
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) == null);
            self.world.unregisterNick(local_id);
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) != null);
            const roots = try cut.prepareRoots(&.{});
            _ = try cut.commit(roots, 1000);
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) == null);
            const restore = try cut.prepareRoots(&.{self.key.public_key});
            _ = try cut.commit(restore, 1000);
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) != null);
            var other = r1;
            other.guest[15] += 1;
            other.routing_class = .authenticated_untracked;
            var obuf: [presence.max_wire_len]u8 = undefined;
            _ = try acceptForTest(cut, try presence.encode(other, self.key, &obuf));
            try std.testing.expect((try currentForTest(cut, subject(other), 1000)) == null);
            var quit = r1;
            quit.operation = .quit;
            quit.revision = 2;
            var qbuf: [presence.max_wire_len]u8 = undefined;
            _ = try acceptForTest(cut, try presence.encode(quit, self.key, &qbuf));
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) == null);
            try std.testing.expectEqual(Disposition.obsolete, try acceptForTest(cut, self.wire));
            try std.testing.expect((try currentForTest(cut, subject(r1), 1000)) == null);
        }
    };
    var context = Context{ .world = &world, .key = &key, .wire = wire };
    try owner.withCut(&context, Context.run);
    const local_owner = try Owner.create(std.testing.allocator, &world, key.public_key, &.{key.public_key}, testLimits());
    defer local_owner.destroyQuiescent() catch @panic("local owner teardown");
    const Local = struct {
        wire: []const u8,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.wire);
            try std.testing.expect((try currentForTest(cut, subject((try presence.decode(self.wire)).record), 1000)) == null);
        }
    };
    try local_owner.withCut(Local{ .wire = wire }, Local.run);
}

test "guest owner FIFO preserves both signed A B C transitions and refuses unfunded publication" {
    var key = try sign.KeyPair.fromSeed(@splat(62));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    var buffers: [3][presence.max_wire_len]u8 = undefined;
    var wires: [3][]const u8 = undefined;
    var record = testRecord(&key);
    for (&wires, 0..) |*wire, n| {
        record.revision = n + 1;
        record.membership_revision = n + 1;
        record.manifest_id = @splat(@as(u8, @intCast(n + 1)));
        record.host = ([_][]const u8{ "a.public", "b.public", "c.public" })[n];
        wire.* = try presence.encode(record, &key, &buffers[n]);
    }
    const Context = struct {
        wires: [3][]const u8,
        saturate: bool,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.wires[0]);
            _ = try acceptForTest(cut, self.wires[1]);
            if (self.saturate) {
                const before = try cut.usage();
                try std.testing.expectError(error.BudgetExceeded, cut.prepareInbound(self.wires[2], 9, 1000));
                try std.testing.expectEqualDeep(before, try cut.usage());
                try std.testing.expectEqualSlices(u8, self.wires[1], (try cut.retainedWire(subject((try presence.decode(self.wires[0])).record))).?);
            } else _ = try acceptForTest(cut, self.wires[2]);
            try std.testing.expectEqual(@as(usize, if (self.saturate) 1 else 2), try cut.pendingCount());
            const first = (try cut.pendingAt(0)).?;
            try std.testing.expectEqualSlices(u8, self.wires[0], first.old_wire);
            try std.testing.expectEqualSlices(u8, self.wires[1], first.new_wire);
            try std.testing.expectEqualDeep(dependency((try presence.decode(self.wires[0])).record), first.old_dependency);
            try std.testing.expectEqualDeep(dependency((try presence.decode(self.wires[1])).record), first.new_dependency);
            if (!self.saturate) {
                const second = (try cut.pendingAt(1)).?;
                try std.testing.expectEqualSlices(u8, self.wires[1], second.old_wire);
                try std.testing.expectEqualSlices(u8, self.wires[2], second.new_wire);
                try std.testing.expectEqualDeep(dependency((try presence.decode(self.wires[2])).record), second.new_dependency);
            }
            const policy = try cut.prepareRoots(&.{});
            _ = try cut.commit(policy, 1000);
            try std.testing.expectEqualSlices(u8, self.wires[0], (try cut.pendingAt(0)).?.old_wire);
        }
    };
    for ([_]bool{ false, true }) |saturate| {
        var limits = testLimits();
        if (saturate) {
            limits.pending = 1;
            limits.dependency_records = 2;
        }
        const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, limits);
        defer owner.destroyQuiescent() catch @panic("owner teardown");
        try owner.withCut(Context{ .wires = wires, .saturate = saturate }, Context.run);
    }
}

test "guest owner active IDs exact peak stale credit slot reuse and verified conflict need no allocation" {
    var key = try sign.KeyPair.fromSeed(@splat(63));
    defer key.deinit();
    var tracker = PeakAllocator{ .child = std.testing.allocator };
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(tracker.allocator(), &world, @splat(250), &.{key.public_key}, testLimits());
    defer {
        owner.destroyQuiescent() catch @panic("owner teardown");
        std.debug.assert(tracker.live == 0);
    }
    var buffers: [4][presence.max_wire_len]u8 = undefined;
    var wires: [4][]const u8 = undefined;
    var record = testRecord(&key);
    for (0..3) |n| {
        record.revision = n + 1;
        record.host = ([_][]const u8{ "a.public", "b.public", "c.public" })[n];
        wires[n] = try presence.encode(record, &key, &buffers[n]);
    }
    record.revision = 3;
    record.host = "equivocal.public";
    wires[3] = try presence.encode(record, &key, &buffers[3]);
    const Context = struct {
        wires: [4][]const u8,
        tracker: *PeakAllocator,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.wires[0]);
            _ = try exactUsageForTest(cut, self.tracker);
            const p = try cut.prepareInbound(self.wires[1], 9, 1000);
            const q = try cut.prepareInbound(self.wires[2], 9, 1000);
            const both = try exactUsageForTest(cut, self.tracker);
            try std.testing.expectEqual(@as(usize, 2), both.active_prepared);
            _ = try cut.commit(p, 1000);
            const after_p = try exactUsageForTest(cut, self.tracker);
            try std.testing.expect(after_p.reserved_payload > 0);
            try std.testing.expectError(error.StalePrepared, cut.commit(q, 1000));
            try std.testing.expectEqual(after_p.reserved_payload, (try cut.usage()).reserved_payload);
            try cut.abort(q);
            _ = try exactUsageForTest(cut, self.tracker);
            try std.testing.expectError(error.StalePrepared, cut.abort(q));
            const retry = try cut.prepareInbound(self.wires[2], 9, 1000);
            try std.testing.expect(retry.sequence != p.sequence);
            try std.testing.expectError(error.StalePrepared, cut.commit(p, 1000));
            _ = try cut.commit(retry, 1000);
            _ = try exactUsageForTest(cut, self.tracker);
            const held = try cut.prepareRoots(&.{});
            const before = try cut.usage();
            const allocations = self.tracker.allocations;
            const o = cutBacking(cut).owner;
            var failing = std.testing.FailingAllocator.init(o.allocator, .{ .fail_index = 0 });
            const original_allocator = o.allocator;
            o.allocator = failing.allocator();
            defer o.allocator = original_allocator;
            try std.testing.expectError(error.Quarantined, cut.prepareInbound(self.wires[3], 9, 1000));
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(allocations, self.tracker.allocations);
            try std.testing.expect((try currentForTest(cut, subject((try presence.decode(self.wires[2])).record), 1000)) == null);
            try std.testing.expectError(error.StalePrepared, cut.commit(held, 1000));
            try std.testing.expectEqual(before.reserved_payload, (try cut.usage()).reserved_payload);
            try cut.abort(held);
            try std.testing.expectEqual(@as(usize, 2), try cut.pendingCount());
            _ = try exactUsageForTest(cut, self.tracker);
        }
    };
    try owner.withCut(Context{ .wires = wires, .tracker = &tracker }, Context.run);
}

test "guest owner every staged update and policy OOM preserves custody and same-owner retry" {
    var key = try sign.KeyPair.fromSeed(@splat(64));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    const first = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.public";
    const second = try presence.encode(r, &key, &b_buf);
    r.revision = 3;
    r.host = "c.public";
    const third = try presence.encode(r, &key, &c_buf);
    const Context = struct {
        first: []const u8,
        second: []const u8,
        third: []const u8,
        root: sign.PublicKey,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.first);
            _ = try acceptForTest(cut, self.second);
            const o = cutBacking(cut).owner;
            const allocator = o.allocator;
            const baseline = try cut.usage();
            var census = std.testing.FailingAllocator.init(allocator, .{});
            o.allocator = census.allocator();
            {
                defer o.allocator = allocator;
                const id = try cut.prepareInbound(self.third, 9, 1000);
                try cut.abort(id);
            }
            try std.testing.expectEqual(@as(usize, 3), census.allocations);
            try std.testing.expectEqual(census.allocations, census.deallocations);
            for (0..census.allocations) |index| {
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
                o.allocator = failing.allocator();
                {
                    defer o.allocator = allocator;
                    try std.testing.expectError(error.OutOfMemory, cut.prepareInbound(self.third, 9, 1000));
                    try std.testing.expectEqualDeep(baseline, try cut.usage());
                    try std.testing.expectEqualSlices(u8, self.second, (try cut.retainedWire(subject((try presence.decode(self.first)).record))).?);
                    try std.testing.expectEqualSlices(u8, self.first, (try cut.pendingAt(0)).?.old_wire);
                    try std.testing.expectEqual(failing.allocations, failing.deallocations);
                    failing.fail_index = std.math.maxInt(usize);
                    const retry = try cut.prepareInbound(self.third, 9, 1000);
                    try cut.abort(retry);
                    try std.testing.expectEqual(failing.allocations, failing.deallocations);
                }
            }
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            o.allocator = failing.allocator();
            {
                defer o.allocator = allocator;
                try std.testing.expectError(error.OutOfMemory, cut.prepareRoots(&.{ self.root, @splat(201) }));
                try std.testing.expectEqualDeep(baseline, try cut.usage());
                failing.fail_index = std.math.maxInt(usize);
                const retry = try cut.prepareRoots(&.{ self.root, @splat(201) });
                try cut.abort(retry);
                try std.testing.expectEqual(failing.allocations, failing.deallocations);
            }
            _ = try acceptForTest(cut, self.third);
            try std.testing.expectEqual(@as(usize, 2), try cut.pendingCount());
            try std.testing.expectEqualSlices(u8, self.first, (try cut.pendingAt(0)).?.old_wire);
        }
    };
    try owner.withCut(Context{ .first = first, .second = second, .third = third, .root = key.public_key }, Context.run);
}

fn emptyCutForTest(_: void, _: *Cut) !void {}
test "guest owner real foreign shared unlocked and foreign-thread World access refuses" {
    var key = try sign.KeyPair.fromSeed(@splat(65));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    var foreign = World.init(std.testing.allocator);
    defer foreign.deinit();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer {
        world.lockWrite();
        owner.destroyQuiescent() catch @panic("owner teardown");
        world.unlockWrite();
    }
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, owner.withCut({}, emptyCutForTest));
    world.lock.lockShared();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, owner.withCut({}, emptyCutForTest));
    world.lock.unlockShared();
    foreign.lockWrite();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, owner.withCut({}, emptyCutForTest));
    foreign.unlockWrite();
    world.lockWrite();
    defer world.unlockWrite();
    const ThreadProbe = struct {
        owner: *Owner,
        observed: ?anyerror = null,
        fn run(self: *@This()) void {
            self.owner.withCut({}, emptyCutForTest) catch |err| {
                self.observed = err;
            };
        }
    };
    var thread_probe = ThreadProbe{ .owner = owner };
    const thread = try std.Thread.spawn(.{}, ThreadProbe.run, .{&thread_probe});
    thread.join();
    try std.testing.expect(thread_probe.observed.? == error.ExclusiveLockNotHeldByCaller);
    try owner.withCut({}, emptyCutForTest);
}

test "guest owner same acquisition actual nick mutation refuses before publish and keeps failed-plan credit" {
    var key = try sign.KeyPair.fromSeed(@splat(66));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var abuf: [presence.max_wire_len]u8 = undefined;
    var bbuf: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    const a = try presence.encode(r, &key, &abuf);
    r.revision = 2;
    r.host = "b.public";
    const b = try presence.encode(r, &key, &bbuf);
    const Context = struct {
        world: *World,
        a: []const u8,
        b: []const u8,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.a);
            const id = try cut.prepareInbound(self.b, 9, 1000);
            const before = try cut.usage();
            const local_id: world_module.ClientId = .{ .shard = 0, .slot = 12, .gen = 4 };
            try self.world.registerNick("Guest", local_id);
            _ = try self.world.join("#actual-local", local_id);
            try std.testing.expectError(error.BindingMismatch, cut.commit(id, 1000));
            try std.testing.expectEqual(before.reserved_payload, (try cut.usage()).reserved_payload);
            try std.testing.expectEqual(@as(usize, 0), try cut.pendingCount());
            try std.testing.expectEqualSlices(u8, self.a, (try cut.retainedWire(subject((try presence.decode(self.a)).record))).?);
            self.world.unregisterNick(local_id);
            try self.world.part("#actual-local", local_id);
            try std.testing.expectError(error.StalePrepared, cut.commit(id, 1000));
            try cut.abort(id);
            _ = try acceptForTest(cut, self.b);
            try std.testing.expectEqual(@as(usize, 1), try cut.pendingCount());
        }
    };
    try owner.withCut(Context{ .world = &world, .a = a, .b = b }, Context.run);
}

test "guest owner interrupted cleanup validates ALL slots before releasing any unpublished custody" {
    var key = try sign.KeyPair.fromSeed(@splat(67));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    const a = try presence.encode(r, &key, &a_buf);
    r.revision = 2;
    r.host = "b.public";
    const b = try presence.encode(r, &key, &b_buf);
    const Context = struct {
        a: []const u8,
        b: []const u8,
        first: ?PreparedId = null,
        second: ?PreparedId = null,
        saved_credit: usize = 0,
        fn firstCut(self: *@This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.a);
            _ = try acceptForTest(cut, self.b);
            self.first = try cut.prepareRoots(&.{(try presence.decode(self.a)).record.origin});
        }
        fn secondCut(self: *@This(), cut: *Cut) !void {
            try std.testing.expectError(error.ExclusiveAcquisitionChanged, cut.abort(self.first.?));
            try std.testing.expectError(error.ExclusiveAcquisitionChanged, cut.commit(self.first.?, 1000));
            self.second = try cut.prepareRoots(&.{(try presence.decode(self.a)).record.origin});
            self.saved_credit = (try cut.usage()).reserved_payload;
        }
        fn stillOwned(self: *@This(), cut: *Cut) !void {
            const u = try cut.usage();
            try std.testing.expectEqual(@as(usize, 2), u.active_prepared);
            try std.testing.expectEqual(self.saved_credit, u.reserved_payload);
            try std.testing.expectEqual(@as(usize, 1), try cut.pendingCount());
            try std.testing.expectEqualSlices(u8, self.a, (try cut.pendingAt(0)).?.old_wire);
            try cut.abort(self.second.?);
        }
        fn afterCleanup(self: *@This(), cut: *Cut) !void {
            const u = try cut.usage();
            try std.testing.expectEqual(@as(usize, 0), u.active_prepared);
            try std.testing.expectEqual(@as(usize, 0), u.reserved_payload);
            try std.testing.expectEqual(@as(usize, 1), try cut.pendingCount());
            try std.testing.expectError(error.StalePrepared, cut.abort(self.first.?));
        }
    };
    var context = Context{ .a = a, .b = b };
    try owner.withCut(&context, Context.firstCut);
    world.unlockWrite();
    world.lockWrite();
    try owner.withCut(&context, Context.secondCut);
    try std.testing.expectError(error.ExclusiveAcquisitionNotInterrupted, owner.reclaimInterrupted());
    try owner.withCut(&context, Context.stillOwned);
    try owner.reclaimInterrupted();
    try owner.withCut(&context, Context.afterCleanup);
}

test "guest owner private counter exhaustion fences normal publication but cannot prevent negative revocation" {
    var key = try sign.KeyPair.fromSeed(@splat(68));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var a_buf: [presence.max_wire_len]u8 = undefined;
    var b_buf: [presence.max_wire_len]u8 = undefined;
    var c_buf: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    const a = try presence.encode(r, &key, &a_buf);
    r.host = "conflict.public";
    const conflict = try presence.encode(r, &key, &c_buf);
    r.revision = 2;
    const b = try presence.encode(r, &key, &b_buf);
    const Context = struct {
        a: []const u8,
        b: []const u8,
        conflict: []const u8,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.a);
            const o = cutBacking(cut).owner;
            const held = try cut.prepareRoots(&.{});
            const saved_sequence = o.next_sequence;
            o.next_sequence = std.math.maxInt(u128);
            try std.testing.expectError(error.GenerationExhausted, cut.prepareInbound(self.b, 9, 1000));
            o.next_sequence = saved_sequence;
            const saved_policy = o.policy_revision;
            o.policy_revision = std.math.maxInt(u64);
            try std.testing.expectError(error.GenerationExhausted, cut.prepareRoots(&.{}));
            o.policy_revision = saved_policy;
            o.generation = std.math.maxInt(u64);
            try std.testing.expectError(error.GenerationExhausted, cut.prepareInbound(self.b, 9, 1000));
            o.security_revision = std.math.maxInt(u64);
            const allocator = o.allocator;
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            o.allocator = failing.allocator();
            defer o.allocator = allocator;
            try std.testing.expectError(error.Quarantined, cut.prepareInbound(self.conflict, 9, 1000));
            try std.testing.expect(o.terminal);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expect((try currentForTest(cut, subject((try presence.decode(self.a)).record), 1000)) == null);
            try std.testing.expectError(error.StalePrepared, cut.commit(held, 1000));
            try cut.abort(held);
        }
    };
    try owner.withCut(Context{ .a = a, .b = b, .conflict = conflict }, Context.run);
}

test "guest owner real lock acquisition exhaustion refuses scopes without wrapping" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{}, testLimits());
    world.lock.exclusive_generation.store(std.math.maxInt(u64) - 1, .monotonic);
    world.lockWrite();
    try owner.withCut({}, emptyCutForTest);
    world.unlockWrite();
    world.lockWrite();
    defer world.unlockWrite();
    try std.testing.expectError(error.ExclusiveAcquisitionExhausted, owner.withCut({}, emptyCutForTest));
    try owner.destroyQuiescent();
}

test "guest owner truncation signature ingress and cached work refusal allocate or publish nothing" {
    var key = try sign.KeyPair.fromSeed(@splat(69));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var buffer: [presence.max_wire_len]u8 = undefined;
    const wire = try presence.encode(testRecord(&key), &key, &buffer);
    const Context = struct {
        wire: []const u8,
        fn run(self: @This(), cut: *Cut) !void {
            const before = try cut.usage();
            const o = cutBacking(cut).owner;
            for (0..self.wire.len) |length| {
                if (cut.prepareInbound(self.wire[0..length], 9, 1000)) |id| {
                    try cut.abort(id);
                    return error.TestUnexpectedResult;
                } else |_| {}
                try std.testing.expectEqualDeep(before, try cut.usage());
            }
            try std.testing.expectError(error.BadIngress, cut.prepareInbound(self.wire, 0, 1000));
            var corrupt: [presence.max_wire_len]u8 = undefined;
            @memcpy(corrupt[0..self.wire.len], self.wire);
            corrupt[self.wire.len - 1] ^= 1;
            try std.testing.expectError(error.BadSignature, cut.prepareInbound(corrupt[0..self.wire.len], 9, 1000));
            const allocator = o.allocator;
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            o.allocator = failing.allocator();
            defer o.allocator = allocator;
            const work = o.limits.work_per_operation;
            o.limits.work_per_operation = 0;
            try std.testing.expectError(error.BudgetExceeded, cut.prepareInbound(self.wire, 9, 1000));
            o.limits.work_per_operation = work;
            o.limits.signature_attempts = 0;
            try std.testing.expectError(error.BudgetExceeded, cut.prepareInbound(self.wire, 9, 1000));
            o.limits.signature_attempts = 1;
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqualDeep(before, try cut.usage());
        }
    };
    try owner.withCut(Context{ .wire = wire }, Context.run);
}

test "guest owner canonical signed-conflict witnesses are arrival-order independent" {
    var key = try sign.KeyPair.fromSeed(@splat(70));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    var abuf: [presence.max_wire_len]u8 = undefined;
    var bbuf: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    const a = try presence.encode(r, &key, &abuf);
    r.host = "contradiction.public";
    const b = try presence.encode(r, &key, &bbuf);
    var witnesses: [2][2][32]u8 = undefined;
    const Context = struct {
        first: []const u8,
        second: []const u8,
        result: *[2][32]u8,
        fn run(self: @This(), cut: *Cut) !void {
            _ = try acceptForTest(cut, self.first);
            const old = try cut.usage();
            try std.testing.expectError(error.Quarantined, cut.prepareInbound(self.second, 9, 1000));
            try std.testing.expectEqual(@as(usize, 0), (try cut.usage()).active_prepared);
            try std.testing.expectEqual(old.live_payload, (try cut.usage()).live_payload);
            const o = cutBacking(cut).owner;
            self.result.* = o.entries[0].witnesses;
            try std.testing.expect((try currentForTest(cut, subject((try presence.decode(self.first)).record), 1000)) == null);
        }
    };
    for (0..2) |n| {
        const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
        defer owner.destroyQuiescent() catch @panic("owner teardown");
        try owner.withCut(Context{ .first = if (n == 0) a else b, .second = if (n == 0) b else a, .result = &witnesses[n] }, Context.run);
    }
    try std.testing.expectEqualDeep(witnesses[0], witnesses[1]);
}

test "guest owner construction every OOM frees exact capacities and succeeds after final cut" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    var census = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const probe = try Owner.create(census.allocator(), &world, @splat(250), &.{@splat(123)}, testLimits());
    try probe.destroyQuiescent();
    try std.testing.expect(census.allocations > 0);
    try std.testing.expectEqual(census.allocations, census.deallocations);
    for (0..census.allocations + 1) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        if (index < census.allocations) {
            try std.testing.expectError(error.OutOfMemory, Owner.create(failing.allocator(), &world, @splat(250), &.{@splat(123)}, testLimits()));
            try std.testing.expect(failing.has_induced_failure);
        } else {
            const owner = try Owner.create(failing.allocator(), &world, @splat(250), &.{@splat(123)}, testLimits());
            try owner.destroyQuiescent();
            try std.testing.expect(!failing.has_induced_failure);
        }
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectEqual(failing.allocations, failing.deallocations);
    }
}

test "guest owner claim HLC future skew rejects before publication and exact boundary revalidates" {
    var key = try sign.KeyPair.fromSeed(@splat(71));
    defer key.deinit();
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const owner = try Owner.create(std.testing.allocator, &world, @splat(250), &.{key.public_key}, testLimits());
    defer owner.destroyQuiescent() catch @panic("owner teardown");
    var far_buffer: [presence.max_wire_len]u8 = undefined;
    var edge_buffer: [presence.max_wire_len]u8 = undefined;
    var conflict_buffer: [presence.max_wire_len]u8 = undefined;
    var r = testRecord(&key);
    r.claim_hlc = @as(u64, 31_001) << 16;
    const far = try presence.encode(r, &key, &far_buffer);
    r.claim_hlc = @as(u64, 31_000) << 16;
    const edge = try presence.encode(r, &key, &edge_buffer);
    r.claim_hlc = @as(u64, 4_000_000) << 16;
    r.host = "conflict.public";
    const conflict = try presence.encode(r, &key, &conflict_buffer);
    const Context = struct {
        far: []const u8,
        edge: []const u8,
        conflict: []const u8,
        fn run(self: @This(), cut: *Cut) !void {
            const before = try cut.usage();
            try std.testing.expectError(error.InvalidClaim, cut.prepareInbound(self.far, 9, 1000));
            try std.testing.expectEqualDeep(before, try cut.usage());
            const id = try cut.prepareInbound(self.edge, 9, 1000);
            const held = try cut.usage();
            try std.testing.expectError(error.InvalidClaim, cut.commit(id, 999));
            try std.testing.expectEqual(held.reserved_payload, (try cut.usage()).reserved_payload);
            try std.testing.expect((try cut.retainedWire(subject((try presence.decode(self.edge)).record))) == null);
            try cut.abort(id);
            _ = try acceptForTest(cut, self.edge);
            const current_subject = subject((try presence.decode(self.edge)).record);
            try std.testing.expect((try currentForTest(cut, current_subject, 1000)) != null);
            try std.testing.expect((try currentForTest(cut, current_subject, 999)) == null);
            const o = cutBacking(cut).owner;
            const allocator = o.allocator;
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            o.allocator = failing.allocator();
            defer o.allocator = allocator;
            // The signed contradictory body revokes BEFORE its intentionally
            // invalid future claim is rejected as ordinary publication.
            try std.testing.expectError(error.Quarantined, cut.prepareInbound(self.conflict, 9, 1000));
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expect((try currentForTest(cut, current_subject, 1000)) == null);
        }
    };
    try owner.withCut(Context{ .far = far, .edge = edge, .conflict = conflict }, Context.run);
}
