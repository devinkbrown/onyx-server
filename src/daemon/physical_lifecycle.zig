// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private physical-lifecycle resource planning. This admission layer has no
//! settlement API: external custody and exact publication
//! receipts must join it before a daemon transaction can publish.
const std = @import("std");
const store = @import("store.zig");

pub const resources = struct {
    const StoreBridge = store.ManagedBridge(@This());
    pub const Failure = error{ InvalidPlan, CapacityExceeded, StaleTicket, Busy, GenerationExhausted, AllocationsHeld, ParticipantsHeld, OutOfMemory };
    /// Registry boot/adopt identity, supplied by the actual registry owner.
    /// No address-derived or default instance can qualify an existing graph.
    pub const FleetInstance = struct {
        bytes: [16]u8,
        pub fn init(bytes: [16]u8) Failure!FleetInstance {
            const result: FleetInstance = .{ .bytes = bytes };
            if (!result.valid()) return error.InvalidPlan;
            return result;
        }
        fn valid(self: FleetInstance) bool {
            return !std.mem.allEqual(u8, &self.bytes, 0);
        }
        fn eql(self: FleetInstance, other: FleetInstance) bool {
            return std.mem.eql(u8, &self.bytes, &other.bytes);
        }
    };
    pub const Category = enum(u1) { output, graph };
    pub const Limits = struct { resident: u64, peak: u64, wire: u64 };
    pub const Totals = struct {
        resident: u64 = 0,
        retiring: u64 = 0,
        preparation: u64 = 0,
        resident_hold: u64 = 0,
        wire: u64 = 0,
        wire_hold: u64 = 0,
        fn permits(self: Totals, limits: Limits) bool {
            const rp = std.math.add(u64, self.resident, self.retiring) catch return false;
            const peak = std.math.add(u64, rp, self.preparation) catch return false;
            const resident = std.math.add(u64, self.resident, self.resident_hold) catch return false;
            const wire = std.math.add(u64, self.wire, self.wire_hold) catch return false;
            return peak <= limits.peak and resident <= limits.resident and wire <= limits.wire;
        }
    };
    const Holds = struct {
        listed: bool = false,
        preparation: u64 = 0,
        resident: u64 = 0,
        wire: u64 = 0,
        move_peak: u64 = 0,
        incoming: u64 = 0,
        outgoing: u64 = 0,
        old_retire: u64 = 0,
        publication_new: u64 = 0,
        fn add(self: *Holds, rhs: Holds) Failure!void {
            const p = std.math.add(u64, self.preparation, rhs.preparation) catch return error.CapacityExceeded;
            const r = std.math.add(u64, self.resident, rhs.resident) catch return error.CapacityExceeded;
            const w = std.math.add(u64, self.wire, rhs.wire) catch return error.CapacityExceeded;
            const incoming = try sum(self.incoming, rhs.incoming);
            const outgoing = try sum(self.outgoing, rhs.outgoing);
            const old_retire = try sum(self.old_retire, rhs.old_retire);
            const publication_new = try sum(self.publication_new, rhs.publication_new);
            self.* = .{ .listed = self.listed, .preparation = p, .resident = r, .wire = w, .incoming = incoming, .outgoing = outgoing, .old_retire = old_retire, .publication_new = publication_new };
        }
        fn derive(self: *Holds, old: Totals) Failure!void {
            const removed = try sum(self.outgoing, self.old_retire);
            if (removed > old.resident) return error.InvalidPlan;
            // Aggregate the complete account before clamping. Equal-size cycles
            // need neither phantom fleet storage nor component-local credits.
            if (self.incoming >= removed) {
                self.resident = try sum(self.resident, self.incoming - removed);
            } else {
                const credit = removed - self.incoming;
                self.resident = self.resident -| credit;
            }
            // Compare complete preparation and publication placements. Unused
            // originating allowance cannot be charged again after transfer.
            const credit = try sum(self.outgoing, self.preparation);
            self.move_peak = if (self.incoming >= credit)
                try sum(self.incoming - credit, self.publication_new)
            else
                self.publication_new -| (credit - self.incoming);
        }
        fn funded(self: Holds, old: Totals) Failure!Totals {
            var result = old;
            result.preparation = std.math.add(u64, old.preparation, try sum(self.preparation, self.move_peak)) catch return error.CapacityExceeded;
            result.resident_hold = std.math.add(u64, old.resident_hold, self.resident) catch return error.CapacityExceeded;
            result.wire_hold = std.math.add(u64, old.wire_hold, self.wire) catch return error.CapacityExceeded;
            return result;
        }
        fn refund(self: Holds, totals: *Totals) void {
            totals.preparation -= self.preparation + self.move_peak;
            totals.resident_hold -= self.resident;
            totals.wire_hold -= self.wire;
        }
    };
    const Account = struct { limits: Limits, totals: Totals = .{} };
    const Row = struct { id: u64 = 0, generation: u64 = 0, account: Account };
    const Component = struct {
        serial: u64 = 0,
        row: usize = 0,
        category: Category = .graph,
        revision: u64 = 1,
        seen_transaction: u64 = 0,
        plan_index: usize = 0,
        owned_head: usize = vacant,
        owned_count: usize = 0,
        owned_charge: u64 = 0,
        participant_slot: usize = vacant,
        participant_serial: u64 = 0,
        next_home: usize = vacant,
    };
    pub const ParticipantId = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, serial: u64 };
    pub const ParticipantPlan = struct { participant: ParticipantId, expected_owner_revision: u64, expected_old_census_revision: u64, work_units: u64 };
    const SourceBinding = if (@import("builtin").is_test) enum { fixture, store } else enum { unavailable, store };
    const ParticipantRecord = struct {
        serial: u64 = 0,
        source_binding: SourceBinding = if (@import("builtin").is_test) .fixture else .unavailable,
        managed: StoreRecord = .{},
        source_lifetime: u64 = 0,
        owner_revision: u64 = 1,
        old_census_revision: u64 = 1,
        first_component: usize = vacant,
        component_count: usize = 0,
        seen_transaction: u64 = 0,
        plan_index: usize = 0,
        source: if (@import("builtin").is_test) FixtureOwner else struct {} = .{},
    };
    const ParticipantEntry = struct {
        copied_plan: ParticipantPlan,
        participant_slot: usize,
        planned_component_count: usize = 0,
        state: enum { funded, issued, released } = .funded,
    };
    const FixtureHome = struct { row: RowHandle, category: Category };
    /// An actual retained source ticket and borrow pin live at a stable catalog
    /// address. This owner has no asynchronous callbacks or escaping tasks.
    /// Primitive fixture facades have a lexical lifetime ending before release;
    /// a raw Allocator copy cannot distinguish a later reissued home epoch.
    const FixtureOwner = struct {
        lifetime: u64 = 0,
        revision: u64 = 1,
        census_revision: u64 = 1,
        guard: std.atomic.Value(u64) = .init(0),
        ticket: ?struct { participant_serial: u64, transaction: u64, source_revision: u64, guard_identity: *std.atomic.Value(u64) } = null,
        borrow_transaction: u64 = 0,
        borrow_seen_transaction: u64 = 0,
        prepare_seen_transaction: u64 = 0,
        loan: ?ParticipantLoan = null,
        candidate: ?struct { allocator: std.mem.Allocator, bytes: []u8 } = null,
        prepare_count: usize = 0,

        fn prepare(self: *FixtureOwner, loan: ParticipantLoan) Failure!void {
            if (comptime !@import("builtin").is_test) @compileError("source fixture is test-only");
            const slot = try loan.validateIssued();
            if (self != &coordinatorBacking(loan.owner).participants[slot].source) return error.StaleTicket;
            if (self.prepare_seen_transaction == loan.transaction or self.ticket != null) return error.Busy;
            try loan.owner.validateParticipantSource(coordinatorBacking(loan.owner).participant_entries[coordinatorBacking(loan.owner).participants[slot].plan_index], true);
            if (self.guard.cmpxchgStrong(0, loan.transaction, .acquire, .monotonic) != null) return error.Busy;
            self.prepare_seen_transaction = loan.transaction;
            self.ticket = .{ .participant_serial = loan.participant_serial, .transaction = loan.transaction, .source_revision = self.revision, .guard_identity = &self.guard };
            self.prepare_count += 1;
            coordinatorBacking(loan.owner).prepared_sources += 1;
        }
        fn prepareBuffer(self: *FixtureOwner, loan: ParticipantLoan, component: ComponentId, len: usize) Failure!void {
            if (comptime !@import("builtin").is_test) @compileError("source fixture is test-only");
            const slot = try loan.validateIssued();
            if (self != &coordinatorBacking(loan.owner).participants[slot].source or self.ticket == null or self.candidate != null) return error.StaleTicket;
            const allocator = try (try loan.componentScope(component)).allocator();
            const bytes = try allocator.alloc(u8, len);
            self.candidate = .{ .allocator = allocator, .bytes = bytes };
        }
        fn abort(self: *FixtureOwner, loan: ParticipantLoan) Failure!void {
            if (comptime !@import("builtin").is_test) @compileError("source fixture is test-only");
            const slot = try loan.validateIssued();
            if (self != &coordinatorBacking(loan.owner).participants[slot].source) return error.StaleTicket;
            const ticket = self.ticket orelse return error.StaleTicket;
            if (ticket.participant_serial != loan.participant_serial or ticket.transaction != loan.transaction or ticket.source_revision != self.revision or ticket.guard_identity != &self.guard or self.guard.load(.acquire) != loan.transaction or self.borrow_transaction != 0) return error.ParticipantsHeld;
            if (self.candidate) |owned| owned.allocator.free(owned.bytes);
            self.candidate = null;
            self.ticket = null;
            self.guard.store(0, .release);
            coordinatorBacking(loan.owner).prepared_sources -= 1;
        }
        fn pinBorrow(self: *FixtureOwner, loan: ParticipantLoan) Failure!FixtureBorrow {
            if (comptime !@import("builtin").is_test) @compileError("source fixture is test-only");
            const slot = try loan.validateIssued();
            if (self != &coordinatorBacking(loan.owner).participants[slot].source or self.borrow_transaction != 0) return error.Busy;
            if (self.borrow_seen_transaction == loan.transaction) return error.StaleTicket;
            self.borrow_seen_transaction = loan.transaction;
            self.borrow_transaction = loan.transaction;
            return .{ .source = self, .loan = loan };
        }
        fn describeAbortState(self: *FixtureOwner) struct { lifetime: u64, revision: u64, census_revision: u64, idle: bool } {
            if (comptime !@import("builtin").is_test) @compileError("source fixture is test-only");
            return .{ .lifetime = self.lifetime, .revision = self.revision, .census_revision = self.census_revision, .idle = self.ticket == null and self.guard.load(.acquire) == 0 and self.borrow_transaction == 0 and self.candidate == null };
        }
    };
    const FixtureBorrow = struct {
        source: *FixtureOwner,
        loan: ParticipantLoan,
        fn finish(self: FixtureBorrow) Failure!void {
            const slot = try self.loan.validateIssued();
            if (self.source != &coordinatorBacking(self.loan.owner).participants[slot].source or self.source.borrow_transaction != self.loan.transaction) return error.StaleTicket;
            self.source.borrow_transaction = 0;
        }
    };
    const AllocationState = enum { free, candidate, resident, retiring };
    pub const FreePoint = enum { publication, finish };
    pub const OldDisposition = union(enum) { keep, keep_retiring, move: ComponentId, retire: FreePoint };
    const vacant = std.math.maxInt(usize);
    const Allocation = struct {
        root: ?store.RootKey = null,
        ptr: ?[*]u8 = null,
        len: usize = 0,
        alignment: std.mem.Alignment = .@"1",
        charge: u64 = 0,
        serial: u64 = 0,
        transaction: u64 = 0,
        state: AllocationState = .free,
        logical_owner: usize = vacant,
        logical_owner_serial: u64 = 0,
        owner_prev: usize = vacant,
        owner_next: usize = vacant,
        encumbered_transaction: u64 = 0,
        declared_transaction: u64 = 0,
        role_slot: usize = vacant,
        next_free: usize = vacant,
    };
    pub const AllocationId = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, home_slot: usize, home_serial: u64, allocation_slot: usize, serial: u64 };
    /// Backend deallocation context remains here, independent of borrowed scope
    /// lifetime and future logical ownership transfers. This table never moves.
    const AllocationHome = struct {
        backend: std.mem.Allocator,
        owner: *Coordinator,
        slot: usize,
        serial: u64,
        records: []Allocation,
        buckets: []usize,
        free_head: usize = 0,
        allocation_serial: u64 = 0,
        active_transaction: u64 = 0,
        peak: u64 = 0,
        slot_allowance: usize = 0,
        actual_new: u64 = 0,
        live_new: usize = 0,
        live_total: usize = 0,
        free_count: usize,

        fn active(self: *AllocationHome) bool {
            return self.active_transaction != 0 and self.active_transaction == coordinatorBacking(self.owner).serial and (coordinatorBacking(self.owner).phase == .funded or coordinatorBacking(self.owner).phase == .preparing) and self.owner.homeIssued(self.slot, self.active_transaction);
        }
        fn allocator(self: *AllocationHome) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = std.mem.Allocator.noRemap, .free = free } };
        }
        fn hash(self: *AllocationHome, ptr: [*]u8) usize {
            const address = @intFromPtr(ptr);
            return @as(usize, @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&address)))) & (self.buckets.len - 1);
        }
        fn insert(self: *AllocationHome, index: usize) void {
            var bucket = self.hash(self.records[index].ptr.?);
            for (0..self.buckets.len) |_| {
                if (self.buckets[bucket] == vacant) {
                    self.buckets[bucket] = index;
                    return;
                }
                bucket = (bucket + 1) & (self.buckets.len - 1);
            }
            unreachable; // At most half the pre-funded buckets can be occupied.
        }
        fn probe(self: *AllocationHome, ptr: [*]u8) ?struct { record: usize, bucket: usize } {
            var bucket = self.hash(ptr);
            for (0..self.buckets.len) |_| {
                const index = self.buckets[bucket];
                if (index == vacant) break;
                const record = &self.records[index];
                if (record.ptr == ptr) {
                    return .{ .record = index, .bucket = bucket };
                }
                bucket = (bucket + 1) & (self.buckets.len - 1);
            }
            return null;
        }
        fn lookup(self: *AllocationHome, memory: []u8, alignment: std.mem.Alignment) struct { record: usize, bucket: usize } {
            const found = self.probe(memory.ptr) orelse @panic("physical allocation home received foreign capacity");
            const record = self.records[found.record];
            std.debug.assert(record.len == memory.len and record.alignment == alignment);
            return .{ .record = found.record, .bucket = found.bucket };
        }
        fn remove(self: *AllocationHome, start: usize) void {
            // Backward-shift deletion preserves lookup across collisions and
            // prevents unbounded tombstone accumulation under scratch reuse.
            const mask = self.buckets.len - 1;
            var hole = start;
            var cursor = (hole + 1) & mask;
            while (self.buckets[cursor] != vacant) : (cursor = (cursor + 1) & mask) {
                const index = self.buckets[cursor];
                const origin = self.hash(self.records[index].ptr.?);
                if (((cursor -% origin) & mask) >= ((hole -% origin) & mask)) {
                    self.buckets[hole] = index;
                    hole = cursor;
                }
            }
            self.buckets[hole] = vacant;
        }
        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *AllocationHome = @ptrCast(@alignCast(ctx));
            if (len == 0 or !self.active() or self.live_new == self.slot_allowance or self.free_head == vacant) return null;
            const charge = sum(len, alignment.toByteUnits() - 1) catch return null;
            if (self.actual_new > self.peak or charge > self.peak - self.actual_new) return null;
            const serial = std.math.add(u64, self.allocation_serial, 1) catch return null;
            self.allocation_serial = serial; // Burn even if backend refuses.
            const ptr = self.backend.rawAlloc(len, alignment, ret_addr) orelse return null;
            const index = self.free_head;
            self.free_head = self.records[index].next_free;
            self.records[index] = .{ .ptr = ptr, .len = len, .alignment = alignment, .charge = charge, .serial = serial, .transaction = self.active_transaction, .state = .candidate };
            self.insert(index);
            self.owner.linkAllocation(self.slot, index, self.slot);
            self.live_total += 1;
            self.free_count -= 1;
            self.actual_new += charge;
            self.live_new += 1;
            return ptr;
        }
        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *AllocationHome = @ptrCast(@alignCast(ctx));
            const found = self.lookup(memory, alignment);
            const record = &self.records[found.record];
            if (!self.active() or record.state != .candidate or record.transaction != self.active_transaction or record.role_slot != vacant) return false;
            const charge = sum(new_len, alignment.toByteUnits() - 1) catch return false;
            const without = self.actual_new - record.charge;
            if (without > self.peak or charge > self.peak - without) return false;
            if (!self.backend.rawResize(memory, alignment, new_len, ret_addr)) return false;
            const logical = &coordinatorBacking(self.owner).components[record.logical_owner];
            logical.owned_charge = logical.owned_charge - record.charge + charge;
            record.len = new_len;
            record.charge = charge;
            self.actual_new = without + charge;
            return true;
        }
        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *AllocationHome = @ptrCast(@alignCast(ctx));
            const found = self.lookup(memory, alignment);
            const record = self.records[found.record];
            std.debug.assert(self.active() and record.state == .candidate and record.transaction == self.active_transaction);
            self.owner.releaseRole(record);
            self.backend.rawFree(memory, alignment, ret_addr);
            self.owner.unlinkAllocation(self.slot, found.record);
            self.remove(found.bucket);
            self.live_total -= 1;
            self.free_count += 1;
            self.actual_new -= record.charge;
            self.live_new -= 1;
            self.records[found.record] = .{ .next_free = self.free_head };
            self.free_head = found.record;
        }
    };
    pub const RowHandle = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, id: u64, generation: u64 };
    pub const ComponentId = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, serial: u64 };
    pub const Profile = struct {
        fleet: Limits,
        categories: [2]Limits,
        infrastructure: Limits,
        rows: u32,
        components: u32,
        transaction_components: u32,
        participant_slots: u32,
        transaction_participant_refs: u32,
        transaction_work_max: u64,
        allocation_slots_per_home: u32 = 16,
        transaction_allocation_refs: u32 = 64,
        new_role_slots: u32 = 128,
    };
    // Only a new, empty boot may use this constructor. Restore cannot invent an
    // empty census for live graph state and must use the future restore owner.
    pub const EmptyBootCensus = enum { empty };
    pub const ComponentPlan = struct {
        component: ComponentId,
        expected_revision: u64,
        new_capacity_peak: u64,
        final_new_capacity_max: u64,
        final_wire_addition_max: u64,
        new_allocation_slots: u32 = 0,
    };
    pub const AllocationDeclaration = struct {
        allocation: AllocationId,
        expected_owner: ComponentId,
        expected_owner_revision: u64,
        expected_length: usize,
        expected_alignment: std.mem.Alignment,
        disposition: OldDisposition,
    };
    const OwnershipEntry = struct { declaration: AllocationDeclaration, record: usize, receiver: usize = vacant };
    pub const RolePlan = struct {
        origin: ComponentId,
        expected_origin_revision: u64,
        label: u32,
        kind: union(enum) { retain: ComponentId, discard: FreePoint },
        max_charge: u64,
        max_live_allocations: u32,
    };
    pub const RoleId = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, transaction: u64, slot: usize, serial: u64 };
    const RoleEntry = struct { plan: RolePlan, origin: usize, receiver: usize, serial: u64, actual_charge: u64 = 0, actual_count: u32 = 0 };
    const RoleContribution = struct { origin: usize, account: usize, retain: u64 = 0, discard: u64 = 0 };
    const Entry = struct { plan: ComponentPlan, index: usize, role_count: usize = 0, role_start: usize = vacant, retained_actual: u64 = 0 };
    const Phase = enum { idle, planning, canonical, funded, preparing };
    pub const StoreConstructionWitness = opaque {};
    pub const StoreDestructionWitness = opaque {};
    pub const StoreConstruction = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, serial: u64, witness: *const StoreConstructionWitness };
    pub const StoreOwnerId = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, serial: u64, source_lifetime: u64 };
    pub const StoreDestruction = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, slot: usize, serial: u64, source_lifetime: u64, witness: *const StoreDestructionWitness };
    pub const StoreAllocationBinding = struct { scope: FundedScope, role: RoleId };
    const StorePhase = enum { absent, reserved, constructing, pending, aborting, registered, destruction_armed, destroying, dead };
    const StoreRecord = struct {
        phase: StorePhase = .absent,
        construction_anchor: u8 = 0,
        destruction_anchor: u8 = 0,
        construction_serial: u64 = 0,
        destruction_serial: u64 = 0,
        expected_creation: ?store.CreationIdentity = null,
        owner: ?*StoreBridge.Owner = null,
        source: store.SourceIdentity = .{ .lifetime = 0, .owner_revision = 0, .census_revision = 0 },
        exclusion: ?StoreBridge.Exclusive = null,
        plan_transaction: u64 = 0,
        roles: [7]?RoleId = @splat(null),
    };
    const StoreSpec = struct { row: RowHandle, args: store.CreationArgs, candidate_allocator: std.mem.Allocator, seed_pending: if (@import("builtin").is_test) bool else void = if (@import("builtin").is_test) false else {}, seed_retirements: if (@import("builtin").is_test) bool else void = if (@import("builtin").is_test) false else {}, poison_pending: if (@import("builtin").is_test) bool else void = if (@import("builtin").is_test) false else {}, arm_ordinary: if (@import("builtin").is_test) bool else void = if (@import("builtin").is_test) false else {} };
    const StoreAllowances = struct {
        homes: [6]struct { peak: u64, final: u64, slots: u32 },
        uses: [7]struct { charge: u64, slots: u32 },
        work: u64,
    };
    const store_home_count = 8; // Two actual original domains plus six NEW origins.

    fn storeConstructionRecord(c: StoreConstruction) Failure!*StoreRecord {
        if (c.owner != c.identity) return error.StaleTicket;
        const b = coordinatorBacking(c.owner);
        if (!c.instance.eql(b.instance) or c.slot >= b.participants.len) return error.StaleTicket;
        const record = &b.participants[c.slot].managed;
        const expected: *const StoreConstructionWitness = @ptrCast(&record.construction_anchor);
        if (c.serial == 0 or c.serial != record.construction_serial or c.witness != expected) return error.StaleTicket;
        return record;
    }
    pub fn beginStoreConstruction(c: StoreConstruction, identity: store.CreationIdentity) Failure!void {
        const m = try storeConstructionRecord(c);
        if (m.phase != .reserved or m.expected_creation == null or !std.meta.eql(m.expected_creation.?, identity)) return error.StaleTicket;
        m.phase = .constructing;
    }
    pub fn resolveConstructingStore(c: StoreConstruction) Failure!*StoreBridge.Owner {
        const m = try storeConstructionRecord(c);
        if (m.phase != .pending) return error.StaleTicket;
        return m.owner orelse error.StaleTicket;
    }
    pub fn beginAbortStoreConstruction(c: StoreConstruction, source: *StoreBridge.Owner) Failure!void {
        const m = try storeConstructionRecord(c);
        if (m.phase != .pending or m.owner != source) return error.StaleTicket;
        m.phase = .aborting;
    }
    pub fn resolveStoreOwner(id: StoreOwnerId) Failure!*StoreBridge.Owner {
        if (id.owner != id.identity) return error.StaleTicket;
        const b = coordinatorBacking(id.owner);
        if (!id.instance.eql(b.instance) or id.slot >= b.participants.len) return error.StaleTicket;
        const p = &b.participants[id.slot];
        const m = &p.managed;
        if (id.serial == 0 or p.serial != id.serial or m.source.lifetime != id.source_lifetime or (m.phase != .pending and m.phase != .registered)) return error.StaleTicket;
        return m.owner orelse error.StaleTicket;
    }
    pub fn resolveIssuedStore(loan: ParticipantLoan) Failure!*StoreBridge.Owner {
        const slot = try loan.validateIssued();
        const p = &coordinatorBacking(loan.owner).participants[slot];
        if (p.source_binding != .store or p.managed.phase != .registered) return error.StaleTicket;
        return p.managed.owner orelse error.StaleTicket;
    }
    pub fn storeWorkLimit(loan: ParticipantLoan) Failure!u64 {
        _ = try resolveIssuedStore(loan);
        const b = coordinatorBacking(loan.owner);
        const p = b.participants[loan.participant_slot];
        const limit = b.participant_entries[p.plan_index].copied_plan.work_units;
        if (limit == 0 or limit == std.math.maxInt(u64) or limit > b.transaction_work_max) return error.InvalidPlan;
        return limit;
    }
    fn candidateHome(purpose: store.CandidateUse) usize {
        return switch (purpose) {
            .packet => 2,
            .new_key, .scratch_key => 3,
            .value => 4,
            .feed_key => 5,
            .feed_value => 6,
            .table_backing => 7,
        };
    }
    pub fn storeAllocationBinding(loan: ParticipantLoan, purpose: store.CandidateUse) Failure!StoreAllocationBinding {
        _ = try resolveIssuedStore(loan);
        const b = coordinatorBacking(loan.owner);
        const p = &b.participants[loan.participant_slot];
        if (p.managed.plan_transaction != loan.transaction) return error.StaleTicket;
        const role = p.managed.roles[@intFromEnum(purpose)] orelse return error.CapacityExceeded;
        const role_slot = try loan.owner.roleIndex(role);
        const origin = p.first_component + candidateHome(purpose);
        if (b.roles[role_slot].origin != origin) return error.StaleTicket;
        try loan.owner.validateRole(b.roles[role_slot]);
        const expected_receiver = switch (purpose) {
            .packet, .scratch_key => vacant,
            else => p.first_component,
        };
        if (b.roles[role_slot].receiver != expected_receiver) return error.InvalidPlan;
        return .{ .scope = try loan.componentScope(loan.owner.componentId(origin)), .role = role };
    }
    fn destructionRecord(d: StoreDestruction) Failure!*StoreRecord {
        if (d.owner != d.identity) return error.StaleTicket;
        const b = coordinatorBacking(d.owner);
        if (!d.instance.eql(b.instance) or d.slot >= b.participants.len) return error.StaleTicket;
        const m = &b.participants[d.slot].managed;
        const expected: *const StoreDestructionWitness = @ptrCast(&m.destruction_anchor);
        if (d.witness != expected or d.serial == 0 or d.serial != m.destruction_serial or d.source_lifetime != m.source.lifetime) return error.StaleTicket;
        return m;
    }
    pub fn beginStoreDestruction(d: StoreDestruction, source: *StoreBridge.Owner) Failure!void {
        const m = try destructionRecord(d);
        if (m.phase != .destruction_armed or m.owner != source) return error.StaleTicket;
        m.phase = .destroying;
    }
    pub fn resolveDestroyingStore(d: StoreDestruction) Failure!*StoreBridge.Owner {
        const m = try destructionRecord(d);
        if (m.phase != .destroying) return error.StaleTicket;
        return m.owner orelse error.StaleTicket;
    }
    fn observedAllocator(a: std.mem.Allocator) store.AllocatorObservation {
        return .{ .context = @intFromPtr(a.ptr), .vtable = @intFromPtr(a.vtable) };
    }
    pub fn freeStoreRoot(d: StoreDestruction, source: *StoreBridge.Owner, key: store.RootKey) !void {
        if (try resolveDestroyingStore(d) != source) return error.StaleTicket;
        const pending = (try source.inspectPendingFree(d)) orelse return error.InvalidPlan;
        if (!std.meta.eql(pending.key, key)) return error.InvalidPlan;
        const b = coordinatorBacking(d.owner);
        const position = d.owner.originalPosition(pending.locator);
        if (position == b.original_span_count) return error.InvalidPlan;
        const index = b.original_spans[position].record;
        if (index == vacant) return error.InvalidPlan;
        const record = b.allocations[index];
        const home_index = index / b.slots_per_home;
        const home = &b.homes[home_index];
        if (record.ptr == null or @intFromPtr(record.ptr.?) != pending.locator or record.root == null or !std.meta.eql(record.root.?, key) or record.len != pending.requested_bytes or record.alignment.toByteUnits() != pending.alignment or record.encumbered_transaction != 0 or !std.meta.eql(observedAllocator(home.backend), pending.original_allocator)) return error.InvalidPlan;
        const p = b.participants[d.slot];
        if (b.components[record.logical_owner].participant_slot != d.slot or b.components[record.logical_owner].participant_serial != p.serial or ((record.state == .retiring) != (pending.ownership == .retiring)) or (record.state != .resident and record.state != .retiring)) return error.InvalidPlan;
        const found = home.probe(record.ptr.?) orelse return error.InvalidPlan;
        if (found.record != index % b.slots_per_home) return error.InvalidPlan;
        const logical = b.components[record.logical_owner];
        const accounts = [_]usize{ 0, 1 + @as(usize, @intFromEnum(logical.category)), 3 + logical.row };
        for (accounts) |account_index| {
            const totals = d.owner.account(account_index).totals;
            if ((if (record.state == .retiring) totals.retiring else totals.resident) < record.charge) return error.InvalidPlan;
        }
        // No lookup, allocation, source access or failure after actual free.
        home.backend.rawFree(record.ptr.?[0..record.len], record.alignment, @returnAddress());
        d.owner.unlinkAllocation(home_index, found.record);
        home.remove(found.bucket);
        home.live_total -= 1;
        home.free_count += 1;
        home.records[found.record] = .{ .next_free = home.free_head };
        home.free_head = found.record;
        for (accounts) |account_index| {
            const totals = &d.owner.account(account_index).totals;
            if (record.state == .retiring) totals.retiring -= record.charge else totals.resident -= record.charge;
        }
        // Keep the immutable address searchable during destruction. A single
        // root-owned compaction removes all tombstones after both boxes are free.
        b.original_spans[position].record = vacant;
    }

    const OriginalSpan = struct { address: usize, record: usize };

    const CoordinatorBacking = struct {
        backend: std.mem.Allocator,
        instance: FleetInstance,
        fleet: Account,
        categories: [2]Account,
        rows: []Row,
        components: []Component,
        entries: []Entry,
        ownership: []OwnershipEntry,
        roles: []RoleEntry,
        role_order: []usize,
        role_contributions: []RoleContribution,
        holds: []Holds, // fleet, both categories, then each physical row
        touched: []usize,
        homes: []AllocationHome,
        allocations: []Allocation,
        buckets: []usize,
        participants: []ParticipantRecord,
        participant_entries: []ParticipantEntry,
        participant_order: []usize,
        original_spans: []OriginalSpan,
        original_span_count: usize = 0,
        source_transition: bool = false,
        transaction_work_max: u64,
        slots_per_home: usize,
        buckets_per_home: usize,
        touched_count: usize = 0,
        row_count: usize = 1,
        component_count: usize = 0,
        participant_count: usize = 0,
        participant_entry_count: usize = 0,
        participant_serial: u64 = 0,
        prepared_sources: usize = 0,
        entry_count: usize = 0,
        ownership_count: usize = 0,
        role_count: usize = 0,
        role_serial: u64 = 0,
        serial: u64 = 0,
        component_serial: u64 = 0,
        revision: u64 = 1,
        phase: Phase = .idle,
        metadata_charge: u64,
    };

    // The public handle and private backing are the same original allocation.
    // This conversion stays source-private; no mutable backing escapes the API.
    fn coordinatorBacking(owner: *Coordinator) *CoordinatorBacking {
        return @ptrCast(@alignCast(owner));
    }

    /// Stable opaque handle. All owner state lives in the single charged private
    /// backing allocation; public tokens retain only this handle and identities.
    pub const Coordinator = opaque {
        pub fn create(backend: std.mem.Allocator, profile: Profile, _: EmptyBootCensus, instance: FleetInstance) Failure!*Coordinator {
            if (!instance.valid()) return error.InvalidPlan;
            if (profile.transaction_work_max == 0 or profile.participant_slots == 0 or profile.transaction_participant_refs == 0 or profile.transaction_participant_refs > profile.participant_slots or profile.new_role_slots == 0 or profile.transaction_allocation_refs == 0 or profile.allocation_slots_per_home == 0 or profile.rows == 0 or profile.components == 0 or profile.transaction_components == 0 or profile.transaction_components > profile.components) return error.InvalidPlan;
            var charge = try capacityCharge(CoordinatorBacking, 1);
            charge = try sum(charge, try capacityCharge(Row, profile.rows));
            charge = try sum(charge, try capacityCharge(Component, profile.components));
            charge = try sum(charge, try capacityCharge(Entry, profile.transaction_components));
            charge = try sum(charge, try capacityCharge(ParticipantRecord, profile.participant_slots));
            charge = try sum(charge, try capacityCharge(ParticipantEntry, profile.transaction_participant_refs));
            charge = try sum(charge, try capacityCharge(usize, profile.transaction_participant_refs));
            charge = try sum(charge, try capacityCharge(OwnershipEntry, profile.transaction_allocation_refs));
            const contribution_count = std.math.mul(usize, profile.new_role_slots, 3) catch return error.CapacityExceeded;
            charge = try sum(charge, try capacityCharge(RoleEntry, profile.new_role_slots));
            charge = try sum(charge, try capacityCharge(usize, profile.new_role_slots));
            charge = try sum(charge, try capacityCharge(RoleContribution, contribution_count));
            const hold_count = std.math.add(usize, profile.rows, 3) catch return error.CapacityExceeded;
            charge = try sum(charge, try capacityCharge(Holds, hold_count));
            charge = try sum(charge, try capacityCharge(usize, hold_count));
            const allocation_count = std.math.mul(usize, profile.components, profile.allocation_slots_per_home) catch return error.CapacityExceeded;
            const twice = std.math.mul(usize, profile.allocation_slots_per_home, 2) catch return error.CapacityExceeded;
            const buckets_per_home = std.math.ceilPowerOfTwo(usize, twice) catch return error.CapacityExceeded;
            const bucket_count = std.math.mul(usize, profile.components, buckets_per_home) catch return error.CapacityExceeded;
            charge = try sum(charge, try capacityCharge(AllocationHome, profile.components));
            charge = try sum(charge, try capacityCharge(Allocation, allocation_count));
            charge = try sum(charge, try capacityCharge(usize, bucket_count));
            charge = try sum(charge, try capacityCharge(OriginalSpan, allocation_count));
            const bootstrap: Totals = .{ .resident = charge };
            if (!bootstrap.permits(profile.fleet) or !bootstrap.permits(profile.categories[@intFromEnum(Category.graph)]) or !bootstrap.permits(profile.infrastructure)) return error.CapacityExceeded;
            // All metadata has been priced before the first backend allocation.
            const self = try backend.create(CoordinatorBacking);
            errdefer backend.destroy(self);
            const rows = try backend.alloc(Row, profile.rows);
            errdefer backend.free(rows);
            const components = try backend.alloc(Component, profile.components);
            errdefer backend.free(components);
            const entries = try backend.alloc(Entry, profile.transaction_components);
            errdefer backend.free(entries);
            const ownership = try backend.alloc(OwnershipEntry, profile.transaction_allocation_refs);
            errdefer backend.free(ownership);
            const roles = try backend.alloc(RoleEntry, profile.new_role_slots);
            errdefer backend.free(roles);
            const role_order = try backend.alloc(usize, profile.new_role_slots);
            errdefer backend.free(role_order);
            const role_contributions = try backend.alloc(RoleContribution, contribution_count);
            errdefer backend.free(role_contributions);
            const holds = try backend.alloc(Holds, hold_count);
            errdefer backend.free(holds);
            const touched = try backend.alloc(usize, hold_count);
            errdefer backend.free(touched);
            const homes = try backend.alloc(AllocationHome, profile.components);
            errdefer backend.free(homes);
            const allocations = try backend.alloc(Allocation, allocation_count);
            errdefer backend.free(allocations);
            const buckets = try backend.alloc(usize, bucket_count);
            errdefer backend.free(buckets);
            const participants = try backend.alloc(ParticipantRecord, profile.participant_slots);
            errdefer backend.free(participants);
            const participant_entries = try backend.alloc(ParticipantEntry, profile.transaction_participant_refs);
            errdefer backend.free(participant_entries);
            const participant_order = try backend.alloc(usize, profile.transaction_participant_refs);
            errdefer backend.free(participant_order);
            const original_spans = try backend.alloc(OriginalSpan, allocation_count);
            errdefer backend.free(original_spans);
            @memset(allocations, .{});
            @memset(buckets, vacant);
            @memset(rows, .{ .account = .{ .limits = profile.infrastructure } });
            @memset(components, .{});
            @memset(holds, .{});
            @memset(participants, .{});
            self.* = .{ .backend = backend, .instance = instance, .fleet = .{ .limits = profile.fleet, .totals = bootstrap }, .categories = .{ .{ .limits = profile.categories[0] }, .{ .limits = profile.categories[1], .totals = bootstrap } }, .rows = rows, .components = components, .entries = entries, .ownership = ownership, .roles = roles, .role_order = role_order, .role_contributions = role_contributions, .holds = holds, .touched = touched, .homes = homes, .allocations = allocations, .buckets = buckets, .participants = participants, .participant_entries = participant_entries, .participant_order = participant_order, .original_spans = original_spans, .transaction_work_max = profile.transaction_work_max, .slots_per_home = profile.allocation_slots_per_home, .buckets_per_home = buckets_per_home, .metadata_charge = charge };
            rows[0] = .{ .id = 1, .generation = 1, .account = .{ .limits = profile.infrastructure, .totals = bootstrap } };
            return @ptrCast(self);
        }
        pub fn deinit(self: *Coordinator) void {
            std.debug.assert(coordinatorBacking(self).phase == .idle);
            std.debug.assert(coordinatorBacking(self).prepared_sources == 0);
            std.debug.assert(coordinatorBacking(self).fleet.totals.resident == coordinatorBacking(self).metadata_charge and coordinatorBacking(self).fleet.totals.wire == 0);
            for (coordinatorBacking(self).participants) |p| if (p.source_binding == .store) std.debug.assert(p.managed.phase == .absent or p.managed.phase == .dead);
            const backend = coordinatorBacking(self).backend;
            std.debug.assert(coordinatorBacking(self).fleet.totals.retiring == 0 and coordinatorBacking(self).original_span_count == 0);
            backend.free(coordinatorBacking(self).original_spans);
            backend.free(coordinatorBacking(self).participant_order);
            backend.free(coordinatorBacking(self).participant_entries);
            backend.free(coordinatorBacking(self).participants);
            backend.free(coordinatorBacking(self).buckets);
            backend.free(coordinatorBacking(self).allocations);
            backend.free(coordinatorBacking(self).homes);
            backend.free(coordinatorBacking(self).touched);
            backend.free(coordinatorBacking(self).holds);
            backend.free(coordinatorBacking(self).ownership);
            backend.free(coordinatorBacking(self).role_contributions);
            backend.free(coordinatorBacking(self).role_order);
            backend.free(coordinatorBacking(self).roles);
            backend.free(coordinatorBacking(self).entries);
            backend.free(coordinatorBacking(self).components);
            backend.free(coordinatorBacking(self).rows);
            backend.destroy(coordinatorBacking(self));
        }
        pub fn infrastructureRow(self: *Coordinator) RowHandle {
            return .{ .owner = self, .identity = self, .instance = coordinatorBacking(self).instance, .slot = 0, .id = 1, .generation = 1 };
        }
        pub fn registerRow(self: *Coordinator, id: u64, generation: u64, limits: Limits) Failure!RowHandle {
            if (coordinatorBacking(self).phase != .idle or coordinatorBacking(self).source_transition) return error.Busy;
            if (id <= 1 or generation == 0) return error.InvalidPlan;
            for (coordinatorBacking(self).rows[0..coordinatorBacking(self).row_count]) |row| if (row.id == id) return error.InvalidPlan;
            if (coordinatorBacking(self).row_count == coordinatorBacking(self).rows.len) return error.CapacityExceeded;
            coordinatorBacking(self).rows[coordinatorBacking(self).row_count] = .{ .id = id, .generation = generation, .account = .{ .limits = limits } };
            coordinatorBacking(self).row_count += 1;
            return .{ .owner = self, .identity = self, .instance = coordinatorBacking(self).instance, .slot = coordinatorBacking(self).row_count - 1, .id = id, .generation = generation };
        }
        fn registerFixture(self: *Coordinator, catalog: []const FixtureHome) Failure!ParticipantId {
            if (comptime !@import("builtin").is_test) @compileError("catalog fixture enrollment is test-only");
            if (coordinatorBacking(self).phase != .idle or coordinatorBacking(self).prepared_sources != 0) return error.Busy;
            if (catalog.len == 0) return error.InvalidPlan;
            if (coordinatorBacking(self).participant_count == coordinatorBacking(self).participants.len or catalog.len > coordinatorBacking(self).components.len - coordinatorBacking(self).component_count) return error.CapacityExceeded;
            const serial = std.math.add(u64, coordinatorBacking(self).participant_serial, 1) catch return error.GenerationExhausted;
            const last_component_serial = std.math.add(u64, coordinatorBacking(self).component_serial, catalog.len) catch return error.GenerationExhausted;
            for (catalog) |home| _ = try self.rowIndex(home.row);
            // The complete source/home set is validated before any catalog row
            // or component becomes visible. Only this closed fixture has a bridge.
            const slot = coordinatorBacking(self).participant_count;
            const first_component = coordinatorBacking(self).component_count;
            for (catalog, 0..) |home, i| {
                const index = first_component + i;
                const component_serial = coordinatorBacking(self).component_serial + i + 1;
                coordinatorBacking(self).components[index] = .{ .serial = component_serial, .row = home.row.slot, .category = home.category, .participant_slot = slot, .participant_serial = serial, .next_home = if (i + 1 == catalog.len) vacant else index + 1 };
                const first = index * coordinatorBacking(self).slots_per_home;
                const bucket_first = index * coordinatorBacking(self).buckets_per_home;
                const records = coordinatorBacking(self).allocations[first..][0..coordinatorBacking(self).slots_per_home];
                for (records, 0..) |*record, j| record.next_free = if (j + 1 == records.len) vacant else j + 1;
                coordinatorBacking(self).homes[index] = .{ .backend = coordinatorBacking(self).backend, .owner = self, .slot = index, .serial = component_serial, .records = records, .free_count = records.len, .buckets = coordinatorBacking(self).buckets[bucket_first..][0..coordinatorBacking(self).buckets_per_home] };
            }
            coordinatorBacking(self).participants[slot] = .{ .serial = serial, .source_lifetime = serial, .first_component = first_component, .component_count = catalog.len, .source = .{ .lifetime = serial } };
            coordinatorBacking(self).component_count += catalog.len;
            coordinatorBacking(self).component_serial = last_component_serial;
            coordinatorBacking(self).participant_count += 1;
            coordinatorBacking(self).participant_serial = serial;
            return .{ .owner = self, .identity = self, .instance = coordinatorBacking(self).instance, .slot = slot, .serial = serial };
        }
        fn componentId(self: *Coordinator, index: usize) ComponentId {
            const b = coordinatorBacking(self);
            return .{ .owner = self, .identity = self, .instance = b.instance, .slot = index, .serial = b.components[index].serial };
        }
        fn storeId(self: *Coordinator, slot: usize) StoreOwnerId {
            const b = coordinatorBacking(self);
            return .{ .owner = self, .identity = self, .instance = b.instance, .slot = slot, .serial = b.participants[slot].serial, .source_lifetime = b.participants[slot].managed.source.lifetime };
        }
        fn originalPosition(self: *Coordinator, address: usize) usize {
            const b = coordinatorBacking(self);
            var lo: usize = 0;
            var hi = b.original_span_count;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (b.original_spans[mid].address < address) lo = mid + 1 else hi = mid;
            }
            return lo;
        }
        fn sortOriginalSpans(_: *Coordinator, indices: []OriginalSpan) void {
            std.mem.sort(OriginalSpan, indices, {}, struct {
                fn less(_: void, a: OriginalSpan, c: OriginalSpan) bool {
                    return a.address < c.address;
                }
            }.less);
        }
        /// Closed source construction, not a public pointer/census importer.
        /// Its caller retains actual backend/Io/directory lifetimes throughout.
        fn constructStore(self: *Coordinator, spec: StoreSpec) !ParticipantId {
            const b = coordinatorBacking(self);
            if (b.phase != .idle or b.source_transition) return error.Busy;
            _ = try self.rowIndex(spec.row);
            if (b.participant_count == b.participants.len or store_home_count > b.components.len - b.component_count) return error.CapacityExceeded;
            const serial = std.math.add(u64, b.participant_serial, 1) catch return error.GenerationExhausted;
            const last_component = std.math.add(u64, b.component_serial, store_home_count) catch return error.GenerationExhausted;
            const slot = b.participant_count;
            b.participant_serial = serial; // Failed construction burns its identity.
            b.source_transition = true;
            defer b.source_transition = false;
            const p = &b.participants[slot];
            const previous_destruction = p.managed.destruction_serial;
            p.* = .{ .serial = serial, .source_binding = .store, .managed = .{ .phase = .reserved, .construction_serial = serial, .destruction_serial = previous_destruction, .expected_creation = store.CreationIdentity.from(spec.args) } };
            const c: StoreConstruction = .{ .owner = self, .identity = self, .instance = b.instance, .slot = slot, .serial = serial, .witness = @ptrCast(&p.managed.construction_anchor) };
            const source = StoreBridge.Owner.construct(c, spec.args) catch |err| {
                p.managed.phase = .dead;
                return err;
            };
            p.managed.owner = source;
            p.managed.phase = .pending;
            self.importConstructedStore(c, spec, last_component) catch |err| {
                // Every catalog/exclusion child has unwound before this call.
                try source.abortConstruction(c);
                p.managed.owner = null;
                p.managed.phase = .dead;
                return err;
            };
            return .{ .owner = self, .identity = self, .instance = b.instance, .slot = slot, .serial = serial };
        }
        fn importConstructedStore(self: *Coordinator, c: StoreConstruction, spec: StoreSpec, last_component: u64) !void {
            const b = coordinatorBacking(self);
            const p = &b.participants[c.slot];
            const m = &p.managed;
            const source = m.owner.?;
            if (comptime @import("builtin").is_test) {
                if (spec.seed_pending) try StoreBridge.TestFixture.seedPending(source, c);
                if (spec.seed_retirements) try StoreBridge.TestFixture.seedRetirementSlotsPending(source, c);
                if (spec.poison_pending) try StoreBridge.TestFixture.poisonPending(source, c);
            }
            var ordinary: ?store.PreparedPut = null;
            defer if (ordinary) |*ticket| ticket.abort();
            if (comptime @import("builtin").is_test) {
                if (spec.arm_ordinary) ordinary = try StoreBridge.TestFixture.armOrdinaryPut(source, c);
            }
            m.source = try source.constructionIdentity(c);
            if (m.source.lifetime == 0 or m.source.owner_revision == 0 or m.source.census_revision == 0) return error.InvalidPlan;
            try source.bindConstructed(c, self.storeId(c.slot));
            const exclusion = try source.acquireExclusive(self.storeId(c.slot));
            defer exclusion.finish() catch unreachable;
            var cursor = try source.catalog(exclusion);
            defer cursor.finish() catch unreachable;
            const base = b.component_count;
            const record_base = base * b.slots_per_home;
            var counts = [_]usize{ 0, 0 };
            var roots: usize = 0;
            var additions: Totals = .{};
            var committed = false;
            defer if (!committed) {
                @memset(b.allocations[record_base..][0 .. 2 * b.slots_per_home], .{});
            };
            while (try cursor.next()) |desc| {
                if (!std.meta.eql(desc.key.source, m.source) or desc.requested_bytes == 0 or desc.locator == 0 or desc.alignment == 0 or !std.math.isPowerOfTwo(desc.alignment) or desc.locator % desc.alignment != 0) return error.InvalidPlan;
                _ = std.math.add(usize, desc.locator, desc.requested_bytes) catch return error.CapacityExceeded;
                const origin: usize = switch (desc.key.location) {
                    .bridge_box, .owner_box => 0,
                    else => 1,
                };
                const backend = if (origin == 0) spec.args.metadata_allocator else spec.args.store_allocator;
                if (!std.meta.eql(desc.original_allocator, observedAllocator(backend))) return error.InvalidPlan;
                if (counts[origin] == b.slots_per_home or roots == b.original_spans.len - b.original_span_count) return error.CapacityExceeded;
                const index = (base + origin) * b.slots_per_home + counts[origin];
                const charge = try sum(desc.requested_bytes, desc.alignment - 1);
                b.allocations[index] = .{ .root = desc.key, .ptr = @ptrFromInt(desc.locator), .len = desc.requested_bytes, .alignment = .fromByteUnits(desc.alignment), .charge = charge, .serial = counts[origin] + 1, .state = if (desc.ownership == .retiring) .retiring else .resident };
                b.original_spans[b.original_span_count + roots] = .{ .address = desc.locator, .record = index };
                roots += 1;
                counts[origin] += 1;
                if (desc.ownership == .retiring) additions.retiring = try sum(additions.retiring, charge) else additions.resident = try sum(additions.resident, charge);
            }
            if (counts[0] != 2) return error.InvalidPlan;
            const staged = b.original_spans[b.original_span_count..][0..roots];
            self.sortOriginalSpans(staged);
            var previous_end: usize = 0;
            for (staged) |span| {
                const r = b.allocations[span.record];
                const start = @intFromPtr(r.ptr.?);
                const end = start + r.len; // Overflow was checked before staging.
                if (start < previous_end) return error.InvalidPlan;
                previous_end = end;
                const at = self.originalPosition(start);
                if (at < b.original_span_count and b.original_spans[at].address < end) return error.InvalidPlan;
                if (at != 0) {
                    const old = b.allocations[b.original_spans[at - 1].record];
                    if (@intFromPtr(old.ptr.?) + old.len > start) return error.InvalidPlan;
                }
            }
            const accounts = [_]usize{ 0, 1 + @as(usize, @intFromEnum(Category.graph)), 3 + spec.row.slot };
            var final: [3]Totals = undefined;
            for (accounts, 0..) |account_index, i| {
                const account_ = self.account(account_index);
                final[i] = account_.totals;
                final[i].resident = try sum(final[i].resident, additions.resident);
                final[i].retiring = try sum(final[i].retiring, additions.retiring);
                if (!final[i].permits(account_.limits)) return error.CapacityExceeded;
            }
            // Complete source, origins, spans, slots and budgets are validated.
            // Installation has no allocation, fallible lookup or source callback.
            for (0..store_home_count) |ordinal| {
                const index = base + ordinal;
                const component_serial = b.component_serial + ordinal + 1;
                b.components[index] = .{ .serial = component_serial, .row = spec.row.slot, .category = .graph, .participant_slot = c.slot, .participant_serial = p.serial, .next_home = if (ordinal + 1 == store_home_count) vacant else index + 1 };
                const records = b.allocations[index * b.slots_per_home ..][0..b.slots_per_home];
                const used = if (ordinal < 2) counts[ordinal] else 0;
                for (records[used..], used..) |*record, j| record.* = .{ .next_free = if (j + 1 == records.len) vacant else j + 1 };
                const buckets = b.buckets[index * b.buckets_per_home ..][0..b.buckets_per_home];
                @memset(buckets, vacant);
                const backend = switch (ordinal) {
                    0 => spec.args.metadata_allocator,
                    1 => spec.args.store_allocator,
                    else => spec.candidate_allocator,
                };
                b.homes[index] = .{ .backend = backend, .owner = self, .slot = index, .serial = component_serial, .records = records, .buckets = buckets, .free_head = if (used == records.len) vacant else used, .allocation_serial = used, .live_total = used, .free_count = records.len - used };
                for (0..used) |j| b.homes[index].insert(j);
            }
            for (staged) |span| self.linkAllocation(span.record / b.slots_per_home, span.record % b.slots_per_home, base);
            p.source_lifetime = m.source.lifetime;
            p.owner_revision = m.source.owner_revision;
            p.old_census_revision = m.source.census_revision;
            p.first_component = base;
            p.component_count = store_home_count;
            b.component_count += store_home_count;
            b.component_serial = last_component;
            b.participant_count += 1;
            b.original_span_count += roots;
            self.sortOriginalSpans(b.original_spans[0..b.original_span_count]);
            for (accounts, final) |account_index, value| self.account(account_index).totals = value;
            m.phase = .registered;
            committed = true;
        }
        fn acquireStore(self: *Coordinator, participant: ParticipantId) !void {
            const slot = try self.participantIndex(participant);
            const p = &coordinatorBacking(self).participants[slot];
            if (p.source_binding != .store or p.managed.phase != .registered or p.managed.exclusion != null) return error.Busy;
            p.managed.exclusion = try p.managed.owner.?.acquireExclusive(self.storeId(slot));
        }
        fn releaseStore(self: *Coordinator, participant: ParticipantId) !void {
            const slot = try self.participantIndex(participant);
            const b = coordinatorBacking(self);
            const m = &b.participants[slot].managed;
            if (b.phase != .idle or m.phase != .registered) return error.Busy;
            const exclusion = m.exclusion orelse return error.InvalidPlan;
            try exclusion.finish();
            m.exclusion = null;
        }
        fn addStorePlan(self: *Coordinator, builder: PlanBuilder, participant: ParticipantId, allowances: StoreAllowances) !void {
            if (builder.owner != self or allowances.work == 0 or allowances.work == std.math.maxInt(u64)) return error.InvalidPlan;
            const slot = try self.participantIndex(participant);
            const b = coordinatorBacking(self);
            const p = &b.participants[slot];
            if (p.source_binding != .store or p.managed.exclusion == null or p.managed.phase != .registered) return error.InvalidPlan;
            p.managed.plan_transaction = builder.serial;
            p.managed.roles = @splat(null);
            for (0..store_home_count) |ordinal| {
                const id = self.componentId(p.first_component + ordinal);
                const cap: @TypeOf(allowances.homes[0]) = if (ordinal < 2) .{ .peak = @as(u64, 0), .final = @as(u64, 0), .slots = @as(u32, 0) } else allowances.homes[ordinal - 2];
                try builder.addComponent(.{ .component = id, .expected_revision = b.components[id.slot].revision, .new_capacity_peak = cap.peak, .final_new_capacity_max = cap.final, .final_wire_addition_max = 0, .new_allocation_slots = cap.slots });
            }
            try builder.addParticipant(.{ .participant = participant, .expected_owner_revision = p.owner_revision, .expected_old_census_revision = p.old_census_revision, .work_units = allowances.work });
            for (allowances.uses, 0..) |cap, i| {
                if (cap.charge == 0 and cap.slots == 0) continue;
                if (cap.charge == 0 or cap.slots == 0) return error.InvalidPlan;
                const purpose: store.CandidateUse = @enumFromInt(i);
                const origin = self.componentId(p.first_component + candidateHome(purpose));
                p.managed.roles[i] = try builder.addNewRole(.{ .origin = origin, .expected_origin_revision = b.components[origin.slot].revision, .label = @intCast(i), .kind = switch (purpose) {
                    .packet, .scratch_key => .{ .discard = .finish },
                    else => .{ .retain = self.componentId(p.first_component) },
                }, .max_charge = cap.charge, .max_live_allocations = cap.slots });
            }
            var next = b.components[p.first_component].owned_head;
            while (next != vacant) {
                const r = b.allocations[next];
                const origin = next / b.slots_per_home;
                try builder.addOwnership(.{ .allocation = .{ .owner = self, .identity = self, .instance = b.instance, .home_slot = origin, .home_serial = b.homes[origin].serial, .allocation_slot = next % b.slots_per_home, .serial = r.serial }, .expected_owner = self.componentId(p.first_component), .expected_owner_revision = b.components[p.first_component].revision, .expected_length = r.len, .expected_alignment = r.alignment, .disposition = if (r.state == .retiring) .keep_retiring else .keep });
                next = r.owner_next;
            }
        }
        fn destroyStore(self: *Coordinator, participant: ParticipantId) !void {
            const slot = try self.participantIndex(participant);
            const b = coordinatorBacking(self);
            const p = &b.participants[slot];
            const m = &p.managed;
            if (b.phase != .idle or b.source_transition or p.source_binding != .store or m.phase != .registered or m.exclusion != null) return error.Busy;
            b.source_transition = true;
            defer b.source_transition = false;
            const source = m.owner.?;
            {
                const exclusion = try source.acquireExclusive(self.storeId(slot));
                defer exclusion.finish() catch unreachable;
                const view = try source.inspectQuiescence(exclusion);
                if (view.candidate_active or view.catalog_active or view.ordinary_active or view.staged_active or view.readers != 0 or !std.meta.eql(view.source, m.source)) return error.ParticipantsHeld;
                var cursor = try source.catalog(exclusion);
                defer cursor.finish() catch unreachable;
                var count: usize = 0;
                while (try cursor.next()) |desc| {
                    const at = self.originalPosition(desc.locator);
                    if (at == b.original_span_count) return error.InvalidPlan;
                    const index = b.original_spans[at].record;
                    const r = b.allocations[index];
                    if (@intFromPtr(r.ptr.?) != desc.locator or r.root == null or !std.meta.eql(r.root.?, desc.key) or r.len != desc.requested_bytes or r.alignment.toByteUnits() != desc.alignment or !std.meta.eql(observedAllocator(b.homes[index / b.slots_per_home].backend), desc.original_allocator) or (r.state == .retiring) != (desc.ownership == .retiring) or r.encumbered_transaction != 0 or b.components[r.logical_owner].participant_slot != slot) return error.InvalidPlan;
                    count += 1;
                }
                if (count != b.components[p.first_component].owned_count) return error.InvalidPlan;
                for (0..p.component_count) |i| if (b.homes[p.first_component + i].live_new != 0) return error.AllocationsHeld;
            }
            m.destruction_serial = std.math.add(u64, m.destruction_serial, 1) catch return error.GenerationExhausted;
            const d: StoreDestruction = .{ .owner = self, .identity = self, .instance = b.instance, .slot = slot, .serial = m.destruction_serial, .source_lifetime = m.source.lifetime, .witness = @ptrCast(&m.destruction_anchor) };
            m.phase = .destruction_armed;
            try source.destroyRegistered(d);
            std.debug.assert(b.components[p.first_component].owned_count == 0);
            m.owner = null;
            m.phase = .dead;
            var write: usize = 0;
            for (b.original_spans[0..b.original_span_count]) |span| {
                if (span.record == vacant) continue;
                b.original_spans[write] = span;
                write += 1;
            }
            b.original_span_count = write;
        }

        fn rowIndex(self: *Coordinator, handle: RowHandle) Failure!usize {
            if (handle.owner != self or handle.identity != self or !handle.instance.eql(coordinatorBacking(self).instance) or handle.slot >= coordinatorBacking(self).row_count) return error.StaleTicket;
            const row = coordinatorBacking(self).rows[handle.slot];
            if (row.id != handle.id or row.generation != handle.generation) return error.StaleTicket;
            return handle.slot;
        }
        fn componentIndex(self: *Coordinator, handle: ComponentId) Failure!usize {
            if (handle.owner != self or handle.identity != self or !handle.instance.eql(coordinatorBacking(self).instance) or handle.serial == 0 or handle.slot >= coordinatorBacking(self).component_count) return error.StaleTicket;
            if (coordinatorBacking(self).components[handle.slot].serial != handle.serial) return error.StaleTicket;
            return handle.slot;
        }
        fn participantIndex(self: *Coordinator, id: ParticipantId) Failure!usize {
            if (id.owner != self or id.identity != self or !id.instance.eql(coordinatorBacking(self).instance) or id.serial == 0 or id.slot >= coordinatorBacking(self).participant_count) return error.StaleTicket;
            if (coordinatorBacking(self).participants[id.slot].serial != id.serial) return error.StaleTicket;
            return id.slot;
        }
        fn homeIssued(self: *Coordinator, component_slot: usize, transaction: u64) bool {
            const component = coordinatorBacking(self).components[component_slot];
            if (component.participant_slot >= coordinatorBacking(self).participant_count) return false;
            const participant = coordinatorBacking(self).participants[component.participant_slot];
            if (participant.serial != component.participant_serial or participant.seen_transaction != transaction or participant.plan_index >= coordinatorBacking(self).participant_entry_count) return false;
            const entry = coordinatorBacking(self).participant_entries[participant.plan_index];
            return entry.participant_slot == component.participant_slot and entry.state == .issued;
        }
        fn releaseAbortedParticipant(self: *Coordinator, loan: ParticipantLoan) Failure!void {
            const slot = try loan.validateIssued();
            if (loan.owner != self) return error.StaleTicket;
            const participant = &coordinatorBacking(self).participants[slot];
            const entry = &coordinatorBacking(self).participant_entries[participant.plan_index];
            try self.validateParticipantSource(entry.*, true);
            var next = participant.first_component;
            while (next != vacant) {
                const home = coordinatorBacking(self).homes[next];
                if (home.live_new != 0 or home.actual_new != 0) return error.AllocationsHeld;
                const component_entry = coordinatorBacking(self).entries[coordinatorBacking(self).components[next].plan_index];
                if (component_entry.retained_actual != 0) return error.AllocationsHeld;
                if (component_entry.role_count != 0) {
                    for (coordinatorBacking(self).role_order[component_entry.role_start..][0..component_entry.role_count]) |role_slot| {
                        const role = coordinatorBacking(self).roles[role_slot];
                        if (role.origin != next) return error.InvalidPlan;
                        if (role.actual_count != 0 or role.actual_charge != 0) return error.AllocationsHeld;
                    }
                }
                next = coordinatorBacking(self).components[next].next_home;
            }
            // All source, allocation and role state was checked before any home
            // is disabled. Whole reservations remain held until tx.abort.
            next = participant.first_component;
            while (next != vacant) {
                coordinatorBacking(self).homes[next].active_transaction = 0;
                next = coordinatorBacking(self).components[next].next_home;
            }
            entry.state = .released;
            if (comptime @import("builtin").is_test) {
                if (participant.source_binding == .fixture) participant.source.loan = null;
            }
        }
        fn validateParticipantSource(self: *Coordinator, entry: ParticipantEntry, require_idle: bool) Failure!void {
            const slot = try self.participantIndex(entry.copied_plan.participant);
            if (slot != entry.participant_slot) return error.StaleTicket;
            const participant = &coordinatorBacking(self).participants[slot];
            if (participant.owner_revision != entry.copied_plan.expected_owner_revision or participant.old_census_revision != entry.copied_plan.expected_old_census_revision) return error.StaleTicket;
            if (participant.source_binding == .store) {
                const m = &participant.managed;
                if (m.phase != .registered or entry.copied_plan.work_units == 0 or entry.copied_plan.work_units == std.math.maxInt(u64)) return error.InvalidPlan;
                const exclusion = m.exclusion orelse return error.ParticipantsHeld;
                const actual = m.owner.?.inspectQuiescence(exclusion) catch return error.ParticipantsHeld;
                if (actual.source.lifetime != participant.source_lifetime or actual.source.owner_revision != entry.copied_plan.expected_owner_revision or actual.source.census_revision != entry.copied_plan.expected_old_census_revision) return error.StaleTicket;
                if (actual.ordinary_active or actual.staged_active or actual.poisoned) return error.ParticipantsHeld;
                if (require_idle and (actual.candidate_active or actual.catalog_active or actual.readers != 0)) return error.ParticipantsHeld;
            } else if (comptime @import("builtin").is_test) {
                const actual = participant.source.describeAbortState();
                if (actual.lifetime != participant.source_lifetime or actual.lifetime != participant.serial or actual.revision != entry.copied_plan.expected_owner_revision or actual.census_revision != entry.copied_plan.expected_old_census_revision) return error.StaleTicket;
                if (require_idle and !actual.idle) return error.ParticipantsHeld;
            } else return error.InvalidPlan;
        }
        fn validateParticipantCoverage(self: *Coordinator) Failure!void {
            // Repeated finish attempts reset only the participants already touched.
            for (coordinatorBacking(self).participant_entries[0..coordinatorBacking(self).participant_entry_count]) |*entry| entry.planned_component_count = 0;
            for (coordinatorBacking(self).entries[0..coordinatorBacking(self).entry_count]) |entry| {
                const component = coordinatorBacking(self).components[entry.index];
                if (component.participant_slot >= coordinatorBacking(self).participant_count) return error.InvalidPlan;
                const participant = coordinatorBacking(self).participants[component.participant_slot];
                if (participant.serial != component.participant_serial or participant.seen_transaction != coordinatorBacking(self).serial) return error.InvalidPlan;
                const planned = &coordinatorBacking(self).participant_entries[participant.plan_index];
                if (planned.participant_slot != component.participant_slot) return error.InvalidPlan;
                planned.planned_component_count = std.math.add(usize, planned.planned_component_count, 1) catch return error.CapacityExceeded;
            }
            for (coordinatorBacking(self).participant_entries[0..coordinatorBacking(self).participant_entry_count]) |entry| {
                const participant = coordinatorBacking(self).participants[entry.participant_slot];
                if (participant.component_count == 0 or entry.planned_component_count != participant.component_count) return error.InvalidPlan;
                try self.validateParticipantSource(entry, true);
                if (participant.source_binding == .store) {
                    if (participant.managed.plan_transaction != coordinatorBacking(self).serial) return error.InvalidPlan;
                    for (participant.managed.roles, 0..) |maybe_role, use_index| if (maybe_role) |id| {
                        const role = coordinatorBacking(self).roles[try self.roleIndex(id)];
                        const purpose: store.CandidateUse = @enumFromInt(use_index);
                        if (role.origin != participant.first_component + candidateHome(purpose)) return error.InvalidPlan;
                        const receiver = switch (purpose) {
                            .packet, .scratch_key => vacant,
                            else => participant.first_component,
                        };
                        if (role.receiver != receiver or role.plan.label != use_index) return error.InvalidPlan;
                    };
                }
            }
        }
        pub fn beginPlan(self: *Coordinator, expected_revision: u64) Failure!PlanBuilder {
            if (coordinatorBacking(self).phase != .idle or coordinatorBacking(self).source_transition) return error.Busy;
            if (expected_revision != coordinatorBacking(self).revision) return error.StaleTicket;
            coordinatorBacking(self).serial = std.math.add(u64, coordinatorBacking(self).serial, 1) catch return error.GenerationExhausted;
            coordinatorBacking(self).entry_count = 0;
            coordinatorBacking(self).ownership_count = 0;
            coordinatorBacking(self).role_count = 0;
            coordinatorBacking(self).participant_entry_count = 0;
            coordinatorBacking(self).phase = .planning;
            return .{ .owner = self, .identity = self, .instance = coordinatorBacking(self).instance, .serial = coordinatorBacking(self).serial };
        }
        fn validate(self: *Coordinator, serial: u64, phase: Phase) Failure!void {
            if (serial != coordinatorBacking(self).serial or coordinatorBacking(self).phase != phase) return error.StaleTicket;
        }
        pub fn beginTransaction(self: *Coordinator, plan: CanonicalPlanView) Failure!TransactionReservation {
            if (plan.owner != self or plan.identity != self or !plan.instance.eql(coordinatorBacking(self).instance)) return error.StaleTicket;
            try self.validate(plan.serial, .canonical);
            try self.validateParticipantCoverage();
            var work_total: u64 = 0;
            for (coordinatorBacking(self).participant_entries[0..coordinatorBacking(self).participant_entry_count]) |entry| work_total = try sum(work_total, entry.copied_plan.work_units);
            if (work_total > coordinatorBacking(self).transaction_work_max) return error.CapacityExceeded;
            // Reset only the accounts visited by the previous attempt. Failed
            // admission may leave scratch here, never published reservations.
            for (coordinatorBacking(self).touched[0..coordinatorBacking(self).touched_count]) |i| coordinatorBacking(self).holds[i] = .{};
            coordinatorBacking(self).touched_count = 0;
            for (coordinatorBacking(self).entries[0..coordinatorBacking(self).entry_count]) |entry| {
                const index = try self.componentIndex(entry.plan.component);
                if (index != entry.index or coordinatorBacking(self).components[index].revision != entry.plan.expected_revision) return error.StaleTicket;
                const component = coordinatorBacking(self).components[index];
                if (entry.plan.new_allocation_slots > coordinatorBacking(self).homes[index].free_count) return error.CapacityExceeded;
                std.debug.assert(coordinatorBacking(self).homes[index].live_new == 0 and coordinatorBacking(self).homes[index].active_transaction == 0);
                const hold: Holds = .{ .preparation = entry.plan.new_capacity_peak, .wire = entry.plan.final_wire_addition_max };
                try self.accumulate(0, hold);
                try self.accumulate(1 + @as(usize, @intFromEnum(component.category)), hold);
                try self.accumulate(3 + component.row, hold);
            }
            try self.accumulateRolePlacements();
            try self.validateOwnershipClosure();
            for (coordinatorBacking(self).ownership[0..coordinatorBacking(self).ownership_count]) |entry| {
                try self.validateOwnership(entry);
                const record = coordinatorBacking(self).allocations[entry.record];
                const source = coordinatorBacking(self).components[record.logical_owner];
                switch (entry.declaration.disposition) {
                    .keep, .keep_retiring => {},
                    .retire => {
                        const hold: Holds = .{ .old_retire = record.charge };
                        try self.accumulate(0, hold);
                        try self.accumulate(1 + @as(usize, @intFromEnum(source.category)), hold);
                        try self.accumulate(3 + source.row, hold);
                    },
                    .move => {
                        const receiver = coordinatorBacking(self).components[entry.receiver];
                        if (source.category != receiver.category) {
                            try self.accumulate(1 + @as(usize, @intFromEnum(source.category)), .{ .outgoing = record.charge });
                            try self.accumulate(1 + @as(usize, @intFromEnum(receiver.category)), .{ .incoming = record.charge });
                        }
                        if (source.row != receiver.row) {
                            try self.accumulate(3 + source.row, .{ .outgoing = record.charge });
                            try self.accumulate(3 + receiver.row, .{ .incoming = record.charge });
                        }
                        // Same-fleet moves never allocate a second backing.
                    },
                }
            }
            // Validation reads every account before any reservation is published.
            for (coordinatorBacking(self).touched[0..coordinatorBacking(self).touched_count]) |i| {
                const domain = self.account(i);
                try coordinatorBacking(self).holds[i].derive(domain.totals);
                const hold = coordinatorBacking(self).holds[i];
                if (!(try hold.funded(domain.totals)).permits(domain.limits)) return error.CapacityExceeded;
            }
            for (coordinatorBacking(self).touched[0..coordinatorBacking(self).touched_count]) |i| {
                const hold = coordinatorBacking(self).holds[i];
                const domain = self.account(i);
                domain.totals = hold.funded(domain.totals) catch unreachable;
            }
            for (coordinatorBacking(self).entries[0..coordinatorBacking(self).entry_count]) |entry| {
                const home = &coordinatorBacking(self).homes[entry.index];
                home.peak = entry.plan.new_capacity_peak;
                home.slot_allowance = entry.plan.new_allocation_slots;
            }
            for (coordinatorBacking(self).ownership[0..coordinatorBacking(self).ownership_count]) |entry| coordinatorBacking(self).allocations[entry.record].encumbered_transaction = coordinatorBacking(self).serial;
            for (coordinatorBacking(self).participant_entries[0..coordinatorBacking(self).participant_entry_count]) |*entry| entry.state = .funded;
            coordinatorBacking(self).phase = .funded;
            return .{ .owner = self, .identity = self, .instance = coordinatorBacking(self).instance, .serial = coordinatorBacking(self).serial };
        }
        fn allocationIndex(self: *Coordinator, id: AllocationId) Failure!usize {
            if (id.owner != self or id.identity != self or !id.instance.eql(coordinatorBacking(self).instance) or id.home_slot >= coordinatorBacking(self).component_count) return error.StaleTicket;
            const home = coordinatorBacking(self).homes[id.home_slot];
            if (id.home_serial != home.serial or id.allocation_slot >= home.records.len) return error.StaleTicket;
            const record = home.records[id.allocation_slot];
            if (record.ptr == null or record.serial != id.serial or record.state == .free) return error.StaleTicket;
            return id.home_slot * coordinatorBacking(self).slots_per_home + id.allocation_slot;
        }
        fn roleIndex(self: *Coordinator, id: RoleId) Failure!usize {
            if (id.owner != self or id.identity != self or !id.instance.eql(coordinatorBacking(self).instance) or id.transaction != coordinatorBacking(self).serial or id.slot >= coordinatorBacking(self).role_count) return error.StaleTicket;
            if (coordinatorBacking(self).roles[id.slot].serial != id.serial) return error.StaleTicket;
            return id.slot;
        }
        fn validateRole(self: *Coordinator, role: RoleEntry) Failure!void {
            const origin = try self.componentIndex(role.plan.origin);
            if (origin != role.origin or coordinatorBacking(self).components[origin].seen_transaction != coordinatorBacking(self).serial or coordinatorBacking(self).components[origin].revision != role.plan.expected_origin_revision) return error.StaleTicket;
            if (role.receiver != vacant) {
                const receiver = switch (role.plan.kind) {
                    .retain => |id| try self.componentIndex(id),
                    else => return error.InvalidPlan,
                };
                if (receiver != role.receiver or coordinatorBacking(self).components[receiver].seen_transaction != coordinatorBacking(self).serial) return error.StaleTicket;
            }
        }
        fn accumulateRolePlacements(self: *Coordinator) Failure!void {
            var count: usize = 0;
            for (coordinatorBacking(self).roles[0..coordinatorBacking(self).role_count]) |role| {
                try self.validateRole(role);
                const target = coordinatorBacking(self).components[if (role.receiver == vacant) role.origin else role.receiver];
                const accounts = [_]usize{ 0, 1 + @as(usize, @intFromEnum(target.category)), 3 + target.row };
                for (accounts) |a| {
                    coordinatorBacking(self).role_contributions[count] = .{ .origin = role.origin, .account = a, .retain = if (role.receiver != vacant) role.plan.max_charge else 0, .discard = if (role.receiver == vacant) role.plan.max_charge else 0 };
                    count += 1;
                }
            }
            const contributions = coordinatorBacking(self).role_contributions[0..count];
            std.mem.sort(RoleContribution, contributions, {}, struct {
                fn less(_: void, a: RoleContribution, b: RoleContribution) bool {
                    return a.origin < b.origin or (a.origin == b.origin and a.account < b.account);
                }
            }.less);
            var i: usize = 0;
            while (i < count) {
                const first = contributions[i];
                const source = coordinatorBacking(self).components[first.origin];
                const plan = coordinatorBacking(self).entries[source.plan_index].plan;
                var retain: u64 = 0;
                var discard: u64 = 0;
                while (i < count and contributions[i].origin == first.origin and contributions[i].account == first.account) : (i += 1) {
                    retain = cappedAdd(retain, contributions[i].retain, plan.final_new_capacity_max);
                    discard = cappedAdd(discard, contributions[i].discard, plan.new_capacity_peak);
                }
                const inside = first.account == 0 or first.account == 1 + @as(usize, @intFromEnum(source.category)) or first.account == 3 + source.row;
                std.debug.assert(inside or discard == 0);
                const publication = if (inside) cappedAdd(discard, retain, plan.new_capacity_peak) else retain;
                try self.accumulate(first.account, .{ .resident = retain, .publication_new = publication });
            }
        }
        fn releaseRole(self: *Coordinator, record: Allocation) void {
            if (record.role_slot == vacant) return;
            const role = &coordinatorBacking(self).roles[record.role_slot];
            std.debug.assert(role.origin == record.logical_owner and role.actual_count > 0 and role.actual_charge >= record.charge);
            role.actual_count -= 1;
            role.actual_charge -= record.charge;
            if (role.receiver != vacant) coordinatorBacking(self).entries[coordinatorBacking(self).components[role.origin].plan_index].retained_actual -= record.charge;
        }
        // Structural closure only; actual source-owned semantic receipts and
        // claims must join the future private seal. This is not a public seal.
        fn validateNewClosure(self: *Coordinator) Failure!void {
            for (coordinatorBacking(self).entries[0..coordinatorBacking(self).entry_count]) |entry| {
                var next = coordinatorBacking(self).components[entry.index].owned_head;
                while (next != vacant) {
                    const record = coordinatorBacking(self).allocations[next];
                    if (record.state == .candidate) {
                        if (record.transaction != coordinatorBacking(self).serial or record.role_slot == vacant) return error.InvalidPlan;
                        const role = coordinatorBacking(self).roles[record.role_slot];
                        if (role.origin != entry.index or role.actual_charge > role.plan.max_charge or role.actual_count > role.plan.max_live_allocations) return error.InvalidPlan;
                    }
                    next = record.owner_next;
                }
                if (entry.retained_actual > entry.plan.final_new_capacity_max) return error.InvalidPlan;
            }
        }
        fn linkAllocation(self: *Coordinator, home: usize, slot: usize, logical: usize) void {
            const index = home * coordinatorBacking(self).slots_per_home + slot;
            const component = &coordinatorBacking(self).components[logical];
            const record = &coordinatorBacking(self).allocations[index];
            record.logical_owner = logical;
            record.logical_owner_serial = component.serial;
            record.owner_next = component.owned_head;
            if (component.owned_head != vacant) coordinatorBacking(self).allocations[component.owned_head].owner_prev = index;
            component.owned_head = index;
            component.owned_count += 1;
            component.owned_charge += record.charge;
        }
        fn unlinkAllocation(self: *Coordinator, home: usize, slot: usize) void {
            const index = home * coordinatorBacking(self).slots_per_home + slot;
            const record = coordinatorBacking(self).allocations[index];
            const component = &coordinatorBacking(self).components[record.logical_owner];
            std.debug.assert(component.serial == record.logical_owner_serial);
            if (record.owner_prev == vacant) component.owned_head = record.owner_next else coordinatorBacking(self).allocations[record.owner_prev].owner_next = record.owner_next;
            if (record.owner_next != vacant) coordinatorBacking(self).allocations[record.owner_next].owner_prev = record.owner_prev;
            component.owned_count -= 1;
            component.owned_charge -= record.charge;
        }
        fn validateOwnership(self: *Coordinator, entry: OwnershipEntry) Failure!void {
            if (try self.allocationIndex(entry.declaration.allocation) != entry.record) return error.StaleTicket;
            const source = try self.componentIndex(entry.declaration.expected_owner);
            const record = coordinatorBacking(self).allocations[entry.record];
            if ((record.state != .resident and record.state != .retiring) or record.logical_owner != source or record.logical_owner_serial != entry.declaration.expected_owner.serial or record.encumbered_transaction != 0) return error.StaleTicket;
            if (coordinatorBacking(self).components[source].seen_transaction != coordinatorBacking(self).serial or coordinatorBacking(self).components[source].revision != entry.declaration.expected_owner_revision) return error.StaleTicket;
            if ((record.state == .retiring) != (entry.declaration.disposition == .keep_retiring)) return error.InvalidPlan;
            if (record.len != entry.declaration.expected_length or record.alignment != entry.declaration.expected_alignment) return error.InvalidPlan;
            if (entry.receiver != vacant) {
                const receiver = switch (entry.declaration.disposition) {
                    .move => |destination| try self.componentIndex(destination),
                    else => return error.InvalidPlan,
                };
                if (receiver != entry.receiver or coordinatorBacking(self).components[receiver].seen_transaction != coordinatorBacking(self).serial) return error.StaleTicket;
            }
        }
        fn validateOwnershipClosure(self: *Coordinator) Failure!void {
            for (coordinatorBacking(self).entries[0..coordinatorBacking(self).entry_count]) |entry| {
                const component = coordinatorBacking(self).components[entry.index];
                var next = component.owned_head;
                var count: usize = 0;
                while (next != vacant) {
                    if (next >= coordinatorBacking(self).allocations.len or count >= component.owned_count) return error.InvalidPlan;
                    const record = coordinatorBacking(self).allocations[next];
                    if ((record.state != .resident and record.state != .retiring) or record.logical_owner != entry.index or record.logical_owner_serial != component.serial or record.declared_transaction != coordinatorBacking(self).serial) return error.InvalidPlan;
                    count += 1;
                    next = record.owner_next;
                }
                if (count != component.owned_count) return error.InvalidPlan;
            }
        }
        fn accumulate(self: *Coordinator, i: usize, hold: Holds) Failure!void {
            if (!coordinatorBacking(self).holds[i].listed) {
                coordinatorBacking(self).touched[coordinatorBacking(self).touched_count] = i;
                coordinatorBacking(self).touched_count += 1;
                coordinatorBacking(self).holds[i].listed = true;
            }
            try coordinatorBacking(self).holds[i].add(hold);
        }
        fn account(self: *Coordinator, i: usize) *Account {
            return if (i == 0) &coordinatorBacking(self).fleet else if (i < 3) &coordinatorBacking(self).categories[i - 1] else &coordinatorBacking(self).rows[i - 3].account;
        }
    };
    pub const PlanBuilder = struct {
        owner: *Coordinator,
        identity: *Coordinator,
        instance: FleetInstance,
        serial: u64,
        pub fn addParticipant(self: PlanBuilder, plan: ParticipantPlan) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.owner.validate(self.serial, .planning);
            const slot = try self.owner.participantIndex(plan.participant);
            const participant = &coordinatorBacking(self.owner).participants[slot];
            if (participant.seen_transaction == self.serial) return error.InvalidPlan;
            if (coordinatorBacking(self.owner).participant_entry_count == coordinatorBacking(self.owner).participant_entries.len) return error.CapacityExceeded;
            const entry: ParticipantEntry = .{ .copied_plan = plan, .participant_slot = slot };
            try self.owner.validateParticipantSource(entry, true);
            const index = coordinatorBacking(self.owner).participant_entry_count;
            coordinatorBacking(self.owner).participant_entries[index] = entry;
            coordinatorBacking(self.owner).participant_order[index] = index;
            coordinatorBacking(self.owner).participant_entry_count += 1;
            participant.seen_transaction = self.serial;
            participant.plan_index = index;
        }
        pub fn addComponent(self: PlanBuilder, plan: ComponentPlan) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.owner.validate(self.serial, .planning);
            if (plan.final_new_capacity_max > plan.new_capacity_peak) return error.InvalidPlan;
            const index = try self.owner.componentIndex(plan.component);
            if (plan.expected_revision != coordinatorBacking(self.owner).components[index].revision) return error.StaleTicket;
            if (coordinatorBacking(self.owner).components[index].seen_transaction == self.serial) return error.InvalidPlan;
            if (coordinatorBacking(self.owner).entry_count == coordinatorBacking(self.owner).entries.len) return error.CapacityExceeded;
            coordinatorBacking(self.owner).entries[coordinatorBacking(self.owner).entry_count] = .{ .plan = plan, .index = index };
            coordinatorBacking(self.owner).components[index].plan_index = coordinatorBacking(self.owner).entry_count;
            coordinatorBacking(self.owner).entry_count += 1;
            coordinatorBacking(self.owner).components[index].seen_transaction = self.serial;
        }
        pub fn addNewRole(self: PlanBuilder, plan: RolePlan) Failure!RoleId {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.owner.validate(self.serial, .planning);
            if (plan.max_charge == 0 or plan.max_live_allocations == 0) return error.InvalidPlan;
            const origin = try self.owner.componentIndex(plan.origin);
            const receiver = switch (plan.kind) {
                .retain => |id| try self.owner.componentIndex(id),
                .discard => vacant,
            };
            const serial = std.math.add(u64, coordinatorBacking(self.owner).role_serial, 1) catch return error.GenerationExhausted;
            const entry: RoleEntry = .{ .plan = plan, .origin = origin, .receiver = receiver, .serial = serial };
            try self.owner.validateRole(entry);
            const source = &coordinatorBacking(self.owner).entries[coordinatorBacking(self.owner).components[origin].plan_index];
            if (source.plan.new_capacity_peak == 0) return error.InvalidPlan;
            if (coordinatorBacking(self.owner).role_count == coordinatorBacking(self.owner).roles.len) return error.CapacityExceeded;
            coordinatorBacking(self.owner).role_serial = serial;
            const slot = coordinatorBacking(self.owner).role_count;
            coordinatorBacking(self.owner).roles[slot] = entry;
            coordinatorBacking(self.owner).role_order[slot] = slot;
            coordinatorBacking(self.owner).role_count += 1;
            source.role_count += 1;
            return .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .transaction = self.serial, .slot = slot, .serial = serial };
        }
        pub fn addOwnership(self: PlanBuilder, declaration: AllocationDeclaration) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.owner.validate(self.serial, .planning);
            const index = try self.owner.allocationIndex(declaration.allocation);
            const receiver = switch (declaration.disposition) {
                .move => |destination| try self.owner.componentIndex(destination),
                else => vacant,
            };
            const entry: OwnershipEntry = .{ .declaration = declaration, .record = index, .receiver = receiver };
            try self.owner.validateOwnership(entry);
            const record = &coordinatorBacking(self.owner).allocations[index];
            if (record.declared_transaction == self.serial) return error.InvalidPlan;
            if (coordinatorBacking(self.owner).ownership_count == coordinatorBacking(self.owner).ownership.len) return error.CapacityExceeded;
            coordinatorBacking(self.owner).ownership[coordinatorBacking(self.owner).ownership_count] = entry;
            coordinatorBacking(self.owner).ownership_count += 1;
            record.declared_transaction = self.serial; // Scratch stamp only.
        }
        pub fn finish(self: PlanBuilder) Failure!CanonicalPlanView {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.owner.validate(self.serial, .planning);
            if (coordinatorBacking(self.owner).entry_count == 0) return error.InvalidPlan;
            try self.owner.validateParticipantCoverage();
            for (coordinatorBacking(self.owner).entries[0..coordinatorBacking(self.owner).entry_count]) |entry| {
                if ((entry.plan.new_capacity_peak != 0 or entry.plan.new_allocation_slots != 0) and entry.role_count == 0) return error.InvalidPlan;
            }
            const order = coordinatorBacking(self.owner).role_order[0..coordinatorBacking(self.owner).role_count];
            std.mem.sort(usize, order, self.owner, struct {
                fn less(owner: *Coordinator, a: usize, b: usize) bool {
                    const x = coordinatorBacking(owner).roles[a];
                    const y = coordinatorBacking(owner).roles[b];
                    return x.plan.origin.serial < y.plan.origin.serial or (x.plan.origin.serial == y.plan.origin.serial and x.plan.label < y.plan.label);
                }
            }.less);
            for (order, 0..) |slot, i| {
                if (i == 0) continue;
                const a = coordinatorBacking(self.owner).roles[order[i - 1]];
                const b = coordinatorBacking(self.owner).roles[slot];
                if (a.origin == b.origin and a.plan.label == b.plan.label) return error.InvalidPlan;
            }
            try self.owner.validateOwnershipClosure();
            // Fixture is the only available closed source kind, with one lock
            // rank. Stable catalog serial orders its owners, never their storage.
            std.mem.sort(usize, coordinatorBacking(self.owner).participant_order[0..coordinatorBacking(self.owner).participant_entry_count], self.owner, struct {
                fn less(owner: *Coordinator, a: usize, b: usize) bool {
                    return coordinatorBacking(owner).participant_entries[a].copied_plan.participant.serial < coordinatorBacking(owner).participant_entries[b].copied_plan.participant.serial;
                }
            }.less);
            std.mem.sort(OwnershipEntry, coordinatorBacking(self.owner).ownership[0..coordinatorBacking(self.owner).ownership_count], {}, ownershipLess);
            std.mem.sort(Entry, coordinatorBacking(self.owner).entries[0..coordinatorBacking(self.owner).entry_count], self.owner, less);
            for (coordinatorBacking(self.owner).entries[0..coordinatorBacking(self.owner).entry_count], 0..) |entry, i| coordinatorBacking(self.owner).components[entry.index].plan_index = i;
            for (order, 0..) |role_slot, i| {
                const origin = coordinatorBacking(self.owner).roles[role_slot].origin;
                if (i == 0 or coordinatorBacking(self.owner).roles[order[i - 1]].origin != origin) coordinatorBacking(self.owner).entries[coordinatorBacking(self.owner).components[origin].plan_index].role_start = i;
            }
            coordinatorBacking(self.owner).phase = .canonical;
            return .{ .owner = self.owner, .identity = self.owner, .instance = self.instance, .serial = self.serial };
        }
        pub fn abort(self: PlanBuilder) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            if (coordinatorBacking(self.owner).phase != .planning and coordinatorBacking(self.owner).phase != .canonical) return error.StaleTicket;
            if (self.serial != coordinatorBacking(self.owner).serial) return error.StaleTicket;
            coordinatorBacking(self.owner).phase = .idle;
            coordinatorBacking(self.owner).entry_count = 0;
            coordinatorBacking(self.owner).ownership_count = 0;
            coordinatorBacking(self.owner).role_count = 0;
            coordinatorBacking(self.owner).participant_entry_count = 0;
        }
        fn ownershipLess(_: void, a: OwnershipEntry, b: OwnershipEntry) bool {
            const x = a.declaration.allocation;
            const y = b.declaration.allocation;
            if (x.home_serial != y.home_serial) return x.home_serial < y.home_serial;
            return x.serial < y.serial;
        }
        fn less(owner: *Coordinator, a: Entry, b: Entry) bool {
            const ca = coordinatorBacking(owner).components[a.index];
            const cb = coordinatorBacking(owner).components[b.index];
            if (ca.category != cb.category) return @intFromEnum(ca.category) < @intFromEnum(cb.category);
            if (coordinatorBacking(owner).rows[ca.row].id != coordinatorBacking(owner).rows[cb.row].id) return coordinatorBacking(owner).rows[ca.row].id < coordinatorBacking(owner).rows[cb.row].id;
            return ca.serial < cb.serial;
        }
    };
    pub const CanonicalPlanView = struct { owner: *Coordinator, identity: *Coordinator, instance: FleetInstance, serial: u64 };
    pub const TransactionReservation = struct {
        owner: *Coordinator,
        identity: *Coordinator,
        instance: FleetInstance,
        serial: u64,
        pub fn participantLoan(self: TransactionReservation, id: ParticipantId) Failure!ParticipantLoan {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.validate();
            const slot = try self.owner.participantIndex(id);
            const participant = &coordinatorBacking(self.owner).participants[slot];
            if (participant.seen_transaction != self.serial) return error.StaleTicket;
            const entry = &coordinatorBacking(self.owner).participant_entries[participant.plan_index];
            if (entry.state != .funded) return error.StaleTicket;
            try self.owner.validateParticipantSource(entry.*, true);
            const loan: ParticipantLoan = .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .transaction = self.serial, .participant_slot = slot, .participant_serial = id.serial };
            entry.state = .issued;
            var next = participant.first_component;
            while (next != vacant) {
                coordinatorBacking(self.owner).homes[next].active_transaction = self.serial;
                next = coordinatorBacking(self.owner).components[next].next_home;
            }
            coordinatorBacking(self.owner).phase = .preparing;
            if (comptime @import("builtin").is_test) {
                if (participant.source_binding == .fixture) participant.source.loan = loan;
            }
            return loan;
        }
        fn bindNewAllocation(self: TransactionReservation, allocation: AllocationId, role_id: RoleId) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.validate();
            const index = try self.owner.allocationIndex(allocation);
            const slot = try self.owner.roleIndex(role_id);
            const record = &coordinatorBacking(self.owner).allocations[index];
            const role = &coordinatorBacking(self.owner).roles[slot];
            if (record.state != .candidate or record.transaction != self.serial or allocation.home_slot != role.origin or !self.owner.homeIssued(role.origin, self.serial)) return error.StaleTicket;
            if (record.role_slot != vacant) return error.InvalidPlan;
            if (role.actual_count == role.plan.max_live_allocations or record.charge > role.plan.max_charge - role.actual_charge) return error.CapacityExceeded;
            const source = &coordinatorBacking(self.owner).entries[coordinatorBacking(self.owner).components[role.origin].plan_index];
            if (role.receiver != vacant and record.charge > source.plan.final_new_capacity_max - source.retained_actual) return error.CapacityExceeded;
            role.actual_count += 1;
            role.actual_charge += record.charge;
            if (role.receiver != vacant) source.retained_actual += record.charge;
            record.role_slot = slot;
        }
        fn validate(self: TransactionReservation) Failure!void {
            if (!self.instance.eql(coordinatorBacking(self.owner).instance) or self.serial != coordinatorBacking(self.owner).serial or (coordinatorBacking(self.owner).phase != .funded and coordinatorBacking(self.owner).phase != .preparing)) return error.StaleTicket;
        }
        pub fn abort(self: TransactionReservation) Failure!void {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            try self.validate();
            // No refund while ANY participant still owns candidate storage.
            for (coordinatorBacking(self.owner).entries[0..coordinatorBacking(self.owner).entry_count]) |entry| if (coordinatorBacking(self.owner).homes[entry.index].live_new != 0 or coordinatorBacking(self.owner).homes[entry.index].actual_new != 0) return error.AllocationsHeld;
            // An empty heap is not a source abort receipt. Prevalidate EVERY
            // participant before changing holds or OLD encumbrances.
            for (coordinatorBacking(self.owner).participant_entries[0..coordinatorBacking(self.owner).participant_entry_count]) |entry| {
                if (entry.state == .issued) return error.ParticipantsHeld;
                try self.owner.validateParticipantSource(entry, true);
            }
            for (coordinatorBacking(self.owner).ownership[0..coordinatorBacking(self.owner).ownership_count]) |entry| {
                std.debug.assert(coordinatorBacking(self.owner).allocations[entry.record].encumbered_transaction == self.serial);
                coordinatorBacking(self.owner).allocations[entry.record].encumbered_transaction = 0;
            }
            for (coordinatorBacking(self.owner).entries[0..coordinatorBacking(self.owner).entry_count]) |entry| coordinatorBacking(self.owner).homes[entry.index].active_transaction = 0;
            for (coordinatorBacking(self.owner).touched[0..coordinatorBacking(self.owner).touched_count]) |i| coordinatorBacking(self.owner).holds[i].refund(&self.owner.account(i).totals);
            coordinatorBacking(self.owner).phase = .idle;
            coordinatorBacking(self.owner).entry_count = 0;
            coordinatorBacking(self.owner).ownership_count = 0;
            coordinatorBacking(self.owner).role_count = 0;
            coordinatorBacking(self.owner).participant_entry_count = 0;
        }
    };
    pub const ParticipantLoan = struct {
        owner: *Coordinator,
        identity: *Coordinator,
        instance: FleetInstance,
        transaction: u64,
        participant_slot: usize,
        participant_serial: u64,
        fn validateIssued(self: ParticipantLoan) Failure!usize {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            const tx: TransactionReservation = .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .serial = self.transaction };
            try tx.validate();
            const slot = try self.owner.participantIndex(.{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .slot = self.participant_slot, .serial = self.participant_serial });
            const participant = coordinatorBacking(self.owner).participants[slot];
            if (participant.seen_transaction != self.transaction or coordinatorBacking(self.owner).participant_entries[participant.plan_index].state != .issued) return error.StaleTicket;
            return slot;
        }
        pub fn componentScope(self: ParticipantLoan, component: ComponentId) Failure!FundedScope {
            const participant = try self.validateIssued();
            const index = try self.owner.componentIndex(component);
            if (coordinatorBacking(self.owner).components[index].participant_slot != participant or coordinatorBacking(self.owner).components[index].participant_serial != self.participant_serial or coordinatorBacking(self.owner).components[index].seen_transaction != self.transaction or !coordinatorBacking(self.owner).homes[index].active()) return error.StaleTicket;
            return .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .component = component, .home_slot = index, .home_serial = coordinatorBacking(self.owner).homes[index].serial, .serial = self.transaction, .participant_slot = participant, .participant_serial = self.participant_serial };
        }
        pub fn bindNewAllocation(self: ParticipantLoan, allocation: AllocationId, role: RoleId) Failure!void {
            const participant = try self.validateIssued();
            if (allocation.home_slot >= coordinatorBacking(self.owner).component_count or coordinatorBacking(self.owner).components[allocation.home_slot].participant_slot != participant) return error.StaleTicket;
            const tx: TransactionReservation = .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .serial = self.transaction };
            try tx.bindNewAllocation(allocation, role);
        }
    };
    pub const FundedScope = struct {
        owner: *Coordinator,
        identity: *Coordinator,
        instance: FleetInstance,
        component: ComponentId,
        home_slot: usize,
        home_serial: u64,
        serial: u64,
        participant_slot: usize,
        participant_serial: u64,
        fn home(self: FundedScope) Failure!*AllocationHome {
            if (self.owner != self.identity or !self.instance.eql(coordinatorBacking(self.owner).instance)) return error.StaleTicket;
            const tx: TransactionReservation = .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .serial = self.serial };
            try tx.validate();
            const index = try self.owner.componentIndex(self.component);
            if (index != self.home_slot or self.component.serial != self.home_serial) return error.StaleTicket;
            const result = &coordinatorBacking(self.owner).homes[index];
            if (result.active_transaction != self.serial or result.serial != self.component.serial or !result.active()) return error.StaleTicket;
            if (coordinatorBacking(self.owner).components[index].participant_slot != self.participant_slot or coordinatorBacking(self.owner).components[index].participant_serial != self.participant_serial) return error.StaleTicket;
            return result;
        }
        pub fn allocator(self: FundedScope) Failure!std.mem.Allocator {
            return (try self.home()).allocator();
        }
        pub fn allocationId(self: FundedScope, memory: []u8, alignment: std.mem.Alignment) Failure!AllocationId {
            const owner_home = try self.home();
            const found = owner_home.probe(memory.ptr) orelse return error.InvalidPlan;
            const record = owner_home.records[found.record];
            if (record.len != memory.len or record.alignment != alignment) return error.InvalidPlan;
            return .{ .owner = self.owner, .identity = self.identity, .instance = self.instance, .home_slot = self.component.slot, .home_serial = owner_home.serial, .allocation_slot = found.record, .serial = record.serial };
        }
    };
    fn sum(a: u64, b: u64) Failure!u64 {
        return std.math.add(u64, a, b) catch error.CapacityExceeded;
    }
    fn cappedAdd(a: u64, b: u64, cap: u64) u64 {
        std.debug.assert(a <= cap);
        return a + @min(b, cap - a);
    }
    fn capacityCharge(comptime T: type, count: usize) Failure!u64 {
        const bytes = std.math.mul(u64, @sizeOf(T), count) catch return error.CapacityExceeded;
        return sum(bytes, @alignOf(T) - 1);
    }
};

// White-box assertions and source fixtures retain their exact previous state
// checks without exposing private backing through the production handle.
fn fixtureCoordinator(owner: *resources.Coordinator) *resources.CoordinatorBacking {
    if (comptime !@import("builtin").is_test) @compileError("coordinator backing fixture is test-only");
    return resources.coordinatorBacking(owner);
}

fn registerFixtureComponent(owner: *resources.Coordinator, row: resources.RowHandle, category: resources.Category) resources.Failure!resources.ComponentId {
    if (comptime !@import("builtin").is_test) @compileError("catalog fixture is test-only");
    const participant = try owner.registerFixture(&.{.{ .row = row, .category = category }});
    return fixtureHome(participant, 0);
}

fn fixtureHome(participant: resources.ParticipantId, ordinal: usize) resources.Failure!resources.ComponentId {
    if (comptime !@import("builtin").is_test) @compileError("catalog fixture is test-only");
    const owner = participant.owner;
    const slot = try owner.participantIndex(participant);
    const catalog = fixtureCoordinator(owner).participants[slot];
    if (ordinal >= catalog.component_count) return error.InvalidPlan;
    var index = catalog.first_component;
    for (0..ordinal) |_| index = fixtureCoordinator(owner).components[index].next_home;
    return .{ .owner = owner, .identity = owner, .instance = fixtureCoordinator(owner).instance, .slot = index, .serial = fixtureCoordinator(owner).components[index].serial };
}

fn fixtureParticipant(component: resources.ComponentId) resources.Failure!resources.ParticipantId {
    if (comptime !@import("builtin").is_test) @compileError("catalog fixture is test-only");
    const owner = component.owner;
    const slot = try owner.componentIndex(component);
    const c = fixtureCoordinator(owner).components[slot];
    return .{ .owner = owner, .identity = owner, .instance = fixtureCoordinator(owner).instance, .slot = c.participant_slot, .serial = c.participant_serial };
}

fn fixtureParticipantPlan(id: resources.ParticipantId) resources.Failure!resources.ParticipantPlan {
    const slot = try id.owner.participantIndex(id);
    const catalog = fixtureCoordinator(id.owner).participants[slot];
    return .{ .participant = id, .expected_owner_revision = catalog.owner_revision, .expected_old_census_revision = catalog.old_census_revision, .work_units = 0 };
}

fn fixtureScope(tx: resources.TransactionReservation, component: resources.ComponentId) resources.Failure!resources.FundedScope {
    if (comptime !@import("builtin").is_test) @compileError("loan fixture is test-only");
    if (tx.owner != tx.identity or !tx.instance.eql(fixtureCoordinator(tx.owner).instance)) return error.StaleTicket;
    try tx.validate();
    const participant = try fixtureParticipant(component);
    const source = &fixtureCoordinator(tx.owner).participants[try tx.owner.participantIndex(participant)].source;
    const loan = source.loan orelse try tx.participantLoan(participant);
    return loan.componentScope(component);
}

fn fixtureBindNew(tx: resources.TransactionReservation, allocation: resources.AllocationId, role: resources.RoleId) resources.Failure!void {
    if (comptime !@import("builtin").is_test) @compileError("loan fixture is test-only");
    if (tx.owner != tx.identity or !tx.instance.eql(fixtureCoordinator(tx.owner).instance)) return error.StaleTicket;
    try tx.validate();
    if (allocation.home_slot >= fixtureCoordinator(tx.owner).component_count) return error.StaleTicket;
    const component: resources.ComponentId = .{ .owner = tx.owner, .identity = tx.owner, .instance = tx.instance, .slot = allocation.home_slot, .serial = allocation.home_serial };
    const participant = try fixtureParticipant(component);
    const source = &fixtureCoordinator(tx.owner).participants[participant.slot].source;
    const loan = source.loan orelse return error.StaleTicket;
    try loan.bindNewAllocation(allocation, role);
}

fn fixtureReleaseIdleLoans(tx: resources.TransactionReservation) resources.Failure!void {
    if (comptime !@import("builtin").is_test) @compileError("source release fixture is test-only");
    if (tx.owner != tx.identity or !tx.instance.eql(fixtureCoordinator(tx.owner).instance)) return error.StaleTicket;
    try tx.validate();
    const order = fixtureCoordinator(tx.owner).participant_order[0..fixtureCoordinator(tx.owner).participant_entry_count];
    var remaining = order.len;
    while (remaining != 0) {
        remaining -= 1;
        const entry = fixtureCoordinator(tx.owner).participant_entries[order[remaining]];
        if (entry.state != .issued) continue;
        const source = &fixtureCoordinator(tx.owner).participants[entry.participant_slot].source;
        const loan = source.loan orelse return error.StaleTicket;
        // Never clears tickets, guards, borrows or leaked allocations. This is
        // the explicit lexical end of primitive fixtures' allocator use.
        try tx.owner.releaseAbortedParticipant(loan);
    }
}

fn addTestComponent(builder: resources.PlanBuilder, plan: resources.ComponentPlan) resources.Failure!void {
    if (comptime !@import("builtin").is_test) @compileError("explicit role fixture is test-only");
    const id = try fixtureParticipant(plan.component);
    const catalog = &fixtureCoordinator(builder.owner).participants[try builder.owner.participantIndex(id)];
    try builder.addComponent(plan);
    if (catalog.seen_transaction != builder.serial) try builder.addParticipant(try fixtureParticipantPlan(id));
    if (plan.new_capacity_peak == 0) return;
    // Explicit local roles preserve historical scalar funding assertions. They
    // are actual declarations, with no production compatibility or fallback.
    if (plan.final_new_capacity_max != 0) _ = try builder.addNewRole(.{ .origin = plan.component, .expected_origin_revision = plan.expected_revision, .label = 0, .kind = .{ .retain = plan.component }, .max_charge = plan.final_new_capacity_max, .max_live_allocations = @max(1, plan.new_allocation_slots) });
    _ = try builder.addNewRole(.{ .origin = plan.component, .expected_origin_revision = plan.expected_revision, .label = 1, .kind = .{ .discard = .finish }, .max_charge = plan.new_capacity_peak, .max_live_allocations = @max(1, plan.new_allocation_slots) });
}

fn testInstance(byte: u8) resources.FleetInstance {
    // Deterministic fixtures only. Production must source the registry boot/adopt
    // identity from its complete constructor; this helper is never exported.
    return .{ .bytes = @splat(byte) };
}

fn testProfile() resources.Profile {
    const limits: resources.Limits = .{ .resident = 100000, .peak = 200000, .wire = 100000 };
    return .{ .fleet = limits, .categories = .{ limits, limits }, .infrastructure = limits, .rows = 4, .components = 4, .transaction_components = 4, .participant_slots = 4, .transaction_participant_refs = 4, .transaction_work_max = 100000000, .new_role_slots = 8 };
}

test "physical whole coordinator opaque handle retains single charged backing" {
    const r = resources;
    try std.testing.expect(@typeInfo(r.Coordinator) == .@"opaque");
    inline for (.{ r.RowHandle, r.ComponentId, r.AllocationId, r.RoleId, r.ParticipantId, r.PlanBuilder, r.CanonicalPlanView, r.TransactionReservation, r.ParticipantLoan, r.FundedScope }) |T| {
        try std.testing.expect(@FieldType(T, "owner") == *r.Coordinator);
        try std.testing.expect(@FieldType(T, "identity") == *r.Coordinator);
    }
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
        defer owner.deinit();
        const backing = fixtureCoordinator(owner);
        try std.testing.expectEqual(@intFromPtr(backing), @intFromPtr(owner));
        try std.testing.expectEqual(@as(usize, 17), backend.allocations);
        var slack: u64 = @alignOf(r.CoordinatorBacking) - 1;
        inline for (.{ backing.rows, backing.components, backing.entries, backing.ownership, backing.roles, backing.role_order, backing.role_contributions, backing.holds, backing.touched, backing.homes, backing.allocations, backing.buckets, backing.participants, backing.participant_entries, backing.participant_order, backing.original_spans }) |slice| {
            slack += @alignOf(@TypeOf(slice[0])) - 1;
        }
        try std.testing.expectEqual(backend.allocated_bytes + slack, backing.metadata_charge);
        try std.testing.expectEqual(backing.metadata_charge, backing.fleet.totals.resident);
    }
    try std.testing.expectEqual(backend.allocations, backend.deallocations);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
}

test "physical whole funding last row refusal leaves every account OLD" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const good = try owner.registerRow(2, 8, .{ .resident = 100, .peak = 200, .wire = 100 });
    const bad = try owner.registerRow(3, 9, .{ .resident = 1, .peak = 1, .wire = 1 });
    const a = try registerFixtureComponent(owner, good, .output);
    const b = try registerFixtureComponent(owner, bad, .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 80, .final_new_capacity_max = 40, .final_wire_addition_max = 20 });
    try addTestComponent(builder, .{ .component = b, .expected_revision = 1, .new_capacity_peak = 2, .final_new_capacity_max = 1, .final_wire_addition_max = 1 });
    const plan = try builder.finish();
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).rows[1].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).categories[0].totals.wire_hold);
    try builder.abort();
}

test "physical whole funding canonical admission copied cancellation and serial exhaustion" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const row = try owner.registerRow(9, 7, .{ .resident = 100, .peak = 200, .wire = 100 });
    const a = try registerFixtureComponent(owner, row, .output);
    const b = try registerFixtureComponent(owner, row, .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    fixtureCoordinator(owner).serial = std.math.maxInt(u64) - 1;
    const builder = try owner.beginPlan(1);
    const p: r.ComponentPlan = .{ .component = b, .expected_revision = 1, .new_capacity_peak = 70, .final_new_capacity_max = 20, .final_wire_addition_max = 10 };
    try addTestComponent(builder, p);
    try std.testing.expectError(error.InvalidPlan, addTestComponent(builder, p));
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 60, .final_new_capacity_max = 30, .final_wire_addition_max = 15 });
    const plan = try builder.finish();
    try std.testing.expectEqual(a.serial, fixtureCoordinator(owner).entries[0].plan.component.serial);
    const tx = try owner.beginTransaction(plan);
    try std.testing.expectEqual(@as(u64, 130), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[1].account.totals.resident_hold);
    // The final legitimately issued serial must still cancel without minting.
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectError(error.StaleTicket, tx.abort());
    try std.testing.expectError(error.GenerationExhausted, owner.beginPlan(1));
}

fn bootstrapOom(allocator: std.mem.Allocator) !void {
    const owner = try resources.Coordinator.create(allocator, testProfile(), .empty, testInstance(1));
    owner.deinit();
}

test "physical whole funding bootstrap allocation failure frees all workspace" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, bootstrapOom, .{});
}

test "physical whole funding rejects metadata before backend allocation" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var profile = testProfile();
    profile.fleet.peak = 1;
    try std.testing.expectError(error.CapacityExceeded, resources.Coordinator.create(fail.allocator(), profile, .empty, testInstance(1)));
    try std.testing.expectEqual(@as(usize, 0), fail.allocations);
}

test "physical whole funding rejects owner retarget generation and stale copied plans" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const other = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer other.deinit();
    const limits: r.Limits = .{ .resident = 100, .peak = 200, .wire = 100 };
    const row = try owner.registerRow(2, 9, limits);
    const other_row = try other.registerRow(2, 9, limits);
    const a = try registerFixtureComponent(owner, row, .output);
    const foreign = try registerFixtureComponent(other, other_row, .output);
    var stale_row = row;
    stale_row.generation = 8;
    try std.testing.expectError(error.StaleTicket, registerFixtureComponent(owner, stale_row, .output));
    const builder = try owner.beginPlan(1);
    var wrong_slot = a;
    wrong_slot.slot = fixtureCoordinator(owner).component_count;
    try std.testing.expectError(error.StaleTicket, addTestComponent(builder, .{ .component = wrong_slot, .expected_revision = 1, .new_capacity_peak = 10, .final_new_capacity_max = 10, .final_wire_addition_max = 10 }));
    try std.testing.expectError(error.StaleTicket, addTestComponent(builder, .{ .component = foreign, .expected_revision = 1, .new_capacity_peak = 10, .final_new_capacity_max = 10, .final_wire_addition_max = 10 }));
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 10, .final_new_capacity_max = 10, .final_wire_addition_max = 10 });
    const plan = try builder.finish();
    try std.testing.expectError(error.StaleTicket, other.beginTransaction(plan));
    const tx = try owner.beginTransaction(plan);
    try std.testing.expectError(error.StaleTicket, owner.beginTransaction(plan));
    const other_builder = try other.beginPlan(1);
    try addTestComponent(other_builder, .{ .component = foreign, .expected_revision = 1, .new_capacity_peak = 10, .final_new_capacity_max = 10, .final_wire_addition_max = 10 });
    const other_tx = try other.beginTransaction(try other_builder.finish());
    defer {
        fixtureReleaseIdleLoans(other_tx) catch unreachable;
        other_tx.abort() catch unreachable;
    }
    const other_before = fixtureCoordinator(other).fleet.totals;
    var tampered = tx;
    tampered.owner = other;
    try std.testing.expectError(error.StaleTicket, tampered.abort());
    try std.testing.expectEqualDeep(other_before, fixtureCoordinator(other).fleet.totals);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    const next = try owner.beginPlan(1);
    try std.testing.expectError(error.StaleTicket, builder.abort());
    try next.abort();
}

test "physical whole funding rejects fleet sums and category before any holds" {
    const r = resources;
    var profile = testProfile();
    profile.fleet.peak = std.math.maxInt(u64);
    profile.fleet.resident = std.math.maxInt(u64);
    profile.fleet.wire = std.math.maxInt(u64);
    const owner = try r.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(1));
    defer owner.deinit();
    const row = try owner.registerRow(2, 1, .{ .resident = std.math.maxInt(u64), .peak = std.math.maxInt(u64), .wire = std.math.maxInt(u64) });
    const a = try registerFixtureComponent(owner, row, .output);
    const b = try registerFixtureComponent(owner, row, .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = std.math.maxInt(u64), .final_new_capacity_max = 0, .final_wire_addition_max = 0 });
    try addTestComponent(builder, .{ .component = b, .expected_revision = 1, .new_capacity_peak = 1, .final_new_capacity_max = 0, .final_wire_addition_max = 0 });
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try builder.finish()));
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try builder.abort();
    const second = try owner.beginPlan(1);
    try addTestComponent(second, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 1, .final_new_capacity_max = 0, .final_wire_addition_max = 100001 });
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try second.finish()));
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try second.abort();
}

test "physical whole funding plan workspace and admission never allocate" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var profile = testProfile();
    profile.transaction_components = 1;
    const owner = try r.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1));
    defer owner.deinit();
    backend.fail_index = backend.alloc_index;
    const row = try owner.registerRow(2, 1, .{ .resident = 100, .peak = 200, .wire = 100 });
    const a = try registerFixtureComponent(owner, row, .output);
    const b = try registerFixtureComponent(owner, row, .output);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 80, .final_new_capacity_max = 40, .final_wire_addition_max = 20 });
    try std.testing.expectError(error.CapacityExceeded, addTestComponent(builder, .{ .component = b, .expected_revision = 1, .new_capacity_peak = 1, .final_new_capacity_max = 1, .final_wire_addition_max = 1 }));
    const tx = try owner.beginTransaction(try builder.finish());
    // Seventeen bootstrap allocations include the original-span index.
    try std.testing.expectEqual(@as(usize, 17), backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole funding above 4096 recipients uses fixed workspace and exact sums" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const limits: r.Limits = .{ .resident = 32 * 1024 * 1024, .peak = 64 * 1024 * 1024, .wire = 100000 };
    const profile: r.Profile = .{ .fleet = limits, .categories = .{ limits, limits }, .infrastructure = limits, .rows = 2, .components = 5001, .transaction_components = 5001, .participant_slots = 5001, .transaction_participant_refs = 5001, .transaction_work_max = 100000000, .new_role_slots = 10002 };
    const owner = try r.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1));
    defer owner.deinit();
    std.debug.print("S2 5001-component bootstrap requested+alignment charge={d} bytes\n", .{fixtureCoordinator(owner).metadata_charge});
    const row = try owner.registerRow(2, 99, limits);
    for (0..5001) |_| _ = try registerFixtureComponent(owner, row, .output);
    backend.fail_index = backend.alloc_index;
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    var i: usize = 5001;
    while (i > 0) {
        i -= 1;
        const id: r.ComponentId = .{ .owner = owner, .identity = owner, .instance = fixtureCoordinator(owner).instance, .slot = i, .serial = fixtureCoordinator(owner).components[i].serial };
        try addTestComponent(builder, .{ .component = id, .expected_revision = 1, .new_capacity_peak = 3, .final_new_capacity_max = 2, .final_wire_addition_max = 1 });
    }
    const tx = try owner.beginTransaction(try builder.finish());
    try std.testing.expectEqual(@as(u64, 15003), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 10002), fixtureCoordinator(owner).rows[1].account.totals.resident_hold);
    try std.testing.expectEqual(@as(u64, 5001), fixtureCoordinator(owner).categories[0].totals.wire_hold);
    // Seventeen bootstrap allocations include the original-span index.
    try std.testing.expectEqual(@as(usize, 17), backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
    for (fixtureCoordinator(owner).entries[0..fixtureCoordinator(owner).entry_count], 0..) |entry, index| try std.testing.expectEqual(index, entry.index);
    try std.testing.expectEqual(@as(usize, 5001), fixtureCoordinator(owner).participant_entry_count);
    for (fixtureCoordinator(owner).participant_order[0..fixtureCoordinator(owner).participant_entry_count], 0..) |slot, ordinal| {
        const current = fixtureCoordinator(owner).participant_entries[slot];
        try std.testing.expectEqual(@as(usize, 1), current.planned_component_count);
        try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).participants[current.participant_slot].source.prepare_count);
        if (ordinal != 0) try std.testing.expect(fixtureCoordinator(owner).participant_entries[fixtureCoordinator(owner).participant_order[ordinal - 1]].copied_plan.participant.serial < current.copied_plan.participant.serial);
    }
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
}

test "physical whole funding sparse account retry resets only touched scratch" {
    const r = resources;
    const limits: r.Limits = .{ .resident = 16 * 1024 * 1024, .peak = 32 * 1024 * 1024, .wire = 100000 };
    const profile: r.Profile = .{ .fleet = limits, .categories = .{ limits, limits }, .infrastructure = limits, .rows = 5001, .components = 2, .transaction_components = 2, .participant_slots = 2, .transaction_participant_refs = 2, .transaction_work_max = 100000000 };
    const owner = try r.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(1));
    defer owner.deinit();
    const row = try owner.registerRow(2, 2, limits);
    const a = try registerFixtureComponent(owner, row, .output);
    const b = try registerFixtureComponent(owner, row, .output);
    const before = fixtureCoordinator(owner).fleet.totals;
    fixtureCoordinator(owner).categories[0].limits.wire = 1;
    const builder = try owner.beginPlan(1);
    for ([_]r.ComponentId{ b, a }) |id| try addTestComponent(builder, .{ .component = id, .expected_revision = 1, .new_capacity_peak = 4, .final_new_capacity_max = 2, .final_wire_addition_max = 1 });
    const plan = try builder.finish();
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(usize, 3), fixtureCoordinator(owner).touched_count);
    fixtureCoordinator(owner).categories[0].limits.wire = 2;
    const tx = try owner.beginTransaction(plan);
    try std.testing.expectEqual(@as(usize, 3), fixtureCoordinator(owner).touched_count);
    try std.testing.expectEqual(@as(u64, 8), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 2), fixtureCoordinator(owner).categories[0].totals.wire_hold);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).rows[5000].account.totals.preparation);
}

fn borrowedFacade(tx: resources.TransactionReservation, id: resources.ComponentId) !std.mem.Allocator {
    const scope = try fixtureScope(tx, id);
    return scope.allocator();
}

test "physical whole homes alignment resize slots and held abort conserve funded envelope" {
    const r = resources;
    var storage: [65536]u8 align(16) = undefined;
    var backend = std.heap.FixedBufferAllocator.init(&storage);
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 96, .final_new_capacity_max = 60, .final_wire_addition_max = 0, .new_allocation_slots = 2 });
    const tx = try owner.beginTransaction(try builder.finish());
    const allocator = try borrowedFacade(tx, component);
    try std.testing.expectEqual(@intFromPtr(&fixtureCoordinator(owner).homes[component.slot]), @intFromPtr(allocator.ptr));
    var first = try allocator.alignedAlloc(u8, .@"16", 33);
    @memset(first, 0xa5);
    const second = try allocator.alloc(u8, 48);
    try std.testing.expectEqual(@as(u64, 96), fixtureCoordinator(owner).homes[component.slot].actual_new);
    try std.testing.expectEqual(@as(u64, 96), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expect(!allocator.resize(first, 34));
    try std.testing.expectEqual(@as(u64, 96), fixtureCoordinator(owner).homes[component.slot].actual_new);
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    allocator.free(second);
    try std.testing.expect(allocator.resize(first, 40));
    first = first.ptr[0..40];
    try std.testing.expectEqual(@as(u64, 55), fixtureCoordinator(owner).homes[component.slot].actual_new);
    for (first[0..33]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    const scope = try fixtureScope(tx, component);
    const id = try scope.allocationId(first, .@"16");
    try std.testing.expectEqual(component.serial, id.home_serial);
    try std.testing.expectError(error.InvalidPlan, scope.allocationId(first[0..39], .@"16"));
    allocator.free(first);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectError(error.StaleTicket, scope.allocator());
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
}

test "physical whole homes one retained participant prevents every refund" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    for ([_]r.ComponentId{ a, b }) |id| try addTestComponent(builder, .{ .component = id, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 16, .final_wire_addition_max = 5, .new_allocation_slots = 2 });
    const tx = try owner.beginTransaction(try builder.finish());
    const aa = try borrowedFacade(tx, a);
    const ba = try borrowedFacade(tx, b);
    const first = try aa.alloc(u8, 16);
    const last = try ba.alloc(u8, 16);
    aa.free(first);
    const funded = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(tx.serial, fixtureCoordinator(owner).homes[a.slot].active_transaction);
    ba.free(last);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).fleet.totals.wire_hold);
}

test "physical whole homes backend OOM burns allocation identity without losing slots" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 64, .final_new_capacity_max = 32, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    const tx = try owner.beginTransaction(try builder.finish());
    const scope = try fixtureScope(tx, component);
    const allocator = try scope.allocator();
    backend.fail_index = backend.alloc_index;
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 32));
    try std.testing.expectEqual(@as(u64, 1), fixtureCoordinator(owner).homes[component.slot].allocation_serial);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).homes[component.slot].live_new);
    backend.fail_index = std.math.maxInt(usize);
    const bytes = try allocator.alloc(u8, 32);
    const id = try scope.allocationId(bytes, .@"1");
    try std.testing.expectEqual(@as(u64, 2), id.serial);
    try std.testing.expectEqual(@as(u64, 32), fixtureCoordinator(owner).homes[component.slot].actual_new);
    fixtureCoordinator(owner).homes[component.slot].allocation_serial = std.math.maxInt(u64);
    allocator.free(bytes);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole homes bounded pointer index survives collision deletion and reuse" {
    const r = resources;
    var storage: [65536]u8 = undefined;
    var backend = std.heap.FixedBufferAllocator.init(&storage);
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 128, .final_new_capacity_max = 128, .final_wire_addition_max = 0, .new_allocation_slots = 16 });
    const tx = try owner.beginTransaction(try builder.finish());
    const scope = try fixtureScope(tx, component);
    const allocator = try scope.allocator();
    var last_serial: u64 = 0;
    for (0..100) |round| {
        var buffers: [16][]u8 = undefined;
        for (&buffers, 0..) |*bytes, i| {
            if (round == 0) {
                // Real backend allocations deliberately share the final bucket,
                // forcing a collision chain that wraps across bucket zero.
                const home = &fixtureCoordinator(owner).homes[component.slot];
                while (home.hash(storage[backend.end_index..].ptr) != home.buckets.len - 1) backend.end_index += 1;
                std.debug.assert(backend.end_index + 8 <= storage.len);
            }
            bytes.* = try allocator.alloc(u8, 8);
            @memset(bytes.*, @intCast(i));
            const id = try scope.allocationId(bytes.*, .@"1");
            try std.testing.expect(id.serial > last_serial);
            last_serial = id.serial;
        }
        // Remove alternate buckets, then verify live neighbors before deletion.
        for (0..8) |i| allocator.free(buffers[i * 2]);
        for (0..8) |i| {
            const bytes = buffers[i * 2 + 1];
            const id = try scope.allocationId(bytes, .@"1");
            try std.testing.expect(id.serial != 0);
            for (bytes) |byte| try std.testing.expectEqual(@as(u8, @intCast(i * 2 + 1)), byte);
            allocator.free(bytes);
        }
        try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).homes[component.slot].actual_new);
        for (fixtureCoordinator(owner).homes[component.slot].buckets) |bucket| try std.testing.expectEqual(r.vacant, bucket);
    }
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole homes refuse unplanned scopes and tracking capacity before source preparation" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const unused = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 64, .final_new_capacity_max = 32, .final_wire_addition_max = 0, .new_allocation_slots = 17 });
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try builder.finish()));
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try builder.abort();
    const next = try owner.beginPlan(1);
    try addTestComponent(next, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 64, .final_new_capacity_max = 32, .final_wire_addition_max = 0 });
    const tx = try owner.beginTransaction(try next.finish());
    try std.testing.expectError(error.StaleTicket, fixtureScope(tx, unused));
    const scope = try fixtureScope(tx, component);
    const allocator = try scope.allocator();
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole homes allocate copy free charges overlapping capacity" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 128, .final_new_capacity_max = 128, .final_wire_addition_max = 0, .new_allocation_slots = 2 });
    const tx = try owner.beginTransaction(try builder.finish());
    const scope = try fixtureScope(tx, component);
    const allocator = try scope.allocator();
    const old = try allocator.alloc(u8, 64);
    @memset(old, 0x5a);
    const old_id = try scope.allocationId(old, .@"1");
    const backend_count = backend.allocations;
    try std.testing.expectError(error.OutOfMemory, allocator.realloc(old, 128));
    try std.testing.expectEqual(backend_count, backend.allocations);
    try std.testing.expectEqual(@as(u64, 64), fixtureCoordinator(owner).homes[component.slot].actual_new);
    const unchanged = try scope.allocationId(old, .@"1");
    // Compare ownership pointers by identity, not recursive coordinator graphs.
    inline for (comptime std.meta.fieldNames(r.AllocationId)) |field| try std.testing.expectEqual(@field(old_id, field), @field(unchanged, field));
    for (old) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
    // A same-length detached copy fits both capacities; neither can disappear
    // from actual peak until its own backend free has happened.
    const copy = try allocator.alloc(u8, 64);
    @memcpy(copy, old);
    try std.testing.expectEqual(@as(u64, 128), fixtureCoordinator(owner).homes[component.slot].actual_new);
    allocator.free(old);
    try std.testing.expectEqual(@as(u64, 64), fixtureCoordinator(owner).homes[component.slot].actual_new);
    for (copy) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
    allocator.free(copy);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

fn candidateOom(allocator: std.mem.Allocator) !void {
    const r = resources;
    const owner = try r.Coordinator.create(allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 160, .final_new_capacity_max = 160, .final_wire_addition_max = 0, .new_allocation_slots = 3 });
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    }
    const facade = try borrowedFacade(tx, component);
    const first = try facade.alloc(u8, 32);
    defer facade.free(first);
    const second = try facade.alignedAlloc(u8, .@"16", 33);
    defer facade.free(second);
    const third = try facade.alloc(u8, 64);
    defer facade.free(third);
}

test "physical whole homes every bootstrap and candidate allocation failure restores owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, candidateOom, .{});
}

test "physical whole homes copied scope cannot retarget a second funded home" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    for ([_]r.ComponentId{ a, b }) |id| try addTestComponent(builder, .{ .component = id, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 16, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    const tx = try owner.beginTransaction(try builder.finish());
    const first = try fixtureScope(tx, a);
    const last = try fixtureScope(tx, b);
    var retargeted = first;
    retargeted.component = b;
    try std.testing.expectError(error.StaleTicket, retargeted.allocator());
    const aa = try first.allocator();
    const ba = try last.allocator();
    const ap = try aa.alloc(u8, 16);
    const bp = try ba.alloc(u8, 16);
    try std.testing.expectError(error.InvalidPlan, first.allocationId(bp, .@"1"));
    try std.testing.expectError(error.StaleTicket, retargeted.allocationId(bp, .@"1"));
    aa.free(ap);
    ba.free(bp);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole instance rejects zero identity before backend allocation" {
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidPlan, resources.FleetInstance.init(@splat(0)));
    try std.testing.expectError(error.InvalidPlan, resources.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(0)));
    try std.testing.expectEqual(@as(usize, 0), backend.allocations);
}

test "physical whole instance address reuse cannot revive old row component plan or scope" {
    const r = resources;
    var backing: [65536]u8 = undefined;
    var backend = std.heap.FixedBufferAllocator.init(&backing);
    const first = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    const old_row = first.infrastructureRow();
    const old_component = try registerFixtureComponent(first, old_row, .graph);
    const old_builder = try first.beginPlan(1);
    try addTestComponent(old_builder, .{ .component = old_component, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 32, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    const old_plan = try old_builder.finish();
    const old_tx = try first.beginTransaction(old_plan);
    const old_scope = try fixtureScope(old_tx, old_component);
    const old_participant = try fixtureParticipant(old_component);
    const old_loan = fixtureCoordinator(first).participants[old_participant.slot].source.loan.?;
    const first_address = @intFromPtr(first);
    try fixtureReleaseIdleLoans(old_tx);
    try old_tx.abort();
    first.deinit();
    backend.reset();

    const second = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(2));
    defer second.deinit();
    try std.testing.expectEqual(first_address, @intFromPtr(second));
    const fresh_row = second.infrastructureRow();
    const fresh_component = try registerFixtureComponent(second, fresh_row, .graph);
    // Identical address, registration slots, revisions and transaction serials.
    // Only the mandatory fleet instance distinguishes the new owner lifetime.
    try std.testing.expectEqual(old_component.serial, fresh_component.serial);
    const builder = try second.beginPlan(1);
    try std.testing.expectError(error.StaleTicket, addTestComponent(builder, .{ .component = old_component, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 32, .final_wire_addition_max = 0 }));
    try addTestComponent(builder, .{ .component = fresh_component, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 32, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    const plan = try builder.finish();
    const tx = try second.beginTransaction(plan);
    const scope = try fixtureScope(tx, fresh_component);
    const before = fixtureCoordinator(second).fleet.totals;
    try std.testing.expectError(error.StaleTicket, second.rowIndex(old_row));
    try std.testing.expectError(error.StaleTicket, second.componentIndex(old_component));
    try std.testing.expectError(error.StaleTicket, second.participantIndex(old_participant));
    try std.testing.expectError(error.StaleTicket, old_loan.componentScope(fresh_component));
    try std.testing.expectError(error.StaleTicket, second.releaseAbortedParticipant(old_loan));
    try std.testing.expectError(error.StaleTicket, second.beginTransaction(old_plan));
    try std.testing.expectError(error.StaleTicket, old_builder.abort());
    try std.testing.expectError(error.StaleTicket, old_tx.abort());
    try std.testing.expectError(error.StaleTicket, fixtureScope(old_tx, fresh_component));
    try std.testing.expectError(error.StaleTicket, old_scope.allocator());
    try std.testing.expectEqualDeep(before, fixtureCoordinator(second).fleet.totals);
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 16);
    const id = try scope.allocationId(bytes, .@"1");
    try std.testing.expect(id.instance.eql(fixtureCoordinator(second).instance));
    allocator.free(bytes);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

// Private OLD ledger fixtures use genuine backend allocations. They are not an
// existing-state census constructor and cannot be called by production owners.
fn fixtureResident(owner: *resources.Coordinator, origin: resources.ComponentId, logical: resources.ComponentId, len: usize, alignment: std.mem.Alignment) !resources.AllocationId {
    comptime {
        if (!@import("builtin").is_test) @compileError("OLD ownership fixture is test-only");
    }
    const home_index = try owner.componentIndex(origin);
    const logical_index = try owner.componentIndex(logical);
    const home = &fixtureCoordinator(owner).homes[home_index];
    std.debug.assert(fixtureCoordinator(owner).phase == .idle and len != 0 and home.free_count != 0);
    const charge = try resources.sum(len, alignment.toByteUnits() - 1);
    const component = fixtureCoordinator(owner).components[logical_index];
    const accounts = [_]usize{ 0, 1 + @as(usize, @intFromEnum(component.category)), 3 + component.row };
    for (accounts) |index| {
        var totals = owner.account(index).totals;
        totals.resident = try resources.sum(totals.resident, charge);
        if (!totals.permits(owner.account(index).limits)) return error.CapacityExceeded;
    }
    home.allocation_serial = std.math.add(u64, home.allocation_serial, 1) catch return error.GenerationExhausted;
    const ptr = fixtureCoordinator(owner).backend.rawAlloc(len, alignment, @returnAddress()) orelse return error.OutOfMemory;
    const index = home.free_head;
    home.free_head = home.records[index].next_free;
    home.records[index] = .{ .ptr = ptr, .len = len, .alignment = alignment, .charge = charge, .serial = home.allocation_serial, .state = .resident };
    home.insert(index);
    owner.linkAllocation(home_index, index, logical_index);
    home.free_count -= 1;
    home.live_total += 1;
    for (accounts) |account| owner.account(account).totals.resident += charge;
    @memset(ptr[0..len], 0x6d);
    return .{ .owner = owner, .identity = owner, .instance = fixtureCoordinator(owner).instance, .home_slot = home_index, .home_serial = home.serial, .allocation_slot = index, .serial = home.allocation_serial };
}

fn clearFixtureResidents(owner: *resources.Coordinator) void {
    comptime {
        if (!@import("builtin").is_test) @compileError("OLD ownership fixture cleanup is test-only");
    }
    std.debug.assert(fixtureCoordinator(owner).phase == .idle);
    for (fixtureCoordinator(owner).homes[0..fixtureCoordinator(owner).component_count], 0..) |*home, home_index| {
        for (home.records, 0..) |record, index| {
            if (record.ptr == null) continue;
            std.debug.assert(record.state == .resident and record.encumbered_transaction == 0);
            const logical = fixtureCoordinator(owner).components[record.logical_owner];
            const found = home.lookup(record.ptr.?[0..record.len], record.alignment);
            fixtureCoordinator(owner).backend.rawFree(record.ptr.?[0..record.len], record.alignment, @returnAddress());
            owner.unlinkAllocation(home_index, index);
            home.remove(found.bucket);
            home.records[index] = .{ .next_free = home.free_head };
            home.free_head = index;
            home.live_total -= 1;
            home.free_count += 1;
            fixtureCoordinator(owner).fleet.totals.resident -= record.charge;
            fixtureCoordinator(owner).categories[@intFromEnum(logical.category)].totals.resident -= record.charge;
            fixtureCoordinator(owner).rows[logical.row].account.totals.resident -= record.charge;
        }
    }
}

fn fixtureDeclaration(owner: *resources.Coordinator, id: resources.AllocationId, logical: resources.ComponentId, disposition: resources.OldDisposition) resources.AllocationDeclaration {
    const record = fixtureCoordinator(owner).allocations[owner.allocationIndex(id) catch unreachable];
    return .{ .allocation = id, .expected_owner = logical, .expected_owner_revision = fixtureCoordinator(owner).components[logical.slot].revision, .expected_length = record.len, .expected_alignment = record.alignment, .disposition = disposition };
}

fn fixtureComponentPlan(id: resources.ComponentId) resources.ComponentPlan {
    return .{ .component = id, .expected_revision = 1, .new_capacity_peak = 0, .final_new_capacity_max = 0, .final_wire_addition_max = 0 };
}

test "physical whole ownership complete OLD declarations reject missing duplicate foreign and altered capacity" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const first = try fixtureResident(owner, component, component, 16, .@"8");
    const second = try fixtureResident(owner, component, component, 24, .@"1");
    const before = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    var declaration = fixtureDeclaration(owner, first, component, .keep);
    try std.testing.expectError(error.StaleTicket, builder.addOwnership(declaration));
    try addTestComponent(builder, fixtureComponentPlan(component));
    declaration.expected_length -= 1;
    try std.testing.expectError(error.InvalidPlan, builder.addOwnership(declaration));
    declaration = fixtureDeclaration(owner, first, component, .keep);
    declaration.expected_alignment = .@"1";
    try std.testing.expectError(error.InvalidPlan, builder.addOwnership(declaration));
    declaration = fixtureDeclaration(owner, first, component, .keep);
    declaration.allocation.instance = testInstance(2);
    try std.testing.expectError(error.StaleTicket, builder.addOwnership(declaration));
    declaration = fixtureDeclaration(owner, first, component, .keep);
    declaration.allocation.serial += 1;
    try std.testing.expectError(error.StaleTicket, builder.addOwnership(declaration));
    try builder.addOwnership(fixtureDeclaration(owner, second, component, .{ .retire = .finish }));
    try std.testing.expectError(error.InvalidPlan, builder.addOwnership(fixtureDeclaration(owner, second, component, .keep)));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(second)].encumbered_transaction);
    try builder.addOwnership(fixtureDeclaration(owner, first, component, .keep));
    const plan = try builder.finish();
    try std.testing.expectEqual(first.serial, fixtureCoordinator(owner).ownership[0].declaration.allocation.serial);
    const tx = try owner.beginTransaction(plan);
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    for ([_]r.AllocationId{ first, second }) |id| {
        const record = fixtureCoordinator(owner).allocations[try owner.allocationIndex(id)];
        try std.testing.expectEqual(tx.serial, record.encumbered_transaction);
        try std.testing.expectEqual(r.AllocationState.resident, record.state);
        try std.testing.expect(std.mem.allEqual(u8, record.ptr.?[0..record.len], 0x6d));
    }
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(first)].encumbered_transaction);
}

test "physical whole ownership three row cycle reserves one simultaneous vector without phantom fleet copy" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    var components: [3]r.ComponentId = undefined;
    var allocations: [3]r.AllocationId = undefined;
    for (0..3) |i| {
        const row = try owner.registerRow(i + 2, i + 1, .{ .resident = 40, .peak = 40, .wire = 0 });
        components[i] = try registerFixtureComponent(owner, row, if (i == 1) .graph else .output);
        allocations[i] = try fixtureResident(owner, components[i], components[i], 40, .@"1");
    }
    for (&fixtureCoordinator(owner).categories) |*category| {
        category.limits.resident = category.totals.resident;
        category.limits.peak = category.totals.resident;
    }
    fixtureCoordinator(owner).fleet.limits.resident = fixtureCoordinator(owner).fleet.totals.resident;
    fixtureCoordinator(owner).fleet.limits.peak = fixtureCoordinator(owner).fleet.totals.resident;
    const before = fixtureCoordinator(owner).fleet.totals;
    const backend_calls = backend.allocations;
    backend.fail_index = backend.alloc_index;
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    for (components) |component| try addTestComponent(builder, fixtureComponentPlan(component));
    for (allocations, 0..) |id, i| try builder.addOwnership(fixtureDeclaration(owner, id, components[i], .{ .move = components[(i + 1) % 3] }));
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    for (components, allocations) |component, id| {
        const record = fixtureCoordinator(owner).allocations[try owner.allocationIndex(id)];
        try std.testing.expectEqual(component.slot, record.logical_owner);
        const row = fixtureCoordinator(owner).rows[fixtureCoordinator(owner).components[component.slot].row];
        try std.testing.expectEqual(@as(u64, 0), row.account.totals.preparation);
        try std.testing.expectEqual(@as(u64, 0), row.account.totals.resident_hold);
    }
    try std.testing.expectEqual(backend_calls, backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole ownership incoming move requires destination resident and publication peak headroom" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const source_row = try owner.registerRow(2, 1, .{ .resident = 50, .peak = 50, .wire = 0 });
    const destination_row = try owner.registerRow(3, 1, .{ .resident = 49, .peak = 100, .wire = 0 });
    const source = try registerFixtureComponent(owner, source_row, .output);
    const destination = try registerFixtureComponent(owner, destination_row, .graph);
    const allocation = try fixtureResident(owner, source, source, 50, .@"1");
    const before = fixtureCoordinator(owner).fleet.totals;
    const calls = backend.allocations;
    backend.fail_index = backend.alloc_index;
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, fixtureComponentPlan(source));
    try std.testing.expectError(error.StaleTicket, builder.addOwnership(fixtureDeclaration(owner, allocation, source, .{ .move = destination })));
    try addTestComponent(builder, fixtureComponentPlan(destination));
    try builder.addOwnership(fixtureDeclaration(owner, allocation, source, .{ .move = destination }));
    const plan = try builder.finish();
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(allocation)].encumbered_transaction);
    fixtureCoordinator(owner).rows[destination_row.slot].account.limits = .{ .resident = 50, .peak = 49, .wire = 0 };
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    fixtureCoordinator(owner).rows[destination_row.slot].account.limits.peak = 50;
    const tx = try owner.beginTransaction(plan);
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[destination_row.slot].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[destination_row.slot].account.totals.resident_hold);
    const scope = try fixtureScope(tx, destination);
    try std.testing.expectError(error.OutOfMemory, (try scope.allocator()).alloc(u8, 1));
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).homes[destination.slot].peak);
    try std.testing.expectEqual(calls, backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
}

test "physical whole ownership future retirement never credits peak and held candidate blocks all OLD release" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const row = try owner.registerRow(2, 1, .{ .resident = 100, .peak = 100, .wire = 0 });
    const component = try registerFixtureComponent(owner, row, .output);
    const allocation = try fixtureResident(owner, component, component, 80, .@"1");
    const before = fixtureCoordinator(owner).fleet.totals;
    const too_large = try owner.beginPlan(1);
    try addTestComponent(too_large, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 30, .final_new_capacity_max = 30, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    try too_large.addOwnership(fixtureDeclaration(owner, allocation, component, .{ .retire = .publication }));
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try too_large.finish()));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try too_large.abort();
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 20, .final_new_capacity_max = 20, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    try builder.addOwnership(fixtureDeclaration(owner, allocation, component, .{ .retire = .finish }));
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    const scope = try fixtureScope(tx, component);
    const allocator = try scope.allocator();
    const candidate = try allocator.alloc(u8, 16);
    const old_record = fixtureCoordinator(owner).allocations[try owner.allocationIndex(allocation)];
    const funded = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expect(!allocator.rawResize(old_record.ptr.?[0..old_record.len], .@"1", 40, @returnAddress()));
    try std.testing.expect(!backend.has_induced_failure);
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(tx.serial, fixtureCoordinator(owner).allocations[try owner.allocationIndex(allocation)].encumbered_transaction);
    allocator.free(candidate);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    const final_old = fixtureCoordinator(owner).allocations[try owner.allocationIndex(allocation)];
    try std.testing.expectEqual(@as(usize, 80), final_old.len);
    try std.testing.expect(std.mem.allEqual(u8, final_old.ptr.?[0..final_old.len], 0x6d));
}

test "physical whole ownership resident slots cannot be borrowed from future retirement" {
    const r = resources;
    var profile = testProfile();
    profile.allocation_slots_per_home = 2;
    const owner = try r.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const first = try fixtureResident(owner, component, component, 8, .@"1");
    const second = try fixtureResident(owner, component, component, 8, .@"1");
    const before = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 1, .final_new_capacity_max = 1, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    try builder.addOwnership(fixtureDeclaration(owner, first, component, .{ .retire = .publication }));
    try builder.addOwnership(fixtureDeclaration(owner, second, component, .keep));
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try builder.finish()));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).homes[component.slot].free_count);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(first)].encumbered_transaction);
}

test "physical whole ownership logical list spans original homes while candidate free preserves OLD backing" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const origin = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const logical = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const allocation = try fixtureResident(owner, origin, logical, 32, .@"1");
    try std.testing.expectEqual(origin.slot, allocation.home_slot);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).components[origin.slot].owned_count);
    try std.testing.expectEqual(@as(usize, 1), fixtureCoordinator(owner).components[logical.slot].owned_count);
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, .{ .component = logical, .expected_revision = 1, .new_capacity_peak = 16, .final_new_capacity_max = 16, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    try builder.addOwnership(fixtureDeclaration(owner, allocation, logical, .keep));
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    const scope = try fixtureScope(tx, logical);
    const allocator = try scope.allocator();
    const candidate = try allocator.alloc(u8, 16);
    try std.testing.expectEqual(@as(usize, 2), fixtureCoordinator(owner).components[logical.slot].owned_count);
    try std.testing.expectEqual(@as(u64, 48), fixtureCoordinator(owner).components[logical.slot].owned_charge);
    allocator.free(candidate);
    try std.testing.expectEqual(@as(usize, 1), fixtureCoordinator(owner).components[logical.slot].owned_count);
    try std.testing.expectEqual(@as(u64, 32), fixtureCoordinator(owner).components[logical.slot].owned_charge);
    try std.testing.expectEqual(@as(usize, 1), fixtureCoordinator(owner).homes[origin.slot].live_total);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).homes[logical.slot].live_total);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(allocation)].owner_prev +% 1);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole ownership declaration workspace refuses before late growth or encumbrance" {
    const r = resources;
    var profile = testProfile();
    profile.transaction_allocation_refs = 1;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const first = try fixtureResident(owner, component, component, 8, .@"1");
    const second = try fixtureResident(owner, component, component, 8, .@"1");
    const calls = backend.allocations;
    backend.fail_index = backend.alloc_index;
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, fixtureComponentPlan(component));
    try builder.addOwnership(fixtureDeclaration(owner, first, component, .keep));
    try std.testing.expectError(error.CapacityExceeded, builder.addOwnership(fixtureDeclaration(owner, second, component, .keep)));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(first)].encumbered_transaction);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(second)].declared_transaction);
    try std.testing.expectEqual(calls, backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
}

fn ownershipOom(allocator: std.mem.Allocator) !void {
    const r = resources;
    const owner = try r.Coordinator.create(allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    defer clearFixtureResidents(owner);
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const first = try fixtureResident(owner, component, component, 8, .@"1");
    const second = try fixtureResident(owner, component, component, 8, .@"1");
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 8, .final_new_capacity_max = 8, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    try builder.addOwnership(fixtureDeclaration(owner, first, component, .keep));
    try builder.addOwnership(fixtureDeclaration(owner, second, component, .{ .retire = .finish }));
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch {};
        tx.abort() catch {};
    }
    const scope = try fixtureScope(tx, component);
    const candidate = try (try scope.allocator()).alloc(u8, 8);
    (try scope.allocator()).free(candidate);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
}

test "physical whole ownership all declaration bootstrap OLD fixture and candidate OOM cuts unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownershipOom, .{});
}

test "physical whole ownership zero declaration workspace refuses before bootstrap allocation" {
    var profile = testProfile();
    profile.transaction_allocation_refs = 0;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidPlan, resources.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1)));
    try std.testing.expectEqual(@as(usize, 0), backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
}

fn explicitNewPlan(builder: resources.PlanBuilder, id: resources.ComponentId, peak: u64, retained: u64, slots: u32) !void {
    const participant = try fixtureParticipant(id);
    try builder.addComponent(.{ .component = id, .expected_revision = 1, .new_capacity_peak = peak, .final_new_capacity_max = retained, .final_wire_addition_max = 0, .new_allocation_slots = slots });
    if (fixtureCoordinator(builder.owner).participants[participant.slot].seen_transaction != builder.serial) try builder.addParticipant(try fixtureParticipantPlan(participant));
}

fn explicitRole(builder: resources.PlanBuilder, origin: resources.ComponentId, label: u32, destination: ?resources.ComponentId, charge: u64, count: u32) !resources.RoleId {
    return builder.addNewRole(.{ .origin = origin, .expected_origin_revision = 1, .label = label, .kind = if (destination) |id| .{ .retain = id } else .{ .discard = .finish }, .max_charge = charge, .max_live_allocations = count });
}

test "physical whole NEW roles require complete predeclared roles and unique canonical labels" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch unreachable;
    try explicitNewPlan(builder, a, 20, 10, 1);
    const calls = backend.allocations;
    backend.fail_index = backend.alloc_index;
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try std.testing.expectError(error.StaleTicket, explicitRole(builder, a, 0, b, 10, 1));
    _ = try explicitRole(builder, a, 7, a, 10, 1);
    _ = try explicitRole(builder, a, 7, null, 20, 1);
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try std.testing.expectEqual(calls, backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).homes[a.slot].active_transaction);
}

test "physical whole NEW roles reciprocal cross-category placement fits exact single-copy peak" {
    const r = resources;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const limits: r.Limits = .{ .resident = 50, .peak = 50, .wire = 0 };
    const ra = try owner.registerRow(2, 1, limits);
    const rb = try owner.registerRow(3, 1, limits);
    const a = try registerFixtureComponent(owner, ra, .output);
    const b = try registerFixtureComponent(owner, rb, .graph);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 50, 50, 1);
    try explicitNewPlan(builder, b, 50, 50, 1);
    const ar = try explicitRole(builder, a, 0, b, 50, 1);
    const br = try explicitRole(builder, b, 0, a, 50, 1);
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    }
    try std.testing.expectEqual(@as(u64, 100), fixtureCoordinator(owner).fleet.totals.preparation);
    for ([_]usize{ ra.slot, rb.slot }) |row| {
        try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[row].account.totals.preparation);
        try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[row].account.totals.resident_hold);
    }
    const aa = try (try fixtureScope(tx, a)).allocator();
    const ba = try (try fixtureScope(tx, b)).allocator();
    const ab = try aa.alloc(u8, 50);
    defer aa.free(ab);
    const bb = try ba.alloc(u8, 50);
    defer ba.free(bb);
    const aid = try (try fixtureScope(tx, a)).allocationId(ab, .@"1");
    const bid = try (try fixtureScope(tx, b)).allocationId(bb, .@"1");
    try std.testing.expectError(error.InvalidPlan, owner.validateNewClosure());
    try std.testing.expectError(error.StaleTicket, fixtureBindNew(tx, aid, br));
    var foreign = ar;
    foreign.instance = testInstance(2);
    try std.testing.expectError(error.StaleTicket, fixtureBindNew(tx, aid, foreign));
    try fixtureBindNew(tx, aid, ar);
    try fixtureBindNew(tx, bid, br);
    try std.testing.expectError(error.InvalidPlan, fixtureBindNew(tx, aid, ar));
    const calls = backend.allocations;
    try std.testing.expect(!aa.rawResize(ab, .@"1", 49, @returnAddress()));
    try std.testing.expectEqual(calls, backend.allocations);
    try owner.validateNewClosure();
    // Binding is still candidate custody at the original logical owner.
    try std.testing.expectEqual(a.slot, fixtureCoordinator(owner).allocations[try owner.allocationIndex(aid)].logical_owner);
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
}

test "physical whole NEW roles scratch overlap refuses peak before any candidate allocation" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const limits: r.Limits = .{ .resident = 50, .peak = 50, .wire = 0 };
    const ra = try owner.registerRow(2, 1, limits);
    const rb = try owner.registerRow(3, 1, limits);
    const a = try registerFixtureComponent(owner, ra, .output);
    const b = try registerFixtureComponent(owner, rb, .output);
    const old = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 50, 50, 1);
    try explicitNewPlan(builder, b, 50, 50, 1);
    _ = try explicitRole(builder, a, 0, b, 50, 1);
    _ = try explicitRole(builder, b, 0, a, 50, 1);
    _ = try explicitRole(builder, a, 1, null, 50, 1);
    _ = try explicitRole(builder, b, 1, null, 50, 1);
    const plan = try builder.finish();
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    fixtureCoordinator(owner).rows[ra.slot].account.limits.peak = 100;
    fixtureCoordinator(owner).rows[rb.slot].account.limits.peak = 100;
    const tx = try owner.beginTransaction(plan);
    try std.testing.expectEqual(@as(u64, 100), fixtureCoordinator(owner).rows[ra.slot].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 100), fixtureCoordinator(owner).rows[rb.slot].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 100), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).homes[a.slot].peak);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
}

test "physical whole NEW roles shared retained cap clips overflowing maxima and frees bindings" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const source_row = try owner.registerRow(2, 1, .{ .resident = 0, .peak = 100, .wire = 0 });
    const target_row = try owner.registerRow(3, 1, .{ .resident = 40, .peak = 40, .wire = 0 });
    const a = try registerFixtureComponent(owner, source_row, .output);
    const b = try registerFixtureComponent(owner, target_row, .output);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 100, 40, 3);
    try explicitNewPlan(builder, b, 0, 0, 0);
    const one = try explicitRole(builder, a, 0, b, std.math.maxInt(u64), 1);
    const two = try explicitRole(builder, a, 1, b, std.math.maxInt(u64), 1);
    _ = try explicitRole(builder, a, 2, null, std.math.maxInt(u64), 3);
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    }
    try std.testing.expectEqual(@as(u64, 40), fixtureCoordinator(owner).fleet.totals.resident_hold);
    try std.testing.expectEqual(@as(u64, 100), fixtureCoordinator(owner).fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 40), fixtureCoordinator(owner).rows[target_row.slot].account.totals.preparation);
    const scope = try fixtureScope(tx, a);
    const allocator = try scope.allocator();
    const x = try allocator.alloc(u8, 30);
    defer allocator.free(x);
    const y = try allocator.alloc(u8, 20);
    const xi = try scope.allocationId(x, .@"1");
    const yi = try scope.allocationId(y, .@"1");
    try fixtureBindNew(tx, xi, one);
    try std.testing.expectError(error.CapacityExceeded, fixtureBindNew(tx, yi, two));
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).roles[two.slot].actual_charge);
    try std.testing.expectEqual(r.vacant, fixtureCoordinator(owner).allocations[try owner.allocationIndex(yi)].role_slot);
    allocator.free(y); // Transient unbound scratch may disappear before sealing.
    const z = try allocator.alloc(u8, 10);
    const zi = try scope.allocationId(z, .@"1");
    try fixtureBindNew(tx, zi, two);
    try owner.validateNewClosure();
    allocator.free(z);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).roles[two.slot].actual_charge);
    try std.testing.expectEqual(@as(u32, 0), fixtureCoordinator(owner).roles[two.slot].actual_count);
    const again = try allocator.alloc(u8, 10);
    defer allocator.free(again);
    try fixtureBindNew(tx, try scope.allocationId(again, .@"1"), two);
    try std.testing.expectError(error.StaleTicket, fixtureBindNew(tx, zi, two));
}

test "physical whole NEW roles workspace and generation refuse without backend mutation" {
    const r = resources;
    var profile = testProfile();
    profile.new_role_slots = 1;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try r.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const old = fixtureCoordinator(owner).fleet.totals;
    fixtureCoordinator(owner).serial = std.math.maxInt(u64) - 1;
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 10, 10, 1);
    fixtureCoordinator(owner).role_serial = std.math.maxInt(u64) - 1;
    const last = try explicitRole(builder, a, 9, a, 10, 1);
    try std.testing.expectEqual(std.math.maxInt(u64), last.serial);
    try std.testing.expectError(error.GenerationExhausted, explicitRole(builder, a, 10, a, 10, 1));
    fixtureCoordinator(owner).role_serial = 1; // Private boundary fixture; no production issuer reset.
    try std.testing.expectError(error.CapacityExceeded, explicitRole(builder, a, 10, a, 10, 1));
    const tx = try owner.beginTransaction(try builder.finish());
    const allocator = try (try fixtureScope(tx, a)).allocator();
    const x = try allocator.alloc(u8, 10);
    try fixtureBindNew(tx, try (try fixtureScope(tx, a)).allocationId(x, .@"1"), last);
    allocator.free(x);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(old, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectError(error.StaleTicket, fixtureBindNew(tx, .{ .owner = owner, .identity = owner, .instance = fixtureCoordinator(owner).instance, .home_slot = a.slot, .home_serial = a.serial, .allocation_slot = 0, .serial = 1 }, last));
    try std.testing.expectError(error.GenerationExhausted, owner.beginPlan(1));
}

test "physical whole NEW roles zero workspace rejects before backend allocation" {
    var profile = testProfile();
    profile.new_role_slots = 0;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidPlan, resources.Coordinator.create(backend.allocator(), profile, .empty, testInstance(1)));
    try std.testing.expectEqual(@as(usize, 0), backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
}

test "physical whole NEW roles OLD outgoing credits placement but retirement never credits peak" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const limits: r.Limits = .{ .resident = 50, .peak = 50, .wire = 0 };
    const ra = try owner.registerRow(2, 1, limits);
    const rb = try owner.registerRow(3, 1, limits);
    const a = try registerFixtureComponent(owner, ra, .output);
    const b = try registerFixtureComponent(owner, rb, .output);
    const old_id = try fixtureResident(owner, a, a, 50, .@"1");
    defer clearFixtureResidents(owner);
    const before = fixtureCoordinator(owner).fleet.totals;
    const first = try owner.beginPlan(1);
    try explicitNewPlan(first, a, 0, 0, 0);
    try explicitNewPlan(first, b, 50, 50, 1);
    try first.addOwnership(fixtureDeclaration(owner, old_id, a, .{ .move = b }));
    const role = try explicitRole(first, b, 0, a, 50, 1);
    const tx = try owner.beginTransaction(try first.finish());
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).rows[ra.slot].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).rows[rb.slot].account.totals.preparation);
    try std.testing.expectEqual(@as(u64, 50), fixtureCoordinator(owner).fleet.totals.preparation);
    const scope = try fixtureScope(tx, b);
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 50);
    try fixtureBindNew(tx, try scope.allocationId(bytes, .@"1"), role);
    try owner.validateNewClosure();
    allocator.free(bytes);
    try fixtureReleaseIdleLoans(tx);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    const second = try owner.beginPlan(1);
    try explicitNewPlan(second, a, 0, 0, 0);
    try explicitNewPlan(second, b, 50, 50, 1);
    try second.addOwnership(fixtureDeclaration(owner, old_id, a, .{ .retire = .finish }));
    _ = try explicitRole(second, b, 0, a, 50, 1);
    const plan = try second.finish();
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try second.abort();
}

fn newRoleOom(backend: std.mem.Allocator) !void {
    const owner = try resources.Coordinator.create(backend, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 30, 20, 2);
    const retained = try explicitRole(builder, a, 0, a, 20, 2);
    const discarded = try explicitRole(builder, a, 1, null, 10, 1);
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    }
    const allocator = try (try fixtureScope(tx, a)).allocator();
    const x = try allocator.alloc(u8, 10);
    defer allocator.free(x);
    try fixtureBindNew(tx, try (try fixtureScope(tx, a)).allocationId(x, .@"1"), retained);
    const y = try allocator.alloc(u8, 10);
    defer allocator.free(y);
    try fixtureBindNew(tx, try (try fixtureScope(tx, a)).allocationId(y, .@"1"), discarded);
    try owner.validateNewClosure();
}

test "physical whole NEW roles allocation failures unwind role and shared counters" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, newRoleOom, .{});
}

test "physical whole participant funding alone does not activate an allocator" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const component = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = component, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 32, .final_wire_addition_max = 0, .new_allocation_slots = 1 });
    const tx = try owner.beginTransaction(try builder.finish());
    defer {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    }
    const allocation = fixtureCoordinator(owner).homes[component.slot].allocator();
    const result = allocation.alloc(u8, 8);
    if (result) |bytes| allocation.free(bytes) else |_| {}
    try std.testing.expectError(error.OutOfMemory, result);
}

fn participantNoNew(component: resources.ComponentId) resources.ComponentPlan {
    return .{ .component = component, .expected_revision = 1, .new_capacity_peak = 0, .final_new_capacity_max = 0, .final_wire_addition_max = 0 };
}

test "physical whole participant enrollment is complete atomic and generation bounded" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    var stale = owner.infrastructureRow();
    stale.generation += 1;
    const catalog = [_]r.FixtureHome{ .{ .row = owner.infrastructureRow(), .category = .graph }, .{ .row = stale, .category = .output } };
    try std.testing.expectError(error.StaleTicket, owner.registerFixture(&catalog));
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).component_count);
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).participant_count);
    try std.testing.expectError(error.InvalidPlan, owner.registerFixture(&.{}));
    fixtureCoordinator(owner).participant_serial = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, owner.registerFixture(catalog[0..1]));
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).component_count);
    fixtureCoordinator(owner).participant_serial = 0;
    fixtureCoordinator(owner).component_serial = std.math.maxInt(u64) - 1;
    var valid = catalog;
    valid[1].row = owner.infrastructureRow();
    try std.testing.expectError(error.GenerationExhausted, owner.registerFixture(&valid));
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).participant_count);
    fixtureCoordinator(owner).component_serial = 0;
    const participant = try owner.registerFixture(&valid);
    const a = try fixtureHome(participant, 0);
    const b = try fixtureHome(participant, 1);
    try std.testing.expectEqual(participant.slot, fixtureCoordinator(owner).components[a.slot].participant_slot);
    try std.testing.expectEqual(participant.serial, fixtureCoordinator(owner).components[b.slot].participant_serial);
    try std.testing.expectEqual(@as(usize, 2), fixtureCoordinator(owner).participants[participant.slot].component_count);
    try std.testing.expectError(error.InvalidPlan, fixtureHome(participant, 2));
    const builder = try owner.beginPlan(1);
    try std.testing.expectError(error.Busy, owner.registerFixture(valid[0..1]));
    try builder.abort();
}

test "physical whole participant plans reject missing duplicate foreign and stale source identity" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const other = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer other.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const foreign = try registerFixtureComponent(other, other.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try builder.addComponent(participantNoNew(a));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try std.testing.expectError(error.StaleTicket, builder.addParticipant(try fixtureParticipantPlan(try fixtureParticipant(foreign))));
    var plan = try fixtureParticipantPlan(id);
    plan.expected_owner_revision += 1;
    try std.testing.expectError(error.StaleTicket, builder.addParticipant(plan));
    plan = try fixtureParticipantPlan(id);
    plan.expected_old_census_revision += 1;
    try std.testing.expectError(error.StaleTicket, builder.addParticipant(plan));
    var forged = id;
    forged.identity = other;
    plan = try fixtureParticipantPlan(id);
    plan.participant = forged;
    try std.testing.expectError(error.StaleTicket, builder.addParticipant(plan));
    try builder.addParticipant(try fixtureParticipantPlan(id));
    try std.testing.expectError(error.InvalidPlan, builder.addParticipant(try fixtureParticipantPlan(id)));
    fixtureCoordinator(owner).participants[id.slot].source.lifetime += 1;
    try std.testing.expectError(error.StaleTicket, builder.finish());
    fixtureCoordinator(owner).participants[id.slot].source.lifetime -= 1;
    _ = try builder.finish();
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).participants[id.slot].source.prepare_count);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).homes[a.slot].active_transaction);
}

test "physical whole participant multi-home coverage includes unchanged OLD keep census" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const id = try owner.registerFixture(&.{ .{ .row = owner.infrastructureRow(), .category = .graph }, .{ .row = owner.infrastructureRow(), .category = .output } });
    const a = try fixtureHome(id, 0);
    const b = try fixtureHome(id, 1);
    const old_a = try fixtureResident(owner, a, a, 8, .@"1");
    const old_b = try fixtureResident(owner, b, b, 8, .@"1");
    defer clearFixtureResidents(owner);
    const builder = try owner.beginPlan(1);
    try builder.addParticipant(try fixtureParticipantPlan(id));
    try builder.addComponent(participantNoNew(a));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try builder.addComponent(participantNoNew(b));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try builder.addOwnership(.{ .allocation = old_a, .expected_owner = a, .expected_owner_revision = 1, .expected_length = 8, .expected_alignment = .@"1", .disposition = .keep });
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try builder.addOwnership(.{ .allocation = old_b, .expected_owner = b, .expected_owner_revision = 1, .expected_length = 8, .expected_alignment = .@"1", .disposition = .keep });
    const tx = try owner.beginTransaction(try builder.finish());
    try std.testing.expectEqual(@as(usize, 2), fixtureCoordinator(owner).participant_entries[0].planned_component_count);
    const loan = try tx.participantLoan(id);
    _ = try loan.componentScope(a);
    _ = try loan.componentScope(b);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
}

test "physical whole participant rechecks actual revisions before funding and loan issue" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    const before = fixtureCoordinator(owner).fleet.totals;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, .{ .component = a, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 16, .final_wire_addition_max = 7, .new_allocation_slots = 1 });
    const plan = try builder.finish();
    source.revision += 1;
    try std.testing.expectError(error.StaleTicket, owner.beginTransaction(plan));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), source.prepare_count);
    source.revision -= 1;
    source.census_revision += 1;
    try std.testing.expectError(error.StaleTicket, owner.beginTransaction(plan));
    source.census_revision -= 1;
    const tx = try owner.beginTransaction(plan);
    const funded = fixtureCoordinator(owner).fleet.totals;
    source.revision += 1;
    try std.testing.expectError(error.StaleTicket, tx.participantLoan(id));
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).homes[a.slot].active_transaction);
    source.revision -= 1;
    const loan = try tx.participantLoan(id);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
}

test "physical whole participant zero-heap source ticket blocks release and whole refund" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, participantNoNew(a));
    const tx = try owner.beginTransaction(try builder.finish());
    const loan = try tx.participantLoan(id);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    try source.prepare(loan);
    const funded = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expect(source.ticket != null);
    try std.testing.expectEqual(tx.serial, source.guard.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).homes[a.slot].live_new);
    try std.testing.expectError(error.Busy, source.prepare(loan));
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try source.abort(loan);
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try owner.releaseAbortedParticipant(loan);
    try std.testing.expectError(error.StaleTicket, owner.releaseAbortedParticipant(loan));
    try std.testing.expectError(error.StaleTicket, tx.participantLoan(id));
    try tx.abort();
}

test "physical whole participant actual borrow pin cannot be replayed or silently cleared" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, participantNoNew(a));
    const tx = try owner.beginTransaction(try builder.finish());
    var cleanup = true;
    defer if (cleanup) {
        fixtureReleaseIdleLoans(tx) catch unreachable;
        tx.abort() catch unreachable;
    };
    const loan = try tx.participantLoan(id);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    const pin = try source.pinBorrow(loan);
    try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
    try std.testing.expectError(error.ParticipantsHeld, fixtureReleaseIdleLoans(tx));
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try pin.finish();
    // Preserve failure cleanup in the deliberate old replay-policy overlay.
    const repeated = source.pinBorrow(loan);
    if (repeated) |unexpected_pin| {
        const before_replay = source.borrow_transaction;
        const replay = pin.finish();
        const after_replay = source.borrow_transaction;
        if (after_replay != 0) try unexpected_pin.finish();
        std.debug.print("borrow replay witness: before={d} after={d}\n", .{ before_replay, after_replay });
        try std.testing.expectError(error.StaleTicket, replay);
    } else |err| try std.testing.expectEqual(error.StaleTicket, err);
    try std.testing.expectError(error.StaleTicket, repeated);
    try std.testing.expectError(error.StaleTicket, pin.finish());
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    cleanup = false;
}

test "physical whole participant live candidate and zero binding keep allocation refusal precedence" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 32, 16, 1);
    const role = try explicitRole(builder, a, 0, a, 16, 1);
    const tx = try owner.beginTransaction(try builder.finish());
    const id = try fixtureParticipant(a);
    const loan = try tx.participantLoan(id);
    const scope = try loan.componentScope(a);
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 16);
    try loan.bindNewAllocation(try scope.allocationId(bytes, .@"1"), role);
    try std.testing.expectError(error.AllocationsHeld, owner.releaseAbortedParticipant(loan));
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    try source.prepare(loan);
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    try source.abort(loan);
    // Source abort does not free the buffer that the test, rather than the
    // source ticket, owns. The home independently proves its live candidate.
    try std.testing.expectError(error.AllocationsHeld, owner.releaseAbortedParticipant(loan));
    allocator.free(bytes);
    try std.testing.expectEqual(@as(u32, 0), fixtureCoordinator(owner).roles[role.slot].actual_count);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).roles[role.slot].actual_charge);
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
}

test "physical whole participant release disables one source without refunding any account" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const builder = try owner.beginPlan(1);
    for ([_]r.ComponentId{ a, b }) |c| try addTestComponent(builder, .{ .component = c, .expected_revision = 1, .new_capacity_peak = 32, .final_new_capacity_max = 16, .final_wire_addition_max = 5, .new_allocation_slots = 1 });
    const tx = try owner.beginTransaction(try builder.finish());
    const ai = try fixtureParticipant(a);
    const bi = try fixtureParticipant(b);
    const al = try tx.participantLoan(ai);
    const bl = try tx.participantLoan(bi);
    const ascope = try al.componentScope(a);
    const aa = try ascope.allocator();
    const ba = try (try bl.componentScope(b)).allocator();
    const bytes = try ba.alloc(u8, 16);
    const funded = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expectError(error.StaleTicket, al.componentScope(b));
    try std.testing.expectError(error.StaleTicket, tx.participantLoan(ai));
    try owner.releaseAbortedParticipant(al);
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectError(error.StaleTicket, al.componentScope(a));
    try std.testing.expectError(error.StaleTicket, ascope.allocator());
    try std.testing.expectError(error.OutOfMemory, aa.alloc(u8, 1));
    try std.testing.expectError(error.StaleTicket, owner.releaseAbortedParticipant(al));
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    ba.free(bytes);
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try owner.releaseAbortedParticipant(bl);
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try tx.abort();
}

fn participantCandidateOom(allocator: std.mem.Allocator) !void {
    const r = resources;
    const owner = try r.Coordinator.create(allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 32, 16, 1);
    const role = try explicitRole(builder, a, 0, a, 16, 1);
    const tx = try owner.beginTransaction(try builder.finish());
    const loan = try tx.participantLoan(id);
    try source.prepare(loan);
    defer {
        source.abort(loan) catch unreachable;
        owner.releaseAbortedParticipant(loan) catch unreachable;
        tx.abort() catch unreachable;
    }
    source.prepareBuffer(loan, a, 16) catch |err| {
        try std.testing.expect(source.candidate == null);
        try std.testing.expect(source.ticket != null);
        try std.testing.expectEqual(tx.serial, source.guard.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).homes[a.slot].live_new);
        try std.testing.expectError(error.ParticipantsHeld, tx.abort());
        return err;
    };
    const scope = try loan.componentScope(a);
    const bytes = source.candidate.?.bytes;
    @memset(bytes, 0x6b);
    try loan.bindNewAllocation(try scope.allocationId(bytes, .@"1"), role);
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
}

test "physical whole participant every bootstrap and owned source candidate OOM unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, participantCandidateOom, .{});
}

test "physical whole participant workspace and metadata refusal do not prepare a source" {
    const r = resources;
    inline for (0..3) |variant| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        var profile = testProfile();
        if (variant == 0) profile.participant_slots = 0;
        if (variant == 1) profile.transaction_participant_refs = 0;
        if (variant == 2) profile.transaction_participant_refs = profile.participant_slots + 1;
        try std.testing.expectError(error.InvalidPlan, r.Coordinator.create(failing.allocator(), profile, .empty, testInstance(1)));
        try std.testing.expectEqual(@as(usize, 0), failing.allocations);
    }
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var impossible = testProfile();
    impossible.participant_slots = std.math.maxInt(u32);
    impossible.transaction_participant_refs = std.math.maxInt(u32);
    try std.testing.expectError(error.CapacityExceeded, r.Coordinator.create(failing.allocator(), impossible, .empty, testInstance(1)));
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
    var profile = testProfile();
    profile.transaction_participant_refs = 1;
    const owner = try r.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const builder = try owner.beginPlan(1);
    defer builder.abort() catch {};
    try builder.addParticipant(try fixtureParticipantPlan(try fixtureParticipant(a)));
    try std.testing.expectError(error.CapacityExceeded, builder.addParticipant(try fixtureParticipantPlan(try fixtureParticipant(b))));
    try builder.addComponent(participantNoNew(a));
    try builder.addComponent(participantNoNew(b));
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    for (fixtureCoordinator(owner).participants[0..fixtureCoordinator(owner).participant_count]) |*p| try std.testing.expectEqual(@as(usize, 0), p.source.prepare_count);
}

test "physical whole participant final serial permits actual source abort release and refund" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    fixtureCoordinator(owner).participant_serial = std.math.maxInt(u64) - 1;
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    try std.testing.expectEqual(std.math.maxInt(u64), id.serial);
    fixtureCoordinator(owner).serial = std.math.maxInt(u64) - 1;
    const builder = try owner.beginPlan(1);
    try addTestComponent(builder, participantNoNew(a));
    const tx = try owner.beginTransaction(try builder.finish());
    try std.testing.expectEqual(std.math.maxInt(u64), tx.serial);
    const loan = try tx.participantLoan(id);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    try source.prepare(loan);
    const borrow = try source.pinBorrow(loan);
    try std.testing.expectError(error.ParticipantsHeld, source.abort(loan));
    try borrow.finish();
    try source.abort(loan);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    try std.testing.expectError(error.GenerationExhausted, owner.beginPlan(1));
    try std.testing.expectError(error.GenerationExhausted, owner.registerFixture(&.{.{ .row = owner.infrastructureRow(), .category = .output }}));
}

test "physical whole participant role binding requires its issued origin loan" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 16, 16, 1);
    try explicitNewPlan(builder, b, 16, 16, 1);
    const role = try explicitRole(builder, a, 0, b, 16, 1);
    _ = try explicitRole(builder, b, 0, a, 16, 1);
    const tx = try owner.beginTransaction(try builder.finish());
    const al = try tx.participantLoan(try fixtureParticipant(a));
    const ascope = try al.componentScope(a);
    const aa = try ascope.allocator();
    const bytes = try aa.alloc(u8, 16);
    const allocation = try ascope.allocationId(bytes, .@"1");
    const bi = try fixtureParticipant(b);
    const bl = try tx.participantLoan(bi);
    try std.testing.expectError(error.StaleTicket, bl.bindNewAllocation(allocation, role));
    var copied = al;
    copied.participant_serial = bi.serial;
    copied.participant_slot = bi.slot;
    try std.testing.expectError(error.StaleTicket, copied.bindNewAllocation(allocation, role));
    try al.bindNewAllocation(allocation, role);
    aa.free(bytes);
    try owner.releaseAbortedParticipant(bl);
    try owner.releaseAbortedParticipant(al);
    try tx.abort();
}

test "physical whole participant whole abort preserves all OLD encumbrances until every loan closes" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const b = try registerFixtureComponent(owner, owner.infrastructureRow(), .output);
    const old_a = try fixtureResident(owner, a, a, 8, .@"1");
    const old_b = try fixtureResident(owner, b, b, 8, .@"1");
    defer clearFixtureResidents(owner);
    const builder = try owner.beginPlan(1);
    for ([_]r.ComponentId{ a, b }) |c| try addTestComponent(builder, .{ .component = c, .expected_revision = 1, .new_capacity_peak = 16, .final_new_capacity_max = 8, .final_wire_addition_max = 3, .new_allocation_slots = 1 });
    try builder.addOwnership(.{ .allocation = old_a, .expected_owner = a, .expected_owner_revision = 1, .expected_length = 8, .expected_alignment = .@"1", .disposition = .keep });
    try builder.addOwnership(.{ .allocation = old_b, .expected_owner = b, .expected_owner_revision = 1, .expected_length = 8, .expected_alignment = .@"1", .disposition = .keep });
    const tx = try owner.beginTransaction(try builder.finish());
    const ai = try fixtureParticipant(a);
    const bi = try fixtureParticipant(b);
    const al = try tx.participantLoan(ai);
    const bl = try tx.participantLoan(bi);
    const source = &fixtureCoordinator(owner).participants[ai.slot].source;
    try source.prepare(al);
    const ba = try (try bl.componentScope(b)).allocator();
    const bytes = try ba.alloc(u8, 8);
    const funded = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    var wrong = bl;
    wrong.participant_slot = ai.slot;
    try std.testing.expectError(error.StaleTicket, owner.releaseAbortedParticipant(wrong));
    try std.testing.expectError(error.AllocationsHeld, owner.releaseAbortedParticipant(bl));
    ba.free(bytes);
    try owner.releaseAbortedParticipant(bl);
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try std.testing.expectEqual(tx.serial, fixtureCoordinator(owner).allocations[try owner.allocationIndex(old_a)].encumbered_transaction);
    try std.testing.expectEqual(tx.serial, fixtureCoordinator(owner).allocations[try owner.allocationIndex(old_b)].encumbered_transaction);
    try std.testing.expectEqual(tx.serial, fixtureCoordinator(owner).homes[a.slot].active_transaction);
    try source.abort(al);
    try owner.releaseAbortedParticipant(al);
    try std.testing.expectEqualDeep(funded, fixtureCoordinator(owner).fleet.totals);
    try tx.abort();
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(old_a)].encumbered_transaction);
    try std.testing.expectEqual(@as(u64, 0), fixtureCoordinator(owner).allocations[try owner.allocationIndex(old_b)].encumbered_transaction);
}

test "physical whole participant unplanned role receiver and late budget refusal precede source preparation" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const row = try owner.registerRow(2, 1, .{ .resident = 1, .peak = 32, .wire = 0 });
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const b = try registerFixtureComponent(owner, row, .output);
    const builder = try owner.beginPlan(1);
    try explicitNewPlan(builder, a, 16, 16, 1);
    try builder.addComponent(participantNoNew(b));
    _ = try explicitRole(builder, a, 0, b, 16, 1);
    try std.testing.expectError(error.InvalidPlan, builder.finish());
    try builder.addParticipant(try fixtureParticipantPlan(try fixtureParticipant(b)));
    const before = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try builder.finish()));
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    for (fixtureCoordinator(owner).participants[0..fixtureCoordinator(owner).participant_count]) |*p| {
        try std.testing.expectEqual(@as(usize, 0), p.source.prepare_count);
        try std.testing.expect(p.source.ticket == null and p.source.guard.load(.acquire) == 0);
    }
    for (fixtureCoordinator(owner).homes[0..fixtureCoordinator(owner).component_count]) |home| try std.testing.expectEqual(@as(u64, 0), home.active_transaction);
    try builder.abort();
}

test "physical whole participant typed loans scopes and borrow pins reject later home epochs" {
    const r = resources;
    const owner = try r.Coordinator.create(std.testing.allocator, testProfile(), .empty, testInstance(1));
    defer owner.deinit();
    const a = try registerFixtureComponent(owner, owner.infrastructureRow(), .graph);
    const id = try fixtureParticipant(a);
    const source = &fixtureCoordinator(owner).participants[id.slot].source;
    const first = try owner.beginPlan(1);
    try addTestComponent(first, participantNoNew(a));
    const old_tx = try owner.beginTransaction(try first.finish());
    const old_loan = try old_tx.participantLoan(id);
    const old_scope = try old_loan.componentScope(a);
    const facade = try old_scope.allocator();
    const old_pin = try source.pinBorrow(old_loan);
    try old_pin.finish();
    try owner.releaseAbortedParticipant(old_loan);
    try old_tx.abort();
    const second = try owner.beginPlan(1);
    try addTestComponent(second, participantNoNew(a));
    const tx = try owner.beginTransaction(try second.finish());
    const loan = try tx.participantLoan(id);
    const scope = try loan.componentScope(a);
    const pin = try source.pinBorrow(loan);
    try std.testing.expectError(error.StaleTicket, old_loan.componentScope(a));
    try std.testing.expectError(error.StaleTicket, old_scope.allocator());
    try std.testing.expectError(error.StaleTicket, old_pin.finish());
    try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
    // This equality explains why source quiescence, not a raw-facade generation
    // promise, is mandatory. The old facade is NEVER used after its lexical cut.
    try std.testing.expectEqual(facade.ptr, (try scope.allocator()).ptr);
    try pin.finish();
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
}

fn storeTestProfile() resources.Profile {
    const limits: resources.Limits = .{ .resident = 64 * 1024 * 1024, .peak = 128 * 1024 * 1024, .wire = 0 };
    return .{ .fleet = limits, .categories = .{ limits, limits }, .infrastructure = limits, .rows = 2, .components = 24, .transaction_components = 24, .participant_slots = 3, .transaction_participant_refs = 3, .transaction_work_max = 10000000, .allocation_slots_per_home = 128, .transaction_allocation_refs = 384, .new_role_slots = 32 };
}
fn storeTestAllowances() resources.StoreAllowances {
    var result: resources.StoreAllowances = .{ .homes = @splat(.{ .peak = 1024 * 1024, .final = 1024 * 1024, .slots = 32 }), .uses = @splat(.{ .charge = 1024 * 1024, .slots = 32 }), .work = 1000000 };
    result.homes[0].final = 0; // The encoded WAL packet is discard-only.
    return result;
}
fn storeTestFunding(owner: *resources.Coordinator, id: resources.ParticipantId, allowances: resources.StoreAllowances) !resources.TransactionReservation {
    const builder = try owner.beginPlan(1);
    errdefer builder.abort() catch unreachable;
    try owner.addStorePlan(builder, id, allowances);
    return owner.beginTransaction(try builder.finish());
}
fn storeTestSpec(owner: *resources.Coordinator, tmp: std.testing.TmpDir, metadata: std.mem.Allocator, payload: std.mem.Allocator, candidate: std.mem.Allocator, seed: bool) resources.StoreSpec {
    return .{ .row = owner.infrastructureRow(), .args = .{ .metadata_allocator = metadata, .store_allocator = payload, .io = std.testing.io, .dir = tmp.dir, .path = "s2.wal", .config = .{ .changefeed_capacity = 64 } }, .candidate_allocator = candidate, .seed_pending = seed };
}

test "physical Store S2 complete original R T census preserves three real backends" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var metadata = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var payload = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(7));
    defer owner.deinit();
    const before = fixtureCoordinator(owner).fleet.totals;
    const id = try owner.constructStore(storeTestSpec(owner, tmp, metadata.allocator(), payload.allocator(), candidate.allocator(), true));
    var destroyed = false;
    defer if (!destroyed) owner.destroyStore(id) catch unreachable;
    const b = fixtureCoordinator(owner);
    const p = &b.participants[id.slot];
    try std.testing.expectEqual(@as(usize, 8), p.component_count);
    try std.testing.expectEqual(@as(usize, 2), b.homes[p.first_component].live_total);
    var resident: u64 = 0;
    var retiring: u64 = 0;
    var meta_bytes: usize = 0;
    var payload_bytes: usize = 0;
    var count: usize = 0;
    var next = b.components[p.first_component].owned_head;
    while (next != resources.vacant) {
        const r = b.allocations[next];
        const origin = next / b.slots_per_home;
        try std.testing.expect(r.root != null and r.ptr != null);
        if (origin == p.first_component) meta_bytes += r.len else {
            try std.testing.expectEqual(p.first_component + 1, origin);
            payload_bytes += r.len;
        }
        if (r.state == .retiring) retiring += r.charge else resident += r.charge;
        count += 1;
        next = r.owner_next;
    }
    try std.testing.expect(retiring != 0);
    try std.testing.expectEqual(metadata.allocated_bytes - metadata.freed_bytes, meta_bytes);
    try std.testing.expectEqual(payload.allocated_bytes - payload.freed_bytes, payload_bytes);
    try std.testing.expectEqual(resident, b.fleet.totals.resident - before.resident);
    try std.testing.expectEqual(retiring, b.fleet.totals.retiring);
    try std.testing.expectEqual(count, b.original_span_count);
    for (2..8) |ordinal| {
        const home = b.homes[p.first_component + ordinal];
        try std.testing.expectEqual(@as(usize, 0), home.live_total);
        try std.testing.expectEqual(candidate.allocator().ptr, home.backend.ptr);
    }
    try std.testing.expectEqual(@as(usize, 0), candidate.allocations);
    try owner.destroyStore(id);
    destroyed = true;
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqual(metadata.allocated_bytes, metadata.freed_bytes);
    try std.testing.expectEqual(payload.allocated_bytes, payload.freed_bytes);
}

const storeTestMutations = [_]store.BatchMutation{
    .{ .family = .memos, .kind = .put, .key = "new", .value = "memo" },
    .{ .family = .accounts, .kind = .put, .key = "account", .value = "updated" },
    .{ .family = .vhosts, .kind = .put, .key = "host", .value = "name" },
    .{ .family = .props, .kind = .delete, .key = "p0" },
};

test "physical Store S2 actual funded candidate zero heap guard and exact OLD abort" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var metadata = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var payload = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(8));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, metadata.allocator(), payload.allocator(), candidate.allocator(), true));
    defer owner.destroyStore(id) catch unreachable;
    const b = fixtureCoordinator(owner);
    const m = &b.participants[id.slot].managed;
    const source = m.owner.?;
    const old = try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot));
    const old_totals = b.fleet.totals;
    const wal = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(wal);
    var read = try source.borrowRead(owner.storeId(id.slot));
    try std.testing.expectError(error.Busy, owner.acquireStore(id));
    try read.finish();
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    metadata.fail_index = metadata.alloc_index;
    payload.fail_index = payload.alloc_index;
    var allowances = storeTestAllowances();
    allowances.work = b.transaction_work_max; // Exact largest admitted finite allowance.
    const tx = try storeTestFunding(owner, id, allowances);
    const loan = try tx.participantLoan(id);
    const c = try source.beginCandidate(m.exclusion.?, loan);
    try std.testing.expectEqual(@as(usize, 0), (try source.inspectCandidate(c)).allocation_count);
    try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
    try std.testing.expectError(error.ParticipantsHeld, tx.abort());
    try source.prepareBatch(c, &storeTestMutations);
    const prepared = try source.inspectCandidate(c);
    try std.testing.expectEqual(.prepared, prepared.state);
    try std.testing.expect(prepared.allocation_count > 10 and prepared.work_used > 0);
    try std.testing.expectEqual(b.transaction_work_max, prepared.work_limit);
    for (0..prepared.allocation_count) |i| {
        const allocation = (try source.inspectCandidateAllocation(c, i)).?;
        const actual = allocation.id.?;
        const record = b.allocations[try owner.allocationIndex(actual)];
        try std.testing.expectEqual(allocation.locator, @intFromPtr(record.ptr.?));
        try std.testing.expectEqual(allocation.role.slot, record.role_slot);
        try std.testing.expectEqual(candidate.allocator().ptr, b.homes[actual.home_slot].backend.ptr);
    }
    try std.testing.expectError(error.AllocationsHeld, tx.abort());
    try source.abortPreAttempt(c);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    try std.testing.expectEqualDeep(old_totals, b.fleet.totals);
    try std.testing.expectEqualDeep(old, try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot)));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, wal, after);
    try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
    try std.testing.expect(!metadata.has_induced_failure and !payload.has_induced_failure);
}

test "physical Store S2 finite shared work and sparse absent table role retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(9));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, std.testing.allocator, std.testing.allocator, candidate.allocator(), true));
    defer owner.destroyStore(id) catch unreachable;
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    const m = &fixtureCoordinator(owner).participants[id.slot].managed;
    const source = m.owner.?;
    const before = fixtureCoordinator(owner).fleet.totals;
    var small = storeTestAllowances();
    small.work = 1;
    {
        const tx = try storeTestFunding(owner, id, small);
        const loan = try tx.participantLoan(id);
        const c = try source.beginCandidate(m.exclusion.?, loan);
        try std.testing.expectError(error.TableWorkExceeded, source.prepareBatch(c, &storeTestMutations));
        try std.testing.expectEqual(.failed, (try source.inspectCandidate(c)).state);
        try std.testing.expectEqual(@as(usize, 0), candidate.allocations);
        try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
        try source.abortPreAttempt(c);
        try owner.releaseAbortedParticipant(loan);
        try tx.abort();
    }
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
    var sparse = storeTestAllowances();
    sparse.homes[5] = .{ .peak = 0, .final = 0, .slots = 0 };
    sparse.uses[@intFromEnum(store.CandidateUse.table_backing)] = .{ .charge = 0, .slots = 0 };
    const tx = try storeTestFunding(owner, id, sparse);
    const loan = try tx.participantLoan(id);
    try std.testing.expectError(error.CapacityExceeded, resources.storeAllocationBinding(loan, .table_backing));
    const c = try source.beginCandidate(m.exclusion.?, loan);
    try source.prepareBatch(c, &.{.{ .family = .accounts, .kind = .put, .key = "account", .value = "same-slot" }});
    const ready = try source.inspectCandidate(c);
    for (0..ready.allocation_count) |i| try std.testing.expect((try source.inspectCandidateAllocation(c, i)).?.use != .table_backing);
    try source.abortPreAttempt(c);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
}

fn storeConstructionOom(allocator: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try resources.Coordinator.create(allocator, storeTestProfile(), .empty, testInstance(10));
    defer owner.deinit();
    const before = fixtureCoordinator(owner).fleet.totals;
    const id = owner.constructStore(storeTestSpec(owner, tmp, allocator, allocator, allocator, false)) catch |err| {
        try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
        try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).component_count);
        try std.testing.expectEqual(@as(usize, 0), fixtureCoordinator(owner).original_span_count);
        return err;
    };
    try owner.destroyStore(id);
    try std.testing.expectEqualDeep(before, fixtureCoordinator(owner).fleet.totals);
}

test "physical Store S2 whole constructor bootstrap source and import OOM ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, storeConstructionOom, .{});
}

fn storeCandidateAttempt(owner: *resources.Coordinator, id: resources.ParticipantId) !void {
    return storeCandidateAttemptMutations(owner, id, &storeTestMutations);
}

fn storeCandidateAttemptMutations(owner: *resources.Coordinator, id: resources.ParticipantId, mutations: []const store.BatchMutation) !void {
    const m = &fixtureCoordinator(owner).participants[id.slot].managed;
    const tx = try storeTestFunding(owner, id, storeTestAllowances());
    defer tx.abort() catch unreachable;
    const loan = try tx.participantLoan(id);
    defer owner.releaseAbortedParticipant(loan) catch unreachable;
    const c = try m.owner.?.beginCandidate(m.exclusion.?, loan);
    defer m.owner.?.abortPreAttempt(c) catch unreachable;
    try m.owner.?.prepareBatch(c, mutations);
    try resources.StoreBridge.TestFixture.requireOwnedCandidate(m.owner.?, c, mutations);
}

test "physical Store S2 every NEW backend failure retains exact OLD and retries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(11));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, std.testing.allocator, std.testing.allocator, candidate.allocator(), true));
    defer owner.destroyStore(id) catch unreachable;
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    const b = fixtureCoordinator(owner);
    const source = b.participants[id.slot].managed.owner.?;
    const before = try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot));
    const totals = b.fleet.totals;
    const wal = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(wal);
    var cuts: usize = 0;
    while (cuts < 64) : (cuts += 1) {
        candidate.fail_index = candidate.alloc_index + cuts;
        var failed = false;
        storeCandidateAttempt(owner, id) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
        };
        try std.testing.expectEqualDeep(totals, b.fleet.totals);
        try std.testing.expectEqualDeep(before, try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot)));
        try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, wal, after);
        candidate.fail_index = std.math.maxInt(usize);
        if (!failed) break;
        try storeCandidateAttempt(owner, id);
        try std.testing.expectEqualDeep(totals, b.fleet.totals);
        try std.testing.expectEqualDeep(before, try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot)));
        try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
    }
    try std.testing.expect(cuts >= 12 and cuts < 64);
    std.debug.print("S2 actual NEW allocation failure cuts={d}, every cut retried\n", .{cuts});
}

test "physical Store S2 all twenty one retirement slots stay charged until source free" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(12));
    defer owner.deinit();
    const before = fixtureCoordinator(owner).fleet.totals;
    var spec = storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false);
    spec.seed_retirements = true;
    const id = try owner.constructStore(spec);
    var destroyed = false;
    defer if (!destroyed) owner.destroyStore(id) catch unreachable;
    const b = fixtureCoordinator(owner);
    const p = &b.participants[id.slot];
    try std.testing.expectEqual(@as(usize, 21), (try resources.StoreBridge.TestFixture.observe(p.managed.owner.?, owner.storeId(id.slot))).retirement_count);
    var retired: usize = 0;
    var next = b.components[p.first_component].owned_head;
    while (next != resources.vacant) {
        const a = b.allocations[next];
        if (a.state == .retiring) retired += 1;
        next = a.owner_next;
    }
    try std.testing.expectEqual(@as(usize, 28), retired); // Seven mutations own two roots.
    const old = b.fleet.totals;
    try owner.acquireStore(id);
    const builder = try owner.beginPlan(1);
    try owner.addStorePlan(builder, id, storeTestAllowances());
    const plan = try builder.finish();
    var retirement: ?usize = null;
    for (b.ownership[0..b.ownership_count], 0..) |entry, i| if (entry.declaration.disposition == .keep_retiring) {
        retirement = i;
        break;
    };
    const ri = retirement.?;
    try std.testing.expectEqual(resources.AllocationState.retiring, b.allocations[b.ownership[ri].record].state);
    try std.testing.expect(b.ownership[ri].declaration.disposition == .keep_retiring);
    b.ownership[ri].declaration.disposition = .keep;
    if (owner.beginTransaction(plan)) |unexpected| {
        b.ownership[ri].declaration.disposition = .keep_retiring;
        const unexpected_loan = try unexpected.participantLoan(id);
        try owner.releaseAbortedParticipant(unexpected_loan);
        try unexpected.abort();
        try owner.releaseStore(id);
        return error.TestExpectedInvalidRetirementRefusal;
    } else |err| try std.testing.expectEqual(error.InvalidPlan, err);
    try std.testing.expectEqualDeep(old, b.fleet.totals);
    for (b.ownership[0..b.ownership_count]) |entry| try std.testing.expectEqual(@as(u64, 0), b.allocations[entry.record].encumbered_transaction);
    b.ownership[ri].declaration.disposition = .keep_retiring;
    const tx = try owner.beginTransaction(plan);
    const loan = try tx.participantLoan(id);
    try owner.releaseAbortedParticipant(loan);
    try tx.abort();
    try std.testing.expectEqualDeep(old, b.fleet.totals);
    try owner.releaseStore(id);
    try owner.destroyStore(id);
    destroyed = true;
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
}

test "physical Store S2 source witnesses reject guessed and cross owner construction before backend" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(13));
    defer owner.deinit();
    const other = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(14));
    defer other.deinit();
    const b = fixtureCoordinator(owner);
    const args = storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false).args;
    // White-box setup represents the actual private pending slot. No public
    // API can set this phase, expose the anchor, or enroll a caller-owned Store.
    const m = &b.participants[0].managed;
    m.* = .{ .phase = .reserved, .construction_serial = 1, .expected_creation = store.CreationIdentity.from(args) };
    defer m.* = .{};
    var foreign_anchor: u8 = 0;
    var c: resources.StoreConstruction = .{ .owner = owner, .identity = owner, .instance = b.instance, .slot = 0, .serial = 1, .witness = @ptrCast(&foreign_anchor) };
    try std.testing.expectError(error.StaleTicket, resources.StoreBridge.Owner.construct(c, args));
    c.witness = @ptrCast(&fixtureCoordinator(other).participants[0].managed.construction_anchor);
    try std.testing.expectError(error.StaleTicket, resources.StoreBridge.Owner.construct(c, args));
    c.witness = @ptrCast(&m.construction_anchor);
    c.serial = 2;
    try std.testing.expectError(error.StaleTicket, resources.StoreBridge.Owner.construct(c, args));
    c.serial = 1;
    c.instance = testInstance(99);
    try std.testing.expectError(error.StaleTicket, resources.StoreBridge.Owner.construct(c, args));
    c.instance = b.instance;
    try resources.beginStoreConstruction(c, store.CreationIdentity.from(args));
    try std.testing.expectError(error.StaleTicket, resources.StoreBridge.Owner.construct(c, args));
    try std.testing.expectEqual(@as(usize, 0), backend.allocations);
    try std.testing.expect(!backend.has_induced_failure);
}

test "physical Store S2 import refusal unwinds real source and burns construction identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var profile = storeTestProfile();
    profile.allocation_slots_per_home = 2; // Metadata fits; the actual payload census does not.
    const owner = try resources.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(15));
    defer owner.deinit();
    const before = fixtureCoordinator(owner).fleet.totals;
    try std.testing.expectError(error.CapacityExceeded, owner.constructStore(storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false)));
    const b = fixtureCoordinator(owner);
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), b.component_count);
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqual(@as(u64, 1), b.participant_serial);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
    try std.testing.expectError(error.CapacityExceeded, owner.constructStore(storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false)));
    try std.testing.expectEqual(@as(u64, 2), b.participant_serial);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
}

test "physical Store S2 owned inputs seven canonical uses and failed binding custody" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(16));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, std.testing.allocator, std.testing.allocator, candidate.allocator(), true));
    defer owner.destroyStore(id) catch unreachable;
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    const b = fixtureCoordinator(owner);
    const m = &b.participants[id.slot].managed;
    const totals = b.fleet.totals;
    {
        const tx = try storeTestFunding(owner, id, storeTestAllowances());
        defer tx.abort() catch unreachable;
        const loan = try tx.participantLoan(id);
        defer owner.releaseAbortedParticipant(loan) catch unreachable;
        const c = try m.owner.?.beginCandidate(m.exclusion.?, loan);
        defer m.owner.?.abortPreAttempt(c) catch unreachable;
        {
            var owned = storeTestMutations;
            var initialized: usize = 0;
            defer for (owned[0..initialized]) |mutation| {
                std.testing.allocator.free(mutation.key);
                if (mutation.value) |v| std.testing.allocator.free(v);
            };
            for (&owned) |*mutation| {
                const key = try std.testing.allocator.dupe(u8, mutation.key);
                errdefer std.testing.allocator.free(key);
                const value = if (mutation.value) |v| try std.testing.allocator.dupe(u8, v) else null;
                mutation.key = key;
                mutation.value = value;
                initialized += 1;
            }
            try m.owner.?.prepareBatch(c, &owned);
        }
        try resources.StoreBridge.TestFixture.requireOwnedCandidate(m.owner.?, c, &storeTestMutations);
        var uses: [7]bool = @splat(false);
        var index: usize = 0;
        while (try m.owner.?.inspectCandidateAllocation(c, index)) |a| : (index += 1) {
            uses[@intFromEnum(a.use)] = true;
            const role = b.roles[a.role.slot];
            try std.testing.expectEqual(m.roles[@intFromEnum(a.use)].?.serial, a.role.serial);
            switch (a.use) {
                .packet, .scratch_key => try std.testing.expectEqual(resources.FreePoint.finish, role.plan.kind.discard),
                else => try std.testing.expectEqual(b.participants[id.slot].first_component, role.plan.kind.retain.slot),
            }
        }
        for (uses) |present| try std.testing.expect(present);
        try owner.validateNewClosure();
    }
    try std.testing.expectEqualDeep(totals, b.fleet.totals);
    var allowance = storeTestAllowances();
    allowance.uses[@intFromEnum(store.CandidateUse.value)].charge = 1;
    {
        const tx = try storeTestFunding(owner, id, allowance);
        defer tx.abort() catch unreachable;
        const loan = try tx.participantLoan(id);
        defer owner.releaseAbortedParticipant(loan) catch unreachable;
        const c = try m.owner.?.beginCandidate(m.exclusion.?, loan);
        defer m.owner.?.abortPreAttempt(c) catch unreachable;
        try std.testing.expectError(error.CapacityExceeded, m.owner.?.prepareBatch(c, &storeTestMutations));
        const view = try m.owner.?.inspectCandidate(c);
        try std.testing.expectEqual(.failed, view.state);
        try std.testing.expect(view.allocation_count > 0);
        try std.testing.expectError(error.ParticipantsHeld, owner.releaseAbortedParticipant(loan));
        try std.testing.expectError(error.AllocationsHeld, tx.abort());
    }
    try std.testing.expectEqualDeep(totals, b.fleet.totals);
    try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
    try storeCandidateAttempt(owner, id);
}

test "physical Store S2 two source loans preserve whole holds and surviving original index" {
    var a_tmp = std.testing.tmpDir(.{});
    defer a_tmp.cleanup();
    var z_tmp = std.testing.tmpDir(.{});
    defer z_tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(17));
    defer owner.deinit();
    const b = fixtureCoordinator(owner);
    const initial = b.fleet.totals;
    const a = try owner.constructStore(storeTestSpec(owner, a_tmp, backend.allocator(), backend.allocator(), backend.allocator(), true));
    var a_alive = true;
    defer if (a_alive) owner.destroyStore(a) catch unreachable;
    const z = try owner.constructStore(storeTestSpec(owner, z_tmp, backend.allocator(), backend.allocator(), backend.allocator(), true));
    var z_alive = true;
    defer if (z_alive) owner.destroyStore(z) catch unreachable;
    const z_roots = b.components[b.participants[z.slot].first_component].owned_count;
    try owner.acquireStore(a);
    try owner.acquireStore(z);
    {
        defer owner.releaseStore(z) catch unreachable;
        defer owner.releaseStore(a) catch unreachable;
        const before = b.fleet.totals;
        const builder = try owner.beginPlan(1);
        var allowances = storeTestAllowances();
        allowances.work = 6000000;
        try owner.addStorePlan(builder, a, allowances);
        try owner.addStorePlan(builder, z, allowances);
        try std.testing.expectError(error.CapacityExceeded, owner.beginTransaction(try builder.finish()));
        try std.testing.expectEqualDeep(before, b.fleet.totals);
        try builder.abort();
        const next = try owner.beginPlan(1);
        try owner.addStorePlan(next, a, storeTestAllowances());
        try owner.addStorePlan(next, z, storeTestAllowances());
        const tx = try owner.beginTransaction(try next.finish());
        const funded = b.fleet.totals;
        const a_loan = try tx.participantLoan(a);
        const z_loan = try tx.participantLoan(z);
        const am = &b.participants[a.slot].managed;
        const zm = &b.participants[z.slot].managed;
        const ac = try am.owner.?.beginCandidate(am.exclusion.?, a_loan);
        const zc = try zm.owner.?.beginCandidate(zm.exclusion.?, z_loan);
        try std.testing.expectError(error.InvalidLease, zm.owner.?.prepareBatch(ac, &storeTestMutations));
        try am.owner.?.prepareBatch(ac, &storeTestMutations);
        try am.owner.?.abortPreAttempt(ac);
        try owner.releaseAbortedParticipant(a_loan);
        try std.testing.expectError(error.ParticipantsHeld, tx.abort());
        try std.testing.expectEqualDeep(funded, b.fleet.totals);
        try std.testing.expectEqual(@as(usize, 0), (try zm.owner.?.inspectCandidate(zc)).allocation_count);
        try zm.owner.?.abortPreAttempt(zc);
        try owner.releaseAbortedParticipant(z_loan);
        try tx.abort();
        try std.testing.expectEqualDeep(before, b.fleet.totals);
    }
    try owner.destroyStore(a);
    a_alive = false;
    try std.testing.expectEqual(z_roots, b.original_span_count);
    for (b.original_spans[0..b.original_span_count]) |span| {
        try std.testing.expect(span.record != resources.vacant);
        const allocation = b.allocations[span.record];
        try std.testing.expectEqual(span.address, @intFromPtr(allocation.ptr.?));
        try std.testing.expectEqual(z.slot, b.components[allocation.logical_owner].participant_slot);
    }
    try owner.acquireStore(z);
    try storeCandidateAttempt(owner, z);
    try owner.releaseStore(z);
    try owner.destroyStore(z);
    z_alive = false;
    try std.testing.expectEqualDeep(initial, b.fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
}

test "physical Store S2 work sentinel poison stale handles and last serial source cleanup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(18));
    defer owner.deinit();
    const b = fixtureCoordinator(owner);
    const initial = b.fleet.totals;
    var spec = storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false);
    spec.poison_pending = true;
    const id = try owner.constructStore(spec);
    var alive = true;
    defer if (alive) owner.destroyStore(id) catch unreachable;
    const source = b.participants[id.slot].managed.owner.?;
    const sid = owner.storeId(id.slot);
    try owner.acquireStore(id);
    {
        defer owner.releaseStore(id) catch unreachable;
        var allowances = storeTestAllowances();
        allowances.work = std.math.maxInt(u64);
        const builder = try owner.beginPlan(1);
        try std.testing.expectError(error.InvalidPlan, owner.addStorePlan(builder, id, allowances));
        try std.testing.expectEqual(@as(usize, 0), b.entry_count);
        try builder.abort();
        const next = try owner.beginPlan(1);
        try std.testing.expectError(error.ParticipantsHeld, owner.addStorePlan(next, id, storeTestAllowances()));
        try next.abort();
        try std.testing.expectEqual(@as(u64, 0), b.fleet.totals.preparation);
        try std.testing.expectEqual(@as(u64, 0), b.fleet.totals.resident_hold);
    }
    var anchor: u8 = 0;
    const fake: resources.StoreDestruction = .{ .owner = owner, .identity = owner, .instance = b.instance, .slot = id.slot, .serial = 1, .source_lifetime = sid.source_lifetime, .witness = @ptrCast(&anchor) };
    const live = backend.allocated_bytes - backend.freed_bytes;
    try std.testing.expectError(error.StaleTicket, source.destroyRegistered(fake));
    try std.testing.expectEqual(live, backend.allocated_bytes - backend.freed_bytes);
    b.participants[id.slot].managed.destruction_serial = std.math.maxInt(u64) - 1;
    b.serial = std.math.maxInt(u64);
    b.component_serial = std.math.maxInt(u64);
    b.participant_serial = std.math.maxInt(u64);
    try owner.destroyStore(id);
    alive = false;
    try std.testing.expectError(error.StaleTicket, resources.resolveStoreOwner(sid));
    try std.testing.expectError(error.StaleTicket, source.borrowRead(sid)); // Resolved before stale pointer dereference.
    try std.testing.expectEqualDeep(initial, b.fleet.totals);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
    const calls = backend.allocations;
    try std.testing.expectError(error.GenerationExhausted, owner.constructStore(spec));
    try std.testing.expectEqual(calls, backend.allocations);
}

test "physical Store S2 empty payloads need no positive candidate roles" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(19));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, std.testing.allocator, std.testing.allocator, std.testing.allocator, false));
    defer owner.destroyStore(id) catch unreachable;
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    var allowances = storeTestAllowances();
    for (1..5) |index| allowances.homes[index] = .{ .peak = 0, .final = 0, .slots = 0 };
    for (1..6) |index| allowances.uses[index] = .{ .charge = 0, .slots = 0 };
    const tx = try storeTestFunding(owner, id, allowances);
    defer tx.abort() catch unreachable;
    const loan = try tx.participantLoan(id);
    defer owner.releaseAbortedParticipant(loan) catch unreachable;
    const m = &fixtureCoordinator(owner).participants[id.slot].managed;
    const c = try m.owner.?.beginCandidate(m.exclusion.?, loan);
    defer m.owner.?.abortPreAttempt(c) catch unreachable;
    const mutation = [_]store.BatchMutation{.{ .family = .memos, .kind = .put, .key = "", .value = "" }};
    try m.owner.?.prepareBatch(c, &mutation);
    try resources.StoreBridge.TestFixture.requireOwnedCandidate(m.owner.?, c, &mutation);
    const view = try m.owner.?.inspectCandidate(c);
    try std.testing.expectEqual(@as(usize, 2), view.allocation_count);
    for (0..view.allocation_count) |index| {
        const a = (try m.owner.?.inspectCandidateAllocation(c, index)).?;
        try std.testing.expect(a.use == .packet or a.use == .table_backing);
        try std.testing.expect(a.requested_bytes > 0);
    }
}

test "physical Store S2 constructor ordinary ticket and final account refusal unwind before enrollment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(20));
    defer owner.deinit();
    const b = fixtureCoordinator(owner);
    const before = b.fleet.totals;
    var spec = storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false);
    spec.arm_ordinary = true;
    try std.testing.expectError(error.SourceCustodyActive, owner.constructStore(spec));
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
    spec.arm_ordinary = false;
    spec.row = try owner.registerRow(21, 1, .{ .resident = 1, .peak = 1, .wire = 0 });
    try std.testing.expectError(error.CapacityExceeded, owner.constructStore(spec));
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(@as(usize, 0), b.component_count);
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
    spec.row = owner.infrastructureRow();
    const id = try owner.constructStore(spec);
    try std.testing.expectEqual(@as(u64, 3), id.serial);
    const source = b.participants[id.slot].managed.owner.?;
    var read = try source.borrowRead(owner.storeId(id.slot));
    try std.testing.expectError(error.Busy, owner.destroyStore(id));
    try read.finish();
    try owner.destroyStore(id);
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
}

test "physical Store S2 four growing families exhaust all twenty one candidate roots" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var candidate = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, storeTestProfile(), .empty, testInstance(22));
    defer owner.deinit();
    const id = try owner.constructStore(storeTestSpec(owner, tmp, std.testing.allocator, std.testing.allocator, candidate.allocator(), false));
    defer owner.destroyStore(id) catch unreachable;
    try owner.acquireStore(id);
    defer owner.releaseStore(id) catch unreachable;
    const mutations = [_]store.BatchMutation{
        .{ .family = .memos, .kind = .put, .key = "m", .value = "memo" },
        .{ .family = .vhosts, .kind = .put, .key = "v", .value = "vhost" },
        .{ .family = .bans, .kind = .put, .key = "b", .value = "ban" },
        .{ .family = .chanregs, .kind = .put, .key = "c", .value = "channel" },
    };
    const b = fixtureCoordinator(owner);
    const source = b.participants[id.slot].managed.owner.?;
    const before = try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot));
    const totals = b.fleet.totals;
    const wal = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(wal);
    for (0..22) |cut| {
        candidate.fail_index = candidate.alloc_index + cut;
        if (cut < 21) {
            try std.testing.expectError(error.OutOfMemory, storeCandidateAttemptMutations(owner, id, &mutations));
        } else {
            const before_allocations = candidate.allocations;
            try storeCandidateAttemptMutations(owner, id, &mutations);
            try std.testing.expectEqual(@as(usize, 21), candidate.allocations - before_allocations);
        }
        try std.testing.expectEqualDeep(totals, b.fleet.totals);
        try std.testing.expectEqualDeep(before, try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot)));
        try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
        candidate.fail_index = std.math.maxInt(usize);
        try storeCandidateAttemptMutations(owner, id, &mutations);
        try std.testing.expectEqualDeep(totals, b.fleet.totals);
        try std.testing.expectEqualDeep(before, try resources.StoreBridge.TestFixture.observe(source, owner.storeId(id.slot)));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "s2.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, wal, after);
    }
    try std.testing.expectEqual(candidate.allocated_bytes, candidate.freed_bytes);
}

test "physical Store S2 genuine replay imports more than 4096 original roots" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var old = try store.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "s2.wal", .{ .changefeed_capacity = 0 });
        defer old.deinit();
        var key: [32]u8 = undefined;
        for (0..2050) |i| try old.put(.memos, try std.fmt.bufPrint(&key, "old-{d}", .{i}), "original value");
    }
    var profile = storeTestProfile();
    profile.components = 8;
    profile.transaction_components = 8;
    profile.participant_slots = 1;
    profile.transaction_participant_refs = 1;
    profile.allocation_slots_per_home = 8192;
    profile.transaction_allocation_refs = 8192;
    var backend = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const owner = try resources.Coordinator.create(std.testing.allocator, profile, .empty, testInstance(23));
    defer owner.deinit();
    const b = fixtureCoordinator(owner);
    const before = b.fleet.totals;
    var spec = storeTestSpec(owner, tmp, backend.allocator(), backend.allocator(), backend.allocator(), false);
    spec.args.config.changefeed_capacity = 0;
    const id = try owner.constructStore(spec);
    var alive = true;
    defer if (alive) owner.destroyStore(id) catch unreachable;
    try std.testing.expectEqual(@as(usize, 4105), b.original_span_count); // Two boxes, two paths, one table, 4100 payloads.
    try std.testing.expectEqual(@as(usize, 4105), b.components[b.participants[id.slot].first_component].owned_count);
    backend.fail_index = backend.alloc_index;
    try owner.acquireStore(id);
    {
        defer owner.releaseStore(id) catch unreachable;
        const tx = try storeTestFunding(owner, id, storeTestAllowances());
        defer tx.abort() catch unreachable;
        const loan = try tx.participantLoan(id);
        defer owner.releaseAbortedParticipant(loan) catch unreachable;
        try std.testing.expectEqual(@as(usize, 4105), b.ownership_count);
        for (b.ownership[0..b.ownership_count]) |entry| try std.testing.expectEqual(tx.serial, b.allocations[entry.record].encumbered_transaction);
    }
    try owner.destroyStore(id);
    alive = false;
    try std.testing.expectEqual(@as(usize, 0), b.original_span_count);
    try std.testing.expectEqualDeep(before, b.fleet.totals);
    try std.testing.expectEqual(backend.allocated_bytes, backend.freed_bytes);
    try std.testing.expect(!backend.has_induced_failure);
}
