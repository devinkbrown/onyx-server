// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned plaintext custody between a committed lifecycle and its transport.
//! One FIFO belongs to one immutable physical attachment. Its caller holds the
//! graph/connection owner lock, reserves aggregate fleet memory, gates all later
//! application output behind this FIFO, and carries pending entries in mandatory
//! hot state. A prepared ticket never survives a turn or owner migration.
const std = @import("std");
const builtin = @import("builtin");
const client = @import("client.zig");
const presence = @import("../proto/mesh_presence.zig");
/// Historical independent settlement model, available only in test builds.
/// Production ownership must use the whole physical-lifecycle coordinator; no
/// independent component commit or arbitrary wire-release API is exported here.
pub const legacy_test_only = if (builtin.is_test) struct {
    pub const Failure = error{ CapacityExceeded, InvalidPlan, PreparationActive, StaleTicket, AllocationsHeld, GenerationExhausted, OutOfMemory };
    pub const Limits = struct { resident: u64, peak: u64, wire: u64 };
    pub const Totals = struct {
        resident: u64 = 0,
        preparation: u64 = 0,
        resident_reserved: u64 = 0,
        wire: u64 = 0,

        fn permits(self: Totals, limits: Limits, plan: Plan) bool {
            const peak = std.math.add(u64, self.resident, self.preparation) catch return false;
            const settled = std.math.add(u64, self.resident, self.resident_reserved) catch return false;
            return fits(peak, plan.peak, limits.peak) and fits(settled, plan.resident, limits.resident) and fits(self.wire, plan.wire, limits.wire);
        }
        fn reserve(self: *Totals, plan: Plan) void {
            self.preparation += plan.peak;
            self.resident_reserved += plan.resident;
            self.wire += plan.wire;
        }
        fn settle(self: *Totals, plan: Plan, resident: u64, wire: u64) void {
            self.preparation -= plan.peak;
            self.resident_reserved -= plan.resident;
            self.resident += resident;
            self.wire -= plan.wire - wire;
        }
    };
    pub const Budget = struct {
        limits: Limits,
        totals: Totals = .{},
        // Burned at component construction, including backend OOM. Never reused
        // during this heap-stable budget's lifetime, even if addresses recycle.
        component_serial: u64 = 0,
    };
    pub const RowBudget = struct { row_id: u64, limits: Limits, totals: Totals = .{} };
    pub const Plan = struct { peak: u64, resident: u64, wire: u64 };

    const Allocation = struct {
        ptr: ?[*]u8 = null,
        len: usize = 0,
        alignment: std.mem.Alignment = .@"1",
        charge: u64 = 0,
        preparation: u64 = 0,
    };
    const Wire = struct { generation: u64 = 0, remaining: u64 = 0, reserved: bool = false };
    const OwnerIdentity = struct {
        fleet: *Budget,
        component_serial: u64,
        row_id: u64,
        fn matches(self: OwnerIdentity, owner: *const Component) bool {
            return self.fleet == owner.fleet and self.component_serial == owner.identity.component_serial and self.row_id == owner.row.row_id;
        }
    };

    pub const Component = struct {
        backend: std.mem.Allocator,
        fleet: *Budget,
        row: *RowBudget,
        allocations: []Allocation,
        wires: []Wire,
        metadata_charge: u64,
        identity: OwnerIdentity,
        generation: u64 = 0,
        settlement_generation: u64 = 0,
        settlement_wire: u64 = 0,
        active: bool = false,
        sealed: bool = false,
        plan: Plan = .{ .peak = 0, .resident = 0, .wire = 0 },
        allocated: u64 = 0,
        wire_slot: ?usize = null,

        /// Tracking is funded and allocated before the allocator is exposed.
        /// Its callbacks never allocate bookkeeping or use a stack ticket as ctx.
        pub fn create(backend: std.mem.Allocator, fleet: *Budget, row: *RowBudget, allocation_slots: usize, wire_slots: usize) Failure!*Component {
            if (row.row_id == 0 or allocation_slots == 0 or wire_slots == 0) return error.InvalidPlan;
            const allocations_bytes = std.math.mul(usize, allocation_slots, @sizeOf(Allocation)) catch return error.CapacityExceeded;
            const wires_bytes = std.math.mul(usize, wire_slots, @sizeOf(Wire)) catch return error.CapacityExceeded;
            var metadata = try charge(@sizeOf(Component), .fromByteUnits(@alignOf(Component)));
            metadata = std.math.add(u64, metadata, try charge(allocations_bytes, .fromByteUnits(@alignOf(Allocation)))) catch return error.CapacityExceeded;
            metadata = std.math.add(u64, metadata, try charge(wires_bytes, .fromByteUnits(@alignOf(Wire)))) catch return error.CapacityExceeded;
            const plan: Plan = .{ .peak = metadata, .resident = metadata, .wire = 0 };
            if (!fleet.totals.permits(fleet.limits, plan) or !row.totals.permits(row.limits, plan)) return error.CapacityExceeded;
            if (fleet.component_serial == std.math.maxInt(u64)) return error.GenerationExhausted;
            fleet.component_serial += 1;
            const identity: OwnerIdentity = .{ .fleet = fleet, .component_serial = fleet.component_serial, .row_id = row.row_id };
            fleet.totals.reserve(plan);
            row.totals.reserve(plan);
            errdefer {
                fleet.totals.settle(plan, 0, 0);
                row.totals.settle(plan, 0, 0);
            }
            const self = try backend.create(Component);
            errdefer backend.destroy(self);
            const allocations = try backend.alloc(Allocation, allocation_slots);
            errdefer backend.free(allocations);
            const wires = try backend.alloc(Wire, wire_slots);
            @memset(allocations, .{});
            @memset(wires, .{});
            self.* = .{ .backend = backend, .fleet = fleet, .row = row, .identity = identity, .allocations = allocations, .wires = wires, .metadata_charge = metadata };
            fleet.totals.settle(plan, metadata, 0);
            row.totals.settle(plan, metadata, 0);
            return self;
        }

        pub fn destroy(self: *Component) void {
            std.debug.assert(!self.active);
            for (self.allocations) |item| std.debug.assert(item.ptr == null);
            for (self.wires) |item| std.debug.assert(item.remaining == 0 and !item.reserved);
            self.fleet.totals.resident -= self.metadata_charge;
            self.row.totals.resident -= self.metadata_charge;
            const backend = self.backend;
            backend.free(self.allocations);
            backend.free(self.wires);
            backend.destroy(self);
        }

        pub fn beginPreparation(self: *Component, plan: Plan) Failure!PreparationScope {
            if (self.active) return error.PreparationActive;
            if (plan.resident > plan.peak) return error.InvalidPlan;
            if (self.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
            if (!self.fleet.totals.permits(self.fleet.limits, plan) or !self.row.totals.permits(self.row.limits, plan)) return error.CapacityExceeded;
            var wire_slot: ?usize = null;
            if (plan.wire != 0) {
                for (self.wires, 0..) |item, i| {
                    if (item.remaining == 0 and !item.reserved) {
                        wire_slot = i;
                        break;
                    }
                }
                if (wire_slot == null) return error.CapacityExceeded;
            }
            self.generation += 1;
            self.plan = plan;
            self.allocated = 0;
            self.wire_slot = wire_slot;
            self.active = true;
            self.sealed = false;
            if (wire_slot) |i| self.wires[i] = .{ .generation = self.generation, .reserved = true };
            self.fleet.totals.reserve(plan);
            self.row.totals.reserve(plan);
            return .{ .owner = self, .identity = self.identity, .generation = self.generation };
        }

        fn allocator(self: *Component) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = std.mem.Allocator.noRemap, .free = free } };
        }
        fn find(self: *Component, memory: []u8, alignment: std.mem.Alignment) *Allocation {
            for (self.allocations) |*item| {
                if (item.ptr == memory.ptr) {
                    std.debug.assert(item.len == memory.len and item.alignment == alignment);
                    return item;
                }
            }
            @panic("custody allocator received foreign allocation");
        }
        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Component = @ptrCast(@alignCast(ctx));
            if (!self.active or self.sealed) return null;
            const cost = charge(len, alignment) catch return null;
            if (!fits(self.allocated, cost, self.plan.peak)) return null;
            var slot: ?*Allocation = null;
            for (self.allocations) |*item| if (item.ptr == null) {
                slot = item;
                break;
            };
            const item = slot orelse return null;
            const ptr = self.backend.rawAlloc(len, alignment, ret_addr) orelse return null;
            item.* = .{ .ptr = ptr, .len = len, .alignment = alignment, .charge = cost, .preparation = self.generation };
            self.allocated += cost;
            return ptr;
        }
        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *Component = @ptrCast(@alignCast(ctx));
            const item = self.find(memory, alignment);
            // Committed predecessor capacity remains immutable. ArrayList may
            // allocate-copy-free through this allocator, charging both copies.
            if (!self.active or self.sealed or item.preparation != self.generation) return false;
            const next = charge(new_len, alignment) catch return false;
            const without = self.allocated - item.charge;
            if (!fits(without, next, self.plan.peak)) return false;
            if (!self.backend.rawResize(memory, alignment, new_len, ret_addr)) return false;
            item.len = new_len;
            item.charge = next;
            self.allocated = without + next;
            return true;
        }
        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *Component = @ptrCast(@alignCast(ctx));
            std.debug.assert(!self.sealed);
            const item = self.find(memory, alignment);
            self.backend.rawFree(memory, alignment, ret_addr);
            if (item.preparation != 0) {
                std.debug.assert(self.active and item.preparation == self.generation);
                self.allocated -= item.charge;
            } else {
                self.fleet.totals.resident -= item.charge;
                self.row.totals.resident -= item.charge;
            }
            item.* = .{};
        }
    };

    pub const PreparationScope = struct {
        owner: *Component,
        identity: OwnerIdentity,
        generation: u64,
        fn validate(self: PreparationScope) Failure!void {
            if (!self.identity.matches(self.owner) or !self.owner.active or self.owner.generation != self.generation) return error.StaleTicket;
        }
        pub fn allocator(self: PreparationScope) Failure!std.mem.Allocator {
            try self.validate();
            return self.owner.allocator();
        }
        /// Allocations must already be released before an abort can refund P.
        pub fn abort(self: PreparationScope) Failure!void {
            try self.validate();
            if (self.owner.sealed) return error.StaleTicket;
            if (self.owner.allocated != 0) return error.AllocationsHeld;
            const owner = self.owner;
            owner.fleet.totals.settle(owner.plan, 0, 0);
            owner.row.totals.settle(owner.plan, 0, 0);
            if (owner.wire_slot) |i| owner.wires[i].reserved = false;
            owner.wire_slot = null;
            owner.active = false;
        }
        /// Converts actual retained preparation capacity to resident legacy_test_only.
        /// Fatal paths retaining alerts use this same operation; they cannot
        /// refund bytes which remain owned by a transport.
        pub fn commit(self: PreparationScope, wire: u64) Failure!?WireReceipt {
            const prepared = try self.prepareSettlement(wire);
            return prepared.commit();
        }
        /// Final fallible check precedes the Authority WAL cut. Sealing prevents
        /// allocations or frees from changing the validated capacity afterward.
        pub fn prepareSettlement(self: PreparationScope, wire: u64) Failure!PreparedSettlement {
            try self.validate();
            const owner = self.owner;
            if (owner.sealed) return error.StaleTicket;
            if (owner.allocated > owner.plan.resident or wire > owner.plan.wire) return error.InvalidPlan;
            if (owner.settlement_generation == std.math.maxInt(u64)) return error.GenerationExhausted;
            owner.settlement_generation += 1;
            owner.settlement_wire = wire;
            owner.sealed = true;
            return .{ .owner = owner, .identity = self.identity, .generation = self.generation, .settlement_generation = owner.settlement_generation, .wire = wire };
        }
    };
    pub const PreparedSettlement = struct {
        owner: *Component,
        identity: OwnerIdentity,
        generation: u64,
        settlement_generation: u64,
        wire: u64,
        pub fn validateForCut(self: PreparedSettlement) Failure!void {
            if (!self.identity.matches(self.owner) or !self.owner.active or !self.owner.sealed or self.owner.generation != self.generation or self.owner.settlement_generation != self.settlement_generation or self.owner.settlement_wire != self.wire) return error.StaleTicket;
        }
        pub fn abort(self: PreparedSettlement) Failure!void {
            try self.validateForCut();
            self.owner.sealed = false;
        }
        /// Trusted owner publication under the same graph lock as validation.
        /// No allocation, I/O, fallible lookup, or callback follows the WAL cut.
        pub fn commit(self: PreparedSettlement) ?WireReceipt {
            const owner = self.owner;
            self.validateForCut() catch @panic("custody settlement changed after WAL validation");
            for (owner.allocations) |*item| if (item.preparation == self.generation) {
                item.preparation = 0;
            };
            owner.fleet.totals.settle(owner.plan, owner.allocated, self.wire);
            owner.row.totals.settle(owner.plan, owner.allocated, self.wire);
            var receipt: ?WireReceipt = null;
            if (owner.wire_slot) |i| {
                owner.wires[i].reserved = false;
                owner.wires[i].remaining = self.wire;
                if (self.wire != 0) receipt = .{ .owner = owner, .identity = self.identity, .slot = i, .generation = self.generation, .remaining = self.wire };
            }
            owner.active = false;
            owner.sealed = false;
            owner.allocated = 0;
            owner.wire_slot = null;
            return receipt;
        }
    };
    pub const WireReceipt = struct {
        owner: *Component,
        identity: OwnerIdentity,
        slot: usize,
        generation: u64,
        remaining: u64,
        /// Exact transport disposition only. Submission is not retirement.
        /// Ledger comparison prevents a copied receipt from refunding twice.
        pub fn release(self: *WireReceipt, bytes: u64) Failure!void {
            if (!self.identity.matches(self.owner) or self.slot >= self.owner.wires.len or self.remaining == 0 or bytes == 0 or bytes > self.remaining) return error.StaleTicket;
            const ledger = &self.owner.wires[self.slot];
            if (ledger.reserved or ledger.generation != self.generation or ledger.remaining != self.remaining) return error.StaleTicket;
            ledger.remaining -= bytes;
            self.remaining -= bytes;
            self.owner.fleet.totals.wire -= bytes;
            self.owner.row.totals.wire -= bytes;
        }
    };
    fn fits(current: u64, extra: u64, limit: u64) bool {
        return current <= limit and extra <= limit - current;
    }
    fn charge(len: usize, alignment: std.mem.Alignment) Failure!u64 {
        return std.math.add(u64, len, alignment.toByteUnits() - 1) catch error.CapacityExceeded;
    }
} else struct {};
pub const Error = error{ OutOfMemory, InvalidRecipient, InvalidPayload, CapacityExceeded, MutationActive, PositionExhausted };

/// Deterministic record partitioning for owned plaintext. Queue availability in
/// a later drain turn cannot change these boundaries or create uncharged tags.
/// The FIFO owns chunks; this allocation-free view borrows them for one turn.
pub const transport_geometry = struct {
    pub const Failure = error{ InvalidPolicy, InvalidPayload, InvalidCursor, ImpossibleProfile, CostOverflow, SequenceExhausted };
    pub const Family = enum { tls13, tls12_gcm, tls12_chacha };
    pub const Policy = struct {
        family: Family,
        peer_raw_limit: u16,
        quantum: u32,
        physical_capacity: u64,
    };
    pub const Geometry = struct {
        content_limit: u32,
        overhead: u32,
        physical_capacity: u64,

        pub fn derive(policy: Policy) Failure!Geometry {
            if (policy.peer_raw_limit < 64 or policy.quantum == 0) return error.InvalidPolicy;
            const overhead: u32 = switch (policy.family) {
                .tls13 => 22, // header + inner type + AEAD tag, zero padding
                .tls12_gcm => 29, // header + explicit nonce + AEAD tag
                .tls12_chacha => 21, // header + AEAD tag
            };
            if (policy.physical_capacity <= overhead) return error.ImpossibleProfile;
            const peer_content: u32 = if (policy.family == .tls13) @min(@as(u32, policy.peer_raw_limit) - 1, 16384) else @min(@as(u32, policy.peer_raw_limit), 16384);
            const limit: u32 = @intCast(@min(peer_content, policy.quantum, policy.physical_capacity - overhead));
            return .{ .content_limit = limit, .overhead = overhead, .physical_capacity = policy.physical_capacity };
        }

        pub fn plan(self: Geometry, chunks: []const []const u8, first_sequence: u64) Failure!Plan {
            try self.validate();
            if (chunks.len == 0 or chunks.len > std.math.maxInt(u32)) return error.InvalidPayload;
            var accumulated: Accumulator = .{};
            for (chunks) |chunk| try accumulated.add(self, chunk.len);
            return accumulated.finish(self, first_sequence);
        }

        /// Price canonical declared lengths before allocating/restoring payload.
        /// The owner must later join these lengths to the actual immutable bytes.
        pub fn planLengths(self: Geometry, lengths: []const u64, first_sequence: u64) Failure!Plan {
            try self.validate();
            if (lengths.len == 0 or lengths.len > std.math.maxInt(u32)) return error.InvalidPayload;
            var accumulated: Accumulator = .{};
            for (lengths) |length| try accumulated.add(self, length);
            return accumulated.finish(self, first_sequence);
        }

        fn validate(self: Geometry) Failure!void {
            if (self.content_limit == 0 or self.content_limit > 16384 or (self.overhead != 21 and self.overhead != 22 and self.overhead != 29)) return error.InvalidPolicy;
            if (self.physical_capacity < @as(u64, self.content_limit) + self.overhead) return error.ImpossibleProfile;
        }

        pub fn next(self: Geometry, chunks: []const []const u8, cursor: Cursor) Failure!?Piece {
            try self.validate();
            if (chunks.len == 0 or chunks.len > std.math.maxInt(u32)) return error.InvalidPayload;
            if (cursor.chunk > chunks.len) return error.InvalidCursor;
            if (cursor.chunk == chunks.len) {
                if (cursor.offset != 0) return error.InvalidCursor;
                return null;
            }
            const chunk = chunks[cursor.chunk];
            if (chunk.len == 0) return error.InvalidPayload;
            // TlsConn first preserves producer chunks and splits each at 16384,
            // then the engine applies the peer limit. Restart cuts at EACH such
            // boundary; flattening them can undercharge one or more AEAD tags.
            const outer_offset = cursor.offset % 16384;
            if (cursor.offset >= chunk.len or outer_offset % self.content_limit != 0) return error.InvalidCursor;
            const offset: usize = @intCast(cursor.offset);
            const length = @min(chunk.len - offset, self.content_limit, 16384 - outer_offset);
            const next_cursor: Cursor = if (offset + length == chunk.len) .{ .chunk = cursor.chunk + 1, .offset = 0 } else .{ .chunk = cursor.chunk, .offset = cursor.offset + length };
            return .{ .bytes = chunk[offset..][0..length], .wire = length + self.overhead, .next_cursor = next_cursor };
        }
    };
    const Accumulator = struct {
        plaintext: u64 = 0,
        records: u64 = 0,
        fn add(self: *Accumulator, geometry: Geometry, length: u64) Failure!void {
            if (length == 0) return error.InvalidPayload;
            const outer_records: u64 = 1 + (16384 - 1) / geometry.content_limit;
            const full = std.math.mul(u64, length / 16384, outer_records) catch return error.CostOverflow;
            const tail = length % 16384;
            const count = std.math.add(u64, full, if (tail == 0) 0 else 1 + (tail - 1) / geometry.content_limit) catch return error.CostOverflow;
            self.plaintext = std.math.add(u64, self.plaintext, length) catch return error.CostOverflow;
            self.records = std.math.add(u64, self.records, count) catch return error.CostOverflow;
        }
        fn finish(self: Accumulator, geometry: Geometry, first_sequence: u64) Failure!Plan {
            const next_sequence = std.math.add(u64, first_sequence, self.records) catch return error.SequenceExhausted;
            const framing = std.math.mul(u64, self.records, geometry.overhead) catch return error.CostOverflow;
            const wire = std.math.add(u64, self.plaintext, framing) catch return error.CostOverflow;
            return .{ .plaintext = self.plaintext, .records = self.records, .wire = wire, .next_sequence = next_sequence };
        }
    };
    pub const Plan = struct { plaintext: u64, records: u64, wire: u64, next_sequence: u64 };
    pub const Cursor = struct { chunk: u32 = 0, offset: u64 = 0 };
    pub const Piece = struct { bytes: []const u8, wire: u64, next_cursor: Cursor };
    pub const Control = enum {
        key_update,
        alert,
        fn bodyBytes(self: Control) u64 {
            return switch (self) {
                .key_update => 5,
                .alert => 2,
            };
        }
    };
    /// One protected record per positively accepted body byte is the conservative
    /// kernel bound. These are wire bytes, distinct from physical body credits.
    pub fn kernelControlRemaining13(control: Control, accepted_body: u64) Failure!u64 {
        if (accepted_body > control.bodyBytes()) return error.InvalidCursor;
        return (control.bodyBytes() - accepted_body) * 23;
    }
    pub fn softwareControlWire(family: Family, control: Control, physical_capacity: u64) Failure!u64 {
        if (family != .tls13 and control == .key_update) return error.InvalidPolicy;
        const overhead: u64 = switch (family) {
            .tls13 => 22,
            .tls12_gcm => 29,
            .tls12_chacha => 21,
        };
        const wire = control.bodyBytes() + overhead;
        if (wire > physical_capacity) return error.ImpossibleProfile;
        return wire;
    }
};

pub const Recipient = struct {
    origin: [32]u8,
    subject: presence.GuestId,
    physical: client.ClientId,

    pub fn eql(a: Recipient, b: Recipient) bool {
        return std.mem.eql(u8, &a.origin, &b.origin) and std.mem.eql(u8, &a.subject, &b.subject) and a.physical.eql(b.physical);
    }
};

/// Existing queued SendQ ciphertext is separate custody and never enters here.
pub const PayloadKind = enum { irc_stream, websocket_control };
pub const Input = struct { transaction: [16]u8, kind: PayloadKind, bytes: []const u8 };
pub const Entry = struct {
    recipient: Recipient,
    position: u64,
    transaction: [16]u8,
    kind: PayloadKind,
    bytes: []const u8,
    next: ?*Entry = null,
};

pub const Outbox = struct {
    allocator: std.mem.Allocator,
    recipient: Recipient,
    max_entries: usize,
    max_bytes: usize,
    head: ?*Entry = null,
    last: ?*Entry = null,
    count: usize = 0,
    byte_count: usize = 0,
    next_position: u64 = 1,
    preparing: bool = false,

    pub fn init(allocator: std.mem.Allocator, recipient: Recipient, max_entries: usize, max_bytes: usize) Error!Outbox {
        _ = presence.subject(recipient.subject) catch return error.InvalidRecipient;
        if (recipient.physical.isNone() or std.mem.allEqual(u8, &recipient.origin, 0)) return error.InvalidRecipient;
        return .{ .allocator = allocator, .recipient = recipient, .max_entries = max_entries, .max_bytes = max_bytes };
    }

    pub fn deinit(self: *Outbox) void {
        std.debug.assert(!self.preparing);
        freeChain(self.allocator, self.head);
        self.* = undefined;
    }

    pub fn peek(self: *const Outbox, recipient: Recipient) Error!?*const Entry {
        if (!self.recipient.eql(recipient)) return error.InvalidRecipient;
        if (self.preparing) return error.MutationActive;
        return self.head;
    }

    /// A failed adapter drain does not call this method. Exact entry position
    /// is acknowledged only after raw SendQ and all adapter state are committed.
    pub fn retireAfterCustody(self: *Outbox, recipient: Recipient, position: u64) void {
        std.debug.assert(!self.preparing and self.recipient.eql(recipient));
        const first = self.head orelse unreachable;
        std.debug.assert(first.position == position);
        self.head = first.next;
        if (self.head == null) self.last = null;
        self.count -= 1;
        self.byte_count -= first.bytes.len;
        self.allocator.free(first.bytes);
        self.allocator.destroy(first);
    }

    pub fn prepare(self: *Outbox, recipient: Recipient, inputs: []const Input) Error!Prepared {
        if (!self.recipient.eql(recipient)) return error.InvalidRecipient;
        if (self.preparing) return error.MutationActive;
        if (inputs.len == 0) return error.InvalidPayload;
        if (self.count > self.max_entries or inputs.len > self.max_entries - self.count) return error.CapacityExceeded;
        const final_position = std.math.add(u64, self.next_position, inputs.len) catch return error.PositionExhausted;
        var bytes: usize = 0;
        for (inputs) |input| {
            if (input.bytes.len == 0) return error.InvalidPayload;
            bytes = std.math.add(usize, bytes, input.bytes.len) catch return error.CapacityExceeded;
        }
        if (self.byte_count > self.max_bytes or bytes > self.max_bytes - self.byte_count) return error.CapacityExceeded;
        var head: ?*Entry = null;
        var last: ?*Entry = null;
        errdefer freeChain(self.allocator, head);
        for (inputs, 0..) |input, index| {
            const node = try self.allocator.create(Entry);
            const owned = self.allocator.dupe(u8, input.bytes) catch |err| {
                self.allocator.destroy(node);
                return err;
            };
            node.* = .{ .recipient = recipient, .position = self.next_position + index, .transaction = input.transaction, .kind = input.kind, .bytes = owned };
            if (last) |previous| previous.next = node else head = node;
            last = node;
        }
        self.preparing = true;
        return .{ .owner = self, .allocator = self.allocator, .head = head, .last = last, .count = inputs.len, .bytes = bytes, .next_position = final_position };
    }
};

pub const Prepared = struct {
    owner: *Outbox,
    allocator: std.mem.Allocator,
    head: ?*Entry,
    last: ?*Entry,
    count: usize,
    bytes: usize,
    next_position: u64,
    done: bool = false,

    pub fn commit(self: *Prepared) void {
        std.debug.assert(!self.done and self.owner.preparing);
        if (self.owner.last) |last| last.next = self.head else self.owner.head = self.head;
        self.owner.last = self.last;
        self.owner.count += self.count;
        self.owner.byte_count += self.bytes;
        self.owner.next_position = self.next_position;
        self.owner.preparing = false;
        self.head = null;
        self.last = null;
        self.done = true;
    }

    pub fn abort(self: *Prepared) void {
        if (self.done) return;
        std.debug.assert(self.owner.preparing);
        freeChain(self.allocator, self.head);
        self.owner.preparing = false;
        self.head = null;
        self.last = null;
        self.done = true;
    }
};

fn freeChain(allocator: std.mem.Allocator, first: ?*Entry) void {
    var node = first;
    while (node) |entry| {
        node = entry.next;
        allocator.free(entry.bytes);
        allocator.destroy(entry);
    }
}

fn testRecipient() Recipient {
    return .{ .origin = @splat(7), .subject = presence.guestId(.{ .epoch = 3, .counter = 9 }) catch unreachable, .physical = .{ .shard = 2, .slot = 1, .gen = 3 } };
}
const test_inputs = [_]Input{
    .{ .transaction = @splat(1), .kind = .irc_stream, .bytes = "001 welcome\r\n" },
    .{ .transaction = @splat(1), .kind = .irc_stream, .bytes = "NOTICE later\r\n" },
};

test "prepared application output: outbox owns FIFO and survives failed drain with exact physical custody" {
    const r = testRecipient();
    var out = try Outbox.init(std.testing.allocator, r, 4, 128);
    defer out.deinit();
    var prepared = try out.prepare(r, &test_inputs);
    defer prepared.abort();
    try std.testing.expectEqual(@as(usize, 0), out.count);
    try std.testing.expectError(error.MutationActive, out.peek(r));
    const allocator = out.allocator;
    out.allocator = std.testing.failing_allocator;
    prepared.commit();
    out.allocator = allocator;
    const first = (try out.peek(r)).?;
    try std.testing.expectEqualStrings("001 welcome\r\n", first.bytes);
    // A queue rejection leaves the exact payload and its position held.
    const position = first.position;
    try std.testing.expectEqual(position, (try out.peek(r)).?.position);
    var replacement = r;
    replacement.physical.gen += 1;
    try std.testing.expectError(error.InvalidRecipient, out.peek(replacement));
    out.retireAfterCustody(r, position);
    try std.testing.expectEqualStrings("NOTICE later\r\n", (try out.peek(r)).?.bytes);
    try std.testing.expectEqual(position + 1, (try out.peek(r)).?.position);
    out.retireAfterCustody(r, position + 1);
    try std.testing.expectEqual(@as(?*const Entry, null), try out.peek(r));
    try std.testing.expectEqual(@as(usize, 0), out.byte_count);
}

test "prepared application output: outbox batch exhaustive OOM and abort preserve committed predecessor" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const r = testRecipient();
            var out = try Outbox.init(std.testing.allocator, r, 4, 128);
            defer out.deinit();
            var old = try out.prepare(r, test_inputs[0..1]);
            old.commit();
            const predecessor = out.head;
            const position = out.next_position;
            out.allocator = allocator;
            var prepared = out.prepare(r, &test_inputs) catch |err| {
                out.allocator = std.testing.allocator;
                try std.testing.expectEqual(predecessor, out.head);
                try std.testing.expectEqual(position, out.next_position);
                try std.testing.expectEqual(@as(usize, 1), out.count);
                try std.testing.expect(!out.preparing);
                var retry = try out.prepare(r, &test_inputs);
                retry.commit();
                try std.testing.expectEqual(@as(usize, 3), out.count);
                return err;
            };
            prepared.abort();
            prepared.abort();
            out.allocator = std.testing.allocator;
            try std.testing.expectEqual(predecessor, out.head);
            try std.testing.expectEqual(position, out.next_position);
            try std.testing.expectEqual(@as(usize, 1), out.count);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "prepared application output: outbox rejects total limits and exhausted positions before publication" {
    const r = testRecipient();
    var out = try Outbox.init(std.testing.allocator, r, 1, 128);
    defer out.deinit();
    try std.testing.expectError(error.CapacityExceeded, out.prepare(r, &test_inputs));
    out.max_entries = 4;
    out.max_bytes = 1;
    try std.testing.expectError(error.CapacityExceeded, out.prepare(r, &test_inputs));
    out.max_bytes = 128;
    out.next_position = std.math.maxInt(u64);
    try std.testing.expectError(error.PositionExhausted, out.prepare(r, test_inputs[0..1]));
    try std.testing.expect(!out.preparing and out.head == null);
}

test "prepared application output: outbox payload ownership is independent of formatting scratch" {
    const r = testRecipient();
    var out = try Outbox.init(std.testing.allocator, r, 2, 128);
    defer out.deinit();
    var scratch = [_]u8{ 'a', 'b', 'c' };
    var prepared = try out.prepare(r, &.{.{ .transaction = @splat(2), .kind = .irc_stream, .bytes = &scratch }});
    defer prepared.abort();
    @memset(&scratch, 'x');
    prepared.commit();
    try std.testing.expectEqualStrings("abc", (try out.peek(r)).?.bytes);
    try std.testing.expectError(error.InvalidPayload, out.prepare(r, &.{.{ .transaction = @splat(2), .kind = .irc_stream, .bytes = "" }}));
    try std.testing.expectEqual(@as(usize, 1), out.count);
}

test "physical custody budget: retained capacity and wire receipts survive commit and reject copied refunds" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 1000 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const component = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 4, 2);
    defer component.destroy();
    const baseline = fleet.totals.resident;
    const scope = try component.beginPreparation(.{ .peak = 512, .resident = 256, .wire = 115 });
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 128);
    try std.testing.expectEqual(baseline, fleet.totals.resident);
    try std.testing.expectEqual(@as(u64, 512), fleet.totals.preparation);
    try std.testing.expectError(error.AllocationsHeld, scope.abort());
    var receipt = (try scope.commit(115)).?;
    var copy = receipt;
    try std.testing.expectEqual(baseline + 128, fleet.totals.resident);
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.preparation);
    try std.testing.expectError(error.StaleTicket, scope.commit(115));
    try receipt.release(23);
    try std.testing.expectError(error.StaleTicket, copy.release(115));
    try std.testing.expectEqual(@as(u64, 92), fleet.totals.wire);
    try receipt.release(92);
    try std.testing.expectError(error.StaleTicket, receipt.release(1));
    allocator.free(bytes);
    try std.testing.expectEqual(baseline, fleet.totals.resident);
    try std.testing.expectEqual(fleet.totals, row.totals);
}

test "physical custody budget: whole fleet and shared row reject pressure without changing predecessor" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const first = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 2, 2);
    defer first.destroy();
    const second = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 2, 2);
    defer second.destroy();
    const scope = try first.beginPreparation(.{ .peak = 128, .resident = 128, .wire = 75 });
    const before = fleet.totals;
    try std.testing.expectError(error.CapacityExceeded, second.beginPreparation(.{ .peak = 128, .resident = 128, .wire = 26 }));
    try std.testing.expectEqual(before, fleet.totals);
    try std.testing.expectEqual(before, row.totals);
    try scope.abort();
    row.limits.peak = row.totals.resident + 7;
    try std.testing.expectError(error.CapacityExceeded, first.beginPreparation(.{ .peak = 8, .resident = 8, .wire = 0 }));
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.preparation);
    first.generation = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, first.beginPreparation(.{ .peak = 0, .resident = 0, .wire = 0 }));
}

test "physical custody budget: backend failure and exhausted tracking refund no retained bytes" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    try std.testing.expectError(error.OutOfMemory, legacy_test_only.Component.create(std.testing.failing_allocator, &fleet, &row, 2, 2));
    try std.testing.expectEqual(legacy_test_only.Totals{}, fleet.totals);
    const component = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer component.destroy();
    const baseline = fleet.totals.resident;
    const scope = try component.beginPreparation(.{ .peak = 64, .resident = 64, .wire = 1 });
    const allocator = try scope.allocator();
    const backend = component.backend;
    component.backend = std.testing.failing_allocator;
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 32));
    try std.testing.expectEqual(@as(u64, 0), component.allocated);
    component.backend = backend;
    const first = try allocator.alloc(u8, 32);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 65));
    allocator.free(first);
    try scope.abort();
    try std.testing.expectEqual(baseline, fleet.totals.resident);
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.wire);
}

test "physical custody budget: component construction exhaustive OOM leaves exact empty budget" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
            var fleet: legacy_test_only.Budget = .{ .limits = limits };
            var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
            const component = legacy_test_only.Component.create(allocator, &fleet, &row, 4, 4) catch |err| {
                try std.testing.expectEqual(legacy_test_only.Totals{}, fleet.totals);
                try std.testing.expectEqual(legacy_test_only.Totals{}, row.totals);
                return err;
            };
            component.destroy();
            try std.testing.expectEqual(legacy_test_only.Totals{}, fleet.totals);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "physical custody budget: sealed publication rejects tampering and stale reseals before WAL" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const component = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 2, 2);
    defer component.destroy();
    const scope = try component.beginPreparation(.{ .peak = 64, .resident = 64, .wire = 10 });
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 32);
    const first = try scope.prepareSettlement(5);
    try first.validateForCut();
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    var tampered = first;
    tampered.wire = 6;
    try std.testing.expectError(error.StaleTicket, tampered.validateForCut());
    try first.abort();
    const second = try scope.prepareSettlement(10);
    try std.testing.expectError(error.StaleTicket, first.validateForCut());
    try std.testing.expectError(error.StaleTicket, first.abort());
    try second.validateForCut();
    // Trusted publication has no allocator use even if the backend fails.
    const backend = component.backend;
    component.backend = std.testing.failing_allocator;
    var receipt = second.commit().?;
    component.backend = backend;
    try receipt.release(10);
    allocator.free(bytes);
}

test "physical custody budget: aligned resize and old plus new capacity remain charged" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    var backing: [2048]u8 align(64) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    const component = try legacy_test_only.Component.create(fixed.allocator(), &fleet, &row, 2, 1);
    defer component.destroy();
    const baseline = fleet.totals.resident;
    const scope = try component.beginPreparation(.{ .peak = 191, .resident = 191, .wire = 0 });
    const allocator = try scope.allocator();
    var bytes = try allocator.alignedAlloc(u8, .@"64", 64);
    try std.testing.expectEqual(@as(u64, 127), component.allocated);
    try std.testing.expect(allocator.resize(bytes, 128));
    bytes = bytes.ptr[0..128];
    try std.testing.expectEqual(@as(u64, 191), component.allocated);
    try std.testing.expect(!allocator.resize(bytes, 129));
    _ = try scope.commit(0);
    try std.testing.expectEqual(baseline + 191, fleet.totals.resident);
    fleet.limits.peak = fleet.totals.resident + 126;
    try std.testing.expectError(error.CapacityExceeded, component.beginPreparation(.{ .peak = 127, .resident = 127, .wire = 0 }));
    fleet.limits.peak += 1;
    const replacement = try component.beginPreparation(.{ .peak = 127, .resident = 127, .wire = 0 });
    try std.testing.expect(!allocator.resize(bytes, 64));
    const next = try allocator.alignedAlloc(u8, .@"64", 64);
    try std.testing.expectEqual(baseline + 191, fleet.totals.resident);
    try std.testing.expectEqual(@as(u64, 127), fleet.totals.preparation);
    allocator.free(next);
    try replacement.abort();
    allocator.free(bytes);
    try std.testing.expectEqual(baseline, fleet.totals.resident);
}

test "physical custody budget: cross-component retargeted settlements refuse before either cut" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const first = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer first.destroy();
    const second = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer second.destroy();
    const a = try first.beginPreparation(.{ .peak = 0, .resident = 0, .wire = 5 });
    defer a.abort() catch {};
    const b = try second.beginPreparation(.{ .peak = 0, .resident = 0, .wire = 5 });
    defer b.abort() catch {};
    const ap = try a.prepareSettlement(5);
    defer ap.abort() catch {};
    const bp = try b.prepareSettlement(5);
    defer bp.abort() catch {};
    var retargeted = ap;
    retargeted.owner = second;
    try std.testing.expectError(error.StaleTicket, retargeted.validateForCut());
    try ap.validateForCut();
    try bp.validateForCut();
}

test "physical custody budget: cross-component retargeted wire receipt cannot retire another obligation" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const first = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer first.destroy();
    const second = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer second.destroy();
    const a = try first.beginPreparation(.{ .peak = 0, .resident = 0, .wire = 5 });
    var ar = (try a.commit(5)).?;
    defer ar.release(ar.remaining) catch {};
    const b = try second.beginPreparation(.{ .peak = 0, .resident = 0, .wire = 5 });
    var br = (try b.commit(5)).?;
    defer {
        // The OLD causal may have incorrectly retired b. Dispose only the
        // ledger's actual remainder so the failing assertion does not leak.
        br.remaining = second.wires[br.slot].remaining;
        if (br.remaining != 0) br.release(br.remaining) catch unreachable;
    }
    var retargeted = ar;
    retargeted.owner = second;
    try std.testing.expectError(error.StaleTicket, retargeted.release(5));
    try std.testing.expectEqual(@as(u64, 10), fleet.totals.wire);
}

test "physical custody budget: final settlement serial never prevents cancellation refund" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const component = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer component.destroy();
    component.settlement_generation = std.math.maxInt(u64) - 1;
    const scope = try component.beginPreparation(.{ .peak = 32, .resident = 16, .wire = 5 });
    defer if (component.active) {
        // Only failure cleanup for the OLD causal; never production behavior.
        component.settlement_generation = 0;
        scope.abort() catch unreachable;
    };
    const prepared = try scope.prepareSettlement(5);
    try prepared.abort();
    try scope.abort();
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.preparation);
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.resident_reserved);
    try std.testing.expectEqual(@as(u64, 0), fleet.totals.wire);
}

test "physical custody budget: scope identity includes fleet and construction serial is never reused" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var a: legacy_test_only.Budget = .{ .limits = limits };
    var b: legacy_test_only.Budget = .{ .limits = limits };
    var ar: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    var br: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const first = try legacy_test_only.Component.create(std.testing.allocator, &a, &ar, 1, 1);
    defer first.destroy();
    const second = try legacy_test_only.Component.create(std.testing.allocator, &b, &br, 1, 1);
    defer second.destroy();
    const x = try first.beginPreparation(.{ .peak = 1, .resident = 1, .wire = 0 });
    defer x.abort() catch unreachable;
    const y = try second.beginPreparation(.{ .peak = 1, .resident = 1, .wire = 0 });
    defer y.abort() catch unreachable;
    var retargeted = x;
    retargeted.owner = second;
    try std.testing.expectError(error.StaleTicket, retargeted.allocator());
    try std.testing.expectError(error.StaleTicket, retargeted.abort());
    try std.testing.expectError(error.OutOfMemory, legacy_test_only.Component.create(std.testing.failing_allocator, &a, &ar, 1, 1));
    try std.testing.expectEqual(@as(u64, 2), a.component_serial);
    const third = try legacy_test_only.Component.create(std.testing.allocator, &a, &ar, 1, 1);
    defer third.destroy();
    try std.testing.expectEqual(@as(u64, 3), third.identity.component_serial);
    const before = a.totals;
    a.component_serial = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, legacy_test_only.Component.create(std.testing.allocator, &a, &ar, 1, 1));
    try std.testing.expectEqual(before, a.totals);
}

test "physical custody budget: exhausted publication serial still permits exact preparation abort" {
    const limits: legacy_test_only.Limits = .{ .resident = 65536, .peak = 65536, .wire = 100 };
    var fleet: legacy_test_only.Budget = .{ .limits = limits };
    var row: legacy_test_only.RowBudget = .{ .row_id = 1, .limits = limits };
    const component = try legacy_test_only.Component.create(std.testing.allocator, &fleet, &row, 1, 1);
    defer component.destroy();
    component.settlement_generation = std.math.maxInt(u64);
    const before = fleet.totals;
    const scope = try component.beginPreparation(.{ .peak = 16, .resident = 16, .wire = 5 });
    const allocator = try scope.allocator();
    const bytes = try allocator.alloc(u8, 8);
    try std.testing.expectError(error.GenerationExhausted, scope.prepareSettlement(5));
    try std.testing.expectError(error.AllocationsHeld, scope.abort());
    allocator.free(bytes);
    try scope.abort();
    try std.testing.expectEqual(before, fleet.totals);
}

test "physical transport geometry: immutable record cuts preserve chunks and checked sequence bounds" {
    const g = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = 128, .physical_capacity = 85 });
    try std.testing.expectEqual(@as(u32, 63), g.content_limit);
    var data: [128]u8 = undefined;
    @memset(&data, 7);
    const chunks = [_][]const u8{ data[0..64], data[64..] };
    const plan = try g.plan(&chunks, 9);
    try std.testing.expectEqual(@as(u64, 4), plan.records);
    try std.testing.expectEqual(@as(u64, 216), plan.wire);
    try std.testing.expectEqual(@as(u64, 13), plan.next_sequence);
    const first = (try g.next(&chunks, .{})).?;
    try std.testing.expectEqual(@as(usize, 63), first.bytes.len);
    try std.testing.expectEqual(@as(u64, 85), first.wire);
    const tail = (try g.next(&chunks, first.next_cursor)).?;
    try std.testing.expectEqual(@as(usize, 1), tail.bytes.len);
    try std.testing.expectEqual(@as(u32, 1), tail.next_cursor.chunk);
    try std.testing.expectError(error.InvalidCursor, g.next(&chunks, .{ .offset = 1 }));
    try std.testing.expectError(error.InvalidCursor, g.next(&chunks, .{ .chunk = 2, .offset = 1 }));
    try std.testing.expectEqual(@as(?transport_geometry.Piece, null), try g.next(&chunks, .{ .chunk = 2 }));
    try std.testing.expectError(error.SequenceExhausted, g.plan(&chunks, std.math.maxInt(u64) - 3));
    try std.testing.expectError(error.InvalidPayload, g.plan(&.{""}, 0));
    try std.testing.expectError(error.ImpossibleProfile, transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = 1, .physical_capacity = 22 }));
    try std.testing.expectError(error.InvalidPolicy, transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 63, .quantum = 1, .physical_capacity = 100 }));
    const future = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 65535, .quantum = 20000, .physical_capacity = 20000 });
    try std.testing.expectEqual(@as(u32, 16384), future.content_limit);
}

test "physical transport geometry: control wire liability never aliases plaintext credit" {
    try std.testing.expectEqual(@as(u64, 115), try transport_geometry.kernelControlRemaining13(.key_update, 0));
    try std.testing.expectEqual(@as(u64, 46), try transport_geometry.kernelControlRemaining13(.alert, 0));
    for (0..6) |sent| try std.testing.expectEqual(@as(u64, (5 - sent) * 23), try transport_geometry.kernelControlRemaining13(.key_update, sent));
    try std.testing.expectError(error.InvalidCursor, transport_geometry.kernelControlRemaining13(.alert, 3));
    try std.testing.expectEqual(@as(u64, 27), try transport_geometry.softwareControlWire(.tls13, .key_update, 27));
    try std.testing.expectEqual(@as(u64, 24), try transport_geometry.softwareControlWire(.tls13, .alert, 24));
    try std.testing.expectError(error.ImpossibleProfile, transport_geometry.softwareControlWire(.tls13, .key_update, 26));
    try std.testing.expectError(error.InvalidPolicy, transport_geometry.softwareControlWire(.tls12_gcm, .key_update, 100));
    const tls12 = @import("../crypto/tls12.zig");
    inline for (.{ tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384, tls12.CipherSuite.tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 }) |suite| {
        const family: transport_geometry.Family = if (suite == .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256) .tls12_chacha else .tls12_gcm;
        var keys: tls12.DirectionKeys = .{};
        defer keys.wipe();
        const sealed = try tls12.sealRecordAlloc(std.testing.allocator, suite, &keys, 0, .alert, &.{ 2, 40 });
        defer std.testing.allocator.free(sealed);
        try std.testing.expectEqual(sealed.len, try transport_geometry.softwareControlWire(family, .alert, 100));
        try std.testing.expectError(error.ImpossibleProfile, transport_geometry.softwareControlWire(family, .alert, sealed.len - 1));
    }
}

test "physical transport geometry: TLS12 actual protected records match GCM and ChaCha plans" {
    const tls12 = @import("../crypto/tls12.zig");
    const a = std.testing.allocator;
    var data: [197]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    const chunks = [_][]const u8{ data[0..1], data[1..65], data[65..] };
    inline for (.{ tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256, tls12.CipherSuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384, tls12.CipherSuite.tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 }) |suite| {
        var keys: tls12.DirectionKeys = .{};
        defer keys.wipe();
        @memset(&keys.key, 0x5a);
        @memset(&keys.iv, 0xa5);
        const family: transport_geometry.Family = if (suite == .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256) .tls12_chacha else .tls12_gcm;
        for ([_]u32{ 17, 64, 16384 }) |quantum| {
            const g = try transport_geometry.Geometry.derive(.{ .family = family, .peer_raw_limit = 64, .quantum = quantum, .physical_capacity = 93 });
            const plan = try g.plan(&chunks, 0);
            var cursor: transport_geometry.Cursor = .{};
            var wire: u64 = 0;
            var seq: u64 = 0;
            while (try g.next(&chunks, cursor)) |piece| {
                const record = try tls12.sealRecordAlloc(a, suite, &keys, seq, .application_data, piece.bytes);
                defer a.free(record);
                const opened = try tls12.openRecordAlloc(a, suite, &keys, seq, record);
                defer a.free(opened.plaintext);
                try std.testing.expectEqualSlices(u8, piece.bytes, opened.plaintext);
                try std.testing.expectEqual(piece.wire, record.len);
                try std.testing.expect(record.len <= g.physical_capacity);
                try std.testing.expect(piece.bytes.len <= 64);
                wire += record.len;
                seq += 1;
                cursor = piece.next_cursor;
            }
            try std.testing.expectEqual(plan.wire, wire);
            try std.testing.expectEqual(plan.records, seq);
        }
    }
}

test "physical transport geometry: TLS13 actual protection matches all suites and fixed partitions" {
    // Socketless record-protection fixture. This verifies byte geometry and
    // decryptability; it is not handshake, kernel support, or hot-adopt evidence.
    const tls_server = @import("../crypto/tls_server.zig");
    const Suite = @typeInfo(@TypeOf(@as(tls_server.Server, undefined).selected_suite)).optional.child;
    const a = std.testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x53));
    var cert_buffer: [1024]u8 = undefined;
    const cert = try @import("../proto/x509_selfsign.zig").buildSelfSigned(&cert_buffer, .{
        .common_name = "geometry.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{1},
        .key_pair = kp,
    });
    var data: [197]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i);
    const chunks = [_][]const u8{ data[0..1], data[1..65], data[65..] };
    inline for (.{ Suite.tls_aes_128_gcm_sha256, Suite.tls_aes_256_gcm_sha384, Suite.tls_chacha20_poly1305_sha256 }) |suite| {
        for ([_]u32{ 17, 63, 16384 }) |quantum| {
            var sender = try tls_server.Server.init(a, .{ .cert_chain = &.{cert}, .signing_key = kp });
            defer sender.deinit();
            var receiver = try tls_server.Server.init(a, .{ .cert_chain = &.{cert}, .signing_key = kp, .receive_record_size_limit = 64 });
            defer receiver.deinit();
            sender.state = .connected;
            sender.selected_suite = suite;
            sender.peer_record_size_limit = 64;
            @memset(&sender.server_app_keys.key, 0x5a);
            @memset(&sender.server_app_keys.iv, 0xa5);
            receiver.state = .connected;
            receiver.selected_suite = suite;
            receiver.client_app_keys = sender.server_app_keys;
            const g = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = quantum, .physical_capacity = 85 });
            const plan = try g.plan(&chunks, 0);
            var cursor: transport_geometry.Cursor = .{};
            var wire: u64 = 0;
            var records: u64 = 0;
            while (try g.next(&chunks, cursor)) |piece| {
                var prepared = try sender.prepareAppWrite(&.{piece.bytes});
                defer prepared.deinit();
                try std.testing.expectEqual(piece.wire, prepared.bytes().len);
                const opened = try receiver.decrypt(prepared.bytes());
                defer a.free(opened);
                try std.testing.expectEqualSlices(u8, piece.bytes, opened);
                prepared.commit();
                wire += prepared.bytes().len;
                records += 1;
                cursor = piece.next_cursor;
            }
            try std.testing.expectEqual(plan.wire, wire);
            try std.testing.expectEqual(plan.records, records);
            try std.testing.expectEqual(plan.next_sequence, sender.app_write_seq);
        }
    }
}

test "physical transport geometry: actual adapter outer splits cannot create uncharged records" {
    const tls_conn = @import("tls_conn.zig");
    const a = std.testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x54));
    var cert_buffer: [1024]u8 = undefined;
    const cert = try @import("../proto/x509_selfsign.zig").buildSelfSigned(&cert_buffer, .{
        .common_name = "geometry.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{1},
        .key_pair = kp,
    });
    var conn = try tls_conn.TlsConn.init(a, .{ .cert_chain = &.{cert}, .signing_key = kp });
    defer conn.deinit();
    const engine = &conn.engine.tls13;
    engine.state = .connected;
    engine.selected_suite = .tls_aes_128_gcm_sha256;
    engine.peer_record_size_limit = 64;
    @memset(&engine.server_app_keys.key, 0x5a);
    @memset(&engine.server_app_keys.iv, 0xa5);
    const bytes = try a.alloc(u8, 32768);
    defer a.free(bytes);
    @memset(bytes, 'o');
    const g = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = 16384, .physical_capacity = 20000 });
    const plan = try g.plan(&.{bytes}, 0);
    var prepared = try conn.prepareWriteBatch(&.{bytes});
    defer prepared.deinit();
    try std.testing.expectEqual(prepared.bytes().len, plan.wire);
    try std.testing.expectEqual(@as(u64, 522), plan.records);
}

test "physical transport geometry: declared size overflow refuses before payload allocation" {
    const g = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = 63, .physical_capacity = 85 });
    try std.testing.expectError(error.CostOverflow, g.planLengths(&.{std.math.maxInt(u64)}, 0));
    try std.testing.expectError(error.CostOverflow, g.planLengths(&.{ std.math.maxInt(u64), 1 }, 0));
    try std.testing.expectError(error.InvalidPayload, g.planLengths(&.{0}, 0));
    try std.testing.expectError(error.SequenceExhausted, g.planLengths(&.{1}, std.math.maxInt(u64)));
    try std.testing.expectEqual(try g.plan(&.{ "abc", "def" }, 10), try g.planLengths(&.{ 3, 3 }, 10));
    const payload: [16400]u8 = @splat(7);
    const boundary = (try g.next(&.{&payload}, .{ .offset = 16384 })).?;
    try std.testing.expectEqual(@as(usize, 16), boundary.bytes.len);
}

test "physical transport geometry: large WebSocket frame streams without reframing or losing owned suffix" {
    const a = std.testing.allocator;
    const input = try a.alloc(u8, 90007);
    defer a.free(input);
    @memset(input[0..90000], 'x');
    @memcpy(input[90000..], "\r\ntail!");
    var framed = try @import("ws_output.zig").prepare(100000, a, "", &.{input}, 100000, 100100);
    defer framed.deinit();
    try std.testing.expectEqual(@as(usize, 1), framed.frameChunks().len);
    try std.testing.expectEqual(@as(u8, 0x81), framed.frameChunks()[0][0]);
    try std.testing.expectEqual(@as(u8, 127), framed.frameChunks()[0][1]);
    try std.testing.expectEqualStrings("tail!", framed.tail());
    const g = try transport_geometry.Geometry.derive(.{ .family = .tls13, .peer_raw_limit = 64, .quantum = 1024, .physical_capacity = 85 });
    const plan = try g.plan(framed.frameChunks(), 0);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(a);
    var cursor: transport_geometry.Cursor = .{};
    var records: u64 = 0;
    var wire: u64 = 0;
    while (try g.next(framed.frameChunks(), cursor)) |piece| {
        try std.testing.expect(piece.bytes.len <= 63 and piece.wire <= 85);
        try joined.appendSlice(a, piece.bytes);
        wire += piece.wire;
        records += 1;
        cursor = piece.next_cursor;
    }
    try std.testing.expectEqualSlices(u8, framed.frameChunks()[0], joined.items);
    try std.testing.expectEqual(plan.records, records);
    try std.testing.expectEqual(plan.wire, wire);
    try std.testing.expectEqualStrings("tail!", framed.tail());
}
