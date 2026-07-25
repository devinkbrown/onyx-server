// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Adaptive transport: reactor-independent adaptive transport seam.
//!
//! This module defines only the transport contract and a deterministic
//! in-memory loopback backend. It performs no OS calls and imports no Onyx Server
//! siblings, so future io_uring, AF_XDP, QUIC, or other backends can implement
//! the same vtable without coupling the seam to a reactor.
const std = @import("std");

/// Transport feature bits advertised by a backend and consumed by policy.
pub const Capabilities = packed struct(u16) {
    zerocopy_tx: bool = false,
    zerocopy_rx: bool = false,
    gso: bool = false,
    gro: bool = false,
    ktls: bool = false,
    multishot_recv: bool = false,
    registered_buffers: bool = false,
    msg_ring: bool = false,
    af_xdp: bool = false,
    quic: bool = false,
    multipath: bool = false,
    ecn_l4s: bool = false,
    _reserved: u4 = 0,

    pub const feature_mask: u16 = (1 << 12) - 1;
    pub const empty: Capabilities = .{};
    pub const all: Capabilities = fromBits(feature_mask);

    /// Return the raw feature bits, excluding reserved storage.
    pub fn bits(self: Capabilities) u16 {
        return @as(u16, @bitCast(self)) & feature_mask;
    }

    /// Build a capability set from raw feature bits.
    pub fn fromBits(raw: u16) Capabilities {
        return @as(Capabilities, @bitCast(raw & feature_mask));
    }

    /// True when every bit in `required` is present in `self`.
    pub fn contains(self: Capabilities, required: Capabilities) bool {
        return (self.bits() & required.bits()) == required.bits();
    }

    /// Feature intersection.
    pub fn intersect(self: Capabilities, other: Capabilities) Capabilities {
        return fromBits(self.bits() & other.bits());
    }

    /// Features in `required` that are missing from `self`.
    pub fn missing(self: Capabilities, required: Capabilities) Capabilities {
        return fromBits(required.bits() & ~self.bits());
    }

    /// Number of advertised feature bits.
    pub fn count(self: Capabilities) u5 {
        return @popCount(self.bits());
    }
};

/// Errors raised by capability policy.
pub const SelectError = error{
    MissingRequiredCapability,
};

/// Select the best compatible feature set from available capabilities.
///
/// With no mutually-exclusive features in adaptive transport's initial bitset, "best"
/// means all available features, provided every required feature is present.
pub fn selectBest(available: Capabilities, required: Capabilities) SelectError!Capabilities {
    if (!available.contains(required)) return error.MissingRequiredCapability;
    return available;
}

/// Send-side completion emitted after a backend accepts part or all of a slice.
pub const SendCompletion = struct {
    id: u64,
    bytes: usize,
    status: Status,

    pub const Status = enum {
        sent,
        dropped,
    };
};

/// Receive-side completion pointing at a caller-supplied inbound buffer.
pub const ReceiveCompletion = struct {
    buffer: []u8,

    /// View only the bytes written by the transport.
    pub fn bytes(self: ReceiveCompletion) []u8 {
        return self.buffer;
    }
};

/// Reactor-independent transport vtable.
///
/// The interface speaks only in byte buffers and completions. `startSend` may
/// accept fewer bytes than requested; callers learn the accepted count through
/// `pollSendCompletions` and can resubmit the remainder.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        start_send: *const fn (*anyopaque, []const u8) anyerror!u64,
        poll_send_completions: *const fn (*anyopaque, []SendCompletion) anyerror!usize,
        supply_receive_buffer: *const fn (*anyopaque, []u8) anyerror!void,
        poll_receive_completions: *const fn (*anyopaque, []ReceiveCompletion) anyerror!usize,
        capabilities: *const fn (*anyopaque) Capabilities,
    };

    /// Start sending bytes through the backend.
    pub fn startSend(self: Transport, bytes: []const u8) !u64 {
        return self.vtable.start_send(self.ptr, bytes);
    }

    /// Drain send completions into `out`.
    pub fn pollSendCompletions(self: Transport, out: []SendCompletion) !usize {
        return self.vtable.poll_send_completions(self.ptr, out);
    }

    /// Supply one inbound buffer for receive completions.
    pub fn supplyReceiveBuffer(self: Transport, buffer: []u8) !void {
        return self.vtable.supply_receive_buffer(self.ptr, buffer);
    }

    /// Drain receive completions into `out`.
    pub fn pollReceiveCompletions(self: Transport, out: []ReceiveCompletion) !usize {
        return self.vtable.poll_receive_completions(self.ptr, out);
    }

    /// Report backend capabilities.
    pub fn capabilities(self: Transport) Capabilities {
        return self.vtable.capabilities(self.ptr);
    }
};

/// Seeded deterministic simulation controls for the loopback backend.
pub const SimulationConfig = struct {
    /// PRNG seed for partial-send, loss, and reordering decisions.
    seed: u64 = 0,
    /// Maximum bytes a single `startSend` accepts. Null or zero means no limit.
    max_send_bytes: ?usize = null,
    /// When true and `max_send_bytes` limits the send, choose 1..limit by PRNG.
    randomize_partial_send: bool = false,
    /// Accepted fragments are dropped with this probability in parts per million.
    loss_per_million: u32 = 0,
    /// Accepted fragments are delayed with this probability in parts per million.
    reorder_per_million: u32 = 0,
};

/// Configuration for a loopback pair.
pub const LoopbackConfig = struct {
    a_capabilities: Capabilities = .{},
    b_capabilities: Capabilities = .{},
    a_simulation: SimulationConfig = .{},
    b_simulation: SimulationConfig = .{},
};

const DirectionQueue = struct {
    fifo: std.ArrayList(u8) = .empty,
    deferred: std.ArrayList([]u8) = .empty,

    fn deinit(self: *DirectionQueue, allocator: std.mem.Allocator) void {
        for (self.deferred.items) |packet| allocator.free(packet);
        self.deferred.deinit(allocator);
        self.fifo.deinit(allocator);
        self.* = undefined;
    }

    fn available(self: *const DirectionQueue) usize {
        return self.fifo.items.len;
    }

    fn write(self: *DirectionQueue, allocator: std.mem.Allocator, bytes: []const u8) !void {
        try self.fifo.appendSlice(allocator, bytes);
    }

    fn deferPacket(self: *DirectionQueue, allocator: std.mem.Allocator, bytes: []const u8) !void {
        const owned = try allocator.dupe(u8, bytes);
        errdefer allocator.free(owned);
        try self.deferred.append(allocator, owned);
    }

    fn flushOneDeferred(self: *DirectionQueue, allocator: std.mem.Allocator) !bool {
        if (self.deferred.items.len == 0) return false;
        const packet = self.deferred.items[0];
        try self.write(allocator, packet);
        consumePrefix([]u8, &self.deferred, 1);
        allocator.free(packet);
        return true;
    }

    fn flushDeferred(self: *DirectionQueue, allocator: std.mem.Allocator) !void {
        while (try self.flushOneDeferred(allocator)) {}
    }

    fn readInto(self: *DirectionQueue, dst: []u8) usize {
        const n = @min(dst.len, self.fifo.items.len);
        if (n == 0) return 0;
        @memcpy(dst[0..n], self.fifo.items[0..n]);
        consumePrefix(u8, &self.fifo, n);
        return n;
    }
};

const SharedLoopback = struct {
    a_to_b: DirectionQueue = .{},
    b_to_a: DirectionQueue = .{},

    fn deinit(self: *SharedLoopback, allocator: std.mem.Allocator) void {
        self.b_to_a.deinit(allocator);
        self.a_to_b.deinit(allocator);
        self.* = undefined;
    }
};

const Side = enum { a, b };

/// Deterministic in-memory transport endpoint.
///
/// Create endpoints with `LoopbackTransport.pair`. Each endpoint implements the
/// `Transport` vtable, copies accepted sends into the peer's shared FIFO, and
/// writes inbound bytes only into buffers supplied by the receiver.
pub const LoopbackTransport = struct {
    allocator: std.mem.Allocator,
    shared: *SharedLoopback,
    side: Side,
    caps: Capabilities,
    simulation: SimulationConfig,
    prng: std.Random.Pcg,
    next_send_id: u64 = 1,
    send_completions: std.ArrayList(SendCompletion) = .empty,
    receive_buffers: std.ArrayList([]u8) = .empty,
    receive_completions: std.ArrayList(ReceiveCompletion) = .empty,

    pub const Pair = struct {
        a: LoopbackTransport,
        b: LoopbackTransport,
        shared: *SharedLoopback,
        allocator: std.mem.Allocator,

        /// Release both endpoints and the shared in-memory FIFOs.
        pub fn deinit(self: *Pair) void {
            self.a.deinitEndpoint();
            self.b.deinitEndpoint();
            self.shared.deinit(self.allocator);
            self.allocator.destroy(self.shared);
            self.* = undefined;
        }
    };

    /// Create a paired loopback transport.
    pub fn pair(allocator: std.mem.Allocator, config: LoopbackConfig) !Pair {
        const shared = try allocator.create(SharedLoopback);
        shared.* = .{};
        return .{
            .a = initEndpoint(allocator, shared, .a, config.a_capabilities, config.a_simulation),
            .b = initEndpoint(allocator, shared, .b, config.b_capabilities, config.b_simulation),
            .shared = shared,
            .allocator = allocator,
        };
    }

    /// Return this endpoint as a transport vtable.
    pub fn transport(self: *LoopbackTransport) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Deterministically flush delayed outbound fragments and local receives.
    pub fn flush(self: *LoopbackTransport) !void {
        try self.outboundQueue().flushDeferred(self.allocator);
        try self.drainInbound();
    }

    fn initEndpoint(
        allocator: std.mem.Allocator,
        shared: *SharedLoopback,
        side: Side,
        caps: Capabilities,
        simulation: SimulationConfig,
    ) LoopbackTransport {
        return .{
            .allocator = allocator,
            .shared = shared,
            .side = side,
            .caps = caps,
            .simulation = simulation,
            .prng = std.Random.Pcg.init(simulation.seed),
        };
    }

    fn deinitEndpoint(self: *LoopbackTransport) void {
        self.receive_completions.deinit(self.allocator);
        self.receive_buffers.deinit(self.allocator);
        self.send_completions.deinit(self.allocator);
        self.* = undefined;
    }

    fn startSend(self: *LoopbackTransport, bytes: []const u8) !u64 {
        const id = self.next_send_id;
        self.next_send_id +%= 1;

        const accepted = self.acceptedLen(bytes.len);
        var status: SendCompletion.Status = .sent;
        if (accepted > 0) {
            const fragment = bytes[0..accepted];
            if (self.chance(self.simulation.loss_per_million)) {
                status = .dropped;
            } else if (self.chance(self.simulation.reorder_per_million)) {
                const queue = self.outboundQueue();
                if (queue.deferred.items.len == 0) {
                    try queue.deferPacket(self.allocator, fragment);
                } else {
                    try queue.write(self.allocator, fragment);
                    _ = try queue.flushOneDeferred(self.allocator);
                }
            } else {
                const queue = self.outboundQueue();
                try queue.write(self.allocator, fragment);
                _ = try queue.flushOneDeferred(self.allocator);
            }
        }

        try self.send_completions.append(self.allocator, .{
            .id = id,
            .bytes = accepted,
            .status = status,
        });
        return id;
    }

    fn pollSendCompletions(self: *LoopbackTransport, out: []SendCompletion) !usize {
        const n = @min(out.len, self.send_completions.items.len);
        if (n == 0) return 0;
        @memcpy(out[0..n], self.send_completions.items[0..n]);
        consumePrefix(SendCompletion, &self.send_completions, n);
        return n;
    }

    fn supplyReceiveBuffer(self: *LoopbackTransport, buffer: []u8) !void {
        if (buffer.len == 0) return error.InvalidReceiveBuffer;
        try self.receive_buffers.append(self.allocator, buffer);
        try self.drainInbound();
    }

    fn pollReceiveCompletions(self: *LoopbackTransport, out: []ReceiveCompletion) !usize {
        try self.drainInbound();
        const n = @min(out.len, self.receive_completions.items.len);
        if (n == 0) return 0;
        @memcpy(out[0..n], self.receive_completions.items[0..n]);
        consumePrefix(ReceiveCompletion, &self.receive_completions, n);
        return n;
    }

    fn capabilities(self: *LoopbackTransport) Capabilities {
        return self.caps;
    }

    fn drainInbound(self: *LoopbackTransport) !void {
        const queue = self.inboundQueue();
        while (queue.available() > 0 and self.receive_buffers.items.len > 0) {
            const buffer = self.receive_buffers.items[0];
            consumePrefix([]u8, &self.receive_buffers, 1);
            const n = queue.readInto(buffer);
            if (n > 0) {
                try self.receive_completions.append(self.allocator, .{ .buffer = buffer[0..n] });
            }
        }
    }

    fn acceptedLen(self: *LoopbackTransport, requested: usize) usize {
        if (requested == 0) return 0;
        const configured_limit = self.simulation.max_send_bytes orelse requested;
        const limit = if (configured_limit == 0) requested else @min(configured_limit, requested);
        if (!self.simulation.randomize_partial_send or limit == 1) return limit;
        return self.prng.random().intRangeAtMost(usize, 1, limit);
    }

    fn chance(self: *LoopbackTransport, per_million: u32) bool {
        if (per_million == 0) return false;
        if (per_million >= 1_000_000) return true;
        return self.prng.random().intRangeLessThan(u32, 0, 1_000_000) < per_million;
    }

    fn outboundQueue(self: *LoopbackTransport) *DirectionQueue {
        return switch (self.side) {
            .a => &self.shared.a_to_b,
            .b => &self.shared.b_to_a,
        };
    }

    fn inboundQueue(self: *LoopbackTransport) *DirectionQueue {
        return switch (self.side) {
            .a => &self.shared.b_to_a,
            .b => &self.shared.a_to_b,
        };
    }

    const vtable: Transport.VTable = .{
        .start_send = vStartSend,
        .poll_send_completions = vPollSendCompletions,
        .supply_receive_buffer = vSupplyReceiveBuffer,
        .poll_receive_completions = vPollReceiveCompletions,
        .capabilities = vCapabilities,
    };

    fn vStartSend(ptr: *anyopaque, bytes: []const u8) anyerror!u64 {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ptr));
        return self.startSend(bytes);
    }

    fn vPollSendCompletions(ptr: *anyopaque, out: []SendCompletion) anyerror!usize {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ptr));
        return self.pollSendCompletions(out);
    }

    fn vSupplyReceiveBuffer(ptr: *anyopaque, buffer: []u8) anyerror!void {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ptr));
        return self.supplyReceiveBuffer(buffer);
    }

    fn vPollReceiveCompletions(ptr: *anyopaque, out: []ReceiveCompletion) anyerror!usize {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ptr));
        return self.pollReceiveCompletions(out);
    }

    fn vCapabilities(ptr: *anyopaque) Capabilities {
        const self: *LoopbackTransport = @ptrCast(@alignCast(ptr));
        return self.capabilities();
    }
};

fn consumePrefix(comptime T: type, list: *std.ArrayList(T), count: usize) void {
    if (count == 0) return;
    std.debug.assert(count <= list.items.len);
    const remaining = list.items.len - count;
    if (remaining > 0) {
        std.mem.copyForwards(T, list.items[0..remaining], list.items[count..]);
    }
    list.items.len = remaining;
}

const DeterminismTrace = struct {
    send_count: usize = 0,
    send_bytes: [32]usize = @splat(0),
    send_status: [32]SendCompletion.Status = @splat(.sent),
    recv_len: usize = 0,
    recv_bytes: [128]u8 = @splat(0),
};

fn runDeterminismTrace(allocator: std.mem.Allocator, seed: u64) !DeterminismTrace {
    var pair_state = try LoopbackTransport.pair(allocator, .{
        .a_simulation = .{
            .seed = seed,
            .max_send_bytes = 5,
            .randomize_partial_send = true,
            .loss_per_million = 200_000,
            .reorder_per_million = 500_000,
        },
    });
    defer pair_state.deinit();

    const payload = "abcdefghijklmnopqrstuvwxyz";
    var tx = pair_state.a.transport();
    var offset: usize = 0;
    var trace: DeterminismTrace = .{};
    while (offset < payload.len) {
        _ = try tx.startSend(payload[offset..]);
        var completions: [1]SendCompletion = undefined;
        const n = try tx.pollSendCompletions(&completions);
        try std.testing.expectEqual(@as(usize, 1), n);
        try std.testing.expect(trace.send_count < trace.send_bytes.len);
        trace.send_bytes[trace.send_count] = completions[0].bytes;
        trace.send_status[trace.send_count] = completions[0].status;
        trace.send_count += 1;
        offset += completions[0].bytes;
    }

    try pair_state.a.flush();
    var rx = pair_state.b.transport();
    var buffer: [128]u8 = undefined;
    try rx.supplyReceiveBuffer(&buffer);
    var receive: [1]ReceiveCompletion = undefined;
    const n = try rx.pollReceiveCompletions(&receive);
    if (n == 1) {
        trace.recv_len = receive[0].buffer.len;
        @memcpy(trace.recv_bytes[0..trace.recv_len], receive[0].buffer);
    }
    return trace;
}

test "loopback round-trip send recv across vtable" {
    const allocator = std.testing.allocator;
    var pair_state = try LoopbackTransport.pair(allocator, .{
        .a_capabilities = .{ .gso = true, .ecn_l4s = true },
        .b_capabilities = .{ .gro = true, .multishot_recv = true },
    });
    defer pair_state.deinit();

    var tx = pair_state.a.transport();
    var rx = pair_state.b.transport();
    try std.testing.expect(tx.capabilities().contains(.{ .gso = true }));
    try std.testing.expect(rx.capabilities().contains(.{ .gro = true }));

    var receive_buffer: [64]u8 = undefined;
    try rx.supplyReceiveBuffer(&receive_buffer);
    const id = try tx.startSend("adaptive");

    var send: [2]SendCompletion = undefined;
    try std.testing.expectEqual(@as(usize, 1), try tx.pollSendCompletions(&send));
    try std.testing.expectEqual(id, send[0].id);
    // Default SimulationConfig has no max_send_bytes and randomize_partial_send=false,
    // so the full payload is accepted in one completion (not a partial 6-byte fragment).
    try std.testing.expectEqual(@as(usize, "adaptive".len), send[0].bytes);
    try std.testing.expectEqual(SendCompletion.Status.sent, send[0].status);

    var receive: [2]ReceiveCompletion = undefined;
    try std.testing.expectEqual(@as(usize, 1), try rx.pollReceiveCompletions(&receive));
    try std.testing.expectEqualSlices(u8, "adaptive", receive[0].bytes());
}

test "capability negotiation accepts superset and rejects missing required" {
    const available: Capabilities = .{
        .zerocopy_tx = true,
        .gso = true,
        .gro = true,
        .quic = true,
        .ecn_l4s = true,
    };
    const required: Capabilities = .{ .gso = true, .quic = true };
    const selected = try selectBest(available, required);
    try std.testing.expect(selected.contains(required));
    try std.testing.expectEqual(available.bits(), selected.bits());
    try std.testing.expectEqual(@as(u5, 5), selected.count());

    try std.testing.expectError(
        error.MissingRequiredCapability,
        selectBest(available, .{ .af_xdp = true }),
    );
    const missing_af_xdp: Capabilities = .{ .af_xdp = true };
    try std.testing.expectEqual(missing_af_xdp.bits(), available.missing(missing_af_xdp).bits());
}

test "completion and flush model drains correctly" {
    const allocator = std.testing.allocator;
    var pair_state = try LoopbackTransport.pair(allocator, .{
        .a_simulation = .{
            .seed = 9,
            .reorder_per_million = 1_000_000,
        },
    });
    defer pair_state.deinit();

    var tx = pair_state.a.transport();
    var rx = pair_state.b.transport();
    var receive_buffer: [32]u8 = undefined;
    try rx.supplyReceiveBuffer(&receive_buffer);
    _ = try tx.startSend("held");

    var send: [1]SendCompletion = undefined;
    try std.testing.expectEqual(@as(usize, 1), try tx.pollSendCompletions(&send));
    try std.testing.expectEqual(@as(usize, 0), try tx.pollSendCompletions(&send));

    var receive: [1]ReceiveCompletion = undefined;
    try std.testing.expectEqual(@as(usize, 0), try rx.pollReceiveCompletions(&receive));
    try pair_state.a.flush();
    try std.testing.expectEqual(@as(usize, 1), try rx.pollReceiveCompletions(&receive));
    try std.testing.expectEqualSlices(u8, "held", receive[0].bytes());
    try std.testing.expectEqual(@as(usize, 0), try rx.pollReceiveCompletions(&receive));
}

test "simulated partial send is handled by resubmitting the remainder" {
    const allocator = std.testing.allocator;
    var pair_state = try LoopbackTransport.pair(allocator, .{
        .a_simulation = .{
            .max_send_bytes = 3,
        },
    });
    defer pair_state.deinit();

    const payload = "partial-send-payload";
    var tx = pair_state.a.transport();
    var offset: usize = 0;
    while (offset < payload.len) {
        _ = try tx.startSend(payload[offset..]);
        var send: [1]SendCompletion = undefined;
        try std.testing.expectEqual(@as(usize, 1), try tx.pollSendCompletions(&send));
        try std.testing.expect(send[0].bytes > 0);
        try std.testing.expect(send[0].bytes <= 3);
        offset += send[0].bytes;
    }

    var rx = pair_state.b.transport();
    var receive_buffer: [64]u8 = undefined;
    try rx.supplyReceiveBuffer(&receive_buffer);
    var receive: [1]ReceiveCompletion = undefined;
    try std.testing.expectEqual(@as(usize, 1), try rx.pollReceiveCompletions(&receive));
    try std.testing.expectEqualSlices(u8, payload, receive[0].bytes());
}

test "loopback simulation is deterministic given seed" {
    const allocator = std.testing.allocator;
    const left = try runDeterminismTrace(allocator, 0x51525354);
    const right = try runDeterminismTrace(allocator, 0x51525354);

    try std.testing.expectEqual(left.send_count, right.send_count);
    try std.testing.expectEqualSlices(usize, left.send_bytes[0..left.send_count], right.send_bytes[0..right.send_count]);
    try std.testing.expectEqualSlices(
        SendCompletion.Status,
        left.send_status[0..left.send_count],
        right.send_status[0..right.send_count],
    );
    try std.testing.expectEqual(left.recv_len, right.recv_len);
    try std.testing.expectEqualSlices(u8, left.recv_bytes[0..left.recv_len], right.recv_bytes[0..right.recv_len]);
}
