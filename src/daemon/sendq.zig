// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection SendQ: inline buffer plus heap overflow.
//!
//! The kernel only ever reads the fixed inline buffer. Overflow is refilled
//! into that buffer on send completion, and an armed send is never compacted.
//! Callers pass the live connection; these functions are the daemon's queue.

const std = @import("std");

/// A turn-local reservation. The caller exclusively owns the connection until
/// commit/abort; no send completion, append or Helix may interleave. Only storage
/// capacity changes during preparation. No borrowed input is retained.
pub fn PreparedAppend(comptime Connection: type) type {
    return struct {
        conn: Connection,
        len: usize,
        old_len: usize,
        old_offset: usize,
        old_overflow: usize,
        old_cap: usize,
        old_armed: bool,
        old_deferred: usize,
        old_control: usize,
        old_tail: usize,
        mode: enum { inline_tail, compact, overflow },
        done: bool = false,

        pub fn abort(self: *@This()) void {
            self.done = true;
        }

        /// Publish exactly the reserved bytes; cannot allocate or return an error.
        pub fn commit(self: *@This(), bytes: []const u8) void {
            std.debug.assert(!self.done and bytes.len == self.len);
            const c = self.conn;
            std.debug.assert(c.send_len == self.old_len and c.send_offset == self.old_offset and
                c.send_overflow.items.len == self.old_overflow and c.sendq_cap == self.old_cap and
                c.send_armed == self.old_armed and deferredCharge(c) == self.old_deferred and
                controlCharge(c) == self.old_control and deferredLength(c) == self.old_tail);
            switch (self.mode) {
                .compact => {
                    const tail = c.send_len - c.send_offset;
                    std.mem.copyForwards(u8, c.send_buf[0..tail], c.send_buf[c.send_offset..c.send_len]);
                    c.send_len = tail;
                    c.send_offset = 0;
                    @memcpy(c.send_buf[c.send_len..][0..bytes.len], bytes);
                    c.send_len += bytes.len;
                },
                .inline_tail => {
                    @memcpy(c.send_buf[c.send_len..][0..bytes.len], bytes);
                    c.send_len += bytes.len;
                },
                .overflow => c.send_overflow.appendSliceAssumeCapacity(bytes),
            }
            self.done = true;
        }
    };
}

pub fn prepareAppend(conn: anytype, bytes_len: usize) error{OutputTooSmall}!PreparedAppend(@TypeOf(conn)) {
    return prepareWire(conn, bytes_len, deferredCharge(conn), controlCharge(conn));
}

fn prepareWire(conn: anytype, bytes_len: usize, retained_deferred: usize, retained_control: usize) error{OutputTooSmall}!PreparedAppend(@TypeOf(conn)) {
    const queued = try checkedTotal(conn, retained_deferred, retained_control);
    if (queued > conn.sendq_cap or bytes_len > conn.sendq_cap - queued) return error.OutputTooSmall;
    const Mode = @FieldType(PreparedAppend(@TypeOf(conn)), "mode");
    const mode: Mode = if (conn.send_overflow.items.len == 0 and bytes_len <= conn.send_buf.len - conn.send_len)
        .inline_tail
    else if (conn.send_overflow.items.len == 0 and !conn.send_armed and conn.send_offset != 0 and
        bytes_len <= conn.send_buf.len - (conn.send_len - conn.send_offset))
        .compact
    else
        .overflow;
    if (mode == .overflow) conn.send_overflow.ensureUnusedCapacity(conn.overflow_allocator, bytes_len) catch
        return error.OutputTooSmall;
    return .{ .conn = conn, .len = bytes_len, .old_len = conn.send_len, .old_offset = conn.send_offset, .old_overflow = conn.send_overflow.items.len, .old_cap = conn.sendq_cap, .old_armed = conn.send_armed, .old_deferred = deferredCharge(conn), .old_control = controlCharge(conn), .old_tail = deferredLength(conn), .mode = mode };
}

/// Actual sendable bytes. Reservations and typed plaintext are never armed.
pub fn wireBacklog(conn: anytype) u64 {
    const inline_queued = conn.send_len -| conn.send_offset;
    return std.math.add(u64, inline_queued, conn.send_overflow.items.len) catch std.math.maxInt(u64);
}

/// Physical queue charge, including future ciphertext and control headroom.
pub fn backlog(conn: anytype) u64 {
    const with_tail = std.math.add(u64, wireBacklog(conn), deferredCharge(conn)) catch return std.math.maxInt(u64);
    return std.math.add(u64, with_tail, controlCharge(conn)) catch std.math.maxInt(u64);
}

// Secured mesh/raw queue users do not have a TLS tail. Typed APIs below require
// all TLS fields; the generic wire API also serves those non-TLS owners.
fn deferredCharge(conn: anytype) usize {
    return if (@hasField(@TypeOf(conn.*), "tls_deferred_charge")) conn.tls_deferred_charge else 0;
}
fn controlCharge(conn: anytype) usize {
    return if (@hasField(@TypeOf(conn.*), "tls_control_charge")) conn.tls_control_charge else 0;
}
fn deferredLength(conn: anytype) usize {
    return if (@hasField(@TypeOf(conn.*), "tls_deferred_plain")) conn.tls_deferred_plain.items.len else 0;
}
fn checkedTotal(conn: anytype, tail: usize, control: usize) error{OutputTooSmall}!usize {
    if (conn.send_offset > conn.send_len or conn.send_len > conn.send_buf.len) return error.OutputTooSmall;
    const stored = deferredLength(conn);
    const charged = deferredCharge(conn);
    if (stored > charged or (stored == 0 and charged != 0)) return error.OutputTooSmall;
    const wire = std.math.add(usize, conn.send_len - conn.send_offset, conn.send_overflow.items.len) catch return error.OutputTooSmall;
    const subtotal = std.math.add(usize, wire, tail) catch return error.OutputTooSmall;
    return std.math.add(usize, subtotal, control) catch error.OutputTooSmall;
}

const QueueState = struct {
    len: usize,
    offset: usize,
    overflow: usize,
    cap: usize,
    armed: bool,
    tail: usize,
    deferred: usize,
    control: usize,

    fn capture(c: anytype) QueueState {
        return .{ .len = c.send_len, .offset = c.send_offset, .overflow = c.send_overflow.items.len, .cap = c.sendq_cap, .armed = c.send_armed, .tail = c.tls_deferred_plain.items.len, .deferred = c.tls_deferred_charge, .control = c.tls_control_charge };
    }
    fn assertUnchanged(self: QueueState, c: anytype) void {
        std.debug.assert(std.meta.eql(self, capture(c)));
    }
};

pub fn PreparedControlReservation(comptime Connection: type) type {
    return struct {
        conn: Connection,
        old: QueueState,
        charge: usize,
        done: bool = false,
        pub fn abort(self: *@This()) void {
            self.done = true;
        }
        pub fn commit(self: *@This()) void {
            std.debug.assert(!self.done);
            self.old.assertUnchanged(self.conn);
            self.conn.tls_control_charge = self.charge;
            self.done = true;
        }
    };
}

pub fn prepareControlReservation(conn: anytype, bytes: usize) error{OutputTooSmall}!PreparedControlReservation(@TypeOf(conn)) {
    if (bytes == 0 or (conn.tls_control_charge != 0 and conn.tls_control_charge != bytes)) return error.OutputTooSmall;
    const total = try checkedTotal(conn, conn.tls_deferred_charge, bytes);
    if (total > conn.sendq_cap) return error.OutputTooSmall;
    return .{ .conn = conn, .old = QueueState.capture(conn), .charge = bytes };
}

/// Only an exclusive owner may account accepted kernel control bytes.
pub fn consumeControlCharge(conn: anytype, accepted: usize) void {
    std.debug.assert(accepted <= conn.tls_control_charge);
    conn.tls_control_charge -= accepted;
}
/// Release unused speculative credit or terminal/aborted custody. The owner
/// must have no outstanding KU reply obligation; request=0 can leave credit unused.
pub fn cancelControlReservation(conn: anytype) void {
    conn.tls_control_charge = 0;
}

pub fn PreparedReservedControlAppend(comptime Connection: type) type {
    return struct {
        wire: PreparedAppend(Connection),
        pub fn abort(self: *@This()) void {
            self.wire.abort();
        }
        pub fn commit(self: *@This(), bytes: []const u8) void {
            self.wire.commit(bytes);
            self.wire.conn.tls_control_charge = 0;
        }
    };
}
pub fn prepareReservedControlAppend(conn: anytype, bytes_len: usize) error{OutputTooSmall}!PreparedReservedControlAppend(@TypeOf(conn)) {
    if (bytes_len == 0 or bytes_len > conn.tls_control_charge) return error.OutputTooSmall;
    return .{ .wire = try prepareWire(conn, bytes_len, conn.tls_deferred_charge, 0) };
}

pub const DeferredIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    pub fn next(self: *DeferredIterator) error{InvalidDeferred}!?[]const u8 {
        if (self.pos > self.bytes.len) return error.InvalidDeferred;
        if (self.pos == self.bytes.len) return null;
        if (self.bytes.len - self.pos < 4) return error.InvalidDeferred;
        const len: usize = std.mem.readInt(u32, self.bytes[self.pos..][0..4], .little);
        if (len == 0 or len > self.bytes.len - self.pos - 4) return error.InvalidDeferred;
        const start = self.pos + 4;
        self.pos = start + len;
        return self.bytes[start..self.pos];
    }
};

fn aliasesDeferredAllocation(conn: anytype, ptr: anytype, len: usize) bool {
    if (len == 0 or conn.tls_deferred_plain.capacity == 0) return false;
    const owned_start = @intFromPtr(conn.tls_deferred_plain.items.ptr);
    const owned_end = std.math.add(usize, owned_start, conn.tls_deferred_plain.capacity) catch return true;
    const input_start = @intFromPtr(ptr);
    const input_end = std.math.add(usize, input_start, len) catch return true;
    return input_start < owned_end and owned_start < input_end;
}

pub fn PreparedDeferred(comptime Connection: type) type {
    return struct {
        conn: Connection,
        old: QueueState,
        serialized: usize,
        charge: usize,
        lengths: []u32,
        allocator: std.mem.Allocator,
        done: bool = false,
        metadata_owned: bool = true,
        pub fn abort(self: *@This()) void {
            // After retained publication, abort only retires preparation metadata;
            // accepted queue bytes and charges are never rolled back.
            if (!self.metadata_owned) return;
            self.allocator.free(self.lengths);
            self.lengths = &.{};
            self.metadata_owned = false;
            self.done = true;
        }
        pub fn deinit(self: *@This()) void {
            self.abort();
        }
        pub fn commit(self: *@This(), chunks: []const []const u8) void {
            self.commitRetainingMetadata(chunks);
            self.deinit();
        }
        /// Publish only into reserved storage, without allocator callbacks. The
        /// exclusive source owner must deinit after leaving its publication cut.
        pub fn commitRetainingMetadata(self: *@This(), chunks: []const []const u8) void {
            std.debug.assert(!self.done and self.metadata_owned);
            self.old.assertUnchanged(self.conn);
            const descriptor_bytes = std.math.mul(usize, chunks.len, @sizeOf([]const u8)) catch unreachable;
            std.debug.assert(!aliasesDeferredAllocation(self.conn, chunks.ptr, descriptor_bytes));
            var shape: usize = 0;
            for (chunks) |chunk| {
                if (chunk.len == 0) continue;
                std.debug.assert(!aliasesDeferredAllocation(self.conn, chunk.ptr, chunk.len));
                std.debug.assert(shape < self.lengths.len and chunk.len == self.lengths[shape]);
                shape += 1;
            }
            std.debug.assert(shape == self.lengths.len);
            const c = self.conn;
            var pos = c.tls_deferred_plain.items.len;
            for (chunks) |chunk| {
                if (chunk.len == 0) continue;
                std.mem.writeInt(u32, c.tls_deferred_plain.allocatedSlice()[pos..][0..4], @intCast(chunk.len), .little);
                pos += 4;
                @memcpy(c.tls_deferred_plain.allocatedSlice()[pos..][0..chunk.len], chunk);
                pos += chunk.len;
            }
            std.debug.assert(pos == self.old.tail + self.serialized);
            c.tls_deferred_plain.items.len = pos;
            c.tls_deferred_charge += self.charge;
            self.done = true;
        }
    };
}

pub fn prepareDeferredAppend(conn: anytype, chunks: []const []const u8, wire_charge: usize) error{OutputTooSmall}!PreparedDeferred(@TypeOf(conn)) {
    // Growing the tail invalidates slices and descriptor arrays borrowed from
    // its allocation. Refuse them before either shape allocation or relocation.
    // Commit inputs must retain this same nonalias boundary.
    const descriptor_bytes = std.math.mul(usize, chunks.len, @sizeOf([]const u8)) catch return error.OutputTooSmall;
    if (aliasesDeferredAllocation(conn, chunks.ptr, descriptor_bytes)) return error.OutputTooSmall;
    var serialized: usize = 0;
    var count: usize = 0;
    for (chunks) |chunk| {
        if (chunk.len == 0) continue;
        if (aliasesDeferredAllocation(conn, chunk.ptr, chunk.len)) return error.OutputTooSmall;
        if (chunk.len > std.math.maxInt(u32)) return error.OutputTooSmall;
        count = std.math.add(usize, count, 1) catch return error.OutputTooSmall;
        serialized = std.math.add(usize, serialized, 4) catch return error.OutputTooSmall;
        serialized = std.math.add(usize, serialized, chunk.len) catch return error.OutputTooSmall;
    }
    if (count > std.math.maxInt(u32) or serialized > std.math.maxInt(u32) or serialized > wire_charge or
        (count == 0 and wire_charge != 0)) return error.OutputTooSmall;
    // First tail publication requires funded reply headroom. A ready tail
    // already has reply custody and may accept later chunks in the same FIFO.
    if (count != 0 and conn.tls_control_charge == 0 and conn.tls_deferred_plain.items.len == 0) return error.OutputTooSmall;
    const total = try checkedTotal(conn, conn.tls_deferred_charge, conn.tls_control_charge);
    if (total > conn.sendq_cap or wire_charge > conn.sendq_cap - total) return error.OutputTooSmall;
    const final_len = std.math.add(usize, conn.tls_deferred_plain.items.len, serialized) catch return error.OutputTooSmall;
    if (final_len > std.math.maxInt(u32)) return error.OutputTooSmall;
    const allocator = conn.overflow_allocator;
    const shape_bytes = std.math.mul(usize, count, @sizeOf(u32)) catch return error.OutputTooSmall;
    if (shape_bytes > serialized) return error.OutputTooSmall;
    const lengths = allocator.alloc(u32, count) catch return error.OutputTooSmall;
    errdefer allocator.free(lengths);
    var index: usize = 0;
    for (chunks) |chunk| {
        if (chunk.len == 0) continue;
        lengths[index] = @intCast(chunk.len);
        index += 1;
    }
    conn.tls_deferred_plain.ensureTotalCapacityPrecise(allocator, final_len) catch return error.OutputTooSmall;
    return .{ .conn = conn, .old = QueueState.capture(conn), .serialized = serialized, .charge = wire_charge, .lengths = lengths, .allocator = allocator };
}

pub fn PreparedDeferredReplacement(comptime Connection: type) type {
    return struct {
        wire: PreparedAppend(Connection),
        pub fn abort(self: *@This()) void {
            self.wire.abort();
        }
        pub fn commit(self: *@This(), bytes: []const u8) void {
            self.wire.commit(bytes);
            self.wire.conn.tls_deferred_plain.clearRetainingCapacity();
            self.wire.conn.tls_deferred_charge = 0;
        }
    };
}
pub fn prepareDeferredReplacement(conn: anytype, ciphertext_len: usize) error{OutputTooSmall}!PreparedDeferredReplacement(@TypeOf(conn)) {
    if (ciphertext_len > conn.tls_deferred_charge or
        (ciphertext_len == 0 and conn.tls_deferred_plain.items.len != 0)) return error.OutputTooSmall;
    return .{ .wire = try prepareWire(conn, ciphertext_len, 0, conn.tls_control_charge) };
}

pub fn rawAppend(conn: anytype, bytes: []const u8) error{OutputTooSmall}!void {
    var prepared = try prepareAppend(conn, bytes.len);
    prepared.commit(bytes);
}

/// Reserve the exact SendQ storage needed by one already-sized secured record
/// before advancing the link's AEAD send counter. Once this succeeds,
/// `rawAppend` cannot fail for capacity or allocation, so replay never has
/// to leave counter-owning ciphertext in a shared SecuredLink outbound buffer.
pub fn reserve(conn: anytype, bytes_len: usize) error{OutputTooSmall}!void {
    var prepared = try prepareAppend(conn, bytes_len);
    prepared.abort();
}

/// Refill the drained inline `send_buf` with the next chunk of the SendQ overflow.
/// Called from the send-completion handler with nothing armed, so writing the
/// inline buffer is safe. The overflow heap is freed entirely once fully drained
/// so a one-off burst never pins memory.
pub fn refill(conn: anytype) void {
    if (conn.send_overflow.items.len == 0) return;
    const n = @min(conn.send_buf.len, conn.send_overflow.items.len);
    @memcpy(conn.send_buf[0..n], conn.send_overflow.items[0..n]);
    conn.send_len = n;
    conn.send_offset = 0;
    if (n == conn.send_overflow.items.len) {
        conn.send_overflow.clearAndFree(conn.overflow_allocator);
    } else {
        const remaining = conn.send_overflow.items.len - n;
        std.mem.copyForwards(u8, conn.send_overflow.items[0..remaining], conn.send_overflow.items[n..]);
        conn.send_overflow.items.len = remaining;
    }
}

const TestConnection = struct {
    send_buf: [8]u8 = undefined,
    send_len: usize = 0,
    send_offset: usize = 0,
    send_armed: bool = false,
    sendq_cap: usize = 64,
    send_overflow: std.ArrayList(u8) = .empty,
    overflow_allocator: std.mem.Allocator,
    tls_deferred_plain: std.ArrayList(u8) = .empty,
    tls_deferred_charge: usize = 0,
    tls_control_charge: usize = 0,
};

test "TLS deferred queue: full cap holds input until reply credit is funded" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .sendq_cap = 27, .send_len = 8 };
    defer c.tls_deferred_plain.deinit(std.testing.allocator);
    @memcpy(&c.send_buf, "OLD_WIRE");
    try std.testing.expectError(error.OutputTooSmall, prepareControlReservation(&c, 27));
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &.{"x"}, 23));
    try std.testing.expectEqualStrings("OLD_WIRE", &c.send_buf);
    c.send_len = 0;
    var reserved = try prepareControlReservation(&c, 27);
    reserved.abort();
    try std.testing.expectEqual(@as(usize, 0), c.tls_control_charge);
    reserved = try prepareControlReservation(&c, 27);
    c.overflow_allocator = std.testing.failing_allocator;
    reserved.commit();
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(u64, 0), wireBacklog(&c));
    try std.testing.expectEqual(@as(u64, 27), backlog(&c));
    try std.testing.expectError(error.OutputTooSmall, prepareAppend(&c, 1));
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &.{"x"}, 23));
    var same = try prepareControlReservation(&c, 27);
    same.commit();
    try std.testing.expectError(error.OutputTooSmall, prepareControlReservation(&c, 5));
    cancelControlReservation(&c);
    var kernel = try prepareControlReservation(&c, 5);
    kernel.commit();
    consumeControlCharge(&c, 2);
    try std.testing.expectEqual(@as(u64, 3), backlog(&c));
    consumeControlCharge(&c, 3);
    try std.testing.expectEqual(@as(u64, 0), backlog(&c));
}

test "TLS deferred queue: armed old wire reply and replacement keep exact FIFO without allocation" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .send_len = 4, .send_armed = true, .sendq_cap = 78 };
    defer c.send_overflow.deinit(std.testing.allocator);
    defer c.tls_deferred_plain.deinit(std.testing.allocator);
    @memcpy(c.send_buf[0..4], "OLD!");
    const armed = c.send_buf[0..4].ptr;
    var credit = try prepareControlReservation(&c, 27);
    credit.commit();
    var deferred = try prepareDeferredAppend(&c, &.{ "a", "", "bc" }, 47);
    c.overflow_allocator = std.testing.failing_allocator;
    deferred.commit(&.{ "a", "bc", "" });
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqual(armed, c.send_buf[0..4].ptr);
    try std.testing.expectEqualStrings("OLD!", c.send_buf[0..4]);
    try std.testing.expectEqual(@as(u64, 78), backlog(&c));
    try std.testing.expectError(error.OutputTooSmall, prepareAppend(&c, 1));
    var iter: DeferredIterator = .{ .bytes = c.tls_deferred_plain.items };
    try std.testing.expectEqualStrings("a", (try iter.next()).?);
    try std.testing.expectEqualStrings("bc", (try iter.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try iter.next());
    const reply: [27]u8 = @splat('K');
    var aborted = try prepareReservedControlAppend(&c, reply.len);
    aborted.abort();
    try std.testing.expectEqual(@as(usize, 27), c.tls_control_charge);
    try std.testing.expectEqual(@as(usize, 0), c.send_overflow.items.len);
    var control = try prepareReservedControlAppend(&c, reply.len);
    c.overflow_allocator = std.testing.failing_allocator;
    control.commit(&reply);
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), c.tls_control_charge);
    try std.testing.expectEqualSlices(u8, &reply, c.send_overflow.items);
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredReplacement(&c, 48));
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredReplacement(&c, 0));
    var replacement_abort = try prepareDeferredReplacement(&c, 47);
    replacement_abort.abort();
    try std.testing.expectEqual(@as(usize, 47), c.tls_deferred_charge);
    const next: [47]u8 = @splat('N');
    var replacement = try prepareDeferredReplacement(&c, next.len);
    c.overflow_allocator = std.testing.failing_allocator;
    replacement.commit(&next);
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqualStrings("OLD!", c.send_buf[0..4]);
    try std.testing.expectEqualSlices(u8, &reply, c.send_overflow.items[0..27]);
    try std.testing.expectEqualSlices(u8, &next, c.send_overflow.items[27..]);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_plain.items.len);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_charge);
    try std.testing.expectEqual(@as(u64, 78), backlog(&c));
    try std.testing.expect(c.send_armed);
}

test "TLS deferred queue: empty input is bounded noop and canonical iterator rejects all truncations" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.failing_allocator };
    const empties: [1024][]const u8 = @splat("");
    var no_op = try prepareDeferredAppend(&c, &empties, 0);
    no_op.commit(&empties);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_plain.capacity);
    try std.testing.expectEqual(@as(u64, 0), backlog(&c));
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &empties, 1));
    const canonical = [_]u8{ 3, 0, 0, 0, 'a', 'b', 'c' };
    for (1..canonical.len) |prefix| {
        var malformed: DeferredIterator = .{ .bytes = canonical[0..prefix] };
        try std.testing.expectError(error.InvalidDeferred, malformed.next());
    }
    var empty: DeferredIterator = .{ .bytes = "" };
    try std.testing.expectEqual(@as(?[]const u8, null), try empty.next());
    var zero: DeferredIterator = .{ .bytes = &.{ 0, 0, 0, 0 } };
    try std.testing.expectError(error.InvalidDeferred, zero.next());
    var overflow: DeferredIterator = .{ .bytes = &.{ 255, 255, 255, 255, 1 } };
    try std.testing.expectError(error.InvalidDeferred, overflow.next());
    var invalid_pos: DeferredIterator = .{ .bytes = "", .pos = 1 };
    try std.testing.expectError(error.InvalidDeferred, invalid_pos.next());
}

test "TLS deferred queue: shape and payload OOM retain predecessor and retry exactly" {
    var failed: usize = 0;
    for (0..16) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var c: TestConnection = .{ .overflow_allocator = failing.allocator(), .send_len = 4, .send_armed = true, .tls_control_charge = 27, .sendq_cap = 256 };
        defer c.tls_deferred_plain.deinit(failing.allocator());
        @memcpy(c.send_buf[0..4], "OLD!");
        var old = try prepareDeferredAppend(&c, &.{"first"}, 27);
        old.commit(&.{"first"});
        const before: [9]u8 = c.tls_deferred_plain.items[0..9].*;
        failing.fail_index = failing.alloc_index + fail_index;
        var ticket = prepareDeferredAppend(&c, &.{ "second", "third" }, 55) catch |err| {
            failed += 1;
            try std.testing.expectEqual(error.OutputTooSmall, err);
            try std.testing.expectEqualStrings("OLD!", c.send_buf[0..4]);
            try std.testing.expectEqualSlices(u8, &before, c.tls_deferred_plain.items);
            try std.testing.expectEqual(@as(usize, 27), c.tls_deferred_charge);
            try std.testing.expectEqual(@as(usize, 27), c.tls_control_charge);
            try std.testing.expectEqual(@as(u64, 4), wireBacklog(&c));
            failing.fail_index = std.math.maxInt(usize);
            var retry = try prepareDeferredAppend(&c, &.{ "second", "third" }, 55);
            retry.commit(&.{ "second", "third" });
            try std.testing.expectEqual(@as(usize, 82), c.tls_deferred_charge);
            continue;
        };
        const allocation_count = failing.alloc_index;
        failing.fail_index = allocation_count;
        c.overflow_allocator = std.testing.failing_allocator;
        ticket.commit(&.{ "second", "third" });
        c.overflow_allocator = failing.allocator();
        try std.testing.expectEqual(allocation_count, failing.alloc_index);
        try std.testing.expectEqual(@as(usize, 82), c.tls_deferred_charge);
        var iterator: DeferredIterator = .{ .bytes = c.tls_deferred_plain.items };
        try std.testing.expectEqualStrings("first", (try iterator.next()).?);
        try std.testing.expectEqualStrings("second", (try iterator.next()).?);
        try std.testing.expectEqualStrings("third", (try iterator.next()).?);
        try std.testing.expectEqual(@as(?[]const u8, null), try iterator.next());
        break;
    }
    try std.testing.expectEqual(@as(usize, 2), failed);
}

test "TLS deferred queue: abort owns shape allocator and wire capacity OOM preserves both reservations" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .send_len = 8, .send_armed = true, .tls_control_charge = 27, .sendq_cap = 128 };
    defer c.tls_deferred_plain.deinit(std.testing.allocator);
    defer c.send_overflow.deinit(std.testing.allocator);
    @memcpy(&c.send_buf, "OLD_WIRE");
    var aborted = try prepareDeferredAppend(&c, &.{"held"}, 26);
    c.overflow_allocator = std.testing.failing_allocator;
    aborted.abort();
    aborted.abort();
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_plain.items.len);
    var retained = try prepareDeferredAppend(&c, &.{"held"}, 26);
    retained.commit(&.{"held"});
    c.overflow_allocator = std.testing.failing_allocator;
    try std.testing.expectError(error.OutputTooSmall, prepareReservedControlAppend(&c, 27));
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredReplacement(&c, 26));
    c.overflow_allocator = std.testing.allocator;
    try std.testing.expectEqualStrings("OLD_WIRE", &c.send_buf);
    try std.testing.expectEqual(@as(usize, 27), c.tls_control_charge);
    try std.testing.expectEqual(@as(usize, 26), c.tls_deferred_charge);
    try std.testing.expectEqual(@as(usize, 0), c.send_overflow.items.len);
}

test "TLS deferred queue: malformed bounds and overflow reject before queue mutation" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.failing_allocator, .tls_control_charge = 27 };
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &.{"payload"}, 1));
    try std.testing.expectError(error.OutputTooSmall, prepareControlReservation(&c, 0));
    try std.testing.expectError(error.OutputTooSmall, prepareReservedControlAppend(&c, 28));
    c.send_offset = 1;
    try std.testing.expectError(error.OutputTooSmall, prepareAppend(&c, 0));
    c.send_offset = 0;
    c.tls_control_charge = std.math.maxInt(usize);
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &.{"x"}, 23));
    c.tls_deferred_charge = std.math.maxInt(usize);
    try std.testing.expectEqual(std.math.maxInt(u64), backlog(&c));
    try std.testing.expectError(error.OutputTooSmall, prepareAppend(&c, 0));
    try std.testing.expectEqual(@as(usize, 0), c.send_len);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_plain.items.len);
}

test "TLS deferred queue: borrowed payload and descriptors refuse before relocation or allocation" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .tls_control_charge = 27, .sendq_cap = 256 };
    defer c.tls_deferred_plain.deinit(std.testing.allocator);
    var seed = try prepareDeferredAppend(&c, &.{"old"}, 25);
    seed.commit(&.{"old"});
    try std.testing.expectEqual(@as(usize, 7), c.tls_deferred_plain.capacity);
    const original = c.tls_deferred_plain.items.ptr;
    c.overflow_allocator = std.testing.failing_allocator;
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, &.{c.tls_deferred_plain.items[4..7]}, 25));
    try std.testing.expectEqual(original, c.tls_deferred_plain.items.ptr);
    try std.testing.expectEqualStrings("old", c.tls_deferred_plain.items[4..7]);
    try std.testing.expectEqual(@as(usize, 25), c.tls_deferred_charge);
    c.overflow_allocator = std.testing.allocator;
    // A canonical 60-byte app chunk may itself contain slice descriptors.
    // The descriptor array is borrowed from its payload at aligned offset8.
    try c.tls_deferred_plain.ensureTotalCapacityPrecise(std.testing.allocator, 64);
    c.tls_deferred_plain.items.len = 64;
    @memset(c.tls_deferred_plain.items, 0);
    std.mem.writeInt(u32, c.tls_deferred_plain.items[0..4], 60, .little);
    c.tls_deferred_charge = 82;
    const descriptors: *[1][]const u8 = @ptrCast(@alignCast(c.tls_deferred_plain.items[8..24].ptr));
    descriptors[0] = "new";
    const descriptor_owner = c.tls_deferred_plain.items.ptr;
    c.overflow_allocator = std.testing.failing_allocator;
    try std.testing.expectError(error.OutputTooSmall, prepareDeferredAppend(&c, descriptors, 25));
    try std.testing.expectEqual(descriptor_owner, c.tls_deferred_plain.items.ptr);
    try std.testing.expectEqual(@as(usize, 64), c.tls_deferred_plain.items.len);
    try std.testing.expectEqual(@as(usize, 82), c.tls_deferred_charge);
    c.overflow_allocator = std.testing.allocator;
}

test "TLS deferred queue: retained publication has no allocator callback and cleanup preserves accepted FIFO" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    var c: TestConnection = .{ .overflow_allocator = allocator, .send_len = 4, .send_armed = true, .tls_control_charge = 5, .sendq_cap = 128 };
    defer c.tls_deferred_plain.deinit(allocator);
    @memcpy(c.send_buf[0..4], "OLD!");
    var first = try prepareDeferredAppend(&c, &.{"first"}, 27);
    first.commit(&.{"first"});
    var retained = try prepareDeferredAppend(&c, &.{ "a", "", "bc" }, 47);
    defer retained.deinit();
    const before_allocations = failing.allocations;
    const before_deallocations = failing.deallocations;
    failing.fail_index = failing.alloc_index;
    c.overflow_allocator = std.testing.failing_allocator;
    retained.commitRetainingMetadata(&.{ "a", "bc", "" });
    try std.testing.expectEqual(before_allocations, failing.allocations);
    try std.testing.expectEqual(before_deallocations, failing.deallocations);
    try std.testing.expect(retained.done and retained.metadata_owned);
    try std.testing.expectEqualStrings("OLD!", c.send_buf[0..4]);
    try std.testing.expect(c.send_armed);
    try std.testing.expectEqual(@as(usize, 5), c.tls_control_charge);
    try std.testing.expectEqual(@as(usize, 74), c.tls_deferred_charge);
    var iter: DeferredIterator = .{ .bytes = c.tls_deferred_plain.items };
    try std.testing.expectEqualStrings("first", (try iter.next()).?);
    try std.testing.expectEqualStrings("a", (try iter.next()).?);
    try std.testing.expectEqualStrings("bc", (try iter.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try iter.next());
    const accepted_len = c.tls_deferred_plain.items.len;
    retained.deinit();
    try std.testing.expectEqual(before_deallocations + 1, failing.deallocations);
    try std.testing.expect(!retained.metadata_owned);
    retained.abort();
    retained.deinit();
    try std.testing.expectEqual(before_deallocations + 1, failing.deallocations);
    try std.testing.expectEqual(accepted_len, c.tls_deferred_plain.items.len);
    try std.testing.expectEqual(@as(usize, 74), c.tls_deferred_charge);
}

test "TLS deferred queue: ordinary publication frees metadata immediately and abort remains idempotent" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    var c: TestConnection = .{ .overflow_allocator = allocator };
    defer c.tls_deferred_plain.deinit(allocator);
    var control = try prepareControlReservation(&c, 5);
    control.commit();
    var aborted = try prepareDeferredAppend(&c, &.{"secret"}, 28);
    const before_abort = failing.deallocations;
    aborted.abort();
    aborted.abort();
    aborted.deinit();
    try std.testing.expectEqual(before_abort + 1, failing.deallocations);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_plain.items.len);
    try std.testing.expectEqual(@as(usize, 0), c.tls_deferred_charge);
    try std.testing.expectEqual(@as(usize, 5), c.tls_control_charge);
    var ordinary = try prepareDeferredAppend(&c, &.{"secret"}, 28);
    const before_commit = failing.deallocations;
    ordinary.commit(&.{"secret"});
    try std.testing.expectEqual(before_commit + 1, failing.deallocations);
    try std.testing.expect(ordinary.done and !ordinary.metadata_owned);
    ordinary.deinit();
    ordinary.abort();
    try std.testing.expectEqual(before_commit + 1, failing.deallocations);
    var iter: DeferredIterator = .{ .bytes = c.tls_deferred_plain.items };
    try std.testing.expectEqualStrings("secret", (try iter.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try iter.next());
    try std.testing.expectEqual(@as(usize, 28), c.tls_deferred_charge);
    try std.testing.expectEqual(@as(usize, 5), c.tls_control_charge);
}

test "prepared application output: SendQ abort and no-allocation compact publication" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .send_len = 8, .send_offset = 6 };
    @memcpy(&c.send_buf, "sentxxAB");
    var aborted = try prepareAppend(&c, 4);
    aborted.abort();
    try std.testing.expectEqualStrings("sentxxAB", &c.send_buf);
    try std.testing.expectEqual(@as(usize, 8), c.send_len);
    try std.testing.expectEqual(@as(usize, 6), c.send_offset);
    var prepared = try prepareAppend(&c, 4);
    c.overflow_allocator = std.testing.failing_allocator;
    prepared.commit("CDEF");
    try std.testing.expectEqualStrings("ABCDEF", c.send_buf[0..c.send_len]);
    try std.testing.expectEqual(@as(usize, 0), c.send_offset);
}

test "prepared application output: armed SendQ buffer stays fixed and overflow commits without allocation" {
    var c: TestConnection = .{ .overflow_allocator = std.testing.allocator, .send_len = 8, .send_offset = 6, .send_armed = true };
    defer c.send_overflow.deinit(std.testing.allocator);
    @memcpy(&c.send_buf, "sentxxAB");
    var prepared = try prepareAppend(&c, 4);
    c.overflow_allocator = std.testing.failing_allocator;
    prepared.commit("CDEF");
    try std.testing.expectEqualStrings("sentxxAB", &c.send_buf);
    try std.testing.expectEqual(@as(usize, 6), c.send_offset);
    try std.testing.expectEqualStrings("CDEF", c.send_overflow.items);
    try std.testing.expectEqual(@as(u64, 6), backlog(&c));
}

test "prepared application output: SendQ overflow OOM and cap rejection preserve queue before retry" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var c: TestConnection = .{ .overflow_allocator = allocator, .send_len = 8, .send_offset = 2, .send_armed = true };
            defer c.send_overflow.deinit(allocator);
            @memcpy(&c.send_buf, "sentxxAB");
            var prepared = prepareAppend(&c, 4) catch |err| {
                try std.testing.expectEqualStrings("sentxxAB", &c.send_buf);
                try std.testing.expectEqual(@as(usize, 8), c.send_len);
                try std.testing.expectEqual(@as(usize, 2), c.send_offset);
                try std.testing.expectEqual(@as(usize, 0), c.send_overflow.items.len);
                // Retry with the same queue at a functioning allocator.
                c.overflow_allocator = std.testing.allocator;
                var retry = try prepareAppend(&c, 4);
                retry.commit("CDEF");
                try std.testing.expectEqualStrings("CDEF", c.send_overflow.items);
                c.send_overflow.deinit(std.testing.allocator);
                c.send_overflow = .empty;
                try std.testing.expectEqual(error.OutputTooSmall, err);
                return error.OutOfMemory;
            };
            prepared.commit("CDEF");
            const old_len = c.send_overflow.items.len;
            try std.testing.expectError(error.OutputTooSmall, prepareAppend(&c, 65));
            try std.testing.expectEqual(old_len, c.send_overflow.items.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}
