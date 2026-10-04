// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turn-local outbound IRC framing. Only the outbound prefix is borrowed at
//! prepare entry; all candidate bytes are owned before any adapter publication.
const std = @import("std");
const websocket = @import("../proto/websocket.zig");
pub const Error = error{ OutOfMemory, OutputTooSmall };

/// A stable allocator context lives through every prepared byte. Refusing
/// resize/remap makes ArrayList retirement pass through the wiping free path,
/// including the old buffer replaced during growth and every partial OOM unwind.
const SensitiveStorage = struct {
    parent: std.mem.Allocator,

    fn allocator(self: *SensitiveStorage) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SensitiveStorage = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(len, alignment, ret_addr);
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *SensitiveStorage = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, bytes);
        self.parent.rawFree(bytes, alignment, ret_addr);
    }
    fn destroy(self: *SensitiveStorage) void {
        const parent = self.parent;
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        parent.destroy(self);
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    initial: []u8,
    wire: std.ArrayList(u8),
    chunks: []const []const u8,
    suffix: std.ArrayList(u8),
    done: bool = false,
    sensitive_storage: ?*SensitiveStorage = null,

    pub fn frameChunks(self: *const Prepared) []const []const u8 {
        return self.chunks;
    }

    pub fn bytes(self: *const Prepared) []const u8 {
        return self.wire.items;
    }

    pub fn tail(self: *const Prepared) []const u8 {
        return self.suffix.items;
    }

    /// Under the same exclusive connection turn as preparation. Inbound WS
    /// state is neither cloned nor modified. SEND arming happens afterwards.
    pub fn commitTail(self: *Prepared, ws: anytype) void {
        std.debug.assert(!self.done and ws.tx_len == self.initial.len);
        std.debug.assert(std.mem.eql(u8, ws.tx_buf[0..ws.tx_len], self.initial));
        std.debug.assert(self.suffix.items.len <= ws.tx_buf.len);
        @memcpy(ws.tx_buf[0..self.suffix.items.len], self.suffix.items);
        ws.tx_len = self.suffix.items.len;
        self.done = true;
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.initial);
        self.allocator.free(self.chunks);
        self.wire.deinit(self.allocator);
        self.suffix.deinit(self.allocator);
        if (self.sensitive_storage) |owner| owner.destroy();
        self.* = undefined;
    }
};

/// Same framing and queue geometry, with source-owned wipe custody for every
/// temporary, superseded allocation and final prepared buffer. deinit remains
/// outside the caller's no-fail publication cut. This plan is lexically owned;
/// copied raw Prepared structs are not independent cleanup authorities.
pub fn prepareSensitive(comptime max_frame: usize, allocator: std.mem.Allocator, initial: []const u8, chunks: []const []const u8, max_tx: usize, max_wire: usize) Error!Prepared {
    const owner = try allocator.create(SensitiveStorage);
    owner.* = .{ .parent = allocator };
    errdefer owner.destroy();
    var prepared = try prepare(max_frame, owner.allocator(), initial, chunks, max_tx, max_wire);
    prepared.sensitive_storage = owner;
    return prepared;
}

/// max_wire is the caller's aggregate queue budget, not a separate allowance.
/// No chunks emits no frame; an explicit empty IRC line emits an empty TEXT
/// frame. Chunk boundaries do not create frames or discard a carried prefix.
pub fn prepare(comptime max_frame: usize, allocator: std.mem.Allocator, initial: []const u8, chunks: []const []const u8, max_tx: usize, max_wire: usize) Error!Prepared {
    if (initial.len > max_tx or std.mem.indexOfScalar(u8, initial, '\n') != null) return error.OutputTooSmall;
    const owned_initial = try allocator.dupe(u8, initial);
    errdefer allocator.free(owned_initial);
    var line: std.ArrayList(u8) = .empty;
    errdefer line.deinit(allocator);
    try line.appendSlice(allocator, initial);
    var wire: std.ArrayList(u8) = .empty;
    errdefer wire.deinit(allocator);
    const Span = struct { start: usize, end: usize };
    var spans: std.ArrayList(Span) = .empty;
    defer spans.deinit(allocator);
    for (chunks) |chunk| {
        var rest = chunk;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            const seg = rest[0..nl];
            const length = std.math.add(usize, line.items.len, seg.len) catch return error.OutputTooSmall;
            if (length > max_frame + 1) return error.OutputTooSmall;
            try line.appendSlice(allocator, seg);
            const payload = if (line.items.len != 0 and line.items[line.items.len - 1] == '\r')
                line.items[0 .. line.items.len - 1]
            else
                line.items;
            if (payload.len > max_frame) return error.OutputTooSmall;
            const header: usize = if (payload.len <= 125) 2 else if (payload.len <= 65535) 4 else 10;
            const frame_len = std.math.add(usize, header, payload.len) catch return error.OutputTooSmall;
            if (wire.items.len > max_wire or frame_len > max_wire - wire.items.len) return error.OutputTooSmall;
            const start = wire.items.len;
            try wire.resize(allocator, start + frame_len);
            _ = websocket.encodeFrame(max_frame, .{ .opcode = .text }, payload, wire.items[start..]) catch
                return error.OutputTooSmall;
            try spans.append(allocator, .{ .start = start, .end = wire.items.len });
            line.clearRetainingCapacity();
            rest = rest[nl + 1 ..];
        }
        if (line.items.len > max_tx or rest.len > max_tx - line.items.len) return error.OutputTooSmall;
        try line.appendSlice(allocator, rest);
    }
    const framed = try allocator.alloc([]const u8, spans.items.len);
    for (spans.items, framed) |span, *chunk| chunk.* = wire.items[span.start..span.end];
    return .{ .allocator = allocator, .initial = owned_initial, .wire = wire, .chunks = framed, .suffix = line };
}

test "prepared application output: WebSocket complete batch preserves prefix until custody" {
    const Ws = struct { tx_buf: [16]u8 = undefined, tx_len: usize = 0 };
    var ws: Ws = .{};
    @memcpy(ws.tx_buf[0..3], "PRE");
    ws.tx_len = 3;
    var prepared = try prepare(64, std.testing.allocator, ws.tx_buf[0..ws.tx_len], &.{ "FIX\r", "\nnext\nend" }, 16, 128);
    defer prepared.deinit();
    try std.testing.expectEqualStrings("PRE", ws.tx_buf[0..ws.tx_len]);
    try std.testing.expectEqual(@as(usize, 2), prepared.frameChunks().len);
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 6, 'P', 'R', 'E', 'F', 'I', 'X' }, prepared.frameChunks()[0]);
    try std.testing.expectEqualStrings("end", prepared.tail());
    prepared.commitTail(&ws);
    try std.testing.expectEqualStrings("end", ws.tx_buf[0..ws.tx_len]);
}

test "prepared application output: later WebSocket failure preserves every live byte" {
    const Ws = struct { tx_buf: [16]u8 = undefined, tx_len: usize = 3 };
    var ws: Ws = .{};
    @memcpy(ws.tx_buf[0..3], "PRE");
    try std.testing.expectError(error.OutputTooSmall, prepare(8, std.testing.allocator, ws.tx_buf[0..3], &.{ "\n", "way too long\n" }, 16, 128));
    try std.testing.expectEqualStrings("PRE", ws.tx_buf[0..ws.tx_len]);
    try std.testing.expectError(error.OutputTooSmall, prepare(64, std.testing.allocator, ws.tx_buf[0..3], &.{"\nsecond\n"}, 16, 6));
    try std.testing.expectEqualStrings("PRE", ws.tx_buf[0..ws.tx_len]);
}

test "prepared application output: WebSocket allocation failures abort and retry" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var prepared = prepare(64, allocator, "pre", &.{ "fix\n", "two\r\n", "tail" }, 16, 128) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                var retry = try prepare(64, std.testing.allocator, "pre", &.{ "fix\n", "two\r\n", "tail" }, 16, 128);
                defer retry.deinit();
                try std.testing.expectEqual(@as(usize, 2), retry.frameChunks().len);
                return err;
            };
            defer prepared.deinit();
            try std.testing.expectEqual(@as(usize, 2), prepared.frameChunks().len);
            try std.testing.expectEqualStrings("tail", prepared.tail());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "prepared application output: WebSocket suffix-only empty lines and frame bounds" {
    var tail_only = try prepare(8, std.testing.allocator, "pre", &.{"fix"}, 8, 0);
    defer tail_only.deinit();
    try std.testing.expectEqual(@as(usize, 0), tail_only.frameChunks().len);
    try std.testing.expectEqualStrings("prefix", tail_only.tail());
    var frames = try prepare(8, std.testing.allocator, "", &.{ "\n", "12345678\r\n" }, 8, 12);
    defer frames.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0 }, frames.frameChunks()[0]);
    try std.testing.expectEqual(@as(usize, 10), frames.frameChunks()[1].len);
    try std.testing.expectEqualStrings("", frames.tail());
    try std.testing.expectError(error.OutputTooSmall, prepare(8, std.testing.allocator, "", &.{"123456789\n"}, 8, 128));
    try std.testing.expectError(error.OutputTooSmall, prepare(8, std.testing.allocator, "bad\n", &.{}, 8, 128));
}

test "prepared application output: WebSocket whole batch SendQ rejection retains prefix for exact retry" {
    const sendq = @import("sendq.zig");
    const Connection = struct {
        send_buf: [8]u8 = undefined,
        send_len: usize = 0,
        send_offset: usize = 0,
        send_armed: bool = false,
        sendq_cap: usize = 4,
        send_overflow: std.ArrayList(u8) = .empty,
        overflow_allocator: std.mem.Allocator = std.testing.allocator,
    };
    const Ws = struct { tx_buf: [16]u8 = undefined, tx_len: usize = 3 };
    var c: Connection = .{};
    defer c.send_overflow.deinit(c.overflow_allocator);
    var ws: Ws = .{};
    @memcpy(ws.tx_buf[0..3], "PRE");
    var first = try prepare(16, std.testing.allocator, ws.tx_buf[0..3], &.{ "\nnext\n", "tail" }, 16, 64);
    defer first.deinit();
    try std.testing.expectError(error.OutputTooSmall, sendq.prepareAppend(&c, first.bytes().len));
    try std.testing.expectEqual(@as(usize, 0), c.send_len);
    try std.testing.expectEqual(@as(usize, 0), c.send_overflow.items.len);
    try std.testing.expectEqualStrings("PRE", ws.tx_buf[0..ws.tx_len]);
    c.sendq_cap = 64;
    var retry = try prepare(16, std.testing.allocator, ws.tx_buf[0..ws.tx_len], &.{ "\nnext\n", "tail" }, 16, 64);
    defer retry.deinit();
    var reserved = try sendq.prepareAppend(&c, retry.bytes().len);
    reserved.commit(retry.bytes());
    retry.commitTail(&ws);
    try std.testing.expectEqualSlices(u8, first.bytes(), c.send_overflow.items);
    try std.testing.expectEqualStrings("tail", ws.tx_buf[0..ws.tx_len]);
}

const WipeObserver = struct {
    parent: std.mem.Allocator,
    allocated: usize = 0,
    freed: usize = 0,
    frees: usize = 0,
    dirty_frees: usize = 0,
    growth_lengths: [3]usize = @splat(0),
    growth_frees: [3]usize = @splat(0),
    growth_pointers: [3]usize = @splat(0),

    fn allocator(self: *WipeObserver) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *WipeObserver = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
        // Nonzero unused backing makes the wipe oracle non-vacuous too.
        @memset(ptr[0..len], 0xa5);
        self.allocated += len;
        for (self.growth_lengths, &self.growth_pointers) |expected, *saved| {
            if (expected == len and saved.* == 0) saved.* = @intFromPtr(ptr);
        }
        return ptr;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *WipeObserver = @ptrCast(@alignCast(ctx));
        if (!std.mem.allEqual(u8, bytes, 0)) self.dirty_frees += 1;
        for (self.growth_lengths, self.growth_pointers, &self.growth_frees) |len, saved, *count| {
            if (len != 0 and len == bytes.len and saved == @intFromPtr(bytes.ptr)) count.* += 1;
        }
        self.frees += 1;
        self.freed += bytes.len;
        self.parent.rawFree(bytes, alignment, ret_addr);
    }
};

// Derive first payload and frame count from this SDK's actual target geometry.
// x86_64 uses a 128-byte cache line: the old fixture's 411-byte payload and six
// spans fitted the initial 413-byte line and nine-span allocations.
const SensitiveTestSpan = struct { start: usize, end: usize };
const sensitive_test_prefix = @as([190]u8, @splat('p'));
const sensitive_test_first_payload = std.ArrayList(u8).growCapacity(sensitive_test_prefix.len) + 32;
const sensitive_test_frame_count = @max(8, std.ArrayList(SensitiveTestSpan).growCapacity(1) + 1);
const sensitive_test_second_line = "secret-" ++ @as([343]u8, @splat('s')) ++ "\r\n";
const sensitive_test_chunk_storage = blk: {
    var chunks: [sensitive_test_frame_count + 1][]const u8 = @splat(sensitive_test_second_line);
    chunks[0] = "first-secret-" ++ @as([sensitive_test_first_payload - sensitive_test_prefix.len - "first-secret-".len]u8, @splat('f')) ++ "\r\n";
    chunks[sensitive_test_frame_count] = "carried-secret-tail";
    break :blk chunks;
};
const sensitive_test_chunks: []const []const u8 = &sensitive_test_chunk_storage;
const sensitive_test_max_frame = @max(512, sensitive_test_first_payload);
const sensitive_test_wire_len = sensitive_test_first_payload + 4 + (sensitive_test_frame_count - 1) * (sensitive_test_second_line.len - 2 + 4);
const sensitive_growth_lengths: [3]usize = .{
    std.ArrayList(u8).growCapacity(sensitive_test_prefix.len),
    std.ArrayList(u8).growCapacity(sensitive_test_first_payload + 4),
    std.ArrayList(SensitiveTestSpan).growCapacity(1) * @sizeOf(SensitiveTestSpan),
};

test "protected application output: sensitive framing preserves exact wire and wipes replaced backing" {
    try std.testing.expect(sensitive_test_prefix.len + sensitive_test_chunks[0].len - 2 > sensitive_growth_lengths[0]);
    try std.testing.expect(sensitive_test_frame_count > std.ArrayList(SensitiveTestSpan).growCapacity(1));
    for (sensitive_growth_lengths, 0..) |length, i| {
        for (sensitive_growth_lengths[i + 1 ..]) |other| try std.testing.expect(length != other);
    }
    var ordinary = try prepare(sensitive_test_max_frame, std.testing.allocator, &sensitive_test_prefix, sensitive_test_chunks, sensitive_test_max_frame, sensitive_test_wire_len);
    defer ordinary.deinit();
    var observed: WipeObserver = .{ .parent = std.testing.allocator, .growth_lengths = sensitive_growth_lengths };
    {
        var sensitive = try prepareSensitive(sensitive_test_max_frame, observed.allocator(), &sensitive_test_prefix, sensitive_test_chunks, sensitive_test_max_frame, sensitive_test_wire_len);
        defer sensitive.deinit();
        try std.testing.expectEqualSlices(u8, ordinary.bytes(), sensitive.bytes());
        try std.testing.expectEqualSlices(u8, ordinary.tail(), sensitive.tail());
        try std.testing.expectEqual(@as(usize, sensitive_test_frame_count), sensitive.frameChunks().len);
        try std.testing.expect(sensitive.bytes().len > 2048);
        try std.testing.expectEqual(sensitive_test_wire_len, sensitive.bytes().len);
        // Exact first capacities are distinct from final descriptor/storage
        // lengths; each count proves replacement BEFORE final Prepared cleanup.
        for (observed.growth_frees) |count| try std.testing.expect(count > 0);
        try std.testing.expectEqual(@as(usize, 0), observed.dirty_frees);
    }
    try std.testing.expectEqual(observed.allocated, observed.freed);
    try std.testing.expectEqual(@as(usize, 0), observed.dirty_frees);
}

test "protected application output: every sensitive OOM and bounds unwind wipes before allocator free" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var observed: WipeObserver = .{ .parent = allocator, .growth_lengths = sensitive_growth_lengths };
            var prepared = prepareSensitive(sensitive_test_max_frame, observed.allocator(), &sensitive_test_prefix, sensitive_test_chunks, sensitive_test_max_frame, sensitive_test_wire_len) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(observed.allocated, observed.freed);
                try std.testing.expectEqual(@as(usize, 0), observed.dirty_frees);
                // Disable pressure and retry with the same source observer.
                observed.parent = std.testing.allocator;
                // The failed attempt has fully retired. Prove the retry's own
                // replacement identities, rather than counting its abort frees.
                observed.growth_pointers = @splat(0);
                observed.growth_frees = @splat(0);
                {
                    var retry = try prepareSensitive(sensitive_test_max_frame, observed.allocator(), &sensitive_test_prefix, sensitive_test_chunks, sensitive_test_max_frame, sensitive_test_wire_len);
                    defer retry.deinit();
                    try std.testing.expectEqual(@as(usize, sensitive_test_frame_count), retry.frameChunks().len);
                    try std.testing.expect(retry.bytes().len > 2048);
                    for (observed.growth_frees) |count| try std.testing.expect(count > 0);
                }
                try std.testing.expectEqual(observed.allocated, observed.freed);
                try std.testing.expectEqual(@as(usize, 0), observed.dirty_frees);
                return err;
            };
            var prepared_live = true;
            defer if (prepared_live) prepared.deinit();
            for (observed.growth_frees) |count| try std.testing.expect(count > 0);
            prepared.deinit();
            prepared_live = false;
            try std.testing.expectEqual(observed.allocated, observed.freed);
            try std.testing.expectEqual(@as(usize, 0), observed.dirty_frees);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
    var bounded: WipeObserver = .{ .parent = std.testing.allocator };
    try std.testing.expectError(error.OutputTooSmall, prepareSensitive(sensitive_test_max_frame, bounded.allocator(), &sensitive_test_prefix, sensitive_test_chunks, sensitive_test_max_frame, 300));
    try std.testing.expect(bounded.frees > 0);
    try std.testing.expectEqual(bounded.allocated, bounded.freed);
    try std.testing.expectEqual(@as(usize, 0), bounded.dirty_frees);
}
