// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public behavior, strict checkpoint and allocation-atomicity regressions.
const std = @import("std");
const message_relay_v2 = @import("../../substrate/undertow/message_relay_v2.zig");
const store = @import("store.zig");
const checkpoint_codec = @import("checkpoint_wire.zig");
const row_storage = @import("rows.zig");
const RelayId = store.RelayId;
const Config = store.Config;
const ReserveOutcome = store.ReserveOutcome;
const PageItem = store.PageItem;
const PrepareAcceptedResult = store.PrepareAcceptedResult;
const PreparedAccepted = store.PreparedAccepted;
const ConfirmationOutcome = store.ConfirmationOutcome;
const EventLog = store.EventLog;
const checkpoint_header_len = checkpoint_codec.checkpoint_header_len;
const row_origin_node_offset = checkpoint_codec.row_origin_node_offset;
const row_wire_len_offset = checkpoint_codec.row_wire_len_offset;
const row_confirmed_count_offset = checkpoint_codec.row_confirmed_count_offset;
const row_required_count_offset = checkpoint_codec.row_required_count_offset;
const row_excluded_count_offset = checkpoint_codec.row_excluded_count_offset;
const row_prefix_len = checkpoint_codec.row_prefix_len;
const checksum_len = checkpoint_codec.checksum_len;
const checkpointChecksum = checkpoint_codec.checkpointChecksum;
const readU32 = checkpoint_codec.readU32;
const readU64 = checkpoint_codec.readU64;
const writeU64 = checkpoint_codec.writeU64;
const originEqual = row_storage.originEqual;
const idsEqual = row_storage.idsEqual;
const lowerBoundRows = row_storage.lowerBoundRows;

const testing = std.testing;

const TestWire = struct {
    id: RelayId,
    bytes: []u8,

    fn deinit(self: *TestWire, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn makeTestWire(
    allocator: std.mem.Allocator,
    kp: *const @import("../../crypto/sign.zig").KeyPair,
    hlc: u64,
    text: []const u8,
) !TestWire {
    const signed_frame = @import("../../substrate/undertow/signed_frame.zig");
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = "#event-log",
        .source_prefix = "alice!u@mesh.test",
        .text = text,
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, kp, &pubkey, &signature);
    const id = switch (try message_relay_v2.verifyAndRelayId(allocator, msg)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    return .{ .id = id, .bytes = try message_relay_v2.encode(allocator, msg) };
}

fn takeReady(result: PrepareAcceptedResult) !PreparedAccepted {
    return switch (result) {
        .ready => |prepared| prepared,
        .conflict => error.TestUnexpectedResult,
    };
}

fn rowsEndInCheckpoint(bytes: []const u8) usize {
    var pos: usize = checkpoint_header_len;
    const row_count: usize = readU32(bytes[30..34]);
    for (0..row_count) |_| {
        const wire_len: usize = readU32(bytes[pos + row_wire_len_offset ..][0..4]);
        const confirmed_count: usize = readU32(bytes[pos + row_confirmed_count_offset ..][0..4]);
        const required_count: usize = readU32(bytes[pos + row_required_count_offset ..][0..4]);
        const excluded_count: usize = readU32(bytes[pos + row_excluded_count_offset ..][0..4]);
        pos += row_prefix_len + wire_len +
            (confirmed_count + required_count + excluded_count) * @sizeOf(u64);
    }
    return pos;
}

test "relay v2 event log prepared accept abort duplicate and conflict are byte inert" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x41)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "other");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();

    try testing.expectEqual(ReserveOutcome.inserted, try log.reserveAccepted(first.id, first.bytes, 7, 8, &required));
    try testing.expect(!log.isConfirmedBy(first.id, 8));
    const retained = log.viewFor(first.id).?;
    try testing.expectEqualSlices(u8, &first.id, &retained.relay_id);
    try testing.expectEqualSlices(u64, &required, retained.required_nodes);
    try testing.expectEqualSlices(u8, first.bytes, log.wireFor(first.id).?);
    try testing.expect(log.viewFor(second.id) == null);
    try testing.expect(log.wireFor(second.id) == null);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    try testing.expectEqual(ReserveOutcome.exact_duplicate, try log.reserveAccepted(first.id, first.bytes, 7, 8, &required));
    const duplicate = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(duplicate);
    try testing.expectEqualSlices(u8, before, duplicate);

    try testing.expectEqual(ReserveOutcome.conflict, try log.reserveAccepted(first.id, second.bytes, 7, null, &required));
    const after_conflict = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_conflict);
    try testing.expectEqualSlices(u8, before, after_conflict);

    var aborted = try takeReady(try log.prepareAccepted(first.id, first.bytes, 7, 9, &required));
    aborted.abort();
    aborted.deinit();
    const after_abort = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);
}

test "relay v2 event log rejects full row before cryptographic work and freezes bounds" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x42)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 1 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.CapacityExceeded, log.reserveAccepted(second.id, &.{0xff}, 7, null, &required));
    const after = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);

    log.config.max_rows = 2;
    try testing.expectError(error.ConfigMismatch, log.encodeCheckpoint(testing.allocator));
    try testing.expectError(error.ConfigMismatch, log.prepareAccepted(second.id, second.bytes, 7, null, &required));
}

test "relay v2 event log ingress is one-sweep exclusion not durable confirmation" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x43)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "ingress");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, 8, &required);
    try testing.expect(log.isConfirmedBy(wire.id, 7));
    try testing.expect(!log.isConfirmedBy(wire.id, 8));
    try testing.expectEqualSlices(u64, &.{8}, log.viewAt(0).excluded_once_nodes);

    var page: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(8, &page));
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(8, &page));
    try testing.expect(idsEqual(wire.id, page[0].relay_id));
}

test "relay v2 event log pages only event-time required missing coverage" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x44)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    var third = try makeTestWire(testing.allocator, &kp, 3, "third");
    defer third.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.reserveAccepted(third.id, third.bytes, 7, null, &required);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(second.id, 99));
    try testing.expectEqual(ConfirmationOutcome.already_confirmed, try log.confirmAuthenticatedDurableAck(second.id, 99));

    var page: [3]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
    try testing.expect(idsEqual(first.id, page[0].relay_id));
    try testing.expectEqual(@as(u64, 1), page[0].hlc);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(first.id, 99));
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
    try testing.expect(idsEqual(third.id, page[0].relay_id));
    try testing.expectEqual(@as(u64, 3), page[0].hlc);
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(100, &page));
}

test "relay v2 event log checkpointed cursor reaches row 33 after restore" {
    const sign = @import("../../crypto/sign.zig");
    const config = Config{ .max_rows = 33 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x45)));
    defer kp.deinit();
    var wires: [33]TestWire = undefined;
    var initialized: usize = 0;
    defer for (wires[0..initialized]) |*wire| wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    for (0..wires.len) |index| {
        wires[index] = try makeTestWire(testing.allocator, &kp, index + 1, "fairness");
        initialized += 1;
        _ = try log.reserveAccepted(wires[index].id, wires[index].bytes, 7, null, &required);
    }
    var page: [1]PageItem = undefined;
    for (0..32) |index| {
        try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
        try testing.expectEqual(@as(u64, index + 1), page[0].hlc);
        try testing.expect(idsEqual(wires[index].id, page[0].relay_id));
        try testing.expectEqual(
            ConfirmationOutcome.confirmed_and_retired,
            try log.confirmAuthenticatedDurableAck(page[0].relay_id, 99),
        );
    }
    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(99, &page));
    try testing.expectEqual(@as(u64, 33), page[0].hlc);
    try testing.expect(idsEqual(wires[32].id, page[0].relay_id));
}

test "relay v2 event log scrambled 129 row backlog stays ascending through RVG2 window" {
    const sign = @import("../../crypto/sign.zig");
    const replay_guard = @import("../relay_v2_replay_guard.zig");
    const config = Config{ .max_rows = 129 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x5c)));
    defer kp.deinit();
    var wires: [129]TestWire = undefined;
    var initialized: usize = 0;
    defer for (wires[0..initialized]) |*wire| wire.deinit(testing.allocator);
    for (0..wires.len) |index| {
        wires[index] = try makeTestWire(testing.allocator, &kp, @intCast(index + 1), "scrambled-window");
        initialized += 1;
    }

    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    // 67 is coprime to 129, so this visits every row exactly once while
    // deliberately destroying HLC insertion order.
    for (0..wires.len) |iteration| {
        const index = (iteration * 67) % wires.len;
        _ = try log.reserveAccepted(wires[index].id, wires[index].bytes, 7, null, &required);
    }

    var guard = try replay_guard.Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var page: [8]PageItem = undefined;
    for (0..wires.len) |index| {
        try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
        try testing.expectEqual(@as(u64, @intCast(index + 1)), page[0].hlc);
        try testing.expect(idsEqual(wires[index].id, page[0].relay_id));
        var owned = try message_relay_v2.decode(testing.allocator, page[0].wire);
        defer owned.deinit(testing.allocator);
        switch (try guard.admitMessage(owned.msg)) {
            .accepted => |id| try testing.expect(idsEqual(page[0].relay_id, id)),
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(
            ConfirmationOutcome.confirmed,
            try log.confirmAuthenticatedDurableAck(page[0].relay_id, 99),
        );
    }
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(99, &page));
}

test "relay v2 event log rotates origin heads fairly and restores mid page" {
    const sign = @import("../../crypto/sign.zig");
    const config = Config{ .max_rows = 9, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp_a = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x61)));
    defer kp_a.deinit();
    var kp_b = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x62)));
    defer kp_b.deinit();
    var kp_c = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x63)));
    defer kp_c.deinit();
    const keys = [_]*const sign.KeyPair{ &kp_a, &kp_b, &kp_c };
    var wires: [3][3]TestWire = undefined;
    var initialized: [3]usize = @splat(0);
    defer for (&wires, 0..) |*origin_wires, origin| {
        for (origin_wires[0..initialized[origin]]) |*wire| wire.deinit(testing.allocator);
    };
    for (keys, 0..) |kp, origin| {
        for (0..3) |index| {
            wires[origin][index] = try makeTestWire(testing.allocator, kp, @intCast(index + 1), "origin-fairness");
            initialized[origin] += 1;
        }
    }

    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    var reverse_hlc: usize = 3;
    while (reverse_hlc != 0) {
        reverse_hlc -= 1;
        var reverse_origin: usize = keys.len;
        while (reverse_origin != 0) {
            reverse_origin -= 1;
            const wire = wires[reverse_origin][reverse_hlc];
            _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &required);
        }
    }

    var page: [2]PageItem = undefined;
    var next_hlc: [3]u64 = @splat(1);
    var first_round_origins: [3]bool = @splat(false);
    const first_count = try log.collectPageForNode(99, &page);
    try testing.expectEqual(@as(usize, 2), first_count);
    for (page[0..first_count]) |item| {
        var origin_index: ?usize = null;
        for (keys, 0..) |kp, index| if (originEqual(item.origin_pubkey, kp.public_key)) {
            origin_index = index;
            break;
        };
        const origin = origin_index orelse return error.TestUnexpectedResult;
        try testing.expectEqual(next_hlc[origin], item.hlc);
        next_hlc[origin] += 1;
        first_round_origins[origin] = true;
        _ = try log.confirmAuthenticatedDurableAck(item.relay_id, 99);
    }

    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    var emitted = first_count;
    while (emitted < 9) {
        const count = try restored.collectPageForNode(99, &page);
        try testing.expect(count != 0);
        for (page[0..count]) |item| {
            var origin_index: ?usize = null;
            for (keys, 0..) |kp, index| if (originEqual(item.origin_pubkey, kp.public_key)) {
                origin_index = index;
                break;
            };
            const origin = origin_index orelse return error.TestUnexpectedResult;
            try testing.expectEqual(next_hlc[origin], item.hlc);
            next_hlc[origin] += 1;
            if (emitted < 3) first_round_origins[origin] = true;
            _ = try restored.confirmAuthenticatedDurableAck(item.relay_id, 99);
            emitted += 1;
        }
        if (emitted >= 3)
            try testing.expect(first_round_origins[0] and first_round_origins[1] and first_round_origins[2]);
    }
    try testing.expectEqualSlices(u64, &.{ 4, 4, 4 }, &next_hlc);
    try testing.expectEqual(@as(usize, 0), try restored.collectPageForNode(99, &page));
}

test "relay v2 event log rejects a second identity at one origin HLC atomically" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x64)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 77, "first identity");
    defer first.deinit(testing.allocator);
    var equivocation = try makeTestWire(testing.allocator, &kp, 77, "second identity");
    defer equivocation.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 2 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(
        error.DuplicateEntry,
        log.reserveAccepted(equivocation.id, equivocation.bytes, 7, null, &required),
    );
    const after = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "relay v2 event log required membership gates safe retirement" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x46)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "partition");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &required);
    const before_ack = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before_ack);
    var aborted_ack = try log.prepareAuthenticatedDurableAck(wire.id, 8);
    aborted_ack.abort();
    aborted_ack.deinit();
    const after_aborted_ack = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_aborted_ack);
    try testing.expectEqualSlices(u8, before_ack, after_aborted_ack);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(wire.id, 8));
    try testing.expectEqual(@as(usize, 1), log.len());
    try testing.expectError(error.NodeNotRequired, log.confirmAuthenticatedDurableAck(wire.id, 10));
    try testing.expectEqual(ConfirmationOutcome.confirmed_and_retired, try log.confirmAuthenticatedDurableAck(wire.id, 9));
    try testing.expectEqual(@as(usize, 0), log.len());
}

test "relay v2 event log later membership is not retroactive and configured retirement is explicit" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x47)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "membership");
    defer wire.deinit(testing.allocator);
    var survivor = try makeTestWire(testing.allocator, &kp, 2, "survivor");
    defer survivor.deinit(testing.allocator);
    const original = [_]u64{ 7, 8, 9 };
    const later = [_]u64{ 7, 8, 9, 99 };
    const survivor_required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &original);
    _ = try log.reserveAccepted(survivor.id, survivor.bytes, 7, null, &survivor_required);
    try testing.expectEqual(ReserveOutcome.exact_duplicate, try log.reserveAccepted(wire.id, wire.bytes, 7, 99, &later));
    const wire_index = lowerBoundRows(log.rows.items, wire.id);
    try testing.expectEqualSlices(u64, &original, log.viewAt(wire_index).required_nodes);
    try testing.expectEqual(@as(usize, 0), log.viewAt(wire_index).excluded_once_nodes.len);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(wire.id, 8));
    var page: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(9, &page));

    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    var aborted = try log.prepareConfiguredNodeRetirement(9);
    aborted.abort();
    aborted.deinit();
    const after_abort = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);

    var retirement = try log.prepareConfiguredNodeRetirement(9);
    defer retirement.deinit();
    const result = retirement.commit();
    try testing.expectEqual(@as(usize, 1), result.rows_changed);
    try testing.expectEqual(@as(usize, 1), result.rows_retired);
    try testing.expect(result.cursor_removed);
    try testing.expectEqual(@as(usize, 1), log.len());
    try testing.expect(log.contains(survivor.id));
}

test "relay v2 event log strict checkpoint preserves required sets and rejects malformed state" {
    const sign = @import("../../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x48)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.confirmAuthenticatedDurableAck(first.id, 9);
    var page: [1]PageItem = undefined;
    _ = try log.collectPageForNode(8, &page);
    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqualSlices(u64, &required, restored.viewAt(0).required_nodes);
    const exact = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(exact);
    try testing.expectEqualSlices(u8, checkpoint, exact);
    var mismatched_config = config;
    mismatched_config.max_rows += 1;
    try testing.expectError(error.ConfigMismatch, EventLog.decodeCheckpoint(testing.allocator, mismatched_config, checkpoint));

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try testing.expectError(error.ChecksumMismatch, EventLog.decodeCheckpoint(testing.allocator, config, corrupt));

    const version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(version);
    version[4] +%= 1;
    try testing.expectError(error.UnsupportedVersion, EventLog.decodeCheckpoint(testing.allocator, config, version));

    const legacy_v2 = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(legacy_v2);
    legacy_v2[4] = 2;
    try testing.expectError(error.UnsupportedVersion, EventLog.decodeCheckpoint(testing.allocator, config, legacy_v2));

    const unknown = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unknown);
    unknown[5] = 1;
    try testing.expectError(error.UnknownFlags, EventLog.decodeCheckpoint(testing.allocator, config, unknown));

    const trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, EventLog.decodeCheckpoint(testing.allocator, config, trailing));

    const mismatched_metadata = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(mismatched_metadata);
    const stored_origin_node = readU64(mismatched_metadata[checkpoint_header_len + row_origin_node_offset ..][0..8]);
    writeU64(
        mismatched_metadata[checkpoint_header_len + row_origin_node_offset ..][0..8],
        stored_origin_node +| 1,
    );
    checkpointChecksum(
        mismatched_metadata[0 .. mismatched_metadata.len - checksum_len],
        mismatched_metadata[mismatched_metadata.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(
        error.InvalidWire,
        EventLog.decodeCheckpoint(testing.allocator, config, mismatched_metadata),
    );

    const duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    const first_offset = checkpoint_header_len;
    const first_id: RelayId = duplicate[first_offset..][0..@sizeOf(RelayId)].*;
    const first_wire_len: usize = readU32(duplicate[first_offset + row_wire_len_offset ..][0..4]);
    const first_confirmed: usize = readU32(duplicate[first_offset + row_confirmed_count_offset ..][0..4]);
    const first_required: usize = readU32(duplicate[first_offset + row_required_count_offset ..][0..4]);
    const first_excluded: usize = readU32(duplicate[first_offset + row_excluded_count_offset ..][0..4]);
    const second_offset = first_offset + row_prefix_len + first_wire_len +
        (first_confirmed + first_required + first_excluded) * @sizeOf(u64);
    @memcpy(duplicate[second_offset..][0..@sizeOf(RelayId)], &first_id);
    checkpointChecksum(duplicate[0 .. duplicate.len - checksum_len], duplicate[duplicate.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.DuplicateEntry, EventLog.decodeCheckpoint(testing.allocator, config, duplicate));

    const bad_required = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_required);
    const required_offset = first_offset + row_prefix_len + first_wire_len;
    @memcpy(bad_required[required_offset + 8 ..][0..8], bad_required[required_offset..][0..8]);
    checkpointChecksum(bad_required[0 .. bad_required.len - checksum_len], bad_required[bad_required.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.DuplicateNode, EventLog.decodeCheckpoint(testing.allocator, config, bad_required));

    const bad_cursor = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_cursor);
    const cursor_offset = rowsEndInCheckpoint(bad_cursor);
    @memset(bad_cursor[cursor_offset + 8 ..][0..message_relay_v2.pubkey_len], 0);
    checkpointChecksum(bad_cursor[0 .. bad_cursor.len - checksum_len], bad_cursor[bad_cursor.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.CursorTargetMissing, EventLog.decodeCheckpoint(testing.allocator, config, bad_cursor));
}

test "relay v2 event log two peer cursors remain valid across retirement checkpoint" {
    const sign = @import("../../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x4b)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    var third = try makeTestWire(testing.allocator, &kp, 3, "third");
    defer third.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.reserveAccepted(third.id, third.bytes, 7, null, &required);

    var one: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(8, &one));
    const retired_id = one[0].relay_id;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(9, &one));
    try testing.expect(idsEqual(retired_id, one[0].relay_id));
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(retired_id, 8));
    try testing.expectEqual(ConfirmationOutcome.confirmed_and_retired, try log.confirmAuthenticatedDurableAck(retired_id, 9));
    try testing.expectEqual(@as(usize, 2), log.len());

    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(8, &one));
    try testing.expect(!idsEqual(retired_id, one[0].relay_id));
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(9, &one));
    try testing.expect(!idsEqual(retired_id, one[0].relay_id));
}

test "relay v2 event log preparation and decode are allocation-failure atomic" {
    const sign = @import("../../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x49)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "allocation sweep");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };

    const PrepareSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, signed_wire: TestWire, membership: []const u64) !void {
            var candidate = try EventLog.init(allocator, cfg);
            defer candidate.deinit();
            const before = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            var prepared = takeReady(candidate.prepareAccepted(signed_wire.id, signed_wire.bytes, 7, 8, membership) catch |err| {
                const after_failure = try candidate.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after_failure);
                try testing.expectEqualSlices(u8, before, after_failure);
                return err;
            }) catch return error.TestUnexpectedResult;
            prepared.abort();
            prepared.deinit();
            const after_abort = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(after_abort);
            try testing.expectEqualSlices(u8, before, after_abort);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, PrepareSweep.run, .{ config, wire, &required });

    var source = try EventLog.init(testing.allocator, config);
    defer source.deinit();
    _ = try source.reserveAccepted(wire.id, wire.bytes, 7, 8, &required);
    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try EventLog.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            try testing.expectEqual(@as(usize, 1), candidate.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ config, checkpoint });

    const CollectSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try EventLog.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            const before = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            var page: [1]PageItem = undefined;
            const count = candidate.collectPageForNode(9, &page) catch |err| {
                const after_failure = try candidate.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after_failure);
                try testing.expectEqualSlices(u8, before, after_failure);
                return err;
            };
            try testing.expectEqual(@as(usize, 1), count);
        }
    };
    // The source ingress excludes node 8, while node 9 is missing and therefore
    // forces the first durable fairness-cursor allocation.
    try testing.checkAllAllocationFailures(testing.allocator, CollectSweep.run, .{ config, checkpoint });
}

test "relay v2 event log empty trust roots cannot fall back to local-only membership" {
    const sign = @import("../../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x4a)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "single");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{7};
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 1 });
    defer log.deinit();
    try testing.expectError(error.InvalidMembership, log.reserveAccepted(wire.id, wire.bytes, 7, null, &required));
    try testing.expectEqual(@as(usize, 0), log.len());
}
