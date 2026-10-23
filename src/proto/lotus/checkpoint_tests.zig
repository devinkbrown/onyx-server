// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! checkpoint tests.

const std = @import("std");
const types = @import("types.zig");
const checkpoint = @import("checkpoint_wire.zig");
const history = @import("store.zig");
const support = @import("test_support.zig");

test "checkpoint round trip is canonical exact and independently owned" {
    const Store = history.Lotus(.{
        .max_targets = 3,
        .max_per_target = 4,
        .max_text = 64,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 32,
        .max_command = 16,
        .max_client_tags = 128,
    });
    var first = Store.init(std.testing.allocator);
    defer first.deinit();
    var reordered = Store.init(std.testing.allocator);
    defer reordered.deinit();

    _ = try first.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "bee", .timestamp = 4, .command = "NOTICE" });
    _ = try first.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try first.append("#a", .{
        .msgid = "a2",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/react=ok",
    });
    _ = try first.append("#a", .{ .msgid = "a3", .sender = "services", .text = "new topic", .timestamp = 3, .command = "TOPIC" });
    _ = try first.append("#b", .{ .msgid = "b2", .sender = "bob", .text = "", .timestamp = 5, .command = "TAGMSG", .client_tags = "" });
    try first.redact("#a", "a2");
    try first.edit("#a", "a3", "edited topic");

    _ = try reordered.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try reordered.append("#a", .{
        .msgid = "a2",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active;+draft/react=ok",
    });
    _ = try reordered.append("#a", .{ .msgid = "a3", .sender = "services", .text = "edited topic", .timestamp = 3, .command = "TOPIC" });
    try reordered.redact("#a", "a2");
    _ = try reordered.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "bee", .timestamp = 4, .command = "NOTICE" });
    _ = try reordered.append("#b", .{ .msgid = "b2", .sender = "bob", .text = "", .timestamp = 5, .command = "TAGMSG", .client_tags = "" });

    const first_wire = try first.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(first_wire);
    const reordered_wire = try reordered.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reordered_wire);
    try std.testing.expectEqualSlices(u8, first_wire, reordered_wire);

    const checkpoint_copy = try std.testing.allocator.dupe(u8, first_wire);
    var restored = Store.decodeCheckpoint(std.testing.allocator, checkpoint_copy) catch |err| {
        std.testing.allocator.free(checkpoint_copy);
        return err;
    };
    @memset(checkpoint_copy, 0xa5);
    std.testing.allocator.free(checkpoint_copy);
    defer restored.deinit();
    const restored_wire = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(restored_wire);
    try std.testing.expectEqualSlices(u8, first_wire, restored_wire);
    const source_root = first.root();
    const restored_root = restored.root();
    try std.testing.expectEqualSlices(u8, &source_root, &restored_root);
    try std.testing.expectEqual(@as(usize, 2), restored.targetCount());
    try std.testing.expectEqual(@as(usize, 5), restored.totalStoredCount());
    try std.testing.expectEqual(@as(usize, 1), restored.tombstoneCount());

    var iterator = restored.deterministicIterator();
    const expected_targets = [_][]const u8{ "#a", "#a", "#a", "#b", "#b" };
    const expected_ids = [_][]const u8{ "a1", "a2", "a3", "b1", "b2" };
    const expected_commands = [_][]const u8{ "PRIVMSG", "TAGMSG", "TOPIC", "NOTICE", "TAGMSG" };
    for (expected_targets, expected_ids, expected_commands, 0..) |target, id, command, index| {
        const entry = iterator.next() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(target, entry.target);
        try std.testing.expectEqualStrings(id, entry.message.msgid);
        try std.testing.expectEqualStrings(command, entry.message.command);
        try std.testing.expectEqual(index == 1, entry.message.tombstone);
        if (index == 1)
            try std.testing.expectEqualStrings("+typing=active;+draft/react=ok", entry.message.client_tags.?);
        if (index == 4) {
            try std.testing.expect(entry.message.client_tags != null);
            try std.testing.expectEqual(@as(usize, 0), entry.message.client_tags.?.len);
        }
    }
    try std.testing.expect(iterator.next() == null);
}

test "checkpoint restores an older smaller text ceiling into a larger Lotus" {
    const Older = history.Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 512,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });
    const Current = history.Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 4096,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });
    const Smaller = history.Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 256,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 128,
    });

    var older = Older.init(std.testing.allocator);
    defer older.deinit();
    var ciphertext: [512]u8 = @splat('x');
    _ = try older.append("#secure", .{
        .msgid = "cipher",
        .sender = "alice",
        .text = &ciphertext,
        .timestamp = 1,
        .command = "PRIVMSG",
    });
    _ = try older.append("#secure", .{
        .msgid = "typing",
        .sender = "alice",
        .text = "",
        .timestamp = 2,
        .command = "TAGMSG",
        .client_tags = "+typing=active",
    });
    try older.redact("#secure", "typing");

    const wire = try older.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try Current.decodeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();

    var iterator = restored.deterministicIterator();
    const first = iterator.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("#secure", first.target);
    try std.testing.expectEqualStrings("cipher", first.message.msgid);
    try std.testing.expectEqualSlices(u8, &ciphertext, first.message.text);
    try std.testing.expect(!first.message.tombstone);
    const second = iterator.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("typing", second.message.msgid);
    try std.testing.expect(second.message.tombstone);
    try std.testing.expectEqualStrings("+typing=active", second.message.client_tags.?);
    try std.testing.expect(iterator.next() == null);

    try std.testing.expectError(error.ConfigMismatch, Smaller.decodeCheckpoint(std.testing.allocator, wire));

    const zero_text_limit = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(zero_text_limit);
    checkpoint.writeU32(zero_text_limit[16..20], 0);
    support.rewriteCheckpointChecksum(zero_text_limit);
    try std.testing.expectError(error.ConfigMismatch, Current.decodeCheckpoint(std.testing.allocator, zero_text_limit));

    var current = Current.init(std.testing.allocator);
    defer current.deinit();
    var large_ciphertext: [4096]u8 = @splat('z');
    _ = try current.append("#secure", .{
        .msgid = "large",
        .sender = "alice",
        .text = &large_ciphertext,
        .timestamp = 3,
    });
    const inconsistent_wire = try current.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(inconsistent_wire);
    checkpoint.writeU32(inconsistent_wire[16..20], 512);
    support.rewriteCheckpointChecksum(inconsistent_wire);
    try std.testing.expectError(error.CapacityExceeded, Current.decodeCheckpoint(std.testing.allocator, inconsistent_wire));
}

test "checkpoint decoder rejects truncation corruption bounds and trailing bytes" {
    const Store = history.Lotus(.{
        .max_targets = 2,
        .max_per_target = 2,
        .max_text = 32,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 16,
        .max_command = 8,
        .max_client_tags = 32,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{
        .msgid = "a1",
        .sender = "alice",
        .text = "one",
        .timestamp = 1,
        .command = "TAGMSG",
        .client_tags = "+x=1",
    });
    _ = try source.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "two", .timestamp = 2 });
    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);

    for (0..wire.len) |len| {
        if (Store.decodeCheckpoint(std.testing.allocator, wire[0..len])) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0xa5;
    try std.testing.expectError(error.TrailingBytes, Store.decodeCheckpoint(std.testing.allocator, trailing));

    const bad_magic = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 0xff;
    try std.testing.expectError(error.BadMagic, Store.decodeCheckpoint(std.testing.allocator, bad_magic));

    const bad_version = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    support.rewriteCheckpointChecksum(bad_version);
    try std.testing.expectError(error.UnsupportedVersion, Store.decodeCheckpoint(std.testing.allocator, bad_version));

    const bad_checksum = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_checksum);
    bad_checksum[wire.len - checkpoint.checkpoint_checksum_len - 1] ^= 0x80;
    try std.testing.expectError(error.ChecksumMismatch, Store.decodeCheckpoint(std.testing.allocator, bad_checksum));

    const first_entry = support.firstCheckpointEntryOffset(wire);
    const bad_flags = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_flags);
    bad_flags[first_entry] = 0x80;
    support.rewriteCheckpointChecksum(bad_flags);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, bad_flags));

    const missing_tag_flag = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(missing_tag_flag);
    missing_tag_flag[first_entry] &= ~checkpoint.checkpoint_flag_has_tags;
    support.rewriteCheckpointChecksum(missing_tag_flag);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, missing_tag_flag));

    const bad_hash = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_hash);
    bad_hash[first_entry + 1 + 8] ^= 1;
    support.rewriteCheckpointChecksum(bad_hash);
    try std.testing.expectError(error.InvalidHash, Store.decodeCheckpoint(std.testing.allocator, bad_hash));

    const zero_target = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(zero_target);
    checkpoint.writeU32(zero_target[checkpoint.checkpoint_header_len..][0..4], 0);
    support.rewriteCheckpointChecksum(zero_target);
    try std.testing.expectError(error.CapacityExceeded, Store.decodeCheckpoint(std.testing.allocator, zero_target));

    const excess_entries = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(excess_entries);
    checkpoint.writeU32(excess_entries[checkpoint.checkpoint_header_len + 4 ..][0..4], 3);
    support.rewriteCheckpointChecksum(excess_entries);
    try std.testing.expectError(error.CapacityExceeded, Store.decodeCheckpoint(std.testing.allocator, excess_entries));

    const wrong_total = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(wrong_total);
    checkpoint.writeU32(wrong_total[44..48], 1);
    support.rewriteCheckpointChecksum(wrong_total);
    try std.testing.expectError(error.InvalidField, Store.decodeCheckpoint(std.testing.allocator, wrong_total));

    const noncanonical = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(noncanonical);
    const second_target = support.nextCheckpointTargetOffset(noncanonical, checkpoint.checkpoint_header_len);
    try std.testing.expectEqual(@as(u32, 2), checkpoint.readU32(noncanonical[second_target..][0..4]));
    @memcpy(noncanonical[second_target + checkpoint.checkpoint_target_prefix_len ..][0..2], "#a");
    support.rewriteCheckpointChecksum(noncanonical);
    try std.testing.expectError(error.NonCanonicalOrder, Store.decodeCheckpoint(std.testing.allocator, noncanonical));

    const authenticated_trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(authenticated_trailing);
    const old_prefix_len = wire.len - checkpoint.checkpoint_checksum_len;
    @memcpy(authenticated_trailing[0..old_prefix_len], wire[0..old_prefix_len]);
    authenticated_trailing[old_prefix_len] = 0x5a;
    checkpoint.writeU32(authenticated_trailing[48..52], checkpoint.readU32(wire[48..52]) + 1);
    support.rewriteCheckpointChecksum(authenticated_trailing);
    try std.testing.expectError(error.TrailingBytes, Store.decodeCheckpoint(std.testing.allocator, authenticated_trailing));

    const Other = history.Lotus(.{
        .max_targets = 3,
        .max_per_target = 2,
        .max_text = 32,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 16,
        .max_command = 8,
        .max_client_tags = 32,
    });
    try std.testing.expectError(error.ConfigMismatch, Other.decodeCheckpoint(std.testing.allocator, wire));
}

test "checkpoint replacement is atomic across every allocation failure" {
    const Store = history.Lotus(.{
        .max_targets = 3,
        .max_per_target = 3,
        .max_text = 32,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 64,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{ .msgid = "a1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try source.append("#a", .{ .msgid = "a2", .sender = "alice", .text = "", .timestamp = 2, .command = "TAGMSG", .client_tags = "+x=1" });
    _ = try source.append("#b", .{ .msgid = "b1", .sender = "bob", .text = "two", .timestamp = 3, .command = "NOTICE" });

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, state: *const Store) !void {
            const bytes = try state.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expect(bytes.len > checkpoint.checkpoint_header_len + checkpoint.checkpoint_checksum_len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});

    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try Store.decodeCheckpoint(allocator, bytes);
            defer decoded.deinit();
            try std.testing.expectEqual(@as(usize, 3), decoded.totalStoredCount());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, DecodeSweep.run, .{wire});

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var target = Store.init(allocator);
            defer target.deinit();
            _ = try target.append("#old", .{ .msgid = "old", .sender = "sentinel", .text = "keep", .timestamp = 99 });
            const before = target.root();
            target.replaceFromCheckpoint(bytes) catch |err| {
                const after = target.root();
                try std.testing.expectEqualSlices(u8, &before, &after);
                try std.testing.expectEqual(@as(usize, 1), target.totalStoredCount());
                return err;
            };
            try std.testing.expectEqual(@as(usize, 3), target.totalStoredCount());
            try std.testing.expectEqual(@as(usize, 2), target.targetCount());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ReplaceSweep.run, .{wire});

    var target = Store.init(std.testing.allocator);
    defer target.deinit();
    _ = try target.append("#old", .{ .msgid = "old", .sender = "sentinel", .text = "keep", .timestamp = 99 });
    const before = target.root();
    const corrupt = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(corrupt);
    corrupt[0] ^= 1;
    try std.testing.expectError(error.BadMagic, target.replaceFromCheckpoint(corrupt));
    const after = target.root();
    try std.testing.expectEqualSlices(u8, &before, &after);
}

test "checkpoint preserves wrapped ring chronology exactly" {
    const Store = history.Lotus(.{
        .max_targets = 1,
        .max_per_target = 3,
        .max_text = 16,
        .max_target = 8,
        .max_msgid = 8,
        .max_sender = 8,
        .max_command = 8,
        .max_client_tags = 8,
    });
    var source = Store.init(std.testing.allocator);
    defer source.deinit();
    _ = try source.append("#a", .{ .msgid = "m1", .sender = "alice", .text = "one", .timestamp = 1 });
    _ = try source.append("#a", .{ .msgid = "m2", .sender = "alice", .text = "two", .timestamp = 2 });
    _ = try source.append("#a", .{ .msgid = "m3", .sender = "alice", .text = "three", .timestamp = 3 });
    _ = try source.append("#a", .{ .msgid = "m4", .sender = "alice", .text = "", .timestamp = 4, .command = "TAGMSG", .client_tags = "" });
    _ = try source.append("#a", .{ .msgid = "m5", .sender = "alice", .text = "five", .timestamp = 5, .command = "NOTICE" });
    try source.redact("#a", "m3");

    const wire = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    var restored = try Store.decodeCheckpoint(std.testing.allocator, wire);
    defer restored.deinit();
    const reencoded = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);

    var iterator = restored.deterministicIterator();
    const expected_ids = [_][]const u8{ "m3", "m4", "m5" };
    for (expected_ids, 0..) |expected_id, index| {
        const entry = iterator.next() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("#a", entry.target);
        try std.testing.expectEqualStrings(expected_id, entry.message.msgid);
        try std.testing.expectEqual(index == 0, entry.message.tombstone);
    }
    try std.testing.expect(iterator.next() == null);
}

test "checkpoint and append bounds fail closed" {
    const Store = history.Lotus(.{
        .max_targets = 1,
        .max_per_target = 1,
        .max_text = 3,
        .max_target = 3,
        .max_msgid = 2,
        .max_sender = 3,
        .max_command = 8,
        .max_client_tags = 4,
        .max_checkpoint_bytes = 128,
    });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.TargetTooLong, store.append("#abc", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.MsgidTooLong, store.append("#a", .{ .msgid = "mid", .sender = "a", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.SenderTooLong, store.append("#a", .{ .msgid = "m", .sender = "long", .text = "x", .timestamp = 1 }));
    try std.testing.expectError(error.TextTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "long", .timestamp = 1 }));
    try std.testing.expectError(error.CommandTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1, .command = "LONG-CMD-X" }));
    try std.testing.expectError(error.ClientTagsTooLong, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "x", .timestamp = 1, .client_tags = "+x=12" }));
    try std.testing.expectError(error.CheckpointCapacityExceeded, store.append("#a", .{ .msgid = "m", .sender = "a", .text = "xxx", .timestamp = 1 }));
    try std.testing.expectEqual(@as(usize, 0), store.totalStoredCount());
    const empty_wire = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(empty_wire);
    try std.testing.expect(empty_wire.len <= 128);
}

test "aggregate checkpoint retention evicts the deterministic global oldest entry" {
    // This deliberately uses 256 rows and the production 4096-byte text
    // ceiling. The smaller test budget reaches the aggregate boundary without
    // allocating a 64 MiB fixture; the same incremental accounting is used by
    // the production 64 MiB Lotus instantiation.
    const Store = history.Lotus(.{
        .max_targets = 512,
        .max_per_target = 256,
        .max_text = 4096,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 16,
        .max_checkpoint_bytes = 1_070_000,
    });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    const payload: [4096]u8 = @splat('x');
    var msgid_buf: [16]u8 = undefined;

    for (0..256) |index| {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "a-{d}", .{index});
        _ = try store.append("#a", .{ .msgid = msgid, .sender = "a", .text = &payload, .timestamp = index });
    }
    try std.testing.expectEqual(@as(usize, 256), try store.storedCount("#a"));

    const appended = try store.append("#b", .{ .msgid = "b-0", .sender = "b", .text = &payload, .timestamp = 256 });
    try std.testing.expect(appended.evicted);
    try std.testing.expectEqual(@as(usize, 255), try store.storedCount("#a"));
    try std.testing.expectEqual(@as(usize, 1), try store.storedCount("#b"));
    var oldest = store.deterministicIterator();
    const first = oldest.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("#a", first.target);
    try std.testing.expectEqualStrings("a-1", first.message.msgid);

    // Exercise aggregate pressure on an existing target. The stale row lives
    // elsewhere, so target-local eviction would incorrectly discard newer #a.
    _ = try store.append("#c", .{ .msgid = "c-old", .sender = "c", .text = &payload, .timestamp = 0 });
    try std.testing.expectEqual(@as(usize, 1), try store.storedCount("#c"));
    _ = try store.append("#a", .{ .msgid = "a-new", .sender = "a", .text = &payload, .timestamp = 999 });
    try std.testing.expectEqual(@as(usize, 0), try store.storedCount("#c"));
    var newest_a_buf: [1]types.Message = undefined;
    const newest_a = try store.latest("#a", 1, &newest_a_buf);
    try std.testing.expectEqualStrings("a-new", newest_a[0].msgid);

    try std.testing.expectEqual(
        types.ExactOnceResult.exact_duplicate,
        try store.ingestExactOnce("#b", .{ .msgid = "b-0", .sender = "b", .text = &payload, .timestamp = 256 }),
    );
    try std.testing.expectEqual(
        types.ExactOnceResult.equivocation,
        try store.ingestExactOnce("#b", .{ .msgid = "b-0", .sender = "b", .text = "different", .timestamp = 256 }),
    );

    const wire = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(wire);
    try std.testing.expect(wire.len <= 1_070_000);
}

test "forget drops the row and the checkpoint still round-trips" {
    const Store = history.Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 32,
        .max_target = 16,
        .max_msgid = 8,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 32,
    });
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try support.appendForTest(&store, "#a", "m1", 10, "one");
    try support.appendForTest(&store, "#a", "m2", 20, "two");
    try support.appendForTest(&store, "#b", "m3", 15, "cipher");
    const expired = store.oldestNotAfter("#a", 10) orelse return error.NotFound;
    try std.testing.expectEqualStrings("m1", expired.msgid);
    try store.forget("#a", "m1");
    try std.testing.expectError(error.NotFound, store.forget("#a", "m1"));
    try std.testing.expectEqual(@as(usize, 1), try store.storedCount("#a"));
    try store.forget("#b", "m3");
    try std.testing.expectEqual(@as(usize, 0), try store.storedCount("#b"));
    try std.testing.expectEqual(@as(usize, 1), store.targetCount());
    const bytes = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var restored = try Store.decodeCheckpoint(std.testing.allocator, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), try restored.storedCount("#a"));
    try std.testing.expectEqual(@as(usize, 0), try restored.storedCount("#b"));
    var out: [4]types.Message = undefined;
    const left = try restored.latest("#a", 4, &out);
    try std.testing.expectEqualStrings("m2", left[0].msgid);
}
