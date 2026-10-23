// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: basic.

const std = @import("std");
const toml = @import("../../proto/toml.zig");
const Config = @import("contracts.zig").Config;
const Family = @import("contracts.zig").Family;
const MutationKind = @import("contracts.zig").MutationKind;
const StoreError = @import("contracts.zig").StoreError;
const default_changefeed_capacity = @import("contracts.zig").default_changefeed_capacity;
const default_max_record_len = @import("contracts.zig").default_max_record_len;
const default_max_wal_len = @import("contracts.zig").default_max_wal_len;
const record_header_len = @import("contracts.zig").record_header_len;
const OroStore = @import("engine.zig").OroStore;
const openTestStore = @import("tests_support.zig").openTestStore;
const writeRecordAt = @import("wal.zig").writeRecordAt;
const writeU32 = @import("wal.zig").writeU32;

test "put/get round-trip per family" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "roundtrip.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "account:alice");
    try store.family(.nicks).put("Alice", "alice");
    try store.family(.chanregs).put("#zig", "founder=alice");
    try store.family(.bans).put("kline:test", "bad.host");
    try store.family(.memos).put("memo:1", "hello");
    try store.family(.vhosts).put("alice", "staff.example");
    try store.family(.props).put("#zig:title", "Zig");
    try store.family(.history).put("#zig:1", "message");

    try std.testing.expectEqualStrings("account:alice", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
    try std.testing.expectEqualStrings("founder=alice", store.family(.chanregs).get("#zig").?);
    try std.testing.expectEqualStrings("bad.host", store.family(.bans).get("kline:test").?);
    try std.testing.expectEqualStrings("hello", store.family(.memos).get("memo:1").?);
    try std.testing.expectEqualStrings("staff.example", store.family(.vhosts).get("alice").?);
    try std.testing.expectEqualStrings("Zig", store.family(.props).get("#zig:title").?);
    try std.testing.expectEqualStrings("message", store.family(.history).get("#zig:1").?);
}

test "WAL replay reconstructs state after reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.accounts).put("alice", "v2");
        try store.family(.history).put("#z:1", "hi");
    }
    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("hi", store.family(.history).get("#z:1").?);
    }
}

test "checksum mismatch is detected and rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "bad.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
        try store.family(.accounts).put("bob", "still-ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "bad.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    var corrupted: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.readPositionalAll(std.testing.io, &corrupted, 6));
    corrupted[0] ^= 0xFF;
    try file.writePositionalAll(std.testing.io, &corrupted, 6);
    try file.sync(std.testing.io);

    try std.testing.expectError(StoreError.ChecksumMismatch, openTestStore(tmp, "bad.wal"));
}

test "torn final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "torn.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "torn.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{ 1, 0, 0, 0 }, stat.size);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "torn.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
}

test "checksum-bad final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "final-checksum.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "final-checksum.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    _ = try writeRecordAt(std.testing.io, file, stat.size, std.testing.allocator, .put, .accounts, "bob", "bad", default_max_record_len);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, stat.size + 6);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "final-checksum.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expect(store.family(.accounts).get("bob") == null);
}

test "torn WAL tail is truncated at open so a later append cannot poison the log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "poison.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append: a garbage torn tail lands after the valid prefix.
    {
        var file = try tmp.dir.openFile(std.testing.io, "poison.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        try file.writePositionalAll(std.testing.io, &.{ 9, 0, 0, 0, 0xDE, 0xAD }, stat.size);
        try file.sync(std.testing.io);
    }

    // First reopen tolerates the tail — and must TRUNCATE it before serving,
    // otherwise the append below lands after the garbage and the SECOND
    // reopen fails outright (the bad bytes are then no longer the final
    // record, so the tail tolerance no longer applies). This exact sequence
    // used to brick the live SASL account store after a power loss.
    {
        var store = try openTestStore(tmp, "poison.wal");
        defer store.deinit();
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "poison.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "zero-filled final WAL tail is truncated at open (in-flight torn tail)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "zerotail.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append leaves a short run of zero bytes (a partial header +
    // partial payload) after the valid prefix. A zero header decodes to a
    // 0-length record whose empty-payload checksum (0x811c9dc5) never matches
    // the zero sum, and record_end lands BEFORE EOF because trailing zeros
    // remain — the exact asymmetry that used to hard-fail replay.
    {
        var file = try tmp.dir.openFile(std.testing.io, "zerotail.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        const zeros = std.mem.zeroes([12]u8);
        try file.writePositionalAll(std.testing.io, &zeros, stat.size);
        try file.sync(std.testing.io);
    }

    // First reopen tolerates AND truncates the torn tail; a later append must
    // land on the valid prefix, so the second reopen sees both records (an
    // untruncated log would refuse to open on the second pass).
    {
        var store = try openTestStore(tmp, "zerotail.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "zerotail.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "oversize final WAL header is truncated at open (in-flight torn tail)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "oversize.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    // Crash mid-append leaves a header whose declared length overruns the file
    // (here max_record_bytes+1) with no payload behind it.
    {
        var file = try tmp.dir.openFile(std.testing.io, "oversize.wal", .{ .mode = .read_write, .allow_directory = false });
        defer file.close(std.testing.io);
        const stat = try file.stat(std.testing.io);
        var header: [record_header_len]u8 = undefined;
        writeU32(header[0..4], default_max_record_len + 1);
        writeU32(header[4..8], 0);
        try file.writePositionalAll(std.testing.io, &header, stat.size);
        try file.sync(std.testing.io);
    }

    {
        var store = try openTestStore(tmp, "oversize.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
        try store.family(.accounts).put("bob", "also-ok");
    }

    var store = try openTestStore(tmp, "oversize.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("also-ok", store.family(.accounts).get("bob").?);
}

test "WAL compacts into the snapshot once it crosses half the replay limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Tiny WAL budget so a few puts cross the max_wal_bytes/2 threshold.
    {
        var store = try OroStore.openWithConfig(
            std.testing.allocator,
            std.testing.io,
            tmp.dir,
            "compact.wal",
            .{ .max_wal_bytes = 256 },
        );
        defer store.deinit();
        var i: u8 = 0;
        while (i < 8) : (i += 1) {
            var key: [4]u8 = .{ 'k', '0' + i, 0, 0 };
            try store.family(.accounts).put(key[0..2], "value-payload");
        }
        // The log must have been folded into the snapshot at least once —
        // an uncompacted WAL here would exceed the whole 256-byte budget and
        // the NEXT open would refuse to replay it (RecordTooLarge).
        try std.testing.expect(store.wal_offset < 256);
    }

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "compact.wal",
        .{ .max_wal_bytes = 256 },
    );
    defer store.deinit();
    var i: u8 = 0;
    while (i < 8) : (i += 1) {
        var key: [4]u8 = .{ 'k', '0' + i, 0, 0 };
        try std.testing.expectEqualStrings("value-payload", store.family(.accounts).get(key[0..2]).?);
    }
}

test "snapshot+truncate preserves data" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.nicks).put("Alice", "alice");
        try store.snapshotAndTruncate();
        try store.family(.accounts).put("bob", "v2");
    }
    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("bob").?);
    }
}

test "changefeed sequence persists across snapshot reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.snapshotAndTruncate();
    }
    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("bob", "v2");
        const mutation = store.changeAt(0).?;
        try std.testing.expectEqual(@as(u64, 2), mutation.seq);
        try std.testing.expectEqualStrings("bob", mutation.key);
    }
}

test "changefeed records mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "changes.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "v1");
    try store.family(.accounts).put("bob", "v2");
    try store.family(.accounts).delete("alice");

    try std.testing.expectEqual(@as(usize, 3), store.changeCount());
    const first = store.changeAt(0).?;
    try std.testing.expectEqual(@as(u64, 1), first.seq);
    try std.testing.expectEqual(Family.accounts, first.family);
    try std.testing.expectEqual(MutationKind.put, first.kind);
    try std.testing.expectEqualStrings("alice", first.key);
    try std.testing.expectEqualStrings("v1", first.value.?);

    const last = store.changeAt(2).?;
    try std.testing.expectEqual(@as(u64, 3), last.seq);
    try std.testing.expectEqual(MutationKind.delete, last.kind);
    try std.testing.expectEqualStrings("alice", last.key);
    try std.testing.expect(last.value == null);
    try std.testing.expect(store.family(.accounts).get("alice") == null);
}

test "storage Config defaults preserve historical limits" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "storage Config.applyToml overlays [storage] keys" {
    var doc = try toml.parse(
        std.testing.allocator,
        "[storage]\nmax_record_bytes = 65536\nmax_wal_bytes = 1048576\nchangefeed_capacity = 128\n",
    );
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 65536), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, 1048576), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, 128), cfg.changefeed_capacity);
}

test "storage Config.applyToml leaves defaults when section absent" {
    var doc = try toml.parse(std.testing.allocator, "[other]\nx = 1\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "opened store exposes authoritative default admission limits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "admission-defaults.wal");
    defer store.deinit();
    const limits = store.admissionLimits();
    try std.testing.expectEqual(@as(usize, default_max_record_len), limits.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), limits.max_wal_bytes);
}

test "opened store exposes exact custom admission limits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "admission-custom.wal",
        .{
            .max_record_bytes = 128,
            .max_wal_bytes = 1024,
            .changefeed_capacity = 7,
        },
    );
    defer store.deinit();
    const limits = store.admissionLimits();
    try std.testing.expectEqual(@as(usize, 128), limits.max_record_bytes);
    try std.testing.expectEqual(@as(usize, 1024), limits.max_wal_bytes);
}

test "openWithConfig honours a smaller record limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "cfg-limit.wal",
        .{ .max_record_bytes = 16 },
    );
    defer store.deinit();

    try std.testing.expectError(
        StoreError.RecordTooLarge,
        store.family(.accounts).put("alice", "this value is definitely longer than sixteen bytes"),
    );
}
