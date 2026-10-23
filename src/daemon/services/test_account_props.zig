// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account props regression tests.

const std = @import("std");
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const RecognizeAdd = @import("contracts.zig").RecognizeAdd;

test "recognize masks: add/match/list/delete and persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "*!*@*.example.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "kain!*@host"));
        // case-insensitive account + mask dedupe
        try std.testing.expectEqual(Services.RecognizeAdd.already_present, try services.recognizeAdd("KAIN", "*!*@*.EXAMPLE.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.invalid_mask, try services.recognizeAdd("kain", ""));

        try std.testing.expect(services.recognizeMatches("kain", "kain!user@gw.example.net"));
        try std.testing.expect(!services.recognizeMatches("kain", "kain!user@other.org"));
        try std.testing.expect(!services.recognizeMatches("nobody", "kain!user@gw.example.net"));

        try std.testing.expect(try services.recognizeDel("kain", "kain!*@host"));
        try std.testing.expect(!try services.recognizeDel("kain", "kain!*@host"));
    }
    {
        // reopen: the remaining mask survived durably; the deleted one did not.
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(services.recognizeMatches("kain", "anyone!x@host.example.net"));
        var lb: [512]u8 = undefined;
        const blob = services.recognizeBlob("kain", &lb);
        try std.testing.expect(std.mem.indexOf(u8, blob, "*!*@*.example.net") != null);
        try std.testing.expect(std.mem.indexOf(u8, blob, "kain!*@host") == null);
    }
}

test "account metadata: put/delete persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.metadataPut("kain", "avatar", "https://x/a.png", "*");
        try services.metadataPut("kain", "display-name", "Kain", "*");
        try services.metadataDelete("kain", "avatar"); // remove one
    }
    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        var count: usize = 0;
        var ok_display = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.metadataForEach("KAIN", Ctx{ .count = &count, .ok = &ok_display }, struct {
            fn cb(c: Ctx, key: []const u8, value: []const u8, vis: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, key, "display-name") and std.mem.eql(u8, value, "Kain") and std.mem.eql(u8, vis, "*")) c.ok.* = true;
            }
        }.cb);
        // avatar was deleted; only display-name survives, with value + visibility intact.
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expect(ok_display);
    }
}

test "account silence: add/remove persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.silencePersistAdd("kain", "*!*@spam.example");
        try services.silencePersistAdd("kain", "troll!*@*");
        try services.silencePersistAdd("KAIN", "*!*@SPAM.example"); // case-insensitive dup: no-op
        try services.silencePersistDel("kain", "troll!*@*");
    }
    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var count: usize = 0;
        var ok = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.silenceForEach("kain", Ctx{ .count = &count, .ok = &ok }, struct {
            fn cb(c: Ctx, mask: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, mask, "*!*@spam.example")) c.ok.* = true;
            }
        }.cb);
        try std.testing.expectEqual(@as(usize, 1), count); // troll removed; one survives
        try std.testing.expect(ok);
    }
}
