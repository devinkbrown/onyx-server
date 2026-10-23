// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Directory regression tests.

const std = @import("std");
const record_max = @import("records.zig").record_max;
const Config = @import("records.zig").Config;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const AccessInfo = @import("records.zig").AccessInfo;
const AkickInfo = @import("records.zig").AkickInfo;
const accessListsMatch = @import("test_support.zig").accessListsMatch;
const akickListsMatch = @import("test_support.zig").akickListsMatch;

test "DST GAP-A9 account verifiers and channel AKICK replicate and disagree fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const password = "correct horse battery staple";
    const fast = Config{ .pbkdf2_rounds = 1 };

    var home_store = try openTestStore(tmp, "gap-a9-home.wal");
    defer home_store.deinit();
    var peer_store = try openTestStore(tmp, "gap-a9-peer.wal");
    defer peer_store.deinit();
    var home = Services.initWithConfig(&home_store, null, fast);
    var peer = Services.initWithConfig(&peer_store, null, fast);
    var scratch: [record_max]u8 = undefined;

    _ = try home.registerAccount("alice", password, &scratch);
    _ = try home.registerAccount("bob", "another good passphrase", &scratch);
    _ = try home.registerChannel("#room", "alice", &scratch);
    _ = try home.channelAccess("#room", "alice", "bob", .grant, .op, &scratch);
    _ = try home.channelAkick("#room", "alice", "*!*@spam.example", .add, "spam", &scratch);
    try home_store.family(.props).put("scram:alice", "not-a-verifier");

    const synced = try home.reconcileDirectory(&peer);
    try std.testing.expect(synced.copied > 0);
    const again = try peer.reconcileDirectory(&home);
    try std.testing.expectEqual(@as(usize, 0), again.copied);

    const stored = peer_store.family(.accounts).get("alice") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, stored, password) == null);
    try std.testing.expect(std.mem.startsWith(u8, stored, "A2|alice|"));
    try std.testing.expect(peer_store.family(.props).get("scram:alice") == null);

    switch (try peer.identifyAccount("Alice", password)) {
        .identified => |acct| try std.testing.expectEqualStrings("alice", acct.name.asSlice()),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.AuthFailed, peer.identifyAccount("alice", "wrong password"));

    switch (try peer.channelInfo("#room")) {
        .channel_info => |info| try std.testing.expectEqualStrings("alice", info.founder.asSlice()),
        else => return error.TestUnexpectedResult,
    }
    var home_access: [8]AccessInfo = undefined;
    var peer_access: [8]AccessInfo = undefined;
    const home_list = try home.channelAccessList("#room", "alice", &home_access);
    const peer_list = try peer.channelAccessList("#room", "alice", &peer_access);
    try std.testing.expect(accessListsMatch(home_list, peer_list));
    try std.testing.expectEqual(@as(usize, 2), peer_list.len);

    var home_akick: [4]AkickInfo = undefined;
    var peer_akick: [4]AkickInfo = undefined;
    const home_kicks = try home.channelAkickList("#room", "alice", &home_akick);
    const peer_kicks = try peer.channelAkickList("#room", "alice", &peer_akick);
    try std.testing.expect(akickListsMatch(home_kicks, peer_kicks));
    try std.testing.expectEqual(@as(usize, 1), peer_kicks.len);

    var drifted_home = try openTestStore(tmp, "gap-a9-drift-home.wal");
    defer drifted_home.deinit();
    var drifted_peer = try openTestStore(tmp, "gap-a9-drift-peer.wal");
    defer drifted_peer.deinit();
    var left = Services.initWithConfig(&drifted_home, null, fast);
    var right = Services.initWithConfig(&drifted_peer, null, fast);
    _ = try left.registerAccount("carol", "left-side passphrase", &scratch);
    _ = try right.registerAccount("carol", "right-side passphrase", &scratch);
    const left_before = try std.testing.allocator.dupe(u8, drifted_home.family(.accounts).get("carol").?);
    defer std.testing.allocator.free(left_before);
    const right_before = try std.testing.allocator.dupe(u8, drifted_peer.family(.accounts).get("carol").?);
    defer std.testing.allocator.free(right_before);

    try std.testing.expectError(error.DirectoryDisagreement, left.reconcileDirectory(&right));
    try std.testing.expectEqualStrings(left_before, drifted_home.family(.accounts).get("carol").?);
    try std.testing.expectEqualStrings(right_before, drifted_peer.family(.accounts).get("carol").?);
    switch (try left.identifyAccount("carol", "left-side passphrase")) {
        .identified => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try right.identifyAccount("carol", "right-side passphrase")) {
        .identified => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.AuthFailed, right.identifyAccount("carol", "left-side passphrase"));
}
