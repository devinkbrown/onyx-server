// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only owner fixture shared with ManagedBridge.TestFixture.

const std = @import("std");
const StoreResourceOwner = @import("source_owner.zig").StoreResourceOwner;
const ownerBacking = @import("source_owner.zig").ownerBacking;

pub fn seedOwnerForCensus(owner: *StoreResourceOwner) !void {
    // Source-private seed precedes every external lease. No mutation wrapper is
    // exported; S2/S3 must reserve real revisions for future source mutations.
    const s = &ownerBacking(owner).store;
    for (0..6) |i| {
        var key: [8]u8 = undefined;
        try s.put(.props, try std.fmt.bufPrint(&key, "p{d}", .{i}), "value");
    }
    try s.put(.accounts, "account", "old");
    try s.put(.history, "gone", "history");
    try s.put(.nicks, "temporary", "");
    try s.delete(.nicks, "temporary");
    var batch = try s.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = "growth", .value = "new" },
        .{ .family = .accounts, .kind = .put, .key = "account", .value = "replacement" },
        .{ .family = .history, .kind = .delete, .key = "gone" },
        .{ .family = .bans, .kind = .delete, .key = "absent" },
    });
    defer batch.abort();
    try batch.commit();
}
