// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const resolveHostFamilies = @import("resolution.zig").resolveHostFamilies;

test "resolveHostFamilies keeps literals off the resolver" {
    const v4 = try resolveHostFamilies("127.0.0.1", 1);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &v4.v4.?);
    try std.testing.expect(v4.v6 == null);
    const v6 = try resolveHostFamilies("::1", 1);
    try std.testing.expect(v6.v4 == null);
    try std.testing.expectEqual(@as(u8, 1), v6.v6.?[15]);
}
