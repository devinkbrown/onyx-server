// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ops.upgrade module — UPGRADE operator command (Helix hot in-place upgrade).
//!
//! Thin dispatch wrapper: the real work lives in `LinuxServer.handleUpgrade`.
//! Windows may select a staged absolute executable path; the native candidate
//! must pass the same capability and authenticated state checks as the default.
const std = @import("std");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");

const Core = module_core.Core;

fn upgrade(ctx: *anyopaque, invocation: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleUpgradeCommand(core.conn, invocation.params);
}

pub const module = registry.Module{
    .id = "ops.upgrade",
    .category = .core,
    .commands = &.{
        .{ .name = "UPGRADE", .access = .oper, .handler = upgrade },
    },
};

test "upgrade module declares UPGRADE" {
    var saw = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "UPGRADE")) {
            saw = true;
            try std.testing.expectEqual(registry.Access.oper, c.access);
        }
    }
    try std.testing.expect(saw);
}
