// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! query.info module — stateless server-information query commands.
//!
//! First module migrated onto the SerpentRegistry live dispatch spine. Each
//! handler is a thin thunk that recovers the typed `Core` and delegates to the
//! existing `LinuxServer` handler body (behavior preserved exactly; only the
//! routing moved off the if-chain). See `docs/planning/17-module-system.md` §6.
const std = @import("std");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");

const Core = module_core.Core;

fn version(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleVersion(core.conn);
}

fn time(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleTime(core.conn);
}

fn admin(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleAdmin(core.conn);
}

fn info(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleInfo(core.conn);
}

fn directory(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleDirectory(core.conn);
}

fn motd(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleMotd(core.conn);
}

fn lusers(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleLusers(core.conn);
}

fn users(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleUsers(core.conn);
}

fn links(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleLinks(core.conn);
}

fn map(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleMap(core.conn);
}

fn chanstats(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleChanstats(core.conn, core.parsed);
}

pub const module = registry.Module{
    .id = "query.info",
    .commands = &.{
        .{ .name = "VERSION", .handler = version },
        .{ .name = "TIME", .handler = time },
        .{ .name = "ADMIN", .handler = admin },
        .{ .name = "INFO", .handler = info },
        .{ .name = "DIRECTORY", .handler = directory, .summary = "public discovery-directory summary for this node" },
        .{ .name = "MOTD", .handler = motd },
        .{ .name = "LUSERS", .handler = lusers },
        .{ .name = "USERS", .handler = users },
        .{ .name = "LINKS", .handler = links },
        .{ .name = "MAP", .handler = map },
        .{ .name = "CHANSTATS", .handler = chanstats, .summary = "channel stats: TOPUSERS|WORDS|ACTIVITY|RECORD #channel" },
    },
};
