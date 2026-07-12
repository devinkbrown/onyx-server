// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! oper.security module — operator tooling + network security/moderation
//! commands. Thin thunks over existing LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn oper(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleOper(x.conn, x.parsed);
}
fn rehash(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRehash(x.conn);
}
fn grant(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGrant(x.conn, x.parsed);
}
fn revoke(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRevoke(x.conn, x.parsed);
}
fn grants(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGrants(x.conn);
}
fn kill(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleKill(x.conn, x.parsed);
}
fn close(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleClose(x.conn);
}
fn drain(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDrain(x.conn, x.parsed);
}
fn unreject(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUnreject(x.conn, x.parsed);
}
fn ward(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWard(x.conn, x.parsed);
}
fn spamtrap(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSpamtrap(x.conn, x.parsed);
}
fn kline(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWardAlias(x.conn, x.parsed, .kline);
}
fn dline(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWardAlias(x.conn, x.parsed, .dline);
}
fn xline(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWardAlias(x.conn, x.parsed, .xline);
}
fn shun(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleShun(x.conn, x.parsed, true);
}
fn unshun(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleShun(x.conn, x.parsed, false);
}
fn global(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGlobal(x.id, x.conn, x.parsed);
}
fn operMotd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleOperMotd(x.conn, x.parsed);
}
fn die(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDie(x.conn, x.parsed.command);
}
fn connect(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleConnectCmd(x.conn, x.parsed);
}
fn squit(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSquit(x.conn, x.parsed);
}
fn trace(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTrace(x.conn);
}
fn sessions(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSessions(x.conn, x.parsed);
}
fn etrace(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleEtrace(x.conn);
}
fn stats(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleStats(x.conn, x.parsed);
}
fn testline(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTestline(x.conn, x.parsed);
}
fn testmask(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTestmask(x.conn, x.parsed);
}
fn userip(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUserip(x.conn, x.parsed);
}
fn debug(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDebug(x.conn);
}
fn audit(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAudit(x.conn, x.parsed);
}
fn mesh(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMesh(x.conn, x.parsed);
}
fn route(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRoute(x.conn);
}
fn nethealth(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleNethealth(x.conn);
}

pub const module = registry.Module{
    .id = "oper.security",
    .commands = &.{
        // OPER is how a client *becomes* an operator; STATS is not
        // operator-gated here. The rest require operator authority, enforced
        // declaratively by the registry (access=.oper).
        .{ .name = "OPER", .handler = oper },
        .{ .name = "REHASH", .access = .oper, .handler = rehash },
        .{ .name = "GRANT", .access = .oper, .handler = grant, .summary = "grant a registered account operator authority network-wide" },
        .{ .name = "REVOKE", .access = .oper, .handler = revoke, .summary = "revoke a runtime operator grant network-wide" },
        .{ .name = "GRANTS", .access = .oper, .handler = grants, .summary = "list live runtime operator grants" },
        .{ .name = "KILL", .access = .oper, .handler = kill },
        .{ .name = "CLOSE", .access = .oper, .handler = close },
        .{ .name = "DRAIN", .access = .oper, .handler = drain },
        .{ .name = "UNREJECT", .access = .oper, .handler = unreject },
        .{ .name = "WARD", .access = .oper, .handler = ward },
        .{ .name = "SPAMTRAP", .access = .oper, .handler = spamtrap },
        .{ .name = "KLINE", .access = .oper, .handler = kline },
        .{ .name = "DLINE", .access = .oper, .handler = dline },
        .{ .name = "XLINE", .access = .oper, .handler = xline },
        .{ .name = "SHUN", .access = .oper, .handler = shun },
        .{ .name = "UNSHUN", .access = .oper, .handler = unshun },
        .{ .name = "GLOBAL", .access = .oper, .handler = global },
        .{ .name = "OPERMOTD", .access = .oper, .handler = operMotd },
        .{ .name = "DIE", .access = .oper, .handler = die },
        .{ .name = "RESTART", .access = .oper, .handler = die },
        .{ .name = "CONNECT", .access = .oper, .handler = connect },
        .{ .name = "SQUIT", .access = .oper, .handler = squit },
        .{ .name = "TRACE", .access = .oper, .handler = trace },
        .{ .name = "ETRACE", .access = .oper, .handler = etrace },
        .{ .name = "STATS", .handler = stats },
        .{ .name = "TESTLINE", .access = .oper, .handler = testline },
        .{ .name = "TESTMASK", .access = .oper, .handler = testmask },
        .{ .name = "USERIP", .access = .oper, .handler = userip },
        .{ .name = "DEBUG", .access = .oper, .handler = debug },
        .{ .name = "AUDIT", .access = .oper, .handler = audit },
        .{ .name = "SESSIONS", .access = .oper, .handler = sessions },
        .{ .name = "MESH", .access = .oper, .handler = mesh, .summary = "mesh peer/link health (NETSTAT)" },
        .{ .name = "NETSTAT", .access = .oper, .handler = mesh, .summary = "alias of MESH" },
        .{ .name = "ROUTE", .access = .oper, .handler = route, .summary = "mesh routing table" },
        .{ .name = "NETHEALTH", .access = .oper, .handler = nethealth, .summary = "mesh node liveness (Sazanami view)" },
    },
};
