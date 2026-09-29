// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! feature.misc module — identity (VHOST/PRIVS), content FILTER, media surface,
//! offline MEMO, and ACTIVITY presence. Thin thunks over existing LinuxServer
//! handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn vhost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleVhost(x.id, x.conn, x.parsed);
}
fn privs(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handlePrivs(x.conn);
}
fn filter(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleFilter(x.conn, x.parsed);
}
fn policyCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handlePolicy(x.conn, x.parsed);
}
fn outhook(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleOutboundWebhook(x.conn, x.parsed);
}
fn botgrant(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleBotGrant(x.conn, x.parsed);
}
fn deferCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDefer(x.id, x.conn, x.parsed);
}
fn unfurlCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUnfurl(x.conn, x.parsed);
}
fn appealCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAppeal(x.conn, x.parsed);
}
fn challengeCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleChallenge(x.id, x.conn, x.parsed);
}
fn holdCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleHold(x.conn, x.parsed);
}
fn quarantineCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleQuarantine(x.conn, x.parsed);
}
fn botcmdCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleBotCmd(x.conn, x.parsed);
}
fn media(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMedia(x.id, x.conn, x.parsed);
}
fn memoCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMemo(x.conn, x.parsed);
}
fn webpushCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWebpush(x.conn, x.parsed);
}
fn activity(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleActivity(x.id, x.conn, x.parsed);
}
fn geoipCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGeoip(x.conn, x.parsed);
}
/// SUMMON <nick> <channel> — repurposed as an operator force-join (the classic
/// host-paging form, RFC 1459 §4.5, is obsolete). Oper-gated by the registry.
fn summon(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSummon(x.conn, x.parsed);
}
/// A registered client's PONG heartbeat reply: accepted, no response.
fn pong(c: *anyopaque, _: I) anyerror!void {
    _ = c;
}

pub const module = registry.Module{
    .id = "feature.misc",
    .commands = &.{
        .{ .name = "VHOST", .handler = vhost },
        .{ .name = "PRIVS", .handler = privs },
        .{ .name = "FILTER", .handler = filter },
        .{ .name = "POLICY", .handler = policyCmd, .summary = "List or roll back ward, filter, class, and ban generations" },
        .{ .name = "OUTHOOK", .handler = outhook, .summary = "Register an outbound webhook URL, secret, and category mask" },
        .{ .name = "BOTGRANT", .handler = botgrant, .summary = "List, add, or revoke a scoped expiring bot grant" },
        .{ .name = "DEFER", .min_params = 4, .access = .registered, .handler = deferCmd, .summary = "Defer a channel message or an oper mode until a timestamp or a cron fire" },
        .{ .name = "UNFURL", .min_params = 1, .access = .registered, .handler = unfurlCmd, .summary = "Opt-in https link preview. Default off. UNFURL OFF refuses previews" },
        .{ .name = "APPEAL", .min_params = 1, .access = .any, .handler = appealCmd, .summary = "File one ban appeal per window without joining. Oper LIST and ANSWER are audited" },
        .{ .name = "CHALLENGE", .min_params = 1, .access = .oper, .handler = challengeCmd, .summary = "Set the pre-001 challenge method or question. An unregistered client answers with CHALLENGE" },
        .{ .name = "HOLD", .min_params = 3, .access = .oper, .handler = holdCmd, .summary = "Release or drop a channel's held first messages" },
        .{ .name = "QUARANTINE", .min_params = 3, .access = .oper, .handler = quarantineCmd, .summary = "Move a joiner into a quarantine channel and audit the reason" },
        .{ .name = "BOTCMD", .min_params = 1, .access = .registered, .handler = botcmdCmd, .summary = "Register or run a bot command. A speak grant allows it. Buttons are not part of this command" },
        .{ .name = "MEDIA", .feature = "media", .handler = media },
        .{ .name = "MEMO", .handler = memoCmd },
        .{ .name = "WEBPUSH", .handler = webpushCmd, .summary = "Browser push subscriptions (VAPID/SUBSCRIBE/UNSUBSCRIBE/LIST)" },
        .{ .name = "ACTIVITY", .handler = activity },
        .{ .name = "GEOIP", .min_params = 1, .access = .oper, .handler = geoipCmd, .summary = "GeoIP lookup of an IP (oper)" },
        .{ .name = "SUMMON", .min_params = 2, .access = .oper, .handler = summon },
        .{ .name = "PONG", .access = .any, .handler = pong },
    },
};
