// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! oper.security command bodies. `LinuxServer` keeps one thunk per command so
//! `modules/oper_security.zig` stays the registry seam.

const std = @import("std");
const builtin = @import("builtin");
const client_model = @import("client.zig");
const cloak = @import("../proto/cloak.zig");
const command_usage = @import("command_usage.zig");
const config_boot = @import("config_boot.zig");
const config_format = @import("config_format.zig");
const credential_redaction = @import("credential_redaction.zig");
const diagnostic_bundle = @import("diagnostic_bundle.zig");
const helix_live = @import("helix/live.zig");
const retired_fences = @import("session_group_retired_policy.zig");
const windows_config_proof = @import("helix/native_windows_config_proof.zig");
const global_notice = @import("../proto/global_notice.zig");
const kill_relay = @import("../proto/kill_relay.zig");
const mesh_event_log = @import("../proto/mesh_event_log.zig");
const mesh_report = @import("../proto/mesh_report.zig");
const moderation_undo = @import("moderation_undo.zig");
const oper_mod = @import("oper.zig");
const oper_motd_mod = @import("../proto/oper_motd.zig");
const partition_detector = @import("../substrate/undertow/partition_detector.zig");
const platform = @import("../substrate/platform.zig");
const protocol_inventory = @import("../proto/protocol_inventory.zig");
const resolv_conf = @import("../proto/resolv_conf.zig");
const ripple_report = @import("../proto/ripple_report.zig");
const route_report = @import("../proto/route_report.zig");
const shun_mod = @import("shun.zig");
const svc_sessionview = @import("svc_sessionview.zig");
const trace = @import("../proto/trace.zig");
const tracelog = @import("../substrate/trace.zig");
const userip = @import("../proto/userip.zig");
const warden = @import("warden.zig");
const wildcard_limit = @import("../proto/wildcard_limit.zig");

/// UNREJECT uses the same mapped-v4 identity as the accepted peer path. Keep
/// existing literal parsing first; only the conventional dotted mapped spelling
/// uses the stricter standard-library IPv6 parser as an additive fallback.
fn unrejectAddress(text: []const u8) ?@import("../proto/dns.zig").Address {
    const Address = @import("../proto/dns.zig").Address;
    const parsed: Address = resolv_conf.parseIp(text) orelse blk: {
        const fallback = std.Io.net.IpAddress.parseIp6(text, 0) catch return null;
        const bytes = fallback.ip6.bytes;
        if (!std.mem.eql(u8, bytes[0..10], &(@as([10]u8, @splat(0)))) or bytes[10] != 0xff or bytes[11] != 0xff) return null;
        break :blk .{ .ipv6 = bytes };
    };
    return switch (parsed) {
        .ipv4 => parsed,
        .ipv6 => |bytes| if (std.mem.eql(u8, bytes[0..10], &(@as([10]u8, @splat(0)))) and bytes[10] == 0xff and bytes[11] == 0xff)
            .{ .ipv4 = bytes[12..16].* }
        else
            parsed,
    };
}

pub fn handleUnreject(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    // Operator gate enforced by the registry (access=.oper).
    if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"UNREJECT"}, "Usage: UNREJECT <ip>");
        return;
    }
    const ip_text = parsed.paramSlice()[0];
    const addr = unrejectAddress(ip_text) orelse {
        try self.failReply(conn, "UNREJECT", "INVALID_IP", "Not a valid IP address");
        return;
    };
    const cleared = self.reputation.clear(addr);
    if (cleared) self.snapshotReputation();
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    const state = if (cleared) "cleared" else "had no penalty";
    const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :UNREJECT {s}: {s}\r\n", .{ self.serverName(), conn.session.displayName(), ip_text, state }) catch return;
    try self.emitReply(conn, line);
}

pub fn handleDrain(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .server_admin)) return;
    const off = parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "OFF");
    self.draining = !off;
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    const state = if (self.draining) "enabled (refusing new connections)" else "disabled (accepting connections)";
    const line = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :DRAIN {s}\r\n", .{ self.serverName(), conn.session.displayName(), state }) catch return;
    try self.emitReply(conn, line);
}

pub fn handleClose(self: anytype, conn: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    var closed: usize = 0;
    const line = "ERROR :Closing unregistered connection\r\n";
    for (self.reactors) |*reactor| {
        var it = reactor.clients.iterator();
        while (it.next()) |entry| {
            const c = entry.value;
            if (c.closing) continue;
            if (c.s2s != null or c.s2s_secured != null) continue;
            if (c.session.registered()) continue;
            if (entry.id.shard == self.rx().shard_id) {
                self.emitServer(c, "ERROR :Closing unregistered connection");
                c.close_reason = "Closed by operator";
                c.closing = true;
                self.armSendIfNeeded(c) catch {};
            } else {
                self.enqueueDeliveryThenClose(entry.id, line, "Closed by operator") catch continue;
            }
            closed += 1;
        }
    }
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    const notice = std.fmt.bufPrint(&buf, ":{s} NOTICE {s} :CLOSE: {d} unregistered connection(s) closed\r\n", .{ self.serverName(), conn.session.displayName(), closed }) catch return;
    try self.emitReply(conn, notice);
}

pub fn handleKill(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_kill)) return;
    if (parsed.param_count < 1) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"KILL"}, "Not enough parameters");
        return;
    }
    const target_nick = parsed.paramSlice()[0];
    // Sanitize the reason: strip control bytes so a KILL can never smuggle
    // CR/LF (or other control bytes) into the local wire lines, and so the
    // cross-mesh KILL codec (which rejects control bytes) always accepts it.
    var reason_buf: [kill_relay.max_reason_len]u8 = undefined;
    const raw_reason = if (parsed.param_count >= 2 and parsed.paramSlice()[1].len != 0) parsed.paramSlice()[1] else "Killed";
    const reason = Server.sanitizeKillReason(raw_reason, &reason_buf);

    var prefix_buf: [Server.client_prefix_bytes]u8 = undefined;
    const active_override = Server.overrideActive(conn);
    const real_killer = conn.session.displayName();
    const public_killer = if (active_override) "SYSTEM" else real_killer;
    const kill_prefix = if (active_override) "SYSTEM" else self.clientPrefixOf(conn, &prefix_buf);

    // Resolve the target: a LOCAL killable client (real connection, not a peer
    // S2S link), or — failing that — a remote user owned by a mesh peer.
    const local_tid: ?client_model.ClientId = blk: {
        const wid = self.world.findNick(target_nick) orelse break :blk null;
        const tid = self.clientIdOfWorld(wid);
        const tconn = self.connFor(tid) orelse break :blk null;
        if (tconn.s2s != null or tconn.s2s_secured != null) break :blk null;
        break :blk tid;
    };

    if (local_tid) |tid| {
        if (active_override) self.auditOverrideUse(conn, "KILL", target_nick, "anonymous SYSTEM attribution");
        try self.publishKillEvent(real_killer, target_nick, reason, active_override);
        try self.performKillDisconnect(tid, target_nick, kill_prefix, public_killer, reason);
        return;
    }

    // Not local: route the KILL to the mesh peer whose route_table owns the
    // nick. The owning node verifies the signed frame and disconnects its
    // local target; the resulting QUIT propagates back normally.
    if (self.sendKillToOwner(target_nick, kill_prefix, reason)) {
        if (active_override) self.auditOverrideUse(conn, "KILL", target_nick, "anonymous SYSTEM attribution");
        try self.publishKillEvent(real_killer, target_nick, reason, active_override);
        var nb: [320]u8 = undefined;
        const nl = std.fmt.bufPrint(&nb, ":{s} NOTICE {s} :KILL: relayed across the mesh to the node owning {s}\r\n", .{ self.serverName(), conn.session.displayName(), target_nick }) catch return;
        try self.emitReply(conn, nl);
        return;
    }

    try self.replyNumeric(conn, .ERR_NOSUCHNICK, &.{target_nick}, "No such nick");
}

pub fn handleStats(self: anytype, conn: anytype, parsed: anytype) !void {
    if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"STATS"}, "Not enough parameters");
        return;
    }
    const letter = parsed.paramSlice()[0];
    // STATS is operator-only, except `p` (online operators), which stays public.
    if (letter[0] != 'p' and letter[0] != 'P' and !conn.session.isOper()) {
        try self.replyNumeric(conn, .ERR_NOPRIVILEGES, &.{"STATS"}, "Permission denied - STATS is operator-only (except STATS p)");
        return;
    }
    // There is no signed remote STATS query yet. Never answer a remote target
    // with this node's local data as though it were the target's report.
    if (parsed.param_count >= 2 and parsed.paramSlice()[1].len != 0 and
        !std.ascii.eqlIgnoreCase(parsed.paramSlice()[1], self.serverName()))
    {
        try self.replyNumeric(conn, .ERR_NOSUCHSERVER, &.{parsed.paramSlice()[1]}, "No such server");
        return;
    }
    switch (letter[0]) {
        'u' => {
            const up_secs: u64 = @intCast(@max(@as(i64, 0), @divTrunc(self.nowMs() - self.start_ms, 1000)));
            const days = up_secs / 86_400;
            const hours = (up_secs % 86_400) / 3600;
            const mins = (up_secs % 3600) / 60;
            const secs = up_secs % 60;
            var buf: [96]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "Server Up {d} days {d:0>2}:{d:0>2}:{d:0>2}", .{ days, hours, mins, secs }) catch return;
            try self.replyNumeric(conn, .RPL_STATSUPTIME, &.{}, text);
        },
        'o' => {
            // One RPL_STATSOLINE per configured oper binding (account -> class).
            if (self.oper_registry) |reg| {
                for (reg.bindings) |b| {
                    try self.replyNumeric(conn, .RPL_STATSOLINE, &.{ "O", b.account_name, "*", b.class_name, "0", "0" }, "");
                }
            }
        },
        'k', 'K' => try self.statsLines(conn, .mask, .RPL_STATSKLINE),
        'd', 'D' => try self.statsLines(conn, .address, .RPL_STATSDLINE),
        'y', 'Y' => {
            // Connection classes (`[class.*]`): one line per class with its full
            // policy, match summary, and live-member count.
            if (self.config.class_registry) |*reg| {
                for (reg.classes) |*cls| {
                    var buf: [900]u8 = undefined;
                    const text = std.fmt.bufPrint(&buf, "sendq={d} recvq={d} max_clients={d} max_per_ip={d} max_per_account={d} max_per_host={d} max_chan={d} max_targets={d} monitor={d} silence={d} ping={d}ms ping_timeout={d}ms reg_timeout={d}ms flood={d}/{d}ms require_tls={} require_sasl={} flood_exempt={} nick_delay_exempt={} cidrs={d} tls_only={} account_only={} oper_only={} live={d}", .{
                        cls.policy.sendq,               cls.policy.recvq,
                        cls.policy.max_clients,         cls.policy.max_per_ip,
                        cls.policy.max_per_account,     cls.policy.max_per_host,
                        cls.policy.max_channels,        cls.policy.max_targets,
                        cls.policy.monitor,             cls.policy.silence,
                        cls.policy.ping_interval_ms,    cls.policy.ping_timeout_ms,
                        cls.policy.register_timeout_ms, cls.policy.flood_lines,
                        cls.policy.flood_window_ms,     cls.policy.require_tls,
                        cls.policy.require_sasl,        cls.policy.flood_exempt,
                        cls.policy.nick_delay_exempt,   cls.cidrs.len,
                        cls.tls_only,                   cls.account_only,
                        cls.oper_only,                  self.countClassMembers(cls.name),
                    }) catch continue;
                    try self.replyNumeric(conn, .RPL_STATSYLINE, &.{ "Y", cls.name }, text);
                }
            }
        },
        'l', 'L' => {
            // Established S2S peer links: name, SendQ ceiling + queued, uptime.
            const now = self.nowMs();
            for (self.reactors) |*reactor| {
                for (reactor.clients.slots.items) |*slot| {
                    if (!slot.occupied) continue;
                    const c = &slot.value;
                    const rname: ?[]const u8 = if (c.s2s_secured) |l|
                        (if (l.established()) l.remoteName() else null)
                    else if (c.s2s) |l|
                        (if (l.established()) l.remoteName() else null)
                    else
                        null;
                    const name = rname orelse continue;
                    const queued = (c.send_len - c.send_offset) + c.send_overflow.items.len;
                    const up_s: i64 = @divTrunc(now - c.connected_at_ms, 1000);
                    var buf: [256]u8 = undefined;
                    const text = std.fmt.bufPrint(&buf, "sendq_cap={d} queued={d} uptime={d}s", .{ c.sendq_cap, queued, @max(@as(i64, 0), up_s) }) catch continue;
                    try self.replyNumeric(conn, .RPL_STATSLLINE, &.{if (name.len != 0) name else "*"}, text);
                }
            }
        },
        'z', 'Z' => {
            // Runtime counters (RPL_STATSDEBUG 249), oper-only.
            if (!conn.session.isOper()) {
                try self.replyNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied; STATS z is for operators");
            } else {
                const ServerPtr = @TypeOf(self);
                const ConnPtr = @TypeOf(conn);
                const Ctx = struct { server: ServerPtr, c: ConnPtr };
                try self.stats.forEachLine(Ctx{ .server = self, .c = conn }, struct {
                    fn emit(cx: Ctx, line: []const u8) !void {
                        try cx.server.replyNumeric(cx.c, .RPL_STATSDEBUG, &.{}, line);
                    }
                }.emit);
            }
        },
        'p', 'P' => {
            // Online operators (public exception). One RPL_STATSDEBUG line per
            // currently-connected oper, mirroring the `l` slot iteration.
            for (self.reactors) |*reactor| {
                for (reactor.clients.slots.items) |*slot| {
                    if (!slot.occupied) continue;
                    const c = &slot.value;
                    if (c.closing or !c.session.registered() or !c.session.isOper()) continue;
                    try self.replyNumeric(conn, .RPL_STATSDEBUG, &.{"p"}, c.session.displayName());
                }
            }
        },
        'c', 'C' => {
            // Connect blocks (C-lines, RPL_STATSCLINE 213): the configured
            // `[mesh].connect` auto-dial peers this node links out to. Each is
            // a "host:port" string; report it as `C <host> * <host> <port>`.
            for (self.config.mesh_connect) |spec| {
                if (self.hostPortOf(spec)) |hp| {
                    var port_buf: [8]u8 = undefined;
                    const port = std.fmt.bufPrint(&port_buf, "{d}", .{hp.port}) catch "*";
                    try self.replyNumeric(conn, .RPL_STATSCLINE, &.{ "C", hp.host, "*", hp.host, port, "mesh" }, "");
                } else {
                    // Unsplittable spec: report it verbatim as the host.
                    try self.replyNumeric(conn, .RPL_STATSCLINE, &.{ "C", spec, "*", spec, "*", "mesh" }, "");
                }
            }
        },
        'i', 'I' => {
            // Allow blocks (I-lines, RPL_STATSILINE 215): the connection
            // classes that gate who may connect. One line per class with its
            // accepted-CIDR count and active match criteria (an I-line is an
            // allow rule, so the class's constraints are its allow conditions).
            if (self.config.class_registry) |*reg| {
                for (reg.classes) |*cls| {
                    var crit_buf: [160]u8 = undefined;
                    const crit = std.fmt.bufPrint(&crit_buf, "cidrs={d} tls_only={} account_only={} oper_only={}", .{
                        cls.cidrs.len, cls.tls_only, cls.account_only, cls.oper_only,
                    }) catch continue;
                    try self.replyNumeric(conn, .RPL_STATSILINE, &.{ "I", "*", "*", cls.name }, crit);
                }
            }
        },
        'm', 'M' => {
            // Command usage (RPL_STATSCOMMANDS 212): one line per dispatched
            // verb as `<command> <count> <bytes> <remote>` — four discrete
            // middle params (never a space-joined blob). Remote is always 0
            // here; these are local-client command totals.
            const ServerPtr = @TypeOf(self);
            const ConnPtr = @TypeOf(conn);
            const Ctx = struct { server: ServerPtr, c: ConnPtr };
            try self.command_usage.forEach(Ctx{ .server = self, .c = conn }, struct {
                fn emit(cx: Ctx, row: command_usage.CommandUsage.Row) anyerror!void {
                    var count_buf: [20]u8 = undefined;
                    var bytes_buf: [20]u8 = undefined;
                    const count_s = try std.fmt.bufPrint(&count_buf, "{d}", .{row.count});
                    const bytes_s = try std.fmt.bufPrint(&bytes_buf, "{d}", .{row.bytes});
                    try cx.server.replyNumeric(cx.c, .RPL_STATSCOMMANDS, &.{ row.name, count_s, bytes_s, "0" }, "");
                }
            }.emit);
        },
        else => {}, // other letters not implemented yet
    }
    try self.replyNumeric(conn, .RPL_ENDOFSTATS, &.{letter}, "End of /STATS report");
}

pub fn handleAbuse(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    const p = parsed.paramSlice();
    if (p.len == 0 or p[0].len == 0) {
        try self.noticeTo(conn, "Usage: ABUSE <nick>");
        return;
    }
    const target = self.liveConnByNick(p[0]) orelse {
        try self.noticeTo(conn, "ABUSE: no such nick");
        return;
    };
    const nick = target.session.displayName();
    if (target.flood_guard) |*guard| {
        const snap = guard.snapshot();
        var b: [Server.reply_scratch_bytes]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: flood {s} excess={d} message_tokens={d}", .{
            nick,
            @tagName(target.last_flood),
            snap.excess_points,
            snap.message_tokens,
        }) catch return;
        try self.noticeTo(conn, line);
    } else {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: flood none", .{nick}) catch return;
        try self.noticeTo(conn, line);
    }
    {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: shun {s}", .{ nick, if (self.shunMatchesConn(target)) "yes" else "no" }) catch return;
        try self.noticeTo(conn, line);
    }
    if (self.config.dnsbl) |bl| {
        if (target.peer_addr) |addr| {
            if (bl.lookup(addr)) |verdict| {
                var b: [160]u8 = undefined;
                const line = if (verdict.listed)
                    std.fmt.bufPrint(&b, "ABUSE {s}: dnsbl listed {d}", .{ nick, verdict.code }) catch return
                else
                    std.fmt.bufPrint(&b, "ABUSE {s}: dnsbl clear", .{nick}) catch return;
                try self.noticeTo(conn, line);
            } else {
                var b: [160]u8 = undefined;
                const line = std.fmt.bufPrint(&b, "ABUSE {s}: dnsbl unknown", .{nick}) catch return;
                try self.noticeTo(conn, line);
            }
        } else {
            var b: [160]u8 = undefined;
            const line = std.fmt.bufPrint(&b, "ABUSE {s}: dnsbl unknown", .{nick}) catch return;
            try self.noticeTo(conn, line);
        }
    } else {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: dnsbl unknown", .{nick}) catch return;
        try self.noticeTo(conn, line);
    }
    if (target.peer_addr) |addr| {
        const shown: u64 = @intFromFloat(@round(@max(@as(f64, 0), self.reputation.score(addr, self.nowU64()))));
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: reputation {d}", .{ nick, shown }) catch return;
        try self.noticeTo(conn, line);
    } else {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: reputation none", .{nick}) catch return;
        try self.noticeTo(conn, line);
    }
    if (target.session.account()) |account| {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: account {s} score={d}", .{ nick, account, self.account_abuse.score(account) }) catch return;
        try self.noticeTo(conn, line);
    } else {
        var b: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "ABUSE {s}: account none score=0", .{nick}) catch return;
        try self.noticeTo(conn, line);
    }
}

pub fn handleOperMotd(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    const p = parsed.paramSlice();
    if (p.len >= 1 and std.ascii.eqlIgnoreCase(p[0], "SET")) {
        if (!self.requirePriv(conn, .server_admin)) return;
        const text = if (p.len >= 2) p[1] else "";
        self.oper_motd.setFromText(text) catch {
            try self.noticeTo(conn, "OPERMOTD: could not set (too long)");
            return;
        };
        try self.noticeTo(conn, "OPERMOTD updated");
        return;
    }
    const nick = conn.session.displayName();
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    if (self.oper_motd.isEmpty()) {
        const line = oper_motd_mod.buildNoOperMotd(&buf, self.serverName(), nick) catch return;
        try self.appendConnLine(conn, line);
        return;
    }
    if (oper_motd_mod.buildOperMotdStart(&buf, self.serverName(), nick)) |line| try self.appendConnLine(conn, line) else |_| {}
    for (self.oper_motd.lines()) |l| {
        var lb: [Server.reply_scratch_bytes]u8 = undefined;
        if (oper_motd_mod.buildOperMotdLine(&lb, self.serverName(), nick, l)) |line| try self.appendConnLine(conn, line) else |_| {}
    }
    if (oper_motd_mod.buildOperMotdEnd(&buf, self.serverName(), nick)) |line| try self.appendConnLine(conn, line) else |_| {}
}

pub fn handleShun(self: anytype, conn: anytype, parsed: anytype, adding: bool) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    const p = parsed.paramSlice();
    if (adding and p.len == 0) {
        var rows: [256]shun_mod.Shun = undefined;
        for (self.shuns.list(&rows)) |s| {
            var b: [Server.reply_scratch_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :SHUN {s} by {s} :{s}\r\n", .{ self.serverName(), conn.session.displayName(), s.mask, s.set_by, s.reason }) catch continue;
            try self.emitReply(conn, line);
        }
        try self.noticeTo(conn, "SHUN: end of list");
        return;
    }
    if (p.len == 0) {
        try self.noticeTo(conn, "Usage: SHUN <mask> [secs] [:reason] | UNSHUN <mask>");
        return;
    }
    const mask = p[0];
    if (!adding) {
        const undo_before = self.moderationSnapshot(moderation_undo.FactKey.ofShun(mask));
        const removed = self.shuns.remove(mask);
        if (removed) self.snapshotShuns();
        const status = if (removed) "removed" else "not found";
        const receipt = self.recordModerationAudit(&undo_before, conn.session.displayName(), .unshun, status);
        var b: [Server.reply_scratch_bytes]u8 = undefined;
        const note = if (receipt.proof_id) |pid|
            std.fmt.bufPrint(&b, "UNSHUN {s}: {s} proof={s}", .{ mask, status, pid[0..] }) catch return
        else
            std.fmt.bufPrint(&b, "UNSHUN {s}: {s}", .{ mask, status }) catch return;
        var cb: [Server.reply_scratch_bytes]u8 = undefined;
        try self.publishOperEvent(.oper_action, .notice, Server.withChangeId(&cb, note, receipt.change_id));
        return;
    }
    // Reject over-broad shun masks (e.g. *!*@*) so a shun can't mute everyone.
    if (wildcard_limit.isTooBroad(mask, wildcard_limit.Policy.channel_ban)) {
        try self.noticeTo(conn, "SHUN: mask too broad (needs more literal characters)");
        return;
    }
    var secs: i64 = 0;
    var reason: []const u8 = "No reason";
    if (p.len >= 2) {
        if (std.fmt.parseInt(i64, p[1], 10)) |n| secs = n else |_| reason = p[1];
    }
    if (p.len >= 3) reason = p[2];
    const now = self.nowMs();
    const undo_before = self.moderationSnapshot(moderation_undo.FactKey.ofShun(mask));
    self.shuns.add(.{
        .mask = mask,
        .reason = reason,
        .set_by = conn.session.displayName(),
        .created_ms = now,
        .expires_ms = if (secs > 0) now + secs * 1000 else 0,
    }) catch {
        try self.noticeTo(conn, "SHUN: could not add (limit or invalid mask)");
        return;
    };
    self.snapshotShuns();
    const receipt = self.recordModerationAudit(&undo_before, conn.session.displayName(), .shun, reason);
    var b: [Server.reply_scratch_bytes]u8 = undefined;
    const note = if (receipt.proof_id) |pid|
        std.fmt.bufPrint(&b, "SHUN {s} proof={s}", .{ mask, pid[0..] }) catch return
    else
        std.fmt.bufPrint(&b, "SHUN {s}", .{mask}) catch return;
    var cb: [Server.reply_scratch_bytes]u8 = undefined;
    try self.publishOperEvent(.oper_action, .notice, Server.withChangeId(&cb, note, receipt.change_id));
}

pub fn handleGlobal(self: anytype, id: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    _ = id;
    if (!self.requirePriv(conn, .server_admin)) return;
    const req = global_notice.Request.parse(parsed.paramSlice()) catch {
        try self.noticeTo(conn, "Usage: GLOBAL [<mask>|#channel] :<text>");
        return;
    };
    var line_buf: [Server.reply_scratch_bytes]u8 = undefined;
    const line = global_notice.formatLine(&line_buf, self.serverName(), req.text) catch {
        try self.noticeTo(conn, "GLOBAL: message too long");
        return;
    };
    var sent: u32 = 0;
    var it = self.rx().clients.iterator();
    while (it.next()) |entry| {
        const c = entry.value;
        if (!c.session.registered()) continue;
        // Build this recipient's facets for audience matching.
        var hm_buf: [Server.client_prefix_bytes]u8 = undefined;
        const hm = self.clientPrefixOf(c, &hm_buf);
        var chans: [64][]const u8 = undefined;
        const nchans = self.world.channelsOf(self.worldIdOf(entry.id), &chans);
        if (!req.inAudience(hm, chans[0..nchans])) continue;
        self.deliver(entry.id, line) catch {};
        sent += 1;
    }
    var nb: [96]u8 = undefined;
    const note = std.fmt.bufPrint(&nb, "GLOBAL sent to {d} user(s)", .{sent}) catch return;
    try self.noticeTo(conn, note);
}

pub fn handleWard(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    // Operator gate enforced by the registry (access=.oper).
    const p = parsed.paramSlice();
    if (p.len < 1) {
        try self.noticeTo(conn, "Usage: WARD <ADD|DEL|LIST|TEST|PREVIEW> …");
        return;
    }
    const sub = p[0];
    if (std.ascii.eqlIgnoreCase(sub, "LIST")) {
        const only: ?warden.Match = if (p.len >= 2) warden.Match.parse(p[1]) else null;
        var rows: [256]warden.Ward = undefined;
        const wards = self.warden.list(only, &rows);
        for (wards) |w| {
            var b: [Server.reply_scratch_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, ":{s} NOTICE {s} :WARD {s} {s} {s}/{s} by {s} :{s}\r\n", .{ self.serverName(), conn.session.displayName(), w.match.token(), w.pattern, w.scope.token(), w.action.token(), w.set_by, w.reason }) catch continue;
            try self.emitReply(conn, line);
        }
        try self.noticeTo(conn, "WARD: end of list");
        return;
    }
    if (std.ascii.eqlIgnoreCase(sub, "TEST")) {
        if (p.len < 3) {
            try self.noticeTo(conn, "Usage: WARD TEST <match> <value>");
            return;
        }
        const m = warden.Match.parse(p[1]) orelse {
            try self.noticeTo(conn, "WARD: unknown match facet");
            return;
        };
        var facets = warden.Facets{};
        switch (m) {
            .address => facets.address = p[2],
            .host => facets.host = p[2],
            .mask => facets.mask = p[2],
            .account => facets.account = p[2],
            .realname => facets.realname = p[2],
            .certfp => facets.certfp = p[2],
            .country => facets.country = p[2],
            .asn => facets.asn = p[2],
        }
        if (self.warden.check(facets, platform.realtimeMillis())) |w| {
            var b: [Server.reply_scratch_bytes]u8 = undefined;
            const line = std.fmt.bufPrint(&b, "WARD TEST: matched {s} {s} ({s}) :{s}", .{ w.match.token(), w.pattern, w.action.token(), w.reason }) catch return;
            try self.noticeTo(conn, line);
        } else {
            try self.noticeTo(conn, "WARD TEST: no match");
        }
        return;
    }
    const adding = std.ascii.eqlIgnoreCase(sub, "ADD");
    const deleting = std.ascii.eqlIgnoreCase(sub, "DEL");
    if ((!adding and !deleting) or p.len < 3) {
        try self.noticeTo(conn, "Usage: WARD ADD <match> <pattern> [scope] [action] [secs] [:reason] | DEL <match> <pattern>");
        return;
    }
    const match = warden.Match.parse(p[1]) orelse {
        try self.noticeTo(conn, "WARD: unknown match facet (address|host|mask|account|realname|certfp|country|asn)");
        return;
    };
    const pattern = p[2];
    if (deleting) {
        try self.deleteWardLive(conn, match, pattern);
        return;
    }
    // Reject over-broad glob patterns (e.g. *!*@*) for non-address facets so
    // a single ward can't sweep the whole network. Address (CIDR) is exempt.
    if (match != .address and wildcard_limit.isTooBroad(pattern, wildcard_limit.Policy.channel_ban)) {
        try self.noticeTo(conn, "WARD: pattern too broad (needs more literal characters)");
        return;
    }
    // ADD: optional positional scope, action, duration, then trailing reason.
    var scope: warden.Scope = .node;
    var action: warden.Action = .expel;
    var secs: i64 = 0;
    var reason: []const u8 = "No reason";
    var i: usize = 3;
    while (i < p.len) : (i += 1) {
        if (warden.Scope.parse(p[i])) |s| {
            scope = s;
        } else if (warden.Action.parse(p[i])) |a| {
            action = a;
        } else if (std.fmt.parseInt(i64, p[i], 10)) |n| {
            secs = n;
        } else |_| {
            reason = p[i]; // first non-axis, non-numeric token is the reason
            break;
        }
    }
    try self.addWardLive(conn, match, pattern, scope, action, secs, reason, .ward_add);
}

pub fn handleWardAlias(self: anytype, conn: anytype, parsed: anytype, alias: anytype) !void {
    if (!self.requirePriv(conn, .client_moderate)) return;
    const p = parsed.paramSlice();
    if (p.len == 0) {
        try self.noticeTo(conn, "Usage: KLINE|DLINE|XLINE [ADD|DEL] <pattern> [secs] [:reason]");
        return;
    }
    const match: warden.Match = switch (alias) {
        .kline => .mask,
        .dline => .address,
        .xline => .realname,
    };
    const default_action: warden.Action = switch (alias) {
        .dline => .refuse,
        .kline, .xline => .expel,
    };

    var idx: usize = 0;
    var adding = true;
    if (std.ascii.eqlIgnoreCase(p[0], "ADD")) {
        idx = 1;
    } else if (std.ascii.eqlIgnoreCase(p[0], "DEL") or std.ascii.eqlIgnoreCase(p[0], "REMOVE")) {
        idx = 1;
        adding = false;
    }
    if (idx >= p.len or p[idx].len == 0) {
        try self.noticeTo(conn, "Usage: KLINE|DLINE|XLINE [ADD|DEL] <pattern> [secs] [:reason]");
        return;
    }
    const pattern = p[idx];
    if (!adding) {
        try self.deleteWardLive(conn, match, pattern);
        return;
    }
    if (match != .address and wildcard_limit.isTooBroad(pattern, wildcard_limit.Policy.channel_ban)) {
        try self.noticeTo(conn, "WARD: pattern too broad (needs more literal characters)");
        return;
    }
    var secs: i64 = 0;
    var reason: []const u8 = "No reason";
    var i = idx + 1;
    while (i < p.len) : (i += 1) {
        if (std.fmt.parseInt(i64, p[i], 10)) |n| {
            secs = n;
        } else |_| {
            reason = p[i];
            break;
        }
    }
    try self.addWardLive(conn, match, pattern, .node, default_action, secs, reason, .kline);
}

pub fn handleUserip(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .oper_spy)) return;
    if (parsed.param_count < 1) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"USERIP"}, "Not enough parameters");
        return;
    }
    var targets: [5]userip.UseripTarget = undefined;
    var ip_bufs: [5][cloak.max_cloak_len]u8 = undefined;
    var n: usize = 0;
    for (parsed.paramSlice()) |nick| {
        if (n >= targets.len) break;
        const wid = self.world.findNick(nick) orelse continue;
        const c = self.connFor(self.clientIdOfWorld(wid));
        const ip = if (c) |cc|
            if (cc.peer_addr) |addr| Server.addrText(addr, &ip_bufs[n]) orelse Server.fallback_host else Server.fallback_host
        else
            Server.fallback_host;
        targets[n] = .{
            .nick = nick,
            .oper = if (c) |cc| cc.session.isOper() else false,
            .away = if (c) |cc| cc.session.awayMessage() != null else false,
            .user = self.usernameFor(wid),
            .ip = ip,
        };
        n += 1;
    }
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    const line = userip.writeUseripReply(&buf, self.serverName(), conn.session.displayName(), targets[0..n]) catch return;
    try self.appendConnLine(conn, line);
    if (!std.mem.endsWith(u8, line, "\n")) try self.appendConnLine(conn, "\r\n");
}

pub fn handleDie(self: anytype, conn: anytype, cmd: []const u8) !void {
    // Registry enforces access=.oper; refine per the specific lifecycle priv.
    const restarting = std.ascii.eqlIgnoreCase(cmd, "RESTART");
    const needed: oper_mod.Privilege = if (restarting) .server_restart else .server_shutdown;
    if (!self.requirePriv(conn, needed)) return;
    const kind = self.twoPersonKindFor(restarting);
    switch (try self.twoPersonAdmit(conn, kind, cmd)) {
        .waiting => return,
        .proceed => {},
        .confirmed => {
            _ = self.recordOperAudit(self.twoPersonIdentityOf(conn), self.twoPersonAuditOf(kind), cmd, "two-person action");
        },
    }
    var nbuf: [128]u8 = undefined;
    const note = std.fmt.bufPrint(&nbuf, "{s} requested by {s}", .{ cmd, conn.session.displayName() }) catch cmd;
    try self.publishOperEvent(.oper_action, .critical, note);
    if (restarting and comptime builtin.os.tag == .linux) {
        // Clean in-place re-exec: re-reads config + rebinds, drops sessions.
        // Reuses the listener-only re-exec path (no state arena). On success
        // this never returns (execve replaces the image); on failure it logs
        // and falls through to clearing the run flag below as a fail-safe.
        self.upgradeListenerOnly(conn) catch {};
    }
    if (self.shutdown) |flag| flag.store(false, .release);
}

pub fn handleTrace(self: anytype, conn: anytype) !void {
    const Server = @TypeOf(self.*);
    // Operator gate enforced by the registry (access=.oper).
    var scratch: [Server.reply_scratch_bytes]u8 = undefined;
    var sink = self.connLineSink(conn);
    const ctx = trace.ReplyContext{ .server_name = self.serverName(), .requester = conn.session.displayName() };
    var it = self.rx().clients.iterator();
    while (it.next()) |e| {
        if (!e.value.session.registered()) continue;
        const entry = trace.TraceEntry{ .user = .{ .class = "users", .nick = e.value.session.displayName(), .ip = Server.fallback_host, .connected_seconds = 0, .idle_seconds = 0 } };
        trace.emitTrace(ctx, &.{entry}, &scratch, &sink) catch {};
    }
    trace.emitTrace(ctx, &.{trace.TraceEntry{ .end = self.serverName() }}, &scratch, &sink) catch {};
}

pub fn handleSessions(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    // Operator gate enforced by the registry (access=.oper).
    const query_raw = if (parsed.param_count >= 1) parsed.paramSlice()[0] else "";
    const query = svc_sessionview.parseFilter(query_raw) catch {
        try self.noticeTo(conn, "SESSIONS: invalid filter (try: oper|user, tls|clear, account=<glob>, ip=<glob>, sort=connected, limit=N)");
        return;
    };

    const max_facts = 1024;
    var facts_buf: [max_facts]svc_sessionview.ConnectionFact = undefined;
    var n: usize = 0;
    const now = self.nowMs();
    outer: for (self.reactors) |*reactor| {
        var it = reactor.clients.iterator();
        while (it.next()) |entry| {
            if (n >= max_facts) break :outer;
            const c = entry.value;
            if (c.s2s != null or c.s2s_secured != null) continue; // skip peer links
            if (!c.session.registered()) continue;
            const age: u64 = @intCast(@max(@as(i64, 0), now - c.connected_at_ms));
            facts_buf[n] = .{
                .nick = c.session.displayName(),
                .account = c.session.account(),
                .ip = c.session.realHost(),
                .connected_ms = age,
                .is_oper = c.session.isOper(),
                .is_tls = c.is_tls,
            };
            n += 1;
        }
    }

    var out_buf: [max_facts]svc_sessionview.ConnectionFact = undefined;
    const view = svc_sessionview.buildView(facts_buf[0..n], query, &out_buf) catch {
        try self.noticeTo(conn, "SESSIONS: too many matches; narrow the filter or add limit=N");
        return;
    };
    const fmt = svc_sessionview.Formatter.init(self.serverName(), conn.session.displayName());
    for (view.rows) |row| {
        var lb: [Server.reply_scratch_bytes]u8 = undefined;
        const ln = fmt.traceLine(&lb, row) catch continue;
        try self.appendConnLine(conn, ln);
    }
    var eb: [128]u8 = undefined;
    const end = fmt.endOfTrace(&eb, "") catch return;
    try self.appendConnLine(conn, end);
}

pub fn handleEtrace(self: anytype, conn: anytype) !void {
    const Server = @TypeOf(self.*);
    // Operator gate enforced by the registry (access=.oper).
    var buf: [Server.reply_scratch_bytes]u8 = undefined;
    var it = self.rx().clients.iterator();
    while (it.next()) |e| {
        const c = e.value;
        if (!c.session.registered()) continue;
        if (c.s2s != null or c.s2s_secured != null) continue;
        const acct = c.session.account() orelse "0";
        const line = std.fmt.bufPrint(&buf, ":{s} 709 {s} users User {s} {s} {s} {s} {s} :{s}\r\n", .{
            protocol_inventory.currentServerName(),
            conn.session.displayName(),
            c.session.displayName(),
            c.session.username(),
            c.session.host(),
            c.session.realHost(),
            acct,
            c.session.realname(),
        }) catch continue;
        self.appendConnLine(conn, line) catch {};
    }
    const endl = std.fmt.bufPrint(&buf, ":{s} 262 {s} {s} :End of ETRACE\r\n", .{ self.serverName(), conn.session.displayName(), protocol_inventory.currentServerName() }) catch return;
    try self.appendConnLine(conn, endl);
}

pub fn handleConnectCmd(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .mesh_admin)) return;
    // Operator gate enforced by the registry (access=.oper).
    if (parsed.param_count < 2) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"CONNECT"}, "Not enough parameters");
        return;
    }
    const host = parsed.paramSlice()[0];
    const port = std.fmt.parseInt(u16, parsed.paramSlice()[1], 10) catch {
        try self.noticeTo(conn, "CONNECT: illegal port number");
        return;
    };
    if (self.rx().clients.len() >= self.config.max_clients) {
        try self.noticeTo(conn, "CONNECT refused: connection table full");
        return;
    }
    _ = self.initiateS2sConnect(host, port) catch |err| {
        try self.noticeTo(conn, switch (err) {
            error.InvalidAddress => "CONNECT failed: invalid host",
            else => "CONNECT failed: cannot create socket",
        });
        return;
    };
    const mode = if (self.s2sSecured()) "secured" else "plain";
    var target_buf: [320]u8 = undefined;
    const target = std.fmt.bufPrint(&target_buf, "{s}:{d}", .{ host, port }) catch host;
    const proof_id = self.recordOperAudit(conn.session.displayName(), .connect, target, mode);
    var event_buf: [Server.reply_scratch_bytes]u8 = undefined;
    const event_note = if (proof_id) |pid|
        std.fmt.bufPrint(&event_buf, "CONNECT {s} {s} proof={s}", .{ target, mode, pid[0..] }) catch return
    else
        std.fmt.bufPrint(&event_buf, "CONNECT {s} {s}", .{ target, mode }) catch return;
    try self.publishOperEvent(.oper_action, .notice, event_note);
    try self.noticeTo(conn, if (self.s2sSecured()) "CONNECT initiated (secured)" else "CONNECT initiated");
}

pub fn handleSquit(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .mesh_admin)) return;
    // Operator gate enforced by the registry (access=.oper).
    if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"SQUIT"}, "Not enough parameters");
        return;
    }
    const target = parsed.paramSlice()[0];
    if (self.findSquitVictim(target)) |victim| {
        try self.enqueueCloseOnOwner(victim.id, "SQUIT");
        const reason = if (parsed.param_count >= 2) parsed.paramSlice()[1] else "SQUIT";
        const proof_id = self.recordOperAudit(conn.session.displayName(), .squit, target, reason);
        var event_buf: [Server.reply_scratch_bytes]u8 = undefined;
        const event_note = if (proof_id) |pid|
            std.fmt.bufPrint(&event_buf, "SQUIT {s} proof={s}", .{ target, pid[0..] }) catch return
        else
            std.fmt.bufPrint(&event_buf, "SQUIT {s}", .{target}) catch return;
        try self.publishOperEvent(.oper_action, .notice, event_note);
        try self.noticeTo(conn, "SQUIT complete");
    } else {
        try self.replyNumeric(conn, .ERR_NOSUCHSERVER, &.{target}, "No such server");
    }
}

pub fn handleDebug(self: anytype, conn: anytype, parsed: anytype) !void {
    if (!self.requirePriv(conn, .audit_read)) return;
    if (parsed.param_count != 0) {
        if (parsed.param_count == 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "BUNDLE"))
            return diagnostic_bundle.sendNotices(self, conn, .{ .wall_ms = @intCast(@max(0, platform.realtimeMillis())) });
        if (parsed.param_count != 1 or !std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "DIAGNOSTICS")) {
            try self.noticeTo(conn, "Usage: DEBUG [DIAGNOSTICS|BUNDLE]");
            return;
        }
        const diagnostics = @import("diagnostics.zig");
        // Bound the IRC response independently of the 128-record retained ring.
        var records: [32]diagnostics.Record = undefined;
        const recent = self.diagnostics.snapshot(&records) catch {
            try self.noticeTo(conn, "DEBUG diagnostics busy; retry");
            return;
        };
        var line: [512]u8 = undefined;
        for (recent) |record| try self.noticeTo(conn, try diagnostics.formatRecord(&line, record));
        try self.noticeTo(conn, "End of DEBUG diagnostics");
        return;
    }
    var buf: [256]tracelog.RecordedEvent = undefined;
    const events = self.trace_recorder.dump(&buf);
    var line_buf: [320]u8 = undefined;
    for (events) |ev| {
        // Defense in depth on the egress side: the flight recorder should
        // already carry redacted messages (traceLog redacts at ingress), but
        // never forward a raw credential to an oper NOTICE regardless.
        var msg_buf: [tracelog.max_recorded_msg_len]u8 = undefined;
        const safe_msg = credential_redaction.redactInto(ev.message(), &msg_buf);
        const l = std.fmt.bufPrint(&line_buf, "[{s}/{s}] {s}", .{ ev.level.token(), ev.category.token(), safe_msg }) catch continue;
        try self.noticeTo(conn, l);
    }
    try self.noticeTo(conn, "End of DEBUG flight recorder");
}

pub fn handleTestline(self: anytype, conn: anytype, parsed: anytype) !void {
    // Operator gate enforced by the registry (access=.oper).
    if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TESTLINE"}, "Not enough parameters");
        return;
    }
    const target = parsed.paramSlice()[0];
    // Probe the target against the most common facets (IP and nick!user@host
    // / host) so a single token still reports any matching ward.
    const facets = warden.Facets{ .address = target, .mask = target, .host = target };
    if (self.warden.check(facets, platform.realtimeMillis())) |w| {
        try self.replyNumeric(conn, .RPL_TESTLINE, &.{ w.match.token(), w.pattern }, w.reason);
        return;
    }
    try self.replyNumeric(conn, .RPL_NOTESTLINE, &.{target}, "No matching ban found");
}

pub fn handleTestmask(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    // Operator gate enforced by the registry (access=.oper).
    if (parsed.param_count < 1 or parsed.paramSlice()[0].len == 0) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"TESTMASK"}, "Not enough parameters");
        return;
    }
    const mask = parsed.paramSlice()[0];
    var matched: u64 = 0;
    var it = self.rx().clients.iterator();
    while (it.next()) |entry| {
        const c = entry.value;
        if (!c.session.registered()) continue;
        var hm_buf: [320]u8 = undefined;
        const hostmask = std.fmt.bufPrint(&hm_buf, "{s}!{s}@{s}", .{ c.session.displayName(), c.session.username(), Server.fallback_host }) catch continue;
        if (warden.globMatch(mask, hostmask)) matched += 1;
    }
    var cnt_buf: [24]u8 = undefined;
    const cnt = std.fmt.bufPrint(&cnt_buf, "{d}", .{matched}) catch "0";
    try self.replyNumeric(conn, .RPL_TESTMASK, &.{ mask, cnt }, "clients match");
}

pub fn handleOper(self: anytype, conn: anytype, _: anytype) !void {
    // OPER is disabled: Onyx Server grants operator status SASL-only. A client is
    // elevated automatically on SASL login when its account has an `[oper]`
    // binding (see elevateOperFromAccount). There is no password credential.
    try self.replyNumeric(conn, .ERR_NOOPERHOST, &.{}, "OPER is disabled; authenticate via SASL (operator status is granted on login)");
}

pub fn handleGrant(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!conn.session.hasPriv(.oper_grant)) {
        try self.replyNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied (oper_grant required)");
        return;
    }
    if (parsed.param_count < 2) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"GRANT"}, "Usage: GRANT <account> <class> [priv,priv,...]");
        return;
    }
    const account = parsed.paramSlice()[0];
    const class = parsed.paramSlice()[1];
    const priv_list = if (parsed.param_count >= 3) parsed.paramSlice()[2] else "";

    // Best-effort: verify the target is a registered account.
    if (self.account_services) |svc| {
        _ = svc.accountInfo(account) catch {
            try self.noticeTo(conn, "GRANT: no such registered account");
            return;
        };
    }
    const privs = Server.grantPrivileges(class, priv_list) orelse {
        try self.noticeTo(conn, "GRANT: unknown privilege name in list");
        return;
    };
    self.mintOperGrant(account, privs, class, "");
    self.persistGrants();

    var b: [256]u8 = undefined;
    try self.noticeTo(conn, std.fmt.bufPrint(
        &b,
        "GRANT: mesh display grant stored for {s} (class {s}); local session authority unchanged",
        .{ account, class },
    ) catch "GRANT: mesh display grant stored; local session authority unchanged");
}

pub fn handleRevoke(self: anytype, conn: anytype, parsed: anytype) !void {
    if (!conn.session.hasPriv(.oper_grant)) {
        try self.replyNumeric(conn, .ERR_NOPRIVILEGES, &.{}, "Permission denied (oper_grant required)");
        return;
    }
    if (parsed.param_count < 1) {
        try self.replyNumeric(conn, .ERR_NEEDMOREPARAMS, &.{"REVOKE"}, "Usage: REVOKE <account>");
        return;
    }
    const account = parsed.paramSlice()[0];
    if (self.oper_registry) |reg| {
        if (reg.lookup(account) != null) {
            try self.noticeTo(conn, "REVOKE: that account is a configured operator; edit [[opers]] and REHASH");
            return;
        }
    }
    self.mintOperGrant(account, oper_mod.OperPrivileges.empty, "revoked", "");
    self.persistGrants();
    var b: [256]u8 = undefined;
    try self.noticeTo(conn, std.fmt.bufPrint(&b, "REVOKE: mesh display grant tombstoned for {s}", .{account}) catch "REVOKE: mesh display grant tombstoned");
}

pub fn handleGrants(self: anytype, conn: anytype) !void {
    try self.noticeTo(conn, "Runtime operator grants:");
    const now: u64 = self.grantNowU64();
    var it = self.oper_grants.liveIterator(now);
    var count: usize = 0;
    while (it.next()) |g| {
        if (g.privilege_bits == 0) continue; // tombstones are not active grants
        count += 1;
        var b: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&b, "  {s}  class={s}  issuer={s}", .{ g.account, g.class, g.issuer_node }) catch continue;
        try self.noticeTo(conn, line);
    }
    var b: [64]u8 = undefined;
    try self.noticeTo(conn, std.fmt.bufPrint(&b, "End of grants ({d}).", .{count}) catch "End of grants.");
}

pub fn handleAudit(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .audit_read)) return;
    const params = parsed.paramSlice();
    if (params.len >= 1 and std.ascii.eqlIgnoreCase(params[0], "PROOF")) {
        var proof_argi: usize = 1;
        var json = false;
        if (params.len > proof_argi and std.ascii.eqlIgnoreCase(params[proof_argi], "JSON")) {
            json = true;
            proof_argi += 1;
        }
        if (params.len <= proof_argi) {
            try self.noticeTo(conn, "AUDIT PROOF: usage AUDIT PROOF [JSON] <proof-id>");
            return;
        }
        try self.handleAuditProof(conn, params[proof_argi], json);
        return;
    }
    var oper_filter: ?[]const u8 = null;
    var count: usize = 20;
    var json = false;
    var argi: usize = 0;
    if (params.len > argi and std.ascii.eqlIgnoreCase(params[argi], "JSON")) {
        json = true;
        argi += 1;
    }
    if (params.len > argi) {
        if (std.fmt.parseInt(usize, params[argi], 10)) |n| {
            count = std.math.clamp(n, 1, 200);
        } else |_| {
            oper_filter = params[argi];
            if (params.len > argi + 1) count = std.math.clamp(std.fmt.parseInt(usize, params[argi + 1], 10) catch 20, 1, 200);
        }
    }
    const entries = (if (oper_filter) |o|
        self.oper_audit.filterByOper(self.allocator, o, count)
    else
        self.oper_audit.recent(self.allocator, count)) catch {
        try self.noticeTo(conn, "AUDIT: temporarily unavailable");
        return;
    };
    defer self.allocator.free(entries);
    if (json) {
        var header: [512]u8 = undefined;
        var hw = std.Io.Writer.fixed(&header);
        try hw.print("{{\"type\":\"audit\",\"count\":{d},\"filter\":", .{entries.len});
        if (oper_filter) |filter| {
            try self.writeJsonText(&hw, filter);
        } else {
            try hw.writeAll("null");
        }
        try hw.writeByte('}');
        try self.appendAuditEventPayload(conn, hw.buffered());
        for (entries) |*e| self.appendAuditEntryJson(conn, e) catch continue;
        var end: [128]u8 = undefined;
        const end_payload = std.fmt.bufPrint(&end, "{{\"type\":\"audit-end\",\"count\":{d}}}", .{entries.len}) catch "{\"type\":\"audit-end\"}";
        try self.appendAuditEventPayload(conn, end_payload);
        return;
    }
    for (entries) |e| {
        var lb: [Server.reply_scratch_bytes]u8 = undefined;
        const tgt = if (e.target.len != 0) e.target else "-";
        const ln = if (e.proof_id.len != 0)
            std.fmt.bufPrint(&lb, ":{s} EVENT {s} AUDIT #{d} {s} {s} {s} proof={s} :{s}\r\n", .{ self.serverName(), conn.session.displayName(), e.seq, e.oper, e.action.label(), tgt, e.proof_id, e.reason }) catch continue
        else
            std.fmt.bufPrint(&lb, ":{s} EVENT {s} AUDIT #{d} {s} {s} {s} :{s}\r\n", .{ self.serverName(), conn.session.displayName(), e.seq, e.oper, e.action.label(), tgt, e.reason }) catch continue;
        try self.appendConnLine(conn, ln);
    }
    var eb: [128]u8 = undefined;
    const end = std.fmt.bufPrint(&eb, ":{s} EVENT {s} AUDIT End of audit ({d})\r\n", .{ self.serverName(), conn.session.displayName(), entries.len }) catch return;
    try self.appendConnLine(conn, end);
}

pub fn handleSpamtrap(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    const p = parsed.paramSlice();
    if (p.len < 1) {
        try self.noticeTo(conn, "Usage: SPAMTRAP <ADD|DEL> <NICK|CHAN> <target> | SPAMTRAP LIST");
        return;
    }
    if (std.ascii.eqlIgnoreCase(p[0], "LIST")) {
        self.spinLock(&self.spamtrap_mu);
        const nnick = self.spamtrap.trapNickCount();
        const nchan = self.spamtrap.trapChannelCount();
        const noff = self.spamtrap.offenderCount();
        const ntrips = self.spamtrap.totalTripCount();
        self.spamtrap_mu.unlock();
        var b: [Server.reply_scratch_bytes]u8 = undefined;
        const note = std.fmt.bufPrint(&b, "SPAMTRAP: {d} trap nick(s), {d} trap channel(s), {d} offender(s), {d} total trip(s)", .{ nnick, nchan, noff, ntrips }) catch return;
        try self.noticeTo(conn, note);
        return;
    }
    if (p.len < 3) {
        try self.noticeTo(conn, "Usage: SPAMTRAP <ADD|DEL> <NICK|CHAN> <target>");
        return;
    }
    const adding = std.ascii.eqlIgnoreCase(p[0], "ADD");
    const deleting = std.ascii.eqlIgnoreCase(p[0], "DEL") or
        std.ascii.eqlIgnoreCase(p[0], "DELETE") or std.ascii.eqlIgnoreCase(p[0], "REMOVE");
    if (!adding and !deleting) {
        try self.noticeTo(conn, "SPAMTRAP: subcommand must be ADD, DEL, or LIST");
        return;
    }
    const is_nick = std.ascii.eqlIgnoreCase(p[1], "NICK");
    const is_chan = std.ascii.eqlIgnoreCase(p[1], "CHAN") or std.ascii.eqlIgnoreCase(p[1], "CHANNEL");
    if (!is_nick and !is_chan) {
        try self.noticeTo(conn, "SPAMTRAP: target kind must be NICK or CHAN");
        return;
    }
    const target = p[2];
    self.spinLock(&self.spamtrap_mu);
    const res = if (adding)
        (if (is_nick) self.spamtrap.addTrapNick(target) else self.spamtrap.addTrapChannel(target))
    else
        (if (is_nick) self.spamtrap.removeTrapNick(target) else self.spamtrap.removeTrapChannel(target));
    self.spamtrap_active.store(self.spamtrap.trapNickCount() + self.spamtrap.trapChannelCount() > 0, .release);
    self.spamtrap_mu.unlock();

    res catch |err| {
        var eb: [160]u8 = undefined;
        const emsg = std.fmt.bufPrint(&eb, "SPAMTRAP: {s} failed ({s})", .{ p[0], @errorName(err) }) catch return;
        try self.noticeTo(conn, emsg);
        return;
    };
    self.snapshotSpamtraps();
    var b: [Server.reply_scratch_bytes]u8 = undefined;
    const note = std.fmt.bufPrint(&b, "SPAMTRAP {s} {s} {s}", .{ if (adding) "ADD" else "DEL", if (is_nick) "NICK" else "CHAN", target }) catch return;
    try self.publishOperEvent(.oper_action, .notice, note);
    try self.noticeTo(conn, note);
}

pub fn handleRehash(self: anytype, conn: anytype) !void {
    try rehashFromConn(self, conn, false);
}

pub fn handleRehashParsed(self: anytype, conn: anytype, parsed_line: anytype) !void {
    const dry = parsed_line.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed_line.paramSlice()[0], "DRY");
    try rehashFromConnWithClassAllocator(self, conn, dry, self.allocator);
}

/// Exposes the class-policy staging allocator to deterministic OOM tests.
/// Production command dispatch always passes the server allocator.
pub fn handleRehashParsedWithClassAllocator(
    self: anytype,
    conn: anytype,
    parsed_line: anytype,
    class_allocator: std.mem.Allocator,
) !void {
    const dry = parsed_line.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed_line.paramSlice()[0], "DRY");
    try rehashFromConnWithClassAllocator(self, conn, dry, class_allocator);
}

/// Capture the values consumed by this parse, rather than resolving a second
/// time after REHASH has already changed live state. Proof exhaustion only
/// disqualifies Helix; it does not change ordinary REHASH parsing semantics.
const WindowsRehashProof = struct {
    inner: config_format.Resolver,
    proof: *windows_config_proof.Builder,
    failed: bool = false,

    fn resolver(self: *WindowsRehashProof) config_format.Resolver {
        return .{
            .ctx = self,
            .env = if (self.inner.env != null) environment else null,
            .file = if (self.inner.file != null) file else null,
        };
    }

    fn environment(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
        const self: *WindowsRehashProof = @ptrCast(@alignCast(ctx.?));
        const value = try self.inner.env.?(self.inner.ctx, allocator, name);
        if (!self.failed) self.proof.recordEnvironment(name, value) catch {
            self.failed = true;
        };
        return value;
    }

    fn file(ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
        const self: *WindowsRehashProof = @ptrCast(@alignCast(ctx.?));
        const value = try self.inner.file.?(self.inner.ctx, allocator, path);
        if (!self.failed) self.proof.recordFile(path, value) catch {
            self.failed = true;
        };
        return value;
    }
};

/// Parse-local shadow resolver. The caller retains its collector and checks
/// failed even when a config field handles a lookup error internally. Neither
/// this resolver nor its stack context may escape the synchronous parse.
pub const ConfigEnvCapture = struct {
    inner: config_format.Resolver,
    collector: *helix_live.ConfigEnvCollector,
    failed: bool = false,
    pub fn resolver(self: *ConfigEnvCapture) config_format.Resolver {
        return .{ .ctx = self, .env = if (self.inner.env != null) environment else null, .file = if (self.inner.file != null) file else null };
    }
    fn environment(ctx: ?*anyopaque, a: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
        const self: *ConfigEnvCapture = @ptrCast(@alignCast(ctx.?));
        const value = try self.inner.env.?(self.inner.ctx, a, name);
        self.collector.record(name, value) catch |err| {
            self.failed = true;
            std.crypto.secureZero(u8, @constCast(value));
            a.free(value);
            return err;
        };
        return value;
    }
    fn file(ctx: ?*anyopaque, a: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
        const self: *ConfigEnvCapture = @ptrCast(@alignCast(ctx.?));
        return self.inner.file.?(self.inner.ctx, a, path);
    }
};

fn rehashFromConn(self: anytype, conn: anytype, dry: bool) !void {
    try rehashFromConnWithClassAllocator(self, conn, dry, self.allocator);
}

fn rehashFromConnWithClassAllocator(
    self: anytype,
    conn: anytype,
    dry: bool,
    class_allocator: std.mem.Allocator,
) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .server_rehash)) return;
    // Operator gate enforced by the registry (access=.oper).
    const path = self.config.config_path orelse {
        try self.replyNumeric(conn, .RPL_REHASHING, &.{"onyx_server.conf"}, "No config file; nothing to reload");
        return;
    };
    const io = self.config.crypto_io orelse {
        try self.replyNumeric(conn, .RPL_REHASHING, &.{path}, "No I/O available; cannot reload");
        return;
    };
    const proof_candidate = if (comptime builtin.os.tag == .windows and @hasField(Server, "windows_helix_source_valid"))
        self.windows_helix_source_valid.load(.acquire) and
            self.config.windows_helix_raw_source_digest != null and
            self.config.windows_helix_static_material_digest != null and
            self.config.windows_helix_boot_parsed != null and
            self.config.native_upgrade_hooks != null and
            self.config.native_upgrade_hooks.?.setSourceDigest != null
    else
        false;
    const canonical_path: ?[:0]u8 = if (proof_candidate)
        std.Io.Dir.cwd().realPathFileAlloc(io, path, self.allocator) catch null
    else
        null;
    defer if (canonical_path) |canonical| self.allocator.free(canonical);
    const source_path = if (canonical_path) |canonical| canonical else path;
    const text = std.Io.Dir.cwd().readFileAlloc(io, source_path, self.allocator, .limited(config_format.max_config_bytes)) catch {
        try self.noticeTo(conn, "REHASH: cannot read config file");
        return;
    };
    defer self.allocator.free(text);

    var proof: ?windows_config_proof.Builder = if (canonical_path) |canonical|
        windows_config_proof.Builder.initCanonical(canonical, text) catch null
    else
        null;
    defer if (proof) |*p| p.deinit();
    var capture: ?WindowsRehashProof = null;
    var parse_resolver = self.config.config_resolver;
    if (proof) |*p| {
        capture = .{ .inner = parse_resolver, .proof = p };
        parse_resolver = (&capture.?).resolver();
    }
    var env_collector = helix_live.ConfigEnvCollector.init(self.allocator);
    defer env_collector.deinit();
    var env_capture = ConfigEnvCapture{ .inner = parse_resolver, .collector = &env_collector };
    const recorded_resolver = env_capture.resolver();
    const resolved = if (comptime helix_live.supportsBootPolicyOn(builtin.os.tag)) recorded_resolver else parse_resolver;
    var parsed = config_format.parseToml(self.allocator, text, resolved) catch |err| {
        // Report the specific parse failure (InvalidSyntax/DuplicateKey/...)
        // so the operator can fix the file rather than guess.
        var reason_buf: [96]u8 = undefined;
        const notice = std.fmt.bufPrint(&reason_buf, "REHASH: config parse error ({s}); keeping current config", .{@errorName(err)}) catch "REHASH: config parse error; keeping current config";
        try self.noticeTo(conn, notice);
        return;
    };
    if (env_capture.failed) {
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: invalid config environment; keeping current config");
        return;
    }
    if (Server.ocg2RehashHasUnsupportedRuntimeMode(parsed.oper_ocg2)) {
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: OCG2 project/mint mode is unsupported by this release; keeping current config");
        return;
    }
    if (!retired_fences.same(self.config.retired_session_group_fences, parsed.mesh.retired_session_group_fences)) {
        self.noticeTo(conn, "REHASH: retired session fence policy changes require a validated cold maintenance transition; current policy is unchanged") catch |err| {
            parsed.deinit(self.allocator);
            return err;
        };
        if (!dry) {
            parsed.deinit(self.allocator);
            return;
        }
    }
    // [resources] stay at boot values; a class or max_clients change that the
    // boot memory budget cannot hold is refused before any commit.
    const next_per_client = config_boot.rehashResourcePerClientBytes(
        self.config.resource_memory_budget_bytes,
        self.config.resource_per_client_override_bytes,
        self.config.max_clients,
        parsed,
    );
    if (next_per_client == null) {
        self.noticeTo(conn, "REHASH: [resources].memory_budget_bytes cannot hold limits.max_clients at the new per-client commitment; keeping current config") catch |err| {
            parsed.deinit(self.allocator);
            return err;
        };
        if (!dry) {
            parsed.deinit(self.allocator);
            return;
        }
    }
    if (dry) {
        defer parsed.deinit(self.allocator);
        try self.emitRehashDry(conn, path, &parsed, text);
        return;
    }
    // Stage the applied-text snapshot before the first fallible preparation so
    // the commit below is a no-fail pointer swap.
    var next_applied: ?[]u8 = self.allocator.dupe(u8, text) catch {
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: out of memory; keeping current config");
        return;
    };
    defer if (next_applied) |bytes| {
        std.crypto.secureZero(u8, bytes);
        self.allocator.free(bytes);
    };
    var next_boot_policy: ?helix_live.OwnedBootPolicy = if (comptime helix_live.supportsBootPolicyOn(builtin.os.tag)) helix_live.OwnedBootPolicy.init(self.allocator, .{
        .strict_existing_identity = self.config.helix_boot_policy.strict_existing_identity,
        .config_env = env_collector.view(),
    }) catch {
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: cannot retain config environment; keeping current config");
        return;
    } else null;
    defer if (next_boot_policy) |*policy| policy.deinit();
    // Build the new oper bindings (strings borrow `parsed`, kept alive below).
    const bindings = self.operBindingsFromConfig(parsed) catch {
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: out of memory; keeping current config");
        return;
    };
    const new_registry: ?oper_mod.OperRegistry = if (bindings.len != 0)
        (oper_mod.OperRegistry.init(bindings) catch {
            self.allocator.free(bindings);
            parsed.deinit(self.allocator);
            try self.noticeTo(conn, "REHASH: invalid oper bindings; keeping current config");
            return;
        })
    else
        null;

    var proven_source: ?windows_config_proof.Digest = null;
    if (capture) |*recorded| {
        if (!recorded.failed) {
            if (proof) |*p| {
                if (p.finish()) |actual| {
                    proven_source = actual;
                } else |_| {}
            }
        }
    }
    const rebind_live_source = proof_candidate and proven_source != null and
        Server.windowsRehashEligibleParsed(self.config.windows_helix_boot_parsed.?, &parsed) and
        Server.windowsRehashIpCapSafe(self.config.max_clones_per_ip, parsed.limits.max_clones_per_ip);

    // The existing command lane excludes module readers on every shard. Keep
    // it through prepare + the nonfallible config/module publication, including
    // detached administrative callers that did not enter via a completion.
    const acquired_module_lane = self.lockModulePolicy();
    defer self.unlockModulePolicy(acquired_module_lane);
    if (comptime helix_live.supportsBootPolicyOn(builtin.os.tag)) self.validateRehashBootIdentity(&parsed, next_boot_policy.?.borrow()) catch {
        self.allocator.free(bindings);
        parsed.deinit(self.allocator);
        try self.noticeTo(conn, "REHASH: node identity or realm requires cold maintenance; keeping current config");
        return;
    };
    self.prepareModuleReload(&parsed) catch |err| {
        self.allocator.free(bindings);
        parsed.deinit(self.allocator);
        var reason: [256]u8 = undefined;
        try self.noticeTo(conn, std.fmt.bufPrint(&reason, "REHASH: module preparation failed ({s}); keeping current config", .{@errorName(err)}) catch "REHASH: module preparation failed; keeping current config");
        return;
    };
    defer _ = self.module_runtime.abortReload();
    // Prepare connection policy before publishing any parsed config, operator
    // binding, limit, or Windows source-proof state. The class Builder and the
    // policy rollback snapshot share the injected allocator boundary; OOM here
    // leaves the active REHASH generation untouched.
    self.applyReloadedLimitsWithClassAllocator(&parsed, class_allocator) catch |err| {
        self.allocator.free(bindings);
        parsed.deinit(self.allocator);
        const note = if (err == error.OutOfMemory)
            "REHASH: out of memory; keeping current config"
        else
            "REHASH: invalid connection class policy; keeping current config";
        try self.noticeTo(conn, note);
        return;
    };

    // Commit: replace the previous reloaded generation, then point the live
    // registry at the new bindings. `parsed`'s strings (incl. the TLS cert/key
    // paths consulted just below) now live in `self.reload_parsed`.
    // No fallible preparation remains. Only a narrow, monotonic per-IP clone
    // cap increase can rebind the Windows source proof below. HXTM carries the
    // exact serving TLS generation and HXWM carries WASM state.
    if (comptime builtin.os.tag == .windows and @hasField(Server, "windows_helix_source_valid"))
        self.windows_helix_source_valid.store(false, .release);
    self.allocator.free(self.reload_bindings);
    if (self.reload_parsed) |*p| p.deinit(self.allocator);
    self.reload_parsed = parsed;
    self.config.resource_per_client_bytes = next_per_client.?;
    if (comptime helix_live.supportsBootPolicyOn(builtin.os.tag)) {
        var previous_boot_policy = self.reload_boot_policy;
        self.reload_boot_policy = next_boot_policy.?;
        next_boot_policy = null;
        self.config.helix_boot_policy = self.reload_boot_policy.?.borrow();
        if (previous_boot_policy) |*policy| policy.deinit();
    }
    self.reload_bindings = bindings;
    self.oper_registry = new_registry;

    self.module_runtime.commitReload() catch unreachable;

    // Cert hot-reload: re-read the cert/key material from the reloaded paths
    // and atomically swap the live `config.tls_*` fields so NEW TLS handshakes
    // present the rotated leaf. Established sessions are untouched (no
    // renegotiation). Any failure keeps the current certs and only NOTICEs.
    var tls_reload_failed = false;
    const tls_outcome = self.reloadTlsCertsForRehash(io, &self.reload_parsed.?.tls, rebind_live_source) catch |err| blk: {
        tls_reload_failed = true;
        var ebuf: [Server.reply_scratch_bytes]u8 = undefined;
        const msg = std.fmt.bufPrint(&ebuf, "REHASH: TLS cert reload failed ({s}); keeping current certificates", .{@errorName(err)}) catch "REHASH: TLS cert reload failed; keeping current certificates";
        try self.noticeTo(conn, msg);
        break :blk Server.TlsReloadOutcome.kept;
    };
    // The preview baseline advances only when the whole file took effect. After
    // a kept-certificate failure the previous text remains: the serving
    // certificate generation still matches it, and a retry still shows tls.*.
    if (!tls_reload_failed) {
        if (self.applied_config_text) |previous| {
            std.crypto.secureZero(u8, previous);
            self.allocator.free(previous);
        }
        self.applied_config_text = next_applied;
        next_applied = null;
    }

    // Rotate the session-ticket key: the current key becomes PREVIOUS (so
    // tickets issued before this REHASH still resume for one more window) and
    // a fresh current key is generated. No-op when resumption is off.
    if (self.config.tls_enable_resumption) self.rotateTicketKey();

    // OCG2 owns a process-lifetime durable State + observer and cannot be
    // rebuilt transactionally by this partial live reload. Be explicit
    // whenever either the running process or the newly parsed file carries
    // OCG2 intent; accepting the rest of REHASH must never imply that its
    // authority tuple or activation stage changed live.
    if (Server.ocg2RehashHasRestartOnlyIntent(self.ocg2_runtime != null, self.reload_parsed.?.oper_ocg2))
        try self.noticeTo(conn, "REHASH: [oper.ocg2] settings are restart-only and were not applied");

    var note_buf: [Server.reply_scratch_bytes]u8 = undefined;
    const note = std.fmt.bufPrint(
        &note_buf,
        "Configuration reloaded ({d} oper bindings; {s})",
        .{ bindings.len, tls_outcome.note() },
    ) catch "Configuration reloaded";
    try self.replyNumeric(conn, .RPL_REHASHING, &.{path}, note);
    if (comptime builtin.os.tag == .windows and @hasField(Server, "windows_helix_source_valid")) {
        if (rebind_live_source and tls_outcome != .kept) {
            const source = proven_source.?;
            // A no-op source reload keeps the existing effective commitment,
            // including the legacy v1 form accepted by older compatible images.
            // HXTM separately carries any newly serving TLS generation.
            if (!std.crypto.timing_safe.eql(
                windows_config_proof.Digest,
                source,
                self.config.windows_helix_raw_source_digest.?,
            )) {
                const effective = windows_config_proof.rebaseEffectiveDigest(
                    source,
                    self.config.windows_helix_static_material_digest.?,
                );
                const hooks = self.config.native_upgrade_hooks.?;
                hooks.setSourceDigest.?(hooks.ctx, effective);
                self.config.windows_helix_raw_source_digest = source;
                self.config.windows_helix_source_digest = effective;
            }
            self.windows_helix_source_valid.store(true, .release);
        }
    }
}

pub fn handleMesh(self: anytype, conn: anytype, parsed: anytype) !void {
    const Server = @TypeOf(self.*);
    // `MESH LOG` renders the recent mesh-event audit ring instead of peers.
    if (parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "LOG")) {
        var body_buf: [8192]u8 = undefined;
        var lw = std.Io.Writer.fixed(&body_buf);
        mesh_event_log.render(&self.mesh_log, &lw) catch {};
        var lines = std.mem.splitScalar(u8, lw.buffered(), '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try self.noticeTo(conn, line);
        }
        return;
    }
    // `MESH ADMISSION` exposes the MeshPass security posture without leaking
    // shared-secret or signed-token bytes.
    if (parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "ADMISSION")) {
        var b: [Server.reply_scratch_bytes]u8 = undefined;
        const relay_v2_roster_digest = std.fmt.bytesToHex(
            self.relay_v2_activation_state.roster_digest,
            .lower,
        );
        const line = std.fmt.bufPrint(&b, "admission mode={s} secured_s2s={s} require_secured={s} require_signed_frames={s} roots={d} token_present={s} min_revocation_epoch={d} relay_v2_bridge_implemented=true relay_v2_authoring={s} relay_v2_eligible={s} relay_v2_epoch={d} relay_v2_roster_count={d} relay_v2_roster_digest={s}", .{
            self.meshAdmissionMode(),
            if (self.s2sSecured()) "true" else "false",
            if (self.config.require_secured) "true" else "false",
            if (self.config.s2s_config.require_signed_frames) "true" else "false",
            self.meshpass_roots.len,
            if (self.mesh_admission_token.len != 0) "true" else "false",
            self.config.mesh_admission_min_revocation_epoch,
            @tagName(self.relay_v2_activation_state.mode),
            if (self.authoredRelayV2Configured()) "true" else "false",
            self.relay_v2_activation_state.activation_epoch,
            self.config.relay_v2_roster.len,
            if (self.relay_v2_activation_state.activation_epoch == 0)
                "none"
            else
                &relay_v2_roster_digest,
        }) catch "admission status unavailable";
        try self.noticeTo(conn, line);
        if (self.meshpass_roots.len != 0 and !self.s2sSecured()) {
            try self.noticeTo(conn, "admission warning: signed MeshPass roots require secured S2S identity and crypto");
        }
        return;
    }
    // `MESH GRANTS` lists the cross-mesh operator grants this node currently
    // recognizes (account, class, title, issuer, remaining TTL).
    if (parsed.param_count >= 1 and std.ascii.eqlIgnoreCase(parsed.paramSlice()[0], "GRANTS")) {
        const now: u64 = self.grantNowU64();
        var it = self.oper_grants.liveIterator(now);
        var any = false;
        var lb: [Server.reply_scratch_bytes]u8 = undefined;
        while (it.next()) |g| {
            any = true;
            const ttl_s: u64 = if (g.expiry_ms > now) (g.expiry_ms - now) / 1000 else 0;
            const line = std.fmt.bufPrint(&lb, "grant account={s} class={s} title={s} issuer={s} ttl={d}s", .{ g.account, g.class, g.title, g.issuer_node, ttl_s }) catch continue;
            try self.noticeTo(conn, line);
        }
        if (!any) try self.noticeTo(conn, "no cross-mesh operator grants recognized");
        return;
    }

    var peers: std.ArrayList(mesh_report.PeerLink) = .empty;
    defer peers.deinit(self.allocator);
    var it = self.rx().clients.iterator();
    while (it.next()) |entry| {
        const c = entry.value;
        // Reflect both plaintext and secured S2S links as mesh peers.
        var name: []const u8 = "";
        var established = false;
        if (c.s2s) |link| {
            name = link.remoteName();
            established = link.established();
        } else if (c.s2s_secured) |link| {
            name = link.remoteName();
            established = link.established();
        } else continue;
        if (name.len == 0) continue;
        self.notePeerSendBacklog(name, self.sendBacklogOf(c));
        var peer = mesh_report.PeerLink{
            .name = name,
            .state = if (established) .established else .handshaking,
            .hops = 1,
        };
        // Enrich with live link health (rtt, bytes, time-in-state) when known.
        if (self.peer_health.get(name)) |h| {
            const now: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
            peer.rtt_ms = h.snapshotRtt();
            peer.bytes_in = h.bytes_in;
            peer.bytes_out = h.bytes_out;
            const now_unix = @divTrunc(platform.realtimeMillis(), 1000);
            peer.since_unix = now_unix - @as(i64, @intCast(h.since(now) / 1000));
        }
        try peers.append(self.allocator, peer);
    }

    var established_peers: u32 = 0;
    for (peers.items) |p| {
        if (p.state == .established) established_peers += 1;
    }

    // Reachability/partition over the multi-hop mesh: assemble the topology
    // from each established peer's gossiped registry plus an explicit
    // local<->peer edge per direct link, then run the partition detector from
    // this node's perspective. Falls back to the direct-peer count when no
    // node identity is configured (single-node / unsigned mesh).
    var reachable_nodes: u32 = established_peers + 1;
    var partitioned_nodes: u32 = 0;
    var mesh_partitioned = false;
    if (self.config.node_identity) |ident| {
        const local_id = ident.shortId();
        var topo: [partition_detector.max_nodes]partition_detector.TopoNode = undefined;
        const tn = self.assembleMeshTopology(local_id, &topo);
        const stats = partition_detector.analyze(local_id, topo[0..tn]);
        reachable_nodes = @intCast(stats.reachable);
        partitioned_nodes = @intCast(stats.partitioned);
        mesh_partitioned = stats.is_partitioned;
    }

    const snap = mesh_report.MeshSnapshot{
        .local_node = protocol_inventory.currentServerName(),
        .peers = peers.items,
        .reachable_nodes = reachable_nodes,
        .partitioned_nodes = partitioned_nodes,
    };

    var body = std.Io.Writer.Allocating.init(self.allocator);
    defer body.deinit();
    mesh_report.renderMesh(snap, &body.writer) catch {};
    try self.noticeBody(conn, body.writer.buffered());

    var facts: std.ArrayList(u8) = .empty;
    defer facts.deinit(self.allocator);
    try self.peer_health.writeOperView(self.allocator, &facts);
    try self.noticeBody(conn, facts.items);

    // Split-brain summary: a strict majority of known nodes reachable from
    // here holds quorum (reachable > partitioned). Operators read this to
    // tell an intact mesh from a minority island they should not act on.
    const known_total = reachable_nodes + partitioned_nodes;
    const has_quorum = reachable_nodes > partitioned_nodes;
    var sb: [Server.reply_scratch_bytes]u8 = undefined;
    const status = if (!mesh_partitioned)
        "intact"
    else if (has_quorum)
        "PARTITIONED (quorum held)"
    else
        "PARTITIONED (NO QUORUM - minority island)";
    const summary = std.fmt.bufPrint(&sb, "mesh {s}: {d}/{d} nodes reachable", .{ status, reachable_nodes, known_total }) catch return;
    try self.noticeTo(conn, summary);
}

pub fn handleRoute(self: anytype, conn: anytype) !void {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(self.allocator);
    try self.collectPeerNames(&names);
    var routes: std.ArrayList(route_report.RouteEntry) = .empty;
    defer routes.deinit(self.allocator);
    try routes.append(self.allocator, .{ .dest = protocol_inventory.currentServerName(), .next_hop = "", .distance = 0, .reachable = true });
    for (names.items) |name| {
        try routes.append(self.allocator, .{ .dest = name, .next_hop = name, .distance = 1, .reachable = true });
    }
    const snap = route_report.RouteSnapshot{ .local_node = protocol_inventory.currentServerName(), .routes = routes.items };
    var body = std.Io.Writer.Allocating.init(self.allocator);
    defer body.deinit();
    route_report.renderRoutes(snap, &body.writer) catch {};
    try self.noticeBody(conn, body.writer.buffered());
}

pub fn handleNethealth(self: anytype, conn: anytype) !void {
    const Server = @TypeOf(self.*);
    const now: u64 = @intCast(@max(@as(i64, 0), self.nowMs()));
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(self.allocator);
    try self.collectPeerNames(&names);
    var nodes: std.ArrayList(ripple_report.NodeStatus) = .empty;
    defer nodes.deinit(self.allocator);
    try nodes.append(self.allocator, .{ .node = protocol_inventory.currentServerName(), .health = .alive, .last_ack_ms_ago = 0 });
    for (names.items) |name| {
        var rtt: u32 = 0;
        var idle: u64 = 0;
        if (self.peer_health.get(name)) |h| {
            rtt = h.snapshotRtt();
            idle = h.idleMs(now);
        }
        try nodes.append(self.allocator, .{ .node = name, .health = .alive, .last_ack_ms_ago = idle, .rtt_ms = rtt });
    }
    const snap = ripple_report.HealthSnapshot{ .local_node = protocol_inventory.currentServerName(), .nodes = nodes.items };
    var body = std.Io.Writer.Allocating.init(self.allocator);
    defer body.deinit();
    ripple_report.renderHealth(snap, &body.writer) catch {};
    try self.noticeBody(conn, body.writer.buffered());
    // Quorum/partition summary from the live transition tracker (consumes the
    // persistent `partition_quorum` / `partition_components` signals so opers
    // can tell a healthy mesh from a minority island this node sits in).
    var qb: [Server.reply_scratch_bytes]u8 = undefined;
    const quorum_status = if (self.partition_split)
        (if (self.meshHasQuorum()) "PARTITIONED (quorum held — majority side)" else "PARTITIONED (NO QUORUM — minority partition, degraded)")
    else
        "intact (quorum held)";
    const qline = std.fmt.bufPrint(&qb, "quorum: {s}; {d} mesh component(s)", .{ quorum_status, self.partition_components }) catch return;
    try self.noticeTo(conn, qline);
}

test "UNREJECT mapped IPv6 addresses clear the same IPv4 reputation key" {
    const rep_mod = @import("ip_reputation.zig");
    const testing = std.testing;
    var rep = try rep_mod.IpReputation.init(testing.allocator, .{});
    defer rep.deinit();
    const ipv4 = unrejectAddress("198.51.100.153") orelse return error.TestUnexpectedResult;
    const hex = unrejectAddress("::ffff:c633:6499") orelse return error.TestUnexpectedResult;
    const dotted = unrejectAddress("::ffff:198.51.100.153") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(ipv4, hex);
    try testing.expectEqual(ipv4, dotted);
    _ = try rep.penalize(ipv4, 25, 0);
    try testing.expect(rep.clear(hex));
    _ = try rep.penalize(ipv4, 25, 0);
    try testing.expect(rep.clear(dotted));
    const ipv6 = unrejectAddress("2001:db8::1") orelse return error.TestUnexpectedResult;
    try testing.expect(ipv6 == .ipv6);
    _ = try rep.penalize(ipv6, 25, 0);
    try testing.expect(!rep.clear(ipv4));
    try testing.expect(rep.clear(ipv6));
    for ([_][]const u8{ "", "::ffff:198.51.100.999", "::ffff:198.51.100.153junk", "::ffff:198.51.100.153%1", "2001::db8::1", "198.51.100.153:42" }) |bad| {
        try testing.expect(unrejectAddress(bad) == null);
    }
}

test "DEBUG flight recorder dump never emits a canary bearer token" {
    const testing = std.testing;
    const canary = "sst_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    const FakeRecorder = struct {
        event: tracelog.RecordedEvent,

        pub fn dump(self: *const @This(), out: []tracelog.RecordedEvent) []const tracelog.RecordedEvent {
            out[0] = self.event;
            return out[0..1];
        }
    };

    const FakeServer = struct {
        trace_recorder: FakeRecorder,
        notices: std.ArrayList([]const u8) = .empty,
        allocator: std.mem.Allocator,

        pub fn requirePriv(self: *@This(), conn: anytype, cap: anytype) bool {
            _ = self;
            _ = conn;
            _ = cap;
            return true;
        }

        pub fn noticeTo(self: *@This(), conn: anytype, text: []const u8) !void {
            _ = conn;
            try self.notices.append(self.allocator, try self.allocator.dupe(u8, text));
        }
    };

    const allocator = testing.allocator;
    var fake = FakeServer{
        .trace_recorder = .{
            .event = tracelog.RecordedEvent.fromEvent(.{
                .level = .err,
                .category = .auth,
                .ts_mono_ns = 0,
                .hlc = 0,
                .msg = "token leak check: " ++ canary,
            }),
        },
        .allocator = allocator,
    };
    defer {
        for (fake.notices.items) |n| allocator.free(n);
        fake.notices.deinit(allocator);
    }

    try handleDebug(&fake, @as(u8, 0), .{ .param_count = @as(usize, 0) });

    try testing.expect(fake.notices.items.len >= 1);
    for (fake.notices.items) |n| {
        try testing.expect(std.mem.indexOf(u8, n, canary) == null);
    }
}
