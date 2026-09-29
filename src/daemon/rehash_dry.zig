// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `REHASH DRY` diff. Compares a parsed config with the running image and
//! returns notice lines. The caller prints them and must not commit the parse.
const std = @import("std");
const config_format = @import("config_format.zig");
const conn_class = @import("conn_class.zig");
const warden = @import("warden.zig");

pub const LimitSnap = struct {
    max_clones_per_ip: u64 = 0,
    max_clones_per_net: u64 = 0,
    max_clones_per_ip_net: u64 = 0,
    nick_delay_ms: u64 = 0,
    throttle_connects: u64 = 0,
    throttle_window_ms: u64 = 0,
    raid_joins: u64 = 0,
    raid_secs: u64 = 0,
};

pub const Input = struct {
    live_limits: LimitSnap = .{},
    proposed_limits: LimitSnap = .{},
    live_classes: []const conn_class.Class = &.{},
    proposed_classes: []const conn_class.Class = &.{},
    /// The proposed `[class.*]` table could not be built. No class commit happens.
    class_rejected: bool = false,
    live_dnsbl_ward: bool = false,
    proposed_dnsbl_ward: bool = false,
    running_wards: []const warden.Ward = &.{},
    live_listeners: config_format.ListenerSet = .{},
    proposed_listeners: config_format.ListenerSet = .{},
};

pub fn freeReport(allocator: std.mem.Allocator, lines: [][]u8) void {
    for (lines) |line| allocator.free(line);
    allocator.free(lines);
}

/// Owned notice bodies. The first line is always `REHASH DRY: applied none`.
/// A listener mismatch includes `config_format.cold_restart_required_reason`
/// as its own line. No line contains CR or LF.
pub fn report(allocator: std.mem.Allocator, in: Input) ![][]u8 {
    var lines: std.ArrayList([]u8) = .empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }
    try pushLiteral(allocator, &lines, "REHASH DRY: applied none");
    try appendWards(allocator, &lines, in);
    try appendClasses(allocator, &lines, in);
    try appendLimits(allocator, &lines, in);
    try appendListeners(allocator, &lines, in);
    return try lines.toOwnedSlice(allocator);
}

fn pushLiteral(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), text: []const u8) !void {
    const line = try allocator.dupe(u8, text);
    lines.append(allocator, line) catch |err| {
        allocator.free(line);
        return err;
    };
}

fn pushFmt(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), comptime fmt: []const u8, args: anytype) !void {
    const line = try std.fmt.allocPrint(allocator, fmt, args);
    lines.append(allocator, line) catch |err| {
        allocator.free(line);
        return err;
    };
}

fn wardAction(on: bool) []const u8 {
    return if (on) "ward" else "refuse";
}

fn appendWards(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), in: Input) !void {
    if (in.live_dnsbl_ward != in.proposed_dnsbl_ward) {
        try pushFmt(allocator, lines, "REHASH DRY ward dnsbl.action: {s} -> {s}", .{
            wardAction(in.live_dnsbl_ward),
            wardAction(in.proposed_dnsbl_ward),
        });
    }
    for (in.running_wards) |row| {
        if (std.mem.indexOfAny(u8, row.pattern, "\r\n") != null) {
            try pushFmt(allocator, lines, "REHASH DRY ward running {s} <control> kept", .{row.match.token()});
            continue;
        }
        try pushFmt(allocator, lines, "REHASH DRY ward running {s} {s} kept", .{ row.match.token(), row.pattern });
    }
    if (in.live_dnsbl_ward == in.proposed_dnsbl_ward and in.running_wards.len == 0) {
        try pushLiteral(allocator, lines, "REHASH DRY ward: unchanged");
    }
}

fn findClass(classes: []const conn_class.Class, name: []const u8) ?*const conn_class.Class {
    for (classes) |*row| {
        if (std.ascii.eqlIgnoreCase(row.name, name)) return row;
    }
    return null;
}

fn classIdentical(a: *const conn_class.Class, b: *const conn_class.Class) bool {
    return std.meta.eql(a.policy, b.policy) and
        a.tls_only == b.tls_only and
        a.account_only == b.account_only and
        a.oper_only == b.oper_only and
        a.cidrs.len == b.cidrs.len and
        optionalEql(a.ident_glob, b.ident_glob) and
        optionalEql(a.host_glob, b.host_glob);
}

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn appendClasses(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), in: Input) !void {
    if (in.class_rejected) {
        try pushLiteral(allocator, lines, "REHASH DRY class: proposed registry rejected");
        return;
    }
    var changes: usize = 0;
    for (in.proposed_classes) |*row| {
        const live = findClass(in.live_classes, row.name) orelse {
            try pushFmt(allocator, lines, "REHASH DRY class +{s} sendq={d}", .{ row.name, row.policy.sendq });
            changes += 1;
            continue;
        };
        if (classIdentical(live, row)) continue;
        changes += 1;
        if (live.policy.sendq != row.policy.sendq) {
            try pushFmt(allocator, lines, "REHASH DRY class {s} sendq {d} -> {d}", .{
                row.name,
                live.policy.sendq,
                row.policy.sendq,
            });
        } else {
            try pushFmt(allocator, lines, "REHASH DRY class {s} changed", .{row.name});
        }
    }
    for (in.live_classes) |*row| {
        if (findClass(in.proposed_classes, row.name) != null) continue;
        try pushFmt(allocator, lines, "REHASH DRY class -{s}", .{row.name});
        changes += 1;
    }
    if (changes == 0) try pushLiteral(allocator, lines, "REHASH DRY class: unchanged");
}

const limit_fields = [_][]const u8{
    "max_clones_per_ip",
    "max_clones_per_net",
    "max_clones_per_ip_net",
    "nick_delay_ms",
    "throttle_connects",
    "throttle_window_ms",
    "raid_joins",
    "raid_secs",
};

fn limitValue(snap: LimitSnap, name: []const u8) u64 {
    return switch (name[0]) {
        'm' => if (std.mem.eql(u8, name, "max_clones_per_ip"))
            snap.max_clones_per_ip
        else if (std.mem.eql(u8, name, "max_clones_per_net"))
            snap.max_clones_per_net
        else
            snap.max_clones_per_ip_net,
        'n' => snap.nick_delay_ms,
        't' => if (std.mem.eql(u8, name, "throttle_connects"))
            snap.throttle_connects
        else
            snap.throttle_window_ms,
        'r' => if (std.mem.eql(u8, name, "raid_joins")) snap.raid_joins else snap.raid_secs,
        else => 0,
    };
}

fn appendLimits(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), in: Input) !void {
    var changes: usize = 0;
    for (limit_fields) |name| {
        const live = limitValue(in.live_limits, name);
        const proposed = limitValue(in.proposed_limits, name);
        if (live == proposed) continue;
        try pushFmt(allocator, lines, "REHASH DRY limit {s}: {d} -> {d}", .{ name, live, proposed });
        changes += 1;
    }
    if (changes == 0) try pushLiteral(allocator, lines, "REHASH DRY limit: unchanged");
}

fn appendListeners(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), in: Input) !void {
    const pairs = [_]struct { []const u8, u16, u16 }{
        .{ "irc", in.live_listeners.irc, in.proposed_listeners.irc },
        .{ "tls", in.live_listeners.tls, in.proposed_listeners.tls },
        .{ "ws", in.live_listeners.ws, in.proposed_listeners.ws },
        .{ "webtransport", in.live_listeners.webtransport, in.proposed_listeners.webtransport },
        .{ "s2s", in.live_listeners.s2s, in.proposed_listeners.s2s },
        .{ "media", in.live_listeners.media, in.proposed_listeners.media },
        .{ "native_media", in.live_listeners.native_media, in.proposed_listeners.native_media },
    };
    var changes: usize = 0;
    for (pairs) |pair| {
        if (pair[1] == pair[2]) continue;
        try pushFmt(allocator, lines, "REHASH DRY listener {s}: {d} -> {d}", .{ pair[0], pair[1], pair[2] });
        changes += 1;
    }
    if (changes == 0) {
        try pushLiteral(allocator, lines, "REHASH DRY listener: unchanged");
        return;
    }
    try pushLiteral(allocator, lines, config_format.cold_restart_required_reason);
}
