// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure renderer for the NETHEALTH Sazanami failure-detector view.
//!
//! The caller owns all live daemon state. This module only formats a plain
//! snapshot into text through a supplied writer.

const std = @import("std");

pub const NodeHealth = enum { alive, suspect, dead, left };

pub const NodeStatus = struct {
    node: []const u8,
    health: NodeHealth,
    incarnation: u64 = 0,
    last_ack_ms_ago: u64 = 0,
    rtt_ms: u32 = 0,
};

pub const HealthSnapshot = struct {
    local_node: []const u8,
    nodes: []const NodeStatus,
    witnesses: []const []const u8 = &.{},
    probe_period_ms: u32 = 0,
};

pub fn healthWord(h: NodeHealth) []const u8 {
    return switch (h) {
        .alive => "alive",
        .suspect => "suspect",
        .dead => "dead",
        .left => "left",
    };
}

pub fn formatAge(buf: []u8, ms: u64) []const u8 {
    if (ms < 1_000) {
        return std.fmt.bufPrint(buf, "{d}ms", .{ms}) catch "";
    }

    if (ms < 60_000) {
        const tenths = ms / 100;
        const secs = tenths / 10;
        const frac = tenths % 10;
        if (frac == 0) {
            return std.fmt.bufPrint(buf, "{d}s", .{secs}) catch "";
        }
        return std.fmt.bufPrint(buf, "{d}.{d}s", .{ secs, frac }) catch "";
    }

    if (ms < 3_600_000) {
        return std.fmt.bufPrint(buf, "{d}m", .{ms / 60_000}) catch "";
    }

    if (ms < 86_400_000) {
        return std.fmt.bufPrint(buf, "{d}h", .{ms / 3_600_000}) catch "";
    }

    return std.fmt.bufPrint(buf, "{d}d", .{ms / 86_400_000}) catch "";
}

pub fn renderHealth(snap: HealthSnapshot, writer: anytype) !void {
    var alive: usize = 0;
    var suspect: usize = 0;
    var dead: usize = 0;
    var max_node_width: usize = "Node".len;
    var max_health_width: usize = "Health".len;

    for (snap.nodes) |node| {
        switch (node.health) {
            .alive => alive += 1,
            .suspect => suspect += 1,
            .dead => dead += 1,
            .left => {},
        }
        max_node_width = @max(max_node_width, node.node.len);
        max_health_width = @max(max_health_width, healthWord(node.health).len);
    }

    var period_buf: [24]u8 = undefined;
    const period = formatAge(&period_buf, snap.probe_period_ms);

    try writer.writeAll("NETHEALTH\n");
    try writer.print("Local node: {s}\n", .{snap.local_node});
    try writer.print("Probe period: {s}\n", .{period});
    try writer.print("Counts: {d} alive / {d} suspect / {d} dead\n", .{ alive, suspect, dead });
    try writer.writeAll("\n");

    try writePadded(writer, "Node", max_node_width);
    try writer.writeAll("  ");
    try writePadded(writer, "Health", max_health_width);
    try writer.writeAll("  Incarnation  Last ack  RTT\n");
    try writeRepeat(writer, '-', max_node_width);
    try writer.writeAll("  ");
    try writeRepeat(writer, '-', max_health_width);
    try writer.writeAll("  -----------  --------  ---\n");

    for (snap.nodes) |node| {
        var age_buf: [24]u8 = undefined;
        const age = formatAge(&age_buf, node.last_ack_ms_ago);

        try writePadded(writer, node.node, max_node_width);
        try writer.writeAll("  ");
        try writePadded(writer, healthWord(node.health), max_health_width);
        try writer.print("  {d:>11}  {s:>8}  {d}ms\n", .{ node.incarnation, age, node.rtt_ms });
    }

    if (snap.witnesses.len != 0) {
        try writer.writeAll("Witnesses: ");
        for (snap.witnesses, 0..) |witness, i| {
            if (i != 0) try writer.writeAll(", ");
            try writer.writeAll(witness);
        }
        try writer.writeAll("\n");
    }

    try writer.print("Summary: {d} alive / {d} suspect / {d} dead\n", .{ alive, suspect, dead });
}

fn writePadded(writer: anytype, text: []const u8, width: usize) !void {
    try writer.writeAll(text);
    if (text.len < width) {
        try writeRepeat(writer, ' ', width - text.len);
    }
}

fn writeRepeat(writer: anytype, byte: u8, count: usize) !void {
    for (0..count) |_| {
        try writer.writeByte(byte);
    }
}

fn renderToBuf(buf: []u8, snap: HealthSnapshot) ![]const u8 {
    var writer = std.Io.Writer.fixed(buf);
    try renderHealth(snap, &writer);
    return writer.buffered();
}

test "healthWord maps every node health state" {
    try std.testing.expectEqualStrings("alive", healthWord(.alive));
    try std.testing.expectEqualStrings("suspect", healthWord(.suspect));
    try std.testing.expectEqualStrings("dead", healthWord(.dead));
    try std.testing.expectEqualStrings("left", healthWord(.left));
}

test "formatAge humanizes milliseconds and second boundaries" {
    var buf: [24]u8 = undefined;

    try std.testing.expectEqualStrings("0ms", formatAge(&buf, 0));
    try std.testing.expectEqualStrings("999ms", formatAge(&buf, 999));
    try std.testing.expectEqualStrings("1s", formatAge(&buf, 1_000));
    try std.testing.expectEqualStrings("1.2s", formatAge(&buf, 1_200));
    try std.testing.expectEqualStrings("59.9s", formatAge(&buf, 59_999));
}

test "formatAge humanizes minute hour and day boundaries" {
    var buf: [24]u8 = undefined;

    try std.testing.expectEqualStrings("1m", formatAge(&buf, 60_000));
    try std.testing.expectEqualStrings("59m", formatAge(&buf, 3_599_999));
    try std.testing.expectEqualStrings("1h", formatAge(&buf, 3_600_000));
    try std.testing.expectEqualStrings("23h", formatAge(&buf, 86_399_999));
    try std.testing.expectEqualStrings("1d", formatAge(&buf, 86_400_000));
    try std.testing.expectEqualStrings("3d", formatAge(&buf, 259_200_000));
}

test "renderHealth renders a single-node mesh without witnesses" {
    const nodes = [_]NodeStatus{.{
        .node = "suzu-a",
        .health = .alive,
        .incarnation = 7,
        .last_ack_ms_ago = 0,
        .rtt_ms = 1,
    }};
    var buf: [4096]u8 = undefined;
    const out = try renderToBuf(&buf, .{
        .local_node = "suzu-a",
        .nodes = &nodes,
        .probe_period_ms = 1_200,
    });

    try std.testing.expect(std.mem.indexOf(u8, out, "Local node: suzu-a\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Probe period: 1.2s\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Counts: 1 alive / 0 suspect / 0 dead\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "suzu-a  alive             7       0ms  1ms\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Witnesses:") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary: 1 alive / 0 suspect / 0 dead\n") != null);
}

test "renderHealth renders mixed alive suspect dead and left rows" {
    const nodes = [_]NodeStatus{
        .{ .node = "alpha", .health = .alive, .incarnation = 1, .last_ack_ms_ago = 35, .rtt_ms = 3 },
        .{ .node = "beta-long", .health = .suspect, .incarnation = 4, .last_ack_ms_ago = 61_000, .rtt_ms = 44 },
        .{ .node = "gamma", .health = .dead, .incarnation = 9, .last_ack_ms_ago = 7_200_000, .rtt_ms = 0 },
        .{ .node = "delta", .health = .left, .incarnation = 10, .last_ack_ms_ago = 172_800_000, .rtt_ms = 0 },
    };
    var buf: [4096]u8 = undefined;
    const out = try renderToBuf(&buf, .{
        .local_node = "alpha",
        .nodes = &nodes,
        .probe_period_ms = 1_000,
    });

    try std.testing.expect(std.mem.indexOf(u8, out, "Counts: 1 alive / 1 suspect / 1 dead\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "alpha      alive              1      35ms  3ms\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "beta-long  suspect            4        1m  44ms\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "gamma      dead               9        2h  0ms\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "delta      left              10        2d  0ms\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary: 1 alive / 1 suspect / 1 dead\n") != null);
}

test "renderHealth renders witness list when present" {
    const nodes = [_]NodeStatus{
        .{ .node = "self", .health = .alive },
        .{ .node = "peer", .health = .suspect, .last_ack_ms_ago = 1_500 },
    };
    const witnesses = [_][]const u8{ "relay-a", "relay-b", "relay-c" };
    var buf: [4096]u8 = undefined;
    const out = try renderToBuf(&buf, .{
        .local_node = "self",
        .nodes = &nodes,
        .witnesses = &witnesses,
        .probe_period_ms = 500,
    });

    try std.testing.expect(std.mem.indexOf(u8, out, "Witnesses: relay-a, relay-b, relay-c\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary: 1 alive / 1 suspect / 0 dead\n") != null);
}

test "renderHealth keeps output lf-only" {
    const nodes = [_]NodeStatus{.{ .node = "self", .health = .alive }};
    var buf: [4096]u8 = undefined;
    const out = try renderToBuf(&buf, .{ .local_node = "self", .nodes = &nodes });

    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    try std.testing.expect(std.mem.endsWith(u8, out, "\n"));
}
