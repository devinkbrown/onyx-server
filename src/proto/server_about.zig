// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-room renderer for the /INFO body — the human-readable description of
//! the server's identity, build, and architecture.
//!
//! Pure and std-only: it takes a populated `AboutInfo` and writes newline-
//! separated body lines into any `std.Io.Writer`-style sink (the same `anytype`
//! writer convention used by `stats_report.zig`). The daemon splits the result
//! on '\n' and emits each line as RPL_INFO (371); tests assert the content
//! directly. No I/O, no allocation, no globals.

const std = @import("std");

/// Build/identity context for the INFO body. All strings are borrowed for the
/// duration of the render call.
pub const AboutInfo = struct {
    /// Daemon version string, e.g. "orochi-0.1".
    version: []const u8,
    /// Compiler version the binary was built with (builtin.zig_version_string).
    zig_version: []const u8 = "",
    /// Target triple fragment, e.g. "x86_64-linux".
    target: []const u8 = "",
    /// Optimize mode tag, e.g. "ReleaseFast".
    optimize: []const u8 = "",
    /// Advertised network name.
    network: []const u8 = "",
    /// Unix-epoch seconds the server process started.
    online_since_unix: i64 = 0,
    /// Seconds the server has been running.
    uptime_secs: u64 = 0,
};

/// Render the INFO body as newline-separated lines into `writer`. Each line is
/// terminated with a single '\n' (no trailing CRLF — the caller wraps each line
/// in its own numeric). The architecture lines are deliberately editorial: this
/// is the one place the daemon describes what it actually is.
pub fn renderInfo(info: AboutInfo, writer: anytype) !void {
    try writer.writeAll("Orochi - a clean-room, pure-Zig mesh IRC daemon.\n");
    try writer.print("Version {s}", .{info.version});
    if (info.zig_version.len != 0 or info.target.len != 0 or info.optimize.len != 0) {
        try writer.writeAll(" (");
        var wrote = false;
        if (info.zig_version.len != 0) {
            try writer.print("zig {s}", .{info.zig_version});
            wrote = true;
        }
        if (info.target.len != 0) {
            if (wrote) try writer.writeAll(", ");
            try writer.writeAll(info.target);
            wrote = true;
        }
        if (info.optimize.len != 0) {
            if (wrote) try writer.writeAll(", ");
            try writer.writeAll(info.optimize);
        }
        try writer.writeAll(")");
    }
    try writer.writeAll("\n");

    try writer.writeAll("100% Zig, zero C interop - substrate, crypto, and daemon are all native.\n");
    try writer.writeAll("\n");
    try writer.writeAll("Mesh:     Suimyaku CRDT world state | Sazanami gossip | Goryu membership\n");
    try writer.writeAll("Security: Tsumugi PQ-hybrid handshake | MeshPass admission | zeroize-on-free key hygiene\n");
    try writer.writeAll("Crypto:   Yoroi - a from-scratch pure-Zig TLS and primitive library\n");
    try writer.writeAll("Media:    Kakehashi SFU | KaguraVox/KaguraVis codecs | QUIC/WebTransport transport\n");
    try writer.writeAll("History:  Lotus event-DAG with verified-streaming backfill\n");
    try writer.writeAll("\n");

    if (info.network.len != 0) {
        try writer.print("Network:  {s}\n", .{info.network});
    }
    var up_buf: [48]u8 = undefined;
    try writer.print("Running since {d} (up {s}).\n", .{ info.online_since_unix, formatUptime(&up_buf, info.uptime_secs) });
}

/// Format an uptime duration as a compact `"Dd HHh MMm SSs"` string into `buf`,
/// dropping leading zero units (e.g. "3m 09s", "2d 00h 05m 12s"). Returns the
/// written slice; `buf` should be at least 48 bytes.
pub fn formatUptime(buf: []u8, secs: u64) []const u8 {
    const days = secs / 86_400;
    const hours = (secs % 86_400) / 3_600;
    const mins = (secs % 3_600) / 60;
    const s = secs % 60;

    var w = std.Io.Writer.fixed(buf);
    if (days != 0) {
        w.print("{d}d {d:0>2}h {d:0>2}m {d:0>2}s", .{ days, hours, mins, s }) catch return buf[0..0];
    } else if (hours != 0) {
        w.print("{d}h {d:0>2}m {d:0>2}s", .{ hours, mins, s }) catch return buf[0..0];
    } else if (mins != 0) {
        w.print("{d}m {d:0>2}s", .{ mins, s }) catch return buf[0..0];
    } else {
        w.print("{d}s", .{s}) catch return buf[0..0];
    }
    return w.buffered();
}

// ── tests ────────────────────────────────────────────────────────────────────

fn renderToBuf(info: AboutInfo, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try renderInfo(info, &w);
    return w.buffered();
}

test "formatUptime drops leading zero units" {
    var b: [48]u8 = undefined;
    try std.testing.expectEqualStrings("9s", formatUptime(&b, 9));
    try std.testing.expectEqualStrings("3m 09s", formatUptime(&b, 189));
    try std.testing.expectEqualStrings("1h 05m 00s", formatUptime(&b, 3900));
    try std.testing.expectEqualStrings("2d 03h 04m 05s", formatUptime(&b, 2 * 86_400 + 3 * 3600 + 4 * 60 + 5));
}

test "renderInfo includes identity, build, and uptime" {
    var buf: [1024]u8 = undefined;
    const out = try renderToBuf(.{
        .version = "orochi-0.1",
        .zig_version = "0.16.0",
        .target = "x86_64-linux",
        .optimize = "ReleaseFast",
        .network = "Orochi",
        .online_since_unix = 1_700_000_000,
        .uptime_secs = 3661,
    }, &buf);

    try std.testing.expect(std.mem.indexOf(u8, out, "Version orochi-0.1 (zig 0.16.0, x86_64-linux, ReleaseFast)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Suimyaku CRDT") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Network:  Orochi") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Running since 1700000000 (up 1h 01m 01s)") != null);
    // Every line is non-empty-terminated by '\n'; never a bare CR.
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
}

test "renderInfo omits the build parens when no build info is present" {
    var buf: [1024]u8 = undefined;
    const out = try renderToBuf(.{ .version = "orochi-0.1" }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "Version orochi-0.1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "(zig") == null);
}
