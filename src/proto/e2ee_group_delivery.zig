// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client-visible E2EEGROUP delivery lines.
//!
//! Mesh relays already carry the origin account. This leaf only renders the
//! local/relay client line with that server-derived account inserted. It never
//! opens the opaque payload.
const std = @import("std");

const e2ee_group_control = @import("e2ee_group_control.zig");

pub const RenderError = error{
    OutputTooSmall,
    InvalidRecord,
};

/// Render one client delivery line:
///   :prefix E2EE.KEYPACKAGE|E2EE.COMMIT <channel> <from-account> <from-device> :payload
///   :prefix E2EE.WELCOME <channel> <from-account> <from-device> <to-account> <to-device> :payload
pub fn renderClientLine(
    source_prefix: []const u8,
    from_account: []const u8,
    record: e2ee_group_control.Record,
    out: []u8,
) RenderError![]const u8 {
    if (source_prefix.len == 0 or !validAccount(from_account)) return error.InvalidRecord;
    e2ee_group_control.validate(record) catch return error.InvalidRecord;

    return if (record.kind == .welcome)
        std.fmt.bufPrint(
            out,
            ":{s} {s} {s} {s} {s} {s} {s} :{s}\r\n",
            .{
                source_prefix,
                record.kind.wireTag(),
                record.channel,
                from_account,
                record.from_device,
                record.to_account.?,
                record.to_device.?,
                record.payload,
            },
        ) catch error.OutputTooSmall
    else
        std.fmt.bufPrint(
            out,
            ":{s} {s} {s} {s} {s} :{s}\r\n",
            .{
                source_prefix,
                record.kind.wireTag(),
                record.channel,
                from_account,
                record.from_device,
                record.payload,
            },
        ) catch error.OutputTooSmall;
}

fn validAccount(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > e2ee_group_control.max_account_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', '@' => {},
        else => return false,
    };
    return true;
}

test "E2EEGROUP client renderer inserts server-derived from-account" {
    var out: [256]u8 = undefined;
    const key_package = try renderClientLine(
        "Alice!alice@localhost",
        "alice",
        .{
            .channel = "#secure",
            .kind = .key_package,
            .from_device = "phone",
            .payload = "AQIDBA",
        },
        &out,
    );
    try std.testing.expectEqualStrings(
        ":Alice!alice@localhost E2EE.KEYPACKAGE #secure alice phone :AQIDBA\r\n",
        key_package,
    );

    const commit = try renderClientLine(
        "Alice!alice@localhost",
        "alice",
        .{
            .channel = "#secure",
            .kind = .commit,
            .from_device = "phone",
            .payload = "b3BhcXVl",
        },
        &out,
    );
    try std.testing.expectEqualStrings(
        ":Alice!alice@localhost E2EE.COMMIT #secure alice phone :b3BhcXVl\r\n",
        commit,
    );

    const welcome = try renderClientLine(
        "Alice!alice@localhost",
        "alice",
        .{
            .channel = "#secure",
            .kind = .welcome,
            .from_device = "phone",
            .to_account = "Bob",
            .to_device = "tablet",
            .payload = "d2VsY29tZQ",
        },
        &out,
    );
    try std.testing.expectEqualStrings(
        ":Alice!alice@localhost E2EE.WELCOME #secure alice phone Bob tablet :d2VsY29tZQ\r\n",
        welcome,
    );
}

test "E2EEGROUP client renderer rejects missing account and undersize buffers" {
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidRecord, renderClientLine(
        "Alice!alice@localhost",
        "",
        .{
            .channel = "#secure",
            .kind = .commit,
            .from_device = "phone",
            .payload = "AQIDBA",
        },
        &out,
    ));
    try std.testing.expectError(error.InvalidRecord, renderClientLine(
        "Alice!alice@localhost",
        "bad account",
        .{
            .channel = "#secure",
            .kind = .commit,
            .from_device = "phone",
            .payload = "AQIDBA",
        },
        &out,
    ));
    try std.testing.expectError(error.InvalidRecord, renderClientLine(
        "",
        "alice",
        .{
            .channel = "#secure",
            .kind = .commit,
            .from_device = "phone",
            .payload = "AQIDBA",
        },
        &out,
    ));
    try std.testing.expectError(error.InvalidRecord, renderClientLine(
        "Alice!alice@localhost",
        "alice",
        .{
            .channel = "#secure",
            .kind = .welcome,
            .from_device = "phone",
            .payload = "d2VsY29tZQ",
        },
        &out,
    ));

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, renderClientLine(
        "Alice!alice@localhost",
        "alice",
        .{
            .channel = "#secure",
            .kind = .commit,
            .from_device = "phone",
            .payload = "AQIDBA",
        },
        &tiny,
    ));
}
