// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CHANNEL_LIST frame payload codec (S2S +b/+e/+I propagation).
//!
//! Carries one last-writer-wins channel list fact:
//! `present` says add/remove, `kind` selects +b/+e/+I, `hlc` orders writes, and
//! `setter`/`set_at` preserve the IRC list metadata surfaced by list numerics.
//! Decode borrows the input and allocates nothing.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_mask_len = 512;
pub const max_setter_len = 256;
const fixed_prefix = 1 + 1 + 8 + 8 + 8; // present, kind, origin_node, hlc, set_at

pub const Error = error{
    Truncated,
    FieldTooLong,
    BadKind,
    TrailingBytes,
};

pub const ListKind = enum(u8) {
    ban = 0,
    exempt = 1,
    invex = 2,
    // +Z quiet (mute) list. Additive tag: pre-quiet peers reject unknown kinds
    // (decode -> error.BadKind), so this stays forward-compatible on the wire.
    quiet = 3,

    pub fn letter(self: ListKind) u8 {
        return switch (self) {
            .ban => 'b',
            .exempt => 'e',
            .invex => 'I',
            .quiet => 'Z',
        };
    }

    pub fn fromTag(tag: u8) ?ListKind {
        return switch (tag) {
            @backingInt(ListKind.ban) => .ban,
            @backingInt(ListKind.exempt) => .exempt,
            @backingInt(ListKind.invex) => .invex,
            @backingInt(ListKind.quiet) => .quiet,
            else => null,
        };
    }
};

pub const ChannelListEvent = struct {
    present: bool,
    kind: ListKind,
    origin_node: u64,
    hlc: u64,
    set_at: i64,
    channel: []const u8,
    mask: []const u8,
    setter: []const u8,
};

pub fn encodedLen(ev: ChannelListEvent) Error!usize {
    if (ev.channel.len > max_channel_len or ev.mask.len > max_mask_len or ev.setter.len > max_setter_len) {
        return error.FieldTooLong;
    }
    return fixed_prefix + 2 + ev.channel.len + 2 + ev.mask.len + 2 + ev.setter.len;
}

pub fn encode(ev: ChannelListEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;

    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    out[i] = @backingInt(ev.kind);
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    std.mem.writeInt(i64, out[i..][0..8], ev.set_at, .little);
    i += 8;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.channel.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.channel.len], ev.channel);
    i += ev.channel.len;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.mask.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.mask.len], ev.mask);
    i += ev.mask.len;

    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.setter.len), .little);
    i += 2;
    @memcpy(out[i..][0..ev.setter.len], ev.setter);
    i += ev.setter.len;

    return out[0..i];
}

pub fn decode(bytes: []const u8) Error!ChannelListEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;

    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const kind = ListKind.fromTag(bytes[i]) orelse return error.BadKind;
    i += 1;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const set_at = std.mem.readInt(i64, bytes[i..][0..8], .little);
    i += 8;

    const channel_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (channel_len > max_channel_len) return error.FieldTooLong;
    if (bytes.len < i + channel_len + 2) return error.Truncated;
    const channel = bytes[i .. i + channel_len];
    i += channel_len;

    const mask_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (mask_len > max_mask_len) return error.FieldTooLong;
    if (bytes.len < i + mask_len + 2) return error.Truncated;
    const mask = bytes[i .. i + mask_len];
    i += mask_len;

    const setter_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (setter_len > max_setter_len) return error.FieldTooLong;
    if (bytes.len < i + setter_len) return error.Truncated;
    const setter = bytes[i .. i + setter_len];
    i += setter_len;

    if (i != bytes.len) return error.TrailingBytes;
    return .{
        .present = present,
        .kind = kind,
        .origin_node = origin_node,
        .hlc = hlc,
        .set_at = set_at,
        .channel = channel,
        .mask = mask,
        .setter = setter,
    };
}

const testing = std.testing;

test "channel list event round-trips add" {
    const ev = ChannelListEvent{
        .present = true,
        .kind = .ban,
        .origin_node = 42,
        .hlc = 99,
        .set_at = 1_781_234_567,
        .channel = "#ops",
        .mask = "*!*@bad.example",
        .setter = "Oper!user@host",
    };
    var buf: [1024]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(ListKind.ban, got.kind);
    try testing.expectEqual(@as(u64, 42), got.origin_node);
    try testing.expectEqual(@as(u64, 99), got.hlc);
    try testing.expectEqual(@as(i64, 1_781_234_567), got.set_at);
    try testing.expectEqualStrings("#ops", got.channel);
    try testing.expectEqualStrings("*!*@bad.example", got.mask);
    try testing.expectEqualStrings("Oper!user@host", got.setter);
}

test "channel list event round-trips remove invex" {
    const ev = ChannelListEvent{
        .present = false,
        .kind = .invex,
        .origin_node = 7,
        .hlc = 8,
        .set_at = 9,
        .channel = "#i",
        .mask = "friend!*@*",
        .setter = "services",
    };
    var buf: [256]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expect(!got.present);
    try testing.expectEqual(ListKind.invex, got.kind);
    try testing.expectEqualStrings("friend!*@*", got.mask);
}

test "channel list event round-trips quiet" {
    const ev = ChannelListEvent{
        .present = true,
        .kind = .quiet,
        .origin_node = 3,
        .hlc = 1234,
        .set_at = 1_781_000_000,
        .channel = "#muted",
        .mask = "loud!*@*",
        .setter = "Op!u@h",
    };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);
    // Wire tag is the additive value 3, and renders as the +Z mode letter.
    try testing.expectEqual(@as(u8, 3), wire[1]);
    try testing.expectEqual(@as(u8, 'Z'), ListKind.quiet.letter());

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(ListKind.quiet, got.kind);
    try testing.expectEqual(@as(u64, 3), got.origin_node);
    try testing.expectEqual(@as(u64, 1234), got.hlc);
    try testing.expectEqual(@as(i64, 1_781_000_000), got.set_at);
    try testing.expectEqualStrings("#muted", got.channel);
    try testing.expectEqualStrings("loud!*@*", got.mask);
    try testing.expectEqualStrings("Op!u@h", got.setter);

    // Round-trip the remove path too.
    var buf2: [256]u8 = undefined;
    const gone = try decode(try encode(.{
        .present = false,
        .kind = .quiet,
        .origin_node = 3,
        .hlc = 1235,
        .set_at = 1_781_000_001,
        .channel = "#muted",
        .mask = "loud!*@*",
        .setter = "Op!u@h",
    }, &buf2));
    try testing.expect(!gone.present);
    try testing.expectEqual(ListKind.quiet, gone.kind);
}

test "channel list event rejects malformed input" {
    const ev = ChannelListEvent{ .present = true, .kind = .exempt, .origin_node = 1, .hlc = 2, .set_at = 3, .channel = "#c", .mask = "m", .setter = "s" };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var bad = @as([32]u8, @splat(0));
    bad[1] = 99;
    try testing.expectError(error.BadKind, decode(&bad));

    var padded: [129]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "channel list event enforces bounds" {
    const big_mask = &@as([(max_mask_len + 1)]u8, @splat('x'));
    const ev = ChannelListEvent{ .present = true, .kind = .ban, .origin_node = 1, .hlc = 1, .set_at = 1, .channel = "#c", .mask = big_mask, .setter = "s" };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
}
