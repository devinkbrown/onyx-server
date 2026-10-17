// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CHANNEL_MODE_STATE frame payload codec (S2S parameter + IRCX flag sync).
//!
//! Carries the channel state that is not represented by the aggregate boolean
//! MODE flag frame: `+k`, `+l`, `+j`, `+f`, private/hidden visibility, and IRCX
//! extended channel flags. One event is an LWW snapshot for a channel, ordered by
//! `hlc` and owned by `origin_node`. Decode borrows the input and allocates
//! nothing.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_key_len = 128;
pub const max_forward_len = 128;
pub const ext_flag_mask: u32 = (1 << 23) - 1;

const flag_private: u8 = 1 << 0;
const flag_hidden: u8 = 1 << 1;
const flag_has_key: u8 = 1 << 2;
const flag_has_limit: u8 = 1 << 3;
const flag_has_throttle: u8 = 1 << 4;
const flag_has_forward: u8 = 1 << 5;
const known_flags: u8 = flag_private | flag_hidden | flag_has_key | flag_has_limit | flag_has_throttle | flag_has_forward;
const fixed_prefix = 8 + 8 + 1 + 4 + 4 + 2 + 4;

pub const Error = error{
    BadFlags,
    FieldTooLong,
    InvalidValue,
    TrailingBytes,
    Truncated,
};

pub const ChannelModeStateEvent = struct {
    origin_node: u64,
    hlc: u64,
    channel: []const u8,
    private: bool = false,
    hidden: bool = false,
    ext_bits: u32 = 0,
    key: ?[]const u8 = null,
    limit: ?u32 = null,
    throttle_joins: u16 = 0,
    throttle_secs: u32 = 0,
    forward: ?[]const u8 = null,

    pub fn hasThrottle(self: ChannelModeStateEvent) bool {
        return self.throttle_joins != 0 and self.throttle_secs != 0;
    }
};

pub fn encodedLen(ev: ChannelModeStateEvent) Error!usize {
    try validate(ev);
    const key_len = if (ev.key) |k| k.len else 0;
    const forward_len = if (ev.forward) |f| f.len else 0;
    return fixed_prefix + 2 + ev.channel.len + 2 + key_len + 2 + forward_len;
}

pub fn encode(ev: ChannelModeStateEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;

    var flags: u8 = 0;
    if (ev.private) flags |= flag_private;
    if (ev.hidden) flags |= flag_hidden;
    if (ev.key != null) flags |= flag_has_key;
    if (ev.limit != null) flags |= flag_has_limit;
    if (ev.hasThrottle()) flags |= flag_has_throttle;
    if (ev.forward != null) flags |= flag_has_forward;

    var i: usize = 0;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    out[i] = flags;
    i += 1;
    std.mem.writeInt(u32, out[i..][0..4], ev.ext_bits, .little);
    i += 4;
    std.mem.writeInt(u32, out[i..][0..4], ev.limit orelse 0, .little);
    i += 4;
    std.mem.writeInt(u16, out[i..][0..2], ev.throttle_joins, .little);
    i += 2;
    std.mem.writeInt(u32, out[i..][0..4], ev.throttle_secs, .little);
    i += 4;
    putBytes16(out, &i, ev.channel);
    putBytes16(out, &i, ev.key orelse "");
    putBytes16(out, &i, ev.forward orelse "");
    return out[0..i];
}

pub fn decode(bytes: []const u8) Error!ChannelModeStateEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const flags = bytes[i];
    i += 1;
    if ((flags & ~known_flags) != 0) return error.BadFlags;
    const ext_bits = std.mem.readInt(u32, bytes[i..][0..4], .little);
    i += 4;
    if ((ext_bits & ~ext_flag_mask) != 0) return error.BadFlags;
    const raw_limit = std.mem.readInt(u32, bytes[i..][0..4], .little);
    i += 4;
    const throttle_joins = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    const throttle_secs = std.mem.readInt(u32, bytes[i..][0..4], .little);
    i += 4;

    const channel = try takeBytes16(bytes, &i, max_channel_len);
    const key_raw = try takeBytes16(bytes, &i, max_key_len);
    const forward_raw = try takeBytes16(bytes, &i, max_forward_len);
    if (i != bytes.len) return error.TrailingBytes;

    if (channel.len == 0) return error.FieldTooLong;
    try validateLineField(channel);
    try validateLineField(key_raw);
    try validateLineField(forward_raw);

    const has_key = (flags & flag_has_key) != 0;
    const has_limit = (flags & flag_has_limit) != 0;
    const has_throttle = (flags & flag_has_throttle) != 0;
    const has_forward = (flags & flag_has_forward) != 0;
    if (has_key != (key_raw.len != 0)) return error.InvalidValue;
    if (has_limit == (raw_limit == 0)) return error.InvalidValue;
    if (has_throttle != (throttle_joins != 0 and throttle_secs != 0)) return error.InvalidValue;
    if (has_forward != (forward_raw.len != 0)) return error.InvalidValue;
    if (!has_throttle and (throttle_joins != 0 or throttle_secs != 0)) return error.InvalidValue;

    return .{
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
        .private = (flags & flag_private) != 0,
        .hidden = (flags & flag_hidden) != 0,
        .ext_bits = ext_bits,
        .key = if (has_key) key_raw else null,
        .limit = if (has_limit) raw_limit else null,
        .throttle_joins = if (has_throttle) throttle_joins else 0,
        .throttle_secs = if (has_throttle) throttle_secs else 0,
        .forward = if (has_forward) forward_raw else null,
    };
}

fn validate(ev: ChannelModeStateEvent) Error!void {
    if (ev.channel.len == 0 or ev.channel.len > max_channel_len) return error.FieldTooLong;
    if ((ev.ext_bits & ~ext_flag_mask) != 0) return error.BadFlags;
    if (ev.key) |k| {
        if (k.len == 0 or k.len > max_key_len) return error.FieldTooLong;
        try validateLineField(k);
    }
    if (ev.limit) |limit| {
        if (limit == 0) return error.InvalidValue;
    }
    const has_throttle = ev.throttle_joins != 0 or ev.throttle_secs != 0;
    if (has_throttle and !ev.hasThrottle()) return error.InvalidValue;
    if (ev.forward) |f| {
        if (f.len == 0 or f.len > max_forward_len) return error.FieldTooLong;
        try validateLineField(f);
    }
    try validateLineField(ev.channel);
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

fn takeBytes16(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.FieldTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

fn validateLineField(bytes: []const u8) Error!void {
    for (bytes) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.FieldTooLong;
    }
}

const testing = std.testing;

test "channel mode state event round-trips full state" {
    const ev = ChannelModeStateEvent{
        .origin_node = 42,
        .hlc = 99,
        .channel = "#ops",
        .private = true,
        .hidden = true,
        .ext_bits = 0b10101,
        .key = "sekret",
        .limit = 50,
        .throttle_joins = 3,
        .throttle_secs = 20,
        .forward = "#overflow",
    };
    var buf: [512]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(@as(u64, 42), got.origin_node);
    try testing.expectEqual(@as(u64, 99), got.hlc);
    try testing.expectEqualStrings("#ops", got.channel);
    try testing.expect(got.private);
    try testing.expect(got.hidden);
    try testing.expectEqual(@as(u32, 0b10101), got.ext_bits);
    try testing.expectEqualStrings("sekret", got.key.?);
    try testing.expectEqual(@as(?u32, 50), got.limit);
    try testing.expectEqual(@as(u16, 3), got.throttle_joins);
    try testing.expectEqual(@as(u32, 20), got.throttle_secs);
    try testing.expectEqualStrings("#overflow", got.forward.?);
}

test "channel mode state event round-trips cleared optionals" {
    const ev = ChannelModeStateEvent{ .origin_node = 1, .hlc = 2, .channel = "#c" };
    var buf: [128]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expect(!got.private);
    try testing.expect(!got.hidden);
    try testing.expect(got.key == null);
    try testing.expect(got.limit == null);
    try testing.expect(!got.hasThrottle());
    try testing.expect(got.forward == null);
}

test "channel mode state event rejects malformed input" {
    const ev = ChannelModeStateEvent{ .origin_node = 1, .hlc = 2, .channel = "#c", .limit = 10 };
    var buf: [128]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var padded: [129]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));

    var corrupt = padded;
    @memcpy(corrupt[0..wire.len], wire);
    corrupt[16] |= 0x80; // unknown flags byte
    try testing.expectError(error.BadFlags, decode(corrupt[0..wire.len]));
}
