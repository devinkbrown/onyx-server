// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One remote client's WHOIS session facts.
//!
//! The handshake capability byte is full, so this record rides frame tag 0x2E
//! only after a PING extension reply. Membership stays unchanged: an older peer
//! never sees a new trailing block, and a peer that does not know the tag
//! skips it. rDNS is optional and is emitted only on a secured oper-info link.
//! The receiver still shows that name, the real host, and the certificate
//! fingerprint only to an operator.

const std = @import("std");

pub const version: u8 = 1;

pub const max_nick_len: usize = 64;
pub const max_cipher_len: usize = 64;
pub const max_away_len: usize = 390;
pub const max_rdns_len: usize = 255;
pub const max_modes_len: usize = 48;
pub const max_class_len: usize = 64;

pub const max_encoded_len: usize = 1 + 2 + (8 * 4) +
    (1 + max_nick_len) +
    (1 + max_cipher_len) +
    (2 + max_away_len) +
    (1 + max_rdns_len) +
    (1 + max_modes_len) +
    (1 + max_class_len);

pub const flag_present: u16 = 1 << 0;
pub const flag_tls: u16 = 1 << 1;
pub const flag_bot: u16 = 1 << 2;
pub const flag_regonly: u16 = 1 << 3;
pub const flag_callerid: u16 = 1 << 4;
pub const flag_common_chan: u16 = 1 << 5;
pub const flag_tls_only: u16 = 1 << 6;
pub const flag_no_invite: u16 = 1 << 7;
pub const flag_hide_idle: u16 = 1 << 8;
pub const flag_hide_chans: u16 = 1 << 9;
pub const flag_away: u16 = 1 << 10;
pub const flag_has_rdns: u16 = 1 << 11;
pub const flag_hide_oper: u16 = 1 << 12;
pub const flag_websocket: u16 = 1 << 13;
/// The rDNS label is a PTR that did not forward-confirm. `flag_has_rdns` is
/// still set so the name is on the wire; operators must not treat it as the
/// confirmed hostname.
pub const flag_rdns_unconfirmed: u16 = 1 << 14;

pub const EncodeError = error{ Invalid, Overflow };

pub const Record = struct {
    present: bool = true,
    tls: bool = false,
    bot: bool = false,
    regonly: bool = false,
    callerid: bool = false,
    common_chan: bool = false,
    tls_only: bool = false,
    no_invite: bool = false,
    hide_idle: bool = false,
    hide_chans: bool = false,
    away: bool = false,
    has_rdns: bool = false,
    /// Meaningful only when `has_rdns` is set. The name is a raw PTR.
    rdns_unconfirmed: bool = false,
    hide_oper: bool = false,
    websocket: bool = false,
    signon_unix: u64 = 0,
    last_active_unix: u64 = 0,
    revision_ms: u64 = 0,
    origin_node: u64 = 0,
    nick: []const u8 = "",
    cipher: []const u8 = "",
    away_text: []const u8 = "",
    rdns: []const u8 = "",
    modes: []const u8 = "",
    class_name: []const u8 = "",
};

pub const View = struct {
    flags: u16,
    signon_unix: u64,
    last_active_unix: u64,
    revision_ms: u64,
    origin_node: u64,
    nick: []const u8,
    cipher: []const u8,
    away_text: []const u8,
    rdns: []const u8,
    modes: []const u8,
    class_name: []const u8,

    pub fn present(self: View) bool {
        return (self.flags & flag_present) != 0;
    }

    pub fn record(self: View, include_rdns: bool) Record {
        const rdns = if (include_rdns and (self.flags & flag_has_rdns) != 0) self.rdns else "";
        return .{
            .present = self.present(),
            .tls = (self.flags & flag_tls) != 0,
            .bot = (self.flags & flag_bot) != 0,
            .regonly = (self.flags & flag_regonly) != 0,
            .callerid = (self.flags & flag_callerid) != 0,
            .common_chan = (self.flags & flag_common_chan) != 0,
            .tls_only = (self.flags & flag_tls_only) != 0,
            .no_invite = (self.flags & flag_no_invite) != 0,
            .hide_idle = (self.flags & flag_hide_idle) != 0,
            .hide_chans = (self.flags & flag_hide_chans) != 0,
            .away = (self.flags & flag_away) != 0,
            .has_rdns = rdns.len != 0,
            .rdns_unconfirmed = rdns.len != 0 and (self.flags & flag_rdns_unconfirmed) != 0,
            .hide_oper = (self.flags & flag_hide_oper) != 0,
            .websocket = (self.flags & flag_websocket) != 0,
            .signon_unix = self.signon_unix,
            .last_active_unix = self.last_active_unix,
            .revision_ms = self.revision_ms,
            .origin_node = self.origin_node,
            .nick = self.nick,
            .cipher = self.cipher,
            .away_text = self.away_text,
            .rdns = rdns,
            .modes = self.modes,
            .class_name = self.class_name,
        };
    }
};

pub fn encode(rec: Record, out: []u8) EncodeError![]const u8 {
    if (!nickOk(rec.nick)) return error.Invalid;
    if (!tokenOk(rec.cipher) or rec.cipher.len > max_cipher_len) return error.Invalid;
    if (!awayOk(rec.away_text) or rec.away_text.len > max_away_len) return error.Invalid;
    if (!tokenOk(rec.rdns) or rec.rdns.len > max_rdns_len) return error.Invalid;
    if (!modesOk(rec.modes) or rec.modes.len > max_modes_len) return error.Invalid;
    if (!tokenOk(rec.class_name) or rec.class_name.len > max_class_len) return error.Invalid;
    if (rec.has_rdns and rec.rdns.len == 0) return error.Invalid;
    if (rec.rdns_unconfirmed and !rec.has_rdns) return error.Invalid;
    if (!rec.present and (rec.cipher.len != 0 or rec.away_text.len != 0 or rec.rdns.len != 0 or rec.modes.len != 0 or rec.class_name.len != 0)) return error.Invalid;

    var flags: u16 = 0;
    if (rec.present) flags |= flag_present;
    if (rec.tls) flags |= flag_tls;
    if (rec.bot) flags |= flag_bot;
    if (rec.regonly) flags |= flag_regonly;
    if (rec.callerid) flags |= flag_callerid;
    if (rec.common_chan) flags |= flag_common_chan;
    if (rec.tls_only) flags |= flag_tls_only;
    if (rec.no_invite) flags |= flag_no_invite;
    if (rec.hide_idle) flags |= flag_hide_idle;
    if (rec.hide_chans) flags |= flag_hide_chans;
    if (rec.away) flags |= flag_away;
    if (rec.has_rdns) flags |= flag_has_rdns;
    if (rec.rdns_unconfirmed) flags |= flag_rdns_unconfirmed;
    if (rec.hide_oper) flags |= flag_hide_oper;
    if (rec.websocket) flags |= flag_websocket;

    var n: usize = 0;
    try put(out, &n, &.{version});
    var flag_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &flag_buf, flags, .little);
    try put(out, &n, &flag_buf);
    try putInt(out, &n, rec.signon_unix);
    try putInt(out, &n, rec.last_active_unix);
    try putInt(out, &n, rec.revision_ms);
    try putInt(out, &n, rec.origin_node);
    try putCounted(out, &n, rec.nick, 1);
    try putCounted(out, &n, rec.cipher, 1);
    try putCounted(out, &n, rec.away_text, 2);
    try putCounted(out, &n, if (rec.has_rdns) rec.rdns else "", 1);
    try putCounted(out, &n, rec.modes, 1);
    try putCounted(out, &n, rec.class_name, 1);
    return out[0..n];
}

pub fn decode(bytes: []const u8) ?View {
    if (bytes.len < 1 + 2 + (8 * 4) + 1) return null;
    if (bytes[0] != version) return null;
    var n: usize = 1;
    const flags = std.mem.readInt(u16, bytes[n..][0..2], .little);
    n += 2;
    const signon_unix = readInt(bytes, &n) orelse return null;
    const last_active_unix = readInt(bytes, &n) orelse return null;
    const revision_ms = readInt(bytes, &n) orelse return null;
    const origin_node = readInt(bytes, &n) orelse return null;
    const nick = readCounted(bytes, &n, 1, max_nick_len) orelse return null;
    const cipher = readCounted(bytes, &n, 1, max_cipher_len) orelse return null;
    const away_text = readCounted(bytes, &n, 2, max_away_len) orelse return null;
    const rdns = readCounted(bytes, &n, 1, max_rdns_len) orelse return null;
    const modes = readCounted(bytes, &n, 1, max_modes_len) orelse return null;
    const class_name = readCounted(bytes, &n, 1, max_class_len) orelse return null;
    if (n != bytes.len) return null;
    if (!nickOk(nick) or !tokenOk(cipher) or !awayOk(away_text) or !tokenOk(rdns) or !modesOk(modes) or !tokenOk(class_name)) return null;
    if ((flags & flag_has_rdns) != 0 and rdns.len == 0) return null;
    if ((flags & flag_has_rdns) == 0 and rdns.len != 0) return null;
    if ((flags & flag_rdns_unconfirmed) != 0 and (flags & flag_has_rdns) == 0) return null;
    if ((flags & flag_present) == 0 and (cipher.len != 0 or away_text.len != 0 or rdns.len != 0 or modes.len != 0 or class_name.len != 0)) return null;
    return .{
        .flags = flags,
        .signon_unix = signon_unix,
        .last_active_unix = last_active_unix,
        .revision_ms = revision_ms,
        .origin_node = origin_node,
        .nick = nick,
        .cipher = cipher,
        .away_text = away_text,
        .rdns = rdns,
        .modes = modes,
        .class_name = class_name,
    };
}

pub fn nickOk(nick: []const u8) bool {
    if (nick.len == 0 or nick.len > max_nick_len) return false;
    if (nick[0] == ':' or nick[0] == '#') return false;
    return tokenOk(nick);
}

fn tokenOk(bytes: []const u8) bool {
    for (bytes) |ch| {
        if (ch <= 0x20 or ch == 0x7f or ch == ':') return false;
    }
    return true;
}

fn awayOk(bytes: []const u8) bool {
    for (bytes) |ch| {
        if (ch < 0x20 or ch == 0x7f) return false;
    }
    return true;
}

fn modesOk(bytes: []const u8) bool {
    if (bytes.len == 0) return true;
    if (bytes[0] != '+') return false;
    if (bytes.len == 1) return false;
    for (bytes[1..]) |ch| {
        if (!std.ascii.isAlphanumeric(ch)) return false;
    }
    return true;
}

fn put(out: []u8, n: *usize, bytes: []const u8) EncodeError!void {
    if (out.len - n.* < bytes.len) return error.Overflow;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn putInt(out: []u8, n: *usize, value: u64) EncodeError!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try put(out, n, &buf);
}

fn putCounted(out: []u8, n: *usize, bytes: []const u8, width: usize) EncodeError!void {
    if (width == 1) {
        if (bytes.len > 255) return error.Invalid;
        try put(out, n, &.{@intCast(bytes.len)});
    } else {
        if (bytes.len > 65535) return error.Invalid;
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, @intCast(bytes.len), .little);
        try put(out, n, &buf);
    }
    try put(out, n, bytes);
}

fn readInt(bytes: []const u8, n: *usize) ?u64 {
    if (bytes.len - n.* < 8) return null;
    const value = std.mem.readInt(u64, bytes[n.*..][0..8], .little);
    n.* += 8;
    return value;
}

fn readCounted(bytes: []const u8, n: *usize, width: usize, max_len: usize) ?[]const u8 {
    const len: usize = if (width == 1) blk: {
        if (bytes.len - n.* < 1) return null;
        const l = bytes[n.*];
        n.* += 1;
        break :blk l;
    } else blk: {
        if (bytes.len - n.* < 2) return null;
        const l = std.mem.readInt(u16, bytes[n.*..][0..2], .little);
        n.* += 2;
        break :blk l;
    };
    if (len > max_len or bytes.len - n.* < len) return null;
    const slice = bytes[n.*..][0..len];
    n.* += len;
    return slice;
}

test "whois profile round-trips public facts and strips rDNS on relay" {
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{
        .present = true,
        .tls = true,
        .regonly = true,
        .away = true,
        .has_rdns = true,
        .hide_oper = true,
        .websocket = true,
        .signon_unix = 1_700_000_000,
        .last_active_unix = 1_700_000_050,
        .revision_ms = 9,
        .origin_node = 4,
        .nick = "klys",
        .cipher = "TLS_AES_128_GCM_SHA256",
        .away_text = "away for a bit",
        .rdns = "ircx.example",
        .modes = "+iR",
        .class_name = "users",
    }, &buf);
    const view = decode(wire) orelse return error.TestUnexpectedResult;
    try std.testing.expect(view.present());
    try std.testing.expectEqual(@as(u64, 4), view.origin_node);
    try std.testing.expectEqualStrings("klys", view.nick);
    try std.testing.expectEqualStrings("ircx.example", view.rdns);
    const relayed = view.record(false);
    try std.testing.expect(!relayed.has_rdns);
    try std.testing.expectEqualStrings("", relayed.rdns);
    try std.testing.expect(relayed.tls);
    try std.testing.expect(relayed.websocket);
    var again: [max_encoded_len]u8 = undefined;
    const stripped = try encode(relayed, &again);
    const stripped_view = decode(stripped) orelse return error.TestUnexpectedResult;
    try std.testing.expect(stripped_view.rdns.len == 0);
    try std.testing.expect((stripped_view.flags & flag_has_rdns) == 0);
    try std.testing.expect((stripped_view.flags & flag_tls) != 0);
}

test "whois profile rejects a truncated body and a gone record with session text" {
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{ .nick = "klys", .revision_ms = 1 }, &buf);
    try std.testing.expect(decode(wire[0 .. wire.len - 1]) == null);
    try std.testing.expect(decode("") == null);
    const gone = try encode(.{ .present = false, .nick = "klys", .revision_ms = 2, .origin_node = 4 }, &buf);
    const view = decode(gone) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!view.present());
    try std.testing.expectError(error.Invalid, encode(.{
        .present = false,
        .nick = "klys",
        .cipher = "TLS_AES_128_GCM_SHA256",
    }, &buf));
}

test "whois profile keeps an unconfirmed rDNS mark and rejects it alone" {
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(.{
        .present = true,
        .has_rdns = true,
        .rdns_unconfirmed = true,
        .nick = "klys",
        .rdns = "ptr.example.net",
        .revision_ms = 3,
        .origin_node = 1,
    }, &buf);
    const view = decode(wire) orelse return error.TestUnexpectedResult;
    try std.testing.expect((view.flags & flag_has_rdns) != 0);
    try std.testing.expect((view.flags & flag_rdns_unconfirmed) != 0);
    try std.testing.expectEqualStrings("ptr.example.net", view.rdns);
    const kept = view.record(true);
    try std.testing.expect(kept.has_rdns);
    try std.testing.expect(kept.rdns_unconfirmed);
    const stripped = view.record(false);
    try std.testing.expect(!stripped.has_rdns);
    try std.testing.expect(!stripped.rdns_unconfirmed);
    try std.testing.expectEqualStrings("", stripped.rdns);
    try std.testing.expectError(error.Invalid, encode(.{
        .present = true,
        .rdns_unconfirmed = true,
        .nick = "klys",
    }, &buf));
    var dropped = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(dropped);
    var flags = std.mem.readInt(u16, dropped[1..3], .little);
    flags &= ~flag_has_rdns;
    std.mem.writeInt(u16, dropped[1..3], flags, .little);
    try std.testing.expect(decode(dropped) == null);
}
