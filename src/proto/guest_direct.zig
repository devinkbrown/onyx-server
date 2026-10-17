// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One signed ordinary-guest direct message. The record names both physical
//! incarnations and carries the author's signature unchanged across hops.
//! A cached copy is not a route: the caller must already hold an active hop.
const std = @import("std");
const sign = @import("../crypto/sign.zig");

pub const domain = "onyx-guest-direct-v1";
pub const magic = "OGDM";
pub const version: u8 = 1;
pub const max_nick_len = 64;
pub const max_text_len = 512;
pub const fixed_prefix_len = 117;
pub const min_wire_len = fixed_prefix_len + 6 + 2 + sign.signature_len;
pub const max_wire_len = fixed_prefix_len + 6 + max_nick_len + max_nick_len + max_text_len + sign.signature_len;
pub const Error = error{ Truncated, BadVersion, InvalidField, TrailingBytes, BadSignature, OriginMismatch, Expired, FutureIssued, InvalidClock };

pub const Record = struct {
    origin: sign.PublicKey,
    sender_guest: [16]u8,
    recipient_origin: sign.PublicKey,
    recipient_guest: [16]u8,
    hlc: u64,
    issued_ms: i64,
    sender_nick: []const u8,
    target_nick: []const u8,
    text: []const u8,
};

pub const ClockPolicy = struct {
    max_lifetime_ms: i64 = 120_000,
    max_future_skew_ms: i64 = 30_000,

    /// A seen-set eviction must not resurrect a body older than the lease.
    /// Equal to the lease is already expired, matching a presence record whose
    /// `expires_ms` is `issued_ms + max_lifetime_ms`.
    pub fn validate(self: ClockPolicy, issued_ms: i64, now_ms: i64) Error!void {
        if (now_ms < 0 or self.max_lifetime_ms <= 0 or self.max_future_skew_ms < 0) return error.InvalidClock;
        if (issued_ms < 0) return error.InvalidClock;
        if (issued_ms > now_ms and issued_ms - now_ms > self.max_future_skew_ms) return error.FutureIssued;
        if (now_ms >= issued_ms and now_ms - issued_ms >= self.max_lifetime_ms) return error.Expired;
    }
};

pub const Decoded = struct {
    record: Record,
    /// Borrowed input. Retain a copy before the caller reuses the buffer.
    wire: []const u8,

    pub fn verify(self: Decoded) Error!void {
        const fresh = (try decode(self.wire)).record;
        if (!sameRecord(fresh, self.record)) return error.InvalidField;
        const signature: sign.Signature = self.wire[self.wire.len - sign.signature_len ..][0..sign.signature_len].*;
        const valid = sign.verifyCtx(domain, self.wire[0 .. self.wire.len - sign.signature_len], signature, self.record.origin) catch return error.BadSignature;
        if (!valid) return error.BadSignature;
    }
};

fn validNick(value: []const u8) Error!void {
    if (value.len == 0 or value.len > max_nick_len) return error.InvalidField;
    for (value) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => {},
        else => return error.InvalidField,
    };
}

fn validText(value: []const u8) Error!void {
    if (value.len > max_text_len) return error.InvalidField;
    if (std.mem.indexOfAny(u8, value, "\x00\r\n") != null) return error.InvalidField;
}

fn validate(record: Record) Error!void {
    if (record.hlc == 0 or record.issued_ms < 0) return error.InvalidField;
    var guest_zero = true;
    for (record.sender_guest) |byte| if (byte != 0) {
        guest_zero = false;
    };
    if (guest_zero) return error.InvalidField;
    guest_zero = true;
    for (record.recipient_guest) |byte| if (byte != 0) {
        guest_zero = false;
    };
    if (guest_zero) return error.InvalidField;
    try validNick(record.sender_nick);
    try validNick(record.target_nick);
    try validText(record.text);
}

fn sameRecord(a: Record, b: Record) bool {
    return std.mem.eql(u8, &a.origin, &b.origin) and std.mem.eql(u8, &a.sender_guest, &b.sender_guest) and
        std.mem.eql(u8, &a.recipient_origin, &b.recipient_origin) and std.mem.eql(u8, &a.recipient_guest, &b.recipient_guest) and
        a.hlc == b.hlc and a.issued_ms == b.issued_ms and std.mem.eql(u8, a.sender_nick, b.sender_nick) and
        std.mem.eql(u8, a.target_nick, b.target_nick) and std.mem.eql(u8, a.text, b.text);
}

pub fn encodedLen(record: Record) Error!usize {
    try validate(record);
    return fixed_prefix_len + 6 + record.sender_nick.len + record.target_nick.len + record.text.len + sign.signature_len;
}

pub fn encode(record: Record, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    const length = try encodedLen(record);
    if (!std.mem.eql(u8, &key.public_key, &record.origin)) return error.OriginMismatch;
    if (out.len < length) return error.Truncated;
    @memcpy(out[0..4], magic);
    out[4] = version;
    @memcpy(out[5..37], &record.origin);
    @memcpy(out[37..53], &record.sender_guest);
    @memcpy(out[53..85], &record.recipient_origin);
    @memcpy(out[85..101], &record.recipient_guest);
    std.mem.writeInt(u64, out[101..109], record.hlc, .big);
    std.mem.writeInt(i64, out[109..117], record.issued_ms, .big);
    var cursor: usize = fixed_prefix_len;
    const fields = [_][]const u8{ record.sender_nick, record.target_nick, record.text };
    for (fields) |field| {
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(field.len), .big);
        cursor += 2;
        @memcpy(out[cursor..][0..field.len], field);
        cursor += field.len;
    }
    const signature = try key.signCtx(domain, out[0..cursor]);
    @memcpy(out[cursor..][0..sign.signature_len], &signature);
    return out[0..length];
}

pub fn decode(wire: []const u8) Error!Decoded {
    if (wire.len < min_wire_len or wire.len > max_wire_len) return error.Truncated;
    if (!std.mem.eql(u8, wire[0..4], magic) or wire[4] != version) return error.BadVersion;
    const body_end = wire.len - sign.signature_len;
    var cursor: usize = fixed_prefix_len;
    var values: [3][]const u8 = undefined;
    for (&values) |*value| {
        if (body_end - cursor < 2) return error.Truncated;
        const length = std.mem.readInt(u16, wire[cursor..][0..2], .big);
        cursor += 2;
        if (length > body_end - cursor) return error.Truncated;
        value.* = wire[cursor..][0..length];
        cursor += length;
    }
    if (cursor != body_end) return error.TrailingBytes;
    const record: Record = .{
        .origin = wire[5..37].*,
        .sender_guest = wire[37..53].*,
        .recipient_origin = wire[53..85].*,
        .recipient_guest = wire[85..101].*,
        .hlc = std.mem.readInt(u64, wire[101..109], .big),
        .issued_ms = std.mem.readInt(i64, wire[109..117], .big),
        .sender_nick = values[0],
        .target_nick = values[1],
        .text = values[2],
    };
    try validate(record);
    return .{ .record = record, .wire = wire };
}

fn markedGuest(last: u8) [16]u8 {
    var guest: [16]u8 = @splat(0);
    guest[15] = last;
    return guest;
}

fn sample(origin: sign.PublicKey, recipient: sign.PublicKey) Record {
    return .{
        .origin = origin,
        .sender_guest = markedGuest(1),
        .recipient_origin = recipient,
        .recipient_guest = markedGuest(2),
        .hlc = 9,
        .issued_ms = 1_000,
        .sender_nick = "GuestA",
        .target_nick = "GuestC",
        .text = "ordinary-far-direct",
    };
}

test "guest direct roundtrip keeps the author signature and rejects mutation" {
    var author = try sign.KeyPair.fromSeed(@splat(11));
    defer author.deinit();
    var home = try sign.KeyPair.fromSeed(@splat(12));
    defer home.deinit();
    var bytes: [max_wire_len]u8 = undefined;
    const record = sample(author.public_key, home.public_key);
    const wire = try encode(record, &author, &bytes);
    const decoded = try decode(wire);
    try decoded.verify();
    try std.testing.expectEqualStrings(record.text, decoded.record.text);
    try std.testing.expectEqualSlices(u8, &record.recipient_guest, &decoded.record.recipient_guest);
    bytes[wire.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, decoded.verify());
    try std.testing.expectError(error.OriginMismatch, encode(record, &home, &bytes));
}

test "guest direct clock rejects future skew and a body as old as the lease" {
    const policy: ClockPolicy = .{};
    try policy.validate(1_000, 1_000);
    try policy.validate(1_000, 1_000 + 120_000 - 1);
    try std.testing.expectError(error.Expired, policy.validate(1_000, 1_000 + 120_000));
    try std.testing.expectError(error.FutureIssued, policy.validate(1_000 + 30_001, 1_000));
    try policy.validate(1_000 + 30_000, 1_000);
}

test "guest direct rejects a zero guest, a control byte, and a truncated body" {
    var author = try sign.KeyPair.fromSeed(@splat(13));
    defer author.deinit();
    var bytes: [max_wire_len]u8 = undefined;
    var record = sample(author.public_key, author.public_key);
    record.sender_guest = @splat(0);
    try std.testing.expectError(error.InvalidField, encode(record, &author, &bytes));
    record = sample(author.public_key, author.public_key);
    record.text = "bad\ntext";
    try std.testing.expectError(error.InvalidField, encode(record, &author, &bytes));
    record = sample(author.public_key, author.public_key);
    const wire = try encode(record, &author, &bytes);
    try std.testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));
}
