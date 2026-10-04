// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Original signed ordinary-client presence. This codec proves neither origin
//! admission nor reachability. Consumers must stage those decisions separately.
//! Guest IDs are public incarnations, never credentials or portable tokens.
const std = @import("std");
const sign = @import("../crypto/sign.zig");

pub const domain = "onyx-mesh-presence-v1";
pub const magic = "OPRS";
pub const version: u8 = 1;
/// Public origin-epoch/counter identity. Epoch advances durably on cold boot;
/// Helix preserves it. Counters never repeat, including aborted reservations.
pub const GuestId = [16]u8;
pub const Subject = struct {
    epoch: u64,
    counter: u64,
};

pub fn guestId(parts: Subject) Error!GuestId {
    if (parts.epoch == 0 or parts.counter == 0) return error.InvalidField;
    var out: GuestId = undefined;
    std.mem.writeInt(u64, out[0..8], parts.epoch, .big);
    std.mem.writeInt(u64, out[8..16], parts.counter, .big);
    return out;
}

pub fn subject(id: GuestId) Error!Subject {
    const result: Subject = .{ .epoch = std.mem.readInt(u64, id[0..8], .big), .counter = std.mem.readInt(u64, id[8..16], .big) };
    if (result.epoch == 0 or result.counter == 0) return error.InvalidField;
    return result;
}
pub const Operation = enum(u8) { present = 1, quit = 2 };
pub const max_wire_len = 4 + 1 + 1 + 32 + 16 + 8 * 5 + 2 * 6 + 64 + 32 + 255 + 256 + 255 + 256 + 64;
pub const Error = error{ Truncated, BadVersion, InvalidField, TrailingBytes, BadSignature, OriginMismatch, Expired, FutureIssued, InvalidClock };

pub const Record = struct {
    operation: Operation,
    origin: sign.PublicKey,
    guest: GuestId,
    revision: u64,
    /// Stable across lease renewals; nickname changes author a new claim clock.
    claim_hlc: u64,
    /// Signed revision that authored this nickname claim. Renewals preserve
    /// both fields; skipped transitions can converge without inventing history.
    claim_revision: u64,
    issued_ms: i64,
    expires_ms: i64,
    nick: []const u8,
    username: []const u8,
    host: []const u8,
    realname: []const u8,
    server: []const u8,
    description: []const u8,
};

pub const ClockPolicy = struct {
    max_lifetime_ms: i64,
    max_future_skew_ms: i64,

    pub fn validate(self: ClockPolicy, record: Record, now_ms: i64) Error!void {
        if (now_ms < 0 or self.max_lifetime_ms <= 0 or self.max_future_skew_ms < 0) return error.InvalidClock;
        if (record.issued_ms < 0 or record.expires_ms <= record.issued_ms) return error.InvalidClock;
        if (record.expires_ms - record.issued_ms > self.max_lifetime_ms) return error.InvalidClock;
        // Compare differences without overflowing an attacker-controlled clock.
        if (record.issued_ms > now_ms and record.issued_ms - now_ms > self.max_future_skew_ms) return error.FutureIssued;
        if (now_ms >= record.expires_ms) return error.Expired;
    }
};

pub const Decoded = struct {
    record: Record,
    /// Exact original wire. Caller must keep borrowed input immutable through
    /// validation and every use; retained stores must own their own copy.
    wire: []const u8,

    pub fn verify(self: Decoded) Error!void {
        const signature: sign.Signature = self.wire[self.wire.len - sign.signature_len ..][0..sign.signature_len].*;
        const valid = sign.verifyCtx(domain, self.wire[0 .. self.wire.len - sign.signature_len], signature, self.record.origin) catch return error.BadSignature;
        if (!valid) return error.BadSignature;
    }
};

fn validLine(value: []const u8, max: usize, token: bool, required: bool) Error!void {
    if (value.len > max or (required and value.len == 0)) return error.InvalidField;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or (token and (byte <= 0x20))) return error.InvalidField;
    }
}

fn validate(record: Record) Error!void {
    if (record.revision == 0 or record.claim_hlc == 0 or record.claim_revision == 0 or record.claim_revision > record.revision) return error.InvalidField;
    _ = try subject(record.guest);
    if (record.issued_ms < 0 or record.expires_ms <= record.issued_ms) return error.InvalidClock;
    try validLine(record.nick, 64, true, true);
    // Match the public WHOIS renderer's nick, ident and host grammar. IPv6
    // host colons are legitimate; consumers must render leading-colon literals
    // safely as middle parameters rather than turning them into trailing text.
    for (record.nick) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => {},
        else => return error.InvalidField,
    };
    if (std.mem.indexOfAny(u8, record.username, "!@:") != null or std.mem.indexOfScalar(u8, record.server, ':') != null) return error.InvalidField;
    for (record.host) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => {},
        else => return error.InvalidField,
    };
    try validLine(record.username, 32, true, true);
    try validLine(record.host, 255, true, true);
    try validLine(record.realname, 256, false, false);
    try validLine(record.server, 255, true, true);
    try validLine(record.description, 256, false, false);
}

fn fields(record: Record) [6][]const u8 {
    return .{ record.nick, record.username, record.host, record.realname, record.server, record.description };
}

pub fn encodedLen(record: Record) Error!usize {
    try validate(record);
    var length: usize = 4 + 1 + 1 + 32 + 16 + 8 * 5 + sign.signature_len;
    for (fields(record)) |field| length += 2 + field.len;
    return length;
}

/// Output is unpublished scratch storage until this function succeeds.
pub fn encode(record: Record, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    const length = try encodedLen(record);
    if (!std.mem.eql(u8, &key.public_key, &record.origin)) return error.OriginMismatch;
    if (out.len < length) return error.Truncated;
    @memcpy(out[0..4], magic);
    out[4] = version;
    out[5] = @intFromEnum(record.operation);
    @memcpy(out[6..38], &record.origin);
    @memcpy(out[38..54], &record.guest);
    std.mem.writeInt(u64, out[54..62], record.revision, .big);
    std.mem.writeInt(u64, out[62..70], record.claim_hlc, .big);
    std.mem.writeInt(u64, out[70..78], record.claim_revision, .big);
    std.mem.writeInt(i64, out[78..86], record.issued_ms, .big);
    std.mem.writeInt(i64, out[86..94], record.expires_ms, .big);
    var cursor: usize = 94;
    for (fields(record)) |field| {
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(field.len), .big);
        cursor += 2;
        @memcpy(out[cursor..][0..field.len], field);
        cursor += field.len;
    }
    const signature = try key.signCtx(domain, out[0..cursor]);
    @memcpy(out[cursor..][0..sign.signature_len], &signature);
    return out[0..length];
}

/// Structural parsing only. Call verify, origin admission, clock policy and
/// transactional store admission before publishing any identity or route.
pub fn decode(wire: []const u8) Error!Decoded {
    if (wire.len < 94 + 12 + sign.signature_len) return error.Truncated;
    if (!std.mem.eql(u8, wire[0..4], magic) or wire[4] != version) return error.BadVersion;
    const operation = std.enums.fromInt(Operation, wire[5]) orelse return error.InvalidField;
    const body_end = wire.len - sign.signature_len;
    var cursor: usize = 94;
    var values: [6][]const u8 = undefined;
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
        .operation = operation,
        .origin = wire[6..38].*,
        .guest = wire[38..54].*,
        .revision = std.mem.readInt(u64, wire[54..62], .big),
        .claim_hlc = std.mem.readInt(u64, wire[62..70], .big),
        .claim_revision = std.mem.readInt(u64, wire[70..78], .big),
        .issued_ms = std.mem.readInt(i64, wire[78..86], .big),
        .expires_ms = std.mem.readInt(i64, wire[86..94], .big),
        .nick = values[0],
        .username = values[1],
        .host = values[2],
        .realname = values[3],
        .server = values[4],
        .description = values[5],
    };
    try validate(record);
    return .{ .record = record, .wire = wire };
}

fn fixture(origin: sign.PublicKey) Record {
    return .{ .operation = .present, .origin = origin, .guest = @splat(3), .revision = 1, .claim_hlc = 7, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "GuestFar", .username = "guest", .host = "cloak.onyx", .realname = "Ordinary Guest", .server = "node-c", .description = "Far node" };
}

test "mesh presence original signature, immutable wire and terminal operation" {
    var key = try sign.KeyPair.fromSeed(@splat(49));
    defer key.deinit();
    var buffer: [max_wire_len]u8 = undefined;
    var record = fixture(key.public_key);
    for ([_]Operation{ .present, .quit }) |operation| {
        record.operation = operation;
        const wire = try encode(record, &key, &buffer);
        const parsed = try decode(wire);
        try parsed.verify();
        try std.testing.expectEqual(operation, parsed.record.operation);
        try std.testing.expectEqualStrings(record.nick, parsed.record.nick);
        try std.testing.expectEqual(wire.ptr, parsed.wire.ptr);
        try std.testing.expectEqual(@as(u64, 7), parsed.record.claim_hlc);
        buffer[54 + 7] ^= 2;
        try std.testing.expectError(error.BadSignature, (try decode(wire)).verify());
    }
}

test "mesh presence rejects every truncated wire and appended bytes" {
    var key = try sign.KeyPair.fromSeed(@splat(50));
    defer key.deinit();
    var buffer: [max_wire_len + 1]u8 = undefined;
    const wire = try encode(fixture(key.public_key), &key, &buffer);
    for (0..wire.len) |length| {
        if (decode(wire[0..length])) |parsed| {
            try std.testing.expectError(error.BadSignature, parsed.verify());
        } else |_| {}
    }
    buffer[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(buffer[0 .. wire.len + 1]));
}

test "mesh presence rejects identity injection zero incarnation and mismatched origin" {
    var key = try sign.KeyPair.fromSeed(@splat(51));
    defer key.deinit();
    var record = fixture(key.public_key);
    var buffer: [max_wire_len]u8 = undefined;
    for ([_][]const u8{ "a b", "a\r\nQUIT", "a!b", "a@b", ":a", "*", "a.b", "" }) |nick| {
        record.nick = nick;
        try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    }
    record = fixture(key.public_key);
    record.username = ":user";
    try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    record = fixture(key.public_key);
    record.server = ":node";
    try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    record = fixture(key.public_key);
    record.realname = "bad\ttext";
    try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    record = fixture(key.public_key);
    record.description = "bad\x01text";
    try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    record = fixture(key.public_key);
    record.guest = @splat(0);
    try std.testing.expectError(error.InvalidField, encode(record, &key, &buffer));
    record = fixture(key.public_key);
    record.origin = @splat(0);
    try std.testing.expectError(error.OriginMismatch, encode(record, &key, &buffer));
}

test "mesh presence signed lifetime boundaries do not renew on replay" {
    const policy: ClockPolicy = .{ .max_lifetime_ms = 1000, .max_future_skew_ms = 20 };
    var record = fixture(@splat(1));
    try policy.validate(record, 980);
    try std.testing.expectError(error.FutureIssued, policy.validate(record, 979));
    try policy.validate(record, 1999);
    try std.testing.expectError(error.Expired, policy.validate(record, 2000));
    record.expires_ms = 2001;
    try std.testing.expectError(error.InvalidClock, policy.validate(record, 1000));
    record.issued_ms = std.math.maxInt(i64) - 1;
    record.expires_ms = std.math.maxInt(i64);
    try std.testing.expectError(error.FutureIssued, policy.validate(record, 0));
}

test "mesh presence binds every byte and rejects another signature domain" {
    var key = try sign.KeyPair.fromSeed(@splat(52));
    defer key.deinit();
    var buffer: [max_wire_len]u8 = undefined;
    const wire = try encode(fixture(key.public_key), &key, &buffer);
    for (0..wire.len) |index| {
        buffer[index] ^= 1;
        if (decode(wire)) |parsed| {
            try std.testing.expectError(error.BadSignature, parsed.verify());
        } else |_| {}
        buffer[index] ^= 1;
    }
    const wrong_domain = try key.signCtx("onyx-s2s-signed-frame-v1", wire[0 .. wire.len - sign.signature_len]);
    @memcpy(buffer[wire.len - sign.signature_len ..][0..sign.signature_len], &wrong_domain);
    try std.testing.expectError(error.BadSignature, (try decode(wire)).verify());
}

test "mesh presence maximum field bounds and unsupported version operation" {
    var key = try sign.KeyPair.fromSeed(@splat(53));
    defer key.deinit();
    const nick: [64]u8 = @splat('n');
    const username: [32]u8 = @splat('u');
    const host: [255]u8 = @splat('h');
    const realname: [256]u8 = @splat('r');
    const server: [255]u8 = @splat('s');
    const description: [256]u8 = @splat('d');
    var record = fixture(key.public_key);
    record.nick = &nick;
    record.username = &username;
    record.host = &host;
    record.realname = &realname;
    record.server = &server;
    record.description = &description;
    var buffer: [max_wire_len]u8 = undefined;
    const wire = try encode(record, &key, &buffer);
    try std.testing.expectEqual(@as(usize, max_wire_len), wire.len);
    try (try decode(wire)).verify();
    buffer[4] = 2;
    try std.testing.expectError(error.BadVersion, decode(wire));
    buffer[4] = version;
    buffer[5] = 0;
    try std.testing.expectError(error.InvalidField, decode(wire));
    const too_long: [257]u8 = @splat('d');
    record.description = &too_long;
    try std.testing.expectError(error.InvalidField, encodedLen(record));
    record = fixture(key.public_key);
    record.host = "::1";
    try (try decode(try encode(record, &key, &buffer))).verify();
}

test "mesh presence subject epoch counter is nonzero and canonical" {
    const id = try guestId(.{ .epoch = 3, .counter = 100 });
    try std.testing.expectEqual(Subject{ .epoch = 3, .counter = 100 }, try subject(id));
    try std.testing.expectError(error.InvalidField, guestId(.{ .epoch = 0, .counter = 100 }));
    try std.testing.expectError(error.InvalidField, guestId(.{ .epoch = 3, .counter = 0 }));
    try std.testing.expectError(error.InvalidField, subject(@splat(0)));
}

test "mesh presence signed claim revision is nonzero and within record revision" {
    var key = try sign.KeyPair.fromSeed(@splat(92));
    defer key.deinit();
    var buffer: [max_wire_len]u8 = undefined;
    var value = fixture(key.public_key);
    for ([_]u64{ 0, 2 }) |revision| {
        value.claim_revision = revision;
        try std.testing.expectError(error.InvalidField, encode(value, &key, &buffer));
    }
    value.revision = 4;
    value.claim_revision = 3;
    const original = try encode(value, &key, &buffer);
    const decoded = try decode(original);
    try decoded.verify();
    try std.testing.expectEqual(@as(u64, 3), decoded.record.claim_revision);
    buffer[77] ^= 1; // stays structurally valid, changes signed claim provenance
    try std.testing.expectError(error.BadSignature, (try decode(original)).verify());
}
