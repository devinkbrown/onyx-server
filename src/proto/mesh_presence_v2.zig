// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signed physical presence with explicit routing-class provenance. Structural
//! validity and class chronology do not admit an origin or authorize routing.
//! Existing v1 bytes/domains remain separate; this staging leaf has no live user.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const v1 = @import("mesh_presence.zig");

pub const domain = "onyx-mesh-presence-v2";
pub const magic = "OPRS";
pub const version: u8 = 2;
/// Physical incarnation helpers retain the identical v1 representation.
pub const GuestId = v1.GuestId;
pub const Subject = v1.Subject;
pub const guestId = v1.guestId;
pub const subject = v1.subject;
pub const Operation = v1.Operation;
pub const RoutingClass = enum(u8) {
    true_guest = 1,
    authenticated_untracked = 2,
    exact_reusable_attachment = 3,
};
pub const fixed_prefix_len = 103;
pub const min_wire_len = fixed_prefix_len + 12 + sign.signature_len;
pub const max_wire_len = v1.max_wire_len + 9;
pub const Error = v1.Error || error{RevisionExhausted};

pub const Record = struct {
    operation: Operation,
    origin: sign.PublicKey,
    guest: GuestId,
    revision: u64,
    /// Required signed class: no default/unknown guest inference is available.
    routing_class: RoutingClass,
    /// Revision that authored the last class change, independent of nickname.
    class_revision: u64,
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
        const policy = v1.ClockPolicy{ .max_lifetime_ms = self.max_lifetime_ms, .max_future_skew_ms = self.max_future_skew_ms };
        try policy.validate(legacyFields(record), now_ms);
    }
};

pub const Decoded = struct {
    record: Record,
    /// Exact original wire. Caller must keep borrowed input immutable through
    /// validation and every use; retained stores must own their own copy.
    wire: []const u8,

    pub fn verify(self: Decoded) Error!void {
        _ = try canonicalRecord(self);
        const signature: sign.Signature = self.wire[self.wire.len - sign.signature_len ..][0..sign.signature_len].*;
        const valid = sign.verifyCtx(domain, self.wire[0 .. self.wire.len - sign.signature_len], signature, self.record.origin) catch return error.BadSignature;
        if (!valid) return error.BadSignature;
    }
};

// Reuse the frozen public grammar/lifetime validation explicitly. This view
// never encodes, resigns or admits a v1 original and grants no routing fallback.
fn legacyFields(record: Record) v1.Record {
    return .{
        .operation = record.operation,
        .origin = record.origin,
        .guest = record.guest,
        .revision = record.revision,
        .claim_hlc = record.claim_hlc,
        .claim_revision = record.claim_revision,
        .issued_ms = record.issued_ms,
        .expires_ms = record.expires_ms,
        .nick = record.nick,
        .username = record.username,
        .host = record.host,
        .realname = record.realname,
        .server = record.server,
        .description = record.description,
    };
}

fn validate(record: Record) Error!void {
    _ = try v1.encodedLen(legacyFields(record));
    if (record.class_revision == 0 or record.class_revision > record.revision) return error.InvalidField;
    if (record.operation == .quit and record.class_revision == record.revision) return error.InvalidField;
}

fn fields(record: Record) [6][]const u8 {
    return .{ record.nick, record.username, record.host, record.realname, record.server, record.description };
}

pub fn encodedLen(record: Record) Error!usize {
    try validate(record);
    return std.math.add(usize, try v1.encodedLen(legacyFields(record)), 9) catch error.InvalidField;
}

/// Checked revision allocation; exhaustion fails before publication.
pub fn nextRevision(revision: u64) Error!u64 {
    if (revision == 0) return error.InvalidField;
    return std.math.add(u64, revision, 1) catch error.RevisionExhausted;
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
    out[94] = @intFromEnum(record.routing_class);
    std.mem.writeInt(u64, out[95..103], record.class_revision, .big);
    var cursor: usize = fixed_prefix_len;
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
    if (wire.len < min_wire_len) return error.Truncated;
    if (!std.mem.eql(u8, wire[0..4], magic) or wire[4] != version) return error.BadVersion;
    const operation = std.enums.fromInt(Operation, wire[5]) orelse return error.InvalidField;
    const routing_class = std.enums.fromInt(RoutingClass, wire[94]) orelse return error.InvalidField;
    const body_end = wire.len - sign.signature_len;
    var cursor: usize = fixed_prefix_len;
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
        .routing_class = routing_class,
        .class_revision = std.mem.readInt(u64, wire[95..103], .big),
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

/// Pure same-subject chronology. The caller independently verifies/admit each
/// immutable original; neither this helper nor class ordinals confer authority.
/// Wrong subjects and unsorted/equal revisions are API errors, not stale rows.
pub fn classProgress(older: Record, newer: Record) Error!bool {
    try orderedPair(older, newer);
    if (newer.class_revision == older.class_revision) return newer.routing_class == older.routing_class;
    if (older.operation == .quit or newer.class_revision <= older.revision) return false;
    return newer.routing_class != older.routing_class or newer.class_revision - older.revision >= 2;
}

fn orderedPair(older: Record, newer: Record) Error!void {
    try validate(older);
    try validate(newer);
    if (!std.mem.eql(u8, &older.origin, &newer.origin) or !std.mem.eql(u8, &older.guest, &newer.guest) or older.revision >= newer.revision) return error.InvalidField;
}

fn samePublicIdentity(older: Record, newer: Record) bool {
    const before = fields(older);
    const after = fields(newer);
    for (before, after) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

/// Nickname and class provenance are independent. Known terminal subjects may
/// only refresh negative revision/lifetime: every public/claim/class field stays.
pub fn consistentProgress(older: Record, newer: Record) Error!bool {
    if (!try classProgress(older, newer)) return false;
    if (newer.issued_ms < older.issued_ms) return false;
    if (older.operation == .quit) {
        return newer.operation == .quit and newer.claim_revision == older.claim_revision and
            newer.claim_hlc == older.claim_hlc and samePublicIdentity(older, newer);
    }
    if (newer.claim_revision == older.claim_revision) {
        return newer.claim_hlc == older.claim_hlc and std.mem.eql(u8, newer.nick, older.nick);
    }
    if (newer.claim_revision <= older.revision or newer.claim_hlc <= older.claim_hlc) return false;
    return !std.mem.eql(u8, newer.nick, older.nick) or newer.claim_revision - older.revision >= 2;
}

fn sameRecord(a: Record, b: Record) bool {
    return a.operation == b.operation and std.mem.eql(u8, &a.origin, &b.origin) and
        std.mem.eql(u8, &a.guest, &b.guest) and a.revision == b.revision and
        a.routing_class == b.routing_class and a.class_revision == b.class_revision and
        a.claim_hlc == b.claim_hlc and a.claim_revision == b.claim_revision and
        a.issued_ms == b.issued_ms and a.expires_ms == b.expires_ms and samePublicIdentity(a, b);
}

// Reject fabricated/stale decoded caches rather than classifying a different
// subject or history than the immutable original the caller actually verified.
fn canonicalRecord(value: Decoded) Error!Record {
    const record = (try decode(value.wire)).record;
    if (!sameRecord(record, value.record)) return error.InvalidField;
    return record;
}

pub const Disposition = enum { duplicate, obsolete, updated, quarantined };

/// Signature/admission verification is a caller prerequisite. This pure helper
/// classifies complete original bodies and preserves contradictions in BOTH
/// arrival orders, including resurrection after a signed QUIT. It publishes no
/// candidate, waives no expiry, and does not prove hidden local auth/token facts.
pub fn comparePresence(before: Decoded, incoming: Decoded) Error!Disposition {
    const a = try canonicalRecord(before);
    const b = try canonicalRecord(incoming);
    if (!std.mem.eql(u8, &a.origin, &b.origin) or !std.mem.eql(u8, &a.guest, &b.guest)) return error.InvalidField;
    if (before.wire.len < min_wire_len or incoming.wire.len < min_wire_len) return error.Truncated;
    if (std.mem.eql(u8, before.wire[0 .. before.wire.len - sign.signature_len], incoming.wire[0 .. incoming.wire.len - sign.signature_len])) return .duplicate;
    if (a.revision == b.revision) return .quarantined;
    const older = if (a.revision < b.revision) a else b;
    const newer = if (a.revision < b.revision) b else a;
    if (!try consistentProgress(older, newer)) return .quarantined;
    return if (b.revision < a.revision) .obsolete else .updated;
}

fn fixture(origin: sign.PublicKey) Record {
    return .{ .operation = .present, .origin = origin, .guest = guestId(.{ .epoch = 3, .counter = 17 }) catch unreachable, .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 7, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "PhysicalFar", .username = "guest", .host = "cloak.onyx", .realname = "Public physical identity", .server = "node-c", .description = "Far node" };
}

fn assertPair(key: *const sign.KeyPair, older: Record, newer: Record, conflict: bool) !void {
    var left: [max_wire_len]u8 = undefined;
    var right: [max_wire_len]u8 = undefined;
    const a = try decode(try encode(older, key, &left));
    const b = try decode(try encode(newer, key, &right));
    try a.verify();
    try b.verify();
    try std.testing.expectEqual(if (conflict) Disposition.quarantined else Disposition.updated, try comparePresence(a, b));
    try std.testing.expectEqual(if (conflict) Disposition.quarantined else Disposition.obsolete, try comparePresence(b, a));
    try std.testing.expectEqual(Disposition.duplicate, try comparePresence(a, a));
    try std.testing.expectEqual(Disposition.duplicate, try comparePresence(b, b));
}

test "presence v2 all required classes sign roundtrip exact offsets and physical identity aliases" {
    var key = try sign.KeyPair.fromSeed(@splat(119));
    defer key.deinit();
    const classes = [_]RoutingClass{ .true_guest, .authenticated_untracked, .exact_reusable_attachment };
    for (classes) |class| for ([_]Operation{ .present, .quit }) |operation| {
        var record = fixture(key.public_key);
        record.routing_class = class;
        record.operation = operation;
        if (operation == .quit) record.revision = 2;
        var bytes: [max_wire_len]u8 = undefined;
        const original = try encode(record, &key, &bytes);
        const decoded = try decode(original);
        try decoded.verify();
        try std.testing.expect(sameRecord(record, decoded.record));
        try std.testing.expectEqual(original.ptr, decoded.wire.ptr);
        try std.testing.expectEqual(@as(u8, 2), original[4]);
        try std.testing.expectEqual(@intFromEnum(class), original[94]);
        try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, original[95..103], .big));
        try std.testing.expectEqual(Subject{ .epoch = 3, .counter = 17 }, try subject(decoded.record.guest));
        var legacy: [v1.max_wire_len]u8 = undefined;
        const old_wire = try v1.encode(legacyFields(record), &key, &legacy);
        try std.testing.expectEqualSlices(u8, old_wire[0..4], original[0..4]);
        try std.testing.expectEqualSlices(u8, old_wire[5..94], original[5..94]);
        try std.testing.expectEqual(old_wire.len + 9, original.len);
    };
}

test "presence v2 rejects unknown versions classes invalid provenance and revision one quit without weakening v1" {
    var key = try sign.KeyPair.fromSeed(@splat(120));
    defer key.deinit();
    var bytes: [max_wire_len]u8 = undefined;
    var record = fixture(key.public_key);
    const original = try encode(record, &key, &bytes);
    for ([_]u8{ 0, 1, 3, 255 }) |unknown| {
        bytes[4] = unknown;
        try std.testing.expectError(error.BadVersion, decode(original));
    }
    bytes[4] = version;
    for ([_]u8{ 0, 4, 255 }) |unknown| {
        bytes[94] = unknown;
        try std.testing.expectError(error.InvalidField, decode(original));
    }
    bytes[94] = @intFromEnum(RoutingClass.true_guest);
    for ([_]u64{ 0, 2 }) |invalid| {
        std.mem.writeInt(u64, bytes[95..103], invalid, .big);
        try std.testing.expectError(error.InvalidField, decode(original));
        record.class_revision = invalid;
        try std.testing.expectError(error.InvalidField, encodedLen(record));
    }
    record = fixture(key.public_key);
    record.operation = .quit;
    try std.testing.expectError(error.InvalidField, encode(record, &key, &bytes));
    var old: [v1.max_wire_len]u8 = undefined;
    // The new terminal restriction is v2-specific; signed v1 behavior is frozen.
    try (try v1.decode(try v1.encode(legacyFields(record), &key, &old))).verify();
    record.revision = 2;
    record.class_revision = 2;
    try std.testing.expectError(error.InvalidField, encode(record, &key, &bytes));
    try std.testing.expectError(error.InvalidField, nextRevision(0));
    try std.testing.expectError(error.RevisionExhausted, nextRevision(std.math.maxInt(u64)));
    try std.testing.expectEqual(@as(u64, 2), try nextRevision(1));
}

test "presence v2 every truncation appended byte and signed mutation fails closed" {
    var key = try sign.KeyPair.fromSeed(@splat(121));
    defer key.deinit();
    var bytes: [max_wire_len + 1]u8 = undefined;
    const original = try encode(fixture(key.public_key), &key, &bytes);
    for (0..original.len) |length| {
        if (decode(original[0..length])) |decoded| {
            try std.testing.expectError(error.BadSignature, decoded.verify());
        } else |_| {}
    }
    bytes[original.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(bytes[0 .. original.len + 1]));
    for (0..original.len) |index| {
        bytes[index] ^= 1;
        if (decode(original)) |decoded| {
            try std.testing.expectError(error.BadSignature, decoded.verify());
        } else |_| {}
        bytes[index] ^= 1;
    }
    try (try decode(original)).verify();
}

test "presence v2 v1 version and application signature domains cannot substitute" {
    var key = try sign.KeyPair.fromSeed(@splat(122));
    defer key.deinit();
    const record = fixture(key.public_key);
    var newer: [max_wire_len]u8 = undefined;
    var older: [v1.max_wire_len]u8 = undefined;
    const current = try encode(record, &key, &newer);
    const legacy = try v1.encode(legacyFields(record), &key, &older);
    try std.testing.expectError(error.BadVersion, decode(legacy));
    try std.testing.expectError(error.BadVersion, v1.decode(current));
    const wrong_new = try key.signCtx(v1.domain, current[0 .. current.len - sign.signature_len]);
    @memcpy(newer[current.len - sign.signature_len ..][0..sign.signature_len], &wrong_new);
    try std.testing.expectError(error.BadSignature, (try decode(current)).verify());
    const wrong_old = try key.signCtx(domain, legacy[0 .. legacy.len - sign.signature_len]);
    @memcpy(older[legacy.len - sign.signature_len ..][0..sign.signature_len], &wrong_old);
    try std.testing.expectError(error.BadSignature, (try v1.decode(legacy)).verify());
}

test "presence v2 maximum exact size malformed public fields lengths and immutable decoded caches" {
    var key = try sign.KeyPair.fromSeed(@splat(123));
    defer key.deinit();
    var record = fixture(key.public_key);
    const nick: [64]u8 = @splat('n');
    const username: [32]u8 = @splat('u');
    const host: [255]u8 = @splat('h');
    const realname: [256]u8 = @splat('r');
    const server: [255]u8 = @splat('s');
    const description: [256]u8 = @splat('d');
    record.nick = &nick;
    record.username = &username;
    record.host = &host;
    record.realname = &realname;
    record.server = &server;
    record.description = &description;
    var bytes: [max_wire_len]u8 = undefined;
    const original = try encode(record, &key, &bytes);
    try std.testing.expectEqual(@as(usize, 1297), original.len);
    try std.testing.expectEqual(@as(usize, 179), min_wire_len);
    try std.testing.expectError(error.Truncated, encode(record, &key, bytes[0 .. original.len - 1]));
    var decoded = try decode(original);
    try decoded.verify();
    decoded.record.routing_class = .authenticated_untracked;
    try std.testing.expectError(error.InvalidField, decoded.verify());
    try std.testing.expectError(error.InvalidField, comparePresence(decoded, try decode(original)));
    const too_long: [257]u8 = @splat('d');
    record.description = &too_long;
    try std.testing.expectError(error.InvalidField, encodedLen(record));
    record = fixture(key.public_key);
    for ([_][]const u8{ "a b", "a!b", "a@b", "a\r\nQUIT", ":a", "", "a.b" }) |invalid| {
        record.nick = invalid;
        try std.testing.expectError(error.InvalidField, encodedLen(record));
    }
    record = fixture(key.public_key);
    record.username = ":user";
    try std.testing.expectError(error.InvalidField, encodedLen(record));
    record = fixture(key.public_key);
    record.host = "bad host";
    try std.testing.expectError(error.InvalidField, encodedLen(record));
    record = fixture(key.public_key);
    record.guest = @splat(0);
    try std.testing.expectError(error.InvalidField, encodedLen(record));
    record = fixture(key.public_key);
    record.origin = @splat(0);
    try std.testing.expectError(error.OriginMismatch, encode(record, &key, &bytes));
    const valid = try encode(fixture(key.public_key), &key, &bytes);
    std.mem.writeInt(u16, bytes[103..105], 65535, .big);
    try std.testing.expectError(error.Truncated, decode(valid));
}

test "presence v2 all six class transitions renewals skipped returns and impossible provenance are order symmetric" {
    var key = try sign.KeyPair.fromSeed(@splat(124));
    defer key.deinit();
    const classes = [_]RoutingClass{ .true_guest, .authenticated_untracked, .exact_reusable_attachment };
    for (classes) |before| for (classes) |after| {
        var older = fixture(key.public_key);
        older.routing_class = before;
        var newer = older;
        newer.revision = 2;
        newer.routing_class = after;
        newer.class_revision = if (before == after) 1 else 2;
        try assertPair(&key, older, newer, false);
        if (before != after) {
            // A class-only transition does not strengthen the nickname claim.
            try std.testing.expectEqual(older.claim_hlc, newer.claim_hlc);
            try std.testing.expectEqual(older.claim_revision, newer.claim_revision);
        }
    };
    const older = fixture(key.public_key);
    var next = older;
    next.revision = 2;
    next.class_revision = 2;
    try assertPair(&key, older, next, true);
    next.revision = 3;
    next.class_revision = 3;
    try assertPair(&key, older, next, false);
    var middle = older;
    middle.revision = 5;
    middle.class_revision = 2;
    next = middle;
    next.revision = 8;
    next.class_revision = 7;
    next.routing_class = .exact_reusable_attachment;
    try assertPair(&key, middle, next, false);
    next.class_revision = 4;
    try assertPair(&key, middle, next, true);
    next.routing_class = middle.routing_class;
    next.class_revision = 7;
    try assertPair(&key, middle, next, false);
    next.class_revision = 6;
    try assertPair(&key, middle, next, true);
    next = older;
    next.revision = 4;
    next.class_revision = 4;
    try assertPair(&key, older, next, false);
}

test "presence v2 nickname progression is independent and unchanged class provenance cannot manufacture claim" {
    var key = try sign.KeyPair.fromSeed(@splat(125));
    defer key.deinit();
    const older = fixture(key.public_key);
    var newer = older;
    newer.revision = 2;
    newer.claim_revision = 2;
    newer.claim_hlc = 8;
    newer.nick = "Renamed";
    try assertPair(&key, older, newer, false);
    newer.routing_class = .authenticated_untracked;
    newer.class_revision = 2;
    try assertPair(&key, older, newer, false);
    newer.nick = older.nick;
    try assertPair(&key, older, newer, true);
    newer.claim_revision = older.claim_revision;
    newer.claim_hlc = older.claim_hlc;
    try assertPair(&key, older, newer, false);
    newer.issued_ms = older.issued_ms - 1;
    try assertPair(&key, older, newer, true);
    newer = older;
    newer.revision = 4;
    newer.claim_revision = 3;
    newer.claim_hlc = 9;
    try assertPair(&key, older, newer, false);
    var observed = older;
    observed.revision = 3;
    try assertPair(&key, observed, newer, true);
}

test "presence v2 terminal chronology fixes class claim public identity and quarantines resurrection in both orders" {
    var key = try sign.KeyPair.fromSeed(@splat(126));
    defer key.deinit();
    const first = fixture(key.public_key);
    var quit = first;
    quit.operation = .quit;
    quit.revision = 2;
    try assertPair(&key, first, quit, false);
    var resurrected = first;
    resurrected.revision = 3;
    try assertPair(&key, quit, resurrected, true);
    var skipped = quit;
    skipped.revision = 3;
    skipped.routing_class = .authenticated_untracked;
    skipped.class_revision = 2;
    try assertPair(&key, first, skipped, false);
    var refreshed = skipped;
    refreshed.revision = 6;
    refreshed.issued_ms += 100;
    refreshed.expires_ms += 200;
    try assertPair(&key, skipped, refreshed, false);
    inline for (.{ "nick", "username", "host", "realname", "server", "description" }) |field| {
        var contradictory = refreshed;
        @field(contradictory, field) = "Changed";
        try assertPair(&key, skipped, contradictory, true);
    }
    var contradictory = refreshed;
    contradictory.routing_class = .exact_reusable_attachment;
    contradictory.class_revision = 5;
    try assertPair(&key, skipped, contradictory, true);
    contradictory = refreshed;
    contradictory.claim_hlc += 1;
    try assertPair(&key, skipped, contradictory, true);
    contradictory = refreshed;
    contradictory.claim_revision = 5;
    contradictory.claim_hlc += 1;
    try assertPair(&key, skipped, contradictory, true);
    contradictory = refreshed;
    contradictory.class_revision = 5;
    try assertPair(&key, skipped, contradictory, true);
    const policy = ClockPolicy{ .max_lifetime_ms = 1000, .max_future_skew_ms = 20 };
    try policy.validate(quit, 1999);
    try std.testing.expectError(error.Expired, policy.validate(quit, 2000));
    // Pure history never waives admission clocks; an expired negative can only
    // enter through a separately authorized future repair admission seam.
    try assertPair(&key, first, quit, false);
}

test "presence v2 same revision class equivocation and full subject mismatch never become duplicates" {
    var key = try sign.KeyPair.fromSeed(@splat(127));
    defer key.deinit();
    const a = fixture(key.public_key);
    var b = a;
    b.routing_class = .authenticated_untracked;
    try assertPair(&key, a, b, true);
    var left: [max_wire_len]u8 = undefined;
    var right: [max_wire_len]u8 = undefined;
    var older = a;
    older.revision = 3;
    var newer = older;
    newer.class_revision = 2;
    try assertPair(&key, older, newer, true);
    newer = older;
    newer.guest = try guestId(.{ .epoch = 3, .counter = 18 });
    const first = try decode(try encode(older, &key, &left));
    const second = try decode(try encode(newer, &key, &right));
    try first.verify();
    try second.verify();
    try std.testing.expectError(error.InvalidField, comparePresence(first, second));
    newer = older;
    newer.revision = 4;
    newer.origin = @splat(2);
    try std.testing.expectError(error.InvalidField, classProgress(older, newer));
    newer = older;
    try std.testing.expectError(error.InvalidField, classProgress(older, newer));
}

fn historyIndex(older_revision: usize, newer_revision: usize, older_class: RoutingClass, older_class_revision: usize, newer_class: RoutingClass, newer_class_revision: usize) usize {
    return (((((older_revision * 6 + newer_revision) * 3 + @intFromEnum(older_class) - 1) * 6 + older_class_revision) * 3 + @intFromEnum(newer_class) - 1) * 6 + newer_class_revision);
}

test "presence v2 exhaustive finite class histories accept exactly possible subsequence chronology" {
    // An independent history oracle authors provenance ONLY on actual class
    // changes. Enumerate every five-revision path and all its observed pairs,
    // then compare every structurally allowed pair against that full oracle.
    var possible: [6 * 6 * 3 * 6 * 3 * 6]bool = @splat(false);
    const classes = [_]RoutingClass{ .true_guest, .authenticated_untracked, .exact_reusable_attachment };
    for (0..243) |encoded_path| {
        var path = encoded_path;
        var records: [5]Record = undefined;
        for (&records, 0..) |*record, step| {
            record.* = fixture(@splat(4));
            record.revision = @intCast(step + 1);
            record.routing_class = classes[path % 3];
            path /= 3;
            record.class_revision = if (step == 0 or record.routing_class != records[step - 1].routing_class) record.revision else records[step - 1].class_revision;
        }
        for (records, 0..) |older, i| for (records[i + 1 ..]) |newer| {
            possible[historyIndex(@intCast(older.revision), @intCast(newer.revision), older.routing_class, @intCast(older.class_revision), newer.routing_class, @intCast(newer.class_revision))] = true;
            try std.testing.expect(try classProgress(older, newer));
            try std.testing.expect(try consistentProgress(older, newer));
        };
    }
    for (1..5) |older_revision| for (older_revision + 1..6) |newer_revision| {
        for (classes) |older_class| for (classes) |newer_class| {
            for (1..older_revision + 1) |older_class_revision| for (1..newer_revision + 1) |newer_class_revision| {
                var older = fixture(@splat(4));
                older.revision = @intCast(older_revision);
                older.routing_class = older_class;
                older.class_revision = @intCast(older_class_revision);
                var newer = older;
                newer.revision = @intCast(newer_revision);
                newer.routing_class = newer_class;
                newer.class_revision = @intCast(newer_class_revision);
                const expected = possible[historyIndex(older_revision, newer_revision, older_class, older_class_revision, newer_class, newer_class_revision)];
                try std.testing.expectEqual(expected, try classProgress(older, newer));
                try std.testing.expectEqual(expected, try consistentProgress(older, newer));
            };
        };
    };
}
