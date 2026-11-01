//! Proposed, unadvertised single-signature presence with immutable membership binding.
//! Structural validity/signature approval are not live presence admission.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const v2 = @import("mesh_presence_v2.zig");
const snapshot = @import("guest_membership_snapshot.zig");

pub const domain = "onyx-mesh-presence-v3";
pub const magic = "OPRS";
pub const version: u8 = 3;
pub const GuestId = v2.GuestId;
pub const guestId = v2.guestId;
pub const subject = v2.subject;
pub const Operation = v2.Operation;
pub const RoutingClass = v2.RoutingClass;
pub const ManifestID = snapshot.ManifestID;
pub const nextMembershipRevision = v2.nextRevision;
pub const fixed_prefix_len = v2.fixed_prefix_len;
pub const binding_len: usize = 40;
pub const min_wire_len = v2.min_wire_len + binding_len;
pub const max_wire_len = v2.max_wire_len + binding_len;
pub const Error = v2.Error || error{UnapprovedOrigin};

pub const Record = struct {
    operation: Operation,
    origin: sign.PublicKey,
    guest: GuestId,
    revision: u64,
    routing_class: RoutingClass,
    class_revision: u64,
    claim_hlc: u64,
    claim_revision: u64,
    issued_ms: i64,
    expires_ms: i64,
    nick: []const u8,
    username: []const u8,
    host: []const u8,
    realname: []const u8,
    server: []const u8,
    description: []const u8,
    membership_revision: u64,
    manifest_id: ManifestID,
};

fn legacyFields(r: Record) v2.Record {
    return .{ .operation = r.operation, .origin = r.origin, .guest = r.guest, .revision = r.revision, .routing_class = r.routing_class, .class_revision = r.class_revision, .claim_hlc = r.claim_hlc, .claim_revision = r.claim_revision, .issued_ms = r.issued_ms, .expires_ms = r.expires_ms, .nick = r.nick, .username = r.username, .host = r.host, .realname = r.realname, .server = r.server, .description = r.description };
}
fn fields(r: Record) [6][]const u8 {
    return .{ r.nick, r.username, r.host, r.realname, r.server, r.description };
}
pub fn encodedLen(r: Record) Error!usize {
    if (r.membership_revision == 0) return error.InvalidField;
    return std.math.add(usize, try v2.encodedLen(legacyFields(r)), binding_len) catch error.InvalidField;
}
pub const ClockPolicy = struct {
    max_lifetime_ms: i64,
    max_future_skew_ms: i64,
    pub fn validate(self: ClockPolicy, r: Record, now: i64) Error!void {
        _ = try encodedLen(r);
        try (v2.ClockPolicy{ .max_lifetime_ms = self.max_lifetime_ms, .max_future_skew_ms = self.max_future_skew_ms }).validate(legacyFields(r), now);
    }
};

pub fn encode(r: Record, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    const length = try encodedLen(r);
    if (!std.mem.eql(u8, &r.origin, &key.public_key)) return error.OriginMismatch;
    if (out.len < length) return error.Truncated;
    @memcpy(out[0..4], magic);
    out[4] = version;
    out[5] = @backingInt(r.operation);
    out[6..38].* = r.origin;
    out[38..54].* = r.guest;
    std.mem.writeInt(u64, out[54..62], r.revision, .big);
    std.mem.writeInt(u64, out[62..70], r.claim_hlc, .big);
    std.mem.writeInt(u64, out[70..78], r.claim_revision, .big);
    std.mem.writeInt(i64, out[78..86], r.issued_ms, .big);
    std.mem.writeInt(i64, out[86..94], r.expires_ms, .big);
    out[94] = @backingInt(r.routing_class);
    std.mem.writeInt(u64, out[95..103], r.class_revision, .big);
    var cursor: usize = fixed_prefix_len;
    for (fields(r)) |value| {
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(value.len), .big);
        cursor += 2;
        @memcpy(out[cursor..][0..value.len], value);
        cursor += value.len;
    }
    std.mem.writeInt(u64, out[cursor..][0..8], r.membership_revision, .big);
    cursor += 8;
    @memcpy(out[cursor..][0..32], &r.manifest_id);
    cursor += 32;
    const signature = try key.signCtx(domain, out[0..cursor]);
    @memcpy(out[cursor..][0..sign.signature_len], &signature);
    return out[0..length];
}

pub const Decoded = struct {
    record: Record,
    wire: []const u8,
    pub fn verify(self: Decoded, approved_origins: []const sign.PublicKey) Error!void {
        const actual = try canonical(self);
        var approved = false;
        for (approved_origins) |origin| approved = approved or std.mem.eql(u8, &origin, &actual.origin);
        if (!approved) return error.UnapprovedOrigin;
        const signature: sign.Signature = self.wire[self.wire.len - sign.signature_len ..][0..sign.signature_len].*;
        const ok = sign.verifyCtx(domain, self.wire[0 .. self.wire.len - sign.signature_len], signature, actual.origin) catch return error.BadSignature;
        if (!ok) return error.BadSignature;
    }
};
pub fn decode(wire: []const u8) Error!Decoded {
    if (wire.len < min_wire_len) return error.Truncated;
    if (wire.len > max_wire_len) return error.TrailingBytes;
    if (!std.mem.eql(u8, wire[0..4], magic) or wire[4] != version) return error.BadVersion;
    const end = wire.len - sign.signature_len - binding_len;
    var cursor: usize = fixed_prefix_len;
    var values: [6][]const u8 = undefined;
    for (&values) |*value| {
        if (cursor > end or end - cursor < 2) return error.Truncated;
        const length = std.mem.readInt(u16, wire[cursor..][0..2], .big);
        cursor += 2;
        if (length > end - cursor) return error.Truncated;
        value.* = wire[cursor..][0..length];
        cursor += length;
    }
    if (cursor != end) return error.TrailingBytes;
    const r = Record{ .operation = std.enums.fromInt(Operation, wire[5]) orelse return error.InvalidField, .origin = wire[6..38].*, .guest = wire[38..54].*, .revision = std.mem.readInt(u64, wire[54..62], .big), .claim_hlc = std.mem.readInt(u64, wire[62..70], .big), .claim_revision = std.mem.readInt(u64, wire[70..78], .big), .issued_ms = std.mem.readInt(i64, wire[78..86], .big), .expires_ms = std.mem.readInt(i64, wire[86..94], .big), .routing_class = std.enums.fromInt(RoutingClass, wire[94]) orelse return error.InvalidField, .class_revision = std.mem.readInt(u64, wire[95..103], .big), .nick = values[0], .username = values[1], .host = values[2], .realname = values[3], .server = values[4], .description = values[5], .membership_revision = std.mem.readInt(u64, wire[end..][0..8], .big), .manifest_id = wire[end + 8 ..][0..32].* };
    _ = try encodedLen(r);
    return .{ .record = r, .wire = wire };
}
fn sameRecord(a: Record, b: Record) bool {
    if (a.operation != b.operation or !std.mem.eql(u8, &a.origin, &b.origin) or !std.mem.eql(u8, &a.guest, &b.guest) or
        a.revision != b.revision or a.routing_class != b.routing_class or a.class_revision != b.class_revision or
        a.claim_hlc != b.claim_hlc or a.claim_revision != b.claim_revision or a.issued_ms != b.issued_ms or a.expires_ms != b.expires_ms or
        a.membership_revision != b.membership_revision or !std.mem.eql(u8, &a.manifest_id, &b.manifest_id)) return false;
    for (fields(a), fields(b)) |left, right| if (!std.mem.eql(u8, left, right)) return false;
    return true;
}
fn canonical(d: Decoded) Error!Record {
    const r = (try decode(d.wire)).record;
    if (!sameRecord(r, d.record)) return error.InvalidField;
    return r;
}
/// A pure binding check; caller still needs admitted current live presence.
pub fn matchesManifest(r: Record, m: snapshot.DecodedManifest) bool {
    _ = encodedLen(r) catch return false;
    const actual = snapshot.decodeManifest(m.wire) catch return false;
    if (!std.meta.eql(actual.record, m.record)) return false;
    const id = snapshot.manifestId(m.wire) catch return false;
    return std.mem.eql(u8, &r.origin, &actual.record.origin) and std.mem.eql(u8, &r.guest, &actual.record.guest) and
        r.claim_hlc == actual.record.claim_hlc and r.claim_revision == actual.record.claim_revision and
        r.routing_class == actual.record.routing_class and r.class_revision == actual.record.class_revision and
        r.membership_revision == actual.record.membership_revision and std.mem.eql(u8, &r.manifest_id, &id) and
        (r.operation != .quit or (actual.record.channel_count == 0 and actual.record.encoded_bytes == 0));
}
pub const Disposition = enum { duplicate, obsolete, updated, quarantined };
pub fn comparePresence(before: Decoded, incoming: Decoded) Error!Disposition {
    const a = try canonical(before);
    const b = try canonical(incoming);
    if (!std.mem.eql(u8, &a.origin, &b.origin) or !std.mem.eql(u8, &a.guest, &b.guest)) return error.InvalidField;
    if (std.mem.eql(u8, before.wire[0 .. before.wire.len - sign.signature_len], incoming.wire[0 .. incoming.wire.len - sign.signature_len])) return .duplicate;
    if (a.revision == b.revision) return .quarantined;
    const older = if (a.revision < b.revision) a else b;
    const newer = if (a.revision < b.revision) b else a;
    if (!try v2.consistentProgress(legacyFields(older), legacyFields(newer))) return .quarantined;
    if (newer.membership_revision < older.membership_revision) return .quarantined;
    if (newer.membership_revision == older.membership_revision and
        (!std.mem.eql(u8, &older.manifest_id, &newer.manifest_id) or older.claim_revision != newer.claim_revision or
            older.claim_hlc != newer.claim_hlc or older.class_revision != newer.class_revision or older.routing_class != newer.routing_class)) return .quarantined;
    return if (b.revision > a.revision) .updated else .obsolete;
}

fn fixture(origin: sign.PublicKey) Record {
    return .{ .operation = .present, .origin = origin, .guest = guestId(.{ .epoch = 1, .counter = 1 }) catch unreachable, .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 1, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "public.cloak", .realname = "Public guest", .server = "origin.test", .description = "Public origin", .membership_revision = 1, .manifest_id = @splat(4) };
}
test "presence v3 single signature strict roots truncations and no legacy fallback" {
    var key = try sign.KeyPair.fromSeed(@splat(7));
    defer key.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(8));
    defer other.deinit();
    const r = fixture(key.public_key);
    var bytes: [max_wire_len + 1]u8 = undefined;
    const wire = try encode(r, &key, &bytes);
    try std.testing.expectEqual(try v2.encodedLen(legacyFields(r)) + binding_len, wire.len);
    try (try decode(wire)).verify(&.{key.public_key});
    try std.testing.expectError(error.UnapprovedOrigin, (try decode(wire)).verify(&.{}));
    try std.testing.expectError(error.UnapprovedOrigin, (try decode(wire)).verify(&.{other.public_key}));
    for (0..wire.len) |n| try std.testing.expectError(error.Truncated, decode(wire[0..n]));
    bytes[wire.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(bytes[0 .. wire.len + 1]));
    var fabricated = try decode(wire);
    fabricated.record.membership_revision += 1;
    try std.testing.expectError(error.InvalidField, fabricated.verify(&.{key.public_key}));
    bytes[4] = 2;
    try std.testing.expectError(error.BadVersion, decode(wire));
    bytes[4] = version;
    bytes[wire.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, (try decode(wire)).verify(&.{key.public_key}));
    var bad = r;
    bad.membership_revision = 0;
    try std.testing.expectError(error.InvalidField, encodedLen(bad));
}
test "presence v3 chronology binds membership independently from public host renewal" {
    var key = try sign.KeyPair.fromSeed(@splat(9));
    defer key.deinit();
    const old = fixture(key.public_key);
    var newer = old;
    newer.revision = 2;
    newer.host = "new.public.cloak";
    var a: [max_wire_len]u8 = undefined;
    var b: [max_wire_len]u8 = undefined;
    const before = try decode(try encode(old, &key, &a));
    var incoming = try decode(try encode(newer, &key, &b));
    try std.testing.expectEqual(Disposition.updated, try comparePresence(before, incoming));
    try std.testing.expectEqual(Disposition.obsolete, try comparePresence(incoming, before));
    newer.manifest_id = @splat(5);
    incoming = try decode(try encode(newer, &key, &b));
    try std.testing.expectEqual(Disposition.quarantined, try comparePresence(before, incoming));
    newer.membership_revision = 2;
    incoming = try decode(try encode(newer, &key, &b));
    try std.testing.expectEqual(Disposition.updated, try comparePresence(before, incoming));
    newer.membership_revision = 1;
    newer.claim_hlc = 2;
    newer.claim_revision = 2;
    newer.nick = "Renamed";
    incoming = try decode(try encode(newer, &key, &b));
    try std.testing.expectEqual(Disposition.quarantined, try comparePresence(before, incoming));
    newer.membership_revision = 2;
    incoming = try decode(try encode(newer, &key, &b));
    try std.testing.expectEqual(Disposition.updated, try comparePresence(before, incoming));
    newer.revision = std.math.maxInt(u64);
    _ = try encodedLen(newer);
    try std.testing.expectError(error.RevisionExhausted, nextMembershipRevision(newer.revision));
}
