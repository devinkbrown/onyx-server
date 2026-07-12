// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-server session reclaim tokens (HMAC-sealed).
//!
//! Today a client's session-resume token is only honored by the node that
//! issued it. This module produces a portable, integrity-protected reclaim
//! token that any Suimyaku mesh node can verify using the shared mesh key,
//! without trusting the presenting client.
//!
//! A token is a canonical, length-prefixed serialization of `ReclaimFields`
//! followed by an HMAC-SHA256 tag computed over that serialization. The mesh
//! shared key is supplied by the caller — never hardcoded here. The codec is
//! deterministic so two honest nodes derive byte-identical tokens for the same
//! fields, and verification is constant-time over the tag.
//!
//! Pure, std-only, no globals, no I/O, no syscalls. Cross-compiles to any
//! 64-bit target including x86_64-windows.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Length of the trailing integrity tag, in bytes.
pub const tag_len: usize = HmacSha256.mac_length;

/// A single field's length is encoded as a u16, so byte-strings are bounded.
pub const max_field_len: usize = std.math.maxInt(u16);

/// Magic + version prefix so a token from a different codec version is rejected
/// at the format layer rather than silently mis-parsed.
const magic: [4]u8 = .{ 'S', 'R', 'M', 1 };

/// Number of variable-length byte fields in the serialization.
const str_field_count = 3;
/// Number of fixed u64 fields (issued_ms, expiry_ms, nonce).
const u64_field_count = 3;

/// Plaintext claims carried by a reclaim token.
pub const ReclaimFields = struct {
    /// Account name the session belongs to.
    account: []const u8,
    /// Opaque per-session identifier.
    session_id: []const u8,
    /// Name of the node that currently holds (or last held) the live session.
    origin_node: []const u8,
    /// Issuance time, milliseconds since an agreed epoch.
    issued_ms: u64,
    /// Expiry time, milliseconds since an agreed epoch. Token invalid after.
    expiry_ms: u64,
    /// Single-use nonce for replay rejection.
    nonce: u64,
};

/// Errors surfaced when opening a token.
pub const OpenError = error{
    /// Structural problem: bad magic, truncation, or a length that overruns.
    BadFormat,
    /// The integrity tag did not verify under the supplied key.
    BadMac,
    /// `now_ms` is past the token's `expiry_ms`.
    Expired,
};

/// Node-side outcome of evaluating a presented reclaim token.
pub const ReclaimDecision = union(enum) {
    /// This node already holds the live session; reclaim it here.
    grant_local,
    /// The live session lives on another reachable node; redirect there.
    grant_redirect: []const u8,
    /// Token has expired.
    deny_expired,
    /// Origin node is neither us nor reachable; cannot place the session.
    deny_unknown,
    /// Nonce already seen; replayed token.
    deny_replay,
};

/// Total serialized length (header + fields + tag) for the given field values.
pub fn sealedLen(fields: ReclaimFields) error{BadFormat}!usize {
    if (fields.account.len > max_field_len) return error.BadFormat;
    if (fields.session_id.len > max_field_len) return error.BadFormat;
    if (fields.origin_node.len > max_field_len) return error.BadFormat;

    // magic(4)
    // + per string: len(2) + bytes
    // + 3 * u64(8)
    // + tag
    var n: usize = magic.len;
    n += 2 + fields.account.len;
    n += 2 + fields.session_id.len;
    n += 2 + fields.origin_node.len;
    n += u64_field_count * 8;
    n += tag_len;
    return n;
}

fn writeU16(buf: []u8, off: *usize, v: u16) void {
    std.mem.writeInt(u16, buf[off.*..][0..2], v, .big);
    off.* += 2;
}

fn writeU64(buf: []u8, off: *usize, v: u64) void {
    std.mem.writeInt(u64, buf[off.*..][0..8], v, .big);
    off.* += 8;
}

fn writeStr(buf: []u8, off: *usize, s: []const u8) void {
    writeU16(buf, off, @intCast(s.len));
    @memcpy(buf[off.*..][0..s.len], s);
    off.* += s.len;
}

/// Serialize `fields` and append an HMAC-SHA256 tag, writing into `out`.
/// Returns the number of bytes written. Deterministic. `out` must be at least
/// `sealedLen(fields)` bytes.
pub fn seal(key: []const u8, fields: ReclaimFields, out: []u8) !usize {
    const total = try sealedLen(fields);
    if (out.len < total) return error.BadFormat;

    var off: usize = 0;
    @memcpy(out[0..magic.len], &magic);
    off += magic.len;

    writeStr(out, &off, fields.account);
    writeStr(out, &off, fields.session_id);
    writeStr(out, &off, fields.origin_node);
    writeU64(out, &off, fields.issued_ms);
    writeU64(out, &off, fields.expiry_ms);
    writeU64(out, &off, fields.nonce);

    // off now points at the start of the tag region == body length.
    var tag: [tag_len]u8 = undefined;
    HmacSha256.create(&tag, out[0..off], key);
    @memcpy(out[off..][0..tag_len], &tag);
    off += tag_len;

    std.debug.assert(off == total);
    return total;
}

const Reader = struct {
    buf: []const u8,
    off: usize = 0,

    fn need(self: *Reader, n: usize) OpenError!void {
        if (self.off + n > self.buf.len) return error.BadFormat;
    }

    fn readU16(self: *Reader) OpenError!u16 {
        try self.need(2);
        const v = std.mem.readInt(u16, self.buf[self.off..][0..2], .big);
        self.off += 2;
        return v;
    }

    fn readU64(self: *Reader) OpenError!u64 {
        try self.need(8);
        const v = std.mem.readInt(u64, self.buf[self.off..][0..8], .big);
        self.off += 8;
        return v;
    }

    fn readStr(self: *Reader) OpenError![]const u8 {
        const n = try self.readU16();
        try self.need(n);
        const s = self.buf[self.off..][0..n];
        self.off += n;
        return s;
    }
};

/// Parse and verify a sealed token. Verifies the HMAC tag in constant time,
/// then rejects if `now_ms > expiry_ms`. The returned slices alias `bytes`.
pub fn open(key: []const u8, bytes: []const u8, now_ms: u64) OpenError!ReclaimFields {
    // Minimum viable token: magic + 3 empty strings (2 bytes each) + 3 u64 + tag.
    const min_len = magic.len + str_field_count * 2 + u64_field_count * 8 + tag_len;
    if (bytes.len < min_len) return error.BadFormat;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadFormat;

    // Split body and tag. The tag is always the final tag_len bytes.
    const body = bytes[0 .. bytes.len - tag_len];
    const received_tag = bytes[bytes.len - tag_len ..][0..tag_len];

    var r = Reader{ .buf = body, .off = magic.len };
    const account = try r.readStr();
    const session_id = try r.readStr();
    const origin_node = try r.readStr();
    const issued_ms = try r.readU64();
    const expiry_ms = try r.readU64();
    const nonce = try r.readU64();

    // Every body byte must be consumed; trailing garbage before the tag is a
    // format error, not a MAC failure.
    if (r.off != body.len) return error.BadFormat;

    var expected: [tag_len]u8 = undefined;
    HmacSha256.create(&expected, body, key);
    if (!std.crypto.timing_safe.eql([tag_len]u8, expected, received_tag.*)) {
        return error.BadMac;
    }

    if (now_ms > expiry_ms) return error.Expired;

    return .{
        .account = account,
        .session_id = session_id,
        .origin_node = origin_node,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
        .nonce = nonce,
    };
}

/// Node-side reclaim logic. Assumes the token's integrity has already been
/// verified by `open` (so `fields` is trustworthy).
///
/// Precedence:
///   1. expired              -> deny_expired
///   2. replayed nonce       -> deny_replay
///   3. local holds session  -> grant_local
///   4. origin is self       -> deny_unknown (we are origin yet hold nothing;
///                              the live session is gone)
///   5. origin is elsewhere  -> grant_redirect(origin_node)
pub fn decide(
    fields: ReclaimFields,
    local_holds_session: bool,
    origin_is_self: bool,
    seen_nonce: bool,
    now_ms: u64,
) ReclaimDecision {
    if (now_ms > fields.expiry_ms) return .deny_expired;
    if (seen_nonce) return .deny_replay;
    if (local_holds_session) return .grant_local;
    if (origin_is_self) return .deny_unknown;
    return .{ .grant_redirect = fields.origin_node };
}

/// A tiny, pure, fixed-capacity nonce-replay tracker. Bounded ring of recently
/// seen nonces; `check` reports whether a nonce was already present and records
/// it otherwise. No allocation, no globals — caller owns the instance.
pub fn ReplayRing(comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    return struct {
        const Self = @This();

        slots: [capacity]u64 = @splat(0),
        /// used[i] true means slot i holds a live (recorded) nonce.
        used: [capacity]bool = @splat(false),
        head: usize = 0,

        /// True if `nonce` is already recorded (a replay). PURE — never mutates,
        /// so a non-consuming outcome (grant_redirect / deny_*) can consult the
        /// ring without burning the nonce for a later legitimate consume.
        pub fn contains(self: *const Self, nonce: u64) bool {
            var i: usize = 0;
            while (i < capacity) : (i += 1) {
                if (self.used[i] and self.slots[i] == nonce) return true;
            }
            return false;
        }

        /// Record `nonce` as seen (evicting the oldest entry if full; idempotent
        /// on an already-recorded nonce). Call ONLY on an outcome that truly
        /// consumes the token (a grant) — redirects and denials must stay
        /// idempotent so they never strand a still-valid token.
        pub fn record(self: *Self, nonce: u64) void {
            if (self.contains(nonce)) return;
            self.slots[self.head] = nonce;
            self.used[self.head] = true;
            self.head = (self.head + 1) % capacity;
        }

        /// contains-then-record in one step: true if `nonce` was already
        /// recorded, otherwise records it and returns false. Only for callers
        /// where every first sight IS a consume.
        pub fn check(self: *Self, nonce: u64) bool {
            if (self.contains(nonce)) return true;
            self.record(nonce);
            return false;
        }
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

const test_key = "mesh-shared-key-do-not-ship-this-0123456789";

fn sampleFields() ReclaimFields {
    return .{
        .account = "alice",
        .session_id = "sess-7f3a",
        .origin_node = "node-east-01",
        .issued_ms = 1_000_000,
        .expiry_ms = 2_000_000,
        .nonce = 0xDEAD_BEEF_CAFE_F00D,
    };
}

/// Test helper: seal into a stack buffer and return the populated slice.
fn sealToBuf(key: []const u8, fields: ReclaimFields, buf: []u8) ![]u8 {
    const n = try seal(key, fields, buf);
    return buf[0..n];
}

test "round-trip seal then open recovers all fields" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;

    // Act
    const tok = try sealToBuf(test_key, fields, &buf);
    const got = try open(test_key, tok, fields.issued_ms);

    // Assert
    try testing.expectEqualStrings(fields.account, got.account);
    try testing.expectEqualStrings(fields.session_id, got.session_id);
    try testing.expectEqualStrings(fields.origin_node, got.origin_node);
    try testing.expectEqual(fields.issued_ms, got.issued_ms);
    try testing.expectEqual(fields.expiry_ms, got.expiry_ms);
    try testing.expectEqual(fields.nonce, got.nonce);
}

test "seal is deterministic for identical inputs" {
    // Arrange
    const fields = sampleFields();
    var a: [256]u8 = undefined;
    var b: [256]u8 = undefined;

    // Act
    const ta = try sealToBuf(test_key, fields, &a);
    const tb = try sealToBuf(test_key, fields, &b);

    // Assert
    try testing.expectEqualSlices(u8, ta, tb);
}

test "sealedLen matches bytes actually written" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;

    // Act
    const predicted = try sealedLen(fields);
    const n = try seal(test_key, fields, &buf);

    // Assert
    try testing.expectEqual(predicted, n);
}

test "seal rejects an out buffer that is too small" {
    // Arrange
    const fields = sampleFields();
    var tiny: [8]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.BadFormat, seal(test_key, fields, &tiny));
}

test "tampering with one body byte yields BadMac" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act: flip a bit inside the account region (just past the magic+len).
    tok[7] ^= 0x01;

    // Assert
    try testing.expectError(error.BadMac, open(test_key, tok, fields.issued_ms));
}

test "tampering with a tag byte yields BadMac" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act: flip a bit in the final (tag) byte.
    tok[tok.len - 1] ^= 0x80;

    // Assert
    try testing.expectError(error.BadMac, open(test_key, tok, fields.issued_ms));
}

test "opening with the wrong key yields BadMac" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act / Assert
    try testing.expectError(error.BadMac, open("a-totally-different-mesh-key-xxxxxxxxxxxxxx", tok, fields.issued_ms));
}

test "open rejects an expired token with Expired" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act / Assert: now is one ms past expiry.
    try testing.expectError(error.Expired, open(test_key, tok, fields.expiry_ms + 1));
}

test "open accepts a token exactly at expiry boundary" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act
    const got = try open(test_key, tok, fields.expiry_ms);

    // Assert
    try testing.expectEqualStrings(fields.account, got.account);
}

test "truncated input yields BadFormat" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act / Assert: drop the last 10 bytes (cuts into the tag).
    try testing.expectError(error.BadFormat, open(test_key, tok[0 .. tok.len - 10], fields.issued_ms));
}

test "empty / too-short buffer yields BadFormat" {
    // Arrange / Act / Assert
    try testing.expectError(error.BadFormat, open(test_key, &[_]u8{}, 0));
    try testing.expectError(error.BadFormat, open(test_key, "abc", 0));
}

test "bad magic yields BadFormat" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    const tok = try sealToBuf(test_key, fields, &buf);

    // Act: corrupt the magic prefix.
    tok[0] = 'X';

    // Assert
    try testing.expectError(error.BadFormat, open(test_key, tok, fields.issued_ms));
}

test "a declared field length overrunning the buffer yields BadFormat" {
    // Arrange: hand-craft a header whose first string claims a huge length.
    var raw: [64]u8 = undefined;
    @memcpy(raw[0..magic.len], &magic);
    // account length = 0xFFFF, far beyond the buffer.
    std.mem.writeInt(u16, raw[magic.len..][0..2], 0xFFFF, .big);
    // Fill the rest so the length test (>= min_len) passes.
    @memset(raw[magic.len + 2 ..], 0);

    // Act / Assert
    try testing.expectError(error.BadFormat, open(test_key, raw[0..], 0));
}

test "empty string fields round-trip" {
    // Arrange
    const fields = ReclaimFields{
        .account = "",
        .session_id = "",
        .origin_node = "",
        .issued_ms = 5,
        .expiry_ms = 10,
        .nonce = 0,
    };
    var buf: [128]u8 = undefined;

    // Act
    const tok = try sealToBuf(test_key, fields, &buf);
    const got = try open(test_key, tok, 7);

    // Assert
    try testing.expectEqual(@as(usize, 0), got.account.len);
    try testing.expectEqual(@as(u64, 10), got.expiry_ms);
}

test "decide grant_local when this node holds the session" {
    // Arrange
    const fields = sampleFields();

    // Act
    const d = decide(fields, true, false, false, fields.issued_ms);

    // Assert
    try testing.expectEqual(ReclaimDecision.grant_local, d);
}

test "decide grant_redirect to origin when held elsewhere" {
    // Arrange
    const fields = sampleFields();

    // Act
    const d = decide(fields, false, false, false, fields.issued_ms);

    // Assert
    switch (d) {
        .grant_redirect => |node| try testing.expectEqualStrings(fields.origin_node, node),
        else => return error.TestUnexpectedResult,
    }
}

test "decide deny_expired takes precedence over everything" {
    // Arrange
    const fields = sampleFields();

    // Act: expired, yet local holds the session and nonce is fresh.
    const d = decide(fields, true, true, false, fields.expiry_ms + 1);

    // Assert
    try testing.expectEqual(ReclaimDecision.deny_expired, d);
}

test "decide deny_replay when nonce already seen" {
    // Arrange
    const fields = sampleFields();

    // Act: replay outranks grant_local but not expiry.
    const d = decide(fields, true, false, true, fields.issued_ms);

    // Assert
    try testing.expectEqual(ReclaimDecision.deny_replay, d);
}

test "decide deny_unknown when origin is self but session is gone" {
    // Arrange
    const fields = sampleFields();

    // Act: we are the origin, but we no longer hold the session.
    const d = decide(fields, false, true, false, fields.issued_ms);

    // Assert
    try testing.expectEqual(ReclaimDecision.deny_unknown, d);
}

test "ReplayRing detects a replayed nonce" {
    // Arrange
    var ring = ReplayRing(4){};

    // Act / Assert
    try testing.expect(!ring.check(1)); // first sight
    try testing.expect(!ring.check(2));
    try testing.expect(ring.check(1)); // replay
    try testing.expect(ring.check(2)); // replay
}

test "ReplayRing contains is pure: probing never records the nonce" {
    // Arrange
    var ring = ReplayRing(4){};

    // Act: probe the same nonce repeatedly without recording.
    try testing.expect(!ring.contains(42));
    try testing.expect(!ring.contains(42));

    // Assert: only an explicit record makes it a replay.
    ring.record(42);
    try testing.expect(ring.contains(42));
}

test "ReplayRing record is idempotent and does not double-fill slots" {
    // Arrange
    var ring = ReplayRing(2){};

    // Act: record the same nonce twice, then one more distinct nonce.
    ring.record(7);
    ring.record(7);
    ring.record(8);

    // Assert: 7 was not stored twice, so recording 8 did not evict it.
    try testing.expect(ring.contains(7));
    try testing.expect(ring.contains(8));
}

test "non-consuming decisions do not burn the nonce for a later consume" {
    // Arrange: a fresh token evaluated on a node that neither holds the
    // session nor is the origin (grant_redirect — non-consuming).
    const fields = sampleFields();
    var ring = ReplayRing(8){};

    // Act: two redirect evaluations, then the session arrives locally and the
    // SAME token is consumed.
    const d1 = decide(fields, false, false, ring.contains(fields.nonce), fields.issued_ms);
    const d2 = decide(fields, false, false, ring.contains(fields.nonce), fields.issued_ms);
    const d3 = decide(fields, true, false, ring.contains(fields.nonce), fields.issued_ms);
    if (d3 == .grant_local) ring.record(fields.nonce); // consume burns it
    const d4 = decide(fields, true, false, ring.contains(fields.nonce), fields.issued_ms);

    // Assert: redirects are idempotent; the consume succeeds; only after the
    // consume is a re-presentation a replay.
    try testing.expect(d1 == .grant_redirect);
    try testing.expect(d2 == .grant_redirect);
    try testing.expectEqual(ReclaimDecision.grant_local, d3);
    try testing.expectEqual(ReclaimDecision.deny_replay, d4);
}

test "ReplayRing evicts oldest when capacity is exceeded" {
    // Arrange
    var ring = ReplayRing(2){};

    // Act: record 10, 20, then 30 (evicts 10).
    try testing.expect(!ring.check(10));
    try testing.expect(!ring.check(20));
    try testing.expect(!ring.check(30));

    // Assert: 10 was evicted, so it reads as fresh again; 20 and 30 are seen.
    try testing.expect(!ring.check(10));
    try testing.expect(ring.check(30));
}

test "full pipeline: seal, open, replay-track, decide" {
    // Arrange
    const fields = sampleFields();
    var buf: [256]u8 = undefined;
    var ring = ReplayRing(8){};

    // Act: a node receives the token, verifies it, then decides.
    const tok = try sealToBuf(test_key, fields, &buf);
    const opened = try open(test_key, tok, fields.issued_ms);
    const first_seen = ring.check(opened.nonce);
    const d1 = decide(opened, false, false, first_seen, fields.issued_ms);

    // A second presentation of the same nonce must be denied as replay.
    const second_seen = ring.check(opened.nonce);
    const d2 = decide(opened, false, false, second_seen, fields.issued_ms);

    // Assert
    try testing.expect(!first_seen);
    switch (d1) {
        .grant_redirect => |n| try testing.expectEqualStrings(fields.origin_node, n),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(second_seen);
    try testing.expectEqual(ReclaimDecision.deny_replay, d2);
}
