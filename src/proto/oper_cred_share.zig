// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-mesh oper authorization grants.
//!
//! Passwords NEVER cross the mesh. When an operator authenticates (via SASL)
//! on the home node, that node mints a signed, expiring "oper authorization
//! grant" describing the operator's account, privilege bitfield, oper class and
//! title. The grant propagates over the Suimyaku mesh; any peer holding the
//! issuer's Ed25519 public key can verify the grant and recognize the operator
//! WITHOUT ever seeing the credential that produced it.
//!
//! The signed payload is a fixed-order, length-prefixed serialization so the
//! exact bytes signed are the exact bytes verified — Ed25519 covers that
//! canonical blob. This module is std-only and allocation-free; the registry
//! uses fixed-capacity storage.
//!
//! This complements `meshpass.zig` (node-admission capability envelopes) but is
//! deliberately standalone: it carries per-operator authority, not node trust.

const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

/// Length of a raw Ed25519 signature.
pub const signature_len = Ed25519.Signature.encoded_length;

/// Fixed magic + version prefix so a stray blob cannot accidentally verify and
/// so the wire format can evolve. Covered by the signature.
pub const magic: u32 = 0x4F_43_47_31; // "OCG1"

/// Upper bound on any single variable-length field, enforced on both encode and
/// decode. Keeps the format bounded and deserialization safe.
pub const max_field_len: usize = 255;

/// Number of fixed-width framing fields (magic + 4 u64s) plus the four
/// length-prefixed byte strings. Used to size the encode buffer hint.
pub const max_grant_len: usize =
    @sizeOf(u32) + // magic
    4 * @sizeOf(u64) + // privilege_bits, incarnation, issued_ms, expiry_ms
    4 * (@sizeOf(u8) + max_field_len) + // account, class, title, issuer_node
    signature_len;

/// Plaintext, integrator-facing grant. Byte slices borrow from the caller on
/// `sign` and from the input buffer on `verify`.
pub const GrantFields = struct {
    /// Account name the operator authenticated as (case handled by integrator).
    account: []const u8,
    /// Opaque privilege EnumSet bitfield; this module never interprets it.
    privilege_bits: u64,
    /// Oper class (e.g. "netadmin"). Opaque label.
    class: []const u8,
    /// Display title (e.g. "Network Administrator"). Opaque label.
    title: []const u8,
    /// Node that minted this grant (the operator's home node).
    issuer_node: []const u8,
    /// Monotonic re-auth counter for the account on the issuer; higher wins.
    incarnation: u64,
    /// Wall-clock issue time in ms.
    issued_ms: u64,
    /// Wall-clock expiry time in ms (exclusive upper bound).
    expiry_ms: u64,
};

/// Errors surfaced by `verify`. Kept intentionally tight per the spec.
pub const VerifyError = error{
    /// Structural problem: truncated, oversized field, bad magic, or trailing
    /// bytes.
    BadFormat,
    /// Signature did not verify against the supplied public key.
    BadSignature,
    /// `now_ms >= expiry_ms`.
    Expired,
};

/// Errors surfaced by `sign`.
pub const SignError = error{
    /// `out` cannot hold the serialized grant.
    BufferTooSmall,
    /// A variable-length field exceeds `max_field_len`.
    FieldTooLong,
    /// `issued_ms > expiry_ms` — a grant that is born expired.
    InvalidTime,
    /// Ed25519 signing failed (weak key / identity element).
    SignFailed,
};

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/// Minimal forward-only byte writer over a caller-supplied buffer.
const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn u8At(self: *Writer, v: u8) SignError!void {
        if (self.pos + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = v;
        self.pos += 1;
    }

    fn u32be(self: *Writer, v: u32) SignError!void {
        if (self.pos + 4 > self.buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }

    fn u64be(self: *Writer, v: u64) SignError!void {
        if (self.pos + 8 > self.buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .big);
        self.pos += 8;
    }

    /// One-byte length prefix followed by the raw bytes.
    fn lenPrefixed(self: *Writer, bytes: []const u8) SignError!void {
        if (bytes.len > max_field_len) return error.FieldTooLong;
        try self.u8At(@intCast(bytes.len));
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn raw(self: *Writer, bytes: []const u8) SignError!void {
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }
};

/// Forward-only reader. All accessors fail with `BadFormat` on underflow.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn u32be(self: *Reader) VerifyError!u32 {
        if (self.pos + 4 > self.buf.len) return error.BadFormat;
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }

    fn u64be(self: *Reader) VerifyError!u64 {
        if (self.pos + 8 > self.buf.len) return error.BadFormat;
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    /// Read a one-byte length prefix and return a borrowed slice of that length.
    fn lenPrefixed(self: *Reader) VerifyError![]const u8 {
        if (self.pos + 1 > self.buf.len) return error.BadFormat;
        const n = self.buf[self.pos];
        self.pos += 1;
        if (self.pos + n > self.buf.len) return error.BadFormat;
        const out = self.buf[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }
};

/// Serialize exactly the bytes covered by the Ed25519 signature into `out`,
/// returning the number of bytes written. Deterministic: field order, framing
/// and big-endian width are fixed.
fn encodeSigned(out: []u8, fields: GrantFields) SignError!usize {
    if (fields.issued_ms > fields.expiry_ms) return error.InvalidTime;

    var w = Writer{ .buf = out };
    try w.u32be(magic);
    try w.lenPrefixed(fields.account);
    try w.u64be(fields.privilege_bits);
    try w.lenPrefixed(fields.class);
    try w.lenPrefixed(fields.title);
    try w.lenPrefixed(fields.issuer_node);
    try w.u64be(fields.incarnation);
    try w.u64be(fields.issued_ms);
    try w.u64be(fields.expiry_ms);
    return w.pos;
}

/// Parse the signed payload from `bytes` (which must be exactly the signed
/// region, no trailing signature) into `GrantFields`. Borrows from `bytes`.
fn decodeSigned(bytes: []const u8) VerifyError!GrantFields {
    var r = Reader{ .buf = bytes };
    if (try r.u32be() != magic) return error.BadFormat;
    const account = try r.lenPrefixed();
    const privilege_bits = try r.u64be();
    const class = try r.lenPrefixed();
    const title = try r.lenPrefixed();
    const issuer_node = try r.lenPrefixed();
    const incarnation = try r.u64be();
    const issued_ms = try r.u64be();
    const expiry_ms = try r.u64be();
    if (r.remaining() != 0) return error.BadFormat;

    return .{
        .account = account,
        .privilege_bits = privilege_bits,
        .class = class,
        .title = title,
        .issuer_node = issuer_node,
        .incarnation = incarnation,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    };
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/// Sign `fields` with the issuer's keypair, writing the canonical serialization
/// followed by the 64-byte Ed25519 signature into `out`. Returns total length.
///
/// The signing keypair is supplied by the caller — never hardcoded here.
pub fn sign(kp: Ed25519.KeyPair, fields: GrantFields, out: []u8) SignError!usize {
    const signed_len = try encodeSigned(out, fields);
    if (signed_len + signature_len > out.len) return error.BufferTooSmall;

    const sig = kp.sign(out[0..signed_len], null) catch return error.SignFailed;

    var w = Writer{ .buf = out, .pos = signed_len };
    try w.raw(&sig.toBytes());
    return w.pos;
}

/// Parse and verify a grant: checks magic/framing, the Ed25519 signature over
/// the canonical region, and freshness (`now_ms < expiry_ms`). Returns the
/// decoded fields (borrowing from `bytes`) only when all checks pass.
pub fn verify(pubkey: Ed25519.PublicKey, bytes: []const u8, now_ms: u64) VerifyError!GrantFields {
    if (bytes.len < signature_len) return error.BadFormat;

    const signed = bytes[0 .. bytes.len - signature_len];
    const sig_bytes = bytes[bytes.len - signature_len ..][0..signature_len];

    // Structural parse first so a malformed blob never reaches crypto needlessly
    // and so trailing-garbage / oversized fields are rejected as BadFormat.
    const fields = try decodeSigned(signed);

    const sig = Ed25519.Signature.fromBytes(sig_bytes.*);
    sig.verifyStrict(signed, pubkey) catch return error.BadSignature;

    if (now_ms >= fields.expiry_ms) return error.Expired;
    return fields;
}

// ---------------------------------------------------------------------------
// Registry — bounded, replay/freshness-protected merge of grants by account
// ---------------------------------------------------------------------------

/// Outcome of `Registry.upsert`.
pub const UpsertResult = enum {
    /// First grant ever seen for this account.
    inserted,
    /// A fresher grant replaced the stored one.
    superseded,
    /// The incoming grant was older-or-equal and was rejected (replay guard).
    stale_ignored,
};

/// Default registry capacity. Sized for a generous oper roster; the type is
/// parameterized so integrators can pick another bound.
pub const default_capacity: usize = 256;

/// Owned, fixed-capacity copy of a grant's variable-length fields so a stored
/// entry never dangles after the source buffer is reused.
const OwnedFields = struct {
    account_buf: [max_field_len]u8 = undefined,
    account_len: usize = 0,
    class_buf: [max_field_len]u8 = undefined,
    class_len: usize = 0,
    title_buf: [max_field_len]u8 = undefined,
    title_len: usize = 0,
    issuer_buf: [max_field_len]u8 = undefined,
    issuer_len: usize = 0,
    privilege_bits: u64 = 0,
    incarnation: u64 = 0,
    issued_ms: u64 = 0,
    expiry_ms: u64 = 0,

    fn store(self: *OwnedFields, f: GrantFields) void {
        self.account_len = copyInto(&self.account_buf, f.account);
        self.class_len = copyInto(&self.class_buf, f.class);
        self.title_len = copyInto(&self.title_buf, f.title);
        self.issuer_len = copyInto(&self.issuer_buf, f.issuer_node);
        self.privilege_bits = f.privilege_bits;
        self.incarnation = f.incarnation;
        self.issued_ms = f.issued_ms;
        self.expiry_ms = f.expiry_ms;
    }

    fn view(self: *const OwnedFields) GrantFields {
        return .{
            .account = self.account_buf[0..self.account_len],
            .privilege_bits = self.privilege_bits,
            .class = self.class_buf[0..self.class_len],
            .title = self.title_buf[0..self.title_len],
            .issuer_node = self.issuer_buf[0..self.issuer_len],
            .incarnation = self.incarnation,
            .issued_ms = self.issued_ms,
            .expiry_ms = self.expiry_ms,
        };
    }

    fn accountSlice(self: *const OwnedFields) []const u8 {
        return self.account_buf[0..self.account_len];
    }
};

fn copyInto(dst: *[max_field_len]u8, src: []const u8) usize {
    const n = @min(src.len, max_field_len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

/// Returns true when `incoming` strictly supersedes `stored`: a higher
/// incarnation always wins; on equal incarnation a later issue time wins.
fn supersedes(incoming: GrantFields, stored: *const OwnedFields) bool {
    if (incoming.incarnation != stored.incarnation)
        return incoming.incarnation > stored.incarnation;
    return incoming.issued_ms > stored.issued_ms;
}

/// Bounded, allocation-free registry that merges verified grants by account
/// with replay and freshness protection. Construct with `Registry.init()` (or
/// the default-initialized struct) and parameterize capacity via `Sized`.
pub const Registry = Sized(default_capacity);

/// Build a registry type with `cap` slots.
pub fn Sized(comptime cap: usize) type {
    return struct {
        const Self = @This();

        slots: [cap]OwnedFields = undefined,
        used: [cap]bool = @splat(false),
        len: usize = 0,

        /// Explicit zero-valued constructor (the default struct value also works).
        pub fn init() Self {
            return .{};
        }

        /// Capacity of this registry.
        pub fn capacity(self: *const Self) usize {
            _ = self;
            return cap;
        }

        /// Number of occupied slots.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Account comparison is case-INSENSITIVE: the `*` pipeline resolves
        /// grants by roster nick (the account == nick convention) and nicks
        /// compare case-insensitively everywhere else — a case-sensitive match
        /// here made a grant unfindable whenever the viewer's roster carried a
        /// different capitalization than the minted account.
        fn findIndex(self: *const Self, account: []const u8) ?usize {
            var i: usize = 0;
            while (i < cap) : (i += 1) {
                if (self.used[i] and std.ascii.eqlIgnoreCase(self.slots[i].accountSlice(), account))
                    return i;
            }
            return null;
        }

        fn firstFree(self: *const Self) ?usize {
            var i: usize = 0;
            while (i < cap) : (i += 1) {
                if (!self.used[i]) return i;
            }
            return null;
        }

        /// Merge `fields` for its account. A newer grant supersedes an older one
        /// only if its incarnation is strictly greater, or equal incarnation but
        /// a later `issued_ms`. Returns the merge outcome. When capacity is
        /// exhausted and the account is new, the grant is dropped as
        /// `stale_ignored`.
        pub fn upsert(self: *Self, fields: GrantFields) UpsertResult {
            if (self.findIndex(fields.account)) |idx| {
                if (!supersedes(fields, &self.slots[idx])) return .stale_ignored;
                self.slots[idx].store(fields);
                return .superseded;
            }

            const free = self.firstFree() orelse return .stale_ignored;
            self.slots[free].store(fields);
            self.used[free] = true;
            self.len += 1;
            return .inserted;
        }

        /// Look up the live grant for `account`, returning null when absent or
        /// expired at `now_ms`. Does not mutate; expired entries are reclaimed
        /// only by `prune`.
        pub fn lookup(self: *const Self, account: []const u8, now_ms: u64) ?GrantFields {
            const idx = self.findIndex(account) orelse return null;
            if (now_ms >= self.slots[idx].expiry_ms) return null;
            return self.slots[idx].view();
        }

        /// Iterator over the live (unexpired-at-`now_ms`) grants. Each yielded
        /// `GrantFields` borrows the registry's slot buffers — valid only until
        /// the next mutation. Order is slot order, not insertion order.
        pub const LiveIterator = struct {
            reg: *const Self,
            now_ms: u64,
            idx: usize = 0,

            pub fn next(self: *LiveIterator) ?GrantFields {
                while (self.idx < cap) {
                    const i = self.idx;
                    self.idx += 1;
                    if (!self.reg.used[i]) continue;
                    if (self.now_ms >= self.reg.slots[i].expiry_ms) continue;
                    return self.reg.slots[i].view();
                }
                return null;
            }
        };

        /// Walk the grants live at `now_ms`. Expired/empty slots are skipped.
        pub fn liveIterator(self: *const Self, now_ms: u64) LiveIterator {
            return .{ .reg = self, .now_ms = now_ms };
        }

        /// Drop every entry that has expired at `now_ms`. Returns the number of
        /// entries removed.
        pub fn prune(self: *Self, now_ms: u64) usize {
            var removed: usize = 0;
            var i: usize = 0;
            while (i < cap) : (i += 1) {
                if (!self.used[i]) continue;
                if (now_ms >= self.slots[i].expiry_ms) {
                    self.used[i] = false;
                    self.len -= 1;
                    removed += 1;
                }
            }
            return removed;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleFields() GrantFields {
    return .{
        .account = "oper_alice",
        .privilege_bits = 0xDEAD_BEEF_0000_0001,
        .class = "netadmin",
        .title = "Network Administrator",
        .issuer_node = "node-a.suimyaku",
        .incarnation = 7,
        .issued_ms = 1_000,
        .expiry_ms = 10_000,
    };
}

fn expectFieldsEqual(a: GrantFields, b: GrantFields) !void {
    try testing.expectEqualStrings(a.account, b.account);
    try testing.expectEqual(a.privilege_bits, b.privilege_bits);
    try testing.expectEqualStrings(a.class, b.class);
    try testing.expectEqualStrings(a.title, b.title);
    try testing.expectEqualStrings(a.issuer_node, b.issuer_node);
    try testing.expectEqual(a.incarnation, b.incarnation);
    try testing.expectEqual(a.issued_ms, b.issued_ms);
    try testing.expectEqual(a.expiry_ms, b.expiry_ms);
}

test "sign and verify round-trip recovers all fields" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x31)));
    const fields = sampleFields();
    var buf: [max_grant_len]u8 = undefined;

    // Act
    const n = try sign(kp, fields, &buf);
    const out = try verify(kp.public_key, buf[0..n], 5_000);

    // Assert
    try expectFieldsEqual(fields, out);
}

test "sign is deterministic for identical fields" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x32)));
    const fields = sampleFields();
    var a: [max_grant_len]u8 = undefined;
    var b: [max_grant_len]u8 = undefined;

    // Act
    const na = try sign(kp, fields, &a);
    const nb = try sign(kp, fields, &b);

    // Assert
    try testing.expectEqual(na, nb);
    try testing.expectEqualSlices(u8, a[0..na], b[0..nb]);
}

test "sign rejects a grant that is born expired" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x33)));
    var fields = sampleFields();
    fields.issued_ms = 10_001;
    fields.expiry_ms = 10_000;
    var buf: [max_grant_len]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.InvalidTime, sign(kp, fields, &buf));
}

test "tampered field is detected as BadSignature" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x34)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf);

    // Act: flip a byte inside the privilege_bits region (just past magic +
    // account length-prefix + account bytes), still structurally valid.
    const account_field_start = @sizeOf(u32) + 1 + "oper_alice".len;
    buf[account_field_start] ^= 0x01;

    // Assert
    try testing.expectError(error.BadSignature, verify(kp.public_key, buf[0..n], 5_000));
}

test "verification with the wrong public key fails as BadSignature" {
    // Arrange
    const signer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x35)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x99)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(signer, sampleFields(), &buf);

    // Act / Assert
    try testing.expectError(error.BadSignature, verify(other.public_key, buf[0..n], 5_000));
}

test "tampered signature byte fails as BadSignature" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x36)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf);

    // Act: corrupt the last (signature) byte.
    buf[n - 1] ^= 0x80;

    // Assert
    try testing.expectError(error.BadSignature, verify(kp.public_key, buf[0..n], 5_000));
}

test "expired grant fails as Expired" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x37)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf); // expiry_ms = 10_000

    // Act / Assert: now_ms == expiry_ms is already expired (exclusive bound).
    try testing.expectError(error.Expired, verify(kp.public_key, buf[0..n], 10_000));
    try testing.expectError(error.Expired, verify(kp.public_key, buf[0..n], 10_001));
}

test "truncated buffer fails as BadFormat" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x38)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf);

    // Act / Assert: shorter than a signature.
    try testing.expectError(error.BadFormat, verify(kp.public_key, buf[0 .. signature_len - 1], 5_000));

    // And a buffer that has a signature's worth of bytes but a mangled signed
    // region (drop a byte from the middle, keeping len >= signature_len).
    try testing.expectError(error.BadFormat, verify(kp.public_key, buf[0 .. n - 1], 5_000));
}

test "wrong magic fails as BadFormat" {
    // Arrange
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x39)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf);

    // Act: clobber the magic prefix (still structurally long enough).
    buf[0] ^= 0xFF;

    // Assert
    try testing.expectError(error.BadFormat, verify(kp.public_key, buf[0..n], 5_000));
}

test "registry insert then lookup returns the grant" {
    // Arrange
    var reg = Registry.init();
    const fields = sampleFields();

    // Act
    const result = reg.upsert(fields);
    const found = reg.lookup(fields.account, 5_000);

    // Assert
    try testing.expectEqual(UpsertResult.inserted, result);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expect(found != null);
    try expectFieldsEqual(fields, found.?);
}

test "liveIterator yields live grants and skips the expired" {
    // Arrange: two accounts, one live and one expired at the query time.
    var reg = Registry.init();
    var live = sampleFields();
    live.account = "oper_live";
    live.expiry_ms = 10_000;
    var expired = sampleFields();
    expired.account = "oper_expired";
    expired.expiry_ms = 4_000;
    _ = reg.upsert(live);
    _ = reg.upsert(expired);

    // Act: walk the grants live at now=5_000 (expired one is past its window).
    var it = reg.liveIterator(5_000);
    var seen_live = false;
    var seen_expired = false;
    var n: usize = 0;
    while (it.next()) |g| {
        n += 1;
        if (std.mem.eql(u8, g.account, "oper_live")) seen_live = true;
        if (std.mem.eql(u8, g.account, "oper_expired")) seen_expired = true;
    }

    // Assert: only the live grant surfaces.
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(seen_live);
    try testing.expect(!seen_expired);
}

test "registry supersedes on strictly higher incarnation" {
    // Arrange
    var reg = Registry.init();
    var older = sampleFields();
    older.incarnation = 7;
    older.privilege_bits = 0x01;
    var newer = sampleFields();
    newer.incarnation = 8;
    newer.privilege_bits = 0x02;

    // Act
    _ = reg.upsert(older);
    const result = reg.upsert(newer);
    const found = reg.lookup(newer.account, 5_000).?;

    // Assert
    try testing.expectEqual(UpsertResult.superseded, result);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expectEqual(@as(u64, 0x02), found.privilege_bits);
    try testing.expectEqual(@as(u64, 8), found.incarnation);
}

test "registry supersedes on equal incarnation with later issued_ms" {
    // Arrange
    var reg = Registry.init();
    var first = sampleFields();
    first.incarnation = 7;
    first.issued_ms = 1_000;
    var second = sampleFields();
    second.incarnation = 7;
    second.issued_ms = 2_000;

    // Act
    _ = reg.upsert(first);
    const result = reg.upsert(second);

    // Assert
    try testing.expectEqual(UpsertResult.superseded, result);
    try testing.expectEqual(@as(u64, 2_000), reg.lookup(second.account, 5_000).?.issued_ms);
}

test "registry ignores a stale lower-incarnation grant" {
    // Arrange
    var reg = Registry.init();
    var newer = sampleFields();
    newer.incarnation = 8;
    newer.privilege_bits = 0x02;
    var older = sampleFields();
    older.incarnation = 7;
    older.privilege_bits = 0x01;

    // Act
    _ = reg.upsert(newer);
    const result = reg.upsert(older);
    const found = reg.lookup(newer.account, 5_000).?;

    // Assert: stale grant rejected, stored grant unchanged.
    try testing.expectEqual(UpsertResult.stale_ignored, result);
    try testing.expectEqual(@as(u64, 0x02), found.privilege_bits);
    try testing.expectEqual(@as(u64, 8), found.incarnation);
}

test "registry ignores an equal-incarnation equal-time replay" {
    // Arrange
    var reg = Registry.init();
    const fields = sampleFields();

    // Act
    _ = reg.upsert(fields);
    const result = reg.upsert(fields);

    // Assert
    try testing.expectEqual(UpsertResult.stale_ignored, result);
    try testing.expectEqual(@as(usize, 1), reg.count());
}

test "lookup returns null after expiry without mutating" {
    // Arrange
    var reg = Registry.init();
    const fields = sampleFields(); // expiry_ms = 10_000
    _ = reg.upsert(fields);

    // Act / Assert
    try testing.expect(reg.lookup(fields.account, 9_999) != null);
    try testing.expect(reg.lookup(fields.account, 10_000) == null);
    // Entry still occupies its slot until pruned.
    try testing.expectEqual(@as(usize, 1), reg.count());
}

test "prune drops expired entries and keeps live ones" {
    // Arrange
    var reg = Registry.init();
    var live = sampleFields();
    live.account = "oper_live";
    live.expiry_ms = 100_000;
    var dead = sampleFields();
    dead.account = "oper_dead";
    dead.expiry_ms = 10_000;
    _ = reg.upsert(live);
    _ = reg.upsert(dead);

    // Act
    const removed = reg.prune(20_000);

    // Assert
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expect(reg.lookup("oper_dead", 5_000) == null);
    try testing.expect(reg.lookup("oper_live", 20_000) != null);
}

test "registry tracks multiple distinct accounts independently" {
    // Arrange
    var reg = Sized(4).init();
    var a = sampleFields();
    a.account = "oper_a";
    var b = sampleFields();
    b.account = "oper_b";

    // Act
    const ra = reg.upsert(a);
    const rb = reg.upsert(b);

    // Assert
    try testing.expectEqual(UpsertResult.inserted, ra);
    try testing.expectEqual(UpsertResult.inserted, rb);
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expect(reg.lookup("oper_a", 5_000) != null);
    try testing.expect(reg.lookup("oper_b", 5_000) != null);
}

test "registry drops new accounts when capacity is exhausted" {
    // Arrange
    var reg = Sized(1).init();
    var a = sampleFields();
    a.account = "oper_a";
    var b = sampleFields();
    b.account = "oper_b";

    // Act
    const ra = reg.upsert(a);
    const rb = reg.upsert(b);

    // Assert: second distinct account has nowhere to go.
    try testing.expectEqual(UpsertResult.inserted, ra);
    try testing.expectEqual(UpsertResult.stale_ignored, rb);
    try testing.expectEqual(@as(usize, 1), reg.count());

    // A freed slot can be reused after prune.
    _ = reg.prune(1_000_000);
    try testing.expectEqual(UpsertResult.inserted, reg.upsert(b));
}

test "verified grant feeds straight into the registry" {
    // Arrange: full end-to-end — sign on node A, verify on node B, store.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x40)));
    var buf: [max_grant_len]u8 = undefined;
    const n = try sign(kp, sampleFields(), &buf);
    var reg = Registry.init();

    // Act
    const decoded = try verify(kp.public_key, buf[0..n], 5_000);
    const result = reg.upsert(decoded);

    // Assert: stored copy survives even after the source buffer is scribbled on.
    @memset(buf[0..n], 0xAA);
    const found = reg.lookup("oper_alice", 5_000).?;
    try testing.expectEqual(UpsertResult.inserted, result);
    try testing.expectEqualStrings("oper_alice", found.account);
    try testing.expectEqualStrings("netadmin", found.class);
    try testing.expectEqual(@as(u64, 0xDEAD_BEEF_0000_0001), found.privilege_bits);
}

test "registry matches accounts case-insensitively (account == nick convention)" {
    // The `*` pipeline resolves grants by roster NICK (account == nick), and
    // nicks compare case-insensitively everywhere else (eqlIgnoreCase). A
    // case-sensitive registry made a remote oper's `*` decay whenever the
    // viewer's roster carried a different capitalization (e.g. `Kain` vs the
    // minted account `kain`).
    var reg = Registry.init();
    _ = reg.upsert(sampleFields()); // account "oper_alice"

    // Arrange/Act/Assert: every capitalization resolves to the stored grant.
    try testing.expect(reg.lookup("oper_alice", 5_000) != null);
    try testing.expect(reg.lookup("Oper_Alice", 5_000) != null);
    try testing.expect(reg.lookup("OPER_ALICE", 5_000) != null);
    try testing.expect(reg.lookup("oper_bob", 5_000) == null); // no false positive

    // A mixed-case re-grant merges into the SAME slot (supersede), never a
    // duplicate account entry.
    var regrant = sampleFields();
    regrant.account = "OPER_ALICE";
    regrant.incarnation = 8;
    try testing.expectEqual(UpsertResult.superseded, reg.upsert(regrant));
    try testing.expectEqual(@as(usize, 1), reg.count());
}
