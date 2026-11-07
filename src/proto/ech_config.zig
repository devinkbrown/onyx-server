// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypted Client Hello (ECH) configuration parsing — RFC 9xxx / the
//! draft-ietf-tls-esni "ECHConfigList" wire format (version `0xfe0d`).
//!
//! Pure, zero-allocation, fail-closed parser. It walks a caller-supplied
//! `ECHConfigList` (base64-decoded from a config file or a DNS HTTPS RR — this
//! module never fetches; the bytes are supplied out of band, mirroring how the
//! CRL and SCT machinery take caller-supplied data) and yields the individual
//! `ECHConfig` entries and their `HpkeKeyConfig` fields. Every length field is
//! bounds-checked before use; a truncated or inconsistent list yields an error
//! rather than reading past the buffer. All returned slices alias the caller's
//! input — nothing is copied.
//!
//! Wire structure (RFC 9xxx §4):
//!
//!     struct { uint16 kdf_id; uint16 aead_id; } HpkeSymmetricCipherSuite;
//!     struct {
//!         uint8  config_id;
//!         uint16 kem_id;
//!         opaque public_key<1..2^16-1>;
//!         HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
//!     } HpkeKeyConfig;
//!     struct {
//!         HpkeKeyConfig key_config;
//!         uint8  maximum_name_length;
//!         opaque public_name<1..255>;
//!         Extension extensions<0..2^16-1>;
//!     } ECHConfigContents;
//!     struct {
//!         uint16 version;   // 0xfe0d for this draft
//!         uint16 length;
//!         select (version) { case 0xfe0d: ECHConfigContents contents; }
//!     } ECHConfig;
//!     ECHConfig ECHConfigList<4..2^16-1>;   // a 2-byte length prefix, then entries
//!
//! This module is the parse/select half of client ECH (roadmap 5.1); the seal
//! and transcript machinery live in `src/crypto/ech_seal.zig`.
//!
//! Relationship to the pre-existing `src/proto/ech.zig`: that module decodes an
//! ECHConfigList into *owned structs* (allocating) and is unwired. It does not
//! fit the live client path here for three concrete reasons, so this purpose-
//! built parser exists alongside it (a consolidation the reviewer may direct):
//!   1. HPKE `info` = `"tls ech"‖0x00‖ECHConfig` needs the *exact original*
//!      serialized config bytes; a decode→re-encode risks non-canonical drift
//!      that would make the server unable to decrypt. This parser retains `raw`.
//!   2. `proto/ech.zig`'s `ECHConfigList.decode` aborts on any unknown-version
//!      entry; a spec-legal list may mix draft versions — this parser skips them.
//!   3. Selection here filters by KEM, validates `public_name` (it becomes the
//!      outer SNI), and skips configs with an unsupported *mandatory* ECHConfig
//!      extension — none of which `proto/ech.zig`'s `selectConfig` does.
//! It is also zero-allocation (borrows the caller's stable ECHConfigList bytes),
//! avoiding an owned-list lifecycle in the TLS `Client`.
const std = @import("std");

/// The ECHConfig version this module understands (draft-ietf-tls-esni-13+,
/// carried unchanged into the RFC).
pub const version_draft13: u16 = 0xfe0d;

pub const Error = error{
    /// A length field ran past the end of the buffer, or a fixed field was
    /// missing. Any structural defect maps here — the parser never reads OOB.
    Malformed,
};

/// One `{kdf_id, aead_id}` pair from a config's `cipher_suites` list.
pub const SymmetricCipherSuite = struct {
    kdf_id: u16,
    aead_id: u16,
};

/// A fully parsed `ECHConfig` of version `0xfe0d`. All slice fields alias the
/// caller's `ECHConfigList` input; the struct owns nothing.
pub const Config = struct {
    /// The whole serialized `ECHConfig` entry (version‖length‖contents). This is
    /// the exact byte string HPKE's `info` folds in (`"tls ech"‖0x00‖ECHConfig`),
    /// so it is retained verbatim rather than reconstructed.
    raw: []const u8,
    version: u16,
    config_id: u8,
    kem_id: u16,
    /// HPKE recipient public key (`pkR`). Length depends on `kem_id`.
    public_key: []const u8,
    /// Raw `cipher_suites` body: a concatenation of `{u16 kdf, u16 aead}` pairs
    /// (length a positive multiple of 4). Iterate with `cipherSuiteCount` /
    /// `cipherSuiteAt`.
    cipher_suites: []const u8,
    maximum_name_length: u8,
    /// The client-facing (cover) server name placed in the ClientHelloOuter SNI.
    public_name: []const u8,
    /// Raw `Extension extensions<0..2^16-1>` body (concatenated entries, no outer
    /// length prefix). Bounds-validated during parse.
    extensions: []const u8,

    /// Number of `{kdf, aead}` pairs in `cipher_suites`.
    pub fn cipherSuiteCount(self: Config) usize {
        return self.cipher_suites.len / 4;
    }

    /// The `i`-th cipher suite. Caller must ensure `i < cipherSuiteCount()`.
    pub fn cipherSuiteAt(self: Config, i: usize) SymmetricCipherSuite {
        const off = i * 4;
        return .{
            .kdf_id = std.mem.readInt(u16, self.cipher_suites[off..][0..2], .big),
            .aead_id = std.mem.readInt(u16, self.cipher_suites[off + 2 ..][0..2], .big),
        };
    }

    /// True when this config advertises the given HPKE symmetric suite.
    pub fn supportsSuite(self: Config, kdf_id: u16, aead_id: u16) bool {
        var i: usize = 0;
        while (i < self.cipherSuiteCount()) : (i += 1) {
            const s = self.cipherSuiteAt(i);
            if (s.kdf_id == kdf_id and s.aead_id == aead_id) return true;
        }
        return false;
    }

    /// True when the config carries an ECHConfig extension the client does not
    /// recognize AND whose type has the high (mandatory) bit set. Per the spec a
    /// client MUST ignore any ECHConfig containing such an extension. We
    /// recognize no ECHConfig extensions today, so *any* mandatory extension
    /// disqualifies the config. Also returns `error.Malformed` on a truncated
    /// extensions block.
    pub fn hasUnsupportedMandatoryExtension(self: Config) Error!bool {
        var r = Reader{ .b = self.extensions };
        while (!r.atEnd()) {
            const ext_type = try r.readU16();
            _ = try r.readVec16(); // ext_data — bounds-checked, contents ignored
            // RFC 9xxx: the high bit of the extension type marks it mandatory.
            if (ext_type & 0x8000 != 0) return true;
        }
        return false;
    }
};

/// Fail-closed forward reader over a byte slice. Every accessor bounds-checks
/// before advancing and returns `error.Malformed` on overrun — the parser can
/// never read past `b`.
const Reader = struct {
    b: []const u8,
    pos: usize = 0,

    fn remaining(self: Reader) usize {
        return self.b.len - self.pos;
    }

    fn atEnd(self: Reader) bool {
        return self.pos == self.b.len;
    }

    fn readU8(self: *Reader) Error!u8 {
        if (self.remaining() < 1) return error.Malformed;
        const v = self.b[self.pos];
        self.pos += 1;
        return v;
    }

    fn readU16(self: *Reader) Error!u16 {
        if (self.remaining() < 2) return error.Malformed;
        const v = std.mem.readInt(u16, self.b[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.Malformed;
        const s = self.b[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    /// A `vec<0..255>`: a 1-byte length prefix then that many bytes.
    fn readVec8(self: *Reader) Error![]const u8 {
        const n = try self.readU8();
        return self.take(n);
    }

    /// A `vec<0..2^16-1>`: a 2-byte length prefix then that many bytes.
    fn readVec16(self: *Reader) Error![]const u8 {
        const n = try self.readU16();
        return self.take(n);
    }
};

/// One entry from an ECHConfigList: its version, the full entry bytes, and the
/// (still unparsed) contents body. Unknown-version entries are yielded so the
/// caller can skip them; only `version_draft13` entries can be `Config.parse`d.
pub const RawEntry = struct {
    version: u16,
    /// The full `ECHConfig` entry (version‖length‖contents).
    raw: []const u8,
    /// The `contents` body alone (`length` bytes).
    contents: []const u8,
};

/// Forward iterator over the entries of an ECHConfigList.
pub const List = struct {
    reader: Reader,

    /// Validate the 2-byte ECHConfigList length prefix and return an iterator
    /// over its entries. `error.Malformed` if the prefix overruns or trailing
    /// bytes follow the declared list.
    pub fn init(list_bytes: []const u8) Error!List {
        var outer = Reader{ .b = list_bytes };
        const body = try outer.readVec16();
        if (!outer.atEnd()) return error.Malformed; // trailing garbage after the list
        return .{ .reader = Reader{ .b = body } };
    }

    /// Next entry, or null at the end. `error.Malformed` on a truncated entry.
    pub fn next(self: *List) Error!?RawEntry {
        if (self.reader.atEnd()) return null;
        const start = self.reader.pos;
        const version = try self.reader.readU16();
        const contents = try self.reader.readVec16();
        const raw = self.reader.b[start..self.reader.pos];
        return .{ .version = version, .raw = raw, .contents = contents };
    }
};

/// Parse the contents of a `version_draft13` entry into a `Config`. Returns
/// `error.Malformed` on any structural defect. The caller must have confirmed
/// `entry.version == version_draft13`.
pub fn parse(entry: RawEntry) Error!Config {
    if (entry.version != version_draft13) return error.Malformed;
    var r = Reader{ .b = entry.contents };

    const config_id = try r.readU8();
    const kem_id = try r.readU16();
    const public_key = try r.readVec16();
    if (public_key.len == 0) return error.Malformed; // public_key<1..2^16-1>
    const cipher_suites = try r.readVec16();
    if (cipher_suites.len < 4 or cipher_suites.len % 4 != 0) return error.Malformed;
    const maximum_name_length = try r.readU8();
    const public_name = try r.readVec8();
    if (public_name.len == 0) return error.Malformed; // public_name<1..255>
    const extensions = try r.readVec16();
    if (!r.atEnd()) return error.Malformed; // contents length must match exactly

    return .{
        .raw = entry.raw,
        .version = entry.version,
        .config_id = config_id,
        .kem_id = kem_id,
        .public_key = public_key,
        .cipher_suites = cipher_suites,
        .maximum_name_length = maximum_name_length,
        .public_name = public_name,
        .extensions = extensions,
    };
}

/// Syntax-only check of an ECHConfigList (draft-ietf-tls-esni §4:
/// `ECHConfig ECHConfigList<4..2^16-1>`): the list is non-empty, every entry is
/// framed exactly, and every `0xfe0d` entry parses. Unknown-version entries are
/// only length-checked. Used for the §6.2 rule that a client which sent GREASE
/// ECH MUST check `retry_configs` syntactically (aborting with decode_error)
/// and otherwise ignore it.
pub fn validateList(list_bytes: []const u8) Error!void {
    var list = try List.init(list_bytes);
    var count: usize = 0;
    while (try list.next()) |entry| {
        count += 1;
        if (entry.version == version_draft13) _ = try parse(entry);
    }
    if (count == 0) return error.Malformed;
}

test "validateList accepts well-formed lists and rejects empty or broken ones" {
    // version 0xfe0d entry: config_id 1, kem 0x0020, pk(1)=0xaa, suites(4),
    // max_name 0, public_name "a", no extensions.
    const fixed = [_]u8{
        0x00, 0x15, // list length 21
        0xfe, 0x0d, 0x00, 0x11, // version, contents length 17
        0x01, // config_id
        0x00, 0x20, // kem_id
        0x00, 0x01, 0xaa, // public_key<1..>
        0x00, 0x04, 0x00, 0x01, 0x00, 0x03, // cipher_suites
        0x00, // maximum_name_length
        0x01, 'a', // public_name
        0x00, 0x00, // extensions
    };
    try validateList(&fixed);
    // An unknown-version entry is only framed, never parsed.
    try validateList(&.{ 0x00, 0x05, 0x12, 0x34, 0x00, 0x01, 0xff });
    try std.testing.expectError(error.Malformed, validateList(&.{ 0x00, 0x00 }));
    try std.testing.expectError(error.Malformed, validateList(&.{ 0x00, 0x05, 0x12, 0x34, 0x00, 0x02, 0xff }));
    try std.testing.expectError(error.Malformed, validateList("garbage"));
    var broken = fixed;
    broken[10] = 0x00; // public_key length 0: an illegal empty key
    try std.testing.expectError(error.Malformed, validateList(&broken));
}

/// Select the first usable ECHConfig from a list: a `0xfe0d` entry whose
/// `kem_id` matches, that advertises the `{kdf_id, aead_id}` suite, whose
/// `public_name` is a valid host name, and that carries no unsupported mandatory
/// extension. Returns null when no entry qualifies (the caller then omits ECH
/// entirely — a byte-identical ClientHello). Propagates `error.Malformed` if the
/// list itself is structurally broken.
///
/// Unknown-version entries and entries that merely lack our KEM/suite are
/// skipped, not errors — an ECHConfigList may legitimately mix draft versions
/// and KEMs.
pub fn selectSupported(
    list_bytes: []const u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
) Error!?Config {
    var list = try List.init(list_bytes);
    while (try list.next()) |entry| {
        if (entry.version != version_draft13) continue;
        const cfg = parse(entry) catch |e| switch (e) {
            // A malformed 0xfe0d entry poisons the whole list: we cannot trust a
            // list we cannot fully parse. Propagate rather than silently skip.
            error.Malformed => return error.Malformed,
        };
        if (cfg.kem_id != kem_id) continue;
        if (!cfg.supportsSuite(kdf_id, aead_id)) continue;
        if (try cfg.hasUnsupportedMandatoryExtension()) continue;
        if (!isValidPublicName(cfg.public_name)) continue;
        return cfg;
    }
    return null;
}

/// A light LDH host-name check for `public_name`, which is copied verbatim into
/// the ClientHelloOuter SNI. Per the spec a client MUST ignore an ECHConfig
/// whose `public_name` is not a valid host name. Accepts dotted labels of
/// `[A-Za-z0-9-]` (a label may not start/end with '-'), total length 1..253, and
/// rejects anything that parses as an IPv4 literal. This is deliberately strict:
/// a bogus public_name would otherwise be emitted on the wire.
pub fn isValidPublicName(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    // Reject a dotted-decimal IPv4 literal (spec: public_name is a DNS name).
    if (looksLikeIpv4(name)) return false;

    var label_len: usize = 0;
    var prev_was_dot = true; // treat start as "after a dot" to forbid a leading dot/hyphen
    for (name, 0..) |c, i| {
        if (c == '.') {
            if (label_len == 0) return false; // empty label (leading dot or "..")
            if (name[i - 1] == '-') return false; // label ended with '-'
            label_len = 0;
            prev_was_dot = true;
            continue;
        }
        const is_ldh = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!is_ldh) return false;
        if (prev_was_dot and c == '-') return false; // label started with '-'
        label_len += 1;
        if (label_len > 63) return false;
        prev_was_dot = false;
    }
    // A trailing dot leaves label_len == 0 with prev_was_dot true — reject.
    if (label_len == 0) return false;
    if (name[name.len - 1] == '-') return false;
    // The rightmost label (the TLD) must not be all-digits — that is not a valid
    // host name and also catches dotted-decimal-ish strings that dodge the strict
    // 3-dot IPv4 check (e.g. "1.2.3.4.5", "12345").
    const last_dot = std.mem.lastIndexOfScalar(u8, name, '.');
    const tld = if (last_dot) |i| name[i + 1 ..] else name;
    var all_digits = true;
    for (tld) |c| {
        if (c < '0' or c > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) return false;
    return true;
}

fn looksLikeIpv4(name: []const u8) bool {
    var dots: usize = 0;
    for (name) |c| {
        if (c == '.') {
            dots += 1;
        } else if (c < '0' or c > '9') {
            return false; // a non-digit, non-dot ⇒ not an IPv4 literal
        }
    }
    return dots == 3;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const testing = std.testing;

/// Build a minimal single-entry ECHConfigList for tests. `pk` is the HPKE
/// public key; one cipher suite {kdf, aead}; the given public_name; no
/// ECHConfig extensions.
fn buildList(
    buf: []u8,
    config_id: u8,
    kem_id: u16,
    pk: []const u8,
    kdf_id: u16,
    aead_id: u16,
    max_name_len: u8,
    public_name: []const u8,
) []const u8 {
    var contents: [512]u8 = undefined;
    var n: usize = 0;
    contents[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], kem_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], @intCast(pk.len), .big);
    n += 2;
    @memcpy(contents[n..][0..pk.len], pk);
    n += pk.len;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big); // cipher_suites length
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], aead_id, .big);
    n += 2;
    contents[n] = max_name_len;
    n += 1;
    contents[n] = @intCast(public_name.len);
    n += 1;
    @memcpy(contents[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big); // extensions length = 0
    n += 2;

    // Wrap one ECHConfig entry: version(2) + length(2) + contents.
    var entry: [560]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, entry[m..][0..2], version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, entry[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(entry[m..][0..n], contents[0..n]);
    m += n;

    // Wrap the ECHConfigList: u16 total length + entries.
    std.mem.writeInt(u16, buf[0..2], @intCast(m), .big);
    @memcpy(buf[2..][0..m], entry[0..m]);
    return buf[0 .. 2 + m];
}

test "parse a well-formed single-entry ECHConfigList" {
    var buf: [600]u8 = undefined;
    const pk: [32]u8 = @splat(0xAB);
    const list = buildList(&buf, 7, 0x0020, &pk, 0x0001, 0x0003, 64, "cover.example");

    const sel = try selectSupported(list, 0x0020, 0x0001, 0x0003);
    try testing.expect(sel != null);
    const cfg = sel.?;
    try testing.expectEqual(@as(u16, 0xfe0d), cfg.version);
    try testing.expectEqual(@as(u8, 7), cfg.config_id);
    try testing.expectEqual(@as(u16, 0x0020), cfg.kem_id);
    try testing.expectEqualSlices(u8, &pk, cfg.public_key);
    try testing.expectEqual(@as(usize, 1), cfg.cipherSuiteCount());
    try testing.expectEqual(@as(u16, 0x0001), cfg.cipherSuiteAt(0).kdf_id);
    try testing.expectEqual(@as(u16, 0x0003), cfg.cipherSuiteAt(0).aead_id);
    try testing.expect(cfg.supportsSuite(0x0001, 0x0003));
    try testing.expect(!cfg.supportsSuite(0x0002, 0x0003));
    try testing.expectEqual(@as(u8, 64), cfg.maximum_name_length);
    try testing.expectEqualSlices(u8, "cover.example", cfg.public_name);
    try testing.expectEqual(@as(usize, 0), cfg.extensions.len);
    // raw begins with the version bytes and covers the whole entry.
    try testing.expectEqual(@as(u16, 0xfe0d), std.mem.readInt(u16, cfg.raw[0..2], .big));
}

test "selectSupported skips entries with a mismatched KEM or suite" {
    var buf: [600]u8 = undefined;
    const pk: [32]u8 = @splat(0x11);
    const list = buildList(&buf, 1, 0x0020, &pk, 0x0001, 0x0003, 32, "a.example");

    // Wrong KEM ⇒ no match.
    try testing.expect((try selectSupported(list, 0x0010, 0x0001, 0x0003)) == null);
    // Wrong AEAD ⇒ no match.
    try testing.expect((try selectSupported(list, 0x0020, 0x0001, 0x0002)) == null);
    // Exact match ⇒ found.
    try testing.expect((try selectSupported(list, 0x0020, 0x0001, 0x0003)) != null);
}

test "malformed: truncated list prefix and overrunning length fields" {
    // Truncated 2-byte list prefix.
    try testing.expectError(error.Malformed, List.init(&[_]u8{0x00}));
    // List prefix claims 10 bytes but only 2 follow.
    try testing.expectError(error.Malformed, List.init(&[_]u8{ 0x00, 0x0A, 0x01, 0x02 }));
    // Well-formed prefix, but the single entry's length overruns.
    // list_len=6: version(fe0d) + length(0x00FF, overrunning) + 2 bytes
    const bad = [_]u8{ 0x00, 0x06, 0xfe, 0x0d, 0x00, 0xff, 0xaa, 0xbb };
    try testing.expectError(error.Malformed, selectSupported(&bad, 0x0020, 0x0001, 0x0003));
}

test "malformed: cipher_suites not a multiple of 4" {
    // Hand-build contents with a 2-byte (invalid) cipher_suites body.
    var contents: [64]u8 = undefined;
    var n: usize = 0;
    contents[n] = 3;
    n += 1; // config_id
    std.mem.writeInt(u16, contents[n..][0..2], 0x0020, .big);
    n += 2; // kem_id
    std.mem.writeInt(u16, contents[n..][0..2], 1, .big);
    n += 2; // public_key len=1
    contents[n] = 0xCD;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], 2, .big);
    n += 2; // cipher_suites len=2 (invalid: not a multiple of 4)
    std.mem.writeInt(u16, contents[n..][0..2], 0x0001, .big);
    n += 2;
    contents[n] = 16;
    n += 1; // max_name_len
    contents[n] = 1;
    n += 1;
    contents[n] = 'x';
    n += 1; // public_name "x"
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big);
    n += 2; // extensions len=0

    const entry = RawEntry{ .version = version_draft13, .raw = &.{}, .contents = contents[0..n] };
    try testing.expectError(error.Malformed, parse(entry));
}

test "unsupported mandatory ECHConfig extension disqualifies the config" {
    // Contents with one mandatory (high-bit) extension.
    var contents: [128]u8 = undefined;
    var n: usize = 0;
    contents[n] = 5;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], 0x0020, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], 32, .big);
    n += 2;
    const ext_pk: [32]u8 = @splat(0x22);
    @memcpy(contents[n..][0..32], &ext_pk);
    n += 32;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], 0x0001, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], 0x0003, .big);
    n += 2;
    contents[n] = 16;
    n += 1;
    contents[n] = 9;
    n += 1;
    @memcpy(contents[n..][0..9], "a.example");
    n += 9;
    // extensions: one entry, type 0x8001 (mandatory), empty data.
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    n += 2; // extensions total length
    std.mem.writeInt(u16, contents[n..][0..2], 0x8001, .big);
    n += 2; // ext type (mandatory)
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big);
    n += 2; // ext data length 0

    var entry_buf: [160]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, entry_buf[m..][0..2], version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, entry_buf[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(entry_buf[m..][0..n], contents[0..n]);
    m += n;
    var list_buf: [200]u8 = undefined;
    std.mem.writeInt(u16, list_buf[0..2], @intCast(m), .big);
    @memcpy(list_buf[2..][0..m], entry_buf[0..m]);
    const list = list_buf[0 .. 2 + m];

    const cfg = (try parse(.{ .version = version_draft13, .raw = entry_buf[0..m], .contents = contents[0..n] }));
    try testing.expect(try cfg.hasUnsupportedMandatoryExtension());
    // selectSupported therefore skips it.
    try testing.expect((try selectSupported(list, 0x0020, 0x0001, 0x0003)) == null);
}

test "selectSupported picks the first matching entry across mixed versions" {
    // Entry 1: an unknown version (0xfe0a) that must be skipped.
    // Entry 2: a good 0xfe0d entry.
    const pk: [32]u8 = @splat(0x33);
    var good_buf: [600]u8 = undefined;
    const good = buildList(&good_buf, 9, 0x0020, &pk, 0x0001, 0x0003, 50, "b.example");
    // good = [u16 list_len][entry]; extract the single entry bytes.
    const good_entry = good[2..];

    // Build an unknown-version entry: version 0xfe0a, length 3, 3 bytes.
    const unknown_entry = [_]u8{ 0xfe, 0x0a, 0x00, 0x03, 0x01, 0x02, 0x03 };

    var list_buf: [700]u8 = undefined;
    const total = unknown_entry.len + good_entry.len;
    std.mem.writeInt(u16, list_buf[0..2], @intCast(total), .big);
    @memcpy(list_buf[2..][0..unknown_entry.len], &unknown_entry);
    @memcpy(list_buf[2 + unknown_entry.len ..][0..good_entry.len], good_entry);
    const list = list_buf[0 .. 2 + total];

    const sel = try selectSupported(list, 0x0020, 0x0001, 0x0003);
    try testing.expect(sel != null);
    try testing.expectEqual(@as(u8, 9), sel.?.config_id);
    try testing.expectEqualSlices(u8, "b.example", sel.?.public_name);
}

test "public_name validation" {
    try testing.expect(isValidPublicName("example.com"));
    try testing.expect(isValidPublicName("a"));
    try testing.expect(isValidPublicName("cover-1.sub.example.org"));
    try testing.expect(!isValidPublicName(""));
    try testing.expect(!isValidPublicName(".leadingdot.com"));
    try testing.expect(!isValidPublicName("trailingdot.com."));
    try testing.expect(!isValidPublicName("double..dot"));
    try testing.expect(!isValidPublicName("-leadinghyphen.com"));
    try testing.expect(!isValidPublicName("trailinghyphen-.com"));
    try testing.expect(!isValidPublicName("under_score.com"));
    try testing.expect(!isValidPublicName("space name.com"));
    try testing.expect(!isValidPublicName("192.168.0.1")); // IPv4 literal
    try testing.expect(!isValidPublicName("12345")); // all-numeric single label
    try testing.expect(!isValidPublicName("1.2.3.4.5")); // all-numeric, dodges 3-dot IPv4 check
    try testing.expect(!isValidPublicName("host.123")); // all-numeric TLD
    try testing.expect(isValidPublicName("v2.example.com")); // digits allowed in non-TLD labels
    // A 64-char label is too long (max label length is 63).
    const long_label: [64]u8 = @splat('a');
    try testing.expect(!isValidPublicName(&long_label));
}

test "config with invalid public_name is skipped by selection" {
    var buf: [600]u8 = undefined;
    const pk: [32]u8 = @splat(0x44);
    const list = buildList(&buf, 2, 0x0020, &pk, 0x0001, 0x0003, 16, "192.168.1.1");
    try testing.expect((try selectSupported(list, 0x0020, 0x0001, 0x0003)) == null);
}
