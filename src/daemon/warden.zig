// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Warden — the network ban registry. The network ban registry for admins and opers.
//! checkpoints where travellers presented papers and were admitted or refused.
//!
//! Onyx Server replaces the legacy single-letter ban alphabet (K/D/G/Z/X/Q-line),
//! whose semantics overlapped and confused "what is matched" with "what
//! happens" and "where it applies", with one coherent entry — a `Ward` — built
//! from three ORTHOGONAL axes:
//!
//!   * Match  — which identity facet the pattern tests
//!              (address / host / mask / account / realname / certfp)
//!   * Scope  — node (this server) or mesh (propagated network-wide)
//!   * Action — what happens to a matching subject
//!              (refuse / expel / quarantine / require_auth)
//!
//! A subject presents its `Facets` at the checkpoint; `check` returns the first
//! active Ward that matches. Address matching understands IPv4 and IPv6 CIDR
//! (family-distinct); every other facet — and a bare/wildcard address pattern —
//! uses case-insensitive globbing. Pure: owns all strings, performs no I/O.

const std = @import("std");
const cidr = @import("../proto/cidr.zig");
const bloom = @import("../substrate/bloom.zig");

/// Which identity facet a Ward's pattern is tested against.
pub const Match = enum {
    address, // IP literal or CIDR (e.g. 192.0.2.0/24)
    host, // resolved/cloaked hostname glob
    mask, // nick!user@host glob
    account, // services account name glob
    realname, // GECOS / realname glob
    certfp, // TLS client-certificate fingerprint glob
    country, // GeoIP ISO-3166 country code (e.g. RU), glob-matched
    asn, // GeoIP autonomous-system number as a decimal string (e.g. 15169)

    pub fn token(self: Match) []const u8 {
        return switch (self) {
            .address => "address",
            .host => "host",
            .mask => "mask",
            .account => "account",
            .realname => "realname",
            .certfp => "certfp",
            .country => "country",
            .asn => "asn",
        };
    }

    pub fn parse(raw: []const u8) ?Match {
        inline for (@typeInfo(Match).@"enum".field_values) |f_value| {
            const m: Match = @enumFromInt(f_value);
            if (std.ascii.eqlIgnoreCase(raw, m.token())) return m;
        }
        return null;
    }
};

/// Where a Ward applies.
pub const Scope = enum {
    node,
    mesh,

    pub fn token(self: Scope) []const u8 {
        return switch (self) {
            .node => "node",
            .mesh => "mesh",
        };
    }

    pub fn parse(raw: []const u8) ?Scope {
        if (std.ascii.eqlIgnoreCase(raw, "node")) return .node;
        if (std.ascii.eqlIgnoreCase(raw, "mesh")) return .mesh;
        return null;
    }
};

/// What happens to a subject a Ward matches.
pub const Action = enum {
    refuse, // reject the connection before registration completes
    expel, // disconnect the client with the Ward's reason
    quarantine, // allow the connection but restrict it (no join/speak)
    require_auth, // permit only if the subject is authenticated to an account

    pub fn token(self: Action) []const u8 {
        return switch (self) {
            .refuse => "refuse",
            .expel => "expel",
            .quarantine => "quarantine",
            .require_auth => "require_auth",
        };
    }

    pub fn parse(raw: []const u8) ?Action {
        inline for (@typeInfo(Action).@"enum".field_values) |f_value| {
            const a: Action = @enumFromInt(f_value);
            if (std.ascii.eqlIgnoreCase(raw, a.token())) return a;
        }
        return null;
    }
};

pub const Params = struct {
    max_wards: usize = 1024,
    max_pattern: usize = 256,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

pub const WardError = error{
    EmptyPattern,
    PatternTooLong,
    ReasonTooLong,
    SetterTooLong,
    TooManyWards,
};

/// A single ban entry. String fields are owned by the registry.
pub const Ward = struct {
    match: Match,
    pattern: []const u8,
    scope: Scope = .node,
    action: Action = .expel,
    reason: []const u8 = "",
    set_by: []const u8 = "",
    created_ms: i64 = 0,
    /// Absolute expiry in epoch millis; 0 means permanent.
    expires_ms: i64 = 0,

    pub fn isExpired(self: Ward, now_ms: i64) bool {
        return self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

/// The identity a subject presents at the checkpoint. Empty/null facets never
/// match (a Ward on a facet the subject lacks simply does not apply).
pub const Facets = struct {
    address: []const u8 = "",
    host: []const u8 = "",
    mask: []const u8 = "",
    account: ?[]const u8 = null,
    realname: []const u8 = "",
    certfp: []const u8 = "",
    country: []const u8 = "",
    asn: []const u8 = "",

    fn facet(self: Facets, m: Match) []const u8 {
        return switch (m) {
            .address => self.address,
            .host => self.host,
            .mask => self.mask,
            .account => self.account orelse "",
            .realname => self.realname,
            .certfp => self.certfp,
            .country => self.country,
            .asn => self.asn,
        };
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    params: Params,
    wards: std.ArrayListUnmanaged(Ward) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Registry {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Registry) void {
        for (self.wards.items) |*w| freeWard(self.allocator, w);
        self.wards.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a Ward (its strings are duped). A Ward with the same (match, pattern)
    /// is replaced in place.
    pub fn add(self: *Registry, ward: Ward) (WardError || std.mem.Allocator.Error)!void {
        try self.validate(ward);
        var owned = try self.clone(ward);
        errdefer freeWard(self.allocator, &owned);
        if (self.indexOf(ward.match, ward.pattern)) |idx| {
            freeWard(self.allocator, &self.wards.items[idx]);
            self.wards.items[idx] = owned;
            return;
        }
        if (self.wards.items.len >= self.params.max_wards) return error.TooManyWards;
        try self.wards.append(self.allocator, owned);
    }

    /// Remove the Ward identified by (match, pattern). Returns true if present.
    pub fn remove(self: *Registry, match: Match, pattern: []const u8) bool {
        const idx = self.indexOf(match, pattern) orelse return false;
        var w = self.wards.orderedRemove(idx);
        freeWard(self.allocator, &w);
        return true;
    }

    /// First active Ward whose facet pattern matches the subject, or null.
    /// Expired Wards are pruned as a side effect.
    pub fn check(self: *Registry, facets: Facets, now_ms: i64) ?*const Ward {
        self.pruneExpired(now_ms);
        for (self.wards.items) |*w| {
            const value = facets.facet(w.match);
            if (value.len == 0) continue;
            if (matchValue(w.match, w.pattern, value)) return w;
        }
        return null;
    }

    /// Copy active Wards (optionally filtered by `only`) into `out`, newest stays
    /// in insertion order. Returns the filled prefix.
    pub fn list(self: *const Registry, only: ?Match, out: []Ward) []const Ward {
        var n: usize = 0;
        for (self.wards.items) |w| {
            if (only) |m| {
                if (w.match != m) continue;
            }
            if (n == out.len) break;
            out[n] = w;
            n += 1;
        }
        return out[0..n];
    }

    /// Borrow every active row without imposing a caller scratch-buffer cap.
    /// Anti-entropy must not silently report completion after a truncated list;
    /// the slice remains valid until the next Registry mutation.
    pub fn all(self: *const Registry) []const Ward {
        return self.wards.items;
    }

    /// The active Ward identified by (match, pattern), or null. A direct registry
    /// lookup (no bounded copy) so a caller can read an entry's `scope`/`action`
    /// regardless of how many Wards share the same `match`.
    pub fn find(self: *const Registry, match: Match, pattern: []const u8) ?*const Ward {
        const idx = self.indexOf(match, pattern) orelse return null;
        return &self.wards.items[idx];
    }

    pub fn count(self: *const Registry) usize {
        return self.wards.items.len;
    }

    /// Owned copy of every ward. The caller frees it with `deinitWardList`.
    pub fn clonedWards(self: *const Registry) std.mem.Allocator.Error!std.ArrayListUnmanaged(Ward) {
        var out: std.ArrayListUnmanaged(Ward) = .empty;
        errdefer deinitWardList(self.allocator, &out);
        for (self.wards.items) |w| try out.append(self.allocator, try self.clone(w));
        return out;
    }

    /// Swap the live list with `next`. The caller owns whatever `next` holds after.
    pub fn exchangeWards(self: *Registry, next: *std.ArrayListUnmanaged(Ward)) void {
        const old = self.wards;
        self.wards = next.*;
        next.* = old;
    }

    pub fn pruneExpired(self: *Registry, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.wards.items.len) {
            if (self.wards.items[i].isExpired(now_ms)) {
                var w = self.wards.orderedRemove(i);
                freeWard(self.allocator, &w);
            } else i += 1;
        }
    }

    fn validate(self: *const Registry, w: Ward) WardError!void {
        if (w.pattern.len == 0) return error.EmptyPattern;
        if (w.pattern.len > self.params.max_pattern) return error.PatternTooLong;
        if (w.reason.len > self.params.max_reason) return error.ReasonTooLong;
        if (w.set_by.len > self.params.max_setter) return error.SetterTooLong;
    }

    fn clone(self: *const Registry, w: Ward) std.mem.Allocator.Error!Ward {
        const pattern = try self.allocator.dupe(u8, w.pattern);
        errdefer self.allocator.free(pattern);
        const reason = try self.allocator.dupe(u8, w.reason);
        errdefer self.allocator.free(reason);
        const set_by = try self.allocator.dupe(u8, w.set_by);
        return .{
            .match = w.match,
            .pattern = pattern,
            .scope = w.scope,
            .action = w.action,
            .reason = reason,
            .set_by = set_by,
            .created_ms = w.created_ms,
            .expires_ms = w.expires_ms,
        };
    }

    fn indexOf(self: *const Registry, match: Match, pattern: []const u8) ?usize {
        for (self.wards.items, 0..) |w, i| {
            if (w.match == match and std.mem.eql(u8, w.pattern, pattern)) return i;
        }
        return null;
    }
};

fn freeWard(allocator: std.mem.Allocator, w: *Ward) void {
    allocator.free(w.pattern);
    allocator.free(w.reason);
    allocator.free(w.set_by);
    w.* = undefined;
}

pub fn deinitWardList(allocator: std.mem.Allocator, wards: *std.ArrayListUnmanaged(Ward)) void {
    for (wards.items) |*w| freeWard(allocator, w);
    wards.deinit(allocator);
    wards.* = .empty;
}

// ── mesh WARD wire codec ───────────────────────────────────────────────────
//
// A `mesh`-scope Ward is propagated to peers so already-running nodes enforce a
// network ban live (and forget it on removal/expiry). The wire form is a flat,
// length-prefixed record — no allocation on decode (the strings borrow the
// payload), pure, and independent of the daemon. Numeric axes (match/action/op)
// ride as single bytes; every string field is u16-length-prefixed.

pub const WireOp = enum(u8) {
    /// Add (or replace) the mesh ward on the receiving node.
    add = 0,
    /// Remove the mesh ward identified by (match, pattern) on the receiving node.
    remove = 1,
    /// Compact bloom of mesh-ban keys. Exchanged before the authoritative records.
    /// A hit is not a ban.
    filter = 2,
};

/// A decoded mesh-WARD record. String fields borrow the source payload.
pub const WireWard = struct {
    op: WireOp,
    match: Match,
    pattern: []const u8,
    action: Action,
    reason: []const u8,
    set_by: []const u8,
    created_ms: i64,
    expires_ms: i64,
};

pub const WireError = error{ ShortBuffer, Truncated, BadField };

/// Upper bound on an encoded record given the registry's string limits, so a
/// caller can size a stack buffer. (op + match + action) + 3 × (u16 len) +
/// 2 × i64 + the three max strings.
pub const max_wire_len: usize = 3 + 6 + 16 + 256 + 512 + 64;

fn putU16(buf: []u8, off: *usize, v: u16) WireError!void {
    if (off.* + 2 > buf.len) return error.ShortBuffer;
    std.mem.writeInt(u16, buf[off.*..][0..2], v, .little);
    off.* += 2;
}

fn putI64(buf: []u8, off: *usize, v: i64) WireError!void {
    if (off.* + 8 > buf.len) return error.ShortBuffer;
    std.mem.writeInt(i64, buf[off.*..][0..8], v, .little);
    off.* += 8;
}

fn putStr(buf: []u8, off: *usize, s: []const u8) WireError!void {
    if (s.len > std.math.maxInt(u16)) return error.BadField;
    try putU16(buf, off, @intCast(s.len));
    if (off.* + s.len > buf.len) return error.ShortBuffer;
    @memcpy(buf[off.* .. off.* + s.len], s);
    off.* += s.len;
}

/// Encode a mesh-WARD record into `out`, returning the written prefix.
pub fn encodeWire(w: WireWard, out: []u8) WireError![]const u8 {
    var off: usize = 0;
    if (off + 3 > out.len) return error.ShortBuffer;
    out[off] = @intFromEnum(w.op);
    out[off + 1] = @intFromEnum(w.match);
    out[off + 2] = @intFromEnum(w.action);
    off += 3;
    try putStr(out, &off, w.pattern);
    try putStr(out, &off, w.reason);
    try putStr(out, &off, w.set_by);
    try putI64(out, &off, w.created_ms);
    try putI64(out, &off, w.expires_ms);
    return out[0..off];
}

fn takeU16(buf: []const u8, off: *usize) WireError!u16 {
    if (off.* + 2 > buf.len) return error.Truncated;
    const v = std.mem.readInt(u16, buf[off.*..][0..2], .little);
    off.* += 2;
    return v;
}

fn takeI64(buf: []const u8, off: *usize) WireError!i64 {
    if (off.* + 8 > buf.len) return error.Truncated;
    const v = std.mem.readInt(i64, buf[off.*..][0..8], .little);
    off.* += 8;
    return v;
}

fn takeStr(buf: []const u8, off: *usize) WireError![]const u8 {
    const n = try takeU16(buf, off);
    if (off.* + n > buf.len) return error.Truncated;
    const s = buf[off.* .. off.* + n];
    off.* += n;
    return s;
}

fn enumFromByte(comptime E: type, raw: u8) WireError!E {
    inline for (@typeInfo(E).@"enum".field_values) |f_value| {
        if (f_value == raw) return @enumFromInt(f_value);
    }
    return error.BadField;
}

/// Reject control bytes in a wire string field. `allow_space` distinguishes
/// free-text fields (reason) from single tokens (pattern, set_by): a hostile
/// peer's CR/LF here would otherwise be rendered verbatim into client-facing
/// lines (the `ERROR :Closing Link … (Banned: <reason>)` close) — an IRC line
/// injection — and a space in a token field splits it into spurious tokens.
fn validateWireField(s: []const u8, allow_space: bool) WireError!void {
    for (s) |c| {
        if (c < 0x20 or c == 0x7f) return error.BadField;
        if (!allow_space and c == ' ') return error.BadField;
    }
}

/// Decode a mesh-WARD record. Returned string slices borrow `bytes`.
pub fn decodeWire(bytes: []const u8) WireError!WireWard {
    if (bytes.len < 3) return error.Truncated;
    const op = try enumFromByte(WireOp, bytes[0]);
    const match = try enumFromByte(Match, bytes[1]);
    const action = try enumFromByte(Action, bytes[2]);
    var off: usize = 3;
    const pattern = try takeStr(bytes, &off);
    const reason = try takeStr(bytes, &off);
    const set_by = try takeStr(bytes, &off);
    const created_ms = try takeI64(bytes, &off);
    const expires_ms = try takeI64(bytes, &off);
    if (pattern.len == 0) return error.BadField;
    // This is the hostile-peer surface: unlike the local WARD command (whose
    // line parser already strips CRLF), these fields arrive raw off the mesh.
    try validateWireField(pattern, false);
    try validateWireField(set_by, false);
    try validateWireField(reason, true);
    return .{
        .op = op,
        .match = match,
        .pattern = pattern,
        .action = action,
        .reason = reason,
        .set_by = set_by,
        .created_ms = created_ms,
        .expires_ms = expires_ms,
    };
}

// ── compact mesh-ban filter ────────────────────────────────────────────────
//
// Peers exchange this bloom before the full mesh-WARD records. Membership is
// approximate: `mayContain` has no false negatives for keys inserted at build
// time and may false-positive. The registry remains the authority.

pub const mesh_ban_filter_bits: usize = 8192;
pub const mesh_ban_filter_hashes: usize = 4;
pub const mesh_ban_filter_wire_len: usize = 1 + 2 + 2 + 4 + (mesh_ban_filter_bits / 8);

pub const FilterError = WireError || std.mem.Allocator.Error || bloom.BloomError;

pub const BanDecision = enum {
    /// The key is not in the filter and not an active mesh ward.
    absent,
    /// The authoritative registry has this mesh ward.
    confirmed,
    /// The filter reported the key and the registry does not. Re-check only.
    false_positive,
};

pub const MeshBanFilter = struct {
    bloom: bloom.Bloom,

    pub fn deinit(self: *MeshBanFilter) void {
        self.bloom.deinit();
        self.* = undefined;
    }

    pub fn mayContain(self: *const MeshBanFilter, match: Match, pattern: []const u8) bool {
        var key_buf: [320]u8 = undefined;
        const key = meshBanKey(&key_buf, match, pattern) orelse return false;
        return self.bloom.mayContain(key);
    }
};

pub fn meshBanKey(buf: []u8, match: Match, pattern: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{s}\x00{s}", .{ match.token(), pattern }) catch null;
}

/// Bloom of active mesh-scope ward keys. Node-scope and expired rows are omitted.
pub fn buildMeshBanFilter(allocator: std.mem.Allocator, wards: []const Ward, now_ms: i64) FilterError!MeshBanFilter {
    var built = try bloom.Bloom.init(allocator, mesh_ban_filter_bits, mesh_ban_filter_hashes);
    errdefer built.deinit();
    var key_buf: [320]u8 = undefined;
    for (wards) |w| {
        if (w.scope != .mesh or w.isExpired(now_ms)) continue;
        const key = meshBanKey(&key_buf, w.match, w.pattern) orelse continue;
        built.add(key);
    }
    return .{ .bloom = built };
}

pub fn encodeMeshBanFilter(filter: *const MeshBanFilter, out: []u8) WireError![]const u8 {
    if (out.len < mesh_ban_filter_wire_len) return error.ShortBuffer;
    if (filter.bloom.bitCount() != mesh_ban_filter_bits or filter.bloom.hashCount() != mesh_ban_filter_hashes) return error.BadField;
    if (filter.bloom.bits.len != mesh_ban_filter_bits / 8) return error.BadField;
    out[0] = @intFromEnum(WireOp.filter);
    std.mem.writeInt(u16, out[1..3], @intCast(mesh_ban_filter_bits), .little);
    std.mem.writeInt(u16, out[3..5], @intCast(mesh_ban_filter_hashes), .little);
    const items: u32 = if (filter.bloom.len() > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(filter.bloom.len());
    std.mem.writeInt(u32, out[5..9], items, .little);
    @memcpy(out[9..][0 .. mesh_ban_filter_bits / 8], filter.bloom.bits);
    return out[0..mesh_ban_filter_wire_len];
}

pub fn decodeMeshBanFilter(allocator: std.mem.Allocator, bytes: []const u8) FilterError!MeshBanFilter {
    if (bytes.len != mesh_ban_filter_wire_len) return error.Truncated;
    if (bytes[0] != @intFromEnum(WireOp.filter)) return error.BadField;
    const bit_count = std.mem.readInt(u16, bytes[1..3], .little);
    const hash_count = std.mem.readInt(u16, bytes[3..5], .little);
    if (bit_count != mesh_ban_filter_bits or hash_count != mesh_ban_filter_hashes) return error.BadField;
    const item_count = std.mem.readInt(u32, bytes[5..9], .little);
    var built = try bloom.Bloom.init(allocator, mesh_ban_filter_bits, mesh_ban_filter_hashes);
    errdefer built.deinit();
    @memcpy(built.bits, bytes[9..][0 .. mesh_ban_filter_bits / 8]);
    built.item_count = item_count;
    return .{ .bloom = built };
}

/// A filter hit refuses nobody by itself. `false_positive` means the bloom
/// reported the key and the live mesh registry does not; the caller re-checks
/// and does not refuse. A registry hit is `confirmed` even when the filter misses.
pub fn decideMeshBan(filter: ?*const MeshBanFilter, registry: *const Registry, match: Match, pattern: []const u8, now_ms: i64) BanDecision {
    const on_list = if (registry.find(match, pattern)) |w|
        w.scope == .mesh and !w.isExpired(now_ms)
    else
        false;
    if (filter) |f| {
        if (f.mayContain(match, pattern) and !on_list) return .false_positive;
    }
    if (on_list) return .confirmed;
    return .absent;
}

/// Match a facet value against a Ward pattern. An `.address` pattern that
/// contains a `/` is an IPv4 **or** IPv6 CIDR network; every other facet — and a
/// bare or wildcard address pattern such as `192.0.2.*` (no `/`) — uses
/// case-insensitive globbing. CIDR matching is family-distinct: a v4 network
/// never matches a v6 address and vice-versa, so a range ban cannot be dodged by
/// address family. A malformed CIDR, or a value that is not an IP of the same
/// family, fails closed on this axis (it is never literal-globbed against the
/// CIDR text).
pub fn matchValue(match: Match, pattern: []const u8, value: []const u8) bool {
    if (match == .address and std.mem.indexOfScalar(u8, pattern, '/') != null) {
        const network = cidr.Cidr.parse(pattern) catch return false;
        return network.containsText(value) catch false;
    }
    return globMatch(pattern, value);
}

/// Iterative, case-insensitive `*`/`?` glob (no recursion, backtracking).
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

// ── tests ────────────────────────────────────────────────────────────────

fn mkWard(match: Match, pattern: []const u8, action: Action) Ward {
    return .{ .match = match, .pattern = pattern, .action = action, .reason = "nope", .set_by = "oper", .created_ms = 100 };
}

test "axis tokens parse round-trip" {
    inline for (@typeInfo(Match).@"enum".field_values) |f_value| {
        const m: Match = @enumFromInt(f_value);
        try std.testing.expectEqual(m, Match.parse(m.token()).?);
    }
    try std.testing.expectEqual(Scope.mesh, Scope.parse("MESH").?);
    try std.testing.expectEqual(Action.quarantine, Action.parse("Quarantine").?);
    try std.testing.expect(Action.parse("kline") == null);
}

test "address ward matches ipv4 cidr; mask ward globs" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.add(mkWard(.address, "192.0.2.0/24", .refuse));
    try reg.add(mkWard(.mask, "*!*@*.evil.example", .expel));

    try std.testing.expect(reg.check(.{ .address = "192.0.2.50" }, 200) != null);
    try std.testing.expect(reg.check(.{ .address = "192.0.3.50" }, 200) == null);
    const hit = reg.check(.{ .mask = "bob!~b@host.evil.example" }, 200).?;
    try std.testing.expectEqual(Action.expel, hit.action);
}

test "address ward matches ipv6 cidr; family-distinct from ipv4" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    // Insertion order matters: the v6 ward is checked first, then the v4 ward.
    try reg.add(mkWard(.address, "2001:db8::/32", .refuse));
    try reg.add(mkWard(.address, "10.0.0.0/8", .expel));

    // An in-range IPv6 address (compressed + full) hits the v6 ward.
    const hit = reg.check(.{ .address = "2001:db8:dead:beef::1" }, 0).?;
    try std.testing.expectEqual(Action.refuse, hit.action);
    // An out-of-range IPv6 address matches nothing.
    try std.testing.expect(reg.check(.{ .address = "2001:dead::1" }, 0) == null);
    // A v4 address falls through the v6 ward (family-distinct) to the v4 ward.
    try std.testing.expectEqual(Action.expel, reg.check(.{ .address = "10.1.2.3" }, 0).?.action);
    // A v6 loopback matches neither the v6 range nor the v4 range.
    try std.testing.expect(reg.check(.{ .address = "::1" }, 0) == null);
}

test "matchValue: ipv6 cidr, family-distinctness, and glob fallthrough" {
    // IPv6 CIDR, in and out of range.
    try std.testing.expect(matchValue(.address, "2001:db8::/32", "2001:db8::1"));
    try std.testing.expect(!matchValue(.address, "2001:db8::/32", "2001:db9::1"));
    // A v4 CIDR never matches a v6 value, and a v6 CIDR never matches a v4 value.
    try std.testing.expect(!matchValue(.address, "192.0.2.0/24", "2001:db8::1"));
    try std.testing.expect(!matchValue(.address, "2001:db8::/32", "192.0.2.1"));
    // A malformed CIDR fails closed (it is not literal-globbed against the value).
    try std.testing.expect(!matchValue(.address, "192.0.2.0/99", "192.0.2.5"));
    // A bare / wildcard address pattern has no '/', so it still globs unchanged.
    try std.testing.expect(matchValue(.address, "192.0.2.*", "192.0.2.55"));
    try std.testing.expect(matchValue(.address, "192.0.2.50", "192.0.2.50"));
    try std.testing.expect(!matchValue(.address, "192.0.2.50", "192.0.2.51"));
    // IPv4 CIDR still works exactly as before.
    try std.testing.expect(matchValue(.address, "192.0.2.0/24", "192.0.2.99"));
    try std.testing.expect(!matchValue(.address, "192.0.2.0/24", "192.0.3.1"));
    // A non-address facet ignores CIDR entirely and globs.
    try std.testing.expect(matchValue(.host, "*.bad", "x.bad"));
}

test "mesh ward wire round-trips an ipv6 cidr pattern" {
    var buf: [max_wire_len]u8 = undefined;
    const w = WireWard{
        .op = .add,
        .match = .address,
        .pattern = "2001:db8::/32",
        .action = .refuse,
        .reason = "range ban",
        .set_by = "oper",
        .created_ms = 7,
        .expires_ms = 0,
    };
    const back = try decodeWire(try encodeWire(w, &buf));
    try std.testing.expectEqual(Match.address, back.match);
    try std.testing.expectEqualStrings("2001:db8::/32", back.pattern);
}

test "country ward matches the GeoIP country facet case-insensitively" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.add(mkWard(.country, "RU", .refuse));
    try reg.add(mkWard(.asn, "1313*", .expel)); // glob: AS131300..131399 etc.
    try std.testing.expect(reg.check(.{ .country = "ru" }, 0) != null);
    try std.testing.expect(reg.check(.{ .country = "US" }, 0) == null);
    try std.testing.expect(reg.check(.{}, 0) == null); // no country/asn facet
    try std.testing.expect(reg.check(.{ .asn = "131337" }, 0) != null);
    try std.testing.expect(reg.check(.{ .asn = "15169" }, 0) == null);
    try std.testing.expectEqual(Match.country, Match.parse("COUNTRY").?);
    try std.testing.expectEqual(Match.asn, Match.parse("asn").?);
}

test "absent facet never matches; account ward needs account" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.add(mkWard(.account, "spammer*", .require_auth));
    try std.testing.expect(reg.check(.{ .mask = "x!y@z" }, 0) == null); // no account facet
    try std.testing.expect(reg.check(.{ .account = "spammer42" }, 0) != null);
}

test "expiry prunes and stops matching" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    var w = mkWard(.host, "*.bad", .expel);
    w.expires_ms = 1000;
    try reg.add(w);
    try std.testing.expect(reg.check(.{ .host = "x.bad" }, 999) != null);
    try std.testing.expect(reg.check(.{ .host = "x.bad" }, 1000) == null);
    try std.testing.expectEqual(@as(usize, 0), reg.count());
}

test "add replaces on same match+pattern; remove + list" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    var a = mkWard(.mask, "*!*@dup", .expel);
    a.reason = "first";
    try reg.add(a);
    var b = mkWard(.mask, "*!*@dup", .quarantine);
    b.reason = "second";
    try reg.add(b);
    try std.testing.expectEqual(@as(usize, 1), reg.count());

    try reg.add(mkWard(.host, "*.other", .expel));
    var out: [8]Ward = undefined;
    const masks = reg.list(.mask, &out);
    try std.testing.expectEqual(@as(usize, 1), masks.len);
    try std.testing.expectEqualStrings("second", masks[0].reason);

    try std.testing.expect(reg.remove(.mask, "*!*@dup"));
    try std.testing.expect(!reg.remove(.mask, "*!*@dup"));
}

test "limits and validation" {
    var reg = Registry.init(std.testing.allocator, .{ .max_wards = 1, .max_pattern = 8, .max_reason = 4 });
    defer reg.deinit();
    try std.testing.expectError(error.EmptyPattern, reg.add(mkWard(.host, "", .expel)));
    try std.testing.expectError(error.PatternTooLong, reg.add(mkWard(.host, "wayyytoolong", .expel)));
    var longr = mkWard(.host, "a.b", .expel);
    longr.reason = "toolong";
    try std.testing.expectError(error.ReasonTooLong, reg.add(longr));
    try reg.add(mkWard(.host, "a.b", .expel));
    try std.testing.expectError(error.TooManyWards, reg.add(mkWard(.host, "c.d", .expel)));
}

test "mesh ward wire round-trips add and remove" {
    var buf: [max_wire_len]u8 = undefined;
    const add = WireWard{
        .op = .add,
        .match = .mask,
        .pattern = "*!*@*.evil.example",
        .action = .quarantine,
        .reason = "spam ring",
        .set_by = "oper!~o@admin",
        .created_ms = 1234,
        .expires_ms = 5678,
    };
    const wire = try encodeWire(add, &buf);
    const back = try decodeWire(wire);
    try std.testing.expectEqual(WireOp.add, back.op);
    try std.testing.expectEqual(Match.mask, back.match);
    try std.testing.expectEqual(Action.quarantine, back.action);
    try std.testing.expectEqualStrings("*!*@*.evil.example", back.pattern);
    try std.testing.expectEqualStrings("spam ring", back.reason);
    try std.testing.expectEqualStrings("oper!~o@admin", back.set_by);
    try std.testing.expectEqual(@as(i64, 1234), back.created_ms);
    try std.testing.expectEqual(@as(i64, 5678), back.expires_ms);

    const del = WireWard{
        .op = .remove,
        .match = .address,
        .pattern = "192.0.2.0/24",
        .action = .refuse,
        .reason = "",
        .set_by = "",
        .created_ms = 0,
        .expires_ms = 0,
    };
    const dwire = try encodeWire(del, &buf);
    const dback = try decodeWire(dwire);
    try std.testing.expectEqual(WireOp.remove, dback.op);
    try std.testing.expectEqual(Match.address, dback.match);
    try std.testing.expectEqualStrings("192.0.2.0/24", dback.pattern);
    try std.testing.expectEqual(@as(usize, 0), dback.reason.len);
}

test "mesh ward wire rejects truncated, empty pattern, and bad enum" {
    try std.testing.expectError(error.Truncated, decodeWire(&.{ 0, 0 }));
    // op=add(0), match=mask, action=expel, then a u16 length of 0 (empty pattern).
    var empty: [5]u8 = .{ 0, @intFromEnum(Match.mask), @intFromEnum(Action.expel), 0, 0 };
    try std.testing.expectError(error.Truncated, decodeWire(&empty));
    // A bad op byte (0xff) is rejected.
    var badop: [3]u8 = .{ 0xff, 0, 0 };
    try std.testing.expectError(error.BadField, decodeWire(&badop));
    // A pattern length that runs past the buffer is truncated.
    var short_pat: [5]u8 = .{ 0, @intFromEnum(Match.host), @intFromEnum(Action.expel), 10, 0 };
    try std.testing.expectError(error.Truncated, decodeWire(&short_pat));
}

test "mesh ward wire rejects control bytes / CRLF (line-injection guard)" {
    var buf: [max_wire_len]u8 = undefined;
    const base = WireWard{
        .op = .add,
        .match = .mask,
        .pattern = "*!*@host",
        .action = .expel,
        .reason = "clean reason",
        .set_by = "oper",
        .created_ms = 0,
        .expires_ms = 0,
    };
    // A CR/LF in the reason would be rendered verbatim into the client-facing
    // `ERROR :Closing Link … (Banned: <reason>)` close — a line injection.
    {
        var w = base;
        w.reason = "boom\r\n:evil 001 victim :pwned";
        const wire = try encodeWire(w, &buf);
        try std.testing.expectError(error.BadField, decodeWire(wire));
    }
    // A space in the single-token pattern/set_by fields is rejected too.
    {
        var w = base;
        w.set_by = "op er";
        const wire = try encodeWire(w, &buf);
        try std.testing.expectError(error.BadField, decodeWire(wire));
    }
    // A NUL anywhere is a control byte.
    {
        var w = base;
        w.pattern = "*!*@ho\x00st";
        const wire = try encodeWire(w, &buf);
        try std.testing.expectError(error.BadField, decodeWire(wire));
    }
    // The clean base still round-trips (guard doesn't over-reject).
    const ok = try decodeWire(try encodeWire(base, &buf));
    try std.testing.expectEqualStrings("clean reason", ok.reason);
}

test "no leak under churn" {
    var reg = Registry.init(std.testing.allocator, .{ .max_wards = 64 });
    defer reg.deinit();
    for (0..40) |i| {
        var buf: [32]u8 = undefined;
        const pat = try std.fmt.bufPrint(&buf, "*!*@host{d}.x", .{i});
        var w = mkWard(.mask, pat, .expel);
        w.expires_ms = @intCast(i + 1);
        try reg.add(w);
    }
    reg.pruneExpired(1000);
    try std.testing.expectEqual(@as(usize, 0), reg.count());
}
