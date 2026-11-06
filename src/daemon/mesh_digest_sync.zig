// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! M03 transport: digest exchange before the periodic anti-entropy burst.
//!
//! The periodic re-burst (`sendMeshStateBurstTo`) ships every burst family
//! to every due peer. With this exchange, the sender first offers one digest
//! per family; the receiver answers which families it does not already hold
//! at that digest; only those families (and, for bucket-scoped families,
//! only the rows in differing buckets) are re-sent.
//!
//! Model: the burst is sender-authored. A family's rows are the sender's
//! canonical projection of exactly the records that family's burst emits
//! (never the per-burst HLC, nonce or signature). Each row is a
//! `digest_reconcile` row keyed by the record identity, so a family digest
//! is the canonical `digest_reconcile.FamilyDigest` (root plus 64 bucket
//! roots) of that row set and never depends on iteration order.
//!
//! Frames (secured, signed, single hop, never relayed; negotiated by a PING
//! extension so peers without it keep the full burst):
//!   * OFFER  (sender -> receiver): round id plus `(family, rows, root)` for
//!     every family the sender digests this round.
//!   * NEED   (receiver -> sender): the families the receiver needs, the
//!     family set it knows, and, for a family it holds an earlier digest of,
//!     that digest's bucket roots so the sender can ship only differing
//!     buckets.
//!   * COMMIT (sender -> receiver): queued on the ordered stream right after
//!     a family's burst records in a pass started by a NEED, carrying the
//!     digest of the rows that burst represents. The receiver records it as
//!     the family it now holds. Other bursts (establishment, RESYNC, Helix
//!     resume, fallback) carry no commits and stay byte-identical to the
//!     pre-M03 wire; the first answered round after them needs every family.
//!
//! Mixed versions (review finding 3): a family one side does not know never
//! escalates the others. A family the receiver does not list as known is
//! always sent in full (exactly the pre-M03 behavior for that family), and
//! an offered family id the receiver does not know is ignored.
//!
//! Fail-safe direction: every failure resolves to sending more. A malformed
//! or missing NEED, an allocation failure while digesting, an inbox overflow
//! or a lost commit makes the affected family (or the whole round) take the
//! full burst. The receiver also forgets a family's accepted digest after
//! `refresh_ms`, bounding how long a receiver-side loss (for example a frame
//! it rejected locally) can hide behind a matching sender digest.
//!
//! Nothing here migrates through Helix: the book and plan live on the
//! secured link and a resumed or re-established link starts empty, which
//! only means the first round after it sends every family.

const std = @import("std");
const digest_reconcile = @import("../substrate/undertow/digest_reconcile.zig");
const s2s_frame = @import("../proto/s2s_frame.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hash = digest_reconcile.Hash;
pub const num_buckets = digest_reconcile.num_buckets;

/// Burst families in `sendMeshStateBurstTo` stage order. The numeric value
/// is the stable wire id; append new families, never renumber.
pub const Family = enum(u8) {
    membership = 0,
    mode_flags = 1,
    mode_state = 2,
    channel_props = 3,
    entity_props = 4,
    topics = 5,
    opers = 6,
    wards = 7,
    access_entries = 8,
    clones = 9,
    keytrans = 10,

    /// Domain-separating `digest_reconcile` family name.
    pub fn name(self: Family) []const u8 {
        return switch (self) {
            .membership => "onyx.burst.membership",
            .mode_flags => "onyx.burst.mode_flags",
            .mode_state => "onyx.burst.mode_state",
            .channel_props => "onyx.burst.channel_props",
            .entity_props => "onyx.burst.entity_props",
            .topics => "onyx.burst.topics",
            .opers => "onyx.burst.opers",
            .wards => "onyx.burst.wards",
            .access_entries => "onyx.burst.access_entries",
            .clones => "onyx.burst.clones",
            .keytrans => "onyx.burst.keytrans",
        };
    }

    /// True when every burst record of the family is an independent,
    /// idempotent LWW fact keyed exactly by its digest row key, so the
    /// records of differing buckets can be re-sent alone. Families whose
    /// burst carries a completion proof (membership's MEMBERSHIP_SYNC), a
    /// derived aggregate (the ward filter) or opaque per-node blobs always
    /// ship whole when they differ.
    pub fn bucketScoped(self: Family) bool {
        return switch (self) {
            .mode_flags, .mode_state, .channel_props, .topics => true,
            else => false,
        };
    }

    pub fn bit(self: Family) FamilyMask {
        return @as(FamilyMask, 1) << @intCast(@backingInt(self));
    }

    pub fn fromId(id: u8) ?Family {
        if (id >= family_count) return null;
        return @fromBackingInt(@intCast(id));
    }
};

pub const family_count: usize = @typeInfo(Family).@"enum".field_names.len;
pub const FamilyMask = u16;
pub const all_families: FamilyMask = (@as(FamilyMask, 1) << family_count) - 1;
/// Family ids on the wire are below this so the known-set fits one u64.
pub const max_wire_families: usize = 64;

comptime {
    std.debug.assert(family_count <= @bitSizeOf(FamilyMask));
    std.debug.assert(family_count <= max_wire_families);
}

/// A receiver forgets an accepted family digest after this long, so the
/// next round re-sends that family whole even when the digests match.
pub const refresh_ms: u64 = 10 * 60 * 1000;
/// Minimum spacing between NEED answers on one link; extra offers inside
/// the window are dropped and the sender falls back to the full burst.
pub const min_answer_interval_ms: u64 = 1000;

pub const FamilyDigest = struct {
    entry_count: u64,
    root: Hash,
    buckets: [num_buckets]Hash,
};

/// Domain-separated hash of one row's content. Variable-length fields are
/// length-prefixed so adjacent fields can never alias.
pub const RowHasher = struct {
    h: Sha256,

    pub fn init(family: Family) RowHasher {
        var h = Sha256.init(.{});
        h.update("onyx-m03-row-v1");
        h.update(&.{@backingInt(family)});
        return .{ .h = h };
    }

    pub fn bytes(self: *RowHasher, value: []const u8) void {
        var len: [8]u8 = undefined;
        std.mem.writeInt(u64, &len, value.len, .little);
        self.h.update(&len);
        self.h.update(value);
    }

    pub fn optBytes(self: *RowHasher, value: ?[]const u8) void {
        if (value) |v| {
            self.h.update(&.{1});
            self.bytes(v);
        } else self.h.update(&.{0});
    }

    pub fn int(self: *RowHasher, value: u64) void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .little);
        self.h.update(&buf);
    }

    pub fn flag(self: *RowHasher, value: bool) void {
        self.h.update(&.{@intFromBool(value)});
    }

    /// Hash every field of `value` by type, so a row covers all the record
    /// fields a burst emits (and any field added later) without a hand-kept
    /// list. Byte slices and arrays are length-prefixed; optionals carry a
    /// presence byte; tagged unions hash the tag and the active payload.
    /// Unsupported types (opaque pointers, functions) fail at compile time.
    pub fn any(self: *RowHasher, value: anytype) void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .bool => self.flag(value),
            .comptime_int => self.int(value),
            .int => |info| {
                if (info.bits <= 64) {
                    const U = @Int(.unsigned, info.bits);
                    self.int(@as(u64, @as(U, @bitCast(value))));
                } else self.bytes(std.mem.asBytes(&value));
            },
            .@"enum" => self.any(@backingInt(value)),
            .optional => if (value) |v| {
                self.h.update(&.{1});
                self.any(v);
            } else self.h.update(&.{0}),
            .array => |a| if (a.child == u8) self.bytes(&value) else {
                self.int(a.len);
                for (value) |v| self.any(v);
            },
            .pointer => |p| switch (p.size) {
                .slice => if (p.child == u8) self.bytes(value) else {
                    self.int(value.len);
                    for (value) |v| self.any(v);
                },
                .one => self.any(value.*),
                else => @compileError("RowHasher.any: unsupported pointer " ++ @typeName(T)),
            },
            .@"struct" => |st| if (st.layout == .@"packed") {
                self.any(@as(st.backing_integer.?, @bitCast(value)));
            } else inline for (st.field_names) |field_name| self.any(@field(value, field_name)),
            .@"union" => |u| {
                if (u.tag_type == null) @compileError("RowHasher.any: untagged union " ++ @typeName(T));
                self.any(std.meta.activeTag(value));
                switch (value) {
                    inline else => |payload| self.any(payload),
                }
            },
            .void => {},
            else => @compileError("RowHasher.any: unsupported type " ++ @typeName(T)),
        }
    }

    pub fn final(self: *RowHasher) Hash {
        var out: Hash = undefined;
        self.h.final(&out);
        return out;
    }
};

pub const FinishError = std.mem.Allocator.Error || error{DuplicateRowKey};

/// Canonical row set of one family under construction. Rows may be added in
/// any order; `finish` sorts them and returns the family digest.
pub const Rows = struct {
    family: Family,
    state: digest_reconcile.FamilyState,

    pub fn init(allocator: std.mem.Allocator, family: Family) std.mem.Allocator.Error!Rows {
        return .{ .family = family, .state = try digest_reconcile.FamilyState.init(allocator, family.name()) };
    }

    pub fn deinit(self: *Rows) void {
        self.state.deinit();
    }

    /// Add one row. `key` is the record identity (also the bucket key for a
    /// bucket-scoped family); `version` is a stored, not per-burst, clock.
    pub fn add(self: *Rows, key: []const u8, version: u64, value_hash: Hash) std.mem.Allocator.Error!void {
        try self.state.appendUnsorted(key, version, value_hash, false);
    }

    /// Sort the rows and digest them. Two rows with one key but different
    /// content would leave one of them out of the digest, so that fails
    /// closed with `error.DuplicateRowKey` (the caller then sends the family
    /// whole and invalidates the peer's held digest).
    pub fn finish(self: *Rows) FinishError!FamilyDigest {
        if (!self.state.normalize()) return error.DuplicateRowKey;
        var d = try self.state.digest();
        defer d.deinit(self.state.allocator);
        return .{ .entry_count = d.entry_count, .root = d.root, .buckets = d.buckets };
    }
};

/// Bucket a bucket-scoped family's row key falls into.
pub fn bucketOf(family: Family, key: []const u8) u8 {
    return digest_reconcile.bucketIndex(family.name(), key);
}

/// Buckets whose roots differ between the receiver's previous digest and
/// the sender's current one. Bit `b` set means bucket `b` must be re-sent.
pub fn differingBuckets(prev: *const [num_buckets]Hash, current: *const FamilyDigest) u64 {
    var mask: u64 = 0;
    for (prev, current.buckets, 0..) |p, c, b| {
        if (!std.mem.eql(u8, &p, &c)) mask |= @as(u64, 1) << @intCast(b);
    }
    return mask;
}

// ---------------------------------------------------------------- wire codec

const offer_magic = "ODO1";
const need_magic = "ODN1";
const commit_magic = "ODC1";
const wire_version: u8 = 1;
const header_len: usize = 4 + 1;
const offer_entry_len: usize = 1 + 8 + 32;
const buckets_len: usize = 32 * num_buckets;

pub const max_offer_len: usize = header_len + 8 + 1 + max_wire_families * offer_entry_len;
pub const max_need_len: usize = header_len + 8 + 8 + 1 + max_wire_families * (2 + buckets_len);
pub const max_commit_len: usize = header_len + 1 + 1 + 8 + 32 + buckets_len;
/// Largest NEED this build ever encodes (it only lists families it knows).
pub const max_local_need_len: usize = header_len + 8 + 8 + 1 + family_count * (2 + buckets_len);

comptime {
    std.debug.assert(max_offer_len == s2s_frame.max_digest_offer_body_len);
    std.debug.assert(max_need_len == s2s_frame.max_digest_need_body_len);
    std.debug.assert(max_commit_len == s2s_frame.max_digest_commit_body_len);
}

pub const DecodeError = error{
    Truncated,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    TooManyFamilies,
    UnsortedFamilies,
    BadFlag,
    UnknownNeedFamily,
    ZeroRound,
};

pub const EncodeError = error{ BufferTooSmall, TooManyFamilies, UnsortedFamilies, ZeroRound };

pub const OfferEntry = struct {
    id: u8,
    entry_count: u64,
    root: Hash,
};

pub const Offer = struct {
    round: u64,
    len: usize = 0,
    entries: [max_wire_families]OfferEntry = undefined,

    pub fn items(self: *const Offer) []const OfferEntry {
        return self.entries[0..self.len];
    }
};

pub const NeedEntry = struct {
    id: u8,
    /// The receiver's previous accepted bucket roots for this family, as raw
    /// wire bytes (`num_buckets` x 32), or null when it holds none.
    prev: ?[]const u8,

    pub fn prevBuckets(self: NeedEntry) ?[num_buckets]Hash {
        const raw = self.prev orelse return null;
        var out: [num_buckets]Hash = undefined;
        for (&out, 0..) |*b, i| @memcpy(b, raw[i * 32 ..][0..32]);
        return out;
    }
};

/// Zero-copy decoded NEED: `entries[i].prev` borrows the decoded bytes.
pub const Need = struct {
    round: u64,
    /// Bit `id` set: the receiver knows family `id` and decided on it.
    known: u64,
    len: usize = 0,
    entries: [max_wire_families]NeedEntry = undefined,

    pub fn items(self: *const Need) []const NeedEntry {
        return self.entries[0..self.len];
    }

    pub fn knows(self: *const Need, id: u8) bool {
        return id < max_wire_families and (self.known >> @intCast(id)) & 1 == 1;
    }
};

pub const Commit = struct {
    id: u8,
    /// Null invalidates the receiver's accepted digest for the family (the
    /// sender could not digest what it just sent).
    digest: ?FamilyDigest,
    /// False ships only `(rows, root)`: the 64 bucket roots (2 KiB) are sent
    /// only where they can narrow a re-send (`commitCarriesBuckets`), which
    /// keeps the per-burst commit overhead small. A receiver never offers
    /// previous buckets it did not receive.
    buckets: bool = true,
};

/// Whether a commit for `family` with `entry_count` rows carries bucket
/// roots: only bucket-scoped families, and only when non-empty.
pub fn commitCarriesBuckets(family: Family, entry_count: u64) bool {
    return family.bucketScoped() and entry_count != 0;
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn put(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.buf.len - self.pos < bytes.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn int(self: *Writer, comptime T: type, value: T) EncodeError!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, value, .little);
        try self.put(&b);
    }

    fn header(self: *Writer, magic: []const u8) EncodeError!void {
        try self.put(magic);
        try self.put(&.{wire_version});
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) DecodeError![]const u8 {
        if (self.bytes.len - self.pos < n) return error.Truncated;
        const out = self.bytes[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    fn int(self: *Reader, comptime T: type) DecodeError!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    fn byte(self: *Reader) DecodeError!u8 {
        return (try self.take(1))[0];
    }

    fn header(self: *Reader, magic: []const u8) DecodeError!void {
        if (self.bytes.len < header_len) return error.Truncated;
        if (!std.mem.eql(u8, (try self.take(4)), magic)) return error.BadMagic;
        if ((try self.byte()) != wire_version) return error.UnsupportedVersion;
    }

    fn end(self: *const Reader) DecodeError!void {
        if (self.pos != self.bytes.len) return error.TrailingBytes;
    }
};

fn flagByte(b: u8) DecodeError!bool {
    return switch (b) {
        0 => false,
        1 => true,
        else => error.BadFlag,
    };
}

pub fn encodeOffer(offer: *const Offer, out: []u8) EncodeError![]const u8 {
    if (offer.round == 0) return error.ZeroRound;
    if (offer.len > max_wire_families) return error.TooManyFamilies;
    var w = Writer{ .buf = out };
    try w.header(offer_magic);
    try w.int(u64, offer.round);
    try w.put(&.{@intCast(offer.len)});
    for (offer.items(), 0..) |e, i| {
        if (e.id >= max_wire_families) return error.TooManyFamilies;
        if (i != 0 and offer.entries[i - 1].id >= e.id) return error.UnsortedFamilies;
        try w.put(&.{e.id});
        try w.int(u64, e.entry_count);
        try w.put(&e.root);
    }
    return out[0..w.pos];
}

pub fn decodeOffer(bytes: []const u8) DecodeError!Offer {
    if (bytes.len > max_offer_len) return error.TooManyFamilies;
    var r = Reader{ .bytes = bytes };
    try r.header(offer_magic);
    var offer = Offer{ .round = try r.int(u64) };
    if (offer.round == 0) return error.ZeroRound;
    const count = try r.byte();
    if (count > max_wire_families) return error.TooManyFamilies;
    for (0..count) |i| {
        const id = try r.byte();
        if (id >= max_wire_families) return error.TooManyFamilies;
        if (i != 0 and offer.entries[i - 1].id >= id) return error.UnsortedFamilies;
        offer.entries[i] = .{ .id = id, .entry_count = try r.int(u64), .root = (try r.take(32))[0..32].* };
    }
    offer.len = count;
    try r.end();
    return offer;
}

pub fn decodeNeed(bytes: []const u8) DecodeError!Need {
    if (bytes.len > max_need_len) return error.TooManyFamilies;
    var r = Reader{ .bytes = bytes };
    try r.header(need_magic);
    var need = Need{ .round = try r.int(u64), .known = try r.int(u64) };
    if (need.round == 0) return error.ZeroRound;
    const count = try r.byte();
    if (count > max_wire_families) return error.TooManyFamilies;
    for (0..count) |i| {
        const id = try r.byte();
        if (id >= max_wire_families) return error.TooManyFamilies;
        if (i != 0 and need.entries[i - 1].id >= id) return error.UnsortedFamilies;
        if (!need.knows(id)) return error.UnknownNeedFamily;
        const has_prev = try flagByte(try r.byte());
        need.entries[i] = .{ .id = id, .prev = if (has_prev) try r.take(buckets_len) else null };
    }
    need.len = count;
    try r.end();
    return need;
}

const commit_invalidate: u8 = 0;
const commit_with_buckets: u8 = 1;
const commit_root_only: u8 = 2;

pub fn encodeCommit(commit: *const Commit, out: []u8) EncodeError![]const u8 {
    if (commit.id >= max_wire_families) return error.TooManyFamilies;
    var w = Writer{ .buf = out };
    try w.header(commit_magic);
    try w.put(&.{commit.id});
    if (commit.digest) |d| {
        try w.put(&.{if (commit.buckets) commit_with_buckets else commit_root_only});
        try w.int(u64, d.entry_count);
        try w.put(&d.root);
        if (commit.buckets) for (d.buckets) |b| try w.put(&b);
    } else try w.put(&.{commit_invalidate});
    return out[0..w.pos];
}

pub fn decodeCommit(bytes: []const u8) DecodeError!Commit {
    if (bytes.len > max_commit_len) return error.TrailingBytes;
    var r = Reader{ .bytes = bytes };
    try r.header(commit_magic);
    const id = try r.byte();
    if (id >= max_wire_families) return error.TooManyFamilies;
    var commit = Commit{ .id = id, .digest = null };
    const kind = try r.byte();
    switch (kind) {
        commit_invalidate => {},
        commit_with_buckets, commit_root_only => {
            var d: FamilyDigest = .{ .entry_count = try r.int(u64), .root = (try r.take(32))[0..32].*, .buckets = @splat(@splat(0)) };
            commit.buckets = kind == commit_with_buckets;
            if (commit.buckets) for (&d.buckets) |*b| {
                b.* = (try r.take(32))[0..32].*;
            };
            commit.digest = d;
        },
        else => return error.BadFlag,
    }
    try r.end();
    return commit;
}

// --------------------------------------------------------- receiver: book

/// What one receiver holds from one sender: the digest of the last complete
/// burst of each family the sender committed on this link.
pub const Book = struct {
    slots: [family_count]Slot = @splat(.{}),

    pub const Slot = struct {
        valid: bool = false,
        /// `digest.buckets` was received and may be offered back.
        has_buckets: bool = false,
        digest: FamilyDigest = undefined,
        accepted_ms: u64 = 0,
    };

    pub fn invalidateAll(self: *Book) void {
        for (&self.slots) |*s| s.valid = false;
    }

    /// Record (or, for a null digest, forget) one committed family. A family
    /// id this build does not know is ignored.
    pub fn applyCommit(self: *Book, commit: *const Commit, now_ms: u64) void {
        const family = Family.fromId(commit.id) orelse return;
        const slot = &self.slots[@backingInt(family)];
        if (commit.digest) |d| {
            slot.* = .{ .valid = true, .has_buckets = commit.buckets, .digest = d, .accepted_ms = now_ms };
        } else slot.valid = false;
    }

    fn fresh(slot: *const Slot, now_ms: u64) bool {
        return slot.valid and now_ms >= slot.accepted_ms and now_ms - slot.accepted_ms < refresh_ms;
    }

    /// Encode the NEED answer to `offer`. A known family is in sync only
    /// when this book holds a fresh digest with the same row count and root;
    /// otherwise it is needed, with the held bucket roots when still fresh so
    /// the sender can ship only differing buckets. Offered ids this build
    /// does not know are ignored (they are absent from `known`).
    pub fn answer(self: *const Book, offer: *const Offer, now_ms: u64, out: []u8) EncodeError![]const u8 {
        if (offer.round == 0) return error.ZeroRound;
        var w = Writer{ .buf = out };
        try w.header(need_magic);
        try w.int(u64, offer.round);
        try w.int(u64, (@as(u64, 1) << family_count) - 1);
        var count: u8 = 0;
        for (offer.items()) |e| {
            const family = Family.fromId(e.id) orelse continue;
            const slot = &self.slots[@backingInt(family)];
            if (fresh(slot, now_ms) and slot.digest.entry_count == e.entry_count and std.mem.eql(u8, &slot.digest.root, &e.root)) continue;
            count += 1;
        }
        try w.put(&.{count});
        for (offer.items()) |e| {
            const family = Family.fromId(e.id) orelse continue;
            const slot = &self.slots[@backingInt(family)];
            const held = fresh(slot, now_ms);
            if (held and slot.digest.entry_count == e.entry_count and std.mem.eql(u8, &slot.digest.root, &e.root)) continue;
            try w.put(&.{e.id});
            if (held and slot.has_buckets) {
                try w.put(&.{1});
                for (slot.digest.buckets) |b| try w.put(&b);
            } else try w.put(&.{0});
        }
        return out[0..w.pos];
    }
};

// ------------------------------------------------------------ sender: plan

/// What the sender ships after one NEED.
pub const SendPlan = struct {
    /// Families to burst this round.
    send: FamilyMask = all_families,
    /// Families with the receiver's previous bucket roots in `prev`; only
    /// bucket-scoped families are marked.
    scoped: FamilyMask = 0,
    prev: [family_count][num_buckets]Hash = undefined,

    pub fn full() SendPlan {
        return .{};
    }

    pub fn sends(self: *const SendPlan, family: Family) bool {
        return self.send & family.bit() != 0;
    }

    pub fn prevFor(self: *const SendPlan, family: Family) ?*const [num_buckets]Hash {
        if (self.scoped & family.bit() == 0) return null;
        return &self.prev[@backingInt(family)];
    }
};

/// Build the send plan for a decoded NEED answering an offer of `offered`.
/// A family is sent when it was not offered, when the receiver does not
/// know it (mixed-version mesh: pre-M03 behavior for that family only), or
/// when the receiver needs it. Everything else is skipped.
pub fn planFromNeed(need: *const Need, offered: FamilyMask, out: *SendPlan) void {
    out.* = .{ .send = 0, .scoped = 0 };
    for (0..family_count) |i| {
        const family: Family = @fromBackingInt(@intCast(i));
        if (offered & family.bit() == 0 or !need.knows(@intCast(i))) out.send |= family.bit();
    }
    for (need.items()) |e| {
        const family = Family.fromId(e.id) orelse continue;
        out.send |= family.bit();
        if (!family.bucketScoped()) continue;
        if (e.prevBuckets()) |prev| {
            out.prev[@backingInt(family)] = prev;
            out.scoped |= family.bit();
        }
    }
}

// ------------------------------------------------------- per-link state

/// Digest-exchange state of one secured link, heap-allocated on first use
/// and freed with the link. Process-local; never carried by Helix.
pub const LinkState = struct {
    /// Receiver side: what the peer committed to us.
    book: Book = .{},
    last_answer_ms: ?u64 = null,
    /// Sender side: outstanding offer round (0 = none) and its family set.
    offer_round: u64 = 0,
    offered: FamilyMask = 0,
    next_round: u64 = 1,
    /// Sender side: plan of the digest-gated burst in progress, if any.
    plan: SendPlan = .{},
    plan_active: bool = false,
    /// Bucket filter for the family stage being encoded right now.
    active_family: ?Family = null,
    active_buckets: u64 = 0,
    /// Counters for operators and tests.
    rounds_offered: u64 = 0,
    rounds_converged: u64 = 0,
    rounds_partial: u64 = 0,
    rounds_fallback: u64 = 0,

    pub fn takeRound(self: *LinkState) u64 {
        const round = self.next_round;
        self.next_round +%= 1;
        if (self.next_round == 0) self.next_round = 1;
        return round;
    }

    /// True when a row with `key` of `family` is wanted by the stage being
    /// encoded: always, unless a bucket filter is active for that family.
    pub fn wantsRow(self: *const LinkState, family: Family, key: []const u8) bool {
        const active = self.active_family orelse return true;
        if (active != family) return true;
        return (self.active_buckets >> @intCast(bucketOf(family, key))) & 1 == 1;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn testDigest(seed: u8, rows: u64) FamilyDigest {
    var d: FamilyDigest = .{ .entry_count = rows, .root = @splat(seed), .buckets = undefined };
    for (&d.buckets, 0..) |*b, i| b.* = @splat(seed +% @as(u8, @intCast(i)));
    return d;
}

test "mesh_digest_sync: offer, need and commit round-trip and reject every malformed form" {
    var offer = Offer{ .round = 7 };
    offer.entries[0] = .{ .id = 1, .entry_count = 3, .root = @splat(0xA1) };
    offer.entries[1] = .{ .id = 5, .entry_count = 0, .root = @splat(0xB2) };
    offer.len = 2;
    var buf: [max_offer_len]u8 = undefined;
    const wire = try encodeOffer(&offer, &buf);
    const back = try decodeOffer(wire);
    try testing.expectEqual(@as(u64, 7), back.round);
    try testing.expectEqual(@as(usize, 2), back.len);
    try testing.expectEqual(@as(u8, 5), back.entries[1].id);
    for (0..wire.len) |cut| try testing.expect(std.meta.isError(decodeOffer(wire[0..cut])));
    var padded: [max_offer_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeOffer(padded[0 .. wire.len + 1]));
    var bad = padded;
    bad[0] = 'X';
    try testing.expectError(error.BadMagic, decodeOffer(bad[0..wire.len]));
    bad = padded;
    bad[4] = 2;
    try testing.expectError(error.UnsupportedVersion, decodeOffer(bad[0..wire.len]));
    // Duplicate / descending ids.
    bad = padded;
    bad[header_len + 8 + 1 + offer_entry_len] = 1;
    try testing.expectError(error.UnsortedFamilies, decodeOffer(bad[0..wire.len]));
    var zero = offer;
    zero.round = 0;
    try testing.expectError(error.ZeroRound, encodeOffer(&zero, &buf));

    var commit = Commit{ .id = 3, .digest = testDigest(9, 42) };
    var cbuf: [max_commit_len]u8 = undefined;
    const cwire = try encodeCommit(&commit, &cbuf);
    try testing.expectEqual(max_commit_len, cwire.len);
    const cback = try decodeCommit(cwire);
    try testing.expectEqual(@as(u64, 42), cback.digest.?.entry_count);
    try testing.expectEqualSlices(u8, &commit.digest.?.buckets[63], &cback.digest.?.buckets[63]);
    for (0..cwire.len) |cut| try testing.expect(std.meta.isError(decodeCommit(cwire[0..cut])));
    commit.digest = null;
    const inval = try encodeCommit(&commit, &cbuf);
    try testing.expect((try decodeCommit(inval)).digest == null);
    // Root-only commit: small, decodes without buckets, and a book holding
    // it never offers bucket roots back.
    var root_only = Commit{ .id = @backingInt(Family.wards), .digest = testDigest(4, 7), .buckets = false };
    const rwire = try encodeCommit(&root_only, &cbuf);
    try testing.expectEqual(header_len + 1 + 1 + 8 + 32, rwire.len);
    const rback = try decodeCommit(rwire);
    try testing.expect(!rback.buckets);
    try testing.expectEqualSlices(u8, &root_only.digest.?.root, &rback.digest.?.root);
    for (0..rwire.len) |cut| try testing.expect(std.meta.isError(decodeCommit(rwire[0..cut])));
    var rbook = Book{};
    rbook.applyCommit(&rback, 10);
    var roffer = Offer{ .round = 2 };
    roffer.entries[0] = .{ .id = @backingInt(Family.wards), .entry_count = 8, .root = @splat(0x55) };
    roffer.len = 1;
    var rneed_buf: [max_need_len]u8 = undefined;
    const rneed = try decodeNeed(try rbook.answer(&roffer, 11, &rneed_buf));
    try testing.expectEqual(@as(usize, 1), rneed.len);
    try testing.expect(rneed.entries[0].prev == null);
    try testing.expect(commitCarriesBuckets(.topics, 1));
    try testing.expect(!commitCarriesBuckets(.topics, 0));
    try testing.expect(!commitCarriesBuckets(.wards, 9));

    var flagged: [16]u8 = undefined;
    @memcpy(flagged[0..inval.len], inval);
    flagged[inval.len - 1] = 3;
    try testing.expectError(error.BadFlag, decodeCommit(flagged[0..inval.len]));
}

test "mesh_digest_sync: book answers in-sync, needed-with-buckets and refresh expiry" {
    var book = Book{};
    const d = testDigest(1, 10);
    book.applyCommit(&.{ .id = @backingInt(Family.topics), .digest = d }, 1000);
    book.applyCommit(&.{ .id = @backingInt(Family.wards), .digest = testDigest(2, 4) }, 1000);
    // An id this build does not know is ignored, never stored.
    book.applyCommit(&.{ .id = 40, .digest = d }, 1000);

    var offer = Offer{ .round = 9 };
    offer.entries[0] = .{ .id = @backingInt(Family.mode_flags), .entry_count = 1, .root = @splat(7) };
    offer.entries[1] = .{ .id = @backingInt(Family.topics), .entry_count = 10, .root = d.root };
    offer.entries[2] = .{ .id = @backingInt(Family.wards), .entry_count = 4, .root = @splat(0xEE) };
    offer.entries[3] = .{ .id = 40, .entry_count = 1, .root = @splat(1) };
    offer.len = 4;

    var buf: [max_need_len]u8 = undefined;
    const need = try decodeNeed(try book.answer(&offer, 2000, &buf));
    try testing.expectEqual(@as(u64, 9), need.round);
    try testing.expect(need.knows(@backingInt(Family.keytrans)));
    try testing.expect(!need.knows(40));
    try testing.expectEqual(@as(usize, 2), need.len);
    try testing.expectEqual(@as(u8, @backingInt(Family.mode_flags)), need.entries[0].id);
    try testing.expect(need.entries[0].prev == null);
    try testing.expectEqual(@as(u8, @backingInt(Family.wards)), need.entries[1].id);
    try testing.expect(need.entries[1].prev != null);

    // Past the refresh window the matching family is needed again, whole.
    const stale = try decodeNeed(try book.answer(&offer, 1000 + refresh_ms, &buf));
    try testing.expectEqual(@as(usize, 3), stale.len);
    for (stale.items()) |e| try testing.expect(e.prev == null);

    // An invalidating commit forgets the family.
    book.applyCommit(&.{ .id = @backingInt(Family.topics), .digest = null }, 2500);
    const forgot = try decodeNeed(try book.answer(&offer, 3000, &buf));
    try testing.expectEqual(@as(usize, 3), forgot.len);
}

test "mesh_digest_sync: the largest local answer fits its bound" {
    var book = Book{};
    var offer = Offer{ .round = 1 };
    for (0..family_count) |i| {
        book.applyCommit(&.{ .id = @intCast(i), .digest = testDigest(@intCast(i), 1) }, 0);
        offer.entries[i] = .{ .id = @intCast(i), .entry_count = 2, .root = @splat(0xFF) };
    }
    offer.len = family_count;
    var buf: [max_local_need_len]u8 = undefined;
    const wire = try book.answer(&offer, 1, &buf);
    try testing.expectEqual(max_local_need_len, wire.len);
    const need = try decodeNeed(wire);
    try testing.expectEqual(family_count, need.len);
    var small: [max_local_need_len - 1]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, book.answer(&offer, 1, &small));
}

test "mesh_digest_sync: need decode is strict" {
    var book = Book{};
    book.applyCommit(&.{ .id = @backingInt(Family.topics), .digest = testDigest(3, 2) }, 0);
    var offer = Offer{ .round = 4 };
    offer.entries[0] = .{ .id = @backingInt(Family.topics), .entry_count = 1, .root = @splat(0) };
    offer.len = 1;
    var buf: [max_need_len]u8 = undefined;
    const wire = try book.answer(&offer, 5, &buf);
    _ = try decodeNeed(wire);
    for (0..wire.len) |cut| try testing.expect(std.meta.isError(decodeNeed(wire[0..cut])));
    var bad: [max_need_len]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    // Clear the known bit of the needed family: an entry outside `known`.
    std.mem.writeInt(u64, bad[header_len + 8 ..][0..8], 0, .little);
    try testing.expectError(error.UnknownNeedFamily, decodeNeed(bad[0..wire.len]));
    @memcpy(bad[0..wire.len], wire);
    bad[header_len + 8 + 8 + 1 + 1] = 7;
    try testing.expectError(error.BadFlag, decodeNeed(bad[0..wire.len]));
    @memcpy(bad[0..wire.len], wire);
    std.mem.writeInt(u64, bad[header_len..][0..8], 0, .little);
    try testing.expectError(error.ZeroRound, decodeNeed(bad[0..wire.len]));
}

test "mesh_digest_sync: send plan keeps mixed-version families independent" {
    // The peer knows only families 0..4 (an older build): families it does
    // not know are always sent whole; known matching families are skipped.
    var need = Need{ .round = 1, .known = 0b11111 };
    need.entries[0] = .{ .id = @backingInt(Family.mode_flags), .prev = null };
    need.len = 1;
    var plan: SendPlan = undefined;
    planFromNeed(&need, all_families, &plan);
    try testing.expect(plan.sends(.mode_flags));
    try testing.expect(!plan.sends(.membership));
    try testing.expect(!plan.sends(.mode_state));
    try testing.expect(!plan.sends(.channel_props));
    try testing.expect(!plan.sends(.entity_props));
    try testing.expect(plan.sends(.topics));
    try testing.expect(plan.sends(.keytrans));
    try testing.expectEqual(@as(FamilyMask, 0), plan.scoped);

    // A family the sender did not offer (could not digest) is always sent.
    planFromNeed(&need, all_families & ~Family.membership.bit(), &plan);
    try testing.expect(plan.sends(.membership));

    // Previous bucket roots are kept only for bucket-scoped families.
    var prev_bytes: [buckets_len]u8 = @splat(0x11);
    need.known = all_families;
    need.entries[0] = .{ .id = @backingInt(Family.topics), .prev = &prev_bytes };
    need.entries[1] = .{ .id = @backingInt(Family.wards), .prev = &prev_bytes };
    need.len = 2;
    planFromNeed(&need, all_families, &plan);
    try testing.expectEqual(Family.topics.bit() | Family.wards.bit(), plan.send);
    try testing.expectEqual(Family.topics.bit(), plan.scoped);
    try testing.expect(plan.prevFor(.wards) == null);
    try testing.expectEqualSlices(u8, &@as(Hash, @splat(0x11)), &plan.prevFor(.topics).?[5]);
}

test "mesh_digest_sync: row digests are order independent and one row localizes to one bucket" {
    const allocator = testing.allocator;
    var a = try Rows.init(allocator, .topics);
    defer a.deinit();
    var b = try Rows.init(allocator, .topics);
    defer b.deinit();
    var keys: [40][8]u8 = undefined;
    for (&keys, 0..) |*k, i| _ = std.fmt.bufPrint(k, "#c{d:0>6}", .{i}) catch unreachable;
    for (keys) |k| {
        var h = RowHasher.init(.topics);
        h.bytes(&k);
        try a.add(&k, 0, h.final());
    }
    var i: usize = keys.len;
    while (i > 0) {
        i -= 1;
        var h = RowHasher.init(.topics);
        h.bytes(&keys[i]);
        try b.add(&keys[i], 0, h.final());
    }
    const da = try a.finish();
    const db = try b.finish();
    try testing.expectEqualSlices(u8, &da.root, &db.root);
    try testing.expectEqual(@as(u64, 0), differingBuckets(&da.buckets, &db));

    var c = try Rows.init(allocator, .topics);
    defer c.deinit();
    for (keys, 0..) |k, j| {
        var h = RowHasher.init(.topics);
        h.bytes(&k);
        if (j == 17) h.bytes("changed");
        try c.add(&k, 0, h.final());
    }
    const dc = try c.finish();
    const mask = differingBuckets(&da.buckets, &dc);
    try testing.expectEqual(@as(u64, 1) << @intCast(bucketOf(.topics, &keys[17])), mask);

    var state = LinkState{ .active_family = .topics, .active_buckets = mask };
    try testing.expect(state.wantsRow(.topics, &keys[17]));
    try testing.expect(state.wantsRow(.mode_flags, &keys[3]));
    var skipped: usize = 0;
    for (keys) |k| {
        if (!state.wantsRow(.topics, &k)) skipped += 1;
    }
    try testing.expect(skipped > 0);
}

test "mesh_digest_sync: reflective row hash covers every field and separates adjacent ones" {
    const Sample = struct { a: []const u8, b: []const u8, n: ?u32, e: enum { x, y }, f: bool };
    const base = Sample{ .a = "ab", .b = "c", .n = 4, .e = .x, .f = false };
    var h0 = RowHasher.init(.access_entries);
    h0.any(base);
    const r0 = h0.final();
    const variants = [_]Sample{
        .{ .a = "a", .b = "bc", .n = 4, .e = .x, .f = false },
        .{ .a = "ab", .b = "c", .n = null, .e = .x, .f = false },
        .{ .a = "ab", .b = "c", .n = 5, .e = .x, .f = false },
        .{ .a = "ab", .b = "c", .n = 4, .e = .y, .f = false },
        .{ .a = "ab", .b = "c", .n = 4, .e = .x, .f = true },
    };
    for (variants) |v| {
        var h = RowHasher.init(.access_entries);
        h.any(v);
        try testing.expect(!std.mem.eql(u8, &r0, &h.final()));
    }
    // Family is part of the domain.
    var other = RowHasher.init(.wards);
    other.any(base);
    try testing.expect(!std.mem.eql(u8, &r0, &other.final()));
}

test "mesh_digest_sync: conflicting rows under one key fail closed" {
    var rows = try Rows.init(testing.allocator, .topics);
    defer rows.deinit();
    try rows.add("#a", 0, @splat(1));
    try rows.add("#a", 0, @splat(2));
    try testing.expectError(error.DuplicateRowKey, rows.finish());

    var same = try Rows.init(testing.allocator, .wards);
    defer same.deinit();
    try same.add("k", 0, @splat(3));
    try same.add("k", 0, @splat(3));
    const d = try same.finish();
    try testing.expectEqual(@as(u64, 1), d.entry_count);
}

test "mesh_digest_sync: row digest build is allocation-failure safe" {
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const allocator = failing.allocator();
        const result = blk: {
            var rows = Rows.init(allocator, .wards) catch |err| break :blk err;
            defer rows.deinit();
            for (0..8) |n| {
                var key: [4]u8 = undefined;
                std.mem.writeInt(u32, &key, @intCast(n), .little);
                rows.add(&key, n, @splat(@intCast(n))) catch |err| break :blk err;
            }
            _ = rows.finish() catch |err| break :blk err;
            break :blk {};
        };
        if (result) |_| break else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}
