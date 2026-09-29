// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper-action audit ring.
//!
//! A bounded, fixed-capacity ring that records structured oper actions —
//! `{ts, oper, action, target, reason, proof_id}` — so opers can review who did
//! what and correlate privileged actions with ProofMark evidence when available.
//!
//! This is intentionally distinct from the neighbouring subsystems:
//!   * `audit_trail.zig` is a generic actor/event string ring.
//!   * `proofmark.zig` produces signed cryptographic proofs.
//!   * the flight-recorder/tracelog captures execution traces.
//!
//! `OperAudit` is a plain, human-facing audit log of privileged actions.
//! The oldest entry is evicted when the ring is full. Each record owns its
//! `oper`, `target`, `reason`, and `proof_id` strings (duped from the allocator),
//! so the ring never aliases caller memory and frees everything on eviction/deinit.

const std = @import("std");
const proofmark = @import("proofmark.zig");

/// Classification of the privileged action being recorded.
///
/// `other` is the catch-all for actions that do not fit a named variant;
/// callers may still supply a descriptive `reason`.
pub const Action = enum {
    kill,
    kline,
    shun,
    jupe,
    mode,
    akill,
    unkline,
    gline,
    kick,
    oper_up,
    rehash,
    die,
    restart,
    ward_add,
    unshun,
    ward_del,
    connect,
    squit,
    redact,
    access_add,
    access_delete,
    access_clear,
    access_copy,
    forcejoin,
    forcepart,
    forceop,
    forcedeop,
    forcetopic,
    other,

    /// Stable lowercase label used when rendering audit lines.
    pub fn label(self: Action) []const u8 {
        return switch (self) {
            .kill => "kill",
            .kline => "kline",
            .shun => "shun",
            .jupe => "jupe",
            .mode => "mode",
            .akill => "akill",
            .unkline => "unkline",
            .gline => "gline",
            .kick => "kick",
            .oper_up => "oper_up",
            .rehash => "rehash",
            .die => "die",
            .restart => "restart",
            .ward_add => "ward_add",
            .unshun => "unshun",
            .ward_del => "ward_del",
            .connect => "connect",
            .squit => "squit",
            .redact => "redact",
            .access_add => "access_add",
            .access_delete => "access_delete",
            .access_clear => "access_clear",
            .access_copy => "access_copy",
            .forcejoin => "forcejoin",
            .forcepart => "forcepart",
            .forceop => "forceop",
            .forcedeop => "forcedeop",
            .forcetopic => "forcetopic",
            .other => "other",
        };
    }

    /// Stable ProofMark action code. Do not reorder when the enum grows.
    pub fn proofCode(self: Action) u8 {
        return switch (self) {
            .kill => 1,
            .kline => 2,
            .shun => 3,
            .jupe => 4,
            .mode => 5,
            .akill => 6,
            .unkline => 7,
            .gline => 8,
            .kick => 9,
            .oper_up => 10,
            .rehash => 11,
            .die => 12,
            .restart => 13,
            .ward_add => 14,
            .unshun => 15,
            .ward_del => 16,
            .connect => 17,
            .squit => 18,
            .redact => 19,
            .access_add => 20,
            .access_delete => 21,
            .access_clear => 22,
            .forcejoin => 23,
            .forcepart => 24,
            .forceop => 25,
            .forcedeop => 26,
            .forcetopic => 27,
            .access_copy => 28,
            .other => 255,
        };
    }

    pub fn fromProofCode(code: u8) ?Action {
        return switch (code) {
            1 => .kill,
            2 => .kline,
            3 => .shun,
            4 => .jupe,
            5 => .mode,
            6 => .akill,
            7 => .unkline,
            8 => .gline,
            9 => .kick,
            10 => .oper_up,
            11 => .rehash,
            12 => .die,
            13 => .restart,
            14 => .ward_add,
            15 => .unshun,
            16 => .ward_del,
            17 => .connect,
            18 => .squit,
            19 => .redact,
            20 => .access_add,
            21 => .access_delete,
            22 => .access_clear,
            23 => .forcejoin,
            24 => .forcepart,
            25 => .forceop,
            26 => .forcedeop,
            27 => .forcetopic,
            28 => .access_copy,
            255 => .other,
            else => null,
        };
    }
};

/// A single recorded oper action. Strings are owned by the ring.
pub const Entry = struct {
    /// Monotonic sequence number assigned at record time (starts at 1).
    seq: u64,
    /// Caller-supplied timestamp (milliseconds; semantics are caller's choice).
    ts: i64,
    /// Oper nick/identity that performed the action.
    oper: []u8,
    /// Classified action kind.
    action: Action,
    /// Target of the action (nick, mask, channel, ...). May be empty.
    target: []u8,
    /// Human-readable reason. May be empty.
    reason: []u8,
    /// Optional ProofMark id. Empty means this record was not cryptographically
    /// signed, usually because the node has no mesh signing key.
    proof_id: []u8,
    /// Optional detached ProofMark signature/public key in lowercase hex. Present
    /// only for records created through `recordWithProofEvidence`.
    proof_signature: []u8,
    proof_public_key: []u8,
    proof_reason_hash: proofmark.Digest = @splat(0),
    proof_policy_version: u32 = 0,
    proof_action: u8 = 0,
    proof_issued_ms: i64 = 0,
    proof_expiry_ms: i64 = 0,
    /// Link of the previous retained entry. Zeros only when this entry was the
    /// first record ever. Oldest-eviction leaves a non-zero prefix here; that
    /// prefix is not a break.
    chain_prev: proofmark.Digest = @splat(0),
};

pub const ProofEvidence = struct {
    id: []const u8,
    signature: []const u8,
    public_key: []const u8,
    reason_hash: proofmark.Digest,
    policy_version: u32,
    action: u8,
    issued_ms: i64,
    expiry_ms: i64,
};

/// Fixed-capacity, oldest-evicted ring of oper actions.
pub const OperAudit = struct {
    /// Maximum number of retained entries.
    pub const cap: usize = 512;

    allocator: std.mem.Allocator,
    slots: [cap]?Entry,
    /// Index of the oldest live entry.
    start: usize,
    /// Number of live entries (0..=cap).
    count: usize,
    /// Next sequence number to assign.
    next_seq: u64,
    /// BLAKE3 link of the newest entry, signed when `chain_sealed` is set.
    chain_head: proofmark.Digest = @splat(0),
    chain_sig: proofmark.Signature = @splat(0),
    chain_pubkey: proofmark.PublicKey = @splat(0),
    chain_sealed: bool = false,
    /// A blob that failed to decode. Later intact records stay untrusted
    /// until a successful `readChain` replaces this ring.
    chain_broken: bool = false,

    pub fn init(allocator: std.mem.Allocator) OperAudit {
        return .{
            .allocator = allocator,
            .slots = @as([cap]?Entry, @splat(null)),
            .start = 0,
            .count = 0,
            .next_seq = 1,
        };
    }

    pub fn deinit(self: *OperAudit) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.start + i) % cap;
            if (self.slots[idx]) |entry| {
                self.freeEntry(entry);
                self.slots[idx] = null;
            }
        }
        self.count = 0;
        self.start = 0;
    }

    fn freeEntry(self: *OperAudit, entry: Entry) void {
        self.allocator.free(entry.oper);
        self.allocator.free(entry.target);
        self.allocator.free(entry.reason);
        self.allocator.free(entry.proof_id);
        self.allocator.free(entry.proof_signature);
        self.allocator.free(entry.proof_public_key);
    }

    /// Record one oper action. Strings are duped into the ring. When the ring
    /// is full the oldest entry is evicted (and freed) first. Returns the
    /// sequence number assigned to the new entry.
    pub fn record(
        self: *OperAudit,
        ts: i64,
        oper: []const u8,
        action: Action,
        target: []const u8,
        reason: []const u8,
    ) !u64 {
        return self.recordWithProof(ts, oper, action, target, reason, "");
    }

    pub fn recordWithProof(
        self: *OperAudit,
        ts: i64,
        oper: []const u8,
        action: Action,
        target: []const u8,
        reason: []const u8,
        proof_id: []const u8,
    ) !u64 {
        return self.recordWithProofEvidence(ts, oper, action, target, reason, if (proof_id.len == 0) null else .{
            .id = proof_id,
            .signature = "",
            .public_key = "",
            .reason_hash = @splat(0),
            .policy_version = 0,
            .action = action.proofCode(),
            .issued_ms = ts,
            .expiry_ms = 0,
        });
    }

    pub fn recordWithProofEvidence(
        self: *OperAudit,
        ts: i64,
        oper: []const u8,
        action: Action,
        target: []const u8,
        reason: []const u8,
        proof: ?ProofEvidence,
    ) !u64 {
        const owned_oper = try self.allocator.dupe(u8, oper);
        errdefer self.allocator.free(owned_oper);

        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);

        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);

        const proof_id = if (proof) |p| p.id else "";
        const proof_signature = if (proof) |p| p.signature else "";
        const proof_public_key = if (proof) |p| p.public_key else "";

        const owned_proof = try self.allocator.dupe(u8, proof_id);
        errdefer self.allocator.free(owned_proof);

        const owned_signature = try self.allocator.dupe(u8, proof_signature);
        errdefer self.allocator.free(owned_signature);

        const owned_public_key = try self.allocator.dupe(u8, proof_public_key);
        errdefer self.allocator.free(owned_public_key);

        const chain_prev: proofmark.Digest = if (self.count == 0)
            @splat(0)
        else
            linkOf(self.at(self.count - 1).?);

        const seq = self.next_seq;
        // Saturate rather than overflow on an absurdly long-lived process.
        self.next_seq = std.math.add(u64, self.next_seq, 1) catch std.math.maxInt(u64);

        var idx: usize = undefined;
        if (self.count < cap) {
            idx = (self.start + self.count) % cap;
            self.count += 1;
        } else {
            // Full: evict oldest.
            idx = self.start;
            if (self.slots[idx]) |old| self.freeEntry(old);
            self.start = (self.start + 1) % cap;
        }

        self.slots[idx] = .{
            .seq = seq,
            .ts = ts,
            .oper = owned_oper,
            .action = action,
            .target = owned_target,
            .reason = owned_reason,
            .proof_id = owned_proof,
            .proof_signature = owned_signature,
            .proof_public_key = owned_public_key,
            .proof_reason_hash = if (proof) |p| p.reason_hash else @splat(0),
            .proof_policy_version = if (proof) |p| p.policy_version else 0,
            .proof_action = if (proof) |p| p.action else action.proofCode(),
            .proof_issued_ms = if (proof) |p| p.issued_ms else ts,
            .proof_expiry_ms = if (proof) |p| p.expiry_ms else 0,
            .chain_prev = chain_prev,
        };
        return seq;
    }

    /// Number of live entries.
    pub fn len(self: *const OperAudit) usize {
        return self.count;
    }

    /// Borrow the entry at logical position `i` (0 == oldest). Returns null
    /// when out of range. The returned pointer is owned by the ring.
    pub fn at(self: *const OperAudit, i: usize) ?*const Entry {
        if (i >= self.count) return null;
        const idx = (self.start + i) % cap;
        return &(self.slots[idx].?);
    }

    pub fn findByProofId(self: *const OperAudit, proof_id: []const u8) ?*const Entry {
        if (proof_id.len == 0) return null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const logical = self.count - 1 - i;
            const idx = (self.start + logical) % cap;
            const entry = &(self.slots[idx].?);
            if (std.mem.eql(u8, entry.proof_id, proof_id)) return entry;
        }
        return null;
    }

    /// Copy up to `n` of the most recent entries, newest-first, into a caller-
    /// owned slice. The `Entry` structs are shallow copies whose string fields
    /// still point into ring-owned memory; they remain valid only until those
    /// entries are evicted. Caller frees the returned slice with `allocator`.
    pub fn recent(self: *const OperAudit, allocator: std.mem.Allocator, n: usize) ![]Entry {
        const take = @min(n, self.count);
        const out = try allocator.alloc(Entry, take);
        var i: usize = 0;
        while (i < take) : (i += 1) {
            // newest is at logical index count-1; walk backwards.
            const logical = self.count - 1 - i;
            const idx = (self.start + logical) % cap;
            out[i] = self.slots[idx].?;
        }
        return out;
    }

    /// Copy up to `n` of the most recent entries performed by `oper`
    /// (exact match), newest-first. Same ownership/lifetime notes as `recent`.
    pub fn filterByOper(
        self: *const OperAudit,
        allocator: std.mem.Allocator,
        oper: []const u8,
        n: usize,
    ) ![]Entry {
        var list: std.ArrayList(Entry) = .empty;
        errdefer list.deinit(allocator);

        var i: usize = 0;
        while (i < self.count and list.items.len < n) : (i += 1) {
            const logical = self.count - 1 - i; // newest-first
            const idx = (self.start + logical) % cap;
            const entry = self.slots[idx].?;
            if (std.mem.eql(u8, entry.oper, oper)) {
                try list.append(allocator, entry);
            }
        }
        return list.toOwnedSlice(allocator);
    }

    /// Render up to `n` most recent entries (newest-first) as a multi-line
    /// text block suitable for an oper-only audit reply. Each line has the
    /// form: `#<seq> ts=<ts> <oper> <action> <target> :<reason>`. Empty
    /// `target` is rendered as `*`; empty `reason` omits the trailing field.
    /// Caller frees the returned buffer with `allocator`.
    pub fn render(self: *const OperAudit, allocator: std.mem.Allocator, n: usize) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        const take = @min(n, self.count);
        var i: usize = 0;
        while (i < take) : (i += 1) {
            const logical = self.count - 1 - i; // newest-first
            const idx = (self.start + logical) % cap;
            const e = self.slots[idx].?;
            const target = if (e.target.len == 0) "*" else e.target;
            if (e.reason.len == 0) {
                if (e.proof_id.len != 0) {
                    try buf.print(allocator, "#{d} ts={d} {s} {s} {s} proof={s}\n", .{
                        e.seq, e.ts, e.oper, e.action.label(), target, e.proof_id,
                    });
                } else {
                    try buf.print(allocator, "#{d} ts={d} {s} {s} {s}\n", .{
                        e.seq, e.ts, e.oper, e.action.label(), target,
                    });
                }
            } else {
                if (e.proof_id.len != 0) {
                    try buf.print(allocator, "#{d} ts={d} {s} {s} {s} proof={s} :{s}\n", .{
                        e.seq, e.ts, e.oper, e.action.label(), target, e.proof_id, e.reason,
                    });
                } else {
                    try buf.print(allocator, "#{d} ts={d} {s} {s} {s} :{s}\n", .{
                        e.seq, e.ts, e.oper, e.action.label(), target, e.reason,
                    });
                }
            }
        }
        return buf.toOwnedSlice(allocator);
    }

    pub fn chainHead(self: *const OperAudit) ?proofmark.Digest {
        if (self.count == 0) return null;
        return linkOf(self.at(self.count - 1).?);
    }

    pub fn seal(self: *OperAudit, head: proofmark.Digest, signature: proofmark.Signature, public_key: proofmark.PublicKey) void {
        self.chain_head = head;
        self.chain_sig = signature;
        self.chain_pubkey = public_key;
        self.chain_sealed = true;
    }

    pub fn markChainBroken(self: *OperAudit) void {
        self.chain_broken = true;
    }

    /// Intact only when every retained link matches and `node_public_key`
    /// signed the head. A missing seal, a different key, or a removed entry
    /// is broken. An empty unsealed ring is empty.
    pub fn chainStatus(self: *const OperAudit, node_public_key: proofmark.PublicKey) ChainStatus {
        if (self.chain_broken) return .broken;
        if (self.count == 0) return if (self.chain_sealed) .broken else .empty;
        var i: usize = 1;
        while (i < self.count) : (i += 1) {
            const prev = self.at(i - 1).?;
            const cur = self.at(i).?;
            const expect = linkOf(prev);
            if (!std.mem.eql(u8, &cur.chain_prev, &expect)) return .broken;
        }
        if (!self.chain_sealed) return .broken;
        const head = linkOf(self.at(self.count - 1).?);
        if (!std.mem.eql(u8, &head, &self.chain_head)) return .broken;
        if (!std.mem.eql(u8, &self.chain_pubkey, &node_public_key)) return .broken;
        if (!verifyChainSeal(self.chain_head, self.chain_sig, self.chain_pubkey)) return .broken;
        return .intact;
    }

    pub fn writeChain(self: *const OperAudit, allocator: std.mem.Allocator) ChainError![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        try buf.appendSlice(allocator, chain_magic);
        try buf.append(allocator, chain_version);
        try buf.append(allocator, if (self.chain_sealed) 1 else 0);
        try appendInt(&buf, allocator, u16, @intCast(self.count));
        try appendInt(&buf, allocator, u64, self.next_seq);
        try buf.appendSlice(allocator, &self.chain_head);
        try buf.appendSlice(allocator, &self.chain_sig);
        try buf.appendSlice(allocator, &self.chain_pubkey);
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            try appendEntry(&buf, allocator, self.at(i).?);
        }
        return buf.toOwnedSlice(allocator);
    }

    pub fn readChain(self: *OperAudit, blob: []const u8) ChainError!void {
        const loaded = try self.allocator.create(OperAudit);
        errdefer self.allocator.destroy(loaded);
        loaded.* = OperAudit.init(self.allocator);
        errdefer loaded.deinit();
        try decodeInto(loaded, blob);
        self.deinit();
        const moved = loaded.*;
        self.allocator.destroy(loaded);
        self.* = moved;
    }
};

pub const chain_store_key = "pm1:chain";
pub const chain_head_domain = "onyx-proof-chain-head-v1";
pub const chain_head_message_len: usize = chain_head_domain.len + 32;

pub const ChainStatus = enum { empty, intact, broken };

pub const ChainError = error{
    Truncated,
    Corrupt,
    StringTooLong,
    OutOfRange,
} || std.mem.Allocator.Error;

const chain_magic = "PM1CHAIN";
const chain_version: u8 = 1;

pub fn chainHeadMessage(head: proofmark.Digest) [chain_head_message_len]u8 {
    var out: [chain_head_message_len]u8 = undefined;
    @memcpy(out[0..chain_head_domain.len], chain_head_domain);
    @memcpy(out[chain_head_domain.len..], &head);
    return out;
}

pub fn verifyChainSeal(head: proofmark.Digest, signature: proofmark.Signature, public_key: proofmark.PublicKey) bool {
    const msg = chainHeadMessage(head);
    const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verifyStrict(&msg, pk) catch return false;
    return true;
}

/// Rebuild `blob` without the entry at `index`. Links and the signed head
/// stay as they were, so a later read reports a broken chain.
pub fn omitEncodedEntry(allocator: std.mem.Allocator, blob: []const u8, index: usize) ChainError![]u8 {
    var src = OperAudit.init(allocator);
    defer src.deinit();
    try src.readChain(blob);
    if (index >= src.count) return error.OutOfRange;
    var dst = OperAudit.init(allocator);
    defer dst.deinit();
    var i: usize = 0;
    while (i < src.count) : (i += 1) {
        if (i == index) continue;
        try copyEntry(&dst, src.at(i).?);
    }
    dst.next_seq = src.next_seq;
    dst.chain_head = src.chain_head;
    dst.chain_sig = src.chain_sig;
    dst.chain_pubkey = src.chain_pubkey;
    dst.chain_sealed = src.chain_sealed;
    return dst.writeChain(allocator);
}

fn linkOf(entry: *const Entry) proofmark.Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("onyx-proof-chain-v1");
    var seq_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_buf, entry.seq, .little);
    hasher.update(&seq_buf);
    var len_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_buf, @as(u64, entry.proof_id.len), .little);
    hasher.update(&len_buf);
    hasher.update(entry.proof_id);
    hasher.update(&entry.chain_prev);
    var out: proofmark.Digest = undefined;
    hasher.final(&out);
    return out;
}

fn copyEntry(self: *OperAudit, src: *const Entry) ChainError!void {
    const oper = try self.allocator.dupe(u8, src.oper);
    errdefer self.allocator.free(oper);
    const target = try self.allocator.dupe(u8, src.target);
    errdefer self.allocator.free(target);
    const reason = try self.allocator.dupe(u8, src.reason);
    errdefer self.allocator.free(reason);
    const proof_id = try self.allocator.dupe(u8, src.proof_id);
    errdefer self.allocator.free(proof_id);
    const proof_signature = try self.allocator.dupe(u8, src.proof_signature);
    errdefer self.allocator.free(proof_signature);
    const proof_public_key = try self.allocator.dupe(u8, src.proof_public_key);
    errdefer self.allocator.free(proof_public_key);
    if (self.count >= OperAudit.cap) return error.Corrupt;
    const idx = (self.start + self.count) % OperAudit.cap;
    self.slots[idx] = .{
        .seq = src.seq,
        .ts = src.ts,
        .oper = oper,
        .action = src.action,
        .target = target,
        .reason = reason,
        .proof_id = proof_id,
        .proof_signature = proof_signature,
        .proof_public_key = proof_public_key,
        .proof_reason_hash = src.proof_reason_hash,
        .proof_policy_version = src.proof_policy_version,
        .proof_action = src.proof_action,
        .proof_issued_ms = src.proof_issued_ms,
        .proof_expiry_ms = src.proof_expiry_ms,
        .chain_prev = src.chain_prev,
    };
    self.count += 1;
}

fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var tmp: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &tmp, value, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendStr(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) !void {
    if (bytes.len > std.math.maxInt(u16)) return error.StringTooLong;
    try appendInt(buf, allocator, u16, @intCast(bytes.len));
    try buf.appendSlice(allocator, bytes);
}

fn appendEntry(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, entry: *const Entry) !void {
    try appendInt(buf, allocator, u64, entry.seq);
    try appendInt(buf, allocator, u64, @bitCast(entry.ts));
    try buf.append(allocator, entry.action.proofCode());
    try buf.appendSlice(allocator, &entry.proof_reason_hash);
    try appendInt(buf, allocator, u32, entry.proof_policy_version);
    try buf.append(allocator, entry.proof_action);
    try appendInt(buf, allocator, u64, @bitCast(entry.proof_issued_ms));
    try appendInt(buf, allocator, u64, @bitCast(entry.proof_expiry_ms));
    try buf.appendSlice(allocator, &entry.chain_prev);
    try appendStr(buf, allocator, entry.oper);
    try appendStr(buf, allocator, entry.target);
    try appendStr(buf, allocator, entry.reason);
    try appendStr(buf, allocator, entry.proof_id);
    try appendStr(buf, allocator, entry.proof_signature);
    try appendStr(buf, allocator, entry.proof_public_key);
}

fn decodeInto(self: *OperAudit, blob: []const u8) ChainError!void {
    var pos: usize = 0;
    if (blob.len < chain_magic.len + 1 + 1 + 2 + 8 + 32 + 64 + 32) return error.Truncated;
    if (!std.mem.eql(u8, blob[0..chain_magic.len], chain_magic)) return error.Corrupt;
    pos = chain_magic.len;
    if (blob[pos] != chain_version) return error.Corrupt;
    pos += 1;
    const flags = blob[pos];
    pos += 1;
    if (flags > 1) return error.Corrupt;
    const count = try readInt(u16, blob, &pos);
    if (count > OperAudit.cap) return error.Corrupt;
    const next_seq = try readInt(u64, blob, &pos);
    self.chain_head = try readArray(32, blob, &pos);
    self.chain_sig = try readArray(64, blob, &pos);
    self.chain_pubkey = try readArray(32, blob, &pos);
    self.chain_sealed = flags == 1;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try decodeEntry(self, blob, &pos);
    }
    if (pos != blob.len) return error.Corrupt;
    if (count > 0) {
        const newest = self.at(count - 1).?;
        if (newest.seq != std.math.maxInt(u64) and next_seq <= newest.seq) return error.Corrupt;
    }
    self.next_seq = next_seq;
}

fn decodeEntry(self: *OperAudit, blob: []const u8, pos: *usize) ChainError!void {
    const seq = try readInt(u64, blob, pos);
    const ts: i64 = @bitCast(try readInt(u64, blob, pos));
    if (pos.* >= blob.len) return error.Truncated;
    const action_code = blob[pos.*];
    pos.* += 1;
    const action = Action.fromProofCode(action_code) orelse return error.Corrupt;
    const reason_hash = try readArray(32, blob, pos);
    const policy = try readInt(u32, blob, pos);
    if (pos.* >= blob.len) return error.Truncated;
    const proof_action = blob[pos.*];
    pos.* += 1;
    const issued: i64 = @bitCast(try readInt(u64, blob, pos));
    const expiry: i64 = @bitCast(try readInt(u64, blob, pos));
    const chain_prev = try readArray(32, blob, pos);
    const oper = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(oper);
    const target = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(target);
    const reason = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(reason);
    const proof_id = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(proof_id);
    const proof_signature = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(proof_signature);
    const proof_public_key = try readStr(self.allocator, blob, pos);
    errdefer self.allocator.free(proof_public_key);
    if (self.count >= OperAudit.cap) return error.Corrupt;
    const idx = (self.start + self.count) % OperAudit.cap;
    self.slots[idx] = .{
        .seq = seq,
        .ts = ts,
        .oper = oper,
        .action = action,
        .target = target,
        .reason = reason,
        .proof_id = proof_id,
        .proof_signature = proof_signature,
        .proof_public_key = proof_public_key,
        .proof_reason_hash = reason_hash,
        .proof_policy_version = policy,
        .proof_action = proof_action,
        .proof_issued_ms = issued,
        .proof_expiry_ms = expiry,
        .chain_prev = chain_prev,
    };
    self.count += 1;
}

fn readInt(comptime T: type, blob: []const u8, pos: *usize) ChainError!T {
    if (pos.* + @sizeOf(T) > blob.len) return error.Truncated;
    const value = std.mem.readInt(T, blob[pos.*..][0..@sizeOf(T)], .little);
    pos.* += @sizeOf(T);
    return value;
}

fn readArray(comptime n: usize, blob: []const u8, pos: *usize) ChainError![n]u8 {
    if (pos.* + n > blob.len) return error.Truncated;
    var out: [n]u8 = undefined;
    @memcpy(&out, blob[pos.*..][0..n]);
    pos.* += n;
    return out;
}

fn readStr(allocator: std.mem.Allocator, blob: []const u8, pos: *usize) ChainError![]u8 {
    const n = try readInt(u16, blob, pos);
    if (pos.* + n > blob.len) return error.Truncated;
    const out = try allocator.dupe(u8, blob[pos.*..][0..n]);
    pos.* += n;
    return out;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

test "record assigns increasing seq and grows count" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    try testing.expectEqual(@as(u64, 1), try audit.record(100, "alice", .kill, "bob", "spam"));
    try testing.expectEqual(@as(u64, 2), try audit.record(101, "alice", .kline, "1.2.3.4", "abuse"));
    try testing.expectEqual(@as(usize, 2), audit.len());
}

test "recordWithProof stores proof id" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    const proof = "0123456789abcdef";
    try testing.expectEqual(@as(u64, 1), try audit.recordWithProof(100, "alice", .kill, "bob", "spam", proof));
    const entry = audit.at(0).?;
    try testing.expectEqualStrings(proof, entry.proof_id);

    const out = try audit.render(testing.allocator, 1);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, " proof=0123456789abcdef ") != null);
}

test "recordWithProofEvidence stores inspectable proof material" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    const reason_hash: proofmark.Digest = @splat(0xab);
    const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const sig = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const public_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    try testing.expectEqual(@as(u64, 1), try audit.recordWithProofEvidence(100, "alice", .kline, "*@bad", "abuse", .{
        .id = id,
        .signature = sig,
        .public_key = public_key,
        .reason_hash = reason_hash,
        .policy_version = 7,
        .action = 2,
        .issued_ms = 100,
        .expiry_ms = 200,
    }));

    const entry = audit.findByProofId(id).?;
    try testing.expectEqualStrings(sig, entry.proof_signature);
    try testing.expectEqualStrings(public_key, entry.proof_public_key);
    try testing.expectEqualSlices(u8, &reason_hash, &entry.proof_reason_hash);
    try testing.expectEqual(@as(u32, 7), entry.proof_policy_version);
    try testing.expectEqual(@as(u8, 2), entry.proof_action);
    try testing.expect(audit.findByProofId("missing") == null);
}

test "ring evicts oldest when over capacity" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    const total = OperAudit.cap + 50;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const oper = try std.fmt.bufPrint(&name_buf, "op{d}", .{i});
        _ = try audit.record(@intCast(i), oper, .mode, "#chan", "");
    }

    // Count is capped.
    try testing.expectEqual(OperAudit.cap, audit.len());

    // Oldest live entry should be the (total-cap)th recorded, seq = 51.
    const oldest = audit.at(0).?;
    try testing.expectEqual(@as(u64, total - OperAudit.cap + 1), oldest.seq);

    // Newest live entry seq = total.
    const newest = audit.at(audit.len() - 1).?;
    try testing.expectEqual(@as(u64, total), newest.seq);
}

test "recent returns newest-first and clamps n" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "a", .kill, "t1", "r1");
    _ = try audit.record(2, "b", .kline, "t2", "r2");
    _ = try audit.record(3, "c", .shun, "t3", "r3");

    const out = try audit.recent(testing.allocator, 10);
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqual(@as(u64, 3), out[0].seq); // newest first
    try testing.expectEqual(@as(u64, 2), out[1].seq);
    try testing.expectEqual(@as(u64, 1), out[2].seq);
    try testing.expect(std.mem.eql(u8, out[0].oper, "c"));
}

test "recent with n smaller than count" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "a", .kill, "t1", "r1");
    _ = try audit.record(2, "b", .kline, "t2", "r2");
    _ = try audit.record(3, "c", .shun, "t3", "r3");

    const out = try audit.recent(testing.allocator, 2);
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqual(@as(u64, 3), out[0].seq);
    try testing.expectEqual(@as(u64, 2), out[1].seq);
}

test "filterByOper matches only the named oper, newest-first" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "alice", .kill, "x", "");
    _ = try audit.record(2, "bob", .kline, "y", "");
    _ = try audit.record(3, "alice", .shun, "z", "");
    _ = try audit.record(4, "bob", .jupe, "w", "");
    _ = try audit.record(5, "alice", .mode, "v", "");

    const out = try audit.filterByOper(testing.allocator, "alice", 100);
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 3), out.len);
    try testing.expectEqual(@as(u64, 5), out[0].seq);
    try testing.expectEqual(@as(u64, 3), out[1].seq);
    try testing.expectEqual(@as(u64, 1), out[2].seq);
}

test "filterByOper respects limit n" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "alice", .kill, "x", "");
    _ = try audit.record(2, "alice", .kline, "y", "");
    _ = try audit.record(3, "alice", .shun, "z", "");

    const out = try audit.filterByOper(testing.allocator, "alice", 2);
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqual(@as(u64, 3), out[0].seq);
    try testing.expectEqual(@as(u64, 2), out[1].seq);
}

test "filterByOper with no matches returns empty slice" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "alice", .kill, "x", "y");

    const out = try audit.filterByOper(testing.allocator, "nobody", 10);
    defer testing.allocator.free(out);

    try testing.expectEqual(@as(usize, 0), out.len);
}

test "render produces newest-first lines with action labels" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(100, "alice", .kill, "bob", "spam");
    _ = try audit.record(101, "carol", .kline, "1.2.3.4", "abuse");

    const out = try audit.render(testing.allocator, 10);
    defer testing.allocator.free(out);

    const expected =
        "#2 ts=101 carol kline 1.2.3.4 :abuse\n" ++
        "#1 ts=100 alice kill bob :spam\n";
    try testing.expectEqualStrings(expected, out);
}

test "render handles empty target and empty reason" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(5, "dave", .rehash, "", "");

    const out = try audit.render(testing.allocator, 10);
    defer testing.allocator.free(out);

    try testing.expectEqualStrings("#1 ts=5 dave rehash *\n", out);
}

test "render clamps to n entries" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    _ = try audit.record(1, "a", .kill, "t1", "r1");
    _ = try audit.record(2, "b", .kline, "t2", "r2");
    _ = try audit.record(3, "c", .shun, "t3", "r3");

    const out = try audit.render(testing.allocator, 1);
    defer testing.allocator.free(out);

    try testing.expectEqualStrings("#3 ts=3 c shun t3 :r3\n", out);
}

test "empty ring renders to empty string and recent is empty" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    const out = try audit.render(testing.allocator, 5);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 0), out.len);

    const r = try audit.recent(testing.allocator, 5);
    defer testing.allocator.free(r);
    try testing.expectEqual(@as(usize, 0), r.len);
}

test "no leaks after eviction churn (allocator-checked)" {
    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();

    var i: usize = 0;
    while (i < OperAudit.cap * 3) : (i += 1) {
        _ = try audit.record(@intCast(i), "oper", .akill, "target", "reason text");
    }
    // testing.allocator asserts no leaks at scope end via deinit.
    try testing.expectEqual(OperAudit.cap, audit.len());
}

test "action labels round-trip" {
    try testing.expectEqualStrings("kill", Action.kill.label());
    try testing.expectEqualStrings("akill", Action.akill.label());
    try testing.expectEqualStrings("other", Action.other.label());
}

test "GAP-K3 a removed entry breaks the signed proof chain" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x51)));
    const pk = kp.public_key.toBytes();
    var empty = OperAudit.init(testing.allocator);
    defer empty.deinit();
    try testing.expect(empty.chainStatus(pk) == .empty);

    var audit = OperAudit.init(testing.allocator);
    defer audit.deinit();
    _ = try audit.record(1, "op", .kline, "*@spam", "flood");
    _ = try audit.record(2, "op", .kick, "nick", "flood");
    _ = try audit.record(3, "op", .shun, "bad", "flood");
    const head = audit.chainHead().?;
    const msg = chainHeadMessage(head);
    const sig = try kp.sign(&msg, null);
    audit.seal(head, sig.toBytes(), pk);
    try testing.expect(audit.chainStatus(pk) == .intact);

    const blob = try audit.writeChain(testing.allocator);
    defer testing.allocator.free(blob);
    var restored = OperAudit.init(testing.allocator);
    defer restored.deinit();
    try restored.readChain(blob);
    try testing.expectEqual(@as(usize, 3), restored.len());
    try testing.expect(restored.chainStatus(pk) == .intact);
    const other = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x52)));
    try testing.expect(restored.chainStatus(other.public_key.toBytes()) == .broken);

    const middle = try omitEncodedEntry(testing.allocator, blob, 1);
    defer testing.allocator.free(middle);
    var broken = OperAudit.init(testing.allocator);
    defer broken.deinit();
    try broken.readChain(middle);
    try testing.expectEqual(@as(usize, 2), broken.len());
    try testing.expect(broken.chainStatus(pk) == .broken);

    const tail = try omitEncodedEntry(testing.allocator, blob, 2);
    defer testing.allocator.free(tail);
    var tailless = OperAudit.init(testing.allocator);
    defer tailless.deinit();
    try tailless.readChain(tail);
    try testing.expectEqual(@as(usize, 2), tailless.len());
    try testing.expect(tailless.chainStatus(pk) == .broken);

    var full = OperAudit.init(testing.allocator);
    defer full.deinit();
    var i: usize = 0;
    while (i < OperAudit.cap + 3) : (i += 1) {
        _ = try full.record(@intCast(i), "op", .kline, "t", "r");
    }
    const full_head = full.chainHead().?;
    const full_msg = chainHeadMessage(full_head);
    const full_sig = try kp.sign(&full_msg, null);
    full.seal(full_head, full_sig.toBytes(), pk);
    try testing.expect(full.chainStatus(pk) == .intact);
    try testing.expect(full.at(0).?.seq != 1);
}
