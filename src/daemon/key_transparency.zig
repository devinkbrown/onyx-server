// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Node-local observational history for account credential facts.
//!
//! This log records that this node observed a bind or delete of a credential
//! identifier. Event digests are appended to a Merkle Mountain Range so a
//! caller can return inclusion proofs for a leaf/root/size tuple. The service
//! layer owns when observations are emitted; this module owns stable hashing,
//! the versioned event codec, retained immutable bodies, and proof verification.
//!
//! Until durable PROP state exists, this log is not current device or identity
//! state, not an E2EE binding oracle, and not a cryptographic consistency
//! proof. A DEVICE/EVENT result is the latest observation on this node. A
//! CONSISTENCY result is a durable checkpoint comparison (`scheme=
//! checkpoint-comparison`). Inclusion proofs show a leaf was recorded here;
//! they do not assert that a key is honest, live, or operator-endorsed.

const std = @import("std");
const mmr = @import("../substrate/merkle_mountain_range.zig");

const Blake3 = std.crypto.hash.Blake3;

pub const Hash = [Blake3.digest_length]u8;

/// Codec version stored with every durable/in-memory body. The digest domain
/// stays `ONYX-KT-EVENT-v1` so existing inclusion proofs remain verifiable.
pub const codec_version: u8 = 1;

/// Matches `services.account_max` so server-derived canonical accounts fit.
pub const max_account_len: usize = 32;
/// Covers certfp hex (64), OGC1 device ids (27), identity labels (32), and
/// WebAuthn credential-id base64url (≤ 344, bounded here to 256).
pub const max_key_id_len: usize = 256;
pub const max_encoded_len: usize = 1 + 1 + 1 + 2 + max_account_len + 2 + max_key_id_len + 32 + 8 + 32;

pub const CredentialKind = enum(u8) {
    certfp = 1,
    webauthn = 2,
    e2ee_device = 3,
    identity = 4,

    pub fn wireName(self: CredentialKind) []const u8 {
        return switch (self) {
            .certfp => "certfp",
            .webauthn => "webauthn",
            .e2ee_device => "e2ee_device",
            .identity => "identity",
        };
    }

    pub fn fromInt(value: u8) ?CredentialKind {
        return std.enums.fromInt(CredentialKind, value);
    }
};

pub const Action = enum(u8) {
    bind = 1,
    delete = 2,

    pub fn wireName(self: Action) []const u8 {
        return switch (self) {
            .bind => "bind",
            .delete => "delete",
        };
    }

    pub fn fromInt(value: u8) ?Action {
        return std.enums.fromInt(Action, value);
    }
};

pub const Event = struct {
    account: []const u8,
    kind: CredentialKind,
    action: Action,
    /// Stable credential identifier: certfp hex for CERTADD, credential-id b64
    /// for WebAuthn, device id for E2EE, identity label for IDENTITY.
    key_id: []const u8,
    /// Hash of the credential material. For certfp this is BLAKE3(certfp); for
    /// WebAuthn this is BLAKE3(raw COSE public key). Deletes may reuse key_id.
    key_hash: Hash,
    timestamp_ms: i64 = 0,
};

/// Fixed-size owned body. ArrayList realloc cannot dangle these fields.
pub const OwnedEvent = struct {
    account_buf: [max_account_len]u8 = undefined,
    account_len: u8 = 0,
    kind: CredentialKind = .certfp,
    action: Action = .bind,
    key_id_buf: [max_key_id_len]u8 = undefined,
    key_id_len: u16 = 0,
    key_hash: Hash = @splat(0),
    timestamp_ms: i64 = 0,
    leaf: Hash = @splat(0),

    pub fn account(self: *const OwnedEvent) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn keyId(self: *const OwnedEvent) []const u8 {
        return self.key_id_buf[0..self.key_id_len];
    }

    pub fn asEvent(self: *const OwnedEvent) Event {
        return .{
            .account = self.account(),
            .kind = self.kind,
            .action = self.action,
            .key_id = self.keyId(),
            .key_hash = self.key_hash,
            .timestamp_ms = self.timestamp_ms,
        };
    }

    pub fn eql(self: *const OwnedEvent, other: *const OwnedEvent) bool {
        return self.kind == other.kind and
            self.action == other.action and
            self.timestamp_ms == other.timestamp_ms and
            std.mem.eql(u8, self.account(), other.account()) and
            std.mem.eql(u8, self.keyId(), other.keyId()) and
            std.mem.eql(u8, &self.key_hash, &other.key_hash) and
            std.mem.eql(u8, &self.leaf, &other.leaf);
    }
};

pub const AppendResult = struct {
    position: usize,
    size: usize,
    root: mmr.Hash,
    leaf: mmr.Hash,
    /// True when the exact event digest was already present. Replay must not
    /// grow the observational log.
    duplicate: bool = false,
};

pub const CodecError = error{
    InvalidVersion,
    InvalidKind,
    InvalidAction,
    InvalidAccount,
    InvalidKeyId,
    InvalidLeaf,
    Truncated,
    TrailingBytes,
    BufferTooSmall,
};

/// Latest observed action for one (account, kind, key_id). This is not
/// current, authoritative, or bound device/identity state.
pub const ObservedAction = Action;

/// Durable checkpoint fields needed for an O(1) observational comparison.
/// `root` and `last_leaf` come from `kt1:c:<size>`; this is not a compact
/// MMR consistency proof.
pub const FrozenPrefix = struct {
    root: Hash,
    last_leaf: Hash,
};

pub const PrefixStatus = enum {
    match,
    mismatch,
};

pub const PrefixComparison = struct {
    old_size: usize,
    old_root: Hash,
    size: usize,
    root: Hash,
    /// Exact durable-checkpoint comparison. Never a cryptographic
    /// consistency proof.
    prefix: PrefixStatus,
};

pub const ConsistencyError = error{
    SizeAhead,
    Unavailable,
    UnknownCheckpoint,
    Corrupt,
    OutOfMemory,
};

/// Domain for a remote/local tombstone observation when deleted material is
/// not on the wire. The hash identifies the fact, it does not invent current
/// credential state.
pub const fact_tombstone_domain = "ONYX-KT-FACT-TOMBSTONE-v1";

/// Domain for an accepted external fact's exact identity. Bind and delete
/// both hash action + canonical material/tombstone + HLC + origin. Account,
/// kind, and key_id are framed here and again on the outer event.
pub const fact_identity_domain = "ONYX-KT-FACT-ID-v1";

pub const FactIdentity = struct {
    account: []const u8,
    kind: CredentialKind,
    action: Action = .bind,
    key_id: []const u8,
    hlc: u64,
    origin_node: u64,
    origin_pubkey: []const u8 = &.{},
};

pub fn observationTimestampMs(hlc: u64) i64 {
    return @intCast(@min(hlc, std.math.maxInt(i64)));
}

pub fn factTombstoneHash(id: FactIdentity) Hash {
    var h = Blake3.init(.{});
    h.update(fact_tombstone_domain);
    updateInt(u8, &h, @intFromEnum(id.kind));
    updateBytes(&h, id.account);
    updateBytes(&h, id.key_id);
    updateInt(u64, &h, id.hlc);
    updateInt(u64, &h, id.origin_node);
    updateBytes(&h, id.origin_pubkey);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

/// Canonical material or tombstone bytes that `factIdentityHash` binds.
pub fn factCanonicalHash(id: FactIdentity, material: []const u8) Hash {
    if (id.action == .delete) return factTombstoneHash(id);
    return materialHash(material);
}

/// Exact identity of an accepted external fact. Same action + material +
/// HLC + origin replay to the same digest; a different origin appends.
pub fn factIdentityHash(id: FactIdentity, canonical: Hash) Hash {
    var h = Blake3.init(.{});
    h.update(fact_identity_domain);
    updateInt(u8, &h, @intFromEnum(id.action));
    h.update(&canonical);
    updateInt(u64, &h, id.hlc);
    updateInt(u64, &h, id.origin_node);
    updateBytes(&h, id.origin_pubkey);
    updateInt(u8, &h, @intFromEnum(id.kind));
    updateBytes(&h, id.account);
    updateBytes(&h, id.key_id);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

pub fn factObservationHash(id: FactIdentity, material: []const u8) Hash {
    return factIdentityHash(id, factCanonicalHash(id, material));
}

pub fn emptyLogRoot() Hash {
    var empty = mmr.MerkleMountainRange.init(undefined);
    return empty.root();
}

pub const KeyTransparencyLog = struct {
    tree: mmr.MerkleMountainRange,
    events: std.ArrayList(OwnedEvent) = .empty,
    latest: std.StringHashMap(usize),
    /// Exact event-digest → position. Replay/burst identity is the digest of
    /// the canonical event bytes, not local arrival time.
    digests: std.AutoHashMap(Hash, usize),
    /// Set when durable restore failed. Append and query stay fail-closed.
    unusable: bool = false,

    pub fn init(allocator: std.mem.Allocator) KeyTransparencyLog {
        return .{
            .tree = mmr.MerkleMountainRange.init(allocator),
            .latest = std.StringHashMap(usize).init(allocator),
            .digests = std.AutoHashMap(Hash, usize).init(allocator),
        };
    }

    pub fn deinit(self: *KeyTransparencyLog) void {
        self.clearLatest();
        self.latest.deinit();
        self.digests.deinit();
        self.events.deinit(self.mem());
        self.tree.deinit();
        self.* = undefined;
    }

    fn mem(self: *const KeyTransparencyLog) std.mem.Allocator {
        return self.tree.allocator;
    }

    pub fn len(self: *const KeyTransparencyLog) usize {
        return self.tree.len();
    }

    pub fn root(self: *const KeyTransparencyLog) mmr.Hash {
        return self.tree.root();
    }

    /// Drop in-memory bodies and the MMR so a restore can rebuild exactly.
    /// Does not clear `unusable`.
    pub fn reset(self: *KeyTransparencyLog) void {
        self.clearLatest();
        self.events.clearRetainingCapacity();
        self.tree.leaves.clearRetainingCapacity();
        self.digests.clearRetainingCapacity();
    }

    pub fn hasDigest(self: *const KeyTransparencyLog, leaf: Hash) bool {
        return self.digests.contains(leaf);
    }

    fn clearLatest(self: *KeyTransparencyLog) void {
        var it = self.latest.iterator();
        while (it.next()) |entry| {
            self.mem().free(entry.key_ptr.*);
        }
        self.latest.clearRetainingCapacity();
    }

    pub fn append(self: *KeyTransparencyLog, event: Event) !AppendResult {
        if (self.unusable) return error.Unavailable;
        const owned = try ownedFromEvent(event);
        return self.appendOwned(owned);
    }

    pub fn appendOwned(self: *KeyTransparencyLog, owned: OwnedEvent) !AppendResult {
        if (self.unusable) return error.Unavailable;
        if (self.digests.get(owned.leaf)) |pos| {
            return .{
                .position = pos,
                .size = self.tree.len(),
                .root = self.tree.root(),
                .leaf = owned.leaf,
                .duplicate = true,
            };
        }
        const alloc = self.mem();
        try self.events.ensureUnusedCapacity(alloc, 1);
        try self.tree.leaves.ensureUnusedCapacity(alloc, 1);
        try self.digests.ensureUnusedCapacity(1);

        var index_buf: [max_index_key_len]u8 = undefined;
        const index_key = writeIndexKey(&index_buf, owned.account(), owned.kind, owned.keyId());
        const existing = self.latest.getPtr(index_key);

        var owned_key: ?[]u8 = null;
        if (existing == null) {
            owned_key = try alloc.dupe(u8, index_key);
        }
        errdefer if (owned_key) |key| alloc.free(key);

        if (owned_key) |key| {
            try self.latest.put(key, 0);
        }

        const pos = self.tree.append(&owned.leaf) catch unreachable;
        self.events.appendAssumeCapacity(owned);
        self.digests.putAssumeCapacity(owned.leaf, pos);
        if (self.latest.getPtr(index_key)) |slot| {
            slot.* = pos;
        } else if (owned_key) |key| {
            // `put` copied the pointer; refresh via the owned key.
            self.latest.putAssumeCapacity(key, pos);
        }
        owned_key = null;

        return .{
            .position = pos,
            .size = self.tree.len(),
            .root = self.tree.root(),
            .leaf = owned.leaf,
        };
    }

    pub fn proof(self: *const KeyTransparencyLog, position: usize) !mmr.Proof {
        if (self.unusable) return error.Unavailable;
        return self.tree.proof(position);
    }

    pub fn eventAt(self: *const KeyTransparencyLog, position: usize) error{ IndexOutOfRange, Unavailable }!OwnedEvent {
        if (self.unusable) return error.Unavailable;
        if (position >= self.events.items.len) return error.IndexOutOfRange;
        return self.events.items[position];
    }

    /// Latest exact (canonical account, kind, key_id) event, or null.
    pub fn latestEvent(
        self: *const KeyTransparencyLog,
        account: []const u8,
        kind: CredentialKind,
        key_id: []const u8,
    ) error{ Unavailable, InvalidAccount, InvalidKeyId }!?struct { position: usize, event: OwnedEvent } {
        if (self.unusable) return error.Unavailable;
        try validateAccount(account);
        try validateKeyId(key_id);
        var index_buf: [max_index_key_len]u8 = undefined;
        const index_key = writeIndexKey(&index_buf, account, kind, key_id);
        if (self.latest.get(index_key)) |position| {
            return .{ .position = position, .event = self.events.items[position] };
        }
        // Bounded fallback: walk from the tail. Used if the index missed a
        // row after an allocation failure on an older process image.
        var idx = self.events.items.len;
        while (idx > 0) {
            idx -= 1;
            const event = self.events.items[idx];
            if (event.kind == kind and
                std.mem.eql(u8, event.account(), account) and
                std.mem.eql(u8, event.keyId(), key_id))
            {
                return .{ .position = idx, .event = event };
            }
        }
        return null;
    }

    /// Latest observed E2EE-device action, or null. This is node-local
    /// history, not current/bound device state.
    pub fn latestDeviceObservation(
        self: *const KeyTransparencyLog,
        account: []const u8,
        device_id: []const u8,
    ) error{ Unavailable, InvalidAccount, InvalidKeyId }!?struct { position: usize, observation: ObservedAction, event: OwnedEvent } {
        const found = try self.latestEvent(account, .e2ee_device, device_id) orelse return null;
        return .{
            .position = found.position,
            .observation = found.event.action,
            .event = found.event,
        };
    }

    /// Exact durable-checkpoint comparison for `old_size`. Size 0 is the
    /// empty prefix. Any other size requires the caller-supplied frozen
    /// checkpoint (exact `kt1:c:<size>` lookup). Missing is
    /// `UnknownCheckpoint`; a checkpoint whose last leaf is not this log's
    /// event at `old_size-1` is `Corrupt`. This never allocates a prefix
    /// copy and is not a compact MMR consistency proof.
    pub fn compareCheckpoint(
        self: *const KeyTransparencyLog,
        old_size: usize,
        frozen: ?FrozenPrefix,
    ) ConsistencyError!PrefixComparison {
        if (self.unusable) return error.Unavailable;
        if (old_size > self.tree.len()) return error.SizeAhead;
        if (old_size == 0) {
            return .{
                .old_size = 0,
                .old_root = emptyLogRoot(),
                .size = self.tree.len(),
                .root = self.tree.root(),
                .prefix = .match,
            };
        }
        const ckpt = frozen orelse return error.UnknownCheckpoint;
        const last = self.events.items[old_size - 1];
        if (!std.mem.eql(u8, &last.leaf, &ckpt.last_leaf)) return error.Corrupt;
        if (old_size == self.tree.len() and !std.mem.eql(u8, &ckpt.root, &self.tree.root())) {
            return error.Corrupt;
        }
        return .{
            .old_size = old_size,
            .old_root = ckpt.root,
            .size = self.tree.len(),
            .root = self.tree.root(),
            .prefix = .match,
        };
    }
};

pub fn eventDigest(event: Event) Hash {
    var h = Blake3.init(.{});
    h.update("ONYX-KT-EVENT-v1");
    updateInt(u8, &h, @intFromEnum(event.kind));
    updateInt(u8, &h, @intFromEnum(event.action));
    updateBytes(&h, event.account);
    updateBytes(&h, event.key_id);
    h.update(&event.key_hash);
    updateInt(i64, &h, event.timestamp_ms);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

pub fn materialHash(material: []const u8) Hash {
    var out: Hash = undefined;
    Blake3.hash(material, &out, .{});
    return out;
}

pub fn verifyInclusion(root: mmr.Hash, event: Event, proof: mmr.Proof, position: usize, size: usize) bool {
    const leaf = eventDigest(event);
    return mmr.verify(root, &leaf, proof, position, size);
}

pub fn validateEvent(event: Event) CodecError!void {
    try validateAccount(event.account);
    try validateKeyId(event.key_id);
}

pub fn ownedFromEvent(event: Event) CodecError!OwnedEvent {
    try validateEvent(event);
    var owned = OwnedEvent{
        .kind = event.kind,
        .action = event.action,
        .key_hash = event.key_hash,
        .timestamp_ms = event.timestamp_ms,
        .leaf = eventDigest(event),
    };
    @memcpy(owned.account_buf[0..event.account.len], event.account);
    owned.account_len = @intCast(event.account.len);
    @memcpy(owned.key_id_buf[0..event.key_id.len], event.key_id);
    owned.key_id_len = @intCast(event.key_id.len);
    return owned;
}

pub fn encodeEvent(event: Event, out: []u8) CodecError![]u8 {
    const owned = try ownedFromEvent(event);
    return encodeOwned(owned, out);
}

pub fn encodeOwned(owned: OwnedEvent, out: []u8) CodecError![]u8 {
    const needed = 79 + @as(usize, owned.account_len) + @as(usize, owned.key_id_len);
    if (out.len < needed) return error.BufferTooSmall;
    var i: usize = 0;
    out[i] = codec_version;
    i += 1;
    out[i] = @intFromEnum(owned.kind);
    i += 1;
    out[i] = @intFromEnum(owned.action);
    i += 1;
    std.mem.writeInt(u16, out[i..][0..2], owned.account_len, .little);
    i += 2;
    @memcpy(out[i..][0..owned.account_len], owned.account());
    i += owned.account_len;
    std.mem.writeInt(u16, out[i..][0..2], owned.key_id_len, .little);
    i += 2;
    @memcpy(out[i..][0..owned.key_id_len], owned.keyId());
    i += owned.key_id_len;
    @memcpy(out[i..][0..32], &owned.key_hash);
    i += 32;
    std.mem.writeInt(i64, out[i..][0..8], owned.timestamp_ms, .little);
    i += 8;
    @memcpy(out[i..][0..32], &owned.leaf);
    i += 32;
    return out[0..i];
}

pub fn decodeEvent(bytes: []const u8) CodecError!OwnedEvent {
    if (bytes.len < 79) return error.Truncated;
    if (bytes[0] != codec_version) return error.InvalidVersion;
    var i: usize = 1;
    const kind = CredentialKind.fromInt(bytes[i]) orelse return error.InvalidKind;
    i += 1;
    const action = Action.fromInt(bytes[i]) orelse return error.InvalidAction;
    i += 1;
    const account_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (account_len == 0 or account_len > max_account_len) return error.InvalidAccount;
    if (bytes.len < i + account_len + 2 + 32 + 8 + 32) return error.Truncated;
    const account = bytes[i .. i + account_len];
    i += account_len;
    const key_id_len = std.mem.readInt(u16, bytes[i..][0..2], .little);
    i += 2;
    if (key_id_len == 0 or key_id_len > max_key_id_len) return error.InvalidKeyId;
    if (bytes.len < i + key_id_len + 32 + 8 + 32) return error.Truncated;
    const key_id = bytes[i .. i + key_id_len];
    i += key_id_len;
    var key_hash: Hash = undefined;
    @memcpy(&key_hash, bytes[i..][0..32]);
    i += 32;
    const timestamp_ms = std.mem.readInt(i64, bytes[i..][0..8], .little);
    i += 8;
    var leaf: Hash = undefined;
    @memcpy(&leaf, bytes[i..][0..32]);
    i += 32;
    if (i != bytes.len) return error.TrailingBytes;

    const event = Event{
        .account = account,
        .kind = kind,
        .action = action,
        .key_id = key_id,
        .key_hash = key_hash,
        .timestamp_ms = timestamp_ms,
    };
    try validateEvent(event);
    const expected = eventDigest(event);
    if (!std.mem.eql(u8, &expected, &leaf)) return error.InvalidLeaf;
    var owned = try ownedFromEvent(event);
    owned.leaf = leaf;
    return owned;
}

pub fn validateAccount(account: []const u8) error{InvalidAccount}!void {
    if (account.len == 0 or account.len > max_account_len) return error.InvalidAccount;
    for (account) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '-' or byte == '.';
        if (!ok) return error.InvalidAccount;
    }
}

pub fn validateKeyId(key_id: []const u8) error{InvalidKeyId}!void {
    if (key_id.len == 0 or key_id.len > max_key_id_len) return error.InvalidKeyId;
    for (key_id) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == 0x1f) return error.InvalidKeyId;
    }
}

const max_index_key_len: usize = max_account_len + 1 + 1 + 1 + max_key_id_len;

fn writeIndexKey(out: *[max_index_key_len]u8, account: []const u8, kind: CredentialKind, key_id: []const u8) []const u8 {
    var i: usize = 0;
    @memcpy(out[i..][0..account.len], account);
    i += account.len;
    out[i] = 0;
    i += 1;
    out[i] = @intFromEnum(kind);
    i += 1;
    out[i] = 0;
    i += 1;
    @memcpy(out[i..][0..key_id.len], key_id);
    i += key_id.len;
    return out[0..i];
}

test {
    _ = @import("key_transparency_store.zig");
}

fn updateBytes(h: *Blake3, bytes: []const u8) void {
    updateInt(u64, h, bytes.len);
    h.update(bytes);
}

fn updateInt(comptime T: type, h: *Blake3, value: T) void {
    var buf: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    h.update(&buf);
}

test "KEYTRANS appends credential events and verifies inclusion" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();

    const e1 = Event{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .key_hash = materialHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        .timestamp_ms = 10,
    };
    const e2 = Event{
        .account = "alice",
        .kind = .webauthn,
        .action = .bind,
        .key_id = "credAAA",
        .key_hash = materialHash("cose-key"),
        .timestamp_ms = 20,
    };

    const r1 = try log.append(e1);
    const r2 = try log.append(e2);
    try std.testing.expectEqual(@as(usize, 0), r1.position);
    try std.testing.expectEqual(@as(usize, 2), r2.size);
    try std.testing.expect(!std.mem.eql(u8, &r1.root, &r2.root));

    var proof = try log.proof(1);
    defer proof.deinit(std.testing.allocator);
    try std.testing.expect(verifyInclusion(r2.root, e2, proof, 1, r2.size));
    try std.testing.expect(!verifyInclusion(r2.root, e1, proof, 1, r2.size));
}

test "KEYTRANS event digest is length framed" {
    const a = Event{
        .account = "ab",
        .kind = .certfp,
        .action = .bind,
        .key_id = "c",
        .key_hash = materialHash("k"),
    };
    const b = Event{
        .account = "a",
        .kind = .certfp,
        .action = .bind,
        .key_id = "bc",
        .key_hash = materialHash("k"),
    };
    try std.testing.expect(!std.mem.eql(u8, &eventDigest(a), &eventDigest(b)));
}

test "KEYTRANS event digest domain-separates E2EE device and identity credentials" {
    const base = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("mls-x25519:device-public-key"),
        .timestamp_ms = 42,
    };
    var identity = base;
    identity.kind = .identity;
    try std.testing.expect(!std.mem.eql(
        u8,
        &eventDigest(base),
        &eventDigest(identity),
    ));
}

test "KEYTRANS canonical event codec round-trips and rejects non-canonical input" {
    const event = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("mls-x25519:abcd"),
        .timestamp_ms = 99,
    };
    var buf: [max_encoded_len]u8 = undefined;
    const encoded = try encodeEvent(event, &buf);
    const decoded = try decodeEvent(encoded);
    try std.testing.expectEqualStrings("alice", decoded.account());
    try std.testing.expectEqual(CredentialKind.e2ee_device, decoded.kind);
    try std.testing.expectEqual(Action.bind, decoded.action);
    try std.testing.expectEqualStrings("phone", decoded.keyId());
    try std.testing.expectEqual(event.timestamp_ms, decoded.timestamp_ms);
    try std.testing.expectEqualSlices(u8, &eventDigest(event), &decoded.leaf);

    try std.testing.expectError(error.InvalidAccount, encodeEvent(.{
        .account = "Alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
    }, &buf));
    try std.testing.expectError(error.InvalidAccount, encodeEvent(.{
        .account = "",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
    }, &buf));
    try std.testing.expectError(error.InvalidKeyId, encodeEvent(.{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "bad\nid",
        .key_hash = materialHash("aa"),
    }, &buf));

    var truncated = buf;
    try std.testing.expectError(error.Truncated, decodeEvent(encoded[0 .. encoded.len - 1]));
    var trailing: [max_encoded_len + 1]u8 = undefined;
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decodeEvent(trailing[0 .. encoded.len + 1]));
    truncated[0] = 2;
    try std.testing.expectError(error.InvalidVersion, decodeEvent(truncated[0..encoded.len]));
    @memcpy(truncated[0..encoded.len], encoded);
    truncated[encoded.len - 1] ^= 0xff;
    try std.testing.expectError(error.InvalidLeaf, decodeEvent(truncated[0..encoded.len]));
}

test "KEYTRANS log retains bodies and locates latest account+kind+key_id" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();

    const bind = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("v1"),
        .timestamp_ms = 1,
    };
    const other = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "laptop",
        .key_hash = materialHash("other"),
        .timestamp_ms = 2,
    };
    const delete = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .delete,
        .key_id = "phone",
        .key_hash = materialHash("v1"),
        .timestamp_ms = 3,
    };

    _ = try log.append(bind);
    _ = try log.append(other);
    const deleted = try log.append(delete);

    const body = try log.eventAt(0);
    try std.testing.expectEqualStrings("phone", body.keyId());
    try std.testing.expectEqualSlices(u8, &eventDigest(bind), &body.leaf);

    const latest_phone = try log.latestEvent("alice", .e2ee_device, "phone");
    try std.testing.expect(latest_phone != null);
    try std.testing.expectEqual(deleted.position, latest_phone.?.position);
    try std.testing.expectEqual(Action.delete, latest_phone.?.event.action);

    const device = try log.latestDeviceObservation("alice", "phone");
    try std.testing.expect(device != null);
    try std.testing.expectEqual(Action.delete, device.?.observation);
    try std.testing.expect(try log.latestDeviceObservation("alice", "missing") == null);
    try std.testing.expect(try log.latestEvent("alice", .identity, "phone") == null);
}

test "KEYTRANS checkpoint comparison requires a stored checkpoint and is not a consistency proof" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();

    const e1 = Event{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
        .timestamp_ms = 1,
    };
    const e2 = Event{
        .account = "alice",
        .kind = .certfp,
        .action = .delete,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
        .timestamp_ms = 2,
    };
    const r1 = try log.append(e1);
    const first = try log.eventAt(0);
    _ = try log.append(e2);

    const empty = try log.compareCheckpoint(0, null);
    try std.testing.expectEqual(@as(usize, 0), empty.old_size);
    try std.testing.expectEqual(PrefixStatus.match, empty.prefix);
    try std.testing.expectEqualSlices(u8, &emptyLogRoot(), &empty.old_root);

    try std.testing.expectError(error.UnknownCheckpoint, log.compareCheckpoint(1, null));

    const at_one = try log.compareCheckpoint(1, .{ .root = r1.root, .last_leaf = first.leaf });
    try std.testing.expectEqualSlices(u8, &r1.root, &at_one.old_root);
    try std.testing.expectEqual(PrefixStatus.match, at_one.prefix);
    try std.testing.expectEqual(@as(usize, 2), at_one.size);

    var wrong_leaf = first.leaf;
    wrong_leaf[0] ^= 0x01;
    try std.testing.expectError(error.Corrupt, log.compareCheckpoint(1, .{ .root = r1.root, .last_leaf = wrong_leaf }));
    try std.testing.expectError(error.SizeAhead, log.compareCheckpoint(9, null));
}

test "KEYTRANS fact tombstone hash is deterministic and domain-separated" {
    const id = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .key_id = "phone",
        .hlc = 42,
        .origin_node = 7,
        .origin_pubkey = "pk",
    };
    const a = factTombstoneHash(id);
    const b = factTombstoneHash(id);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &materialHash("phone")));
    var other = id;
    other.origin_node = 8;
    try std.testing.expect(!std.mem.eql(u8, &a, &factTombstoneHash(other)));
    try std.testing.expectEqual(@as(i64, 42), observationTimestampMs(42));
}

test "KEYTRANS exact fact identity binds action material HLC and origin" {
    const bind = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 100,
        .origin_node = 0xA,
        .origin_pubkey = "pk-a",
    };
    const material = "mls-x25519:abcd+/=";
    const first = factObservationHash(bind, material);
    try std.testing.expectEqualSlices(u8, &first, &factObservationHash(bind, material));
    try std.testing.expect(!std.mem.eql(u8, &first, &materialHash(material)));

    var other_origin = bind;
    other_origin.origin_node = 0xB;
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_origin, material)));

    var other_pk = bind;
    other_pk.origin_pubkey = "pk-b";
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_pk, material)));

    var other_hlc = bind;
    other_hlc.hlc = 101;
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_hlc, material)));

    var del = bind;
    del.action = .delete;
    const tomb = factObservationHash(del, "");
    try std.testing.expect(!std.mem.eql(u8, &first, &tomb));
    try std.testing.expectEqualSlices(u8, &tomb, &factIdentityHash(del, factTombstoneHash(del)));
    try std.testing.expect(!std.mem.eql(u8, &tomb, &factTombstoneHash(del)));
}

test "KEYTRANS exact fact identity domain-separates account kind and key_id" {
    const base = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 7,
        .origin_node = 1,
        .origin_pubkey = "pk",
    };
    const material = "v1";
    const first = factObservationHash(base, material);
    var other_account = base;
    other_account.account = "bob";
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_account, material)));
    var other_kind = base;
    other_kind.kind = .identity;
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_kind, material)));
    var other_key = base;
    other_key.key_id = "laptop";
    try std.testing.expect(!std.mem.eql(u8, &first, &factObservationHash(other_key, material)));
}

test "KEYTRANS exact fact replay dedups and different origin appends" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const bind = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 50,
        .origin_node = 1,
        .origin_pubkey = "pk1",
    };
    const event_a = Event{
        .account = bind.account,
        .kind = bind.kind,
        .action = bind.action,
        .key_id = bind.key_id,
        .key_hash = factObservationHash(bind, "mat"),
        .timestamp_ms = observationTimestampMs(bind.hlc),
    };
    var bind_b = bind;
    bind_b.origin_node = 2;
    bind_b.origin_pubkey = "pk2";
    const event_b = Event{
        .account = bind_b.account,
        .kind = bind_b.kind,
        .action = bind_b.action,
        .key_id = bind_b.key_id,
        .key_hash = factObservationHash(bind_b, "mat"),
        .timestamp_ms = observationTimestampMs(bind_b.hlc),
    };
    const first = try log.append(event_a);
    const replay = try log.append(event_a);
    try std.testing.expect(replay.duplicate);
    try std.testing.expectEqual(first.position, replay.position);
    const other = try log.append(event_b);
    try std.testing.expect(!other.duplicate);
    try std.testing.expectEqual(@as(usize, 2), log.len());
}

test "KEYTRANS exact fact identity distinguishes bind from delete of same material" {
    const id = FactIdentity{
        .account = "alice",
        .kind = .identity,
        .action = .bind,
        .key_id = "primary",
        .hlc = 9,
        .origin_node = 3,
        .origin_pubkey = "",
    };
    var del = id;
    del.action = .delete;
    try std.testing.expect(!std.mem.eql(
        u8,
        &factObservationHash(id, "pub"),
        &factObservationHash(del, "pub"),
    ));
}

test "KEYTRANS unusable log rejects append proof and latest lookup" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    log.unusable = true;
    try std.testing.expectError(error.Unavailable, log.append(Event{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
    }));
    try std.testing.expectError(error.Unavailable, log.proof(0));
    try std.testing.expectError(error.Unavailable, log.eventAt(0));
    try std.testing.expectError(error.Unavailable, log.latestEvent("alice", .certfp, "aa"));
    try std.testing.expectError(error.Unavailable, log.compareCheckpoint(0, null));
}

test "KEYTRANS latestEvent rejects invalid account and key id" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    try std.testing.expectError(error.InvalidAccount, log.latestEvent("Alice", .e2ee_device, "phone"));
    try std.testing.expectError(error.InvalidKeyId, log.latestEvent("alice", .e2ee_device, "bad\nid"));
}

test "KEYTRANS reset clears digest index but keeps unusable" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const event = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("v"),
        .timestamp_ms = 1,
    };
    const first = try log.append(event);
    try std.testing.expect(log.hasDigest(first.leaf));
    log.unusable = true;
    log.reset();
    try std.testing.expect(log.unusable);
    try std.testing.expectEqual(@as(usize, 0), log.len());
    try std.testing.expect(!log.hasDigest(first.leaf));
}

test "KEYTRANS encodeOwned rejects a too-small buffer" {
    const owned = try ownedFromEvent(.{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
    });
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeOwned(owned, &tiny));
}

test "KEYTRANS OwnedEvent eql requires matching leaf and fields" {
    const a = try ownedFromEvent(.{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("v"),
        .timestamp_ms = 1,
    });
    var b = a;
    try std.testing.expect(a.eql(&b));
    b.timestamp_ms = 2;
    try std.testing.expect(!a.eql(&b));
}

test "KEYTRANS empty log root is stable" {
    try std.testing.expectEqualSlices(u8, &emptyLogRoot(), &emptyLogRoot());
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    try std.testing.expectEqualSlices(u8, &emptyLogRoot(), &log.root());
}

test "KEYTRANS compareCheckpoint current size root mismatch is corrupt" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const r = try log.append(.{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
        .timestamp_ms = 1,
    });
    const last = try log.eventAt(0);
    var wrong = r.root;
    wrong[0] ^= 0x7f;
    try std.testing.expectError(error.Corrupt, log.compareCheckpoint(1, .{ .root = wrong, .last_leaf = last.leaf }));
}

test "KEYTRANS credential kind and action wire names" {
    try std.testing.expectEqualStrings("certfp", CredentialKind.certfp.wireName());
    try std.testing.expectEqualStrings("webauthn", CredentialKind.webauthn.wireName());
    try std.testing.expectEqualStrings("e2ee_device", CredentialKind.e2ee_device.wireName());
    try std.testing.expectEqualStrings("identity", CredentialKind.identity.wireName());
    try std.testing.expectEqualStrings("bind", Action.bind.wireName());
    try std.testing.expectEqualStrings("delete", Action.delete.wireName());
    try std.testing.expect(CredentialKind.fromInt(99) == null);
    try std.testing.expect(Action.fromInt(99) == null);
}

test "KEYTRANS fact identity empty pubkey differs from missing material" {
    const id = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 1,
        .origin_node = 1,
        .origin_pubkey = "",
    };
    try std.testing.expect(!std.mem.eql(u8, &factObservationHash(id, ""), &factObservationHash(id, "x")));
}

test "KEYTRANS fact canonical hash uses tombstone only for delete" {
    const bind = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 4,
        .origin_node = 1,
    };
    var del = bind;
    del.action = .delete;
    try std.testing.expectEqualSlices(u8, &materialHash("mat"), &factCanonicalHash(bind, "mat"));
    try std.testing.expectEqualSlices(u8, &factTombstoneHash(del), &factCanonicalHash(del, "mat"));
}

test "KEYTRANS fact identity same origin different action appends two leaves" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const bind = FactIdentity{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 8,
        .origin_node = 4,
        .origin_pubkey = "pk",
    };
    var del = bind;
    del.action = .delete;
    _ = try log.append(.{
        .account = bind.account,
        .kind = bind.kind,
        .action = .bind,
        .key_id = bind.key_id,
        .key_hash = factObservationHash(bind, "m"),
        .timestamp_ms = 8,
    });
    _ = try log.append(.{
        .account = del.account,
        .kind = del.kind,
        .action = .delete,
        .key_id = del.key_id,
        .key_hash = factObservationHash(del, ""),
        .timestamp_ms = 8,
    });
    try std.testing.expectEqual(@as(usize, 2), log.len());
}

test "KEYTRANS latestDeviceObservation is kind scoped" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try log.append(.{
        .account = "alice",
        .kind = .identity,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("v"),
        .timestamp_ms = 1,
    });
    try std.testing.expect(try log.latestDeviceObservation("alice", "phone") == null);
}

test "KEYTRANS validateAccount rejects punctuation and uppercase" {
    try std.testing.expectError(error.InvalidAccount, validateAccount(""));
    try std.testing.expectError(error.InvalidAccount, validateAccount("Alice"));
    try std.testing.expectError(error.InvalidAccount, validateAccount("a b"));
    try validateAccount("a_b-c.1");
}

test "KEYTRANS validateKeyId rejects controls and empty" {
    try std.testing.expectError(error.InvalidKeyId, validateKeyId(""));
    try std.testing.expectError(error.InvalidKeyId, validateKeyId("x\x1f"));
    try std.testing.expectError(error.InvalidKeyId, validateKeyId("x\x7f"));
    try validateKeyId("phone.1");
}

test "KEYTRANS decodeEvent rejects unknown kind and action" {
    const event = Event{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "aa",
        .key_hash = materialHash("aa"),
    };
    var buf: [max_encoded_len]u8 = undefined;
    const encoded = try encodeEvent(event, &buf);
    var bad_kind = buf;
    @memcpy(bad_kind[0..encoded.len], encoded);
    bad_kind[1] = 99;
    try std.testing.expectError(error.InvalidKind, decodeEvent(bad_kind[0..encoded.len]));
    var bad_action = buf;
    @memcpy(bad_action[0..encoded.len], encoded);
    bad_action[2] = 99;
    try std.testing.expectError(error.InvalidAction, decodeEvent(bad_action[0..encoded.len]));
}

test "KEYTRANS eventAt rejects an out of range position" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    try std.testing.expectError(error.IndexOutOfRange, log.eventAt(0));
}

test "KEYTRANS fact identity different HLC with same origin appends" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = FactIdentity{
        .account = "alice",
        .kind = .identity,
        .action = .bind,
        .key_id = "primary",
        .hlc = 1,
        .origin_node = 1,
    };
    var second = first;
    second.hlc = 2;
    _ = try log.append(.{
        .account = first.account,
        .kind = first.kind,
        .action = first.action,
        .key_id = first.key_id,
        .key_hash = factObservationHash(first, "k"),
        .timestamp_ms = 1,
    });
    const again = try log.append(.{
        .account = second.account,
        .kind = second.kind,
        .action = second.action,
        .key_id = second.key_id,
        .key_hash = factObservationHash(second, "k"),
        .timestamp_ms = 2,
    });
    try std.testing.expect(!again.duplicate);
    try std.testing.expectEqual(@as(usize, 2), log.len());
}

test "KEYTRANS duplicate digest does not grow the log" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const event = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("v1"),
        .timestamp_ms = 99,
    };
    const first = try log.append(event);
    const again = try log.append(event);
    try std.testing.expectEqual(@as(usize, 1), log.len());
    try std.testing.expect(again.duplicate);
    try std.testing.expectEqual(first.position, again.position);
    try std.testing.expectEqualSlices(u8, &first.root, &again.root);
    try std.testing.expect(log.hasDigest(first.leaf));
}

test "KEYTRANS append allocation failure is atomic" {
    const allocator = std.testing.allocator;
    const Sweep = struct {
        fn run(failing: std.mem.Allocator) !void {
            var log = KeyTransparencyLog.init(failing);
            defer log.deinit();
            const e1 = Event{
                .account = "alice",
                .kind = .e2ee_device,
                .action = .bind,
                .key_id = "phone",
                .key_hash = materialHash("one"),
                .timestamp_ms = 1,
            };
            const e2 = Event{
                .account = "alice",
                .kind = .e2ee_device,
                .action = .delete,
                .key_id = "phone",
                .key_hash = materialHash("one"),
                .timestamp_ms = 2,
            };
            _ = try log.append(e1);
            const before_len = log.len();
            const before_root = log.root();
            _ = log.append(e2) catch |err| {
                try std.testing.expectEqual(before_len, log.len());
                try std.testing.expectEqualSlices(u8, &before_root, &log.root());
                return err;
            };
            try std.testing.expectEqual(@as(usize, 2), log.len());
            const latest = try log.latestEvent("alice", .e2ee_device, "phone");
            try std.testing.expect(latest != null);
            try std.testing.expectEqual(Action.delete, latest.?.event.action);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Sweep.run, .{});
}
