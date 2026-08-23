// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Append-only OroStore persistence for node-local observational KT history.
//!
//! Records live in the `props` family under the `kt1:` prefix so they coexist
//! with certfp/WebAuthn rows. The log is append-only: event bodies are never
//! rewritten. A commit writes an authenticated prepare marker, then event,
//! index, checkpoint, and meta, then clears the marker. A crash mid-commit
//! is completed only when a matching valid prepare marker is present;
//! event-only, marker-only, mismatched, corrupt, or extra beyond-meta rows
//! fail closed.
//!
//! Migration: pre-Wave3 deployments kept an in-memory MMR only. Those roots
//! die on restart. A missing `kt1:meta` with no `kt1:` rows is a fresh
//! empty log, not corruption. Historical events are never invented. A
//! present `kt1:meta` or any `kt1:e:`/`kt1:c:`/`kt1:i:`/`kt1:p` row that
//! fails validation makes the log unusable; restore never silently creates a
//! fresh empty root over corrupt state. A `kt1:dead` poison row is fail-closed.
//!
//! Frozen checkpoints (`kt1:c:<size>`) are tamper-evident BLAKE3 commitments
//! over (size, root, last leaf). They are exact-lookup observational
//! checkpoints, not auditor signatures and not an MMR consistency proof.

const std = @import("std");
const store_mod = @import("store.zig");
const kt = @import("key_transparency.zig");

pub const OroStore = store_mod.OroStore;
pub const family = store_mod.Family.props;

pub const schema_version: u8 = 1;
pub const key_prefix = "kt1:";
const meta_key = key_prefix ++ "meta";
pub const prepare_key = key_prefix ++ "p";
pub const unavailable_key = key_prefix ++ "dead";
const event_key_prefix = key_prefix ++ "e:";
const index_key_prefix = key_prefix ++ "i:";
const checkpoint_key_prefix = key_prefix ++ "c:";
pub const event_key_len: usize = event_key_prefix.len + 16;
pub const checkpoint_key_len: usize = checkpoint_key_prefix.len + 16;
pub const prepare_encoded_len: usize = 1 + 8 + 32 + 32 + 32 + 32;

const StorePutError = @typeInfo(@typeInfo(@TypeOf(OroStore.put)).@"fn".return_type.?).error_union.error_set;
const StoreDeleteError = @typeInfo(@typeInfo(@TypeOf(OroStore.delete)).@"fn".return_type.?).error_union.error_set;

pub const StoreError = error{
    Corrupt,
    Truncated,
    Unavailable,
} || kt.CodecError || store_mod.StoreError || StorePutError || StoreDeleteError || std.mem.Allocator.Error;

pub const Meta = struct {
    size: u64,
    root: kt.Hash,
};

pub const FrozenCheckpoint = struct {
    size: u64,
    root: kt.Hash,
    last_leaf: kt.Hash,
    commit: kt.Hash,
};

pub const PrepareMarker = struct {
    position: u64,
    leaf: kt.Hash,
    root: kt.Hash,
    body_hash: kt.Hash,
    commit: kt.Hash,
};

pub fn eventKey(position: u64, out: *[event_key_len]u8) []const u8 {
    return writePrefixedHex(event_key_prefix, position, out);
}

pub fn checkpointKey(size: u64, out: *[checkpoint_key_len]u8) []const u8 {
    return writePrefixedHex(checkpoint_key_prefix, size, out);
}

pub fn indexKey(
    account: []const u8,
    kind: kt.CredentialKind,
    key_id: []const u8,
    out: *[index_key_max]u8,
) error{ InvalidAccount, InvalidKeyId, BufferTooSmall }![]const u8 {
    try kt.validateAccount(account);
    try kt.validateKeyId(key_id);
    const needed = index_key_prefix.len + account.len + 1 + 1 + 1 + key_id.len;
    if (out.len < needed) return error.BufferTooSmall;
    var i: usize = 0;
    @memcpy(out[i..][0..index_key_prefix.len], index_key_prefix);
    i += index_key_prefix.len;
    @memcpy(out[i..][0..account.len], account);
    i += account.len;
    out[i] = 0x1f;
    i += 1;
    out[i] = @intFromEnum(kind);
    i += 1;
    out[i] = 0x1f;
    i += 1;
    @memcpy(out[i..][0..key_id.len], key_id);
    i += key_id.len;
    return out[0..i];
}

pub const index_key_max: usize = index_key_prefix.len + kt.max_account_len + 1 + 1 + 1 + kt.max_key_id_len;

pub fn encodeMeta(meta: Meta, out: *[1 + 8 + 32]u8) []const u8 {
    out[0] = schema_version;
    std.mem.writeInt(u64, out[1..9], meta.size, .little);
    @memcpy(out[9..41], &meta.root);
    return out;
}

pub fn decodeMeta(bytes: []const u8) StoreError!Meta {
    if (bytes.len < 41) return error.Truncated;
    if (bytes.len != 41) return error.Corrupt;
    if (bytes[0] != schema_version) return error.Corrupt;
    var root: kt.Hash = undefined;
    @memcpy(&root, bytes[9..41]);
    return .{
        .size = std.mem.readInt(u64, bytes[1..9], .little),
        .root = root,
    };
}

pub fn encodeCheckpoint(ckpt: FrozenCheckpoint, out: *[8 + 32 + 32 + 32]u8) []const u8 {
    std.mem.writeInt(u64, out[0..8], ckpt.size, .little);
    @memcpy(out[8..40], &ckpt.root);
    @memcpy(out[40..72], &ckpt.last_leaf);
    @memcpy(out[72..104], &ckpt.commit);
    return out;
}

pub fn decodeCheckpoint(bytes: []const u8) StoreError!FrozenCheckpoint {
    if (bytes.len != 104) return error.Corrupt;
    var ckpt = FrozenCheckpoint{
        .size = std.mem.readInt(u64, bytes[0..8], .little),
        .root = undefined,
        .last_leaf = undefined,
        .commit = undefined,
    };
    @memcpy(&ckpt.root, bytes[8..40]);
    @memcpy(&ckpt.last_leaf, bytes[40..72]);
    @memcpy(&ckpt.commit, bytes[72..104]);
    const expected = checkpointCommit(ckpt.size, ckpt.root, ckpt.last_leaf);
    if (!std.mem.eql(u8, &expected, &ckpt.commit)) return error.Corrupt;
    return ckpt;
}

pub fn checkpointCommit(size: u64, root: kt.Hash, last_leaf: kt.Hash) kt.Hash {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update("ONYX-KT-CKPT-v1");
    var size_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_buf, size, .little);
    h.update(&size_buf);
    h.update(&root);
    h.update(&last_leaf);
    var out: kt.Hash = undefined;
    h.final(&out);
    return out;
}

pub fn prepareBodyHash(body: []const u8) kt.Hash {
    var out: kt.Hash = undefined;
    std.crypto.hash.Blake3.hash(body, &out, .{});
    return out;
}

pub fn prepareCommit(position: u64, leaf: kt.Hash, root: kt.Hash, body_hash: kt.Hash) kt.Hash {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update("ONYX-KT-PREPARE-v1");
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, position, .little);
    h.update(&pos_buf);
    h.update(&leaf);
    h.update(&root);
    h.update(&body_hash);
    var out: kt.Hash = undefined;
    h.final(&out);
    return out;
}

pub fn encodePrepare(marker: PrepareMarker, out: *[prepare_encoded_len]u8) []const u8 {
    out[0] = schema_version;
    std.mem.writeInt(u64, out[1..9], marker.position, .little);
    @memcpy(out[9..41], &marker.leaf);
    @memcpy(out[41..73], &marker.root);
    @memcpy(out[73..105], &marker.body_hash);
    @memcpy(out[105..137], &marker.commit);
    return out;
}

pub fn decodePrepare(bytes: []const u8) StoreError!PrepareMarker {
    if (bytes.len != prepare_encoded_len) return error.Corrupt;
    if (bytes[0] != schema_version) return error.Corrupt;
    var marker = PrepareMarker{
        .position = std.mem.readInt(u64, bytes[1..9], .little),
        .leaf = undefined,
        .root = undefined,
        .body_hash = undefined,
        .commit = undefined,
    };
    @memcpy(&marker.leaf, bytes[9..41]);
    @memcpy(&marker.root, bytes[41..73]);
    @memcpy(&marker.body_hash, bytes[73..105]);
    @memcpy(&marker.commit, bytes[105..137]);
    const expected = prepareCommit(marker.position, marker.leaf, marker.root, marker.body_hash);
    if (!std.mem.eql(u8, &expected, &marker.commit)) return error.Corrupt;
    return marker;
}

pub fn makePrepare(position: u64, owned: kt.OwnedEvent, root: kt.Hash, body: []const u8) PrepareMarker {
    const body_hash = prepareBodyHash(body);
    return .{
        .position = position,
        .leaf = owned.leaf,
        .root = root,
        .body_hash = body_hash,
        .commit = prepareCommit(position, owned.leaf, root, body_hash),
    };
}

pub fn loadPrepare(store: *const OroStore) StoreError!?PrepareMarker {
    const raw = store.get(family, prepare_key) orelse return null;
    return try decodePrepare(raw);
}

pub fn markUnavailable(store: *OroStore) void {
    store.family(family).put(unavailable_key, "1") catch {};
}

pub fn isMarkedUnavailable(store: *const OroStore) bool {
    return store.get(family, unavailable_key) != null;
}

pub fn loadMeta(store: *const OroStore) StoreError!?Meta {
    const raw = store.get(family, meta_key) orelse return null;
    return try decodeMeta(raw);
}

pub fn loadEvent(store: *const OroStore, position: u64) StoreError!?kt.OwnedEvent {
    var key_buf: [event_key_len]u8 = undefined;
    const key = eventKey(position, &key_buf);
    const raw = store.get(family, key) orelse return null;
    return kt.decodeEvent(raw) catch return error.Corrupt;
}

pub fn loadCheckpoint(store: *const OroStore, size: u64) StoreError!?FrozenCheckpoint {
    if (size == 0) return null;
    var key_buf: [checkpoint_key_len]u8 = undefined;
    const key = checkpointKey(size, &key_buf);
    const raw = store.get(family, key) orelse return null;
    return try decodeCheckpoint(raw);
}

pub fn loadLatestIndex(
    store: *const OroStore,
    account: []const u8,
    kind: kt.CredentialKind,
    key_id: []const u8,
) StoreError!?u64 {
    var key_buf: [index_key_max]u8 = undefined;
    const key = try indexKey(account, kind, key_id, &key_buf);
    const raw = store.get(family, key) orelse return null;
    if (raw.len != 8) return error.Corrupt;
    return std.mem.readInt(u64, raw[0..8], .little);
}

/// Persist one append. Prepare marker first (binding position, event body
/// hash, leaf, and target root), then event, latest-index, frozen checkpoint,
/// then meta, then clear the marker. A returned failure cleans those rows
/// so restore cannot adopt the aborted event. If cleanup cannot be proven
/// the store is marked unavailable. Writing the same exact body at an
/// already-committed position is idempotent.
pub fn commit(store: *OroStore, position: u64, owned: kt.OwnedEvent, root: kt.Hash) StoreError!void {
    if (isMarkedUnavailable(store)) return error.Unavailable;
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);

    if (try alreadyCommitted(store, position, body, root)) return;

    const previous_index = loadLatestIndex(store, owned.account(), owned.kind, owned.keyId()) catch null;
    var wrote_event = false;
    var wrote_index = false;
    var wrote_checkpoint = false;
    errdefer abortIncomplete(store, position, owned, previous_index, wrote_event, wrote_index, wrote_checkpoint);

    try writePrepare(store, position, owned, root, body);

    var event_key_buf: [event_key_len]u8 = undefined;
    const ev_key = eventKey(position, &event_key_buf);
    if (store.family(family).get(ev_key)) |existing| {
        if (!std.mem.eql(u8, existing, body)) return error.Corrupt;
    } else {
        try store.family(family).put(ev_key, body);
    }
    wrote_event = true;

    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey(owned.account(), owned.kind, owned.keyId(), &idx_buf);
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, position, .little);
    try store.family(family).put(idx_key, &pos_buf);
    wrote_index = true;

    try writeCheckpoint(store, position + 1, root, owned.leaf);
    wrote_checkpoint = true;

    var meta_buf: [1 + 8 + 32]u8 = undefined;
    try store.family(family).put(meta_key, encodeMeta(.{ .size = position + 1, .root = root }, &meta_buf));
    store.family(family).delete(prepare_key) catch {};
}

fn alreadyCommitted(store: *const OroStore, position: u64, body: []const u8, root: kt.Hash) StoreError!bool {
    const meta = try loadMeta(store);
    if (meta) |m| {
        if (m.size > position + 1) return error.Corrupt;
        if (m.size == position + 1) {
            if (!std.mem.eql(u8, &m.root, &root)) return error.Corrupt;
            const existing = try loadEvent(store, position) orelse return error.Truncated;
            var existing_buf: [kt.max_encoded_len]u8 = undefined;
            const existing_body = try kt.encodeOwned(existing, &existing_buf);
            if (!std.mem.eql(u8, existing_body, body)) return error.Corrupt;
            return true;
        }
    }
    return false;
}

fn writePrepare(store: *OroStore, position: u64, owned: kt.OwnedEvent, root: kt.Hash, body: []const u8) StoreError!void {
    const marker = makePrepare(position, owned, root, body);
    var marker_buf: [prepare_encoded_len]u8 = undefined;
    try store.family(family).put(prepare_key, encodePrepare(marker, &marker_buf));
}

fn writeCheckpoint(store: *OroStore, size: u64, root: kt.Hash, last_leaf: kt.Hash) StoreError!void {
    const ckpt = FrozenCheckpoint{
        .size = size,
        .root = root,
        .last_leaf = last_leaf,
        .commit = checkpointCommit(size, root, last_leaf),
    };
    var ckpt_val: [8 + 32 + 32 + 32]u8 = undefined;
    const ckpt_bytes = encodeCheckpoint(ckpt, &ckpt_val);
    var ckpt_key_buf: [checkpoint_key_len]u8 = undefined;
    try store.family(family).put(checkpointKey(size, &ckpt_key_buf), ckpt_bytes);
}

/// Remove an aborted transaction. If any restorable residue remains, poison
/// the store so a later restore cannot adopt it.
pub fn abortIncomplete(
    store: *OroStore,
    position: u64,
    owned: kt.OwnedEvent,
    previous_index: ?u64,
    wrote_event: bool,
    wrote_index: bool,
    wrote_checkpoint: bool,
) void {
    store.family(family).delete(prepare_key) catch {};
    if (wrote_event) {
        var ev_key: [event_key_len]u8 = undefined;
        store.family(family).delete(eventKey(position, &ev_key)) catch {};
    }
    if (wrote_index) {
        var idx_buf: [index_key_max]u8 = undefined;
        if (indexKey(owned.account(), owned.kind, owned.keyId(), &idx_buf)) |idx_key| {
            if (previous_index) |prev| {
                var pos_buf: [8]u8 = undefined;
                std.mem.writeInt(u64, &pos_buf, prev, .little);
                store.family(family).put(idx_key, &pos_buf) catch markUnavailable(store);
            } else {
                store.family(family).delete(idx_key) catch {};
            }
        } else |_| {
            markUnavailable(store);
        }
    }
    if (wrote_checkpoint) {
        var ckpt_key: [checkpoint_key_len]u8 = undefined;
        store.family(family).delete(checkpointKey(position + 1, &ckpt_key)) catch {};
    }
    if (!cleanupProven(store, position)) markUnavailable(store);
}

pub fn abortPrepare(store: *OroStore, position: u64, owned: kt.OwnedEvent, previous_index: ?u64) void {
    abortIncomplete(store, position, owned, previous_index, true, true, true);
}

fn cleanupProven(store: *const OroStore, position: u64) bool {
    if (store.get(family, prepare_key) != null) return false;
    var ev_key: [event_key_len]u8 = undefined;
    if (store.get(family, eventKey(position, &ev_key)) != null) {
        const meta = loadMeta(store) catch return false;
        const committed = if (meta) |m| m.size else 0;
        if (position >= committed) return false;
    }
    return true;
}

/// Rebuild `log` from durable records. Fail-closed on missing, corrupt, or
/// truncated committed bodies, checkpoints, or latest-index rows. Completes
/// a beyond-meta event only when an exactly matching valid prepare marker
/// is present. Event-only, marker-only, mismatched, corrupt, or extra
/// beyond-meta rows fail closed. Never invents a fresh empty log over a
/// half-written or corrupt store.
pub fn restore(store: *OroStore, log: *kt.KeyTransparencyLog) StoreError!void {
    log.reset();
    log.unusable = false;
    errdefer {
        log.reset();
        log.unusable = true;
    }

    if (isMarkedUnavailable(store)) return error.Unavailable;

    const meta = try loadMeta(store);
    const committed_size: u64 = if (meta) |m| m.size else 0;

    var position: u64 = 0;
    while (position < committed_size) : (position += 1) {
        const owned = try loadEvent(store, position) orelse return error.Truncated;
        const result = try log.appendOwned(owned);
        if (result.duplicate or result.position != position) return error.Corrupt;
        try validateCheckpoint(store, result.size, result.root, owned.leaf);
    }

    if (meta) |m| {
        if (log.len() != m.size) return error.Truncated;
        if (!std.mem.eql(u8, &log.root(), &m.root)) return error.Corrupt;
    } else if (log.len() != 0) {
        return error.Corrupt;
    }

    try finishOrRejectBeyondMeta(store, log, committed_size);
    try validateAllKtRows(store, log);
}

fn validateCheckpoint(store: *const OroStore, size: usize, root: kt.Hash, last_leaf: kt.Hash) StoreError!void {
    const ckpt = try loadCheckpoint(store, size) orelse return error.Truncated;
    if (ckpt.size != size) return error.Corrupt;
    if (!std.mem.eql(u8, &ckpt.root, &root)) return error.Corrupt;
    if (!std.mem.eql(u8, &ckpt.last_leaf, &last_leaf)) return error.Corrupt;
}

fn finishOrRejectBeyondMeta(store: *OroStore, log: *kt.KeyTransparencyLog, committed_size: u64) StoreError!void {
    const beyond = try loadEvent(store, committed_size);
    const marker_raw = store.get(family, prepare_key);
    if (try loadEvent(store, committed_size + 1)) |_| return error.Corrupt;

    if (beyond == null and marker_raw == null) return;

    const marker = if (marker_raw) |raw| try decodePrepare(raw) else return error.Corrupt;
    if (marker.position < committed_size) {
        // A marker below meta can only be a torn clear from the immediately
        // preceding commit.  Never clear an arbitrary old marker: bind it to
        // the committed event body, leaf, and the exact committed checkpoint
        // (including its root).  This keeps stale or replayed markers
        // fail-closed instead of silently masking durable corruption.
        if (beyond != null or committed_size == 0 or marker.position != committed_size - 1) return error.Corrupt;
        const committed_event = try loadEvent(store, marker.position) orelse return error.Corrupt;
        if (!std.mem.eql(u8, &marker.leaf, &committed_event.leaf)) return error.Corrupt;
        var body_buf: [kt.max_encoded_len]u8 = undefined;
        const body = try kt.encodeOwned(committed_event, &body_buf);
        if (!std.mem.eql(u8, &marker.body_hash, &prepareBodyHash(body))) return error.Corrupt;
        const checkpoint = try loadCheckpoint(store, committed_size) orelse return error.Corrupt;
        if (checkpoint.size != committed_size) return error.Corrupt;
        if (!std.mem.eql(u8, &marker.leaf, &checkpoint.last_leaf)) return error.Corrupt;
        if (!std.mem.eql(u8, &marker.root, &checkpoint.root)) return error.Corrupt;
        if (!std.mem.eql(u8, &marker.root, &log.root())) return error.Corrupt;
        try store.family(family).delete(prepare_key);
        return;
    }
    const torn = beyond orelse return error.Corrupt;
    if (marker.position != committed_size) return error.Corrupt;
    if (!std.mem.eql(u8, &marker.leaf, &torn.leaf)) return error.Corrupt;

    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(torn, &body_buf);
    if (!std.mem.eql(u8, &marker.body_hash, &prepareBodyHash(body))) return error.Corrupt;

    const result = try log.appendOwned(torn);
    if (result.duplicate or result.position != committed_size) return error.Corrupt;
    if (!std.mem.eql(u8, &marker.root, &result.root)) return error.Corrupt;

    try finishPrepared(store, result.position, torn, result.root);
}

fn finishPrepared(store: *OroStore, position: u64, owned: kt.OwnedEvent, root: kt.Hash) StoreError!void {
    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey(owned.account(), owned.kind, owned.keyId(), &idx_buf);
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, position, .little);
    try store.family(family).put(idx_key, &pos_buf);
    try writeCheckpoint(store, position + 1, root, owned.leaf);
    var meta_buf: [1 + 8 + 32]u8 = undefined;
    try store.family(family).put(meta_key, encodeMeta(.{ .size = position + 1, .root = root }, &meta_buf));
    try store.family(family).delete(prepare_key);
}

fn validateAllKtRows(store: *const OroStore, log: *const kt.KeyTransparencyLog) StoreError!void {
    try validateLatestIndexes(store, log);
    var seen_indexes: usize = 0;
    var seen_events: usize = 0;
    var seen_checkpoints: usize = 0;
    var it = store.maps[@intFromEnum(store_mod.Family.props)].map.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (!std.mem.startsWith(u8, key, key_prefix)) continue;
        if (std.mem.eql(u8, key, meta_key)) continue;
        if (std.mem.eql(u8, key, prepare_key)) return error.Corrupt;
        if (std.mem.eql(u8, key, unavailable_key)) return error.Unavailable;
        if (std.mem.startsWith(u8, key, event_key_prefix)) {
            const pos = parsePrefixedHex(event_key_prefix, key) orelse return error.Corrupt;
            if (pos >= log.len()) return error.Corrupt;
            const owned = try loadEvent(store, pos) orelse return error.Truncated;
            if (!owned.eql(&log.events.items[pos])) return error.Corrupt;
            seen_events += 1;
            continue;
        }
        if (std.mem.startsWith(u8, key, checkpoint_key_prefix)) {
            const size = parsePrefixedHex(checkpoint_key_prefix, key) orelse return error.Corrupt;
            if (size == 0 or size > log.len()) return error.Corrupt;
            const last = log.events.items[size - 1];
            const ckpt = try loadCheckpoint(store, size) orelse return error.Truncated;
            if (ckpt.size != size) return error.Corrupt;
            if (!std.mem.eql(u8, &ckpt.last_leaf, &last.leaf)) return error.Corrupt;
            if (size == log.len() and !std.mem.eql(u8, &ckpt.root, &log.root())) return error.Corrupt;
            seen_checkpoints += 1;
            continue;
        }
        if (std.mem.startsWith(u8, key, index_key_prefix)) {
            if (entry.value_ptr.*.len != 8) return error.Corrupt;
            const stored = std.mem.readInt(u64, entry.value_ptr.*[0..8], .little);
            if (stored >= log.len()) return error.Corrupt;
            const event = log.events.items[stored];
            var expected_buf: [index_key_max]u8 = undefined;
            const expected = try indexKey(event.account(), event.kind, event.keyId(), &expected_buf);
            if (!std.mem.eql(u8, expected, key)) return error.Corrupt;
            const latest = try log.latestEvent(event.account(), event.kind, event.keyId());
            const row = latest orelse return error.Corrupt;
            if (row.position != stored) return error.Corrupt;
            seen_indexes += 1;
            continue;
        }
        return error.Corrupt;
    }
    if (seen_events != log.len()) return error.Corrupt;
    if (seen_checkpoints != log.len()) return error.Corrupt;
    if (seen_indexes != log.latest.count()) return error.Corrupt;
}

fn validateLatestIndexes(store: *const OroStore, log: *const kt.KeyTransparencyLog) StoreError!void {
    var it = log.latest.iterator();
    while (it.next()) |entry| {
        const event = log.events.items[entry.value_ptr.*];
        const stored = try loadLatestIndex(store, event.account(), event.kind, event.keyId()) orelse
            return error.Truncated;
        if (stored != entry.value_ptr.*) return error.Corrupt;
    }
}

fn parsePrefixedHex(comptime prefix: []const u8, key: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, key, prefix)) return null;
    if (key.len != prefix.len + 16) return null;
    return std.fmt.parseInt(u64, key[prefix.len..], 16) catch null;
}

fn writePrefixedHex(comptime prefix: []const u8, value: u64, out: *[prefix.len + 16]u8) []const u8 {
    @memcpy(out[0..prefix.len], prefix);
    const hex = "0123456789abcdef";
    var remaining = value;
    var i: usize = prefix.len + 16;
    while (i > prefix.len) {
        i -= 1;
        out[i] = hex[@intCast(remaining & 0xf)];
        remaining >>= 4;
    }
    return out;
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

fn sampleEvent(account: []const u8, key_id: []const u8, action: kt.Action, ts: i64) kt.Event {
    return .{
        .account = account,
        .kind = .e2ee_device,
        .action = action,
        .key_id = key_id,
        .key_hash = kt.materialHash(key_id),
        .timestamp_ms = ts,
    };
}

test "KEYTRANS store commit restores exact root size and event bodies" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-roundtrip.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 10));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);
    const second = try kt.ownedFromEvent(sampleEvent("alice", "phone", .delete, 20));
    const r2 = try log.appendOwned(second);
    try commit(&store, r2.position, second, r2.root);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(log.len(), restored.len());
    try std.testing.expectEqualSlices(u8, &log.root(), &restored.root());
    const body = try restored.eventAt(0);
    try std.testing.expect(body.eql(&first));
    try std.testing.expectEqualSlices(u8, &kt.eventDigest(first.asEvent()), &body.leaf);
    const latest = try restored.latestEvent("alice", .e2ee_device, "phone");
    try std.testing.expect(latest != null);
    try std.testing.expectEqual(kt.Action.delete, latest.?.event.action);
    try std.testing.expectEqual(@as(u64, 1), (try loadLatestIndex(&store, "alice", .e2ee_device, "phone")).?);
}

test "KEYTRANS store duplicate durable replay does not double-append" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-idempotent.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const owned = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const first = try log.appendOwned(owned);
    try commit(&store, first.position, owned, first.root);
    try commit(&store, first.position, owned, first.root);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expectEqualSlices(u8, &first.root, &restored.root());
}

fn putEventBody(store: *OroStore, position: u64, owned: kt.OwnedEvent) !void {
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);
    var ev_key: [event_key_len]u8 = undefined;
    try store.family(family).put(eventKey(position, &ev_key), body);
}

fn putPrepareMarker(store: *OroStore, position: u64, owned: kt.OwnedEvent, root: kt.Hash) !void {
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);
    try writePrepare(store, position, owned, root, body);
}

fn expectRestoreFails(store: *OroStore, expected: anyerror) !void {
    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expectError(expected, restore(store, &restored));
    try std.testing.expect(restored.unusable);
    try std.testing.expectEqual(@as(usize, 0), restored.len());
}

test "KEYTRANS store event without prepare fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-event-only.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);

    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putEventBody(&store, r2.position, second);
    try expectRestoreFails(&store, error.Corrupt);
    try std.testing.expectEqual(@as(u64, 1), (try loadMeta(&store)).?.size);
}

test "KEYTRANS store corrupt and truncated stores fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-corrupt.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);
    const second = try kt.ownedFromEvent(sampleEvent("alice", "phone", .delete, 2));
    const r2 = try log.appendOwned(second);
    try commit(&store, r2.position, second, r2.root);

    var ev_key: [event_key_len]u8 = undefined;
    try store.family(family).put(eventKey(1, &ev_key), "junk");

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expectError(error.Corrupt, restore(&store, &restored));
    try std.testing.expect(restored.unusable);
    try std.testing.expectEqual(@as(usize, 0), restored.len());
    try std.testing.expectError(error.Unavailable, restored.append(sampleEvent("alice", "x", .bind, 3)));

    try store.family(family).delete(eventKey(1, &ev_key));
    restored.unusable = false;
    try std.testing.expectError(error.Truncated, restore(&store, &restored));
    try std.testing.expect(restored.unusable);
}

test "KEYTRANS store fresh store with no kt1 keys is an empty migrated log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-empty.wal");
    defer store.deinit();
    try store.family(family).put("certfp:deadbeef", "alice");

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    try restore(&store, &log);
    try std.testing.expectEqual(@as(usize, 0), log.len());
    try std.testing.expect(!log.unusable);
}

test "KEYTRANS store restore allocation failure does not leave a partial log" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-oom.wal");
    defer store.deinit();

    var seed = kt.KeyTransparencyLog.init(allocator);
    defer seed.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try seed.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);
    const second = try kt.ownedFromEvent(sampleEvent("bob", "laptop", .bind, 2));
    const r2 = try seed.appendOwned(second);
    try commit(&store, r2.position, second, r2.root);

    const Sweep = struct {
        fn run(failing: std.mem.Allocator, backing: *OroStore) !void {
            var log = kt.KeyTransparencyLog.init(failing);
            defer log.deinit();
            try restore(backing, &log);
            try std.testing.expectEqual(@as(usize, 2), log.len());
            try std.testing.expect(!log.unusable);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Sweep.run, .{&store});
}

test "KEYTRANS store missing checkpoint fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-missing-ckpt.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);

    var ckpt_key: [checkpoint_key_len]u8 = undefined;
    try store.family(family).delete(checkpointKey(1, &ckpt_key));

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expectError(error.Truncated, restore(&store, &restored));
    try std.testing.expect(restored.unusable);
    try std.testing.expectEqual(@as(usize, 0), restored.len());
}

test "KEYTRANS store corrupt checkpoint fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-corrupt-ckpt.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);

    var ckpt_key: [checkpoint_key_len]u8 = undefined;
    try store.family(family).put(checkpointKey(1, &ckpt_key), "junk-checkpoint");

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expectError(error.Corrupt, restore(&store, &restored));
    try std.testing.expect(restored.unusable);
    try std.testing.expectEqual(@as(usize, 0), restored.len());
}

test "KEYTRANS store index mismatch fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-bad-index.wal");
    defer store.deinit();

    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);

    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey("alice", .e2ee_device, "phone", &idx_buf);
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, 9, .little);
    try store.family(family).put(idx_key, &pos_buf);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expectError(error.Corrupt, restore(&store, &restored));
    try std.testing.expect(restored.unusable);
}

fn seedCommitted(store: *OroStore, log: *kt.KeyTransparencyLog, event: kt.Event) !kt.AppendResult {
    const owned = try kt.ownedFromEvent(event);
    const result = try log.appendOwned(owned);
    try commit(store, result.position, owned, result.root);
    return result;
}

test "KEYTRANS store prepare marker binds position leaf body and root" {
    const owned = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);
    var root: kt.Hash = @splat(3);
    const marker = makePrepare(0, owned, root, body);
    try std.testing.expectEqual(@as(u64, 0), marker.position);
    try std.testing.expectEqualSlices(u8, &owned.leaf, &marker.leaf);
    try std.testing.expectEqualSlices(u8, &root, &marker.root);
    try std.testing.expectEqualSlices(u8, &prepareBodyHash(body), &marker.body_hash);
    var buf: [prepare_encoded_len]u8 = undefined;
    const encoded = encodePrepare(marker, &buf);
    const decoded = try decodePrepare(encoded);
    try std.testing.expectEqual(marker.position, decoded.position);
    try std.testing.expectEqualSlices(u8, &marker.commit, &decoded.commit);
    buf[10] ^= 0x01;
    try std.testing.expectError(error.Corrupt, decodePrepare(&buf));
}

test "KEYTRANS store valid prepare and event resumes on restore" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-resume.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 2), restored.len());
    try std.testing.expectEqualSlices(u8, &r2.root, &restored.root());
    try std.testing.expect(try loadPrepare(&store) == null);
    try std.testing.expectEqual(@as(u64, 2), (try loadMeta(&store)).?.size);
}

test "KEYTRANS store marker only fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-marker-only.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store mismatched prepare and event fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-mismatch.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    const other = try kt.ownedFromEvent(sampleEvent("bob", "tablet", .bind, 3));
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, other);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store corrupt prepare marker fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-bad-prepare.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putEventBody(&store, r2.position, second);
    try store.family(family).put(prepare_key, "junk-prepare");
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store corrupt prepare commit fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-bad-prepare-mac.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    const raw = (store.get(family, prepare_key)).?;
    var buf: [prepare_encoded_len]u8 = undefined;
    @memcpy(&buf, raw);
    buf[buf.len - 1] ^= 0xff;
    try store.family(family).put(prepare_key, &buf);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store prepare root mismatch fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-bad-root.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    var wrong_root = r2.root;
    wrong_root[0] ^= 0x01;
    try putPrepareMarker(&store, r2.position, second, wrong_root);
    try putEventBody(&store, r2.position, second);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store extra beyond-meta event fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-extra-event.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    const third = try kt.ownedFromEvent(sampleEvent("carol", "watch", .bind, 3));
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    try putEventBody(&store, 2, third);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store extra checkpoint fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-extra-ckpt.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    var ckpt_key: [checkpoint_key_len]u8 = undefined;
    var ckpt_val: [8 + 32 + 32 + 32]u8 = undefined;
    const extra = FrozenCheckpoint{
        .size = 9,
        .root = @splat(1),
        .last_leaf = @splat(2),
        .commit = checkpointCommit(9, @splat(1), @splat(2)),
    };
    try store.family(family).put(checkpointKey(9, &ckpt_key), encodeCheckpoint(extra, &ckpt_val));
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store extra index fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-extra-index.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey("bob", .e2ee_device, "ghost", &idx_buf);
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, 0, .little);
    try store.family(family).put(idx_key, &pos_buf);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store leftover prepare after complete commit is stale" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-stale-prepare.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const r1 = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    try putPrepareMarker(&store, r1.position, first, r1.root);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expect(try loadPrepare(&store) == null);
}

test "KEYTRANS store mismatched stale prepare fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-stale-mismatch.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const r1 = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    var wrong_root = r1.root;
    wrong_root[0] ^= 0x01;
    // The marker is well-formed and points at the last committed position, but
    // its authenticated root does not match the durable checkpoint/meta.
    try putPrepareMarker(&store, r1.position, first, wrong_root);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store too-old stale prepare fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-stale-too-old.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const r1 = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "laptop", .bind, 2));
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    // Position zero is older than the immediately preceding committed event;
    // even an otherwise exact marker must not be silently cleared.
    try putPrepareMarker(&store, r1.position, first, r1.root);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store abort incomplete cannot advance on restore" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-abort.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    abortPrepare(&store, r2.position, second, null);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expectEqualSlices(u8, &log.events.items[0].leaf, &(try restored.eventAt(0)).leaf);
}

test "KEYTRANS store double abort stays fail-closed and does not advance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-double-abort.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    abortPrepare(&store, r2.position, second, null);
    abortPrepare(&store, r2.position, second, null);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expect(!restored.unusable);
}

test "KEYTRANS store poison row fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-poison.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    markUnavailable(&store);
    try expectRestoreFails(&store, error.Unavailable);
}

test "KEYTRANS store abort after unprovable cleanup poisons the store" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-poison-abort.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putEventBody(&store, r2.position, second);
    abortIncomplete(&store, r2.position, second, null, false, false, false);
    try std.testing.expect(isMarkedUnavailable(&store));
    try expectRestoreFails(&store, error.Unavailable);
}

test "KEYTRANS store prepare plus event plus index resumes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-resume-index.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey(second.account(), second.kind, second.keyId(), &idx_buf);
    var pos_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pos_buf, r2.position, .little);
    try store.family(family).put(idx_key, &pos_buf);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 2), restored.len());
}

test "KEYTRANS store prepare event index and checkpoint resumes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-resume-ckpt.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    try writeCheckpoint(&store, r2.size, r2.root, second.leaf);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 2), restored.len());
    try std.testing.expectEqualSlices(u8, &r2.root, &restored.root());
}

test "KEYTRANS store unknown kt1 row fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-unknown-row.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    try store.family(family).put("kt1:weird", "nope");
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store commit after failed abort does not restore aborted event" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-failed-commit.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, r2.position, second, r2.root);
    try putEventBody(&store, r2.position, second);
    abortPrepare(&store, r2.position, second, null);

    var restored = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer restored.deinit();
    try restore(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.len());
    try std.testing.expectError(error.IndexOutOfRange, restored.eventAt(1));
}

test "KEYTRANS store empty prepare decode rejects short and trailing input" {
    try std.testing.expectError(error.Corrupt, decodePrepare(""));
    try std.testing.expectError(error.Corrupt, decodePrepare("short"));
    var buf: [prepare_encoded_len + 1]u8 = undefined;
    @memset(&buf, 0);
    buf[0] = schema_version;
    try std.testing.expectError(error.Corrupt, decodePrepare(buf[0 .. prepare_encoded_len + 1]));
}

test "KEYTRANS store marker for wrong position fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-wrong-pos.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const second = try kt.ownedFromEvent(sampleEvent("alice", "laptop", .bind, 2));
    const r2 = try log.appendOwned(second);
    try putPrepareMarker(&store, 9, second, r2.root);
    try putEventBody(&store, r2.position, second);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store commit refuses a poisoned store" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-commit-poison.wal");
    defer store.deinit();
    markUnavailable(&store);
    const owned = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    try std.testing.expectError(error.Unavailable, commit(&store, 0, owned, @splat(0)));
}

test "KEYTRANS store duplicate commit of a different body is corrupt" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-dup-body.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    const first = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    const r1 = try log.appendOwned(first);
    try commit(&store, r1.position, first, r1.root);
    const other = try kt.ownedFromEvent(sampleEvent("alice", "phone", .delete, 2));
    try std.testing.expectError(error.Corrupt, commit(&store, r1.position, other, r1.root));
}

test "KEYTRANS store load helpers reject truncated meta and checkpoint" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-trunc-helpers.wal");
    defer store.deinit();
    try store.family(family).put(meta_key, "x");
    try std.testing.expectError(error.Truncated, loadMeta(&store));
    var ckpt_key: [checkpoint_key_len]u8 = undefined;
    try store.family(family).put(checkpointKey(1, &ckpt_key), "yy");
    try std.testing.expectError(error.Corrupt, loadCheckpoint(&store, 1));
}

test "KEYTRANS store index key rejects invalid account and key id" {
    var buf: [index_key_max]u8 = undefined;
    try std.testing.expectError(error.InvalidAccount, indexKey("Alice", .e2ee_device, "phone", &buf));
    try std.testing.expectError(error.InvalidKeyId, indexKey("alice", .e2ee_device, "bad\nid", &buf));
}

test "KEYTRANS store restore twice of a complete log is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-restore-twice.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .delete, 2));
    var a = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer a.deinit();
    try restore(&store, &a);
    var b = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer b.deinit();
    try restore(&store, &b);
    try std.testing.expectEqual(a.len(), b.len());
    try std.testing.expectEqualSlices(u8, &a.root(), &b.root());
}

test "KEYTRANS store event key and checkpoint key are hex stable" {
    var ev: [event_key_len]u8 = undefined;
    var ck: [checkpoint_key_len]u8 = undefined;
    try std.testing.expectEqualStrings("kt1:e:0000000000000000", eventKey(0, &ev));
    try std.testing.expectEqualStrings("kt1:e:000000000000000a", eventKey(10, &ev));
    try std.testing.expectEqualStrings("kt1:c:0000000000000001", checkpointKey(1, &ck));
}

test "KEYTRANS store prepare body hash is blake3 of the encoded event" {
    const owned = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 4));
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);
    var expected: kt.Hash = undefined;
    std.crypto.hash.Blake3.hash(body, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &prepareBodyHash(body));
}

test "KEYTRANS store loadEvent missing position is null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-missing-event.wal");
    defer store.deinit();
    try std.testing.expect(try loadEvent(&store, 0) == null);
    try std.testing.expect(try loadCheckpoint(&store, 1) == null);
    try std.testing.expect(try loadPrepare(&store) == null);
}

test "KEYTRANS store loadLatestIndex missing is null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-missing-index.wal");
    defer store.deinit();
    try std.testing.expect(try loadLatestIndex(&store, "alice", .e2ee_device, "phone") == null);
}

test "KEYTRANS store corrupt index value length fails restore closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-short-index.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    var idx_buf: [index_key_max]u8 = undefined;
    const idx_key = try indexKey("alice", .e2ee_device, "phone", &idx_buf);
    try store.family(family).put(idx_key, "xx");
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store extra event after complete commit fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-extra-complete.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    _ = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    const extra = try kt.ownedFromEvent(sampleEvent("bob", "x", .bind, 9));
    try putEventBody(&store, 1, extra);
    try expectRestoreFails(&store, error.Corrupt);
}

test "KEYTRANS store decodeMeta rejects wrong version" {
    var buf: [41]u8 = @splat(0);
    buf[0] = 9;
    try std.testing.expectError(error.Corrupt, decodeMeta(&buf));
}

test "KEYTRANS store isMarkedUnavailable is false on a fresh store" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-fresh-flag.wal");
    defer store.deinit();
    try std.testing.expect(!isMarkedUnavailable(&store));
}

test "KEYTRANS store checkpoint size zero load is null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-ckpt-zero.wal");
    defer store.deinit();
    try std.testing.expect(try loadCheckpoint(&store, 0) == null);
}

test "KEYTRANS store decodeCheckpoint rejects a bad commit" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u64, buf[0..8], 1, .little);
    try std.testing.expectError(error.Corrupt, decodeCheckpoint(&buf));
}

test "KEYTRANS store encodeMeta round-trips size and root" {
    var buf: [1 + 8 + 32]u8 = undefined;
    var root: kt.Hash = @splat(7);
    const encoded = encodeMeta(.{ .size = 4, .root = root }, &buf);
    const decoded = try decodeMeta(encoded);
    try std.testing.expectEqual(@as(u64, 4), decoded.size);
    try std.testing.expectEqualSlices(u8, &root, &decoded.root);
}

test "KEYTRANS store prepare commit changes when position changes" {
    const owned = try kt.ownedFromEvent(sampleEvent("alice", "phone", .bind, 1));
    var body_buf: [kt.max_encoded_len]u8 = undefined;
    const body = try kt.encodeOwned(owned, &body_buf);
    const a = makePrepare(0, owned, @splat(1), body);
    const b = makePrepare(1, owned, @splat(1), body);
    try std.testing.expect(!std.mem.eql(u8, &a.commit, &b.commit));
}

test "KEYTRANS store empty restore then first commit is position zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "kt-store-empty-then-commit.wal");
    defer store.deinit();
    var log = kt.KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();
    try restore(&store, &log);
    try std.testing.expectEqual(@as(usize, 0), log.len());
    const r = try seedCommitted(&store, &log, sampleEvent("alice", "phone", .bind, 1));
    try std.testing.expectEqual(@as(usize, 0), r.position);
}
