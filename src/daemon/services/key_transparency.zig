// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key transparency.

const std = @import("std");
const key_transparency = @import("../key_transparency.zig");
const key_transparency_store = @import("../key_transparency_store.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const accountKey = @import("records.zig").accountKey;
const KeyTransparencyStatus = @import("contracts.zig").KeyTransparencyStatus;
const KeyTransparencyProofStep = @import("contracts.zig").KeyTransparencyProofStep;
const KeyTransparencyProofSnapshot = @import("contracts.zig").KeyTransparencyProofSnapshot;
const KeyTransparencyEventSnapshot = @import("contracts.zig").KeyTransparencyEventSnapshot;
const KeyTransparencyDeviceSnapshot = @import("contracts.zig").KeyTransparencyDeviceSnapshot;
const KeyTransparencyRecordError = @import("contracts.zig").KeyTransparencyRecordError;
const ObservationOrigin = @import("contracts.zig").ObservationOrigin;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    key_transparency: *const ?*key_transparency.KeyTransparencyLog,

    /// Return the observational log root/size for status surfaces. This is
    /// not current/authoritative credential state.
    pub fn keyTransparencyStatus(self: Context) KeyTransparencyStatus {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency.* orelse return .{ .enabled = false };
        if (log.unusable) return .{ .enabled = true, .available = false };
        return .{
            .enabled = true,
            .available = true,
            .entries = log.len(),
            .root = log.root(),
        };
    }

    pub fn storeKeyTransparencyHead(self: Context, head: key_transparency.SignedHead) (error{ Disabled, Unavailable, BadSignature, KeyMismatch, BadHead, StaleHead } || std.mem.Allocator.Error)!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const log = self.key_transparency.* orelse return error.Disabled;
        if (log.unusable) return error.Unavailable;
        try log.storePeerHead(head);
    }

    /// Unsigned summary of this node's own log. The caller signs it with the
    /// node identity. An empty log is `Empty` so anti-entropy sends nothing.
    pub fn keyTransparencyUnsignedLocalHead(self: Context, node_id: u64) (error{ Disabled, Unavailable, Empty, BadHead } || std.mem.Allocator.Error)!key_transparency.SignedHead {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const log = self.key_transparency.* orelse return error.Disabled;
        if (log.unusable) return error.Unavailable;
        if (log.len() == 0) return error.Empty;
        const last = log.eventAt(log.len() - 1) catch return error.Unavailable;
        const action: key_transparency.HeadAction = switch (last.action) {
            .bind => .bind,
            .delete => .delete,
        };
        return key_transparency.headFromParts(node_id, log.len(), log.root(), action, last.keyId());
    }

    pub fn keyTransparencyPeerHead(self: Context, node_id: u64) error{ Disabled, Unavailable }!?key_transparency.SignedHead {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const log = self.key_transparency.* orelse return error.Disabled;
        if (log.unusable) return error.Unavailable;
        return log.peerHead(node_id);
    }

    /// Copy an inclusion proof for `position` into caller-owned memory. The
    /// returned snapshot is stable after the services lock releases.
    pub fn keyTransparencyProof(self: Context, allocator: std.mem.Allocator, position: usize) (std.mem.Allocator.Error || error{ Disabled, Unavailable, IndexOutOfRange })!KeyTransparencyProofSnapshot {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency.* orelse return error.Disabled;
        var proof = log.proof(position) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.IndexOutOfRange => return error.IndexOutOfRange,
            error.Unavailable => return error.Unavailable,
        };
        defer proof.deinit(log.tree.allocator);

        const path = try allocator.alloc(KeyTransparencyProofStep, proof.path.len);
        errdefer allocator.free(path);
        for (proof.path, 0..) |step, i| {
            path[i] = .{ .side = step.side, .hash = step.hash };
        }

        const peaks = try allocator.alloc(key_transparency.Hash, proof.peaks.len);
        errdefer allocator.free(peaks);
        @memcpy(peaks, proof.peaks);

        return .{
            .position = position,
            .size = log.len(),
            .root = log.root(),
            .path = path,
            .peaks = peaks,
        };
    }

    /// Copy the immutable event body at `position`. The snapshot does not
    /// include raw credential material — only the canonical account, kind,
    /// action, key id, material hash, timestamp, and leaf hash.
    pub fn keyTransparencyEvent(
        self: Context,
        position: usize,
    ) error{ Disabled, Unavailable, IndexOutOfRange }!KeyTransparencyEventSnapshot {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency.* orelse return error.Disabled;
        const event = log.eventAt(position) catch |err| switch (err) {
            error.Unavailable => return error.Unavailable,
            error.IndexOutOfRange => return error.IndexOutOfRange,
        };
        return .{
            .position = position,
            .size = log.len(),
            .root = log.root(),
            .event = event,
        };
    }

    /// Latest observed E2EE-device action for the server-canonical account.
    /// Observational / node-local: not current, bound, or authoritative.
    pub fn keyTransparencyDevice(
        self: Context,
        account: []const u8,
        device_id: []const u8,
    ) error{ Disabled, Unavailable, InvalidName, InvalidKeyId, NotFound }!KeyTransparencyDeviceSnapshot {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency.* orelse return error.Disabled;
        const canonical = accountKey(account) catch return error.InvalidName;
        const found = log.latestDeviceObservation(canonical.asSlice(), device_id) catch |err| switch (err) {
            error.Unavailable => return error.Unavailable,
            error.InvalidAccount => return error.InvalidName,
            error.InvalidKeyId => return error.InvalidKeyId,
        };
        const row = found orelse return error.NotFound;
        return .{
            .position = row.position,
            .size = log.len(),
            .root = log.root(),
            .observation = row.observation,
            .event = row.event,
        };
    }

    /// Exact durable-checkpoint comparison for `old_size`. O(1) `kt1:c:<size>`
    /// lookup; never reallocates a prefix under this lock. Missing/corrupt
    /// checkpoints fail closed. This is not a compact MMR consistency proof.
    pub fn keyTransparencyConsistency(
        self: Context,
        old_size: usize,
    ) (key_transparency.ConsistencyError || error{Disabled})!key_transparency.PrefixComparison {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency.* orelse return error.Disabled;
        if (log.unusable) return error.Unavailable;
        if (old_size > log.len()) return error.SizeAhead;
        if (old_size == 0) return log.compareCheckpoint(0, null);
        const loaded = key_transparency_store.loadCheckpoint(self.store.*, old_size) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unavailable => return error.Unavailable,
            else => return error.Corrupt,
        };
        const row = loaded orelse return error.UnknownCheckpoint;
        return log.compareCheckpoint(old_size, .{
            .root = row.root,
            .last_leaf = row.last_leaf,
        });
    }

    /// Best-effort observational append. PROP/mesh callers must not treat
    /// failure as a mutation rollback. A durable miss marks the log unusable.
    /// `material` is hashed for binds. Deletes hash the canonical tombstone
    /// fact identity (`hlc` + origin), never fabricated current state.
    pub fn observeKeyTransparencyEvent(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        self.observeKeyTransparencyFact(
            account,
            kind,
            action,
            key_id,
            material,
            timestamp_ms,
            null,
        );
    }

    pub fn observeKeyTransparencyFact(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
        origin: ?ObservationOrigin,
    ) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const canonical = accountKey(account) catch return;
        const key_hash = observationFactHash(
            canonical.asSlice(),
            kind,
            action,
            key_id,
            material,
            origin,
        );
        self.commitKeyTransparencyHashed(
            canonical.asSlice(),
            kind,
            action,
            key_id,
            key_hash,
            timestamp_ms,
        ) catch {};
    }

    /// Append an observational event for a credential stored outside the
    /// account service's own tables (signed E2EE/identity user PROP facts).
    /// Exact event identity is the canonical digest; a replay of the same
    /// bytes is a no-op. Failure is returned for explicit callers/tests.
    /// Local PROP mutations must use `observeKeyTransparencyEvent` and must
    /// not roll back a successful prop write.
    pub fn recordExternalKeyTransparencyEvent(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const canonical = accountKey(account) catch return error.InvalidName;
        try self.commitKeyTransparency(
            canonical.asSlice(),
            kind,
            action,
            key_id,
            material,
            timestamp_ms,
        );
    }

    pub fn observationFactHash(
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        origin: ?ObservationOrigin,
    ) key_transparency.Hash {
        if (origin) |src| {
            return key_transparency.factObservationHash(.{
                .account = account,
                .kind = kind,
                .action = action,
                .key_id = key_id,
                .hlc = src.hlc,
                .origin_node = src.origin_node,
                .origin_pubkey = src.origin_pubkey,
            }, material);
        }
        return key_transparency.materialHash(material);
    }

    pub fn recordKeyTransparency(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        self.commitKeyTransparency(account, kind, action, key_id, material, timestamp_ms) catch {};
    }

    pub fn commitKeyTransparency(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        return self.commitKeyTransparencyHashed(
            account,
            kind,
            action,
            key_id,
            key_transparency.materialHash(material),
            timestamp_ms,
        );
    }

    pub fn commitKeyTransparencyHashed(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        key_hash: key_transparency.Hash,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        const log = self.key_transparency.* orelse return;
        if (log.unusable) return error.Unavailable;
        const canonical = accountKey(account) catch return error.InvalidName;
        const event = key_transparency.Event{
            .account = canonical.asSlice(),
            .kind = kind,
            .action = action,
            .key_id = key_id,
            .key_hash = key_hash,
            .timestamp_ms = timestamp_ms,
        };
        const owned = try key_transparency.ownedFromEvent(event);
        if (log.hasDigest(owned.leaf)) return;
        const result = try log.appendOwned(owned);
        if (result.duplicate) return;
        key_transparency_store.commit(self.store.*, result.position, owned, result.root) catch |err| {
            // Observational: do not roll back a recorded observation. Durable
            // miss makes the log unavailable rather than inventing a successful
            // undo of a mutation the caller may already have applied.
            log.unusable = true;
            return err;
        };
    }
};
