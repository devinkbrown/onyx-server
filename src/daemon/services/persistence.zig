// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence.

const std = @import("std");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const ScramStore = @import("records.zig").ScramStore;
const key_max = @import("records.zig").key_max;
const generation_len = @import("records.zig").generation_len;
const channel_access_family = @import("records.zig").channel_access_family;
const ServiceError = @import("records.zig").ServiceError;
const AccountName = @import("records.zig").AccountName;
const AccessLevel = @import("records.zig").AccessLevel;
const account_flag_suspended = @import("records.zig").account_flag_suspended;
const account_flag_forbidden = @import("records.zig").account_flag_forbidden;
const AccountRecord = @import("records.zig").AccountRecord;
const ChannelRecord = @import("records.zig").ChannelRecord;
const AccessRecord = @import("records.zig").AccessRecord;
const AkickRecord = @import("records.zig").AkickRecord;
const forbidden_account_key_max = @import("records.zig").forbidden_account_key_max;
const forbiddenAccountKey = @import("records.zig").forbiddenAccountKey;
const scram_key_max = @import("records.zig").scram_key_max;
const scramKey = @import("records.zig").scramKey;
const accountKey = @import("records.zig").accountKey;
const channelKey = @import("records.zig").channelKey;
const encodeAccount = @import("records.zig").encodeAccount;
const decodeAccount = @import("records.zig").decodeAccount;
const decodeChannel = @import("records.zig").decodeChannel;
const encodeAccess = @import("records.zig").encodeAccess;
const decodeAccess = @import("records.zig").decodeAccess;
const decodeAkick = @import("records.zig").decodeAkick;
const accessKey = @import("records.zig").accessKey;
const akickKey = @import("records.zig").akickKey;
const sameBytes = @import("records.zig").sameBytes;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,

    /// Force the backing OroStore into a compact snapshot for external backup.
    /// The caller may copy `store.snapshot_path` after this returns. Serialized with
    /// normal services mutations so the snapshot represents a whole store state.
    pub fn compactStoreForBackup(self: Context) !void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        try self.store.*.snapshotAndTruncate();
    }

    /// Mirror an account's derived SCRAM tuple into the durable store, keyed by
    /// account. Serializes BOTH the SHA-256 and (when provisioned) SHA-512
    /// material in a single backward-compatible record so a SCRAM-SHA-256 OR
    /// SCRAM-SHA-512 login resolves after a restart. Best-effort; the in-memory
    /// SCRAM store is authoritative live.
    pub fn persistScram(self: Context, scram: *ScramStore, account: []const u8) void {
        const rec256 = scram.lookup(account) orelse return;
        var full = ScramStore.FullRecord{
            .salt = rec256.salt,
            .iterations = rec256.iterations,
            .stored_key = rec256.stored_key,
            .server_key = rec256.server_key,
        };
        if (scram.lookup512(account)) |rec512| {
            full.has_512 = true;
            full.stored_key_512 = rec512.stored_key;
            full.server_key_512 = rec512.server_key;
        }
        var vbuf: [ScramStore.serialized_max]u8 = undefined;
        const value = ScramStore.serializeFullRecord(full, &vbuf) orelse return;
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return;
        self.store.*.family(.props).put(key, value) catch {};
    }

    pub fn accountSuspendedUnlocked(self: Context, account: []const u8) ServiceError!bool {
        const key = try accountKey(account);
        const value = self.store.*.family(.accounts).get(key.asSlice()) orelse return false;
        const record = try decodeAccount(value);
        return (record.flags & account_flag_suspended) != 0;
    }

    pub fn accountForbiddenUnlocked(self: Context, account: []const u8) bool {
        const key = accountKey(account) catch return false;
        if (self.store.*.family(.accounts).get(key.asSlice())) |value| {
            const record = decodeAccount(value) catch return false;
            if ((record.flags & account_flag_forbidden) != 0) return true;
        }
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return false;
        return self.store.*.family(.props).get(reservation_key) != null;
    }

    pub fn loadAccount(self: Context, name: []const u8) ServiceError!AccountRecord {
        const key = try accountKey(name);
        const value = self.store.*.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        return decodeAccount(value);
    }

    pub fn saveAccount(self: Context, record: AccountRecord, scratch: []u8) ServiceError!void {
        const encoded = try encodeAccount(record, scratch);
        try self.store.*.family(.accounts).put(record.name.asSlice(), encoded);
    }

    pub fn loadChannel(self: Context, channel: []const u8) ServiceError!ChannelRecord {
        const key = try channelKey(channel);
        const value = self.store.*.family(.chanregs).get(key.asSlice()) orelse return error.NotFound;
        return decodeChannel(value);
    }

    /// Whether `channel` has a durable registration (a `.chanregs` record).
    /// Used to decide a channel still "exists" for stats even when momentarily
    /// empty; a malformed name is simply not registered.
    pub fn channelIsRegistered(self: Context, channel: []const u8) bool {
        const key = channelKey(channel) catch return false;
        return self.store.*.family(.chanregs).get(key.asSlice()) != null;
    }

    pub fn putAccess(
        self: Context,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        const record = AccessRecord{
            .channel = channel.name,
            .account = account,
            .generation = channel.generation,
            .level = level,
        };
        const encoded = try encodeAccess(record, scratch);
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account.asSlice(), &key_buf);
        try self.store.*.put(channel_access_family, key, encoded);
        return record;
    }

    pub fn loadAccess(self: Context, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account, &key_buf);
        const value = self.store.*.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAccess(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    pub fn loadAkick(self: Context, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try akickKey(channel.name.asSlice(), mask, &key_buf);
        const value = self.store.*.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAkick(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    pub fn requireAccess(self: Context, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        const actor_key = try accountKey(actor);
        if (std.mem.eql(u8, actor_key.asSlice(), channel.founder.asSlice())) return;
        const access = self.loadAccess(channel, actor_key.asSlice()) catch |err| switch (err) {
            error.NotFound => return error.Forbidden,
            else => return err,
        };
        if (!access.level.allows(needed)) return error.Forbidden;
    }
};
