// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Channels.

const std = @import("std");
const store_mod = @import("../store.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const key_max = @import("records.zig").key_max;
const generation_len = @import("records.zig").generation_len;
const access_prefix = @import("records.zig").access_prefix;
const akick_prefix = @import("records.zig").akick_prefix;
const ward_prefix = @import("records.zig").ward_prefix;
const saccess_prefix = @import("records.zig").saccess_prefix;
const channel_access_family = @import("records.zig").channel_access_family;
const ServiceError = @import("records.zig").ServiceError;
const StateHook = @import("records.zig").StateHook;
const AccountName = @import("records.zig").AccountName;
const ChannelName = @import("records.zig").ChannelName;
const AccessLevel = @import("records.zig").AccessLevel;
const ChannelSetField = @import("records.zig").ChannelSetField;
const AccessAction = @import("records.zig").AccessAction;
const AkickAction = @import("records.zig").AkickAction;
const AccessInfo = @import("records.zig").AccessInfo;
const AkickInfo = @import("records.zig").AkickInfo;
const ReplayWard = @import("records.zig").ReplayWard;
const ReplaySaccess = @import("records.zig").ReplaySaccess;
const LiveReplaySummary = @import("records.zig").LiveReplaySummary;
const LiveReplaySink = @import("records.zig").LiveReplaySink;
const CommandResult = @import("records.zig").CommandResult;
const ChannelRecord = @import("records.zig").ChannelRecord;
const AccessRecord = @import("records.zig").AccessRecord;
const AkickRecord = @import("records.zig").AkickRecord;
const validateMlock = @import("records.zig").validateMlock;
const validateReason = @import("records.zig").validateReason;
const validateMask = @import("records.zig").validateMask;
const ward_value_max = @import("records.zig").ward_value_max;
const saccess_key_max = @import("records.zig").saccess_key_max;
const saccess_value_max = @import("records.zig").saccess_value_max;
const accountKey = @import("records.zig").accountKey;
const channelKey = @import("records.zig").channelKey;
const encodeChannel = @import("records.zig").encodeChannel;
const decodeChannel = @import("records.zig").decodeChannel;
const decodeAccess = @import("records.zig").decodeAccess;
const encodeAkick = @import("records.zig").encodeAkick;
const decodeAkick = @import("records.zig").decodeAkick;
const wardKey = @import("records.zig").wardKey;
const encodeWard = @import("records.zig").encodeWard;
const decodeWard = @import("records.zig").decodeWard;
const saccessKey = @import("records.zig").saccessKey;
const encodeSaccess = @import("records.zig").encodeSaccess;
const decodeSaccess = @import("records.zig").decodeSaccess;
const accessKey = @import("records.zig").accessKey;
const akickKey = @import("records.zig").akickKey;
const prefixedKey = @import("records.zig").prefixedKey;
const sameBytes = @import("records.zig").sameBytes;
const persistence_domain = @import("persistence.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    state: *const ?StateHook,

    pub fn registerChannel(self: Context, channel: []const u8, founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const channel_key = try channelKey(channel);
        if (self.store.*.family(.chanregs).get(channel_key.asSlice()) != null) return error.AlreadyExists;
        const founder_key = try accountKey(founder);
        if (self.store.*.family(.accounts).get(founder_key.asSlice()) == null) return error.NotFound;

        var generation: [generation_len]u8 = undefined;
        self.store.*.io.randomSecure(&generation) catch self.store.*.io.random(&generation);

        const record = ChannelRecord{
            .name = ChannelName.init(channel_key.asSlice()) catch return error.InvalidChannel,
            .founder = AccountName.init(founder_key.asSlice()) catch return error.InvalidName,
            .generation = generation,
        };
        const encoded = try encodeChannel(record, scratch);
        try self.store.*.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);

        if (self.state.*) |hook| try hook.createChannel(record.name.asSlice());

        return .{ .registered_channel = record.info() };
    }

    pub fn dropChannel(self: Context, channel: []const u8, actor: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .founder);
        try self.store.*.family(.chanregs).delete(record.name.asSlice());
        if (self.state.*) |hook| try hook.dropChannel(record.name.asSlice());
        return .{ .dropped_channel = .{ .name = record.name } };
    }

    /// Transfer founder ownership of a registered channel. Only the CURRENT founder
    /// may transfer; the new founder must be a registered account. The new founder
    /// also receives an explicit FOUNDER access grant.
    pub fn transferChannel(self: Context, channel: []const u8, actor: []const u8, new_founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        const actor_key = try accountKey(actor);
        if (!std.ascii.eqlIgnoreCase(record.founder.asSlice(), actor_key.asSlice())) return error.Forbidden;
        const nf_key = try accountKey(new_founder);
        if (self.store.*.family(.accounts).get(nf_key.asSlice()) == null) return error.NotFound;

        record.founder = nf_key;
        const encoded = try encodeChannel(record, scratch);
        try self.store.*.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);
        return .{ .registered_channel = record.info() };
    }

    pub fn channelAccess(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
            .grant, .revoke => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
        }
    }

    pub fn channelAccessList(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        out: []AccessInfo,
    ) ServiceError![]AccessInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(access_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.*.maps[@backingInt(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const access = try decodeAccess(entry.value_ptr.*);
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = access.info();
            count += 1;
        }
        return out[0..count];
    }

    pub fn channelAccessUnlocked(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        // Authorize BEFORE probing target-account existence. All three actions
        // require .admin, so hoisting the gate above the `.accounts` lookup
        // closes a registration-enumeration oracle: without it a non-admin
        // actor distinguished a registered target (Forbidden) from an
        // unregistered one (NotFound) on a channel they do not administer.
        try self.requireAccess(record, actor, .admin);
        const target_key = try accountKey(target);
        if (self.store.*.family(.accounts).get(target_key.asSlice()) == null) return error.NotFound;

        switch (action) {
            .query => {
                const access = try self.loadAccess(record, target_key.asSlice());
                return .{ .access = access.info() };
            },
            .grant => {
                if (level == .founder) try self.requireAccess(record, actor, .founder);
                const access = try self.putAccess(record, AccountName.init(target_key.asSlice()) catch return error.InvalidName, level, scratch);
                return .{ .access = access.info() };
            },
            .revoke => {
                try self.requireAccess(record, actor, .admin);
                if (std.mem.eql(u8, target_key.asSlice(), record.founder.asSlice())) return error.Forbidden;
                const existing = try self.loadAccess(record, target_key.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try accessKey(record.name.asSlice(), target_key.asSlice(), &key_buf);
                try self.store.*.delete(channel_access_family, key);
                return .{ .access_revoked = existing.info() };
            },
        }
    }

    pub fn channelAkick(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
            .add, .remove => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
        }
    }

    pub fn channelAkickList(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        out: []AkickInfo,
    ) ServiceError![]AkickInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(akick_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.*.maps[@backingInt(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const akick = try decodeAkick(entry.value_ptr.*);
            if (!sameBytes(generation_len, &akick.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = akick.info();
            count += 1;
        }
        return out[0..count];
    }

    pub fn channelAkickUnlocked(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const clean_mask = try validateMask(mask);
        switch (action) {
            .query => {
                // An AKICK mask + its reason text is moderation state: gate the
                // query with the same .admin requirement as the list-all sibling
                // (channelAkickList) so an actor with no access to the channel
                // cannot read back the ban list mask/reason.
                try self.requireAccess(record, actor, .admin);
                const akick = try self.loadAkick(record, clean_mask.asSlice());
                return .{ .akick = akick.info() };
            },
            .add => {
                try self.requireAccess(record, actor, .admin);
                const actor_key = try accountKey(actor);
                const akick = AkickRecord{
                    .channel = record.name,
                    .mask = clean_mask,
                    .generation = record.generation,
                    .setter = AccountName.init(actor_key.asSlice()) catch return error.InvalidName,
                    .reason = try validateReason(reason),
                };
                const encoded = try encodeAkick(akick, scratch);
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.*.put(channel_access_family, key, encoded);
                return .{ .akick = akick.info() };
            },
            .remove => {
                try self.requireAccess(record, actor, .admin);
                const existing = try self.loadAkick(record, clean_mask.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.*.delete(channel_access_family, key);
                return .{ .akick_removed = existing.info() };
            },
        }
    }

    pub fn setChannel(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        field: ChannelSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        switch (field) {
            .flags => |flags| record.flags = flags,
            .mlock => |spec| record.mlock = try validateMlock(spec),
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.*.family(.chanregs).put(record.name.asSlice(), encoded);
        return .{ .set_channel = record.info() };
    }

    /// Set or clear a single registered-channel boolean flag bit (TOPICLOCK /
    /// GUARD / PRIVATE) while preserving the others. Requires founder-or-admin
    /// ACCESS on the channel. Persists the record so the flag survives recreation.
    pub fn setChannelFlag(
        self: Context,
        channel: []const u8,
        actor: []const u8,
        flag: u32,
        on: bool,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        if (on) {
            record.flags |= flag;
        } else {
            record.flags &= ~flag;
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.*.family(.chanregs).put(record.name.asSlice(), encoded);
    }

    /// True when `flag` is set on `channel`'s registration record. False for an
    /// unregistered channel (read-only, no lock contention on the live path).
    pub fn channelFlagSet(self: Context, channel: []const u8, flag: u32) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const record = self.loadChannel(channel) catch return false;
        return (record.flags & flag) != 0;
    }

    pub fn channelInfo(self: Context, channel: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        return .{ .channel_info = record.info() };
    }

    pub fn channelAccessLevelFor(self: Context, channel: []const u8, account: []const u8) ServiceError!?AccessLevel {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        const key = try accountKey(account);
        if (std.mem.eql(u8, key.asSlice(), record.founder.asSlice())) return .founder;
        const access = self.loadAccess(record, key.asSlice()) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return access.level;
    }

    pub fn persistWard(self: Context, ward: ReplayWard, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(ward.match, ward.pattern, scratch);
        var value_buf: [ward_value_max]u8 = undefined;
        const value = try encodeWard(ward, &value_buf);
        try self.store.*.family(.bans).put(key, value);
    }

    pub fn deleteWard(self: Context, match: []const u8, pattern: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(match, pattern, scratch);
        try self.store.*.family(.bans).delete(key);
    }

    /// Persist (add or replace) one server-level IRCX ACCESS / SACCESS entry so
    /// it survives restart and hot-rebuild. Mirrors `persistWard`: keyed by
    /// `saccess:<type>:<mask>` in the durable `bans` family. Idempotent — a
    /// re-add of the same type+mask overwrites the prior value.
    pub fn persistSaccess(self: Context, entry: ReplaySaccess, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry.entry_type, entry.mask, scratch);
        var value_buf: [saccess_value_max]u8 = undefined;
        const value = try encodeSaccess(entry, &value_buf);
        try self.store.*.family(.bans).put(key, value);
    }

    /// Remove one persisted SACCESS entry by type+mask. Restart-safe: a delete
    /// that mutated the live store is durably reflected.
    pub fn deleteSaccess(self: Context, entry_type: []const u8, mask: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry_type, mask, scratch);
        try self.store.*.family(.bans).delete(key);
    }

    /// Remove all persisted SACCESS entries (optionally one type). Mirrors the
    /// live `ServerAccessStore.clear` so a CLEAR is durable across restart.
    ///
    /// Keys are snapshotted into a caller-owned buffer BEFORE any delete: the
    /// store frees the map-owned key on delete, so deleting straight from a
    /// borrowed iterator key would be a use-after-free (the WAL/changefeed
    /// re-reads the key after the map entry is freed).
    pub fn clearSaccess(self: Context, entry_type: ?[]const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var key_store: [256][saccess_key_max]u8 = undefined;
        var key_lens: [256]usize = undefined;
        var keys_len: usize = 0;
        {
            var it = self.store.*.maps[@backingInt(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                if (!std.mem.startsWith(u8, key, saccess_prefix)) continue;
                if (entry_type) |want| {
                    const decoded = decodeSaccess(entry.value_ptr.*) catch continue;
                    if (!std.ascii.eqlIgnoreCase(decoded.entry_type, want)) continue;
                }
                if (keys_len >= key_store.len or key.len > saccess_key_max) continue;
                @memcpy(key_store[keys_len][0..key.len], key);
                key_lens[keys_len] = key.len;
                keys_len += 1;
            }
        }
        for (0..keys_len) |idx| {
            self.store.*.family(.bans).delete(key_store[idx][0..key_lens[idx]]) catch {};
        }
    }

    /// Invoke `cb(ctx, channel, level)` for every channel where `account` holds a
    /// live access grant — the durable reverse of `channelAccessList`, backing
    /// LISTCHANS. Stale grants (channel dropped, or dropped+re-registered) are
    /// skipped by re-checking the channel's current generation.
    pub fn channelsForAccount(self: Context, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, AccessLevel) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var it = self.store.*.maps[@backingInt(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, access_prefix)) continue;
            const access = decodeAccess(entry.value_ptr.*) catch continue;
            if (!std.ascii.eqlIgnoreCase(access.account.asSlice(), account)) continue;
            const record = self.loadChannel(access.channel.asSlice()) catch continue;
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            cb(ctx, access.channel.asSlice(), access.level);
        }
    }

    pub fn replayLiveState(self: Context, sink: LiveReplaySink) ServiceError!LiveReplaySummary {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var summary = LiveReplaySummary{};
        {
            var it = self.store.*.maps[@backingInt(store_mod.Family.chanregs)].map.iterator();
            while (it.next()) |entry| {
                const record = decodeChannel(entry.value_ptr.*) catch continue;
                try sink.channel(sink.ptr, record.name.asSlice(), record.mlock.asSlice());
                summary.channels += 1;
                if (record.mlock.asSlice().len != 0) summary.mlocks += 1;
            }
        }
        if (sink.akick) |on_akick| {
            var it = self.store.*.maps[@backingInt(channel_access_family)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, akick_prefix)) continue;
                const akick = decodeAkick(entry.value_ptr.*) catch continue;
                const channel = self.loadChannel(akick.channel.asSlice()) catch continue;
                if (!sameBytes(generation_len, &akick.generation, &channel.generation)) continue;
                try on_akick(sink.ptr, akick.channel.asSlice(), akick.mask.asSlice(), akick.reason.asSlice(), akick.setter.asSlice());
                summary.akicks += 1;
            }
        }
        if (sink.ward) |on_ward| {
            var it = self.store.*.maps[@backingInt(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, ward_prefix)) continue;
                const ward = decodeWard(entry.value_ptr.*) catch continue;
                try on_ward(sink.ptr, ward);
                summary.wards += 1;
            }
        }
        if (sink.saccess) |on_saccess| {
            var it = self.store.*.maps[@backingInt(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, saccess_prefix)) continue;
                const sa = decodeSaccess(entry.value_ptr.*) catch continue;
                try on_saccess(sink.ptr, sa);
                summary.saccesses += 1;
            }
        }
        return summary;
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn loadAccess(self: Context, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).loadAccess(channel, account);
    }

    pub fn loadAkick(self: Context, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).loadAkick(channel, mask);
    }

    pub fn loadChannel(self: Context, channel: []const u8) ServiceError!ChannelRecord {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).loadChannel(channel);
    }

    pub fn putAccess(
        self: Context,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).putAccess(channel, account, level, scratch);
    }

    pub fn requireAccess(self: Context, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).requireAccess(channel, actor, needed);
    }
};
