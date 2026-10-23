// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webpush.

const std = @import("std");
const store_mod = @import("../store.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const webpush_mod = @import("../webpush.zig");
const OroStore = @import("records.zig").OroStore;
const account_max = @import("records.zig").account_max;
const ServiceError = @import("records.zig").ServiceError;
const secureZero = @import("records.zig").secureZero;
const accountKey = @import("records.zig").accountKey;
const canonicalAccount = @import("records.zig").canonicalAccount;
const webpush_prefix = @import("contracts.zig").webpush_prefix;
const webpush_key_max = @import("contracts.zig").webpush_key_max;
const webpush_value_max = @import("contracts.zig").webpush_value_max;
const WebpushPruneResult = @import("contracts.zig").WebpushPruneResult;
const WebpushPruneRow = @import("contracts.zig").WebpushPruneRow;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,

    pub fn webpushKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < webpush_prefix.len + account.len) return null;
        @memcpy(buf[0..webpush_prefix.len], webpush_prefix);
        for (account, 0..) |c, i| buf[webpush_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. webpush_prefix.len + account.len];
    }

    /// Copy of the account's stored subscription blob (caller frees), or null.
    pub fn webpushGetAlloc(self: Context, allocator: std.mem.Allocator, account: []const u8) ?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, account) orelse return null;
        const blob = self.store.*.family(.props).get(k) orelse return null;
        return allocator.dupe(u8, blob) catch null;
    }

    /// Exact stored blob copy. Missing state alone returns null; source poison,
    /// invalid names and allocator failure remain explicit. Decode remains the
    /// typed consumer's obligation and malformed data is never called absent.
    pub fn webpushGetAllocStrict(self: Context, allocator: std.mem.Allocator, account: []const u8) (ServiceError || std.mem.Allocator.Error)!?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        const canonical = try accountKey(account);
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, canonical.asSlice()) orelse return error.InvalidName;
        const blob = self.store.*.family(.props).get(k) orelse return null;
        return try allocator.dupe(u8, blob);
    }

    /// Replace the account's subscription blob; empty blob deletes the record.
    pub fn webpushPut(self: Context, account: []const u8, blob: []const u8) ServiceError!void {
        if (blob.len > webpush_value_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, account) orelse return;
        if (blob.len == 0) {
            try self.store.*.family(.props).delete(k);
        } else {
            try self.store.*.family(.props).put(k, blob);
        }
    }

    /// Closed shared-context dispatch cannot turn invalid/oversized input into
    /// an accepted no-op. The actual source lock and fixed webpush namespace
    /// protect the original Store; these keys cannot address authority rows.
    /// All fallible staging precedes synced no-fail RAM publication. Ambiguous
    /// IO retains prior live state and poisons this exact Store until cold open.
    pub fn webpushPutStrict(self: Context, account: []const u8, blob: []const u8) ServiceError!void {
        if (blob.len > webpush_value_max) return error.InvalidValue;
        const canonical = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, canonical.asSlice()) orelse return error.InvalidName;
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .props, .kind = if (blob.len == 0) .delete else .put, .key = k, .value = if (blob.len == 0) null else blob },
        });
        defer prepared.abort();
        try prepared.commit();
    }

    /// Prune an original worker-owned dead-endpoint cut from EVERY actual
    /// private Webpush row in this Services' Store. The caller retains that
    /// cut until this entire operation succeeds; no input ownership is taken.
    /// All namespace rows strictly decode before the first mutation. Each
    /// prepared group is synced before publication. A later failure can leave
    /// a durable prefix of groups; retrying the complete cut is idempotent.
    /// Ambiguous write/sync poisons the original Store and requires cold reopen.
    /// The serialized Services lock also excludes concurrent subscription edits.
    pub fn webpushPruneDead(self: Context, allocator: std.mem.Allocator, endpoints: []const []const u8) !WebpushPruneResult {
        return self.webpushPruneDeadImpl(allocator, endpoints, null);
    }

    /// Lifecycle consumer variant: use the original absolute source deadline.
    /// Deadline checks precede each staged row and each prepared commit. A
    /// completed sync can still leave a durable prefix before a later timeout;
    /// fsync itself is not made cancelable by this admission check.
    pub fn webpushPruneDeadUntil(self: Context, allocator: std.mem.Allocator, endpoints: []const []const u8, deadline: std.Io.Clock.Timestamp) !WebpushPruneResult {
        if (deadline.clock != .awake) return error.InvalidDeadline;
        return self.webpushPruneDeadImpl(allocator, endpoints, deadline);
    }

    pub fn requireWebpushPruneDeadline(self: Context, deadline: ?std.Io.Clock.Timestamp) !void {
        if (deadline) |until| if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(self.store.*.io, .awake), .gte, until)) return error.Timeout;
    }

    pub fn webpushPruneDeadImpl(self: Context, allocator: std.mem.Allocator, endpoints: []const []const u8, deadline: ?std.Io.Clock.Timestamp) !WebpushPruneResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        try self.requireWebpushPruneDeadline(deadline);
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        for (endpoints) |endpoint| if (!webpush_mod.validEndpoint(endpoint)) return error.InvalidValue;
        if (endpoints.len == 0) return .{};

        var rows: std.ArrayListUnmanaged(WebpushPruneRow) = .empty;
        defer {
            for (rows.items) |row| if (row.blob) |blob| {
                std.crypto.secureZero(u8, blob);
                allocator.free(blob);
            };
            rows.deinit(allocator);
        }
        var result: WebpushPruneResult = .{};
        var iterator = self.store.*.maps[@backingInt(store_mod.Family.props)].map.iterator();
        while (iterator.next()) |entry| {
            try self.requireWebpushPruneDeadline(deadline);
            const key = entry.key_ptr.*;
            if (!std.mem.startsWith(u8, key, webpush_prefix)) continue;
            const account = key[webpush_prefix.len..];
            const canonical = canonicalAccount(account) catch return error.InvalidRecord;
            if (!std.mem.eql(u8, canonical.asSlice(), account)) return error.InvalidRecord;
            const blob = entry.value_ptr.*;
            if (blob.len == 0 or blob.len > webpush_value_max) return error.InvalidRecord;
            const subs = try webpush_mod.decodeList(allocator, blob);
            defer {
                for (subs) |*sub| std.crypto.secureZero(u8, &sub.auth);
                webpush_mod.freeList(allocator, subs);
            }
            if (subs.len == 0 or subs.len > webpush_mod.max_subscriptions_per_account) return error.InvalidRecord;
            var kept: [webpush_mod.max_subscriptions_per_account]webpush_mod.Subscription = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&kept));
            var count: usize = 0;
            for (subs, 0..) |sub, index| {
                if (!webpush_mod.validEndpoint(sub.endpoint)) return error.InvalidRecord;
                for (subs[0..index]) |previous| if (std.mem.eql(u8, previous.endpoint, sub.endpoint)) return error.InvalidRecord;
                var dead = false;
                for (endpoints) |endpoint| if (std.mem.eql(u8, sub.endpoint, endpoint)) {
                    dead = true;
                    break;
                };
                if (!dead) {
                    kept[count] = sub;
                    count += 1;
                }
            }
            result.rows_examined = try std.math.add(usize, result.rows_examined, 1);
            if (count == subs.len) continue;
            const next_rows_changed = try std.math.add(usize, result.rows_changed, 1);
            const next_removed = try std.math.add(usize, result.subscriptions_removed, subs.len - count);
            var row: WebpushPruneRow = .{ .key = undefined, .key_len = key.len, .blob = null };
            @memcpy(row.key[0..key.len], key);
            if (count != 0) row.blob = try webpush_mod.encodeList(allocator, kept[0..count]);
            errdefer if (row.blob) |owned| {
                std.crypto.secureZero(u8, owned);
                allocator.free(owned);
            };
            try rows.append(allocator, row);
            result.rows_changed = next_rows_changed;
            result.subscriptions_removed = next_removed;
        }
        // Keys/blobs are independent of the Store iterator and of earlier
        // committed rows. Prepared WAL preflight/compaction may replace tables.
        std.mem.sort(WebpushPruneRow, rows.items, {}, WebpushPruneRow.before);
        var offset: usize = 0;
        while (offset < rows.items.len) {
            try self.requireWebpushPruneDeadline(deadline);
            // Current OroStore prepared groups support at most four mutations.
            var mutations: [4]store_mod.BatchMutation = undefined;
            const count = @min(mutations.len, rows.items.len - offset);
            for (rows.items[offset..][0..count], mutations[0..count]) |*row, *mutation| mutation.* = .{
                .family = .props,
                .kind = if (row.blob != null) .put else .delete,
                .key = row.key[0..row.key_len],
                .value = row.blob,
            };
            var prepared = try self.store.*.prepareBatch(mutations[0..count]);
            defer prepared.deinit();
            try self.requireWebpushPruneDeadline(deadline);
            try prepared.commit();
            offset += count;
        }
        return result;
    }
};
