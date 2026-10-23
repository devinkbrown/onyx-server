// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account props.

const std = @import("std");
const store_mod = @import("../store.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const svc_acclist = @import("../svc_acclist.zig");
const OroStore = @import("records.zig").OroStore;
const account_max = @import("records.zig").account_max;
const ServiceError = @import("records.zig").ServiceError;
const recognize_prefix = @import("contracts.zig").recognize_prefix;
const recognize_max_masks = @import("contracts.zig").recognize_max_masks;
const recognize_mask_max = @import("contracts.zig").recognize_mask_max;
const recognize_key_max = @import("contracts.zig").recognize_key_max;
const recognize_value_max = @import("contracts.zig").recognize_value_max;
const RecognizeAdd = @import("contracts.zig").RecognizeAdd;
const metadata_prefix = @import("contracts.zig").metadata_prefix;
const metadata_key_max = @import("contracts.zig").metadata_key_max;
const metadata_value_max = @import("contracts.zig").metadata_value_max;
const metadata_full_key_max = @import("contracts.zig").metadata_full_key_max;
const silence_prefix = @import("contracts.zig").silence_prefix;
const silence_max_masks = @import("contracts.zig").silence_max_masks;
const silence_mask_max = @import("contracts.zig").silence_mask_max;
const silence_key_max = @import("contracts.zig").silence_key_max;
const silence_value_max = @import("contracts.zig").silence_value_max;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,

    pub fn recognizeKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < recognize_prefix.len + account.len) return null;
        @memcpy(buf[0..recognize_prefix.len], recognize_prefix);
        for (account, 0..) |c, i| buf[recognize_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. recognize_prefix.len + account.len];
    }

    pub fn validRecognizeMask(mask: []const u8) bool {
        if (mask.len == 0 or mask.len > recognize_mask_max) return false;
        for (mask) |c| {
            if (c < 0x20 or c == '\n' or c == 0) return false;
        }
        return true;
    }

    /// True if `hostmask` (nick!user@host) matches any recognition mask owned by
    /// `account`. Reads the durable mirror, so it is correct immediately after a
    /// restart with no in-memory warm-up.
    pub fn recognizeMatches(self: Context, account: []const u8, hostmask: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return false;
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const blob = self.store.*.family(.props).get(key) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |mask| {
            if (mask.len != 0 and svc_acclist.globMatch(mask, hostmask)) return true;
        }
        return false;
    }

    /// Copy the newline-joined recognition mask blob for `account` into `out`,
    /// returning the populated slice ("" when none). Used by RECOGNIZE LIST.
    pub fn recognizeBlob(self: Context, account: []const u8, out: []u8) []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return out[0..0];
        const blob = self.store.*.family(.props).get(key) orelse return out[0..0];
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Add `mask` to `account`'s recognition list (durable). Idempotent; bounded
    /// by `recognize_max_masks`.
    pub fn recognizeAdd(self: Context, account: []const u8, mask: []const u8) ServiceError!RecognizeAdd {
        if (!validRecognizeMask(mask)) return .invalid_mask;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return .invalid_mask;
        const existing = self.store.*.family(.props).get(key) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return .already_present;
            count += 1;
        }
        if (count >= recognize_max_masks) return .list_full;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        if (existing.len != 0) {
            w.writeAll(existing) catch return .list_full;
            w.writeAll("\n") catch return .list_full;
        }
        w.writeAll(mask) catch return .list_full;
        try self.store.*.family(.props).put(key, w.buffered());
        return .added;
    }

    /// Remove `mask` from `account`'s recognition list (durable). Returns whether
    /// a mask was actually removed.
    pub fn recognizeDel(self: Context, account: []const u8, mask: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const existing = self.store.*.family(.props).get(key) orelse return false;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(m) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.*.family(.props).delete(key);
        } else {
            try self.store.*.family(.props).put(key, w.buffered());
        }
        return true;
    }

    pub fn metadataAccountPrefix(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < metadata_prefix.len + account.len + 1) return null;
        @memcpy(buf[0..metadata_prefix.len], metadata_prefix);
        for (account, 0..) |c, i| buf[metadata_prefix.len + i] = std.ascii.toLower(c);
        buf[metadata_prefix.len + account.len] = 0;
        return buf[0 .. metadata_prefix.len + account.len + 1];
    }

    pub fn metadataKey(buf: []u8, account: []const u8, key: []const u8) ?[]const u8 {
        if (key.len == 0 or key.len > metadata_key_max) return null;
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return null;
        if (buf.len < prefix.len + key.len) return null;
        @memcpy(buf[0..prefix.len], prefix);
        @memcpy(buf[prefix.len .. prefix.len + key.len], key);
        return buf[0 .. prefix.len + key.len];
    }

    pub fn metadataPut(self: Context, account: []const u8, key: []const u8, value: []const u8, vis_token: []const u8) ServiceError!void {
        if (value.len > metadata_value_max or vis_token.len == 0 or vis_token.len > 16) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        var vb: [metadata_value_max + 24]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        w.writeAll(vis_token) catch return;
        w.writeAll("\x00") catch return;
        w.writeAll(value) catch return;
        try self.store.*.family(.props).put(k, w.buffered());
    }

    pub fn metadataDelete(self: Context, account: []const u8, key: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        try self.store.*.family(.props).delete(k);
    }

    /// Invoke `cb(ctx, key, value, vis_token)` for every durable metadata entry
    /// owned by `account`. Used to restore a user's profile metadata at login.
    pub fn metadataForEach(self: Context, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, []const u8, []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return;
        var it = self.store.*.maps[@backingInt(store_mod.Family.props)].map.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (!std.mem.startsWith(u8, k, prefix)) continue;
            const blob = entry.value_ptr.*;
            const sep = std.mem.indexOfScalar(u8, blob, 0) orelse continue;
            cb(ctx, k[prefix.len..], blob[sep + 1 ..], blob[0..sep]);
        }
    }

    pub fn silenceKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < silence_prefix.len + account.len) return null;
        @memcpy(buf[0..silence_prefix.len], silence_prefix);
        for (account, 0..) |c, i| buf[silence_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. silence_prefix.len + account.len];
    }

    pub fn silencePersistAdd(self: Context, account: []const u8, mask: []const u8) ServiceError!void {
        if (mask.len == 0 or mask.len > silence_mask_max) return;
        for (mask) |c| if (c < 0x20 or c == '\n' or c == 0) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.*.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return;
            count += 1;
        }
        if (count >= silence_max_masks) return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return;
            w.writeAll("\n") catch return;
        }
        w.writeAll(mask) catch return;
        try self.store.*.family(.props).put(k, w.buffered());
    }

    pub fn silencePersistDel(self: Context, account: []const u8, mask: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.*.family(.props).get(k) orelse return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) continue;
            if (remaining != 0) w.writeAll("\n") catch return;
            w.writeAll(m) catch return;
            remaining += 1;
        }
        if (remaining == 0) {
            try self.store.*.family(.props).delete(k);
        } else {
            try self.store.*.family(.props).put(k, w.buffered());
        }
    }

    /// Invoke `cb(ctx, mask)` for each persisted SILENCE mask owned by `account`.
    pub fn silenceForEach(self: Context, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const blob = self.store.*.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |m| {
            if (m.len != 0) cb(ctx, m);
        }
    }
};
