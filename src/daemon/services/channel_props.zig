// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Channel props.

const std = @import("std");
const rwlock = @import("../../substrate/rwlock.zig");
const svc_chanbadwords = @import("../svc_chanbadwords.zig");
const OroStore = @import("records.zig").OroStore;
const account_max = @import("records.zig").account_max;
const channel_max = @import("records.zig").channel_max;
const ServiceError = @import("records.zig").ServiceError;
const successor_hold_ms = @import("records.zig").successor_hold_ms;
const accountKey = @import("records.zig").accountKey;
const chanbadword_prefix = @import("contracts.zig").chanbadword_prefix;
const chanbadword_max = @import("contracts.zig").chanbadword_max;
const chanbadword_pattern_max = @import("contracts.zig").chanbadword_pattern_max;
const chanbadword_key_max = @import("contracts.zig").chanbadword_key_max;
const chanbadword_value_max = @import("contracts.zig").chanbadword_value_max;
const keeptopic_prefix = @import("contracts.zig").keeptopic_prefix;
const keeptopic_key_max = @import("contracts.zig").keeptopic_key_max;
const keeptopic_text_max = @import("contracts.zig").keeptopic_text_max;
const keeptopic_setter_max = @import("contracts.zig").keeptopic_setter_max;
const keeptopic_meta_sentinel = @import("contracts.zig").keeptopic_meta_sentinel;
const keeptopic_meta_version = @import("contracts.zig").keeptopic_meta_version;
const keeptopic_meta_header = @import("contracts.zig").keeptopic_meta_header;
const keeptopic_value_max = @import("contracts.zig").keeptopic_value_max;
const KeepTopicRestore = @import("contracts.zig").KeepTopicRestore;
const successor_prefix = @import("contracts.zig").successor_prefix;
const successor_pending_prefix = @import("contracts.zig").successor_pending_prefix;
const successor_key_max = @import("contracts.zig").successor_key_max;
const successor_pending_key_max = @import("contracts.zig").successor_pending_key_max;
const meta_value_max = @import("contracts.zig").meta_value_max;
const clock_domain = @import("clock.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    clock_override_ms: *const std.atomic.Value(u64),

    pub fn chanBadwordKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < chanbadword_prefix.len + channel.len) return null;
        @memcpy(buf[0..chanbadword_prefix.len], chanbadword_prefix);
        for (channel, 0..) |c, i| buf[chanbadword_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. chanbadword_prefix.len + channel.len];
    }

    pub fn chanBadwordAdd(self: Context, channel: []const u8, pattern: []const u8) ServiceError!bool {
        if (pattern.len == 0 or pattern.len > chanbadword_pattern_max) return false;
        for (pattern) |c| if (c < 0x20 or c == '\n' or c == 0) return false;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.*.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) return false;
            count += 1;
        }
        if (count >= chanbadword_max) return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return false;
            w.writeAll("\n") catch return false;
        }
        w.writeAll(pattern) catch return false;
        try self.store.*.family(.props).put(k, w.buffered());
        return true;
    }

    pub fn chanBadwordDel(self: Context, channel: []const u8, pattern: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.*.family(.props).get(k) orelse return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(p) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.*.family(.props).delete(k);
        } else {
            try self.store.*.family(.props).put(k, w.buffered());
        }
        return true;
    }

    pub fn chanBadwordForEach(self: Context, channel: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return;
        const blob = self.store.*.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| if (p.len != 0) cb(ctx, p);
    }

    /// True if `text` contains any of `channel`'s bad-word patterns. Read directly
    /// from the durable store (correct across restarts, no warm-up).
    pub fn chanBadwordMatches(self: Context, channel: []const u8, text: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const blob = self.store.*.family(.props).get(k) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| {
            if (p.len != 0 and svc_chanbadwords.containsIgnoreCase(text, p)) return true;
        }
        return false;
    }

    pub fn keepTopicKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < keeptopic_prefix.len + channel.len) return null;
        @memcpy(buf[0..keeptopic_prefix.len], keeptopic_prefix);
        for (channel, 0..) |c, i| buf[keeptopic_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. keeptopic_prefix.len + channel.len];
    }

    pub fn chanKeepTopicEnable(self: Context, channel: []const u8, on: bool) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (on) {
            if (self.store.*.family(.props).get(k) == null) try self.store.*.family(.props).put(k, "");
        } else {
            try self.store.*.family(.props).delete(k);
        }
    }

    /// Persist `topic` with the `setter` that set it and `set_at` (Unix seconds)
    /// for `channel` — only when KEEPTOPIC is enabled (key present). Oversize text
    /// (> keeptopic_text_max) is not persisted (unchanged behaviour); the setter
    /// is truncated to keeptopic_setter_max.
    pub fn chanKeepTopicSave(
        self: Context,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
    ) ServiceError!void {
        if (topic.len > keeptopic_text_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (self.store.*.family(.props).get(k) == null) return; // not enabled

        // An empty topic clears the remembered value: store the empty marker so
        // recreation restores nothing, matching the pre-metadata behaviour (a
        // metadata blob is never empty, so `get` returns null for this).
        if (topic.len == 0) {
            try self.store.*.family(.props).put(k, "");
            return;
        }

        const setter_clamped = setter[0..@min(setter.len, keeptopic_setter_max)];
        var blob: [keeptopic_value_max]u8 = undefined;
        blob[0] = keeptopic_meta_sentinel;
        blob[1] = keeptopic_meta_version;
        std.mem.writeInt(i64, blob[2..10], set_at, .little);
        std.mem.writeInt(u16, blob[10..12], @intCast(setter_clamped.len), .little);
        @memcpy(blob[keeptopic_meta_header .. keeptopic_meta_header + setter_clamped.len], setter_clamped);
        const text_off = keeptopic_meta_header + setter_clamped.len;
        @memcpy(blob[text_off .. text_off + topic.len], topic);
        try self.store.*.family(.props).put(k, blob[0 .. text_off + topic.len]);
    }

    /// Return the saved topic for `channel` when KEEPTOPIC is enabled and a
    /// non-empty value is stored; else null. `text`/`setter` slice into `text_out`
    /// / `setter_out`. A legacy (pre-metadata) value returns `setter == null`, so
    /// the caller falls back to serverName()/now — see KeepTopicRestore.
    pub fn chanKeepTopicGet(
        self: Context,
        channel: []const u8,
        text_out: []u8,
        setter_out: []u8,
    ) ?KeepTopicRestore {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return null;
        const blob = self.store.*.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;

        // Versioned blob: decode fail-closed — malformed metadata falls through to
        // the legacy whole-value-is-text interpretation below. A decoded but empty
        // topic restores nothing (mirrors the empty-value case above).
        if (blob[0] == keeptopic_meta_sentinel) {
            if (decodeKeepTopicMeta(blob, text_out, setter_out)) |r| {
                return if (r.text.len == 0) null else r;
            }
        }

        // Legacy value (or malformed metadata): the whole value is the topic text,
        // with no setter/set_at — signal metadata absent.
        const n = @min(blob.len, text_out.len);
        @memcpy(text_out[0..n], blob[0..n]);
        return .{ .text = text_out[0..n], .setter = null, .set_at = 0 };
    }

    /// Decode a sentinel-led KEEPTOPIC value. Every field is bounds-checked; any
    /// malformation (short header, unknown version, setter length past the end)
    /// returns null so the caller falls back to the legacy text-only path.
    pub fn decodeKeepTopicMeta(blob: []const u8, text_out: []u8, setter_out: []u8) ?KeepTopicRestore {
        if (blob.len < keeptopic_meta_header) return null;
        if (blob[1] != keeptopic_meta_version) return null;
        const set_at = std.mem.readInt(i64, blob[2..10], .little);
        const setter_len: usize = std.mem.readInt(u16, blob[10..12], .little);
        const setter_end = keeptopic_meta_header + setter_len;
        if (setter_end > blob.len) return null; // truncated setter
        const setter = blob[keeptopic_meta_header..setter_end];
        const text = blob[setter_end..];
        const sn = @min(setter.len, setter_out.len);
        @memcpy(setter_out[0..sn], setter[0..sn]);
        const tn = @min(text.len, text_out.len);
        @memcpy(text_out[0..tn], text[0..tn]);
        return .{ .text = text_out[0..tn], .setter = setter_out[0..sn], .set_at = set_at };
    }

    pub fn successorKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return successorPrefixedKey(buf, successor_prefix, channel);
    }

    pub fn successorPendingKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return successorPrefixedKey(buf, successor_pending_prefix, channel);
    }

    pub fn successorPrefixedKey(buf: []u8, prefix: []const u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < prefix.len + channel.len) return null;
        @memcpy(buf[0..prefix.len], prefix);
        for (channel, 0..) |c, i| buf[prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. prefix.len + channel.len];
    }

    pub fn promoteReadySuccessorUnlocked(self: Context, armed_key: []const u8, pending_key: []const u8) ServiceError!void {
        const blob = self.store.*.family(.props).get(pending_key) orelse return;
        if (blob.len <= 8 or blob.len > 8 + account_max) return;
        const ready = std.mem.readInt(u64, blob[0..8], .little);
        if (self.servicesNowMs() < ready) return;
        var name_buf: [account_max]u8 = undefined;
        const name_len = blob.len - 8;
        @memcpy(name_buf[0..name_len], blob[8..]);
        try self.store.*.family(.props).put(armed_key, name_buf[0..name_len]);
        try self.store.*.family(.props).delete(pending_key);
    }

    pub fn copyBoundedProp(self: Context, key: []const u8, dest: []u8) ?[]const u8 {
        const blob = self.store.*.family(.props).get(key) orelse return null;
        if (blob.len == 0 or blob.len > dest.len) return null;
        @memcpy(dest[0..blob.len], blob);
        return dest[0..blob.len];
    }

    /// Queue `account` as `channel`'s successor. Replacing an armed successor
    /// waits `successor_hold_ms`. Setting the armed account again cancels that
    /// wait. A clock that cannot represent the deadline arms the name immediately.
    pub fn channelSuccessorSet(self: Context, channel: []const u8, account: []const u8) ServiceError!void {
        const acc = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var armed_key_buf: [successor_key_max]u8 = undefined;
        const armed_key = successorKey(&armed_key_buf, channel) orelse return error.InvalidChannel;
        var pending_key_buf: [successor_pending_key_max]u8 = undefined;
        const pending_key = successorPendingKey(&pending_key_buf, channel) orelse return error.InvalidChannel;
        // A matured replacement is the successor a new hold has to beat. Fold
        // it into the armed key before comparing, or the next SET would hide
        // it behind the previous armed name.
        try self.promoteReadySuccessorUnlocked(armed_key, pending_key);

        var armed_buf: [account_max]u8 = undefined;
        if (self.copyBoundedProp(armed_key, &armed_buf)) |armed| {
            if (std.mem.eql(u8, armed, acc.asSlice())) {
                if (self.store.*.family(.props).get(pending_key) != null) {
                    try self.store.*.family(.props).delete(pending_key);
                }
                return;
            }
        }

        const ready = std.math.add(u64, self.servicesNowMs(), successor_hold_ms) catch {
            try self.store.*.family(.props).put(armed_key, acc.asSlice());
            if (self.store.*.family(.props).get(pending_key) != null) {
                try self.store.*.family(.props).delete(pending_key);
            }
            return;
        };
        var value: [8 + account_max]u8 = undefined;
        std.mem.writeInt(u64, value[0..8], ready, .little);
        const name = acc.asSlice();
        @memcpy(value[8..][0..name.len], name);
        try self.store.*.family(.props).put(pending_key, value[0 .. 8 + name.len]);
    }

    /// Cancel an unready replacement, or remove the armed successor once the
    /// replacement is ready (or when nothing is waiting).
    pub fn channelSuccessorClear(self: Context, channel: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var pending_key_buf: [successor_pending_key_max]u8 = undefined;
        const pending_key = successorPendingKey(&pending_key_buf, channel) orelse return;
        var armed_key_buf: [successor_key_max]u8 = undefined;
        const armed_key = successorKey(&armed_key_buf, channel) orelse return;

        var hold_until: ?u64 = null;
        if (self.store.*.family(.props).get(pending_key)) |blob| {
            if (blob.len > 8 and blob.len <= 8 + account_max) {
                hold_until = std.mem.readInt(u64, blob[0..8], .little);
            }
        }
        if (hold_until) |at| {
            if (self.servicesNowMs() < at) {
                try self.store.*.family(.props).delete(pending_key);
                return;
            }
        }
        if (self.store.*.family(.props).get(pending_key) != null) {
            try self.store.*.family(.props).delete(pending_key);
        }
        if (self.store.*.family(.props).get(armed_key) != null) {
            try self.store.*.family(.props).delete(armed_key);
        }
    }

    /// Copy the successor account into `out`. An unready replacement is hidden.
    /// A ready replacement is the name returned. Null when neither is visible.
    pub fn channelSuccessorGet(self: Context, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var pending_key_buf: [successor_pending_key_max]u8 = undefined;
        if (successorPendingKey(&pending_key_buf, channel)) |pending_key| {
            if (self.store.*.family(.props).get(pending_key)) |blob| {
                if (blob.len > 8 and blob.len <= 8 + account_max) {
                    const ready = std.mem.readInt(u64, blob[0..8], .little);
                    const account = blob[8..];
                    if (self.servicesNowMs() >= ready and out.len != 0) {
                        const n = @min(account.len, out.len);
                        @memcpy(out[0..n], account[0..n]);
                        return out[0..n];
                    }
                }
            }
        }
        var armed_key_buf: [successor_key_max]u8 = undefined;
        const armed_key = successorKey(&armed_key_buf, channel) orelse return null;
        const blob = self.store.*.family(.props).get(armed_key) orelse return null;
        if (blob.len == 0 or out.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    pub fn metaKey(buf: []u8, tag: []const u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < tag.len + channel.len) return null;
        @memcpy(buf[0..tag.len], tag);
        for (channel, 0..) |c, i| buf[tag.len + i] = std.ascii.toLower(c);
        return buf[0 .. tag.len + channel.len];
    }

    pub fn chanMetaSet(self: Context, tag: []const u8, channel: []const u8, value: []const u8) ServiceError!void {
        if (value.len > meta_value_max) return error.InvalidChannel;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return error.InvalidChannel;
        if (value.len == 0) {
            try self.store.*.family(.props).delete(k);
        } else {
            try self.store.*.family(.props).put(k, value);
        }
    }

    pub fn chanMetaGet(self: Context, tag: []const u8, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return null;
        const blob = self.store.*.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Set (or clear, when empty) `channel`'s human description (CHANNEL SET DESC).
    pub fn chanDescSet(self: Context, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("desc\x00", channel, value);
    }

    /// Copy `channel`'s description into `out`, or null if unset.
    pub fn chanDescGet(self: Context, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("desc\x00", channel, out);
    }

    /// Set (or clear, when empty) `channel`'s homepage URL (CHANNEL SET URL).
    pub fn chanUrlSet(self: Context, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("url\x00", channel, value);
    }

    /// Copy `channel`'s URL into `out`, or null if unset.
    pub fn chanUrlGet(self: Context, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("url\x00", channel, out);
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn servicesNowMs(self: Context) u64 {
        return (clock_domain.Context{ .store = self.store, .clock_override_ms = self.clock_override_ms }).servicesNowMs();
    }
};
