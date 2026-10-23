// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Channels regression tests.

const std = @import("std");
const record_max = @import("records.zig").record_max;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const Internal = @import("core.zig").Internal;
const ServiceError = @import("records.zig").ServiceError;
const AccessLevel = @import("records.zig").AccessLevel;
const keeptopic_key_max = @import("contracts.zig").keeptopic_key_max;
const channel_max = @import("records.zig").channel_max;
const mlock_max = @import("records.zig").mlock_max;
const mask_max = @import("records.zig").mask_max;
const reason_max = @import("records.zig").reason_max;
const ReplayWard = @import("records.zig").ReplayWard;
const ReplaySaccess = @import("records.zig").ReplaySaccess;
const saccess_key_max = @import("records.zig").saccess_key_max;
const saccess_value_max = @import("records.zig").saccess_value_max;
const saccessKey = @import("records.zig").saccessKey;
const encodeSaccess = @import("records.zig").encodeSaccess;
const decodeSaccess = @import("records.zig").decodeSaccess;
const channel_flag_topiclock = @import("records.zig").channel_flag_topiclock;
const channel_flag_guard = @import("records.zig").channel_flag_guard;
const channel_flag_private = @import("records.zig").channel_flag_private;

test "channelsForAccount: durable reverse access lookup (LISTCHANS)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-listchans.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);
    _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);

    var count: usize = 0;
    var found_op = false;
    const Ctx = struct { count: *usize, found: *bool };
    services.channelsForAccount("BOB", Ctx{ .count = &count, .found = &found_op }, struct {
        fn cb(c: Ctx, channel: []const u8, level: AccessLevel) void {
            c.count.* += 1;
            if (std.ascii.eqlIgnoreCase(channel, "#onyx") and level == .op) c.found.* = true;
        }
    }.cb);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(found_op);
}

test "channel bad-words: add/match/remove persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(try services.chanBadwordAdd("#chan", "spam"));
        try std.testing.expect(try services.chanBadwordAdd("#chan", "scam"));
        try std.testing.expect(!try services.chanBadwordAdd("#CHAN", "SPAM")); // case-insensitive dup
        try std.testing.expect(services.chanBadwordMatches("#chan", "buy this SpAm now"));
        try std.testing.expect(!services.chanBadwordMatches("#chan", "a clean message"));
        try std.testing.expect(try services.chanBadwordDel("#chan", "spam"));
    }
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(!services.chanBadwordMatches("#chan", "buy this spam now")); // removed
        try std.testing.expect(services.chanBadwordMatches("#chan", "a scam here")); // survived
    }
}

test "keeptopic: enable/save/get persist across reopen; save is a no-op when off" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [128]u8 = undefined;
        var s: [128]u8 = undefined;
        // off by default; save does nothing while off
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
        try services.chanKeepTopicSave("#chan", "ignored", "nick!u@h", 100);
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
        // enable then save
        try services.chanKeepTopicEnable("#chan", true);
        try services.chanKeepTopicSave("#chan", "the topic", "nick!u@h", 100);
        const got = services.chanKeepTopicGet("#CHAN", &t, &s) orelse return error.TestUnexpectedResult; // case-insensitive
        try std.testing.expectEqualStrings("the topic", got.text);
    }
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [128]u8 = undefined;
        var s: [128]u8 = undefined;
        const got = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("the topic", got.text); // survived reopen
        try std.testing.expectEqualStrings("nick!u@h", got.setter.?);
        try std.testing.expectEqual(@as(i64, 100), got.set_at);
        try services.chanKeepTopicEnable("#chan", false);
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null); // disabled -> gone
    }
}

test "keeptopic: setter and set-time round-trip exactly, and survive reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-keeptopic-meta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.chanKeepTopicEnable("#chan", true);
        try services.chanKeepTopicSave("#chan", "hello world", "alice!a@host.example", 1_700_000_000);
        var t: [512]u8 = undefined;
        var s: [256]u8 = undefined;
        const r = services.chanKeepTopicGet("#CHAN", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("hello world", r.text);
        try std.testing.expectEqualStrings("alice!a@host.example", r.setter.?);
        try std.testing.expectEqual(@as(i64, 1_700_000_000), r.set_at);
    }
    {
        var store = try openTestStore(tmp, "services-keeptopic-meta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [512]u8 = undefined;
        var s: [256]u8 = undefined;
        const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("hello world", r.text); // survived reopen
        try std.testing.expectEqualStrings("alice!a@host.example", r.setter.?);
        try std.testing.expectEqual(@as(i64, 1_700_000_000), r.set_at);
    }
}

test "keeptopic: legacy raw-text blob decodes as text-only with metadata absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-legacy.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    // Write a legacy value directly (raw topic bytes, no sentinel/metadata) under
    // the exact ktp key, as an older build would have stored it.
    var kb: [Internal.keeptopic_key_max]u8 = undefined;
    const key = Internal.keepTopicKey(&kb, "#chan").?;
    try store.family(.props).put(key, "an old topic set before metadata");

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("an old topic set before metadata", r.text);
    try std.testing.expect(r.setter == null); // metadata absent -> caller uses serverName()/now
}

test "keeptopic: malformed metadata fails closed to text-only, no crash" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-malformed.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var kb: [Internal.keeptopic_key_max]u8 = undefined;
    const key = Internal.keepTopicKey(&kb, "#chan").?;
    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;

    // Case 1: sentinel + version present but the fixed header is truncated (< 12).
    const short_header = [_]u8{ 0x01, 0x01, 0x00, 0x00 };
    try store.family(.props).put(key, &short_header);
    const r1 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r1.setter == null); // fell back to legacy text-only
    try std.testing.expectEqualSlices(u8, &short_header, r1.text);

    // Case 2: full 12-byte header but setter_len points past the end of the value.
    var bad_setter_len: [12]u8 = @splat(0);
    bad_setter_len[0] = 0x01; // sentinel
    bad_setter_len[1] = 0x01; // version
    // set_at bytes [2..10] left 0; setter_len (u16 LE at [10..12]) = 100, but no
    // setter bytes follow -> setter_end (112) > blob.len (12).
    std.mem.writeInt(u16, bad_setter_len[10..12], 100, .little);
    try store.family(.props).put(key, &bad_setter_len);
    const r2 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r2.setter == null); // fell back to legacy text-only
    try std.testing.expectEqualSlices(u8, &bad_setter_len, r2.text);

    // Case 3: unknown version -> fail closed to text-only.
    var bad_version: [12]u8 = @splat(0);
    bad_version[0] = 0x01; // sentinel
    bad_version[1] = 0xFF; // unknown version
    try store.family(.props).put(key, &bad_version);
    const r3 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r3.setter == null);
    try std.testing.expectEqualSlices(u8, &bad_version, r3.text);
}

test "keeptopic: setter truncated to cap; oversize text not persisted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-caps.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;

    // A setter over the 256-byte cap is truncated to the cap.
    var long_setter: [400]u8 = undefined;
    @memset(&long_setter, 'x');
    try services.chanKeepTopicSave("#chan", "topic", &long_setter, 42);
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("topic", r.text);
    try std.testing.expectEqual(@as(usize, 256), r.setter.?.len); // truncated to keeptopic_setter_max
    try std.testing.expectEqual(@as(i64, 42), r.set_at);

    // A topic over the 512-byte text cap is a no-op (unchanged behaviour): the
    // prior saved value stays intact.
    var long_text: [600]u8 = undefined;
    @memset(&long_text, 't');
    try services.chanKeepTopicSave("#chan", &long_text, "bob!b@h", 43);
    const r2 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("topic", r2.text); // oversize text rejected, prior value kept
    try std.testing.expectEqual(@as(i64, 42), r2.set_at);
}

test "keeptopic: a legacy value beginning with the sentinel fails closed to text-only" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-legacy-sentinel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    // A pre-metadata topic that legitimately begins with SOH (0x01) but is NOT a
    // valid versioned blob (byte[1] is not the format version) must fall back to
    // legacy text — bounds-checked, no crash, whole value returned as text with
    // metadata absent so the caller uses serverName()/now.
    var kb: [Internal.keeptopic_key_max]u8 = undefined;
    const key = Internal.keepTopicKey(&kb, "#chan").?;
    const legacy = "\x01ACTION waves at the channel from before metadata existed";
    try store.family(.props).put(key, legacy);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r.setter == null);
    try std.testing.expectEqualStrings(legacy, r.text);
}

test "keeptopic: saving an empty topic clears an enabled channel's remembered value" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-clear.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    // Remember a topic, then clear it with an empty save.
    try services.chanKeepTopicSave("#chan", "remembered", "alice!a@h", 500);
    _ = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try services.chanKeepTopicSave("#chan", "", "alice!a@h", 600);
    // Cleared: recreation restores nothing, but KEEPTOPIC stays enabled.
    try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
    // Still enabled -> a fresh save is remembered again.
    try services.chanKeepTopicSave("#chan", "again", "bob!b@h", 700);
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("again", r.text);
    try std.testing.expectEqualStrings("bob!b@h", r.setter.?);
    try std.testing.expectEqual(@as(i64, 700), r.set_at);
}

test "channel transfer: only the founder may hand ownership to a registered account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-chantransfer.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.transferChannel("#onyx", "bob", "bob", &scratch)); // not founder
    try std.testing.expectError(error.NotFound, services.transferChannel("#onyx", "alice", "carol", &scratch)); // unknown target
    const res = try services.transferChannel("#onyx", "alice", "bob", &scratch);
    try std.testing.expectEqualStrings("bob", res.registered_channel.founder.asSlice());
    // ownership moved: alice can no longer transfer
    try std.testing.expectError(error.Forbidden, services.transferChannel("#onyx", "alice", "alice", &scratch));
}

test "channel register and access grant" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    const registered = try services.registerChannel("#Onyx", "alice", &scratch);
    try std.testing.expectEqualStrings("#onyx", registered.registered_channel.name.asSlice());
    try std.testing.expectEqualStrings("alice", registered.registered_channel.founder.asSlice());

    const granted = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
    try std.testing.expectEqual(AccessLevel.op, granted.access.level);

    // The founder (admin+) may read back another account's access level.
    const queried = try services.channelAccess("#onyx", "alice", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, queried.access.level);
    // But an actor lacking .admin (op-level bob) may NOT probe access state.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "bob", .query, .voice, &scratch));
}

test "channel mlock access akick and ward replay from durable services" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
        _ = try services.registerChannel("#Onyx", "alice", &scratch);
        _ = try services.setChannel("#onyx", "alice", .{ .mlock = "+nt-k" }, &scratch);
        _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
        _ = try services.channelAkick("#onyx", "alice", "Bad!*@*", .add, "go away", &scratch);
        try services.persistWard(.{
            .match = "mask",
            .pattern = "Bad!*@*",
            .scope = "node",
            .action = "expel",
            .reason = "spam",
            .setter = "alice",
            .created_ms = 111,
            .expires_ms = 222,
        }, &scratch);
    }

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const info = try services.channelInfo("#onyx");
        try std.testing.expectEqualStrings("+nt-k", info.channel_info.mlock.asSlice());
        try std.testing.expectEqual(AccessLevel.op, (try services.channelAccessLevelFor("#onyx", "bob")).?);

        const ReplayRecorder = struct {
            channel: [channel_max]u8 = @splat(0),
            channel_len: usize = 0,
            mlock: [mlock_max]u8 = @splat(0),
            mlock_len: usize = 0,
            akick_channel: [channel_max]u8 = @splat(0),
            akick_channel_len: usize = 0,
            akick_mask: [mask_max]u8 = @splat(0),
            akick_mask_len: usize = 0,
            akick_reason: [reason_max]u8 = @splat(0),
            akick_reason_len: usize = 0,
            ward_match: [16]u8 = @splat(0),
            ward_match_len: usize = 0,
            ward_pattern: [mask_max]u8 = @splat(0),
            ward_pattern_len: usize = 0,
            ward_reason: [reason_max]u8 = @splat(0),
            ward_reason_len: usize = 0,

            fn copyInto(dst: []u8, len: *usize, value: []const u8) ServiceError!void {
                if (value.len > dst.len) return error.BufferTooSmall;
                @memcpy(dst[0..value.len], value);
                len.* = value.len;
            }

            fn onChannel(ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.channel, &self.channel_len, channel);
                try copyInto(&self.mlock, &self.mlock_len, mlock);
            }

            fn onAkick(ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, _: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.akick_channel, &self.akick_channel_len, channel);
                try copyInto(&self.akick_mask, &self.akick_mask_len, mask);
                try copyInto(&self.akick_reason, &self.akick_reason_len, reason);
            }

            fn onWard(ctx: *anyopaque, ward: ReplayWard) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.ward_match, &self.ward_match_len, ward.match);
                try copyInto(&self.ward_pattern, &self.ward_pattern_len, ward.pattern);
                try copyInto(&self.ward_reason, &self.ward_reason_len, ward.reason);
            }
        };
        var recorder = ReplayRecorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = ReplayRecorder.onChannel,
            .akick = ReplayRecorder.onAkick,
            .ward = ReplayRecorder.onWard,
        });
        try std.testing.expectEqual(@as(usize, 1), summary.channels);
        try std.testing.expectEqual(@as(usize, 1), summary.mlocks);
        try std.testing.expectEqual(@as(usize, 1), summary.akicks);
        try std.testing.expectEqual(@as(usize, 1), summary.wards);
        try std.testing.expectEqualStrings("#onyx", recorder.channel[0..recorder.channel_len]);
        try std.testing.expectEqualStrings("+nt-k", recorder.mlock[0..recorder.mlock_len]);
        try std.testing.expectEqualStrings("#onyx", recorder.akick_channel[0..recorder.akick_channel_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.akick_mask[0..recorder.akick_mask_len]);
        try std.testing.expectEqualStrings("go away", recorder.akick_reason[0..recorder.akick_reason_len]);
        try std.testing.expectEqualStrings("mask", recorder.ward_match[0..recorder.ward_match_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.ward_pattern[0..recorder.ward_pattern_len]);
        try std.testing.expectEqualStrings("spam", recorder.ward_reason[0..recorder.ward_reason_len]);
    }
}

test "SACCESS entries persist across a WAL reopen and replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "bad!*@*", .duration = 60, .reason = "abuse" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GRANT", .mask = "trusted!*@*" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*" }, &scratch);
        // A deleted entry must not survive the reopen.
        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "temp!*@*" }, &scratch);
        try services.deleteSaccess("DENY", "temp!*@*", &scratch);
        // A re-add of the same type+mask is idempotent (overwrite, not duplicate).
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*", .reason = "updated" }, &scratch);
    }

    {
        // Reopen the WAL — this is the actual "restart": state comes only from disk.
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const Recorder = struct {
            count: usize = 0,
            deny_mask: [256]u8 = @splat(0),
            deny_mask_len: usize = 0,
            deny_duration: u64 = 0,
            deny_reason: [512]u8 = @splat(0),
            deny_reason_len: usize = 0,
            saw_grant: bool = false,
            saw_gag: bool = false,
            gag_reason: [512]u8 = @splat(0),
            gag_reason_len: usize = 0,
            saw_temp: bool = false,

            fn onChannel(_: *anyopaque, _: []const u8, _: []const u8) ServiceError!void {}

            fn onSaccess(ctx: *anyopaque, entry: ReplaySaccess) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                self.count += 1;
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "bad!*@*")) {
                    @memcpy(self.deny_mask[0..entry.mask.len], entry.mask);
                    self.deny_mask_len = entry.mask.len;
                    self.deny_duration = entry.duration;
                    @memcpy(self.deny_reason[0..entry.reason.len], entry.reason);
                    self.deny_reason_len = entry.reason.len;
                }
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "temp!*@*")) self.saw_temp = true;
                if (std.mem.eql(u8, entry.entry_type, "GRANT")) self.saw_grant = true;
                if (std.mem.eql(u8, entry.entry_type, "GAG")) {
                    self.saw_gag = true;
                    @memcpy(self.gag_reason[0..entry.reason.len], entry.reason);
                    self.gag_reason_len = entry.reason.len;
                }
            }
        };
        var recorder = Recorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = Recorder.onChannel,
            .saccess = Recorder.onSaccess,
        });

        // 3 survivors: DENY bad, GRANT trusted, GAG noisy (temp DENY was deleted,
        // and the duplicate GAG add overwrote rather than added).
        try std.testing.expectEqual(@as(usize, 3), summary.saccesses);
        try std.testing.expectEqual(@as(usize, 3), recorder.count);
        try std.testing.expectEqualStrings("bad!*@*", recorder.deny_mask[0..recorder.deny_mask_len]);
        try std.testing.expectEqual(@as(u64, 60), recorder.deny_duration);
        try std.testing.expectEqualStrings("abuse", recorder.deny_reason[0..recorder.deny_reason_len]);
        try std.testing.expect(recorder.saw_grant);
        try std.testing.expect(recorder.saw_gag);
        try std.testing.expectEqualStrings("updated", recorder.gag_reason[0..recorder.gag_reason_len]);
        try std.testing.expect(!recorder.saw_temp);
    }
}

test "SACCESS codec round-trips and rejects malformed records" {
    var key_buf: [saccess_key_max]u8 = undefined;
    const key = try saccessKey("DENY", "bad!*@*", &key_buf);
    try std.testing.expectEqualStrings("saccess:DENY:bad!*@*", key);

    var val_buf: [saccess_value_max]u8 = undefined;
    const encoded = try encodeSaccess(.{ .entry_type = "GAG", .mask = "x!*@*", .duration = 7, .reason = "hush" }, &val_buf);
    const decoded = try decodeSaccess(encoded);
    try std.testing.expectEqualStrings("GAG", decoded.entry_type);
    try std.testing.expectEqualStrings("x!*@*", decoded.mask);
    try std.testing.expectEqual(@as(u64, 7), decoded.duration);
    try std.testing.expectEqualStrings("hush", decoded.reason);

    // A pipe in a field would corrupt the delimiter; encode rejects it.
    try std.testing.expectError(error.InvalidValue, encodeSaccess(.{ .entry_type = "DENY", .mask = "a|b", .duration = 0, .reason = "" }, &val_buf));
    // Wrong version / truncated record is rejected on decode.
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S9|DENY|m|0|"));
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S1|DENY"));
}

test "non-admin channel mutations are forbidden" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-forbidden.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerAccount("carol", "carol correct battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "carol", .grant, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "carol", .revoke, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "*!*@bad.test", .add, "bad", &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "*!*@bad.test", .remove, "", &scratch));
}

test "channel access and akick query require admin" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-query-gate.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerAccount("mallory", "a third correct battery staple", &scratch);
    _ = try services.registerChannel("#Onyx", "alice", &scratch);
    _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
    _ = try services.channelAkick("#onyx", "alice", "Bad!*@*", .add, "go away", &scratch);

    // mallory has NO access to #onyx: both query paths must be Forbidden and
    // must not leak the access level or the akick mask/reason.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "mallory", "bob", .query, .voice, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "mallory", "Bad!*@*", .query, "", &scratch));

    // bob holds op (below .admin): still Forbidden on either query.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "bob", .query, .voice, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "Bad!*@*", .query, "", &scratch));

    // A non-admin querying an UNREGISTERED target must get Forbidden, NOT
    // NotFound: the .admin gate is hoisted above the target-account existence
    // probe so the reply cannot distinguish a registered from an unregistered
    // account (a registration-enumeration oracle). Pre-hoist this returned
    // error.NotFound.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "mallory", "no_such_account", .query, .voice, &scratch));

    // The founder (admin+) may still read both back.
    const acc = try services.channelAccess("#onyx", "alice", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, acc.access.level);
    const ak = try services.channelAkick("#onyx", "alice", "Bad!*@*", .query, "", &scratch);
    try std.testing.expectEqualStrings("go away", ak.akick.reason.asSlice());
}

test "missing access and akick removals return not found" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-missing-remove.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.NotFound, services.channelAccess("#onyx", "alice", "bob", .revoke, .op, &scratch));
    try std.testing.expectError(error.NotFound, services.channelAkick("#onyx", "alice", "*!*@missing.test", .remove, "", &scratch));
}

test "drop account and channel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-drop.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);
    _ = try services.dropChannel("#onyx", "alice");
    try std.testing.expectError(error.NotFound, services.channelInfo("#onyx"));

    _ = try services.dropAccount("alice", "correct horse battery staple");
    try std.testing.expectError(error.NotFound, services.accountInfo("alice"));
}

test "state hook fires on channel register and drop" {
    const Recorder = struct {
        created: [64]u8 = undefined,
        created_len: usize = 0,
        dropped: [64]u8 = undefined,
        dropped_len: usize = 0,

        fn onCreate(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.created[0..channel.len], channel);
            self.created_len = channel.len;
        }
        fn onDrop(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.dropped[0..channel.len], channel);
            self.dropped_len = channel.len;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-hook.wal");
    defer store.deinit();

    var rec = Recorder{};
    var services = Services.init(&store, .{
        .ptr = &rec,
        .create_channel = Recorder.onCreate,
        .drop_channel = Recorder.onDrop,
    });
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#Onyx", "alice", &scratch);
    // The canonical (lowercased) channel name is bridged to the live world.
    try std.testing.expectEqualStrings("#onyx", rec.created[0..rec.created_len]);
    try std.testing.expectEqual(@as(usize, 0), rec.dropped_len);

    _ = try services.dropChannel("#onyx", "alice");
    try std.testing.expectEqualStrings("#onyx", rec.dropped[0..rec.dropped_len]);
}

test "channel SET flags and DESC/URL persist and round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-set.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("admin", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#room", "admin", &scratch);

    // Flags start clear, set independently, and persist without clobbering siblings.
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, true, &scratch);
    try services.setChannelFlag("#room", "admin", channel_flag_private, true, &scratch);
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_guard));

    // Clearing one leaves the other intact.
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, false, &scratch);
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));

    // DESC / URL round-trip and clear on empty.
    var out: [512]u8 = undefined;
    try std.testing.expect(services.chanDescGet("#room", &out) == null);
    try services.chanDescSet("#room", "Our room");
    try std.testing.expectEqualStrings("Our room", services.chanDescGet("#room", &out).?);
    try services.chanUrlSet("#room", "https://example.test");
    try std.testing.expectEqualStrings("https://example.test", services.chanUrlGet("#room", &out).?);
    try services.chanDescSet("#room", "");
    try std.testing.expect(services.chanDescGet("#room", &out) == null);

    // A non-founder/non-admin actor cannot set flags.
    _ = try services.registerAccount("mallory", "another correct horse battery", &scratch);
    try std.testing.expectError(error.Forbidden, services.setChannelFlag("#room", "mallory", channel_flag_guard, true, &scratch));
}
