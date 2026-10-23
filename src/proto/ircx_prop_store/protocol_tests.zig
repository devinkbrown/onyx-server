// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! protocol tests.

const std = @import("std");
const model = @import("model.zig");
const prop_store = @import("store.zig");
const protocol = @import("protocol.zig");

test "parse each PROP request form" {
    const list = try protocol.parseLine("PROP #chan");
    try std.testing.expectEqual(model.Request.list, @as(std.meta.Tag(model.Request), list));
    try std.testing.expectEqualStrings("#chan", list.list.id);

    const get = try protocol.parseLine("PROP #chan TOPIC,ONJOIN");
    try std.testing.expectEqual(model.Request.get, @as(std.meta.Tag(model.Request), get));
    try std.testing.expectEqualStrings("TOPIC,ONJOIN", get.get.keys);

    const set = try protocol.parseLine("PROP #chan TOPIC :hello world");
    try std.testing.expectEqual(model.Request.set, @as(std.meta.Tag(model.Request), set));
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try protocol.parseLine("PROP #chan TOPIC :");
    try std.testing.expectEqual(model.Request.delete, @as(std.meta.Tag(model.Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.InvalidCommand, protocol.parseLine("PRIVMSG #chan :no"));
    try std.testing.expectError(error.NeedMoreParams, protocol.parseLine("PROP"));
    try std.testing.expectError(error.TooManyParams, protocol.parseLine("PROP #c A B C"));
}

test "parse IRCX PROP verb request forms" {
    const clear = try protocol.parseLine("PROP #chan CLEAR");
    try std.testing.expectEqual(model.Request.delete, @as(std.meta.Tag(model.Request), clear));
    try std.testing.expectEqualStrings("#chan", clear.delete.entity.id);
    try std.testing.expectEqualStrings("", clear.delete.key);

    const get = try protocol.parseLine("PROP #chan GET TOPIC,NAME");
    try std.testing.expectEqual(model.Request.get, @as(std.meta.Tag(model.Request), get));
    try std.testing.expectEqualStrings("TOPIC,NAME", get.get.keys);

    const set = try protocol.parseLine("PROP #chan SET TOPIC :hello world");
    try std.testing.expectEqual(model.Request.set, @as(std.meta.Tag(model.Request), set));
    try std.testing.expectEqualStrings("TOPIC", set.set.key);
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try protocol.parseLine("PROP #chan SET TOPIC :");
    try std.testing.expectEqual(model.Request.delete, @as(std.meta.Tag(model.Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.NeedMoreParams, protocol.parseLine("PROP #chan GET"));
    try std.testing.expectError(error.TooManyParams, protocol.parseLine("PROP #chan CLEAR TOPIC"));
}

test "secret channel props stay hidden except raw internal lookup" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try model.Entity.fromId("#keys");
    _ = try store.setProp(entity, "HOSTKEY", "s3cret", .{ .id = "owner", .access = .owner });

    try std.testing.expectError(error.PropMissing, store.getProp(entity, "HOSTKEY"));
    const raw = try store.getPropRaw(entity, "HOSTKEY");
    try std.testing.expectEqualStrings("HOSTKEY", raw.key);
    try std.testing.expectEqualStrings("s3cret", raw.value);

    // FOUNDERKEY is a secret tier key too — hidden from getProp, visible RAW.
    _ = try store.setProp(entity, "FOUNDERKEY", "topkey", .{ .id = "owner", .access = .owner });
    try std.testing.expect((model.channelPropInfo("FOUNDERKEY").?).secret);
    try std.testing.expect(model.channelPropKey("no-ai") == .no_ai);
    try std.testing.expect(model.channelPropKey("LOCAL-ONLY") == .local_only);
    try std.testing.expect(model.channelPropKey("server-ai-ok") == .server_ai_ok);
    try std.testing.expect(model.channelPropKey("history-policy") == .history_policy);
    try std.testing.expectError(error.PropMissing, store.getProp(entity, "FOUNDERKEY"));
    try std.testing.expectEqualStrings("topkey", (try store.getPropRaw(entity, "FOUNDERKEY")).value);

    // A plain LIST omits every secret key; listPropsRaw surfaces them for the
    // caller to gate (here: a non-secret CUSTOM plus the two secret tier keys).
    _ = try store.setProp(entity, "CUSTOM", "v", .{ .id = "owner", .access = .host });
    var views: [8]model.EntryView = undefined;
    const plain = try store.listProps(entity, &views);
    try std.testing.expectEqual(@as(usize, 1), plain.len);
    try std.testing.expectEqualStrings("CUSTOM", plain[0].key);
    var raw_views: [8]model.EntryView = undefined;
    const all = try store.listPropsRaw(entity, &raw_views);
    try std.testing.expectEqual(@as(usize, 3), all.len); // CUSTOM + HOSTKEY + FOUNDERKEY
}

test "limits and built-in channel property metadata are enforced" {
    const Tiny = prop_store.PropStore(.{
        .max_entities = 1,
        .max_props_per_entity = 1,
        .max_entity_id = 8,
        .max_key = 8,
        .max_value = 8,
        .max_owner_bytes = 8,
    });
    var store = Tiny.init(std.testing.allocator);
    defer store.deinit();

    const entity = try model.Entity.fromId("#c");
    _ = try store.setProp(entity, "custom", "12345678", .{ .id = "owner", .access = .host });
    // Capacity checks use the normalized lookup key: a differently-cased
    // spelling updates the existing row even when the entity is otherwise full.
    try store.preflightSetProp(entity, "CUSTOM", "changed", .{ .id = "owner", .access = .host });
    _ = try store.setProp(entity, "CUSTOM", "changed", .{ .id = "owner", .access = .host });
    try std.testing.expectEqualStrings("changed", (try store.getPropRaw(entity, "custom")).value);
    try std.testing.expectError(error.LimitReached, store.setProp(entity, "other", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.LimitReached, store.setProp(try model.Entity.fromId("#d"), "custom", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "custom", "123456789", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidOwner, store.setProp(entity, "custom", "1", .{ .id = "bad owner", .access = .host }));

    try std.testing.expect(model.channelPropKey("OWNERKEY").? == .ownerkey);
    try std.testing.expect((model.channelPropInfo("OWNERKEY").?).secret);
    try std.testing.expectError(error.ReadOnlyProperty, store.setProp(entity, "OID", "1", .{ .id = "server", .access = .server }));
    try std.testing.expectError(error.AccessDenied, store.setProp(entity, "PICS", "safe", .{ .id = "owner", .access = .owner }));

    // MEMBERCOUNT is a computed read-only builtin; MEMBERLIMIT is host-settable.
    // (Checked via metadata + a default-limit store; the Tiny store's 8-byte key
    // cap would reject these long key names before the read-only rule applies.)
    try std.testing.expect(model.channelPropKey("MEMBERCOUNT").? == .membercount);
    try std.testing.expect(model.channelPropInfo("MEMBERCOUNT").?.read_only);
    try std.testing.expect(!model.channelPropInfo("MEMBERLIMIT").?.read_only);

    var full = prop_store.DefaultStore.init(std.testing.allocator);
    defer full.deinit();
    const chan = try model.Entity.fromId("#mc");
    try std.testing.expectError(error.ReadOnlyProperty, full.setProp(chan, "MEMBERCOUNT", "1", .{ .id = "server", .access = .server }));
    _ = try full.setProp(chan, "MEMBERLIMIT", "50", .{ .id = "host", .access = .host });

    // Draft LAG is a 0–2 second member pause. A one-character impostor is not.
    try std.testing.expectEqual(@as(?u8, 2), model.lagSeconds("2"));
    try std.testing.expectEqual(@as(?u8, 0), model.lagSeconds("0"));
    try std.testing.expect(model.lagSeconds("3") == null);
    try std.testing.expect(model.lagSeconds("10") == null);
    _ = try full.setProp(chan, "LAG", "2", .{ .id = "owner", .access = .owner });
    try std.testing.expectEqualStrings("2", (try full.getProp(chan, "LAG")).value);
    try std.testing.expectError(error.InvalidValue, full.setProp(chan, "LAG", "9", .{ .id = "owner", .access = .owner }));
    try std.testing.expectError(error.AccessDenied, full.setProp(chan, "LAG", "1", .{ .id = "host", .access = .host }));
    try std.testing.expectEqualStrings("2", (try full.getProp(chan, "LAG")).value);
}

test "user profile properties use the profile value limit" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try model.Entity.fromId("Alice");
    const setter = model.Setter{ .id = "Alice", .access = .member };
    const cases = [_]struct {
        key: []const u8,
        value: []const u8,
    }{
        .{ .key = "URL", .value = "https://example.test/alice" },
        .{ .key = "GENDER", .value = "nonbinary" },
        .{ .key = "PICTURE", .value = "https://example.test/a.png" },
        .{ .key = "BIO", .value = "Onyx operator" },
        .{ .key = "EMAIL", .value = "alice@example.test" },
    };

    for (cases) |case| {
        const ev = try store.setProp(entity, case.key, case.value, setter);
        try std.testing.expectEqualStrings(case.key, ev.key);
        try std.testing.expectEqualStrings(case.value, ev.value);
        try std.testing.expect(model.userProfilePropKey(case.key) != null);
    }

    var too_long = @as([(model.user_profile_max_value + 1)]u8, @splat('x'));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "URL", too_long[0..], setter));

    // The tighter cap applies only to the newly added user-profile fields.
    // Existing Onyx Server profile keys and generic user props retain the store-wide
    // value budget.
    _ = try store.setProp(entity, "display", too_long[0..], setter);
    _ = try store.setProp(entity, "custom", too_long[0..], setter);
}

test "reply builders and no-leak clear path" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try model.Entity.fromId("#reply");
    const entry = try store.setProp(entity, "TOPIC", "hello", .{ .id = "oper", .access = .owner });

    var out: [160]u8 = undefined;
    try std.testing.expectEqualStrings("PROP #reply TOPIC :hello", try protocol.buildPropMessage(entity, entry.key, entry.value, &out));
    try std.testing.expectEqualStrings(":irc.example 818 nick #reply TOPIC :hello", try protocol.buildPropListReply("irc.example", "nick", entry, &out));
    try std.testing.expectEqualStrings(":irc.example 819 nick #reply :End of properties", try protocol.buildPropEndReply("irc.example", "nick", entity, &out));
    try std.testing.expectError(error.OutputTooSmall, protocol.buildPropListReply("irc.example", "nick", entry, out[0..8]));

    store.clear();
    _ = try store.setProp(try model.Entity.fromId("nick"), "away", "no", .{ .id = "nick", .access = .user });
}
