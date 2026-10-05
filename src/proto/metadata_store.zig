// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCv3 metadata-2 key/value store.
//!
//! This store deliberately avoids daemon, IRCX, subscription, and dispatch
//! concerns. It owns retained target, key, and value bytes; callers own list
//! output storage and protocol rendering.
const std = @import("std");
const limits_config = @import("limits_config.zig");

pub const default_max_targets: usize = 1024;
pub const default_max_keys_per_target: usize = 64;
pub const default_max_key: usize = 64;
pub const default_max_value: usize = 512;

pub const Params = struct {
    max_targets: usize = default_max_targets,
    max_keys_per_target: usize = default_max_keys_per_target,
    max_key: usize = default_max_key,
    max_value: usize = default_max_value,

    /// Derive `Params` from the central policy limits (config-driven).
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_targets = limits.metadata_max_targets,
            .max_keys_per_target = limits.metadata_max_keys,
            .max_key = limits.metadata_key_len,
            .max_value = limits.metadata_value_len,
        };
    }
};

pub const MetadataStoreError = error{
    KEY_INVALID,
    KEY_NOT_SET,
    LIMIT_REACHED,
    TARGET_INVALID,
    VALUE_INVALID,
    OUTPUT_TOO_SMALL,
};

pub const Visibility = enum {
    public,
    members,
    admins,
    server,
    secret,

    pub fn token(self: Visibility) []const u8 {
        return switch (self) {
            .public => "*",
            .members => "members",
            .admins => "admins",
            .server => "server",
            .secret => "secret",
        };
    }

    pub fn fromToken(raw: []const u8) ?Visibility {
        if (std.mem.eql(u8, raw, "*")) return .public;
        if (std.mem.eql(u8, raw, "members")) return .members;
        if (std.mem.eql(u8, raw, "admins")) return .admins;
        if (std.mem.eql(u8, raw, "server")) return .server;
        if (std.mem.eql(u8, raw, "secret")) return .secret;
        return null;
    }
};

pub const EntryView = struct {
    target: []const u8,
    key: []const u8,
    value: []const u8,
    visibility: Visibility,

    pub fn ircv3VisibilityToken(self: EntryView) []const u8 {
        return self.visibility.token();
    }
};

pub fn MetadataStore(comptime params: Params) type {
    if (params.max_targets == 0 or params.max_keys_per_target == 0 or params.max_key == 0) {
        @compileError("metadata store limits must be non-zero");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        targets: std.StringHashMap(TargetState),
        target_count: usize = 0,

        const Entry = struct {
            value: []u8,
            visibility: Visibility,

            fn deinit(self: Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.value);
            }
        };

        const TargetState = struct {
            target: []const u8,
            entries: std.StringHashMap(Entry),
            key_count: usize = 0,

            fn init(allocator: std.mem.Allocator, target: []const u8) TargetState {
                return .{
                    .target = target,
                    .entries = std.StringHashMap(Entry).init(allocator),
                };
            }

            fn deinit(self: *TargetState, allocator: std.mem.Allocator) void {
                var it = self.entries.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                self.entries.deinit();
                self.* = undefined;
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .targets = std.StringHashMap(TargetState).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.targets.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.targets.clearRetainingCapacity();
            self.target_count = 0;
        }

        pub fn set(self: *Self, target: []const u8, key: []const u8, value: []const u8) MetadataStoreError!EntryView {
            return self.setWithVisibility(target, key, value, .public);
        }

        pub fn setWithVisibility(
            self: *Self,
            target: []const u8,
            key: []const u8,
            value: []const u8,
            visibility: Visibility,
        ) MetadataStoreError!EntryView {
            try validateTarget(target);
            try validateKeyWithLimit(key, params.max_key);
            try validateValue(value, params.max_value);

            var state = try self.getOrCreateTarget(target);
            const existing = state.entries.getEntry(key);
            if (existing == null and state.key_count >= params.max_keys_per_target) return error.LIMIT_REACHED;

            const value_copy = self.allocator.dupe(u8, value) catch return error.LIMIT_REACHED;
            errdefer self.allocator.free(value_copy);

            if (existing) |entry| {
                self.allocator.free(entry.value_ptr.value);
                entry.value_ptr.* = .{ .value = value_copy, .visibility = visibility };
                return view(state, entry.key_ptr.*, entry.value_ptr);
            }

            const key_copy = self.allocator.dupe(u8, key) catch return error.LIMIT_REACHED;
            errdefer self.allocator.free(key_copy);

            const gop = state.entries.getOrPut(key) catch return error.LIMIT_REACHED;
            if (gop.found_existing) {
                self.allocator.free(gop.value_ptr.value);
                gop.value_ptr.* = .{ .value = value_copy, .visibility = visibility };
                return view(state, gop.key_ptr.*, gop.value_ptr);
            }

            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = .{ .value = value_copy, .visibility = visibility };
            state.key_count += 1;
            return view(state, gop.key_ptr.*, gop.value_ptr);
        }

        pub fn get(self: *const Self, target: []const u8, key: []const u8) MetadataStoreError!EntryView {
            try validateTarget(target);
            try validateKeyWithLimit(key, params.max_key);

            const state = self.targets.getPtr(target) orelse return error.KEY_NOT_SET;
            const entry = state.entries.getEntry(key) orelse return error.KEY_NOT_SET;
            return view(state, entry.key_ptr.*, entry.value_ptr);
        }

        pub fn delete(self: *Self, target: []const u8, key: []const u8) MetadataStoreError!void {
            try validateTarget(target);
            try validateKeyWithLimit(key, params.max_key);

            var state = self.targets.getPtr(target) orelse return error.KEY_NOT_SET;
            const removed = state.entries.fetchRemove(key) orelse return error.KEY_NOT_SET;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
            state.key_count -= 1;

            if (state.key_count == 0) {
                const removed_target = self.targets.fetchRemove(target).?;
                self.allocator.free(removed_target.key);
                var empty_state = removed_target.value;
                empty_state.deinit(self.allocator);
                self.target_count -= 1;
            }
        }

        pub fn list(self: *const Self, target: []const u8, out: []EntryView) MetadataStoreError![]EntryView {
            try validateTarget(target);

            const state = self.targets.getPtr(target) orelse return out[0..0];
            if (state.key_count > out.len) return error.OUTPUT_TOO_SMALL;

            var count: usize = 0;
            var it = state.entries.iterator();
            while (it.next()) |entry| {
                out[count] = view(state, entry.key_ptr.*, entry.value_ptr);
                count += 1;
            }

            const listed = out[0..count];
            std.sort.insertion(EntryView, listed, {}, entryLessThan);
            return listed;
        }

        pub fn countTargets(self: *const Self) usize {
            return self.target_count;
        }

        /// Borrow every retained target, including a zero-key target left by
        /// an earlier allocation failure. The order is stable for checkpoint
        /// encoding even though the backing hash map's order is not.
        pub fn listTargets(self: *const Self, out: [][]const u8) MetadataStoreError![][]const u8 {
            if (self.target_count > out.len) return error.OUTPUT_TOO_SMALL;
            var count: usize = 0;
            var it = self.targets.iterator();
            while (it.next()) |entry| {
                if (count == out.len) return error.OUTPUT_TOO_SMALL;
                out[count] = entry.key_ptr.*;
                count += 1;
            }
            const listed = out[0..count];
            std.sort.insertion([]const u8, listed, {}, struct {
                fn less(_: void, lhs: []const u8, rhs: []const u8) bool {
                    return std.mem.lessThan(u8, lhs, rhs);
                }
            }.less);
            return listed;
        }

        /// Restore a target with no keys. Such a target is still counted by
        /// the live store and consumes one capacity slot, so a checkpoint must
        /// carry it instead of silently dropping it.
        pub fn ensureTargetForSnapshot(self: *Self, target: []const u8) MetadataStoreError!void {
            try validateTarget(target);
            _ = try self.getOrCreateTarget(target);
        }

        pub fn countKeys(self: *const Self, target: []const u8) MetadataStoreError!usize {
            try validateTarget(target);
            const state = self.targets.getPtr(target) orelse return 0;
            return state.key_count;
        }

        fn getOrCreateTarget(self: *Self, target: []const u8) MetadataStoreError!*TargetState {
            if (self.targets.getPtr(target)) |state| return state;
            if (self.target_count >= params.max_targets) return error.LIMIT_REACHED;

            const target_copy = self.allocator.dupe(u8, target) catch return error.LIMIT_REACHED;
            errdefer self.allocator.free(target_copy);

            const gop = self.targets.getOrPut(target) catch return error.LIMIT_REACHED;
            if (gop.found_existing) {
                self.allocator.free(target_copy);
                return gop.value_ptr;
            }

            gop.key_ptr.* = target_copy;
            gop.value_ptr.* = TargetState.init(self.allocator, gop.key_ptr.*);
            self.target_count += 1;
            return gop.value_ptr;
        }

        fn view(state: *const TargetState, key: []const u8, entry: *const Entry) EntryView {
            return .{
                .target = state.target,
                .key = key,
                .value = entry.value,
                .visibility = entry.visibility,
            };
        }
    };
}

pub const DefaultStore = MetadataStore(.{});

pub fn validateKey(key: []const u8) MetadataStoreError!void {
    try validateKeyWithLimit(key, default_max_key);
}

pub fn validateTarget(target: []const u8) MetadataStoreError!void {
    if (target.len == 0) return error.TARGET_INVALID;
    for (target) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == ':') return error.TARGET_INVALID;
    }
}

fn validateKeyWithLimit(key: []const u8, max_key: usize) MetadataStoreError!void {
    if (key.len == 0 or key.len > max_key) return error.KEY_INVALID;
    for (key) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '/' or byte == '-';
        if (!ok) return error.KEY_INVALID;
    }
}

fn validateValue(value: []const u8, max_value: usize) MetadataStoreError!void {
    if (value.len > max_value) return error.VALUE_INVALID;
    if (!std.unicode.utf8ValidateSlice(value)) return error.VALUE_INVALID;
}

fn entryLessThan(_: void, lhs: EntryView, rhs: EntryView) bool {
    return std.mem.lessThan(u8, lhs.key, rhs.key);
}

test "set get and overwrite metadata" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const first = try store.set("#zig", "topic", "Zig 0.16");
    try std.testing.expectEqualStrings("#zig", first.target);
    try std.testing.expectEqualStrings("topic", first.key);
    try std.testing.expectEqualStrings("Zig 0.16", first.value);
    try std.testing.expectEqual(.public, first.visibility);
    try std.testing.expectEqualStrings("*", first.ircv3VisibilityToken());

    const updated = try store.setWithVisibility("#zig", "topic", "new topic", .members);
    try std.testing.expectEqualStrings("new topic", updated.value);
    try std.testing.expectEqual(.members, updated.visibility);

    const got = try store.get("#zig", "topic");
    try std.testing.expectEqualStrings("new topic", got.value);
    try std.testing.expectEqual(.members, got.visibility);
    try std.testing.expectEqual(@as(usize, 1), try store.countKeys("#zig"));
}

test "delete removes keys and empty targets" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.set("alice", "account", "alice");
    try std.testing.expectEqual(@as(usize, 1), store.countTargets());

    try store.delete("alice", "account");
    try std.testing.expectError(error.KEY_NOT_SET, store.get("alice", "account"));
    try std.testing.expectError(error.KEY_NOT_SET, store.delete("alice", "account"));
    try std.testing.expectEqual(@as(usize, 0), store.countTargets());
}

test "list returns key ordered entries" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.set("#ops", "zeta", "last");
    _ = try store.setWithVisibility("#ops", "alpha", "first", .server);
    _ = try store.set("#ops", "middle", "mid");

    var out: [4]EntryView = undefined;
    const listed = try store.list("#ops", &out);

    try std.testing.expectEqual(@as(usize, 3), listed.len);
    try std.testing.expectEqualStrings("alpha", listed[0].key);
    try std.testing.expectEqualStrings("middle", listed[1].key);
    try std.testing.expectEqualStrings("zeta", listed[2].key);
    try std.testing.expectEqual(.server, listed[0].visibility);
}

test "limit enforcement" {
    const TinyStore = MetadataStore(.{
        .max_targets = 2,
        .max_keys_per_target = 2,
        .max_key = 8,
        .max_value = 4,
    });
    var store = TinyStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.set("alice", "a", "1");
    _ = try store.set("alice", "b", "2");
    try std.testing.expectError(error.LIMIT_REACHED, store.set("alice", "c", "3"));

    _ = try store.set("bob", "a", "1");
    try std.testing.expectError(error.LIMIT_REACHED, store.set("carol", "a", "1"));
    try std.testing.expectError(error.KEY_INVALID, store.set("alice", "toolongkey", "1"));
    try std.testing.expectError(error.VALUE_INVALID, store.set("alice", "a", "12345"));
}

test "key validation follows IRCv3 metadata syntax" {
    try validateKey("im.xmpp");
    try validateKey("client/status-v1");
    try validateKey("vendor/key_name");
    try std.testing.expectError(error.KEY_INVALID, validateKey(""));
    try std.testing.expectError(error.KEY_INVALID, validateKey("BadKey"));
    try std.testing.expectError(error.KEY_INVALID, validateKey("bad key"));
    try std.testing.expectError(error.KEY_INVALID, validateKey("bad$key"));

    var max_key: [default_max_key]u8 = undefined;
    @memset(&max_key, 'a');
    try validateKey(&max_key);

    var too_long: [default_max_key + 1]u8 = undefined;
    @memset(&too_long, 'a');
    try std.testing.expectError(error.KEY_INVALID, validateKey(&too_long));
}

test "fill clear and deinit do not leak" {
    var store = MetadataStore(.{
        .max_targets = 4,
        .max_keys_per_target = 3,
        .max_key = 16,
        .max_value = 16,
    }).init(std.testing.allocator);
    defer store.deinit();

    const targets = [_][]const u8{ "alice", "bob", "#ops", "#chat" };
    const keys = [_][]const u8{ "alpha", "beta", "gamma" };

    for (targets) |target| {
        for (keys, 0..) |key, idx| {
            const value = switch (idx) {
                0 => "one",
                1 => "two",
                else => "three",
            };
            _ = try store.setWithVisibility(target, key, value, .public);
        }
    }

    try std.testing.expectEqual(@as(usize, 4), store.countTargets());
    store.clear();
    try std.testing.expectEqual(@as(usize, 0), store.countTargets());
    _ = try store.set("#after-clear", "key", "value");
}
