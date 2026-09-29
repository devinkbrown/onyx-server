// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Spam trap registry for operator-designated nick and channel targets.
//!
//! The store is deliberately pure state: it tracks trap targets, records
//! non-operator trips, and exposes recent trip views for the server layer to
//! turn into policy action.

const std = @import("std");

/// Compile-time limits for a spam trap registry instance.
pub const Params = struct {
    max_trap_nicks: usize = 1024,
    max_trap_channels: usize = 1024,
    max_offenders: usize = 4096,
    max_recent_trips: usize = 128,
    max_nick_bytes: usize = 64,
    max_channel_bytes: usize = 128,
    max_actor_bytes: usize = 64,
};

/// Identifies whether a trip target is a nick or a channel.
pub const TrapKind = enum(u1) {
    nick,
    channel,
};

/// Read-only view of one recent spam trap trip.
pub const Trip = struct {
    actor: []const u8,
    kind: TrapKind,
    target: []const u8,
    count_for_actor: u64,
};

/// Errors returned by spam trap registry operations.
pub const SpamtrapError = std.mem.Allocator.Error || error{
    InvalidActor,
    ActorTooLong,
    InvalidNick,
    NickTooLong,
    InvalidChannel,
    ChannelTooLong,
    TrapExists,
    TrapNotFound,
    TrapFull,
    OutputTooSmall,
    CounterOverflow,
};

/// Build a bounded spam trap registry type.
pub fn Spamtrap(comptime params: Params) type {
    comptime {
        if (params.max_nick_bytes == 0) @compileError("spam trap nick keys need storage");
        if (params.max_channel_bytes == 0) @compileError("spam trap channel keys need storage");
        if (params.max_actor_bytes == 0) @compileError("spam trap actor keys need storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        trap_nicks: std.StringHashMap(void),
        trap_channels: std.StringHashMap(void),
        offender_trips: std.StringHashMap(u64),
        recent: std.ArrayListUnmanaged(RecentTrip) = .empty,
        total_trips: u64 = 0,

        const RecentTrip = struct {
            actor: []u8,
            kind: TrapKind,
            target: []u8,
            count_for_actor: u64,
        };

        /// Initialize an empty spam trap registry.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .trap_nicks = std.StringHashMap(void).init(allocator),
                .trap_channels = std.StringHashMap(void).init(allocator),
                .offender_trips = std.StringHashMap(u64).init(allocator),
            };
        }

        /// Free every owned key, recent-trip entry, and backing container.
        pub fn deinit(self: *Self) void {
            self.clearTrapKeys(&self.trap_nicks);
            self.trap_nicks.deinit();

            self.clearTrapKeys(&self.trap_channels);
            self.trap_channels.deinit();

            self.clearOffenders();
            self.offender_trips.deinit();

            self.clearRecent();
            self.recent.deinit(self.allocator);
            self.* = undefined;
        }

        /// Remove all trap targets and trip accounting while retaining capacity.
        pub fn clear(self: *Self) void {
            self.clearTrapKeys(&self.trap_nicks);
            self.clearTrapKeys(&self.trap_channels);
            self.clearOffenders();
            self.clearRecent();
            self.total_trips = 0;
        }

        /// Add a case-insensitive trap nick.
        pub fn addTrapNick(self: *Self, nick: []const u8) SpamtrapError!void {
            var key_buf: [params.max_nick_bytes]u8 = undefined;
            const key = try normalizeNick(nick, &key_buf);
            if (self.trap_nicks.contains(key)) return error.TrapExists;
            if (self.trap_nicks.count() >= params.max_trap_nicks) return error.TrapFull;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);
            try self.trap_nicks.putNoClobber(owned_key, {});
        }

        /// Add a case-insensitive trap channel.
        pub fn addTrapChannel(self: *Self, channel: []const u8) SpamtrapError!void {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            if (self.trap_channels.contains(key)) return error.TrapExists;
            if (self.trap_channels.count() >= params.max_trap_channels) return error.TrapFull;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);
            try self.trap_channels.putNoClobber(owned_key, {});
        }

        /// Remove a trap nick.
        pub fn removeTrapNick(self: *Self, nick: []const u8) SpamtrapError!void {
            var key_buf: [params.max_nick_bytes]u8 = undefined;
            const key = try normalizeNick(nick, &key_buf);
            const removed = self.trap_nicks.fetchRemove(key) orelse return error.TrapNotFound;
            self.allocator.free(removed.key);
        }

        /// Remove a trap channel.
        pub fn removeTrapChannel(self: *Self, channel: []const u8) SpamtrapError!void {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            const removed = self.trap_channels.fetchRemove(key) orelse return error.TrapNotFound;
            self.allocator.free(removed.key);
        }

        /// Return whether `nick` is a configured trap nick.
        pub fn isTrapNick(self: *const Self, nick: []const u8) SpamtrapError!bool {
            var key_buf: [params.max_nick_bytes]u8 = undefined;
            const key = try normalizeNick(nick, &key_buf);
            return self.trap_nicks.contains(key);
        }

        /// Return whether `channel` is a configured trap channel.
        pub fn isTrapChannel(self: *const Self, channel: []const u8) SpamtrapError!bool {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            return self.trap_channels.contains(key);
        }

        /// Record a trip when a non-operator touches a configured trap target.
        ///
        /// Returns `true` when the actor was recorded. Operators and non-trap
        /// targets return `false` without changing accounting.
        pub fn triggered(
            self: *Self,
            actor: []const u8,
            kind: TrapKind,
            target: []const u8,
            actor_is_oper: bool,
        ) SpamtrapError!bool {
            if (actor_is_oper) return false;

            const is_trap = switch (kind) {
                .nick => try self.isTrapNick(target),
                .channel => try self.isTrapChannel(target),
            };
            if (!is_trap) return false;

            try validateActor(actor);
            if (self.total_trips == std.math.maxInt(u64)) return error.CounterOverflow;

            const count = try self.incrementActor(actor);
            errdefer self.rollbackActor(actor);

            try self.appendRecent(actor, kind, target, count);
            self.total_trips += 1;
            return true;
        }

        /// Return whether `actor` has ever tripped a trap.
        pub fn isFlagged(self: *const Self, actor: []const u8) SpamtrapError!bool {
            var key_buf: [params.max_actor_bytes]u8 = undefined;
            const key = try normalizeActor(actor, &key_buf);
            return self.offender_trips.contains(key);
        }

        /// Return the number of trips recorded for `actor`.
        pub fn tripCount(self: *const Self, actor: []const u8) SpamtrapError!u64 {
            var key_buf: [params.max_actor_bytes]u8 = undefined;
            const key = try normalizeActor(actor, &key_buf);
            return self.offender_trips.get(key) orelse 0;
        }

        /// Return the total number of recorded trips.
        pub fn totalTripCount(self: *const Self) u64 {
            return self.total_trips;
        }

        /// Return the number of distinct flagged actors.
        pub fn offenderCount(self: *const Self) usize {
            return self.offender_trips.count();
        }

        /// Return the number of configured trap nicks.
        pub fn trapNickCount(self: *const Self) usize {
            return self.trap_nicks.count();
        }

        /// Return the number of configured trap channels.
        pub fn trapChannelCount(self: *const Self) usize {
            return self.trap_channels.count();
        }

        /// Duplicate configured trap names into caller-owned lists. Recent
        /// trips and offender counts stay process-local.
        pub fn dupeTrapNames(
            self: *const Self,
            alloc: std.mem.Allocator,
            nicks: *std.ArrayListUnmanaged([]u8),
            channels: *std.ArrayListUnmanaged([]u8),
        ) !void {
            var nit = self.trap_nicks.iterator();
            while (nit.next()) |kv| {
                const owned = try alloc.dupe(u8, kv.key_ptr.*);
                nicks.append(alloc, owned) catch |err| {
                    alloc.free(owned);
                    return err;
                };
            }
            var cit = self.trap_channels.iterator();
            while (cit.next()) |kv| {
                const owned = try alloc.dupe(u8, kv.key_ptr.*);
                channels.append(alloc, owned) catch |err| {
                    alloc.free(owned);
                    return err;
                };
            }
        }

        /// Return the number of retained recent trips.
        pub fn recentTripCount(self: *const Self) usize {
            return self.recent.items.len;
        }

        /// Copy recent trips into `out` in oldest-to-newest order.
        pub fn recentTrips(self: *const Self, out: []Trip) SpamtrapError![]const Trip {
            if (out.len < self.recent.items.len) return error.OutputTooSmall;

            for (self.recent.items, 0..) |entry, index| {
                out[index] = .{
                    .actor = entry.actor,
                    .kind = entry.kind,
                    .target = entry.target,
                    .count_for_actor = entry.count_for_actor,
                };
            }
            return out[0..self.recent.items.len];
        }

        fn incrementActor(self: *Self, actor: []const u8) SpamtrapError!u64 {
            var key_buf: [params.max_actor_bytes]u8 = undefined;
            const key = try normalizeActor(actor, &key_buf);

            if (self.offender_trips.getPtr(key)) |trips| {
                if (trips.* == std.math.maxInt(u64)) return error.CounterOverflow;
                trips.* += 1;
                return trips.*;
            }

            if (self.offender_trips.count() >= params.max_offenders) return error.TrapFull;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);
            try self.offender_trips.putNoClobber(owned_key, 1);
            return 1;
        }

        fn rollbackActor(self: *Self, actor: []const u8) void {
            var key_buf: [params.max_actor_bytes]u8 = undefined;
            const key = normalizeActor(actor, &key_buf) catch return;
            const trips = self.offender_trips.getPtr(key) orelse return;
            if (trips.* > 1) {
                trips.* -= 1;
                return;
            }

            const removed = self.offender_trips.fetchRemove(key) orelse return;
            self.allocator.free(removed.key);
        }

        fn appendRecent(
            self: *Self,
            actor: []const u8,
            kind: TrapKind,
            target: []const u8,
            count_for_actor: u64,
        ) SpamtrapError!void {
            if (params.max_recent_trips == 0) return;

            if (self.recent.items.len >= params.max_recent_trips) {
                var oldest = self.recent.orderedRemove(0);
                self.freeRecentTrip(&oldest);
            }

            const owned_actor = try self.allocator.dupe(u8, actor);
            errdefer self.allocator.free(owned_actor);

            const owned_target = try self.allocator.dupe(u8, target);
            errdefer self.allocator.free(owned_target);

            try self.recent.append(self.allocator, .{
                .actor = owned_actor,
                .kind = kind,
                .target = owned_target,
                .count_for_actor = count_for_actor,
            });
        }

        fn clearTrapKeys(self: *Self, map: *std.StringHashMap(void)) void {
            var it = map.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            map.clearRetainingCapacity();
        }

        fn clearOffenders(self: *Self) void {
            var it = self.offender_trips.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            self.offender_trips.clearRetainingCapacity();
        }

        fn clearRecent(self: *Self) void {
            for (self.recent.items) |*entry| {
                self.freeRecentTrip(entry);
            }
            self.recent.clearRetainingCapacity();
        }

        fn freeRecentTrip(self: *Self, entry: *RecentTrip) void {
            self.allocator.free(entry.actor);
            self.allocator.free(entry.target);
            entry.* = undefined;
        }

        fn normalizeNick(nick: []const u8, buf: *[params.max_nick_bytes]u8) SpamtrapError![]const u8 {
            try validateNick(nick);
            return foldAscii(nick, buf);
        }

        fn normalizeChannel(channel: []const u8, buf: *[params.max_channel_bytes]u8) SpamtrapError![]const u8 {
            try validateChannel(channel);
            return foldAscii(channel, buf);
        }

        fn normalizeActor(actor: []const u8, buf: *[params.max_actor_bytes]u8) SpamtrapError![]const u8 {
            try validateActor(actor);
            return foldAscii(actor, buf);
        }

        fn validateNick(nick: []const u8) SpamtrapError!void {
            if (nick.len == 0 or isChannelLead(nick[0])) return error.InvalidNick;
            if (nick.len > params.max_nick_bytes) return error.NickTooLong;
            if (hasBadTokenByte(nick)) return error.InvalidNick;
        }

        fn validateChannel(channel: []const u8) SpamtrapError!void {
            if (channel.len < 2 or channel[0] != '#') return error.InvalidChannel;
            if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
            if (hasBadTokenByte(channel)) return error.InvalidChannel;
        }

        fn validateActor(actor: []const u8) SpamtrapError!void {
            if (actor.len == 0 or actor.len > params.max_actor_bytes) {
                return if (actor.len == 0) error.InvalidActor else error.ActorTooLong;
            }
            if (hasBadTokenByte(actor)) return error.InvalidActor;
        }
    };
}

/// Default spam trap registry bounds for daemon use.
pub const DefaultSpamtrap = Spamtrap(.{});

fn foldAscii(input: []const u8, buf: []u8) []const u8 {
    for (input, 0..) |byte, index| {
        buf[index] = std.ascii.toLower(byte);
    }
    return buf[0..input.len];
}

fn hasBadTokenByte(input: []const u8) bool {
    for (input) |byte| {
        if (byte <= ' ' or byte == ',' or byte == 0x7f) return true;
    }
    return false;
}

fn isChannelLead(byte: u8) bool {
    return byte == '#' or byte == '&';
}

const testing = std.testing;

test "add trap targets stores them case-insensitively and rejects duplicates" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();

    // Act.
    try registry.addTrapNick("TrapNick");
    try registry.addTrapChannel("#TrapChan");

    // Assert.
    try testing.expect(try registry.isTrapNick("trapnick"));
    try testing.expect(try registry.isTrapNick("TRAPNICK"));
    try testing.expect(try registry.isTrapChannel("#trapchan"));
    try testing.expect(try registry.isTrapChannel("#TRAPCHAN"));
    try testing.expectEqual(@as(usize, 1), registry.trapNickCount());
    try testing.expectEqual(@as(usize, 1), registry.trapChannelCount());
    try testing.expectError(error.TrapExists, registry.addTrapNick("trapnick"));
    try testing.expectError(error.TrapExists, registry.addTrapChannel("#trapchan"));
}

test "remove trap targets clears membership and reports missing targets" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapNick("Decoy");
    try registry.addTrapChannel("#decoy");

    // Act.
    try registry.removeTrapNick("DECOY");
    try registry.removeTrapChannel("#DECOY");

    // Assert.
    try testing.expect(!try registry.isTrapNick("decoy"));
    try testing.expect(!try registry.isTrapChannel("#decoy"));
    try testing.expectEqual(@as(usize, 0), registry.trapNickCount());
    try testing.expectEqual(@as(usize, 0), registry.trapChannelCount());
    try testing.expectError(error.TrapNotFound, registry.removeTrapNick("decoy"));
    try testing.expectError(error.TrapNotFound, registry.removeTrapChannel("#decoy"));
}

test "triggered ignores operators and ordinary targets" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapNick("sleepy");
    try registry.addTrapChannel("#quiet");

    // Act.
    const oper_hit = try registry.triggered("Helper", .nick, "sleepy", true);
    const normal_nick = try registry.triggered("Guest", .nick, "ordinary", false);
    const normal_channel = try registry.triggered("Guest", .channel, "#ordinary", false);

    // Assert.
    try testing.expect(!oper_hit);
    try testing.expect(!normal_nick);
    try testing.expect(!normal_channel);
    try testing.expect(!try registry.isFlagged("Helper"));
    try testing.expect(!try registry.isFlagged("Guest"));
    try testing.expectEqual(@as(u64, 0), registry.totalTripCount());
    try testing.expectEqual(@as(usize, 0), registry.recentTripCount());
}

test "triggered records non-operator nick trips with actor accounting" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapNick("Sink");

    // Act.
    try testing.expect(try registry.triggered("NoisyUser", .nick, "sink", false));
    try testing.expect(try registry.triggered("noisyuser", .nick, "SINK", false));

    // Assert.
    try testing.expect(try registry.isFlagged("NOISYUSER"));
    try testing.expectEqual(@as(u64, 2), try registry.tripCount("NoisyUser"));
    try testing.expectEqual(@as(u64, 2), registry.totalTripCount());
    try testing.expectEqual(@as(usize, 1), registry.offenderCount());

    var trips: [2]Trip = undefined;
    const recent = try registry.recentTrips(&trips);
    try testing.expectEqual(@as(usize, 2), recent.len);
    try testing.expectEqualStrings("NoisyUser", recent[0].actor);
    try testing.expectEqual(.nick, recent[0].kind);
    try testing.expectEqualStrings("sink", recent[0].target);
    try testing.expectEqual(@as(u64, 1), recent[0].count_for_actor);
    try testing.expectEqualStrings("noisyuser", recent[1].actor);
    try testing.expectEqual(@as(u64, 2), recent[1].count_for_actor);
}

test "triggered records channel trips independently from nick traps" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapNick("Bait");
    try registry.addTrapChannel("#bait");

    // Act.
    const nick_hit = try registry.triggered("Alice", .nick, "bait", false);
    const channel_hit = try registry.triggered("Bob", .channel, "#BAIT", false);

    // Assert.
    try testing.expect(nick_hit);
    try testing.expect(channel_hit);
    try testing.expectEqual(@as(u64, 1), try registry.tripCount("alice"));
    try testing.expectEqual(@as(u64, 1), try registry.tripCount("bob"));
    try testing.expectEqual(@as(usize, 2), registry.offenderCount());

    var trips: [2]Trip = undefined;
    const recent = try registry.recentTrips(&trips);
    try testing.expectEqual(.nick, recent[0].kind);
    try testing.expectEqualStrings("bait", recent[0].target);
    try testing.expectEqual(.channel, recent[1].kind);
    try testing.expectEqualStrings("#BAIT", recent[1].target);
}

test "recent trips are bounded and evict the oldest entry" {
    // Arrange.
    const SmallSpamtrap = Spamtrap(.{
        .max_trap_nicks = 4,
        .max_trap_channels = 4,
        .max_offenders = 8,
        .max_recent_trips = 2,
        .max_nick_bytes = 32,
        .max_channel_bytes = 32,
        .max_actor_bytes = 32,
    });
    var registry = SmallSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapChannel("#sink");

    // Act.
    try testing.expect(try registry.triggered("one", .channel, "#sink", false));
    try testing.expect(try registry.triggered("two", .channel, "#sink", false));
    try testing.expect(try registry.triggered("three", .channel, "#sink", false));

    // Assert.
    try testing.expectEqual(@as(u64, 3), registry.totalTripCount());
    try testing.expectEqual(@as(usize, 3), registry.offenderCount());
    try testing.expectEqual(@as(usize, 2), registry.recentTripCount());

    var trips: [2]Trip = undefined;
    const recent = try registry.recentTrips(&trips);
    try testing.expectEqualStrings("two", recent[0].actor);
    try testing.expectEqualStrings("three", recent[1].actor);
}

test "bounded trap and offender storage returns typed full errors" {
    // Arrange.
    const SmallSpamtrap = Spamtrap(.{
        .max_trap_nicks = 1,
        .max_trap_channels = 1,
        .max_offenders = 1,
        .max_recent_trips = 1,
        .max_nick_bytes = 32,
        .max_channel_bytes = 32,
        .max_actor_bytes = 32,
    });
    var registry = SmallSpamtrap.init(testing.allocator);
    defer registry.deinit();

    // Act.
    try registry.addTrapNick("first");
    try registry.addTrapChannel("#first");
    try testing.expect(try registry.triggered("actor-one", .nick, "first", false));

    // Assert.
    try testing.expectError(error.TrapFull, registry.addTrapNick("second"));
    try testing.expectError(error.TrapFull, registry.addTrapChannel("#second"));
    try testing.expectError(error.TrapFull, registry.triggered("actor-two", .channel, "#first", false));
    try testing.expectEqual(@as(u64, 1), registry.totalTripCount());
    try testing.expectEqual(@as(usize, 1), registry.offenderCount());
}

test "validation rejects malformed and oversized input" {
    // Arrange.
    const SmallSpamtrap = Spamtrap(.{
        .max_trap_nicks = 4,
        .max_trap_channels = 4,
        .max_offenders = 4,
        .max_recent_trips = 4,
        .max_nick_bytes = 4,
        .max_channel_bytes = 6,
        .max_actor_bytes = 5,
    });
    var registry = SmallSpamtrap.init(testing.allocator);
    defer registry.deinit();

    // Act and assert.
    try testing.expectError(error.InvalidNick, registry.addTrapNick(""));
    try testing.expectError(error.InvalidNick, registry.addTrapNick("#nick"));
    try testing.expectError(error.InvalidNick, registry.addTrapNick("a b"));
    try testing.expectError(error.NickTooLong, registry.addTrapNick("abcde"));

    try testing.expectError(error.InvalidChannel, registry.addTrapChannel("plain"));
    try testing.expectError(error.InvalidChannel, registry.addTrapChannel("#b c"));
    try testing.expectError(error.ChannelTooLong, registry.addTrapChannel("#abcdef"));

    try registry.addTrapNick("ok");
    try testing.expectError(error.InvalidActor, registry.triggered("", .nick, "ok", false));
    try testing.expectError(error.InvalidActor, registry.triggered("b ad", .nick, "ok", false));
    try testing.expectError(error.ActorTooLong, registry.triggered("toolong", .nick, "ok", false));
}

test "recentTrips requires enough output storage" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapChannel("#sink");
    try testing.expect(try registry.triggered("user", .channel, "#sink", false));

    // Act and assert.
    var too_small: [0]Trip = .{};
    try testing.expectError(error.OutputTooSmall, registry.recentTrips(&too_small));
}

test "clear frees entries and leaves the registry reusable" {
    // Arrange.
    var registry = DefaultSpamtrap.init(testing.allocator);
    defer registry.deinit();
    try registry.addTrapNick("first");
    try registry.addTrapChannel("#first");
    try testing.expect(try registry.triggered("actor", .nick, "first", false));

    // Act.
    registry.clear();
    try registry.addTrapNick("second");
    try testing.expect(try registry.triggered("actor", .nick, "second", false));

    // Assert.
    try testing.expect(!try registry.isTrapChannel("#first"));
    try testing.expect(try registry.isTrapNick("second"));
    try testing.expectEqual(@as(u64, 1), try registry.tripCount("actor"));
    try testing.expectEqual(@as(u64, 1), registry.totalTripCount());
    try testing.expectEqual(@as(usize, 1), registry.recentTripCount());
}
