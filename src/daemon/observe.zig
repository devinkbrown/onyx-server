// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx Server OBSERVE — operator observation subscriptions on the Event Spine.
//!
//! This is NOT a stateless "spy and dump" query. An operator declares a standing
//! *interest mask* with `EVENT OBSERVE <mask>`; the daemon then keeps that filter
//! and **pushes** a live `:<srv> EVENT <oper> OBSERVE` record (carrying the subject's real,
//! uncloaked identity) every time a matching client's lifecycle changes —
//! connect, quit, nick change, join, part, host change, oper-up. Subscribing also
//! emits an immediate snapshot of the currently-matching population.
//!
//! The model inverts the legacy pull-based surveillance command into a stateful,
//! filtered, push-based feed that rides the existing Event Spine delivery.
//! This module is pure: it owns the per-observer filters and the matching/render
//! logic; the live server supplies subject snapshots and performs delivery.

const std = @import("std");

/// A lifecycle transition an observer can be notified about.
pub const Action = enum(u8) {
    connect,
    quit,
    nick,
    join,
    part,
    host_change,
    oper_up,

    /// Lowercase wire token for the action (used in event rendering + parsing).
    pub fn token(self: Action) []const u8 {
        return switch (self) {
            .connect => "connect",
            .quit => "quit",
            .nick => "nick",
            .join => "join",
            .part => "part",
            .host_change => "host",
            .oper_up => "oper",
        };
    }

    /// Bit position of this action within a `Filter.actions` bitset.
    pub fn bit(self: Action) u16 {
        return @as(u16, 1) << @as(u4, @intCast(@backingInt(self)));
    }

    /// Parse a case-insensitive action token, or null if unknown.
    pub fn parse(raw: []const u8) ?Action {
        inline for (@typeInfo(Action).@"enum".field_values) |f_value| {
            const a: Action = @fromBackingInt(@intCast(f_value));
            if (std.ascii.eqlIgnoreCase(raw, a.token())) return a;
        }
        return null;
    }
};

/// Bitset value covering every action (the default subscription scope).
pub const all_actions: u16 = blk: {
    var m: u16 = 0;
    for (@typeInfo(Action).@"enum".field_values) |f_value| {
        const a: Action = @fromBackingInt(@intCast(f_value));
        m |= a.bit();
    }
    break :blk m;
};

/// A read-only snapshot of the client an event concerns. All slices are borrowed
/// from the live server for the duration of a notify call; `host` is the REAL
/// (uncloaked) host — observation is an operator-trust surface.
pub const Subject = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    account: ?[]const u8 = null,
    /// Action-specific extra: new nick, channel name, quit reason, etc.
    detail: []const u8 = "",
};

/// A standing observer subscription: a glob mask over `nick!user@host` plus the
/// set of actions of interest.
pub const Filter = struct {
    mask: []const u8,
    actions: u16,
    since_ms: i64,
};

/// Operational limits for the registry.
pub const Params = struct {
    max_observers: usize = 256,
    max_mask_bytes: usize = 256,
};

pub const ObserveError = std.mem.Allocator.Error || error{
    TooManyObservers,
    MaskTooLong,
    EmptyMask,
};

/// Per-observer subscription store, keyed by an opaque observer id (the live
/// server's bitcast ClientId). Mask strings are owned and freed on replace/clear.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    params: Params,
    map: std.AutoHashMapUnmanaged(u64, Filter) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Registry {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.map.iterator();
        while (it.next()) |e| self.allocator.free(e.value_ptr.mask);
        self.map.deinit(self.allocator);
    }

    /// Install or replace `observer`'s filter. `actions` selects the lifecycle
    /// bits (use `all_actions` for the default). The mask is duped and owned.
    pub fn set(self: *Registry, observer: u64, mask: []const u8, actions: u16, now_ms: i64) ObserveError!void {
        if (mask.len == 0) return error.EmptyMask;
        if (mask.len > self.params.max_mask_bytes) return error.MaskTooLong;
        const existing = self.map.getPtr(observer);
        if (existing == null and self.map.count() >= self.params.max_observers) return error.TooManyObservers;

        const owned = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned);
        const filter = Filter{ .mask = owned, .actions = if (actions == 0) all_actions else actions, .since_ms = now_ms };
        if (existing) |slot| {
            self.allocator.free(slot.mask);
            slot.* = filter;
        } else {
            try self.map.put(self.allocator, observer, filter);
        }
    }

    /// Remove `observer`'s subscription. Returns true if one existed.
    pub fn clear(self: *Registry, observer: u64) bool {
        if (self.map.fetchRemove(observer)) |kv| {
            self.allocator.free(kv.value.mask);
            return true;
        }
        return false;
    }

    /// The observer's current filter, or null if not subscribed.
    pub fn get(self: *const Registry, observer: u64) ?Filter {
        return self.map.get(observer);
    }

    /// Number of live subscriptions.
    pub fn count(self: *const Registry) usize {
        return self.map.count();
    }

    /// Whether `filter` is interested in `action` AND its mask matches the
    /// subject's `nick!user@host`.
    pub fn matches(filter: Filter, subject: Subject, action: Action) bool {
        if (filter.actions & action.bit() == 0) return false;
        var buf: [Subject_hostmask_max]u8 = undefined;
        const hm = hostmask(&buf, subject) orelse return false;
        return globMatch(filter.mask, hm);
    }

    /// Render the chatsvc-faithful OBSERVE event line into `out`:
    ///   `:<server> EVENT <target> OBSERVE <action> <nick>!<user>@<host> acct=<acct>[ <detail>]`
    /// `target` is the watching operator's nick (the recipient), matching the raw
    /// `:<srv> EVENT <target> <body>` form every other Event-Spine event now uses.
    pub fn formatEvent(out: []u8, server_name: []const u8, target: []const u8, action: Action, subject: Subject) ?[]const u8 {
        const acct = subject.account orelse "*";
        if (subject.detail.len == 0) {
            return std.fmt.bufPrint(out, ":{s} EVENT {s} OBSERVE {s} {s}!{s}@{s} acct={s}\r\n", .{ server_name, target, action.token(), subject.nick, subject.user, subject.host, acct }) catch null;
        }
        return std.fmt.bufPrint(out, ":{s} EVENT {s} OBSERVE {s} {s}!{s}@{s} acct={s} {s}\r\n", .{ server_name, target, action.token(), subject.nick, subject.user, subject.host, acct, subject.detail }) catch null;
    }
};

const Subject_hostmask_max = 64 + 64 + 256 + 2;

/// Build `nick!user@host` into `buf`; null if it would overflow.
fn hostmask(buf: []u8, subject: Subject) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{s}!{s}@{s}", .{ subject.nick, subject.user, subject.host }) catch null;
}

/// Iterative, case-insensitive `*`/`?` glob matcher (no recursion, backtracking).
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

test "action token round-trips and bits are distinct" {
    inline for (@typeInfo(Action).@"enum".field_values) |f_value| {
        const a: Action = @fromBackingInt(@intCast(f_value));
        try std.testing.expectEqual(a, Action.parse(a.token()).?);
    }
    try std.testing.expect(Action.connect.bit() != Action.quit.bit());
    try std.testing.expect(all_actions & Action.oper_up.bit() != 0);
}

test "glob matches nick!user@host case-insensitively" {
    try std.testing.expect(globMatch("*!*@*.example", "Bob!~b@host.example"));
    try std.testing.expect(globMatch("bob!*@*", "BOB!~x@1.2.3.4"));
    try std.testing.expect(!globMatch("alice!*@*", "bob!~x@1.2.3.4"));
    try std.testing.expect(globMatch("*", "anything"));
    try std.testing.expect(globMatch("a?c", "abc"));
}

test "set/get/clear with owned masks and no leak" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();

    try reg.set(1, "*!*@*.evil", all_actions, 100);
    try std.testing.expect(reg.get(1) != null);
    try std.testing.expectEqual(@as(usize, 1), reg.count());

    // Replace keeps a single owned mask (no leak on replace).
    try reg.set(1, "bad!*@*", Action.quit.bit(), 200);
    try std.testing.expectEqualStrings("bad!*@*", reg.get(1).?.mask);

    try std.testing.expect(reg.clear(1));
    try std.testing.expect(!reg.clear(1));
    try std.testing.expectEqual(@as(usize, 0), reg.count());
}

test "matches gates on action bit and mask" {
    const subj = Subject{ .nick = "bob", .user = "~b", .host = "10.0.0.4", .account = "bob" };
    const only_quit = Filter{ .mask = "*!*@10.0.0.*", .actions = Action.quit.bit(), .since_ms = 0 };
    try std.testing.expect(Registry.matches(only_quit, subj, .quit));
    try std.testing.expect(!Registry.matches(only_quit, subj, .connect)); // action not subscribed
    const wrong_mask = Filter{ .mask = "*!*@192.*", .actions = all_actions, .since_ms = 0 };
    try std.testing.expect(!Registry.matches(wrong_mask, subj, .quit));
}

test "set enforces limits" {
    var reg = Registry.init(std.testing.allocator, .{ .max_observers = 1, .max_mask_bytes = 8 });
    defer reg.deinit();
    try reg.set(1, "*", all_actions, 0);
    try std.testing.expectError(error.TooManyObservers, reg.set(2, "*", all_actions, 0));
    try std.testing.expectError(error.MaskTooLong, reg.set(1, "toolongmask!", all_actions, 0));
    try std.testing.expectError(error.EmptyMask, reg.set(1, "", all_actions, 0));
}

test "formatEvent renders the chatsvc EVENT line with and without detail" {
    const subj = Subject{ .nick = "bob", .user = "~b", .host = "10.0.0.4", .account = "bob" };
    var buf: [256]u8 = undefined;
    const a = Registry.formatEvent(&buf, "onyx.local", "kain", .connect, subj).?;
    try std.testing.expectEqualStrings(":onyx.local EVENT kain OBSERVE connect bob!~b@10.0.0.4 acct=bob\r\n", a);
    var buf2: [256]u8 = undefined;
    const subj2 = Subject{ .nick = "bob", .user = "~b", .host = "10.0.0.4", .detail = "-> robert" };
    const b = Registry.formatEvent(&buf2, "onyx.local", "kain", .nick, subj2).?;
    try std.testing.expectEqualStrings(":onyx.local EVENT kain OBSERVE nick bob!~b@10.0.0.4 acct=* -> robert\r\n", b);
}
