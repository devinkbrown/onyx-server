// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-time activity schemas: typing, reactions, and presence.
//!
//! Clean-room server-side data model for the Event-Spine "activity stream"
//! (planning/13): typed representations the daemon stores, converges (Concord
//! CRDT for reactions), and pushes to `ACTIVITY SUBSCRIBE`rs. The IRCv3 tag
//! *relay* already lives in `message_tags_relay`; this is the typed layer
//! underneath — parsing tag values into states, and one tagged union the
//! activity subscription carries.
//!
//! Wire conventions (IRCv3 drafts):
//!   * typing:    `@+typing=active|paused|done` on TAGMSG.
//!   * reactions: `@+draft/react=<reaction>;+draft/reply=<msgid>` on TAGMSG.
//!   * presence:  availability + activity, carried in the Event-Spine payload.
const std = @import("std");

pub const Error = error{
    UnknownTypingState,
    UnknownAvailability,
    EmptyReaction,
    ReactionTooLong,
    MissingReplyTarget,
};

/// Longest accepted reaction token (an emoji or short `:shortcode:`). Bounds the
/// store and prevents a hostile client from pinning unbounded reaction strings.
pub const max_reaction_len = 64;

// ---------------------------------------------------------------------------
// Typing  (IRCv3 draft/typing)
// ---------------------------------------------------------------------------

pub const TypingState = enum {
    active,
    paused,
    done,

    pub fn token(self: TypingState) []const u8 {
        return @tagName(self);
    }

    /// Parse a `+typing` tag value. Unknown values are an error (callers may map
    /// that to `.done` to fail safe, but the schema does not guess).
    pub fn parse(value: []const u8) Error!TypingState {
        if (std.mem.eql(u8, value, "active")) return .active;
        if (std.mem.eql(u8, value, "paused")) return .paused;
        if (std.mem.eql(u8, value, "done")) return .done;
        return error.UnknownTypingState;
    }
};

// ---------------------------------------------------------------------------
// Reactions  (IRCv3 draft/react + draft/reply)
// ---------------------------------------------------------------------------

pub const ReactionOp = enum { add, remove };

/// A reaction event against a prior message. `reaction` and `target_msgid`
/// borrow their inputs. The convergent store keys on `(target_msgid, reactor,
/// reaction)`; `op` drives add/remove in the CRDT.
pub const Reaction = struct {
    target_msgid: []const u8,
    reaction: []const u8,
    op: ReactionOp = .add,

    /// Build a reaction from a TAGMSG's `+draft/react` value plus its
    /// `+draft/reply` target. A bare TAGMSG react is always an `add`; removal is
    /// a separate convergent op the store applies.
    pub fn fromTags(react_value: []const u8, reply_target: ?[]const u8) Error!Reaction {
        return fromTagsWithOp(react_value, reply_target, .add);
    }

    pub fn fromTagsWithOp(react_value: []const u8, reply_target: ?[]const u8, op: ReactionOp) Error!Reaction {
        if (react_value.len == 0) return error.EmptyReaction;
        if (react_value.len > max_reaction_len) return error.ReactionTooLong;
        const target = reply_target orelse return error.MissingReplyTarget;
        if (target.len == 0) return error.MissingReplyTarget;
        return .{ .target_msgid = target, .reaction = react_value, .op = op };
    }
};

// ---------------------------------------------------------------------------
// Reaction tally  (stored; readable after the live push has returned)
// ---------------------------------------------------------------------------

/// Wire caps mirrored here so the ledger can bound its own copies. A msgid is
/// at most the IRCv3 value `msgedit` accepts; a channel name fits the daemon's
/// fixed channel buffer.
pub const max_reaction_target_len = 255;
pub const max_reaction_channel_len = 128;
pub const max_reaction_channels = 4096;
pub const max_reaction_targets_per_channel = 4096;
pub const max_reactions_per_target = 32;
pub const max_reactors_per_reaction = 4096;

const ReactorSet = std.AutoHashMap(u64, void);

const TargetReactions = struct {
    reactions: std.StringHashMap(ReactorSet),
};

const ChannelReactions = struct {
    targets: std.StringHashMap(TargetReactions),
};

/// Convergent reaction tally keyed by `(channel, target_msgid, reaction, reactor)`.
/// `reactor` is the packed client id. Add is idempotent per reactor; remove drops
/// that reactor. The tally a reader observes is the live reactor count of each
/// reaction still on that target. Copies are owned by the ledger.
pub const ReactionLedger = struct {
    pub const Error = std.mem.Allocator.Error || error{
        InvalidChannel,
        InvalidTarget,
        InvalidReaction,
        TooManyChannels,
        TooManyTargets,
        TooManyReactions,
        TooManyReactors,
    };

    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelReactions),

    pub fn init(allocator: std.mem.Allocator) ReactionLedger {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelReactions).init(allocator),
        };
    }

    pub fn deinit(self: *ReactionLedger) void {
        var channels = self.channels.iterator();
        while (channels.next()) |channel| {
            self.allocator.free(channel.key_ptr.*);
            var targets = channel.value_ptr.targets.iterator();
            while (targets.next()) |target| {
                self.allocator.free(target.key_ptr.*);
                var reactions = target.value_ptr.reactions.iterator();
                while (reactions.next()) |reaction| {
                    self.allocator.free(reaction.key_ptr.*);
                    reaction.value_ptr.deinit();
                }
                target.value_ptr.reactions.deinit();
            }
            channel.value_ptr.targets.deinit();
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn apply(
        self: *ReactionLedger,
        channel: []const u8,
        reactor: u64,
        target_msgid: []const u8,
        reaction: []const u8,
        op: ReactionOp,
    ) ReactionLedger.Error!void {
        try validateReactionKey(channel, target_msgid, reaction);
        switch (op) {
            .add => try self.add(channel, reactor, target_msgid, reaction),
            .remove => self.remove(channel, reactor, target_msgid, reaction),
        }
    }

    /// Write the tally for `target_msgid` into `out`.
    /// Form: `target=<msgid>` plus ` <reaction>=<count>` pairs, reactions in
    /// byte order, counts of reactors still holding that reaction. An unknown
    /// target is a zero tally (`target=<msgid>`), not an error.
    pub fn writeTally(
        self: *const ReactionLedger,
        channel: []const u8,
        target_msgid: []const u8,
        out: []u8,
    ) error{NoSpaceLeft}![]const u8 {
        const head = std.fmt.bufPrint(out, "target={s}", .{target_msgid}) catch return error.NoSpaceLeft;
        var pos: usize = head.len;
        const channel_bucket = self.channels.getPtr(channel) orelse return out[0..pos];
        const target_bucket = channel_bucket.targets.getPtr(target_msgid) orelse return out[0..pos];

        const Item = struct { reaction: []const u8, count: u32 };
        var items: [max_reactions_per_target]Item = undefined;
        var n: usize = 0;
        var it = target_bucket.reactions.iterator();
        while (it.next()) |entry| {
            const count = entry.value_ptr.count();
            if (count == 0) continue;
            if (n == items.len) break;
            items[n] = .{
                .reaction = entry.key_ptr.*,
                .count = @intCast(count),
            };
            n += 1;
        }
        std.mem.sort(Item, items[0..n], {}, struct {
            fn lessThan(_: void, a: Item, b: Item) bool {
                return std.mem.lessThan(u8, a.reaction, b.reaction);
            }
        }.lessThan);
        for (items[0..n]) |item| {
            const piece = std.fmt.bufPrint(out[pos..], " {s}={d}", .{ item.reaction, item.count }) catch return error.NoSpaceLeft;
            pos += piece.len;
        }
        return out[0..pos];
    }

    fn add(
        self: *ReactionLedger,
        channel: []const u8,
        reactor: u64,
        target_msgid: []const u8,
        reaction: []const u8,
    ) ReactionLedger.Error!void {
        const channel_bucket = try self.ensureChannel(channel);
        const target_bucket = try self.ensureTarget(channel_bucket, target_msgid);
        const reactors = try self.ensureReaction(target_bucket, reaction);
        if (reactors.contains(reactor)) return;
        if (reactors.count() >= max_reactors_per_reaction) return error.TooManyReactors;
        try reactors.put(reactor, {});
    }

    fn remove(
        self: *ReactionLedger,
        channel: []const u8,
        reactor: u64,
        target_msgid: []const u8,
        reaction: []const u8,
    ) void {
        const channel_entry = self.channels.getEntry(channel) orelse return;
        const target_entry = channel_entry.value_ptr.targets.getEntry(target_msgid) orelse return;
        const reaction_entry = target_entry.value_ptr.reactions.getEntry(reaction) orelse return;
        if (!reaction_entry.value_ptr.remove(reactor)) return;
        if (reaction_entry.value_ptr.count() != 0) return;

        const reaction_key = reaction_entry.key_ptr.*;
        reaction_entry.value_ptr.deinit();
        const reactions = &target_entry.value_ptr.reactions;
        reactions.removeByPtr(reaction_entry.key_ptr);
        self.allocator.free(reaction_key);
        if (reactions.count() != 0) return;

        const target_key = target_entry.key_ptr.*;
        reactions.deinit();
        const targets = &channel_entry.value_ptr.targets;
        targets.removeByPtr(target_entry.key_ptr);
        self.allocator.free(target_key);
        if (targets.count() != 0) return;

        const channel_key = channel_entry.key_ptr.*;
        targets.deinit();
        self.channels.removeByPtr(channel_entry.key_ptr);
        self.allocator.free(channel_key);
    }

    fn ensureChannel(self: *ReactionLedger, channel: []const u8) ReactionLedger.Error!*ChannelReactions {
        if (self.channels.getPtr(channel)) |bucket| return bucket;
        if (self.channels.count() >= max_reaction_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{
            .targets = std.StringHashMap(TargetReactions).init(self.allocator),
        });
        return self.channels.getPtr(owned).?;
    }

    fn ensureTarget(self: *ReactionLedger, channel_bucket: *ChannelReactions, target_msgid: []const u8) ReactionLedger.Error!*TargetReactions {
        if (channel_bucket.targets.getPtr(target_msgid)) |bucket| return bucket;
        if (channel_bucket.targets.count() >= max_reaction_targets_per_channel) return error.TooManyTargets;
        const owned = try self.allocator.dupe(u8, target_msgid);
        errdefer self.allocator.free(owned);
        try channel_bucket.targets.putNoClobber(owned, .{
            .reactions = std.StringHashMap(ReactorSet).init(self.allocator),
        });
        return channel_bucket.targets.getPtr(owned).?;
    }

    fn ensureReaction(self: *ReactionLedger, target_bucket: *TargetReactions, reaction: []const u8) ReactionLedger.Error!*ReactorSet {
        if (target_bucket.reactions.getPtr(reaction)) |set| return set;
        if (target_bucket.reactions.count() >= max_reactions_per_target) return error.TooManyReactions;
        const owned = try self.allocator.dupe(u8, reaction);
        errdefer self.allocator.free(owned);
        try target_bucket.reactions.putNoClobber(owned, ReactorSet.init(self.allocator));
        return target_bucket.reactions.getPtr(owned).?;
    }
};

fn validateReactionKey(channel: []const u8, target_msgid: []const u8, reaction: []const u8) ReactionLedger.Error!void {
    if (channel.len == 0 or channel.len > max_reaction_channel_len) return error.InvalidChannel;
    if (target_msgid.len == 0 or target_msgid.len > max_reaction_target_len) return error.InvalidTarget;
    if (reaction.len == 0 or reaction.len > max_reaction_len) return error.InvalidReaction;
}

// ---------------------------------------------------------------------------
// Presence  (status + activity)
// ---------------------------------------------------------------------------

/// Coarse availability, ordered least→most "do not disturb". Maps onto AWAY:
/// `.active` is here/available, the rest are degrees of unavailable.
pub const Availability = enum {
    active, // present and available
    away, // stepped away
    extended_away, // away for a long time (xa)
    dnd, // do not disturb

    pub fn token(self: Availability) []const u8 {
        return switch (self) {
            .active => "active",
            .away => "away",
            .extended_away => "xa",
            .dnd => "dnd",
        };
    }

    pub fn parse(value: []const u8) Error!Availability {
        if (std.mem.eql(u8, value, "active")) return .active;
        if (std.mem.eql(u8, value, "away")) return .away;
        if (std.mem.eql(u8, value, "xa")) return .extended_away;
        if (std.mem.eql(u8, value, "dnd")) return .dnd;
        return error.UnknownAvailability;
    }
};

/// What the user is actively doing right now (orthogonal to availability).
pub const Activity = enum { idle, typing, speaking };

pub const Presence = struct {
    availability: Availability = .active,
    activity: Activity = .idle,
};

// ---------------------------------------------------------------------------
// Event-Spine activity event
// ---------------------------------------------------------------------------

/// One activity event delivered to an `ACTIVITY SUBSCRIBE`r. The `who`/`channel`
/// strings borrow the caller's storage.
pub const ActivityEvent = struct {
    who: []const u8,
    channel: []const u8,
    payload: Payload,

    pub const Kind = enum { typing, reaction, presence };

    pub const Payload = union(Kind) {
        typing: TypingState,
        reaction: Reaction,
        presence: Presence,
    };

    pub fn kind(self: ActivityEvent) Kind {
        return self.payload;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "typing state round-trips through its tag token" {
    for ([_]TypingState{ .active, .paused, .done }) |s| {
        try testing.expectEqual(s, try TypingState.parse(s.token()));
    }
    try testing.expectError(error.UnknownTypingState, TypingState.parse("typing"));
}

test "reaction from tags requires a reply target and a non-empty reaction" {
    const r = try Reaction.fromTags("🔥", "msg-7");
    try testing.expectEqualStrings("msg-7", r.target_msgid);
    try testing.expectEqualStrings("🔥", r.reaction);
    try testing.expectEqual(ReactionOp.add, r.op);

    const removed = try Reaction.fromTagsWithOp("🔥", "msg-7", .remove);
    try testing.expectEqualStrings("msg-7", removed.target_msgid);
    try testing.expectEqualStrings("🔥", removed.reaction);
    try testing.expectEqual(ReactionOp.remove, removed.op);

    try testing.expectError(error.EmptyReaction, Reaction.fromTags("", "msg-7"));
    try testing.expectError(error.MissingReplyTarget, Reaction.fromTags("👍", null));
    try testing.expectError(error.MissingReplyTarget, Reaction.fromTags("👍", ""));
}

test "an over-long reaction is rejected" {
    const big = &@as([(max_reaction_len + 1)]u8, @splat('x'));
    try testing.expectError(error.ReactionTooLong, Reaction.fromTags(big, "m1"));
}

test "availability tokens map xa correctly and reject unknowns" {
    try testing.expectEqualStrings("xa", Availability.extended_away.token());
    try testing.expectEqual(Availability.extended_away, try Availability.parse("xa"));
    try testing.expectEqual(Availability.dnd, try Availability.parse("dnd"));
    try testing.expectError(error.UnknownAvailability, Availability.parse("invisible"));
}

test "activity event reports its kind from the payload union" {
    const ev = ActivityEvent{
        .who = "alice",
        .channel = "#chat",
        .payload = .{ .typing = .active },
    };
    try testing.expectEqual(ActivityEvent.Kind.typing, ev.kind());

    const re = ActivityEvent{
        .who = "bob",
        .channel = "#chat",
        .payload = .{ .reaction = try Reaction.fromTags("👍", "m1") },
    };
    try testing.expectEqual(ActivityEvent.Kind.reaction, re.kind());
}

test "default presence is active and idle" {
    const p = Presence{};
    try testing.expectEqual(Availability.active, p.availability);
    try testing.expectEqual(Activity.idle, p.activity);
}

test "reaction ledger tally counts distinct reactors on one target" {
    var ledger = ReactionLedger.init(testing.allocator);
    defer ledger.deinit();
    const channel = "#chat";
    const target = "msg-stable-1";
    try ledger.apply(channel, 1, target, "fire", .add);
    try ledger.apply(channel, 1, target, "fire", .add);
    try ledger.apply(channel, 2, target, "fire", .add);
    try ledger.apply(channel, 2, "msg-other", "fire", .add);
    try ledger.apply(channel, 1, target, "fire", .remove);

    var buf: [128]u8 = undefined;
    const tally = try ledger.writeTally(channel, target, &buf);
    try testing.expectEqualStrings("target=msg-stable-1 fire=1", tally);
    const other = try ledger.writeTally(channel, "msg-other", &buf);
    try testing.expectEqualStrings("target=msg-other fire=1", other);
    const empty = try ledger.writeTally(channel, "msg-none", &buf);
    try testing.expectEqualStrings("target=msg-none", empty);

    try ledger.apply(channel, 2, target, "fire", .remove);
    const gone = try ledger.writeTally(channel, target, &buf);
    try testing.expectEqualStrings("target=msg-stable-1", gone);
    try ledger.apply(channel, 2, target, "wave", .add);
    try ledger.apply(channel, 2, target, "fire", .add);
    const both = try ledger.writeTally(channel, target, &buf);
    try testing.expectEqualStrings("target=msg-stable-1 fire=1 wave=1", both);
}
