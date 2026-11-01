//! Exact physical media crypto provenance, independent of browser routing.
const std = @import("std");
const client = @import("client.zig");
pub const max_channel_len = client.MAX_CHANNEL_NAME_BYTES;
pub const max_participant_len = client.MAX_NICK_BYTES;
comptime {
    // HXMG2 explicitly encodes these owned fixed arrays. Future bound changes
    // require schema review rather than silently changing an inherited body.
    if (max_channel_len != 128 or max_participant_len != 64) @compileError("media crypto scope bounds changed; review HXMG schema version");
}

pub const Error = error{InvalidScope};
pub const Scope = struct {
    channel: [max_channel_len]u8 = @splat(0),
    participant: [max_participant_len]u8 = @splat(0),
    attachment: [16]u8 = @splat(0),
    channel_len: u8 = 0,
    participant_len: u8 = 0,
    bound: bool = false,

    pub fn init(channel: []const u8, participant: []const u8, attachment: [16]u8) Error!Scope {
        if (channel.len == 0 or channel.len > max_channel_len or participant.len == 0 or participant.len > max_participant_len) return error.InvalidScope;
        var result = Scope{ .channel_len = @intCast(channel.len), .participant_len = @intCast(participant.len), .attachment = attachment, .bound = true };
        @memcpy(result.channel[0..channel.len], channel);
        @memcpy(result.participant[0..participant.len], participant);
        try result.validate();
        return result;
    }
    pub fn channelSlice(self: *const Scope) []const u8 {
        return self.channel[0..self.channel_len];
    }
    pub fn participantSlice(self: *const Scope) []const u8 {
        return self.participant[0..self.participant_len];
    }
    pub fn validate(self: *const Scope) Error!void {
        if (self.channel_len > self.channel.len or self.participant_len > self.participant.len) return error.InvalidScope;
        if (!self.bound) {
            if (self.channel_len != 0 or self.participant_len != 0) return error.InvalidScope;
            for (self.channel) |byte| if (byte != 0) return error.InvalidScope;
            for (self.participant) |byte| if (byte != 0) return error.InvalidScope;
            for (self.attachment) |byte| if (byte != 0) return error.InvalidScope;
            return;
        }
        if (self.channel_len == 0 or self.participant_len == 0) return error.InvalidScope;
        const channel = self.channelSlice();
        if (channel[0] != '#' and channel[0] != '&' and !(channel.len >= 2 and channel[0] == '%' and (channel[1] == '#' or channel[1] == '&'))) return error.InvalidScope;
        for (channel) |byte| if (byte <= 0x20 or byte == 0x7f) return error.InvalidScope;
        for (self.participantSlice()) |byte| if (byte <= 0x20 or byte == 0x7f) return error.InvalidScope;
        for (self.channel[self.channel_len..]) |byte| if (byte != 0) return error.InvalidScope;
        for (self.participant[self.participant_len..]) |byte| if (byte != 0) return error.InvalidScope;
        var nonzero = false;
        for (self.attachment) |byte| nonzero = nonzero or byte != 0;
        if (!nonzero) return error.InvalidScope;
    }
    pub fn matchesIdentity(self: *const Scope, channel: []const u8, participant: []const u8) bool {
        self.validate() catch return false;
        return self.bound and std.ascii.eqlIgnoreCase(self.channelSlice(), channel) and std.ascii.eqlIgnoreCase(self.participantSlice(), participant);
    }
    pub fn matches(self: *const Scope, channel: []const u8, participant: []const u8, attachment: [16]u8) bool {
        return self.matchesIdentity(channel, participant) and std.crypto.timing_safe.eql([16]u8, self.attachment, attachment);
    }
    /// DETACH addresses this public tuple, not a local ClientId. Two physical
    /// owners must never hold the same canonical tuple concurrently.
    pub fn sameTuple(self: *const Scope, other: *const Scope) bool {
        other.validate() catch return false;
        return other.bound and self.matches(other.channelSlice(), other.participantSlice(), other.attachment);
    }
    pub fn clear(self: *Scope) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

test "media crypto scope owns complete identity and distinguishes same bytes across calls" {
    const aid: [16]u8 = @splat(0x31);
    var scope = try Scope.init("#first", "Person", aid);
    try std.testing.expect(scope.matches("#FIRST", "person", aid));
    try std.testing.expect(!scope.matches("#second", "Person", aid));
    try std.testing.expect(!scope.matches("#first", "Sibling", aid));
    try std.testing.expect(!scope.matches("#first", "Person", @splat(0x32)));
    scope.clear();
    try scope.validate();
    try std.testing.expect(!scope.bound);
    try std.testing.expectError(error.InvalidScope, Scope.init("#first", "Person", @splat(0)));
    try std.testing.expectError(error.InvalidScope, Scope.init("#bad channel", "Person", aid));
    try std.testing.expectError(error.InvalidScope, Scope.init("#first", "bad\nparticipant", aid));
}

test "media crypto scope accepts complete native channel and nickname storage boundaries" {
    var channel: [max_channel_len]u8 = @splat('c');
    channel[0] = '#';
    const nick: [max_participant_len]u8 = @splat('N');
    const scope = try Scope.init(&channel, &nick, @splat(0x41));
    try std.testing.expect(scope.matches(&channel, &nick, @splat(0x41)));
    var too_long_channel: [max_channel_len + 1]u8 = @splat('c');
    too_long_channel[0] = '#';
    const too_long_nick: [max_participant_len + 1]u8 = @splat('N');
    try std.testing.expectError(error.InvalidScope, Scope.init(&too_long_channel, &nick, @splat(0x41)));
    try std.testing.expectError(error.InvalidScope, Scope.init(&channel, &too_long_nick, @splat(0x41)));
    try std.testing.expect(scope.matches(&channel, &nick, @splat(0x41)));
}

test "media crypto scope canonical tuple distinguishes owner-independent collisions from cross-channel reuse" {
    const first = try Scope.init("#first", "Person", @splat(0x61));
    const same = try Scope.init("#FIRST", "person", @splat(0x61));
    const other_channel = try Scope.init("#second", "Person", @splat(0x61));
    const other_participant = try Scope.init("#first", "Other", @splat(0x61));
    const other_attachment = try Scope.init("#first", "Person", @splat(0x62));
    try std.testing.expect(first.sameTuple(&same));
    try std.testing.expect(!first.sameTuple(&other_channel));
    try std.testing.expect(!first.sameTuple(&other_participant));
    try std.testing.expect(!first.sameTuple(&other_attachment));
    try std.testing.expect(!first.sameTuple(&Scope{}));
}
