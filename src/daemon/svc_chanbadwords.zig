// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel bad-word moderation policy.
//!
//! This module is intentionally pure: it stores channel-local patterns, parses
//! real server commands, and returns actions for the daemon to enforce with
//! normal IRC commands/numerics. It does not model ChanServ/NickServ/OperServ
//! pseudo-clients and it is separate from the global Koshi content filter.
const std = @import("std");

pub const hard_max_channel_len: usize = 256;
pub const default_max_channels: usize = 1024;
pub const default_max_rules_per_channel: usize = 64;
pub const default_max_channel_len: usize = 128;
pub const default_max_pattern_len: usize = 128;

pub const Params = struct {
    max_channels: usize = default_max_channels,
    max_rules_per_channel: usize = default_max_rules_per_channel,
    max_channel_len: usize = default_max_channel_len,
    max_pattern_len: usize = default_max_pattern_len,
};

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    InvalidChannel,
    ChannelTooLong,
    EmptyPattern,
    PatternTooLong,
    InvalidPattern,
    TooManyChannels,
    TooManyRules,
    OutputTooSmall,
};

pub const ParseError = error{
    EmptyLine,
    UnknownCommand,
    InvalidSubcommand,
    InvalidAction,
    NeedMoreParams,
    TooManyParams,
    PseudoClientCommand,
};

pub const Action = enum {
    kick,

    pub fn fromToken(token: []const u8) ?Action {
        if (std.ascii.eqlIgnoreCase(token, "KICK")) return .kick;
        return null;
    }

    pub fn commandName(self: Action) []const u8 {
        return switch (self) {
            .kick => "KICK",
        };
    }
};

pub const RequestKind = enum {
    add,
    remove,
    list,
};

/// Parsed request. Slices point into the input line passed to `parseRequest`.
pub const Request = struct {
    kind: RequestKind,
    channel: []const u8,
    pattern: ?[]const u8 = null,
    action: ?Action = null,
};

/// Numeric hints a caller can use when translating this module's outcomes to
/// IRC replies. The list numerics are Onyx Server extension numerics; the errors
/// are standard server numerics already used by IRC daemons.
pub const Numeric = enum(u16) {
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_INVALIDMODEPARAM = 696,
    RPL_CHANBADWORD = 950,
    RPL_ENDOFCHANBADWORDS = 951,

    pub fn code(self: Numeric) u16 {
        return @backingInt(self);
    }

    pub fn format(self: Numeric, out: *[3]u8) []const u8 {
        return std.fmt.bufPrint(out, "{d:0>3}", .{self.code()}) catch unreachable;
    }
};

pub const Entry = struct {
    channel: []const u8,
    pattern: []const u8,
    action: Action,
};

const StoredRule = struct {
    pattern: []u8,
    action: Action,
};

const ChannelRules = struct {
    rules: std.ArrayListUnmanaged(StoredRule) = .empty,

    fn deinit(self: *ChannelRules, allocator: std.mem.Allocator) void {
        for (self.rules.items) |rule| allocator.free(rule.pattern);
        self.rules.deinit(allocator);
        self.* = undefined;
    }

    fn add(self: *ChannelRules, allocator: std.mem.Allocator, max_rules: usize, pattern: []const u8, action: Action) Error!bool {
        if (self.indexOf(pattern) != null) return false;
        if (self.rules.items.len >= max_rules) return error.TooManyRules;

        const owned = try allocator.dupe(u8, pattern);
        errdefer allocator.free(owned);
        try self.rules.append(allocator, .{ .pattern = owned, .action = action });
        return true;
    }

    fn remove(self: *ChannelRules, allocator: std.mem.Allocator, pattern: []const u8) bool {
        const idx = self.indexOf(pattern) orelse return false;
        allocator.free(self.rules.items[idx].pattern);
        _ = self.rules.orderedRemove(idx);
        return true;
    }

    fn indexOf(self: *const ChannelRules, pattern: []const u8) ?usize {
        for (self.rules.items, 0..) |rule, idx| {
            if (std.ascii.eqlIgnoreCase(rule.pattern, pattern)) return idx;
        }
        return null;
    }

    fn matchingAction(self: *const ChannelRules, text: []const u8) ?Action {
        for (self.rules.items) |rule| {
            if (containsIgnoreCase(text, rule.pattern)) return rule.action;
        }
        return null;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    channels: std.StringHashMapUnmanaged(ChannelRules) = .empty,

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithParams(allocator, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Store {
        std.debug.assert(params.max_channels > 0);
        std.debug.assert(params.max_rules_per_channel > 0);
        std.debug.assert(params.max_channel_len > 0);
        std.debug.assert(params.max_channel_len <= hard_max_channel_len);
        std.debug.assert(params.max_pattern_len > 0);
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Store) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *Store, channel: []const u8, pattern: []const u8, action: Action) Error!bool {
        try self.validateChannel(channel);
        try self.validatePattern(pattern);

        var key_buf: [hard_max_channel_len]u8 = undefined;
        const key = canonicalChannelInto(channel, &key_buf) orelse return error.ChannelTooLong;
        if (self.channels.getPtr(key)) |rules| {
            return rules.add(self.allocator, self.params.max_rules_per_channel, pattern, action);
        }
        if (self.channels.count() >= self.params.max_channels) return error.TooManyChannels;

        var rules = ChannelRules{};
        errdefer rules.deinit(self.allocator);
        _ = try rules.add(self.allocator, self.params.max_rules_per_channel, pattern, action);

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.channels.putNoClobber(self.allocator, owned_key, rules);
        return true;
    }

    pub fn remove(self: *Store, channel: []const u8, pattern: []const u8) Error!bool {
        try self.validateChannel(channel);
        try self.validatePattern(pattern);

        var key_buf: [hard_max_channel_len]u8 = undefined;
        const key = canonicalChannelInto(channel, &key_buf) orelse return error.ChannelTooLong;
        var rules = self.channels.getPtr(key) orelse return false;
        if (!rules.remove(self.allocator, pattern)) return false;

        if (rules.rules.items.len == 0) {
            var removed = self.channels.fetchRemove(key).?;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
        }
        return true;
    }

    /// Copy channel rules into caller-owned output. Entry channels borrow the
    /// caller's `channel` argument; entry patterns borrow storage owned by
    /// `Store` and remain valid until the next mutation.
    pub fn list(self: *const Store, channel: []const u8, out: []Entry) Error![]const Entry {
        try self.validateChannel(channel);

        var key_buf: [hard_max_channel_len]u8 = undefined;
        const key = canonicalChannelInto(channel, &key_buf) orelse return error.ChannelTooLong;
        const rules = self.channels.get(key) orelse return out[0..0];
        if (out.len < rules.rules.items.len) return error.OutputTooSmall;

        for (rules.rules.items, 0..) |rule, idx| {
            out[idx] = .{ .channel = channel, .pattern = rule.pattern, .action = rule.action };
        }
        return out[0..rules.rules.items.len];
    }

    /// Return the action for the first bad-word hit in `text`, or null.
    pub fn matches(self: *const Store, channel: []const u8, text: []const u8) ?Action {
        var key_buf: [hard_max_channel_len]u8 = undefined;
        const key = canonicalChannelInto(channel, &key_buf) orelse return null;
        const rules = self.channels.get(key) orelse return null;
        return rules.matchingAction(text);
    }

    pub fn channelCount(self: *const Store) usize {
        return self.channels.count();
    }

    fn validateChannel(self: *const Store, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.params.max_channel_len) return error.ChannelTooLong;
        if (!isChannelPrefix(channel[0])) return error.InvalidChannel;
        for (channel) |byte| {
            if (byte == 0 or byte == 7 or byte == 10 or byte == 13 or byte == ' ' or byte == ',' or byte == ':') {
                return error.InvalidChannel;
            }
        }
    }

    fn validatePattern(self: *const Store, pattern: []const u8) Error!void {
        if (pattern.len == 0) return error.EmptyPattern;
        if (pattern.len > self.params.max_pattern_len) return error.PatternTooLong;
        for (pattern) |byte| {
            if (byte == 0 or byte == 10 or byte == 13) return error.InvalidPattern;
        }
    }
};

pub fn parseRequest(input: []const u8) ParseError!Request {
    const line = try parseLine(input);
    if (isPseudoService(line.command)) return error.PseudoClientCommand;
    if (std.ascii.eqlIgnoreCase(line.command, "PRIVMSG") and line.len > 0 and isPseudoService(line.params[0])) {
        return error.PseudoClientCommand;
    }

    if (std.ascii.eqlIgnoreCase(line.command, "CHANNEL")) {
        if (line.len == 0) return error.NeedMoreParams;
        if (!std.ascii.eqlIgnoreCase(line.params[0], "BADWORDS")) return error.InvalidSubcommand;
        return parseSubcommand(line.params[1..line.len]);
    }

    if (std.ascii.eqlIgnoreCase(line.command, "CHANBADWORDS")) {
        return parseSubcommand(line.params[0..line.len]);
    }

    return error.UnknownCommand;
}

fn parseSubcommand(params: []const []const u8) ParseError!Request {
    if (params.len == 0) return error.NeedMoreParams;
    const op = params[0];

    if (std.ascii.eqlIgnoreCase(op, "ADD") or std.mem.eql(u8, op, "+")) {
        if (params.len < 4) return error.NeedMoreParams;
        const action = Action.fromToken(params[2]) orelse return error.InvalidAction;
        return .{ .kind = .add, .channel = params[1], .pattern = params[3], .action = action };
    }

    if (std.ascii.eqlIgnoreCase(op, "REMOVE") or
        std.ascii.eqlIgnoreCase(op, "DEL") or
        std.ascii.eqlIgnoreCase(op, "DELETE") or
        std.mem.eql(u8, op, "-"))
    {
        if (params.len < 3) return error.NeedMoreParams;
        return .{ .kind = .remove, .channel = params[1], .pattern = params[2] };
    }

    if (std.ascii.eqlIgnoreCase(op, "LIST")) {
        if (params.len < 2) return error.NeedMoreParams;
        return .{ .kind = .list, .channel = params[1] };
    }

    return error.InvalidSubcommand;
}

const ParsedLine = struct {
    command: []const u8,
    params: [8][]const u8 = undefined,
    len: usize = 0,
};

fn parseLine(input: []const u8) ParseError!ParsedLine {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.EmptyLine;

    var i: usize = 0;
    if (trimmed[i] == '@') {
        skipToken(trimmed, &i);
        skipSpaces(trimmed, &i);
        if (i >= trimmed.len) return error.EmptyLine;
    }
    if (trimmed[i] == ':') {
        skipToken(trimmed, &i);
        skipSpaces(trimmed, &i);
        if (i >= trimmed.len) return error.EmptyLine;
    }

    const command = nextToken(trimmed, &i) orelse return error.EmptyLine;
    var parsed = ParsedLine{ .command = command };

    while (true) {
        skipSpaces(trimmed, &i);
        if (i >= trimmed.len) break;
        if (parsed.len >= parsed.params.len) return error.TooManyParams;

        if (trimmed[i] == ':') {
            parsed.params[parsed.len] = trimmed[i + 1 ..];
            parsed.len += 1;
            break;
        }

        parsed.params[parsed.len] = nextToken(trimmed, &i) orelse break;
        parsed.len += 1;
    }

    return parsed;
}

fn skipSpaces(input: []const u8, index: *usize) void {
    while (index.* < input.len and (input[index.*] == ' ' or input[index.*] == '\t')) {
        index.* += 1;
    }
}

fn skipToken(input: []const u8, index: *usize) void {
    while (index.* < input.len and input[index.*] != ' ' and input[index.*] != '\t') {
        index.* += 1;
    }
}

fn nextToken(input: []const u8, index: *usize) ?[]const u8 {
    skipSpaces(input, index);
    if (index.* >= input.len) return null;
    const start = index.*;
    skipToken(input, index);
    return input[start..index.*];
}

fn isPseudoService(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "CHANSERV") or
        std.ascii.eqlIgnoreCase(token, "NICKSERV") or
        std.ascii.eqlIgnoreCase(token, "OPERSERV") or
        std.ascii.eqlIgnoreCase(token, "MEMOSERV") or
        std.ascii.eqlIgnoreCase(token, "BOTSERV");
}

fn isChannelPrefix(byte: u8) bool {
    return byte == '#' or byte == '&';
}

fn canonicalChannelInto(channel: []const u8, out: *[hard_max_channel_len]u8) ?[]const u8 {
    if (channel.len > hard_max_channel_len) return null;
    for (channel, 0..) |byte, idx| out[idx] = std.ascii.toLower(byte);
    return out[0..channel.len];
}

pub fn containsIgnoreCase(text: []const u8, pattern: []const u8) bool {
    if (pattern.len == 0) return true;
    if (pattern.len > text.len) return false;

    var start: usize = 0;
    while (start + pattern.len <= text.len) : (start += 1) {
        var offset: usize = 0;
        while (offset < pattern.len) : (offset += 1) {
            if (std.ascii.toLower(text[start + offset]) != std.ascii.toLower(pattern[offset])) break;
        } else {
            return true;
        }
    }
    return false;
}

const testing = std.testing;

test "add list match and remove per channel" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    try testing.expect(try store.add("#ops", "bad phrase", .kick));
    try testing.expectEqual(Action.kick, store.matches("#OPS", "that BAD PHRASE is blocked").?);
    try testing.expectEqual(@as(?Action, null), store.matches("#ops", "clean text"));
    try testing.expectEqual(@as(?Action, null), store.matches("#other", "bad phrase"));

    var out: [4]Entry = undefined;
    const listed = try store.list("#Ops", &out);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("#Ops", listed[0].channel);
    try testing.expectEqualStrings("bad phrase", listed[0].pattern);
    try testing.expectEqual(Action.kick, listed[0].action);

    try testing.expect(try store.remove("#OPS", "BAD PHRASE"));
    try testing.expectEqual(@as(?Action, null), store.matches("#ops", "bad phrase"));
    try testing.expectEqual(@as(usize, 0), store.channelCount());
}

test "duplicates are case insensitive but channel scopes are independent" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    try testing.expect(try store.add("#a", "word", .kick));
    try testing.expect(!try store.add("#A", "WORD", .kick));
    try testing.expect(try store.add("#b", "WORD", .kick));
    try testing.expectEqual(Action.kick, store.matches("#a", "a word").?);
    try testing.expectEqual(Action.kick, store.matches("#B", "a word").?);
}

test "bounds reject invalid channels patterns and full tables" {
    var store = Store.initWithParams(testing.allocator, .{
        .max_channels = 1,
        .max_rules_per_channel = 1,
        .max_channel_len = 8,
        .max_pattern_len = 5,
    });
    defer store.deinit();

    try testing.expectError(error.InvalidChannel, store.add("notchan", "word", .kick));
    try testing.expectError(error.EmptyPattern, store.add("#a", "", .kick));
    try testing.expectError(error.PatternTooLong, store.add("#a", "toolong", .kick));
    try testing.expect(try store.add("#a", "word", .kick));
    try testing.expectError(error.TooManyRules, store.add("#a", "other", .kick));
    try testing.expectError(error.TooManyChannels, store.add("#b", "word", .kick));

    var out: [0]Entry = .{};
    try testing.expectError(error.OutputTooSmall, store.list("#a", &out));
}

test "parser accepts real server command forms" {
    const a = try parseRequest("CHANNEL BADWORDS ADD #chat KICK :bad phrase\r\n");
    try testing.expectEqual(RequestKind.add, a.kind);
    try testing.expectEqualStrings("#chat", a.channel);
    try testing.expectEqualStrings("bad phrase", a.pattern.?);
    try testing.expectEqual(Action.kick, a.action.?);

    const b = try parseRequest("CHANBADWORDS DEL #chat :bad phrase");
    try testing.expectEqual(RequestKind.remove, b.kind);
    try testing.expectEqualStrings("#chat", b.channel);
    try testing.expectEqualStrings("bad phrase", b.pattern.?);

    const c = try parseRequest("@aaa=bbb :nick!u@h CHANNEL BADWORDS LIST #chat");
    try testing.expectEqual(RequestKind.list, c.kind);
    try testing.expectEqualStrings("#chat", c.channel);
}

test "parser rejects pseudo service commands and invalid actions" {
    try testing.expectError(error.PseudoClientCommand, parseRequest("CHANSERV BADWORDS ADD #x KICK :word"));
    try testing.expectError(error.PseudoClientCommand, parseRequest("PRIVMSG ChanServ :BADWORDS ADD #x KICK word"));
    try testing.expectError(error.InvalidAction, parseRequest("CHANNEL BADWORDS ADD #x WARN :word"));
    try testing.expectError(error.UnknownCommand, parseRequest("NOTICE #x :word"));
}

test "numeric codes format as IRC numeric tokens" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("461", Numeric.ERR_NEEDMOREPARAMS.format(&buf));
    try testing.expectEqualStrings("482", Numeric.ERR_CHANOPRIVSNEEDED.format(&buf));
    try testing.expectEqualStrings("950", Numeric.RPL_CHANBADWORD.format(&buf));
}

test "action exposes real command name for daemon enforcement" {
    try testing.expectEqualStrings("KICK", Action.kick.commandName());
}
