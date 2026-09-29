// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 Bot Mode helpers.
//!
//! User-mode ownership is intentionally outside this module. Callers compose
//! these allocation-free helpers with their usermode, ISUPPORT, WHO/WHOIS, and
//! message-tag send paths.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_WHOIS_MESSAGE_BYTES: usize = 128;
pub const BOT_ISUPPORT_NAME = "BOT";
pub const BOT_TAG = "bot";
pub const DEFAULT_WHOIS_BOT_MESSAGE = "is a bot";

pub const BotModeError = error{
    InvalidModeLetter,
    InvalidNick,
    NickTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidWhoisMessage,
    WhoisMessageTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Runtime Bot Mode policy selected by the daemon.
pub const BotMode = struct {
    letter: u8 = 'B',
};

/// Compile-time limits for builders and validators.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_whois_message_bytes: usize = DEFAULT_MAX_WHOIS_MESSAGE_BYTES,
};

/// One visible client that may receive the IRCv3 `bot` message tag.
pub const Watcher = struct {
    client: ClientId,
    message_tags: bool = false,
};

/// One selected recipient for an outbound bare `bot` tag.
pub const Recipient = struct {
    client: ClientId,
    tag: []const u8 = BOT_TAG,
};

/// Caller-provided storage for selected bot-tag recipients.
pub const Sink = struct {
    recipients: []Recipient,
    count: usize = 0,

    pub fn append(self: *Sink, client: ClientId) BotModeError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client };
        self.count += 1;
    }

    pub fn slice(self: *const Sink) []const Recipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *Sink) void {
        self.count = 0;
    }
};

/// Bot indicators a caller may add to message, WHO, and WHOIS output.
pub const BotIndicators = struct {
    message_tag: ?[]const u8 = null,
    who_flag: ?u8 = null,
    whois_numeric: bool = false,
};

/// Build the ISUPPORT `BOT` token value, for example `B`.
pub fn buildIsupportBotValue(out: []u8, config: BotMode) BotModeError![]const u8 {
    try validateMode(config);
    if (out.len < 1) return error.OutputTooSmall;
    out[0] = config.letter;
    return out[0..1];
}

/// Build the complete ISUPPORT token text, for example `BOT=B`.
pub fn buildIsupportBotToken(out: []u8, config: BotMode) BotModeError![]const u8 {
    try validateMode(config);
    var n: usize = 0;
    try append(out, &n, BOT_ISUPPORT_NAME);
    try appendByte(out, &n, '=');
    try appendByte(out, &n, config.letter);
    return out[0..n];
}

/// Build `:server 335 requester nick :is a bot` into caller-owned storage.
pub fn buildWhoisBotNumeric(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) BotModeError![]const u8 {
    return buildWhoisBotNumericWith(.{}, out, server_name, requester_nick, target_nick, DEFAULT_WHOIS_BOT_MESSAGE);
}

/// Build RPL_WHOISBOT using caller-selected limits and message text.
pub fn buildWhoisBotNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    message: []const u8,
) BotModeError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, target_nick);
    try validateWhoisMessageWith(params, message);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, server_name);
    try appendByte(out, &n, ' ');

    var code_buf: [3]u8 = undefined;
    try append(out, &n, numeric.formatCode(.RPL_WHOISBOT, &code_buf));
    try appendByte(out, &n, ' ');
    try append(out, &n, requester_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, target_nick);
    try append(out, &n, " :");
    try append(out, &n, message);
    return out[0..n];
}

/// Return the bot indicators that apply to one sender/recipient pair.
pub fn indicators(config: BotMode, sender_is_bot: bool, recipient_message_tags: bool) BotModeError!BotIndicators {
    try validateMode(config);
    if (!sender_is_bot) return .{};
    return .{
        .message_tag = if (recipient_message_tags) BOT_TAG else null,
        .who_flag = config.letter,
        .whois_numeric = true,
    };
}

/// Return the WHO flags extension for a bot, or null for a non-bot.
pub fn whoFlag(config: BotMode, sender_is_bot: bool) BotModeError!?u8 {
    try validateMode(config);
    return if (sender_is_bot) config.letter else null;
}

/// Return whether RPL_WHOISBOT should be emitted for a WHOIS target.
pub fn shouldEmitWhoisBot(sender_is_bot: bool) bool {
    return sender_is_bot;
}

/// Select visible recipients that negotiated message-tags for the bare `bot` tag.
pub fn selectBotTagRecipients(
    sender_is_bot: bool,
    watchers: []const Watcher,
    sink: *Sink,
) BotModeError!void {
    if (!sender_is_bot) return;
    for (watchers) |watcher| {
        if (watcher.message_tags) try sink.append(watcher.client);
    }
}

pub fn validateMode(config: BotMode) BotModeError!void {
    if (!validModeLetter(config.letter)) return error.InvalidModeLetter;
}

pub fn validateNick(nick: []const u8) BotModeError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) BotModeError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateServerName(server_name: []const u8) BotModeError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) BotModeError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validParamByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateWhoisMessage(message: []const u8) BotModeError!void {
    return validateWhoisMessageWith(.{}, message);
}

pub fn validateWhoisMessageWith(comptime params: Params, message: []const u8) BotModeError!void {
    if (message.len == 0) return error.InvalidWhoisMessage;
    if (message.len > params.max_whois_message_bytes) return error.WhoisMessageTooLong;
    for (message) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidWhoisMessage;
    }
}

fn validModeLetter(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

fn validTrailingByte(ch: u8) bool {
    return switch (ch) {
        0, '\r', '\n' => false,
        else => true,
    };
}

fn append(out: []u8, n: *usize, bytes: []const u8) BotModeError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) BotModeError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRecipient(recipient: Recipient, client: ClientId) !void {
    try std.testing.expectEqual(client, recipient.client);
    try std.testing.expectEqualStrings(BOT_TAG, recipient.tag);
}

test "isupport bot value and token build" {
    var value_buf: [1]u8 = undefined;
    const value = try buildIsupportBotValue(&value_buf, .{});
    try std.testing.expectEqualStrings("B", value);

    var token_buf: [8]u8 = undefined;
    const token = try buildIsupportBotToken(&token_buf, .{ .letter = 'b' });
    try std.testing.expectEqualStrings("BOT=b", token);
}

test "GAP-P0c WHOIS 335 follows bot mode while the registry and board stay uncalled" {
    try std.testing.expect(shouldEmitWhoisBot(true));
    try std.testing.expect(!shouldEmitWhoisBot(false));
    var buf: [128]u8 = undefined;
    const line = try buildWhoisBotNumeric(&buf, "irc.example", "alice", "robodan");
    try std.testing.expectEqualStrings(":irc.example 335 alice robodan :is a bot", line);

    const io = std.testing.io;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, "src/daemon/server.zig", std.testing.allocator, .limited(20 << 20));
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "const bot_registry_mod = @import(\"bot_registry.zig\");") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "const announce_board_mod = @import(\"announce_board.zig\");") != null);
    // BOTGRANT records the account so isBot matches the grant. The registry
    // does not build WHOIS 335 and does not answer channel ! commands.
    try std.testing.expect(std.mem.indexOf(u8, text, "self.bot_registry.register(") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "self.bot_registry.isBot(") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "bot_registry.mayAnnounce") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "announce_board_mod.") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "!weather") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "!news") != null);
    std.debug.print("GAP-P0c branch=WHOIS 335 follows bot mode; BOTGRANT marks isBot; announce board stays uncalled; in-channel commands stay weather and news\n", .{});
}

test "rpl whoisbot numeric build" {
    var buf: [128]u8 = undefined;
    const line = try buildWhoisBotNumeric(&buf, "irc.example", "alice", "robodan");
    try std.testing.expectEqualStrings(":irc.example 335 alice robodan :is a bot", line);
}

test "custom whoisbot message build" {
    var buf: [128]u8 = undefined;
    const line = try buildWhoisBotNumericWith(
        .{},
        &buf,
        "irc.example",
        "alice",
        "robodan",
        "is a Bot on IRCv3",
    );
    try std.testing.expectEqualStrings(":irc.example 335 alice robodan :is a Bot on IRCv3", line);
}

test "bot indicators reflect tag capability and whois state" {
    const bot_with_tags = try indicators(.{ .letter = 'b' }, true, true);
    try std.testing.expectEqualStrings(BOT_TAG, bot_with_tags.message_tag.?);
    try std.testing.expectEqual(@as(?u8, 'b'), bot_with_tags.who_flag);
    try std.testing.expect(bot_with_tags.whois_numeric);

    const bot_without_tags = try indicators(.{}, true, false);
    try std.testing.expectEqual(@as(?[]const u8, null), bot_without_tags.message_tag);
    try std.testing.expectEqual(@as(?u8, 'B'), bot_without_tags.who_flag);
    try std.testing.expect(bot_without_tags.whois_numeric);

    const human = try indicators(.{}, false, true);
    try std.testing.expectEqual(@as(?[]const u8, null), human.message_tag);
    try std.testing.expectEqual(@as(?u8, null), human.who_flag);
    try std.testing.expect(!human.whois_numeric);
    try std.testing.expectEqual(@as(?u8, null), try whoFlag(.{}, false));
    try std.testing.expect(!shouldEmitWhoisBot(false));
}

test "cap-gated bot tag recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .message_tags = true },
        .{ .client = 2, .message_tags = false },
        .{ .client = 3, .message_tags = true },
    };

    var storage: [3]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try selectBotTagRecipients(true, &watchers, &sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
    try expectRecipient(sink.slice()[1], 3);

    sink.reset();
    try selectBotTagRecipients(false, &watchers, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);
}

test "recipient sink reports overflow" {
    const watchers = [_]Watcher{
        .{ .client = 1, .message_tags = true },
        .{ .client = 2, .message_tags = true },
    };

    var storage: [1]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectBotTagRecipients(true, &watchers, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1);
}

test "builders report output too small" {
    var empty: [0]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildIsupportBotValue(&empty, .{}));

    var small_token: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildIsupportBotToken(&small_token, .{}));

    var small_numeric: [16]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        buildWhoisBotNumeric(&small_numeric, "irc.example", "alice", "robodan"),
    );
}

test "invalid attacker-controlled input rejected" {
    var buf: [128]u8 = undefined;

    try std.testing.expectError(error.InvalidModeLetter, validateMode(.{ .letter = '1' }));
    try std.testing.expectError(error.InvalidNick, validateNick(""));
    try std.testing.expectError(error.InvalidNick, validateNick("bad nick"));
    try std.testing.expectError(error.InvalidNick, validateNick("bad\rnick"));
    try std.testing.expectError(error.NickTooLong, validateNickWith(.{ .max_nick_bytes = 3 }, "alice"));
    try std.testing.expectError(error.InvalidServerName, validateServerName("irc example"));
    try std.testing.expectError(error.InvalidServerName, validateServerName("irc\nexample"));
    try std.testing.expectError(error.InvalidWhoisMessage, validateWhoisMessage(""));
    try std.testing.expectError(error.InvalidWhoisMessage, validateWhoisMessage("is a bot\r"));
    try std.testing.expectError(
        error.WhoisMessageTooLong,
        validateWhoisMessageWith(.{ .max_whois_message_bytes = 3 }, "bot!"),
    );

    try std.testing.expectError(
        error.InvalidNick,
        buildWhoisBotNumeric(&buf, "irc.example", "alice", "bad nick"),
    );
    try std.testing.expectError(
        error.InvalidWhoisMessage,
        buildWhoisBotNumericWith(.{}, &buf, "irc.example", "alice", "robodan", "bad\nmessage"),
    );
}
