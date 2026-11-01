// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX WHISPER command parsing, precondition checks, and wire-line builders.
//!
//! WHISPER is a channel-scoped private message:
//! `WHISPER <channel> <nick[,nick...]> :<text>`. Delivery is only valid when
//! the sender is on the channel, channel mode `+w` (NOWHISPER) is absent, and
//! each selected recipient is also on the channel. Channel storage, nickname
//! existence checks, membership lookup, and fanout are owned by the caller.
//! This module validates attacker-controlled bytes and writes all output into
//! caller-owned buffers without allocation.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 512;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 512;
pub const DEFAULT_MAX_RECIPIENTS: usize = 16;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

/// draft-pfenning IRCX NOWHISPER denial numeric.
pub const ERR_NOWHISPER_CODE: u16 = 923;

pub const WhisperError = error{
    MissingChannel,
    MissingRecipients,
    MissingText,
    TooManyParameters,
    TooManyRecipients,
    EmptyRecipient,
    EmptyText,
    InvalidChannel,
    ChannelTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
    InvalidText,
    TextTooLong,
    InvalidDescription,
    DescriptionTooLong,
    SenderNotOnChannel,
    NowhisperSet,
    OutputTooSmall,
};

/// Compile-time limits and protocol-edge validation policy.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_text_bytes: usize = DEFAULT_MAX_TEXT_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
    max_recipients: usize = DEFAULT_MAX_RECIPIENTS,
    channel_prefixes: []const u8 = DEFAULT_CHANNEL_PREFIXES,
    require_utf8: bool = true,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_channel_bytes` keeps its builder default. `channel_prefixes` aliases
    /// the config value, which must outlive any use of the returned `Params`.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_server_name_bytes = limits.server_name_len,
            .max_text_bytes = limits.message_len,
            .max_description_bytes = limits.realname_len,
            .max_recipients = limits.whisper_recipients,
            .channel_prefixes = limits.channel_prefixes.slice(),
        };
    }
};

/// Identity used as the IRC message prefix: `nick!user@host`.
pub const Prefix = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

/// Onyx Server channel member tiers: founder `!` > owner `.` > op `@` > voice `+`.
pub const MemberTier = enum(u8) {
    none = 0,
    voice = 1,
    op = 2,
    owner = 3,
    founder = 4,

    pub fn isOperator(self: MemberTier) bool {
        return @backingInt(self) >= @backingInt(MemberTier.op);
    }

    pub fn prefix(self: MemberTier) []const u8 {
        return switch (self) {
            .none => "",
            .voice => "+",
            .op => "@",
            .owner => ".",
            .founder => "!",
        };
    }
};

/// Parsed `WHISPER <channel> <nick[,nick...]> :<text>` command parameters.
pub const WhisperArgs = struct {
    channel: []const u8,
    recipients: []const []const u8,
    text: []const u8,
};

/// Caller-provided recipient membership facts for a parsed WHISPER.
pub const RecipientPresence = struct {
    nick: []const u8,
    on_channel: bool,
};

/// Channel-scoped preconditions supplied by the daemon's membership/mode store.
pub const Preconditions = struct {
    sender_on_channel: bool,
    nowhisper_set: bool,
    recipients: []const RecipientPresence,
};

/// Deliverable recipients after channel preconditions have been applied.
pub const PrecheckResult = struct {
    deliverable: []const []const u8,
    skipped_not_on_channel: usize,
};

/// WHISPER failure numerics emitted by this module.
pub const WhisperNumeric = enum(u16) {
    ERR_NOWHISPER = ERR_NOWHISPER_CODE,
    ERR_NOSUCHNICK = @backingInt(numeric.Numeric.ERR_NOSUCHNICK),
    ERR_NOTONCHANNEL = @backingInt(numeric.Numeric.ERR_NOTONCHANNEL),
    ERR_CANNOTSENDTOCHAN = @backingInt(numeric.Numeric.ERR_CANNOTSENDTOCHAN),

    pub fn code(self: WhisperNumeric) u16 {
        return @backingInt(self);
    }
};

/// Parse WHISPER parameters after IRC line parsing.
///
/// The trailing text parameter should be supplied without the leading `:`.
/// Recipient nick slices are written into `recipient_storage`.
pub fn parseWhisperArgs(params: []const []const u8, recipient_storage: [][]const u8) WhisperError!WhisperArgs {
    return parseWhisperArgsWith(.{}, params, recipient_storage);
}

/// Parse WHISPER parameters with caller-selected compile-time limits.
pub fn parseWhisperArgsWith(
    comptime params_config: Params,
    params: []const []const u8,
    recipient_storage: [][]const u8,
) WhisperError!WhisperArgs {
    if (params.len == 0) return error.MissingChannel;
    if (params.len == 1) return error.MissingRecipients;
    if (params.len == 2) return error.MissingText;
    if (params.len > 3) return error.TooManyParameters;

    try validateChannelWith(params_config, params[0]);
    const recipients = try parseRecipientListWith(params_config, params[1], recipient_storage);
    try validateTextWith(params_config, params[2]);

    return .{
        .channel = params[0],
        .recipients = recipients,
        .text = params[2],
    };
}

/// Parse a comma-separated WHISPER recipient list into caller-owned storage.
pub fn parseRecipientList(list: []const u8, recipient_storage: [][]const u8) WhisperError![]const []const u8 {
    return parseRecipientListWith(.{}, list, recipient_storage);
}

/// Parse a recipient list with caller-selected compile-time limits.
pub fn parseRecipientListWith(
    comptime params: Params,
    list: []const u8,
    recipient_storage: [][]const u8,
) WhisperError![]const []const u8 {
    if (list.len == 0) return error.MissingRecipients;

    var count: usize = 0;
    var start: usize = 0;
    while (start <= list.len) {
        const end = findRecipientEnd(list, start);
        const nick = list[start..end];
        if (nick.len == 0) return error.EmptyRecipient;
        try validateNickWith(params, nick);
        if (count >= params.max_recipients or count >= recipient_storage.len) {
            return error.TooManyRecipients;
        }
        recipient_storage[count] = nick;
        count += 1;

        if (end == list.len) break;
        start = end + 1;
    }

    return recipient_storage[0..count];
}

/// Apply channel preconditions and select only recipients present on the channel.
pub fn checkWhisperPreconditions(
    preconditions: Preconditions,
    deliverable_storage: [][]const u8,
) WhisperError!PrecheckResult {
    if (!preconditions.sender_on_channel) return error.SenderNotOnChannel;
    if (preconditions.nowhisper_set) return error.NowhisperSet;

    var count: usize = 0;
    var skipped: usize = 0;
    for (preconditions.recipients) |recipient| {
        try validateNick(recipient.nick);
        if (!recipient.on_channel) {
            skipped += 1;
            continue;
        }
        if (count >= deliverable_storage.len) return error.TooManyRecipients;
        deliverable_storage[count] = recipient.nick;
        count += 1;
    }

    return .{
        .deliverable = deliverable_storage[0..count],
        .skipped_not_on_channel = skipped,
    };
}

/// Build `:sender!user@host WHISPER <channel> <nick> :<text>`.
pub fn buildWhisperLine(
    out: []u8,
    sender: Prefix,
    channel: []const u8,
    recipient_nick: []const u8,
    text: []const u8,
) WhisperError![]const u8 {
    return buildWhisperLineWith(.{}, out, sender, channel, recipient_nick, text);
}

/// Build a WHISPER delivery line using caller-selected compile-time limits.
pub fn buildWhisperLineWith(
    comptime params: Params,
    out: []u8,
    sender: Prefix,
    channel: []const u8,
    recipient_nick: []const u8,
    text: []const u8,
) WhisperError![]const u8 {
    try validatePrefix(params, sender);
    try validateChannelWith(params, channel);
    try validateNickWith(params, recipient_nick);
    try validateTextWith(params, text);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try appendPrefix(out, &n, sender);
    try append(out, &n, " WHISPER ");
    try append(out, &n, channel);
    try appendByte(out, &n, ' ');
    try append(out, &n, recipient_nick);
    try append(out, &n, " :");
    try append(out, &n, text);
    return out[0..n];
}

/// Build `ERR_NOWHISPER` 923.
pub fn buildNowhisperNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) WhisperError![]const u8 {
    return buildChannelNumeric(out, server_name, recipient_nick, channel, .ERR_NOWHISPER, "Cannot WHISPER to channel (+w)");
}

/// Build `ERR_NOSUCHNICK` 401.
pub fn buildNoSuchNickNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, target_nick: []const u8) WhisperError![]const u8 {
    return buildTargetNumeric(out, server_name, recipient_nick, target_nick, .ERR_NOSUCHNICK, "No such nick");
}

/// Build `ERR_NOTONCHANNEL` 442.
pub fn buildNotOnChannelNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) WhisperError![]const u8 {
    return buildChannelNumeric(out, server_name, recipient_nick, channel, .ERR_NOTONCHANNEL, "You're not on that channel");
}

/// Build `ERR_CANNOTSENDTOCHAN` 404.
pub fn buildCannotSendToChanNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) WhisperError![]const u8 {
    return buildChannelNumeric(out, server_name, recipient_nick, channel, .ERR_CANNOTSENDTOCHAN, "Cannot send to channel");
}

/// Build a channel-scoped WHISPER numeric using caller-selected limits.
pub fn buildChannelNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: WhisperNumeric,
    description: []const u8,
) WhisperError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateChannelWith(params, channel);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, failure.code(), recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a channel-scoped WHISPER numeric with the default validation policy.
pub fn buildChannelNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: WhisperNumeric,
    description: []const u8,
) WhisperError![]const u8 {
    return buildChannelNumericWith(.{}, out, server_name, recipient_nick, channel, failure, description);
}

/// Build a target-scoped WHISPER numeric using caller-selected limits.
pub fn buildTargetNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    failure: WhisperNumeric,
    description: []const u8,
) WhisperError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateNickWith(params, target_nick);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, failure.code(), recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, target_nick);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build a target-scoped WHISPER numeric with the default validation policy.
pub fn buildTargetNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    target_nick: []const u8,
    failure: WhisperNumeric,
    description: []const u8,
) WhisperError![]const u8 {
    return buildTargetNumericWith(.{}, out, server_name, recipient_nick, target_nick, failure, description);
}

pub fn validateChannel(channel: []const u8) WhisperError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateChannelWith(comptime params: Params, channel: []const u8) WhisperError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

pub fn validateNick(nick: []const u8) WhisperError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) WhisperError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateText(text: []const u8) WhisperError!void {
    return validateTextWith(.{}, text);
}

pub fn validateTextWith(comptime params: Params, text: []const u8) WhisperError!void {
    if (text.len == 0) return error.EmptyText;
    if (text.len > params.max_text_bytes) return error.TextTooLong;
    for (text) |ch| {
        if (!validTextByte(ch)) return error.InvalidText;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(text)) return error.InvalidText;
}

pub fn validateServerName(server_name: []const u8) WhisperError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) WhisperError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) WhisperError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTextByte(ch)) return error.InvalidDescription;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(description)) return error.InvalidDescription;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) WhisperError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
}

fn validateUserWith(comptime params: Params, user: []const u8) WhisperError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

fn validateHostWith(comptime params: Params, host: []const u8) WhisperError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(host)) return error.InvalidHost;
}

fn findRecipientEnd(list: []const u8, start: usize) usize {
    var index = start;
    while (index < list.len) : (index += 1) {
        if (list[index] == ',') break;
    }
    return index;
}

fn validChannelPrefix(comptime params: Params, prefix: u8) bool {
    for (params.channel_prefixes) |candidate| {
        if (prefix == candidate) return true;
    }
    return false;
}

fn validChannelByte(ch: u8) bool {
    if (ch <= 0x20 or ch == 0x7f) return false;
    return switch (ch) {
        ',', ':', '|' => false,
        else => true,
    };
}

fn validTextByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validUserByte(ch: u8) bool {
    if (ch <= 0x1f or ch == 0x7f) return false;
    return switch (ch) {
        '!', '@', ':', ' ' => false,
        else => true,
    };
}

fn validHostByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn appendPrefix(out: []u8, n: *usize, prefix: Prefix) WhisperError!void {
    try append(out, n, prefix.nick);
    try appendByte(out, n, '!');
    try append(out, n, prefix.user);
    try appendByte(out, n, '@');
    try append(out, n, prefix.host);
}

fn appendServerNumericHead(out: []u8, n: *usize, server_name: []const u8, code: u16, recipient_nick: []const u8) WhisperError!void {
    var code_buf: [3]u8 = undefined;
    formatCode(code, &code_buf);
    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, &code_buf);
    try appendByte(out, n, ' ');
    try append(out, n, recipient_nick);
}

fn formatCode(code: u16, buf: *[3]u8) void {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((code / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code % 10));
}

fn append(out: []u8, n: *usize, bytes: []const u8) WhisperError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) WhisperError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

test "parse multi-recipient whisper args" {
    var recipients_storage: [4][]const u8 = undefined;
    const params = [_][]const u8{ "#ops", "alice,bob,carol", "quiet hello" };

    const parsed = try parseWhisperArgs(&params, &recipients_storage);

    try std.testing.expectEqualStrings("#ops", parsed.channel);
    try std.testing.expectEqual(@as(usize, 3), parsed.recipients.len);
    try std.testing.expectEqualStrings("alice", parsed.recipients[0]);
    try std.testing.expectEqualStrings("bob", parsed.recipients[1]);
    try std.testing.expectEqualStrings("carol", parsed.recipients[2]);
    try std.testing.expectEqualStrings("quiet hello", parsed.text);
}

test "malformed whisper args and attacker bytes are rejected" {
    var recipients_storage: [2][]const u8 = undefined;

    const missing_channel = [_][]const u8{};
    try std.testing.expectError(error.MissingChannel, parseWhisperArgs(&missing_channel, &recipients_storage));

    const missing_recipients = [_][]const u8{"#ops"};
    try std.testing.expectError(error.MissingRecipients, parseWhisperArgs(&missing_recipients, &recipients_storage));

    const missing_text = [_][]const u8{ "#ops", "alice" };
    try std.testing.expectError(error.MissingText, parseWhisperArgs(&missing_text, &recipients_storage));

    const too_many = [_][]const u8{ "#ops", "alice", "hello", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseWhisperArgs(&too_many, &recipients_storage));

    const empty_recipient = [_][]const u8{ "#ops", "alice,,bob", "hello" };
    try std.testing.expectError(error.EmptyRecipient, parseWhisperArgs(&empty_recipient, &recipients_storage));

    const bad_channel = [_][]const u8{ "#bad channel", "alice", "hello" };
    try std.testing.expectError(error.InvalidChannel, parseWhisperArgs(&bad_channel, &recipients_storage));

    const bad_nick = [_][]const u8{ "#ops", "bad nick", "hello" };
    try std.testing.expectError(error.InvalidNick, parseWhisperArgs(&bad_nick, &recipients_storage));

    const bad_text = [_][]const u8{ "#ops", "alice", "bad\rtext" };
    try std.testing.expectError(error.InvalidText, parseWhisperArgs(&bad_text, &recipients_storage));

    const empty_text = [_][]const u8{ "#ops", "alice", "" };
    try std.testing.expectError(error.EmptyText, parseWhisperArgs(&empty_text, &recipients_storage));
}

test "nowhisper denied before recipient selection" {
    var deliverable_storage: [2][]const u8 = undefined;
    const recipients = [_]RecipientPresence{
        .{ .nick = "alice", .on_channel = true },
        .{ .nick = "bob", .on_channel = true },
    };

    try std.testing.expectError(error.NowhisperSet, checkWhisperPreconditions(.{
        .sender_on_channel = true,
        .nowhisper_set = true,
        .recipients = &recipients,
    }, &deliverable_storage));
}

test "sender must be on channel" {
    var deliverable_storage: [1][]const u8 = undefined;
    const recipients = [_]RecipientPresence{.{ .nick = "alice", .on_channel = true }};

    try std.testing.expectError(error.SenderNotOnChannel, checkWhisperPreconditions(.{
        .sender_on_channel = false,
        .nowhisper_set = false,
        .recipients = &recipients,
    }, &deliverable_storage));
}

test "non-member recipient skipped" {
    var deliverable_storage: [3][]const u8 = undefined;
    const recipients = [_]RecipientPresence{
        .{ .nick = "alice", .on_channel = true },
        .{ .nick = "mallory", .on_channel = false },
        .{ .nick = "bob", .on_channel = true },
    };

    const checked = try checkWhisperPreconditions(.{
        .sender_on_channel = true,
        .nowhisper_set = false,
        .recipients = &recipients,
    }, &deliverable_storage);

    try std.testing.expectEqual(@as(usize, 2), checked.deliverable.len);
    try std.testing.expectEqualStrings("alice", checked.deliverable[0]);
    try std.testing.expectEqualStrings("bob", checked.deliverable[1]);
    try std.testing.expectEqual(@as(usize, 1), checked.skipped_not_on_channel);
}

test "whisper line format" {
    var buf: [160]u8 = undefined;
    const line = try buildWhisperLine(&buf, .{
        .nick = "sender",
        .user = "u",
        .host = "h",
    }, "#chan", "target", "secret text");

    try std.testing.expectEqualStrings(":sender!u@h WHISPER #chan target :secret text", line);
}

test "numeric builders emit required codes" {
    var buf: [192]u8 = undefined;

    const nowhisper = try buildNowhisperNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 923 alice #ops :Cannot WHISPER to channel (+w)", nowhisper);

    const no_such = try buildNoSuchNickNumeric(&buf, "irc.example", "alice", "missing");
    try std.testing.expectEqualStrings(":irc.example 401 alice missing :No such nick", no_such);

    const not_on = try buildNotOnChannelNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 442 alice #ops :You're not on that channel", not_on);

    const cannot_send = try buildCannotSendToChanNumeric(&buf, "irc.example", "alice", "#ops");
    try std.testing.expectEqualStrings(":irc.example 404 alice #ops :Cannot send to channel", cannot_send);
}

test "builders validate bytes and output size" {
    var buf: [96]u8 = undefined;
    var small: [8]u8 = undefined;

    try std.testing.expectError(error.InvalidUser, buildWhisperLine(&buf, .{
        .nick = "sender",
        .user = "bad user",
        .host = "h",
    }, "#chan", "target", "secret"));

    try std.testing.expectError(error.InvalidText, buildWhisperLine(&buf, .{
        .nick = "sender",
        .user = "u",
        .host = "h",
    }, "#chan", "target", "bad\ntext"));

    try std.testing.expectError(error.InvalidServerName, buildNowhisperNumeric(&buf, "irc example", "alice", "#ops"));
    try std.testing.expectError(error.OutputTooSmall, buildNowhisperNumeric(&small, "irc.example", "alice", "#ops"));
}

test "recipient and text limits are enforced" {
    var one_recipient: [1][]const u8 = undefined;
    try std.testing.expectError(error.TooManyRecipients, parseRecipientList("alice,bob", &one_recipient));

    var recipients_storage: [2][]const u8 = undefined;
    try std.testing.expectError(error.TooManyRecipients, parseRecipientListWith(.{ .max_recipients = 1 }, "alice,bob", &recipients_storage));
    try std.testing.expectError(error.TextTooLong, validateTextWith(.{ .max_text_bytes = 3 }, "four"));
    try std.testing.expectError(error.InvalidText, validateText("bad\x00text"));
    try validateText("caf\xc3\xa9");
    try std.testing.expectError(error.InvalidText, validateText("bad\xff"));
    try validateTextWith(.{ .require_utf8 = false }, "raw\xff");
}

test "member tiers preserve Onyx Server ordering" {
    try std.testing.expect(MemberTier.founder.isOperator());
    try std.testing.expect(MemberTier.owner.isOperator());
    try std.testing.expect(MemberTier.op.isOperator());
    try std.testing.expect(!MemberTier.voice.isOperator());
    try std.testing.expect(!MemberTier.none.isOperator());
    try std.testing.expectEqualStrings("!", MemberTier.founder.prefix());
    try std.testing.expectEqualStrings(".", MemberTier.owner.prefix());
    try std.testing.expectEqualStrings("@", MemberTier.op.prefix());
    try std.testing.expectEqualStrings("+", MemberTier.voice.prefix());
}
