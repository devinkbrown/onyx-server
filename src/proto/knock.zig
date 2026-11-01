// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! KNOCK command parsing and notification helpers.
//!
//! Channel state, invite/restriction policy, duplicate/rate-limit tracking, and
//! channel privilege computation are owned by the caller. This module validates
//! attacker-controlled fields, parses `KNOCK <channel> [:reason]`, builds
//! allocation-free operator notifications, knocker acknowledgements, and
//! standard FAIL/numeric errors into caller-owned storage, and selects only
//! caller-marked channel operators for delivery.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 200;
pub const DEFAULT_MAX_REASON_BYTES: usize = 512;
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 512;
pub const DEFAULT_CHANNEL_PREFIXES: []const u8 = "#+&!";

/// Local KNOCK numerics not currently exported by `numeric.zig`.
pub const RPL_KNOCK_CODE: u16 = 710;
/// Local KNOCK delivery acknowledgement numeric not currently exported by `numeric.zig`.
pub const RPL_KNOCKDLVR_CODE: u16 = 711;
/// KNOCK error numerics (not in numeric.zig): 712 throttle, 713 channel
/// is open (no need to knock), 714 already on channel, 715 KNOCK disabled.
pub const ERR_TOOMANYKNOCK_CODE: u16 = 712;
pub const ERR_CHANOPEN_CODE: u16 = 713;
pub const ERR_KNOCKONCHAN_CODE: u16 = 714;
pub const ERR_KNOCKDISABLED_CODE: u16 = 715;

pub const KnockError = error{
    MissingChannel,
    TooManyParameters,
    InvalidChannel,
    ChannelTooLong,
    InvalidReason,
    ReasonTooLong,
    InvalidDescription,
    DescriptionTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidServerName,
    ServerNameTooLong,
    OutputTooSmall,
    TooManyRecipients,
};

/// Compile-time limits and protocol-edge validation policy.
pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_description_bytes: usize = DEFAULT_MAX_DESCRIPTION_BYTES,
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
            .max_reason_bytes = limits.reason_len,
            .max_description_bytes = limits.realname_len,
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

/// Parsed `KNOCK <channel> [:reason]` command parameters.
pub const KnockArgs = struct {
    channel: []const u8,
    reason: []const u8 = "",
};

/// One channel member that may receive a KNOCK notification.
pub const Watcher = struct {
    client: ClientId,
    channel_operator: bool = false,
    modern_knock: bool = false,
};

pub const NotifyFallback = enum {
    none,
    notice,
};

pub const NotifyAction = enum {
    rpl_knock,
    notice,
};

/// One selected operator recipient and how KNOCK should be represented.
pub const Recipient = struct {
    client: ClientId,
    action: NotifyAction,
};

/// Caller-provided storage for selected operator recipients.
pub const Sink = struct {
    recipients: []Recipient,
    count: usize = 0,

    pub fn append(self: *Sink, client: ClientId, action: NotifyAction) KnockError!void {
        if (self.count >= self.recipients.len) return error.TooManyRecipients;
        self.recipients[self.count] = .{ .client = client, .action = action };
        self.count += 1;
    }

    pub fn slice(self: *const Sink) []const Recipient {
        return self.recipients[0..self.count];
    }

    pub fn reset(self: *Sink) void {
        self.count = 0;
    }
};

/// Standard-reply FAIL codes for KNOCK command failures.
pub const FailCode = enum {
    BAD_CHANNEL_NAME,
    CANNOT_KNOCK,
    KNOCK_ON_CHANNEL,
    NEED_MORE_PARAMS,
    TOO_MANY_KNOCKS,

    pub fn token(self: FailCode) []const u8 {
        return @tagName(self);
    }
};

/// KNOCK numeric failures that are local to this module.
pub const FailureNumeric = enum(u16) {
    ERR_TOOMANYKNOCK = ERR_TOOMANYKNOCK_CODE,
    ERR_CHANOPEN = ERR_CHANOPEN_CODE,
    ERR_KNOCKONCHAN = ERR_KNOCKONCHAN_CODE,
    ERR_KNOCKDISABLED = ERR_KNOCKDISABLED_CODE,

    pub fn code(self: FailureNumeric) u16 {
        return @backingInt(self);
    }
};

/// Parse `KNOCK <channel> [:reason]` parameters.
///
/// `params` must be the command parameter slice after IRC line parsing. The
/// optional trailing reason should be supplied as the second parameter without
/// the leading `:`.
pub fn parseKnockArgs(params: []const []const u8) KnockError!KnockArgs {
    return parseKnockArgsWith(.{}, params);
}

/// Parse KNOCK parameters with caller-selected compile-time limits.
pub fn parseKnockArgsWith(comptime params_config: Params, params: []const []const u8) KnockError!KnockArgs {
    if (params.len == 0) return error.MissingChannel;
    if (params.len > 2) return error.TooManyParameters;

    const reason = if (params.len == 2) params[1] else "";
    try validateChannelWith(params_config, params[0]);
    try validateReasonWith(params_config, reason);

    return .{
        .channel = params[0],
        .reason = reason,
    };
}

/// Validate one channel name with the default KNOCK channel policy.
pub fn validateChannel(channel: []const u8) KnockError!void {
    return validateChannelWith(.{}, channel);
}

/// Validate one channel name with caller-selected compile-time limits.
pub fn validateChannelWith(comptime params: Params, channel: []const u8) KnockError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!validChannelPrefix(params, channel[0])) return error.InvalidChannel;
    for (channel) |ch| {
        if (!validChannelByte(ch)) return error.InvalidChannel;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(channel)) return error.InvalidChannel;
}

/// Build `:server NOTICE @#channel :[Knock] by nick!user@host (reason)`.
pub fn buildOpsNotice(
    out: []u8,
    server_name: []const u8,
    knocker: Prefix,
    channel: []const u8,
    reason: []const u8,
) KnockError![]const u8 {
    return buildOpsNoticeWith(.{}, out, server_name, knocker, channel, reason);
}

/// Build an operator NOTICE using caller-selected compile-time limits.
pub fn buildOpsNoticeWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    knocker: Prefix,
    channel: []const u8,
    reason: []const u8,
) KnockError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validatePrefix(params, knocker);
    try validateChannelWith(params, channel);
    try validateReasonWith(params, reason);

    var n: usize = 0;
    try appendByte(out, &n, ':');
    try append(out, &n, server_name);
    try append(out, &n, " NOTICE @");
    try append(out, &n, channel);
    try append(out, &n, " :[Knock] by ");
    try appendPrefix(out, &n, knocker);
    if (reason.len != 0) {
        try append(out, &n, " (");
        try append(out, &n, reason);
        try appendByte(out, &n, ')');
    }
    return out[0..n];
}

/// Build modern `RPL_KNOCK` 710 for one channel operator.
pub fn buildOpsKnockNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    knocker: Prefix,
    reason: []const u8,
) KnockError![]const u8 {
    return buildOpsKnockNumericWith(.{}, out, server_name, recipient_nick, channel, knocker, reason);
}

/// Build modern `RPL_KNOCK` 710 using caller-selected compile-time limits.
pub fn buildOpsKnockNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    knocker: Prefix,
    reason: []const u8,
) KnockError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);
    try validateChannelWith(params, channel);
    try validatePrefix(params, knocker);
    try validateReasonWith(params, reason);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, RPL_KNOCK_CODE, recipient_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try appendByte(out, &n, ' ');
    try appendPrefix(out, &n, knocker);
    try append(out, &n, " :has asked for an invite");
    if (reason.len != 0) {
        try append(out, &n, " (");
        try append(out, &n, reason);
        try appendByte(out, &n, ')');
    }
    return out[0..n];
}

/// Build modern `RPL_KNOCKDLVR` 711 acknowledgement for the knocker.
pub fn buildKnockerAck(
    out: []u8,
    server_name: []const u8,
    knocker_nick: []const u8,
    channel: []const u8,
) KnockError![]const u8 {
    return buildKnockerAckWith(.{}, out, server_name, knocker_nick, channel);
}

/// Build modern `RPL_KNOCKDLVR` 711 using caller-selected compile-time limits.
pub fn buildKnockerAckWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    knocker_nick: []const u8,
    channel: []const u8,
) KnockError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, knocker_nick);
    try validateChannelWith(params, channel);

    var n: usize = 0;
    try appendServerNumericHead(out, &n, server_name, RPL_KNOCKDLVR_CODE, knocker_nick);
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :Your KNOCK has been delivered");
    return out[0..n];
}

/// Build a local KNOCK failure numeric: 712, 713, or 714.
pub fn buildFailureNumeric(
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: FailureNumeric,
    description: []const u8,
) KnockError![]const u8 {
    return buildFailureNumericWith(.{}, out, server_name, recipient_nick, channel, failure, description);
}

/// Build a local KNOCK failure numeric using caller-selected compile-time limits.
pub fn buildFailureNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
    channel: []const u8,
    failure: FailureNumeric,
    description: []const u8,
) KnockError![]const u8 {
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

/// Build `ERR_TOOMANYKNOCK` 712.
pub fn buildTooManyKnockNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) KnockError![]const u8 {
    return buildFailureNumeric(out, server_name, recipient_nick, channel, .ERR_TOOMANYKNOCK, "Too many KNOCKs for this channel");
}

/// Build `ERR_CHANOPEN` 713 (channel is open, knocking pointless).
pub fn buildChanOpenNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) KnockError![]const u8 {
    return buildFailureNumeric(out, server_name, recipient_nick, channel, .ERR_CHANOPEN, "Channel is open; no need to KNOCK");
}

/// Build `ERR_KNOCKONCHAN` 714.
pub fn buildKnockOnChannelNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8, channel: []const u8) KnockError![]const u8 {
    return buildFailureNumeric(out, server_name, recipient_nick, channel, .ERR_KNOCKONCHAN, "You are already on that channel");
}

/// Build exported `ERR_NEEDMOREPARAMS` 461 for malformed KNOCK input.
pub fn buildNeedMoreParamsNumeric(out: []u8, server_name: []const u8, recipient_nick: []const u8) KnockError![]const u8 {
    return buildNeedMoreParamsNumericWith(.{}, out, server_name, recipient_nick);
}

/// Build exported `ERR_NEEDMOREPARAMS` 461 using caller-selected limits.
pub fn buildNeedMoreParamsNumericWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    recipient_nick: []const u8,
) KnockError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, recipient_nick);

    var n: usize = 0;
    var code_buf: [3]u8 = undefined;
    try appendServerNumericHeadText(out, &n, server_name, numeric.formatCode(.ERR_NEEDMOREPARAMS, &code_buf), recipient_nick);
    try append(out, &n, " KNOCK :Not enough parameters");
    return out[0..n];
}

/// Build `FAIL KNOCK <code> [channel] :<description>`.
pub fn buildFailLine(
    out: []u8,
    code: FailCode,
    channel: []const u8,
    description: []const u8,
) KnockError![]const u8 {
    return buildFailLineWith(.{}, out, code, channel, description);
}

/// Build a KNOCK FAIL line with caller-selected compile-time limits.
pub fn buildFailLineWith(
    comptime params: Params,
    out: []u8,
    code: FailCode,
    channel: []const u8,
    description: []const u8,
) KnockError![]const u8 {
    try validateChannelWith(params, channel);
    try validateDescriptionWith(params, description);

    var n: usize = 0;
    try append(out, &n, "FAIL KNOCK ");
    try append(out, &n, code.token());
    try appendByte(out, &n, ' ');
    try append(out, &n, channel);
    try append(out, &n, " :");
    try append(out, &n, description);
    return out[0..n];
}

/// Build `FAIL KNOCK NEED_MORE_PARAMS * :Not enough parameters`.
pub fn buildNeedMoreParamsFail(out: []u8) KnockError![]const u8 {
    var n: usize = 0;
    try append(out, &n, "FAIL KNOCK NEED_MORE_PARAMS * :Not enough parameters");
    return out[0..n];
}

/// Build a standard-reply FAIL for KNOCK throttle rejection.
pub fn buildTooManyKnockFail(out: []u8, channel: []const u8) KnockError![]const u8 {
    return buildFailLine(out, .TOO_MANY_KNOCKS, channel, "Too many KNOCKs for this channel");
}

/// Build a standard-reply FAIL for non-knockable channels.
pub fn buildChanOpenFail(out: []u8, channel: []const u8) KnockError![]const u8 {
    return buildFailLine(out, .CANNOT_KNOCK, channel, "Channel is open; no need to KNOCK");
}

/// Build a standard-reply FAIL for users already joined to the channel.
pub fn buildKnockOnChannelFail(out: []u8, channel: []const u8) KnockError![]const u8 {
    return buildFailLine(out, .KNOCK_ON_CHANNEL, channel, "You are already on that channel");
}

/// Select channel operators for a KNOCK notification.
///
/// Operators with `modern_knock` receive RPL_KNOCK. Operators without it
/// receive the caller-selected fallback NOTICE action or are omitted.
pub fn selectRecipients(
    watchers: []const Watcher,
    fallback: NotifyFallback,
    sink: *Sink,
) KnockError!void {
    for (watchers) |watcher| {
        if (!watcher.channel_operator) continue;
        if (watcher.modern_knock) {
            try sink.append(watcher.client, .rpl_knock);
        } else if (fallback == .notice) {
            try sink.append(watcher.client, .notice);
        }
    }
}

pub fn validateReason(reason: []const u8) KnockError!void {
    return validateReasonWith(.{}, reason);
}

pub fn validateReasonWith(comptime params: Params, reason: []const u8) KnockError!void {
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |ch| {
        if (!validTextByte(ch)) return error.InvalidReason;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(reason)) return error.InvalidReason;
}

pub fn validateNick(nick: []const u8) KnockError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) KnockError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) KnockError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) KnockError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(user)) return error.InvalidUser;
}

pub fn validateHost(host: []const u8) KnockError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) KnockError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(host)) return error.InvalidHost;
}

pub fn validateServerName(server_name: []const u8) KnockError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) KnockError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

fn validateDescriptionWith(comptime params: Params, description: []const u8) KnockError!void {
    if (description.len == 0) return error.InvalidDescription;
    if (description.len > params.max_description_bytes) return error.DescriptionTooLong;
    for (description) |ch| {
        if (!validTextByte(ch)) return error.InvalidDescription;
    }
    if (params.require_utf8 and !std.unicode.utf8ValidateSlice(description)) return error.InvalidDescription;
}

fn validatePrefix(comptime params: Params, prefix: Prefix) KnockError!void {
    try validateNickWith(params, prefix.nick);
    try validateUserWith(params, prefix.user);
    try validateHostWith(params, prefix.host);
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

fn appendPrefix(out: []u8, n: *usize, prefix: Prefix) KnockError!void {
    try append(out, n, prefix.nick);
    try appendByte(out, n, '!');
    try append(out, n, prefix.user);
    try appendByte(out, n, '@');
    try append(out, n, prefix.host);
}

fn appendServerNumericHead(out: []u8, n: *usize, server_name: []const u8, code: u16, recipient_nick: []const u8) KnockError!void {
    var code_buf: [3]u8 = undefined;
    formatLocalCode(code, &code_buf);
    try appendServerNumericHeadText(out, n, server_name, &code_buf, recipient_nick);
}

fn appendServerNumericHeadText(out: []u8, n: *usize, server_name: []const u8, code_text: []const u8, recipient_nick: []const u8) KnockError!void {
    try appendByte(out, n, ':');
    try append(out, n, server_name);
    try appendByte(out, n, ' ');
    try append(out, n, code_text);
    try appendByte(out, n, ' ');
    try append(out, n, recipient_nick);
}

fn formatLocalCode(code: u16, buf: *[3]u8) void {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((code / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code % 10));
}

fn append(out: []u8, n: *usize, bytes: []const u8) KnockError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) KnockError!void {
    if (out.len - n.* < 1) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn expectRecipient(recipient: Recipient, client: ClientId, action: NotifyAction) !void {
    try std.testing.expectEqual(client, recipient.client);
    try std.testing.expectEqual(action, recipient.action);
}

test "parse knock args with optional reason" {
    const with_reason = [_][]const u8{ "#secret", "invite me please" };
    const parsed = try parseKnockArgs(&with_reason);
    try std.testing.expectEqualStrings("#secret", parsed.channel);
    try std.testing.expectEqualStrings("invite me please", parsed.reason);

    const without_reason = [_][]const u8{"#secret"};
    const parsed_without = try parseKnockArgs(&without_reason);
    try std.testing.expectEqualStrings("#secret", parsed_without.channel);
    try std.testing.expectEqualStrings("", parsed_without.reason);
}

test "ops notice build includes operator channel target" {
    var buf: [160]u8 = undefined;
    const line = try buildOpsNotice(&buf, "irc.example", .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "#secret", "invite me");

    try std.testing.expectEqualStrings(":irc.example NOTICE @#secret :[Knock] by alice!user@cloak.example (invite me)", line);
}

test "modern knock numeric and knocker ack build" {
    var buf: [192]u8 = undefined;
    const ops = try buildOpsKnockNumeric(&buf, "irc.example", "oper", "#secret", .{
        .nick = "alice",
        .user = "user",
        .host = "cloak.example",
    }, "invite me");
    try std.testing.expectEqualStrings(":irc.example 710 oper #secret alice!user@cloak.example :has asked for an invite (invite me)", ops);

    const ack = try buildKnockerAck(&buf, "irc.example", "alice", "#secret");
    try std.testing.expectEqualStrings(":irc.example 711 alice #secret :Your KNOCK has been delivered", ack);
}

test "failure numeric and fail builders" {
    var buf: [160]u8 = undefined;
    const throttled = try buildTooManyKnockNumeric(&buf, "irc.example", "alice", "#secret");
    try std.testing.expectEqualStrings(":irc.example 712 alice #secret :Too many KNOCKs for this channel", throttled);

    const cannot = try buildChanOpenFail(&buf, "#secret");
    try std.testing.expectEqualStrings("FAIL KNOCK CANNOT_KNOCK #secret :Channel is open; no need to KNOCK", cannot);

    const need_more = try buildNeedMoreParamsNumeric(&buf, "irc.example", "alice");
    try std.testing.expectEqualStrings(":irc.example 461 alice KNOCK :Not enough parameters", need_more);
}

test "cap-gated operator recipient selection" {
    const watchers = [_]Watcher{
        .{ .client = 1, .channel_operator = true, .modern_knock = true },
        .{ .client = 2, .channel_operator = true, .modern_knock = false },
        .{ .client = 3, .channel_operator = false, .modern_knock = true },
    };

    var storage: [3]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try selectRecipients(&watchers, .none, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1, .rpl_knock);

    sink.reset();
    try selectRecipients(&watchers, .notice, &sink);
    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try expectRecipient(sink.slice()[0], 1, .rpl_knock);
    try expectRecipient(sink.slice()[1], 2, .notice);
}

test "recipient sink reports too many recipients" {
    const watchers = [_]Watcher{
        .{ .client = 1, .channel_operator = true, .modern_knock = true },
        .{ .client = 2, .channel_operator = true, .modern_knock = true },
    };

    var storage: [1]Recipient = undefined;
    var sink = Sink{ .recipients = &storage };
    try std.testing.expectError(error.TooManyRecipients, selectRecipients(&watchers, .none, &sink));
    try std.testing.expectEqual(@as(usize, 1), sink.slice().len);
}

test "buffer too small reported by builders" {
    var small: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildOpsNotice(&small, "irc.example", .{
        .nick = "alice",
        .user = "user",
        .host = "host",
    }, "#secret", "invite me"));
    try std.testing.expectError(error.OutputTooSmall, buildKnockerAck(&small, "irc.example", "alice", "#secret"));
    try std.testing.expectError(error.OutputTooSmall, buildChanOpenFail(&small, "#secret"));
}

test "invalid input rejected" {
    const missing = [_][]const u8{};
    try std.testing.expectError(error.MissingChannel, parseKnockArgs(&missing));

    const too_many = [_][]const u8{ "#secret", "reason", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseKnockArgs(&too_many));

    const bad_channel = [_][]const u8{"#bad channel"};
    try std.testing.expectError(error.InvalidChannel, parseKnockArgs(&bad_channel));

    const bad_reason = [_][]const u8{ "#secret", "bad\rreason" };
    try std.testing.expectError(error.InvalidReason, parseKnockArgs(&bad_reason));

    try validateChannel("#caf\xc3\xa9");
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad\xff"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("#bad:name"));
    try std.testing.expectError(error.InvalidChannel, validateChannel("secret"));
    try std.testing.expectError(error.ChannelTooLong, validateChannelWith(.{ .max_channel_bytes = 4 }, "#long"));
    try validateChannelWith(.{ .require_utf8 = false }, "#raw\xff");

    var buf: [160]u8 = undefined;
    try std.testing.expectError(error.InvalidNick, buildOpsKnockNumeric(&buf, "irc.example", "bad nick", "#secret", .{
        .nick = "alice",
        .user = "user",
        .host = "host",
    }, ""));
    try std.testing.expectError(error.InvalidUser, buildOpsNotice(&buf, "irc.example", .{
        .nick = "alice",
        .user = "bad user",
        .host = "host",
    }, "#secret", ""));
    try std.testing.expectError(error.InvalidDescription, buildFailureNumeric(&buf, "irc.example", "alice", "#secret", .ERR_CHANOPEN, "bad\ndescription"));
}
