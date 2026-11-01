// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-server force channel action policy.
//!
//! This module is intentionally standalone: it imports only `std`, owns no
//! daemon state, performs no I/O, and never models pseudo-clients. Callers pass
//! an operator privilege set and a parsed force action; the result is either a
//! typed real IRC command plan or a typed numeric-denial plan.

const std = @import("std");

pub const required_privilege_name: []const u8 = "channel_moderate";

pub const Params = struct {
    max_command_params: usize = 8,
    max_channel_len: usize = 64,
    max_nick_len: usize = 64,
    max_topic_len: usize = 390,
    max_reason_len: usize = 390,
};

pub const default_params = Params{};

/// Operator privilege names match the daemon's account-oper grant vocabulary.
/// This module does not import the grant registry; it only needs a pure value
/// that can be built from the caller's active grant.
pub const Privilege = enum {
    server_rehash,
    server_restart,
    server_shutdown,
    client_moderate,
    channel_moderate,
    service_admin,
    mesh_admin,
    event_subscribe,
    audit_read,
    oper_grant,

    pub fn token(self: Privilege) []const u8 {
        return switch (self) {
            .server_rehash => "server_rehash",
            .server_restart => "server_restart",
            .server_shutdown => "server_shutdown",
            .client_moderate => "client_moderate",
            .channel_moderate => required_privilege_name,
            .service_admin => "service_admin",
            .mesh_admin => "mesh_admin",
            .event_subscribe => "event_subscribe",
            .audit_read => "audit_read",
            .oper_grant => "oper_grant",
        };
    }

    pub fn parse(raw: []const u8) ?Privilege {
        inline for (@typeInfo(Privilege).@"enum".field_values) |field_value| {
            const privilege: Privilege = @fromBackingInt(@intCast(field_value));
            if (std.ascii.eqlIgnoreCase(raw, privilege.token())) return privilege;
        }
        return null;
    }
};

pub const PrivilegeError = error{UnknownPrivilege};

pub const OperPrivileges = struct {
    set: std.EnumSet(Privilege) = .empty,

    pub const empty: OperPrivileges = .{};
    pub const full: OperPrivileges = .{ .set = std.EnumSet(Privilege).full };

    pub fn initMany(privileges: []const Privilege) OperPrivileges {
        return .{ .set = std.EnumSet(Privilege).initMany(privileges) };
    }

    pub fn fromNames(names: []const []const u8) PrivilegeError!OperPrivileges {
        var out = OperPrivileges.empty;
        for (names) |name| out.insert(Privilege.parse(name) orelse return error.UnknownPrivilege);
        return out;
    }

    pub fn insert(self: *OperPrivileges, privilege: Privilege) void {
        self.set.insert(privilege);
    }

    pub fn has(self: OperPrivileges, privilege: Privilege) bool {
        return self.set.contains(privilege);
    }
};

pub const ForceActionKind = enum {
    forceop,
    forcedeop,
    forcepart,
    forcejoin,
    forcetopic,

    pub fn command(self: ForceActionKind) []const u8 {
        return switch (self) {
            .forceop => "FORCEOP",
            .forcedeop => "FORCEDEOP",
            .forcepart => "FORCEPART",
            .forcejoin => "FORCEJOIN",
            .forcetopic => "FORCETOPIC",
        };
    }

    pub fn parse(raw: []const u8) ?ForceActionKind {
        inline for (@typeInfo(ForceActionKind).@"enum".field_values) |field_value| {
            const action: ForceActionKind = @fromBackingInt(@intCast(field_value));
            if (std.ascii.eqlIgnoreCase(raw, action.command())) return action;
        }
        return null;
    }
};

pub const ChannelTarget = struct {
    channel: []const u8,
    nick: []const u8,
};

pub const ChannelTargetReason = struct {
    channel: []const u8,
    nick: []const u8,
    reason: []const u8 = "",
};

pub const ChannelTopic = struct {
    channel: []const u8,
    topic: []const u8,
};

pub const ForceAction = union(ForceActionKind) {
    forceop: ChannelTarget,
    forcedeop: ChannelTarget,
    forcepart: ChannelTargetReason,
    forcejoin: ChannelTarget,
    forcetopic: ChannelTopic,

    pub fn kind(self: ForceAction) ForceActionKind {
        return std.meta.activeTag(self);
    }
};

pub const ServerCommand = enum {
    MODE,
    KICK,
    JOIN,
    TOPIC,
};

pub const Numeric = enum(u16) {
    ERR_NOSUCHCHANNEL = 403,
    ERR_NEEDMOREPARAMS = 461,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED = 482,
};

pub fn formatNumericCode(numeric: Numeric, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    const value: u16 = @backingInt(numeric);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

pub const ModePlan = struct {
    command: ServerCommand = .MODE,
    channel: []const u8,
    sign: u8,
    mode: u8 = 'o',
    nick: []const u8,
};

pub const KickPlan = struct {
    command: ServerCommand = .KICK,
    channel: []const u8,
    nick: []const u8,
    reason: []const u8,
};

pub const JoinPlan = struct {
    command: ServerCommand = .JOIN,
    channel: []const u8,
    nick: []const u8,
};

pub const TopicPlan = struct {
    command: ServerCommand = .TOPIC,
    channel: []const u8,
    topic: []const u8,
};

pub const NumericPlan = struct {
    numeric: Numeric,
    action: ForceActionKind,
    detail: DenyReason,
};

pub const ActionPlan = union(enum) {
    mode: ModePlan,
    kick: KickPlan,
    join: JoinPlan,
    topic: TopicPlan,
    numeric: NumericPlan,

    pub fn isRealServerCommand(self: ActionPlan) bool {
        return switch (self) {
            .mode, .kick, .join, .topic => true,
            .numeric => false,
        };
    }

    pub fn serverCommand(self: ActionPlan) ?ServerCommand {
        return switch (self) {
            .mode => |plan| plan.command,
            .kick => |plan| plan.command,
            .join => |plan| plan.command,
            .topic => |plan| plan.command,
            .numeric => null,
        };
    }
};

pub const DenyReason = enum {
    missing_oper_privilege,
    invalid_channel,
};

pub const Decision = struct {
    allowed: bool,
    plan: ActionPlan,

    pub fn allow(plan: ActionPlan) Decision {
        return .{ .allowed = true, .plan = plan };
    }

    pub fn deny(action: ForceActionKind, numeric: Numeric, reason: DenyReason) Decision {
        return .{
            .allowed = false,
            .plan = .{ .numeric = .{ .numeric = numeric, .action = action, .detail = reason } },
        };
    }
};

pub const ParseError = error{
    UnknownAction,
    NeedMoreParams,
    TooManyParams,
    InvalidChannel,
    InvalidNick,
    TopicTooLong,
    ReasonTooLong,
};

pub const ParsedLine = struct {
    params: [default_params.max_command_params][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const ParsedLine) []const []const u8 {
        return self.params[0..self.len];
    }
};

/// Parse one IRC-style command line into borrowed parameters. A `:` parameter
/// consumes the rest of the line as a single trailing value.
pub fn parseLine(line: []const u8) ParseError!ParsedLine {
    return parseLineWithParams(default_params, line);
}

fn parseLineWithParams(comptime params: Params, line: []const u8) ParseError!ParsedLine {
    if (params.max_command_params != default_params.max_command_params) {
        @compileError("ParsedLine has fixed default capacity; use parseRequest for custom Params");
    }

    var out = ParsedLine{};
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    var i: usize = 0;
    while (i < trimmed.len) {
        while (i < trimmed.len and trimmed[i] == ' ') i += 1;
        if (i >= trimmed.len) break;
        if (out.len == out.params.len) return error.TooManyParams;

        if (trimmed[i] == ':') {
            out.params[out.len] = trimmed[i + 1 ..];
            out.len += 1;
            break;
        }

        const start = i;
        while (i < trimmed.len and trimmed[i] != ' ') i += 1;
        out.params[out.len] = trimmed[start..i];
        out.len += 1;
    }
    return out;
}

/// Parse a full command line such as `FORCEOP #ops alice`.
pub fn parse(line: []const u8) ParseError!ForceAction {
    const parsed = try parseLine(line);
    return parseRequest(parsed.slice());
}

/// Parse argv-style parameters. The first element must be one of the real
/// server force-action command names; no pseudo-client target is accepted.
pub fn parseRequest(argv: []const []const u8) ParseError!ForceAction {
    if (argv.len == 0) return error.UnknownAction;
    const action = ForceActionKind.parse(argv[0]) orelse return error.UnknownAction;
    return switch (action) {
        .forceop => .{ .forceop = try parseChannelTarget(argv) },
        .forcedeop => .{ .forcedeop = try parseChannelTarget(argv) },
        .forcejoin => .{ .forcejoin = try parseChannelTarget(argv) },
        .forcepart => .{ .forcepart = try parseChannelTargetReason(argv) },
        .forcetopic => .{ .forcetopic = try parseChannelTopic(argv) },
    };
}

/// Authorize a force action and return a typed action plan. Denials are real
/// numerics; allowed actions are real IRC command plans.
pub fn authorize(privileges: OperPrivileges, action: ForceAction) Decision {
    if (!privileges.has(.channel_moderate)) {
        return Decision.deny(action.kind(), .ERR_NOPRIVILEGES, .missing_oper_privilege);
    }

    return switch (action) {
        .forceop => |target| Decision.allow(.{ .mode = .{
            .channel = target.channel,
            .sign = '+',
            .nick = target.nick,
        } }),
        .forcedeop => |target| Decision.allow(.{ .mode = .{
            .channel = target.channel,
            .sign = '-',
            .nick = target.nick,
        } }),
        .forcepart => |target| Decision.allow(.{ .kick = .{
            .channel = target.channel,
            .nick = target.nick,
            .reason = target.reason,
        } }),
        .forcejoin => |target| Decision.allow(.{ .join = .{
            .channel = target.channel,
            .nick = target.nick,
        } }),
        .forcetopic => |topic| Decision.allow(.{ .topic = .{
            .channel = topic.channel,
            .topic = topic.topic,
        } }),
    };
}

pub fn requiredPrivilege(_: ForceActionKind) Privilege {
    return .channel_moderate;
}

fn parseChannelTarget(argv: []const []const u8) ParseError!ChannelTarget {
    if (argv.len < 3) return error.NeedMoreParams;
    const channel = try checkedChannel(argv[1], default_params);
    const nick = try checkedNick(argv[2], default_params);
    return .{ .channel = channel, .nick = nick };
}

fn parseChannelTargetReason(argv: []const []const u8) ParseError!ChannelTargetReason {
    if (argv.len < 3) return error.NeedMoreParams;
    const channel = try checkedChannel(argv[1], default_params);
    const nick = try checkedNick(argv[2], default_params);
    const reason = if (argv.len >= 4) argv[3] else "";
    if (reason.len > default_params.max_reason_len) return error.ReasonTooLong;
    return .{ .channel = channel, .nick = nick, .reason = reason };
}

fn parseChannelTopic(argv: []const []const u8) ParseError!ChannelTopic {
    if (argv.len < 3) return error.NeedMoreParams;
    const channel = try checkedChannel(argv[1], default_params);
    const topic = argv[2];
    if (topic.len > default_params.max_topic_len) return error.TopicTooLong;
    return .{ .channel = channel, .topic = topic };
}

fn checkedChannel(raw: []const u8, params: Params) ParseError![]const u8 {
    if (!isChannelName(raw, params)) return error.InvalidChannel;
    return raw;
}

fn checkedNick(raw: []const u8, params: Params) ParseError![]const u8 {
    if (!isNickName(raw, params)) return error.InvalidNick;
    return raw;
}

pub fn isChannelName(raw: []const u8, params: Params) bool {
    if (raw.len < 2 or raw.len > params.max_channel_len) return false;
    switch (raw[0]) {
        '#', '&', '+', '!' => {},
        else => return false,
    }
    for (raw) |byte| {
        if (byte == 0 or byte == 7 or byte == '\r' or byte == '\n' or byte == ' ' or byte == ',') return false;
    }
    return true;
}

pub fn isNickName(raw: []const u8, params: Params) bool {
    if (raw.len == 0 or raw.len > params.max_nick_len) return false;
    if (!isNickStart(raw[0])) return false;
    for (raw[1..]) |byte| {
        if (!isNickByte(byte)) return false;
    }
    return true;
}

fn isNickStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '[' or byte == ']' or byte == '\\' or byte == '`' or byte == '_' or byte == '^' or byte == '{' or byte == '|' or byte == '}';
}

fn isNickByte(byte: u8) bool {
    return isNickStart(byte) or std.ascii.isDigit(byte) or byte == '-';
}

test "parse action names case insensitively" {
    try std.testing.expectEqual(ForceActionKind.forceop, ForceActionKind.parse("forceop").?);
    try std.testing.expectEqual(ForceActionKind.forcedeop, ForceActionKind.parse("FORCEDEOP").?);
    try std.testing.expectEqual(ForceActionKind.forcepart, ForceActionKind.parse("ForcePart").?);
    try std.testing.expectEqual(ForceActionKind.forcejoin, ForceActionKind.parse("forcejoin").?);
    try std.testing.expectEqual(ForceActionKind.forcetopic, ForceActionKind.parse("FORCETOPIC").?);
    try std.testing.expect(ForceActionKind.parse("ChanServ") == null);
}

test "parse forceop argv into channel target" {
    const argv = [_][]const u8{ "FORCEOP", "#ops", "alice" };
    const action = try parseRequest(&argv);
    try std.testing.expectEqual(ForceActionKind.forceop, action.kind());
    try std.testing.expectEqualStrings("#ops", action.forceop.channel);
    try std.testing.expectEqualStrings("alice", action.forceop.nick);
}

test "parse full command line with trailing forcepart reason" {
    const action = try parse("FORCEPART #ops bob :cleanup requested by oper\r\n");
    try std.testing.expectEqual(ForceActionKind.forcepart, action.kind());
    try std.testing.expectEqualStrings("#ops", action.forcepart.channel);
    try std.testing.expectEqualStrings("bob", action.forcepart.nick);
    try std.testing.expectEqualStrings("cleanup requested by oper", action.forcepart.reason);
}

test "parse forcetopic keeps trailing topic as one parameter" {
    const action = try parse("FORCETOPIC #ops :new topic with spaces");
    try std.testing.expectEqual(ForceActionKind.forcetopic, action.kind());
    try std.testing.expectEqualStrings("#ops", action.forcetopic.channel);
    try std.testing.expectEqualStrings("new topic with spaces", action.forcetopic.topic);
}

test "parser rejects missing parameters and invalid targets" {
    try std.testing.expectError(error.NeedMoreParams, parse("FORCEOP #ops"));
    try std.testing.expectError(error.InvalidChannel, parse("FORCEOP ops alice"));
    try std.testing.expectError(error.InvalidNick, parse("FORCEOP #ops 1alice"));
    try std.testing.expectError(error.UnknownAction, parse("PRIVMSG ChanServ :op #ops alice"));
}

test "privilege names parse into oper privilege set" {
    const names = [_][]const u8{ "audit_read", "CHANNEL_MODERATE" };
    const privileges = try OperPrivileges.fromNames(&names);
    try std.testing.expect(privileges.has(.audit_read));
    try std.testing.expect(privileges.has(.channel_moderate));
    try std.testing.expect(!privileges.has(.service_admin));
    try std.testing.expectError(error.UnknownPrivilege, OperPrivileges.fromNames(&[_][]const u8{"chanserv"}));
}

test "missing channel privilege denies with ERR_NOPRIVILEGES numeric plan" {
    const action = try parse("FORCEJOIN #ops alice");
    const decision = authorize(OperPrivileges.empty, action);
    try std.testing.expect(!decision.allowed);
    try std.testing.expectEqual(ActionPlan.numeric, std.meta.activeTag(decision.plan));
    try std.testing.expectEqual(Numeric.ERR_NOPRIVILEGES, decision.plan.numeric.numeric);
    try std.testing.expectEqual(DenyReason.missing_oper_privilege, decision.plan.numeric.detail);
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualStrings("481", formatNumericCode(decision.plan.numeric.numeric, &buf));
}

test "forceop authorizes to real MODE plus-o plan" {
    const action = try parse("FORCEOP #ops alice");
    const decision = authorize(OperPrivileges.initMany(&.{.channel_moderate}), action);
    try std.testing.expect(decision.allowed);
    try std.testing.expect(decision.plan.isRealServerCommand());
    try std.testing.expectEqual(ServerCommand.MODE, decision.plan.serverCommand().?);
    try std.testing.expectEqualStrings("#ops", decision.plan.mode.channel);
    try std.testing.expectEqual(@as(u8, '+'), decision.plan.mode.sign);
    try std.testing.expectEqual(@as(u8, 'o'), decision.plan.mode.mode);
    try std.testing.expectEqualStrings("alice", decision.plan.mode.nick);
}

test "forcedeop authorizes to real MODE minus-o plan" {
    const action = try parse("FORCEDEOP #ops alice");
    const decision = authorize(OperPrivileges.initMany(&.{.channel_moderate}), action);
    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(ServerCommand.MODE, decision.plan.serverCommand().?);
    try std.testing.expectEqual(@as(u8, '-'), decision.plan.mode.sign);
    try std.testing.expectEqual(@as(u8, 'o'), decision.plan.mode.mode);
}

test "forcepart authorizes to real KICK plan" {
    const action = try parse("FORCEPART #ops bob :operator requested part");
    const decision = authorize(OperPrivileges.initMany(&.{.channel_moderate}), action);
    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(ServerCommand.KICK, decision.plan.serverCommand().?);
    try std.testing.expectEqualStrings("#ops", decision.plan.kick.channel);
    try std.testing.expectEqualStrings("bob", decision.plan.kick.nick);
    try std.testing.expectEqualStrings("operator requested part", decision.plan.kick.reason);
}

test "forcejoin authorizes to real JOIN plan" {
    const action = try parse("FORCEJOIN #ops carol");
    const decision = authorize(OperPrivileges.initMany(&.{.channel_moderate}), action);
    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(ServerCommand.JOIN, decision.plan.serverCommand().?);
    try std.testing.expectEqualStrings("#ops", decision.plan.join.channel);
    try std.testing.expectEqualStrings("carol", decision.plan.join.nick);
}

test "forcetopic authorizes to real TOPIC plan" {
    const action = try parse("FORCETOPIC #ops :maintenance window");
    const decision = authorize(OperPrivileges.initMany(&.{.channel_moderate}), action);
    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(ServerCommand.TOPIC, decision.plan.serverCommand().?);
    try std.testing.expectEqualStrings("#ops", decision.plan.topic.channel);
    try std.testing.expectEqualStrings("maintenance window", decision.plan.topic.topic);
}

test "required privilege is stable for every force action" {
    inline for (@typeInfo(ForceActionKind).@"enum".field_values) |field_value| {
        const action: ForceActionKind = @fromBackingInt(@intCast(field_value));
        try std.testing.expectEqual(Privilege.channel_moderate, requiredPrivilege(action));
    }
}
