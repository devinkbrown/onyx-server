// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure CLEAR USERS mass-kick planning for the Onyx Server daemon.
//!
//! This module parses a real IRC command shape (`CLEAR <channel> USERS ...`),
//! plans real `KICK` commands from an injected membership snapshot, and can
//! format standard numeric replies.
const std = @import("std");

pub const default_reason = "Channel cleared";

const max_parse_params: usize = 12;

pub const Params = struct {
    max_channel_bytes: usize = 64,
    max_nick_bytes: usize = 64,
    max_account_bytes: usize = 64,
    max_reason_bytes: usize = 180,
    max_members: usize = 4096,
    max_allow_accounts: usize = 256,
    max_line_bytes: usize = 512,
};

pub const Error = error{
    NeedMoreParams,
    UnknownCommand,
    UnsupportedClearTarget,
    UnknownOption,
    InvalidRank,
    InvalidChannel,
    ChannelTooLong,
    InvalidNick,
    NickTooLong,
    InvalidAccount,
    AccountTooLong,
    InvalidReason,
    ReasonTooLong,
    InvalidServerName,
    MessageTooLong,
    TooManyMembers,
    TooManyAllowAccounts,
    OutputTooSmall,
    Forbidden,
};

pub const Numeric = enum(u16) {
    ERR_NOSUCHCHANNEL = 403,
    ERR_NEEDMOREPARAMS = 461,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_BADCHANMASK = 476,
};

pub fn formatCode(numeric: Numeric, out: *[3]u8) []const u8 {
    const value: u16 = @backingInt(numeric);
    out[0] = '0' + @as(u8, @intCast((value / 100) % 10));
    out[1] = '0' + @as(u8, @intCast((value / 10) % 10));
    out[2] = '0' + @as(u8, @intCast(value % 10));
    return out[0..3];
}

pub const Rank = enum(u8) {
    member = 0,
    voice = 10,
    halfop = 20,
    op = 30,
    admin = 40,
    owner = 50,
    founder = 60,

    pub fn atLeast(self: Rank, keep: Rank) bool {
        return @backingInt(self) >= @backingInt(keep);
    }

    pub fn parse(raw: []const u8) Error!Rank {
        var rank = raw;
        if (std.mem.startsWith(u8, rank, ">=")) rank = rank[2..];
        if (rank.len == 1) {
            return switch (rank[0]) {
                '+', 'v' => .voice,
                '%' => .halfop,
                '@', 'o' => .op,
                '&', 'a' => .admin,
                '~', 'q', '!' => .founder,
                else => error.InvalidRank,
            };
        }
        if (std.ascii.eqlIgnoreCase(rank, "member")) return .member;
        if (std.ascii.eqlIgnoreCase(rank, "voice")) return .voice;
        if (std.ascii.eqlIgnoreCase(rank, "voiced")) return .voice;
        if (std.ascii.eqlIgnoreCase(rank, "halfop")) return .halfop;
        if (std.ascii.eqlIgnoreCase(rank, "hop")) return .halfop;
        if (std.ascii.eqlIgnoreCase(rank, "op")) return .op;
        if (std.ascii.eqlIgnoreCase(rank, "oper")) return .op;
        if (std.ascii.eqlIgnoreCase(rank, "admin")) return .admin;
        if (std.ascii.eqlIgnoreCase(rank, "owner")) return .owner;
        if (std.ascii.eqlIgnoreCase(rank, "founder")) return .founder;
        return error.InvalidRank;
    }
};

pub const Actor = struct {
    nick: []const u8,
    rank: Rank = .member,
    is_oper: bool = false,
};

pub const Member = struct {
    nick: []const u8,
    account: ?[]const u8 = null,
    rank: Rank = .member,
};

pub const Exemptions = struct {
    /// Members with rank >= keep_rank are protected. Null disables rank-based
    /// protection; the account allowlist still applies.
    keep_rank: ?Rank = .founder,
    account_allowlist: []const []const u8 = &.{},

    pub fn protects(self: Exemptions, member: Member) bool {
        if (self.keep_rank) |keep| {
            if (member.rank.atLeast(keep)) return true;
        }
        if (member.account) |account| {
            for (self.account_allowlist) |allowed| {
                if (std.ascii.eqlIgnoreCase(account, allowed)) return true;
            }
        }
        return false;
    }
};

pub const ClearUsersRequest = struct {
    channel: []const u8,
    reason: []const u8 = default_reason,
    exemptions: Exemptions = .{},
};

pub const KickPlanEntry = struct {
    command: []const u8 = "KICK",
    channel: []const u8,
    nick: []const u8,
    reason: []const u8,
    member_index: usize,
};

pub fn canExecuteClearUsers(actor: Actor) bool {
    return actor.is_oper or actor.rank.atLeast(.founder);
}

pub fn parseClearUsers(line: []const u8, allow_out: [][]const u8) Error!ClearUsersRequest {
    return parseClearUsersWithParams(.{}, line, allow_out);
}

/// Parse `CLEAR <channel> USERS [KEEP <rank>] [ALLOW <acct[,acct...]>] [:reason]`.
///
/// The returned request borrows from `line`; `allow_out` receives borrowed
/// account slices and bounds account allowlist size without allocation.
pub fn parseClearUsersWithParams(params: Params, line: []const u8, allow_out: [][]const u8) Error!ClearUsersRequest {
    var storage: [max_parse_params]Token = undefined;
    const tokens = try tokenize(line, &storage);
    if (tokens.len == 0) return error.NeedMoreParams;
    if (!std.ascii.eqlIgnoreCase(tokens[0].bytes, "CLEAR")) return error.UnknownCommand;
    if (tokens.len < 3) return error.NeedMoreParams;
    if (!std.ascii.eqlIgnoreCase(tokens[2].bytes, "USERS")) return error.UnsupportedClearTarget;

    const channel = tokens[1].bytes;
    try validateChannel(params, channel);

    var request = ClearUsersRequest{
        .channel = channel,
        .reason = default_reason,
        .exemptions = .{ .keep_rank = .founder, .account_allowlist = allow_out[0..0] },
    };

    var allow_count: usize = 0;
    var i: usize = 3;
    while (i < tokens.len) {
        const token = tokens[i];
        if (token.trailing) {
            try validateReason(params, token.bytes);
            request.reason = token.bytes;
            i += 1;
            continue;
        }

        if (std.ascii.eqlIgnoreCase(token.bytes, "KEEP")) {
            if (i + 1 >= tokens.len or tokens[i + 1].trailing) return error.NeedMoreParams;
            request.exemptions.keep_rank = try Rank.parse(tokens[i + 1].bytes);
            i += 2;
            continue;
        }

        if (std.ascii.eqlIgnoreCase(token.bytes, "ALLOW")) {
            if (i + 1 >= tokens.len or tokens[i + 1].trailing) return error.NeedMoreParams;
            const added = try parseAllowlist(params, tokens[i + 1].bytes, allow_out[allow_count..]);
            allow_count += added;
            if (allow_count > params.max_allow_accounts) return error.TooManyAllowAccounts;
            request.exemptions.account_allowlist = allow_out[0..allow_count];
            i += 2;
            continue;
        }

        return error.UnknownOption;
    }

    try validateReason(params, request.reason);
    return request;
}

pub fn buildKickPlan(
    actor: Actor,
    request: ClearUsersRequest,
    members: []const Member,
    out: []KickPlanEntry,
) Error![]const KickPlanEntry {
    return buildKickPlanWithParams(.{}, actor, request, members, out);
}

/// Build a stable, input-ordered KICK plan. The planner never mutates channel
/// state; callers apply the returned real `KICK` commands in order.
pub fn buildKickPlanWithParams(
    params: Params,
    actor: Actor,
    request: ClearUsersRequest,
    members: []const Member,
    out: []KickPlanEntry,
) Error![]const KickPlanEntry {
    try validateNick(params, actor.nick);
    try validateChannel(params, request.channel);
    try validateReason(params, request.reason);
    try validateAllowlist(params, request.exemptions.account_allowlist);
    if (members.len > params.max_members) return error.TooManyMembers;
    if (!canExecuteClearUsers(actor)) return error.Forbidden;

    var count: usize = 0;
    for (members, 0..) |member, index| {
        try validateMember(params, member);
        if (request.exemptions.protects(member)) continue;
        if (count >= out.len) return error.OutputTooSmall;
        out[count] = .{
            .channel = request.channel,
            .nick = member.nick,
            .reason = request.reason,
            .member_index = index,
        };
        count += 1;
    }
    return out[0..count];
}

pub fn formatKickLine(source_server: []const u8, entry: KickPlanEntry, out: []u8) Error![]const u8 {
    return formatKickLineWithParams(.{}, source_server, entry, out);
}

/// Format a server-originated real IRC KICK line:
/// `:<server> KICK <channel> <nick> :<reason>\r\n`.
pub fn formatKickLineWithParams(params: Params, source_server: []const u8, entry: KickPlanEntry, out: []u8) Error![]const u8 {
    try validateServerName(source_server);
    try validateChannel(params, entry.channel);
    try validateNick(params, entry.nick);
    try validateReason(params, entry.reason);

    var builder = LineBuilder.init(params, out);
    try builder.byte(':');
    try builder.bytes(source_server);
    try builder.bytes(" KICK ");
    try builder.bytes(entry.channel);
    try builder.byte(' ');
    try builder.bytes(entry.nick);
    try builder.bytes(" :");
    try builder.bytes(entry.reason);
    try builder.bytes("\r\n");
    return builder.done();
}

pub const NumericReply = struct {
    code: Numeric,
    arg: []const u8,
    text: []const u8,
};

pub fn numericForError(err: Error, channel: []const u8) NumericReply {
    return switch (err) {
        error.NeedMoreParams => .{ .code = .ERR_NEEDMOREPARAMS, .arg = "CLEAR", .text = "Not enough parameters" },
        error.UnknownCommand => .{ .code = .ERR_UNKNOWNCOMMAND, .arg = "CLEAR", .text = "Unknown command" },
        error.Forbidden => .{ .code = .ERR_CHANOPRIVSNEEDED, .arg = channel, .text = "You're not channel founder or IRC operator" },
        error.InvalidChannel, error.ChannelTooLong => .{ .code = .ERR_BADCHANMASK, .arg = channel, .text = "Bad channel mask" },
        else => .{ .code = .ERR_CHANOPRIVSNEEDED, .arg = channel, .text = "Cannot clear channel users" },
    };
}

pub fn formatNumericLine(
    source_server: []const u8,
    requester_nick: []const u8,
    reply: NumericReply,
    out: []u8,
) Error![]const u8 {
    return formatNumericLineWithParams(.{}, source_server, requester_nick, reply, out);
}

pub fn formatNumericLineWithParams(
    params: Params,
    source_server: []const u8,
    requester_nick: []const u8,
    reply: NumericReply,
    out: []u8,
) Error![]const u8 {
    try validateServerName(source_server);
    try validateNick(params, requester_nick);

    var builder = LineBuilder.init(params, out);
    try builder.byte(':');
    try builder.bytes(source_server);
    try builder.byte(' ');
    var code_buf: [3]u8 = undefined;
    try builder.bytes(formatCode(reply.code, &code_buf));
    try builder.byte(' ');
    try builder.bytes(requester_nick);
    if (reply.arg.len != 0) {
        try builder.byte(' ');
        try builder.bytes(reply.arg);
    }
    try builder.bytes(" :");
    try builder.bytes(reply.text);
    try builder.bytes("\r\n");
    return builder.done();
}

const Token = struct {
    bytes: []const u8,
    trailing: bool = false,
};

fn tokenize(line: []const u8, out: *[max_parse_params]Token) Error![]const Token {
    const clean = std.mem.trimEnd(u8, line, "\r\n");
    var i: usize = 0;
    var count: usize = 0;
    while (i < clean.len) {
        while (i < clean.len and clean[i] == ' ') i += 1;
        if (i >= clean.len) break;
        if (count >= out.len) return error.MessageTooLong;

        if (clean[i] == ':') {
            out[count] = .{ .bytes = clean[i + 1 ..], .trailing = true };
            count += 1;
            break;
        }

        const start = i;
        while (i < clean.len and clean[i] != ' ') i += 1;
        out[count] = .{ .bytes = clean[start..i] };
        count += 1;
    }
    return out[0..count];
}

fn parseAllowlist(params: Params, raw: []const u8, out: [][]const u8) Error!usize {
    var count: usize = 0;
    var start: usize = 0;
    while (start <= raw.len) {
        const comma = std.mem.indexOfScalarPos(u8, raw, start, ',') orelse raw.len;
        const account = raw[start..comma];
        try validateAccount(params, account);
        if (count >= out.len or count >= params.max_allow_accounts) return error.TooManyAllowAccounts;
        out[count] = account;
        count += 1;
        if (comma == raw.len) break;
        start = comma + 1;
    }
    return count;
}

fn validateAllowlist(params: Params, allowlist: []const []const u8) Error!void {
    if (allowlist.len > params.max_allow_accounts) return error.TooManyAllowAccounts;
    for (allowlist) |account| try validateAccount(params, account);
}

fn validateMember(params: Params, member: Member) Error!void {
    try validateNick(params, member.nick);
    if (member.account) |account| try validateAccount(params, account);
}

fn validateChannel(params: Params, channel: []const u8) Error!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (!isChannelPrefix(channel[0])) return error.InvalidChannel;
    for (channel) |byte| {
        if (!validChannelByte(byte)) return error.InvalidChannel;
    }
}

fn validateNick(params: Params, nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':' or byte == ',' or byte == '*') {
            return error.InvalidNick;
        }
    }
}

fn validateAccount(params: Params, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':' or byte == ',') {
            return error.InvalidAccount;
        }
    }
}

fn validateReason(params: Params, reason: []const u8) Error!void {
    if (reason.len == 0) return error.InvalidReason;
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return error.InvalidReason;
    }
}

fn validateServerName(server: []const u8) Error!void {
    if (server.len == 0) return error.InvalidServerName;
    for (server) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':' or byte == ',') {
            return error.InvalidServerName;
        }
    }
}

fn isChannelPrefix(byte: u8) bool {
    return switch (byte) {
        '#', '&', '+', '!' => true,
        else => false,
    };
}

fn validChannelByte(byte: u8) bool {
    if (byte <= 0x20 or byte == 0x7f) return false;
    return switch (byte) {
        ',', ':' => false,
        else => true,
    };
}

const LineBuilder = struct {
    params: Params,
    out: []u8,
    len: usize = 0,

    fn init(params: Params, out: []u8) LineBuilder {
        return .{ .params = params, .out = out };
    }

    fn done(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn byte(self: *LineBuilder, value: u8) Error!void {
        if (self.len + 1 > self.out.len or self.len + 1 > self.params.max_line_bytes) {
            return error.MessageTooLong;
        }
        self.out[self.len] = value;
        self.len += 1;
    }

    fn bytes(self: *LineBuilder, value: []const u8) Error!void {
        if (self.len + value.len > self.out.len or self.len + value.len > self.params.max_line_bytes) {
            return error.MessageTooLong;
        }
        @memcpy(self.out[self.len .. self.len + value.len], value);
        self.len += value.len;
    }
};

const testing = std.testing;

test "parse minimal CLEAR USERS command with default founder protection and reason" {
    var allow: [4][]const u8 = undefined;
    const request = try parseClearUsers("CLEAR #river USERS", allow[0..]);

    try testing.expectEqualStrings("#river", request.channel);
    try testing.expectEqual(Rank.founder, request.exemptions.keep_rank.?);
    try testing.expectEqual(@as(usize, 0), request.exemptions.account_allowlist.len);
    try testing.expectEqualStrings(default_reason, request.reason);
}

test "parse KEEP ALLOW and trailing reason without allocation" {
    var allow: [4][]const u8 = undefined;
    const request = try parseClearUsers("CLEAR #ops USERS KEEP op ALLOW alice,bob :cleanup sweep", allow[0..]);

    try testing.expectEqualStrings("#ops", request.channel);
    try testing.expectEqual(Rank.op, request.exemptions.keep_rank.?);
    try testing.expectEqual(@as(usize, 2), request.exemptions.account_allowlist.len);
    try testing.expectEqualStrings("alice", request.exemptions.account_allowlist[0]);
    try testing.expectEqualStrings("bob", request.exemptions.account_allowlist[1]);
    try testing.expectEqualStrings("cleanup sweep", request.reason);
}

test "parser rejects indirect shapes and malformed CLEAR requests" {
    var allow: [1][]const u8 = undefined;
    try testing.expectError(error.UnknownCommand, parseClearUsers("PRIVMSG #x :CLEAR USERS", allow[0..]));
    try testing.expectError(error.NeedMoreParams, parseClearUsers("CLEAR #x", allow[0..]));
    try testing.expectError(error.UnsupportedClearTarget, parseClearUsers("CLEAR #x BANS", allow[0..]));
    try testing.expectError(error.UnknownOption, parseClearUsers("CLEAR #x USERS VIA service", allow[0..]));
    try testing.expectError(error.InvalidChannel, parseClearUsers("CLEAR users USERS", allow[0..]));
}

test "rank parser accepts named and prefix forms" {
    try testing.expectEqual(Rank.voice, try Rank.parse("+"));
    try testing.expectEqual(Rank.op, try Rank.parse("@"));
    try testing.expectEqual(Rank.admin, try Rank.parse("&"));
    try testing.expectEqual(Rank.founder, try Rank.parse("!"));
    try testing.expectEqual(Rank.owner, try Rank.parse("OWNER"));
    try testing.expectEqual(Rank.op, try Rank.parse(">=op"));
    try testing.expectError(error.InvalidRank, Rank.parse("services"));
}

test "founder can clear regular users while protecting keep rank and allowlist accounts" {
    const request = ClearUsersRequest{
        .channel = "#main",
        .reason = "founder sweep",
        .exemptions = .{ .keep_rank = .op, .account_allowlist = &.{ "trusted", "CaseFold" } },
    };
    const actor = Actor{ .nick = "founder", .rank = .founder };
    const members = [_]Member{
        .{ .nick = "alice", .account = "alice", .rank = .member },
        .{ .nick = "bob", .account = "trusted", .rank = .member },
        .{ .nick = "carol", .account = "carol", .rank = .voice },
        .{ .nick = "dave", .account = "dave", .rank = .op },
        .{ .nick = "erin", .account = "casefold", .rank = .member },
    };
    var out: [5]KickPlanEntry = undefined;

    const plan = try buildKickPlan(actor, request, &members, &out);
    try testing.expectEqual(@as(usize, 2), plan.len);
    try testing.expectEqualStrings("KICK", plan[0].command);
    try testing.expectEqualStrings("alice", plan[0].nick);
    try testing.expectEqual(@as(usize, 0), plan[0].member_index);
    try testing.expectEqualStrings("carol", plan[1].nick);
    try testing.expectEqual(@as(usize, 2), plan[1].member_index);
    try testing.expectEqualStrings("founder sweep", plan[0].reason);
    try testing.expectEqualStrings(plan[0].reason, plan[1].reason);
}

test "IRC operator may clear even without channel founder rank" {
    const request = ClearUsersRequest{ .channel = "#main", .reason = "oper sweep", .exemptions = .{ .keep_rank = .founder } };
    const actor = Actor{ .nick = "oper", .rank = .member, .is_oper = true };
    const members = [_]Member{
        .{ .nick = "alice", .rank = .member },
        .{ .nick = "founder", .rank = .founder },
    };
    var out: [2]KickPlanEntry = undefined;

    const plan = try buildKickPlan(actor, request, &members, &out);
    try testing.expectEqual(@as(usize, 1), plan.len);
    try testing.expectEqualStrings("alice", plan[0].nick);
}

test "non-founder non-oper cannot build a mass-kick plan" {
    const request = ClearUsersRequest{ .channel = "#main" };
    const actor = Actor{ .nick = "helper", .rank = .op };
    const members = [_]Member{.{ .nick = "alice" }};
    var out: [1]KickPlanEntry = undefined;

    try testing.expectError(error.Forbidden, buildKickPlan(actor, request, &members, &out));
}

test "plan preserves membership snapshot order" {
    const request = ClearUsersRequest{ .channel = "#main", .reason = "order test", .exemptions = .{ .keep_rank = null } };
    const actor = Actor{ .nick = "root", .rank = .founder };
    const members = [_]Member{
        .{ .nick = "zeta", .rank = .voice },
        .{ .nick = "alpha", .rank = .member },
        .{ .nick = "middle", .rank = .op },
    };
    var out: [3]KickPlanEntry = undefined;

    const plan = try buildKickPlan(actor, request, &members, &out);
    try testing.expectEqualStrings("zeta", plan[0].nick);
    try testing.expectEqualStrings("alpha", plan[1].nick);
    try testing.expectEqualStrings("middle", plan[2].nick);
}

test "bounded outputs and inputs are enforced" {
    const request = ClearUsersRequest{ .channel = "#main", .reason = "bounded", .exemptions = .{ .keep_rank = null } };
    const actor = Actor{ .nick = "root", .rank = .founder };
    const members = [_]Member{
        .{ .nick = "a" },
        .{ .nick = "b" },
    };
    var too_small: [1]KickPlanEntry = undefined;
    try testing.expectError(error.OutputTooSmall, buildKickPlan(actor, request, &members, &too_small));

    var enough: [2]KickPlanEntry = undefined;
    try testing.expectError(error.TooManyMembers, buildKickPlanWithParams(.{ .max_members = 1 }, actor, request, &members, &enough));
}

test "validation rejects unsafe nick account reason and channel fields" {
    const actor = Actor{ .nick = "root", .rank = .founder };
    var out: [1]KickPlanEntry = undefined;

    try testing.expectError(error.InvalidChannel, buildKickPlan(actor, .{ .channel = "plain" }, &.{.{ .nick = "a" }}, &out));
    try testing.expectError(error.InvalidNick, buildKickPlan(actor, .{ .channel = "#x" }, &.{.{ .nick = "bad nick" }}, &out));
    try testing.expectError(error.InvalidAccount, buildKickPlan(actor, .{ .channel = "#x" }, &.{.{ .nick = "a", .account = "bad,acct" }}, &out));
    try testing.expectError(error.InvalidReason, buildKickPlan(actor, .{ .channel = "#x", .reason = "bad\nreason" }, &.{.{ .nick = "a" }}, &out));
}

test "formatKickLine emits a real server-originated KICK command" {
    const entry = KickPlanEntry{
        .channel = "#main",
        .nick = "alice",
        .reason = "founder sweep",
        .member_index = 0,
    };
    var buf: [128]u8 = undefined;

    const line = try formatKickLine("irc.example", entry, &buf);
    try testing.expectEqualStrings(":irc.example KICK #main alice :founder sweep\r\n", line);
}

test "formatKickLine rejects non-server prefix and short buffers" {
    const entry = KickPlanEntry{ .channel = "#main", .nick = "alice", .reason = "sweep", .member_index = 0 };
    var buf: [8]u8 = undefined;

    try testing.expectError(error.InvalidServerName, formatKickLine("bad server", entry, &buf));
    try testing.expectError(error.MessageTooLong, formatKickLine("irc.example", entry, &buf));
}

test "numeric formatter emits standard IRC numeric lines" {
    const reply = NumericReply{
        .code = .ERR_CHANOPRIVSNEEDED,
        .arg = "#main",
        .text = "You're not channel founder or IRC operator",
    };
    var buf: [160]u8 = undefined;

    const line = try formatNumericLine("irc.example", "alice", reply, &buf);
    try testing.expectEqualStrings(":irc.example 482 alice #main :You're not channel founder or IRC operator\r\n", line);
}

test "numericForError maps parser and planner errors to real numerics" {
    try testing.expectEqual(Numeric.ERR_NEEDMOREPARAMS, numericForError(error.NeedMoreParams, "#x").code);
    try testing.expectEqual(Numeric.ERR_UNKNOWNCOMMAND, numericForError(error.UnknownCommand, "#x").code);
    try testing.expectEqual(Numeric.ERR_CHANOPRIVSNEEDED, numericForError(error.Forbidden, "#x").code);
    try testing.expectEqual(Numeric.ERR_BADCHANMASK, numericForError(error.InvalidChannel, "#x").code);
}

test "parser enforces allowlist and reason bounds" {
    var allow: [1][]const u8 = undefined;
    try testing.expectError(error.TooManyAllowAccounts, parseClearUsers("CLEAR #x USERS ALLOW a,b", allow[0..]));
    try testing.expectError(error.InvalidAccount, parseClearUsers("CLEAR #x USERS ALLOW bad:acct", allow[0..]));
    try testing.expectError(error.InvalidReason, parseClearUsers("CLEAR #x USERS :\r\n", allow[0..]));

    const long_reason = &@as([181]u8, @splat('x'));
    const line = "CLEAR #x USERS :" ++ long_reason;
    try testing.expectError(error.ReasonTooLong, parseClearUsers(line, allow[0..]));
}
