// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX MODEX parsing and query reply builders.
//!
//! MODEX uses named channel/member modes instead of one-byte IRC mode letters:
//! `MODEX #team +AUTHONLY` or `MODEX #team,alice +OWNER`. This module does not
//! own input bytes and does not apply modes; it validates and normalizes caller
//! input into mode letters and optional mode parameters for the command layer.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

// MODEX is an Onyx Server IRCX extension and is NOT in draft-pfenning-04, which
// assigns 806/807 to EVENT ADD/DEL. To stay draft-faithful for EVENT, MODEX's
// list/end numerics live just past the EVENT range at 826/827.
pub const RPL_MODEXLIST: u16 = 826;
pub const RPL_MODEXEND: u16 = 827;

pub const DEFAULT_MAX_CHANGES: usize = 16;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_NAME_BYTES: usize = 64;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_TARGET_BYTES: usize = 160;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_MEMBER_BYTES: usize = 64;

pub const ModexError = error{
    NeedMoreParams,
    UnknownCommand,
    InvalidCommand,
    InvalidTarget,
    InvalidChannelName,
    InvalidMemberName,
    InvalidModeToken,
    InvalidModeName,
    UnknownModeName,
    ModeTargetMismatch,
    TooManyChanges,
    InvalidServerName,
    InvalidRequester,
    LineTooLong,
    OutputTooSmall,
};

/// Compile-time parser and builder limits.
pub const Params = struct {
    max_changes: usize = DEFAULT_MAX_CHANGES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_name_bytes: usize = DEFAULT_MAX_NAME_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_target_bytes: usize = DEFAULT_MAX_TARGET_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_member_bytes: usize = DEFAULT_MAX_MEMBER_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_changes = limits.ircx_modex_max_changes,
            .max_name_bytes = limits.ircx_modex_name_len,
            .max_server_bytes = limits.server_name_len,
            .max_requester_bytes = limits.nick_len,
            .max_target_bytes = limits.ircx_modex_target_len,
            .max_channel_bytes = limits.target_len_128,
            .max_member_bytes = limits.nick_len,
        };
    }
};

/// The kind of state controlled by a MODEX name.
pub const ModeKind = enum {
    channel,
    visibility,
    member,
};

/// Normalized operation requested for one named mode.
pub const ModeOp = enum {
    add,
    remove,

    pub fn sign(self: ModeOp) u8 {
        return switch (self) {
            .add => '+',
            .remove => '-',
        };
    }
};

/// One IRCX named mode. `letter == null` is reserved for `PUBLIC`, the absence
/// of private/hidden/secret visibility flags.
pub const ModeSpec = struct {
    name: []const u8,
    letter: ?u8,
    kind: ModeKind,
    requires_oper: bool = false,
    status_prefix: ?u8 = null,
};

/// IRCX MODEX name table derived from `docs/protocols/ircx.md`.
pub const mode_table = [_]ModeSpec{
    .{ .name = "PUBLIC", .letter = null, .kind = .visibility },
    .{ .name = "PRIVATE", .letter = 'p', .kind = .visibility },
    .{ .name = "HIDDEN", .letter = 'h', .kind = .visibility },
    .{ .name = "SECRET", .letter = 's', .kind = .visibility },
    .{ .name = "MODERATED", .letter = 'm', .kind = .channel },
    .{ .name = "TOPICOP", .letter = 't', .kind = .channel },
    .{ .name = "INVITEONLY", .letter = 'i', .kind = .channel },
    .{ .name = "NOEXTERN", .letter = 'n', .kind = .channel },
    .{ .name = "KNOCK", .letter = 'u', .kind = .channel },
    .{ .name = "AUTHONLY", .letter = 'a', .kind = .channel },
    .{ .name = "NOFORMAT", .letter = 'f', .kind = .channel },
    .{ .name = "CLONEABLE", .letter = 'd', .kind = .channel },
    .{ .name = "CLONE", .letter = 'E', .kind = .channel, .requires_oper = true },
    .{ .name = "REGISTERED", .letter = 'r', .kind = .channel, .requires_oper = true },
    .{ .name = "SERVICE", .letter = 'z', .kind = .channel, .requires_oper = true },
    .{ .name = "AUDITORIUM", .letter = 'x', .kind = .channel },
    .{ .name = "NOWHISPER", .letter = 'w', .kind = .channel },
    // OPMODERATE (+U): redirect blocked-by-+m speech to channel ops rather than
    // rejecting it. Enforced live (the `U` ext flag, reassigned from `O` in
    // dc69cfb), so the MODEX query row no longer risks advertise-without-enforce.
    .{ .name = "OPMODERATE", .letter = 'U', .kind = .channel },
    .{ .name = "NOCOMICDATA", .letter = 'V', .kind = .channel },
    // FREETARGET (+F): let anyone set this channel as a `+f` forward target.
    // DISFORWARD (+D): refuse to be a forward destination. Both enforced live on
    // the forward path, so the MODEX rows carry no advertise-without-enforce risk.
    .{ .name = "FREETARGET", .letter = 'F', .kind = .channel },
    .{ .name = "DISFORWARD", .letter = 'D', .kind = .channel },
    .{ .name = "NOCOLOR", .letter = 'c', .kind = .channel },
    .{ .name = "NOBOT", .letter = 'B', .kind = .channel },
    .{ .name = "FOUNDERKICK", .letter = 'K', .kind = .channel },
    .{ .name = "FOUNDER", .letter = 'Q', .kind = .member, .status_prefix = '~' },
    .{ .name = "OWNER", .letter = 'q', .kind = .member, .status_prefix = '.' },
    .{ .name = "HOST", .letter = 'o', .kind = .member, .status_prefix = '@' },
    .{ .name = "VOICE", .letter = 'v', .kind = .member, .status_prefix = '+' },
};

comptime {
    // Name and letter uniqueness scans every pair. The added rows exceed
    // Zig's default comptime branch quota.
    @setEvalBranchQuota(10_000);
    for (mode_table, 0..) |left, left_index| {
        for (mode_table[left_index + 1 ..]) |right| {
            if (asciiEqlComptime(left.name, right.name)) {
                @compileError("duplicate MODEX name");
            }
            if (left.letter != null and right.letter != null and left.letter.? == right.letter.?) {
                @compileError("duplicate MODEX letter");
            }
        }
    }
}

/// Parsed MODEX target.
pub const Target = struct {
    channel: []const u8,
    member: ?[]const u8 = null,

    pub fn isMember(self: Target) bool {
        return self.member != null;
    }
};

/// One normalized named-mode change. `mode_name` is the canonical static table
/// spelling. Member modes set `param` to the member nick from `#channel,nick`.
pub const ModeChange = struct {
    op: ModeOp,
    mode_name: []const u8,
    letter: ?u8,
    param: ?[]const u8 = null,
};

/// Parsed MODEX request. `changes` points into caller-owned storage.
pub const Request = struct {
    target: Target,
    changes: []const ModeChange,

    pub fn isQuery(self: Request) bool {
        return self.changes.len == 0;
    }
};

/// Context shared by MODEX numeric reply builders.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// Return the canonical MODEX spec for `name`.
pub fn lookupName(name: []const u8) ModexError!ModeSpec {
    return lookupNameWith(.{}, name);
}

fn lookupNameWith(comptime params: Params, name: []const u8) ModexError!ModeSpec {
    try validateModeNameWith(params, name);
    for (mode_table) |spec| {
        if (asciiEql(name, spec.name)) return spec;
    }
    return error.UnknownModeName;
}

/// Map a MODEX name to its IRC mode letter. `PUBLIC` returns null.
pub fn nameToLetter(name: []const u8) ModexError!?u8 {
    return (try lookupName(name)).letter;
}

/// Map an IRC mode letter to the canonical MODEX name.
pub fn letterToName(letter: u8) ModexError![]const u8 {
    return (try lookupLetter(letter)).name;
}

/// Return the canonical MODEX spec for a mode letter.
pub fn lookupLetter(letter: u8) ModexError!ModeSpec {
    for (mode_table) |spec| {
        if (spec.letter) |value| {
            if (value == letter) return spec;
        }
    }
    return error.UnknownModeName;
}

/// Parse a raw `MODEX ...` command line into caller-owned change storage.
pub fn parseCommand(line: []const u8, out: []ModeChange) ModexError!Request {
    return parseCommandWith(.{}, line, out);
}

/// Parse a raw `MODEX ...` command line with caller-selected limits.
pub fn parseCommandWith(comptime params: Params, line: []const u8, out: []ModeChange) ModexError!Request {
    const body = trimLineEnding(line);
    try validateLineBytes(body);

    var it = TokenIterator.init(body);
    const command = it.next() orelse return error.NeedMoreParams;
    if (!asciiEql(command, "MODEX")) return error.UnknownCommand;

    const target_param = it.next() orelse return error.NeedMoreParams;
    const target = try parseTargetWith(params, target_param);
    var count: usize = 0;
    while (it.next()) |token| {
        if (count >= out.len or count >= params.max_changes) return error.TooManyChanges;
        out[count] = try parseModeTokenForTarget(params, target, token);
        count += 1;
    }

    return .{
        .target = target,
        .changes = out[0..count],
    };
}

/// Parse tokenized MODEX parameters, excluding the command name.
pub fn parseParams(params: []const []const u8, out: []ModeChange) ModexError!Request {
    return parseParamsWith(.{}, params, out);
}

/// Parse tokenized MODEX parameters with caller-selected limits.
pub fn parseParamsWith(comptime params_limits: Params, params: []const []const u8, out: []ModeChange) ModexError!Request {
    if (params.len == 0) return error.NeedMoreParams;

    const target = try parseTargetWith(params_limits, params[0]);
    var count: usize = 0;
    for (params[1..]) |token| {
        if (count >= out.len or count >= params_limits.max_changes) return error.TooManyChanges;
        out[count] = try parseModeTokenForTarget(params_limits, target, token);
        count += 1;
    }

    return .{
        .target = target,
        .changes = out[0..count],
    };
}

/// Parse just the `#channel` or `#channel,nick` MODEX target.
pub fn parseTarget(target: []const u8) ModexError!Target {
    return parseTargetWith(.{}, target);
}

/// Parse a MODEX target with caller-selected limits.
pub fn parseTargetWith(comptime params: Params, target: []const u8) ModexError!Target {
    if (target.len == 0 or target.len > params.max_target_bytes) return error.InvalidTarget;

    var comma: ?usize = null;
    for (target, 0..) |byte, index| {
        if (byte == ',') {
            if (comma != null) return error.InvalidTarget;
            comma = index;
        }
    }

    if (comma) |split| {
        const channel = target[0..split];
        const member = target[split + 1 ..];
        try validateChannelWith(params, channel);
        try validateMemberWith(params, member);
        return .{ .channel = channel, .member = member };
    }

    try validateChannelWith(params, target);
    return .{ .channel = target };
}

/// Parse one signed MODEX mode token for `target`.
pub fn parseModeToken(target: []const u8, token: []const u8) ModexError!ModeChange {
    return parseModeTokenWith(.{}, target, token);
}

/// Parse one signed MODEX mode token with caller-selected limits.
pub fn parseModeTokenWith(comptime params: Params, target: []const u8, token: []const u8) ModexError!ModeChange {
    const parsed_target = try parseTargetWith(params, target);
    return parseModeTokenForTarget(params, parsed_target, token);
}

fn parseModeTokenForTarget(comptime params: Params, target: Target, token: []const u8) ModexError!ModeChange {
    if (token.len < 2) return error.InvalidModeToken;

    const op: ModeOp = switch (token[0]) {
        '+' => .add,
        '-' => .remove,
        else => return error.InvalidModeToken,
    };

    const spec = try lookupNameWith(params, token[1..]);
    if (target.isMember()) {
        if (spec.kind != .member) return error.ModeTargetMismatch;
    } else if (spec.kind == .member) {
        return error.ModeTargetMismatch;
    }

    return .{
        .op = op,
        .mode_name = spec.name,
        .letter = spec.letter,
        .param = if (spec.kind == .member) target.member else null,
    };
}

/// Build RPL_MODEXLIST (826): `<target> :<space-separated named modes>`.
pub fn writeModexList(
    out: []u8,
    ctx: ReplyContext,
    target: []const u8,
    mode_names: []const []const u8,
) ModexError![]const u8 {
    return writeModexListWith(.{}, out, ctx, target, mode_names);
}

/// Build RPL_MODEXLIST (826) with caller-selected limits.
pub fn writeModexListWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    target: []const u8,
    mode_names: []const []const u8,
) ModexError![]const u8 {
    try validateContextWith(params, ctx);
    _ = try parseTargetWith(params, target);
    for (mode_names) |mode_name| {
        _ = try lookupNameWith(params, mode_name);
    }

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_MODEXLIST, ctx.server_name, ctx.requester);
    try b.spaceParam(target);
    try b.appendBytes(" :");
    for (mode_names, 0..) |mode_name, index| {
        if (index != 0) try b.appendByte(' ');
        try b.appendBytes((try lookupNameWith(params, mode_name)).name);
    }
    try b.crlf();
    return b.slice();
}

/// Build RPL_MODEXEND (827): `<target> :End of modes`.
pub fn writeModexEnd(out: []u8, ctx: ReplyContext, target: []const u8) ModexError![]const u8 {
    return writeModexEndWith(.{}, out, ctx, target);
}

/// Build RPL_MODEXEND (827) with caller-selected limits.
pub fn writeModexEndWith(comptime params: Params, out: []u8, ctx: ReplyContext, target: []const u8) ModexError![]const u8 {
    try validateContextWith(params, ctx);
    _ = try parseTargetWith(params, target);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_MODEXEND, ctx.server_name, ctx.requester);
    try b.spaceParam(target);
    try b.appendBytes(" :End of modes");
    try b.crlf();
    return b.slice();
}

fn validateContextWith(comptime params: Params, ctx: ReplyContext) ModexError!void {
    try validateParamBounded(ctx.server_name, params.max_server_bytes, error.InvalidServerName);
    try validateParamBounded(ctx.requester, params.max_requester_bytes, error.InvalidRequester);
}

fn validateChannelWith(comptime params: Params, channel: []const u8) ModexError!void {
    if (channel.len == 0 or channel.len > params.max_channel_bytes) return error.InvalidChannelName;
    if (!validChannelNamePrefix(channel)) return error.InvalidChannelName;
    for (channel) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n', 0x7f => return error.InvalidChannelName,
            else => {},
        }
    }
}

fn validChannelNamePrefix(channel: []const u8) bool {
    return switch (channel[0]) {
        '#', '&' => true,
        '%' => channel.len >= 2 and (channel[1] == '#' or channel[1] == '&'),
        else => false,
    };
}

fn validateMemberWith(comptime params: Params, member: []const u8) ModexError!void {
    if (member.len == 0 or member.len > params.max_member_bytes) return error.InvalidMemberName;
    for (member) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n', 0x7f => return error.InvalidMemberName,
            else => {},
        }
    }
}

fn validateParamBounded(param: []const u8, max_len: usize, err: ModexError) ModexError!void {
    if (param.len == 0 or param.len > max_len) return err;
    if (param[0] == ':') return err;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn validateModeNameWith(comptime params: Params, name: []const u8) ModexError!void {
    if (name.len == 0 or name.len > params.max_name_bytes) return error.InvalidModeName;
    for (name) |byte| {
        if (!isAsciiAlpha(byte)) return error.InvalidModeName;
    }
}

fn validateLineBytes(line: []const u8) ModexError!void {
    for (line) |byte| {
        switch (byte) {
            0, '\r', '\n', 0x7f => return error.InvalidCommand,
            else => {},
        }
    }
}

fn trimLineEnding(line: []const u8) []const u8 {
    if (std.mem.endsWith(u8, line, "\r\n")) return line[0 .. line.len - 2];
    if (std.mem.endsWith(u8, line, "\n")) return line[0 .. line.len - 1];
    return line;
}

fn isAsciiAlpha(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiEqlComptime(comptime a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLowerComptime(left) != asciiLowerComptime(right)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn asciiLowerComptime(comptime byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn formatCodeValue(value: u16, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

const TokenIterator = struct {
    input: []const u8,
    cursor: usize = 0,

    fn init(input: []const u8) TokenIterator {
        return .{ .input = input };
    }

    fn next(self: *TokenIterator) ?[]const u8 {
        while (self.cursor < self.input.len and isSeparator(self.input[self.cursor])) {
            self.cursor += 1;
        }
        if (self.cursor >= self.input.len) return null;

        const start = self.cursor;
        while (self.cursor < self.input.len and !isSeparator(self.input[self.cursor])) {
            self.cursor += 1;
        }
        return self.input[start..self.cursor];
    }

    fn isSeparator(byte: u8) bool {
        return byte == ' ' or byte == '\t';
    }
};

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{
            .out = out,
            .max_line_bytes = @min(max_line_bytes, DEFAULT_MAX_LINE_BYTES),
        };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code_value: u16, server_name: []const u8, requester: []const u8) ModexError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCodeValue(code_value, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) ModexError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn crlf(self: *LineBuilder) ModexError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) ModexError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) ModexError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test {
    _ = numeric.numericTable;
}

test "name to letter mapping follows IRCX table" {
    try std.testing.expectEqual(@as(?u8, 'q'), try nameToLetter("OWNER"));
    try std.testing.expectEqual(@as(?u8, 'o'), try nameToLetter("HOST"));
    try std.testing.expectEqual(@as(?u8, 'v'), try nameToLetter("VOICE"));
    try std.testing.expectEqual(@as(?u8, 't'), try nameToLetter("TOPICOP"));
    try std.testing.expectEqual(@as(?u8, 'f'), try nameToLetter("NOFORMAT"));
    try std.testing.expectEqual(@as(?u8, 'Q'), try nameToLetter("FOUNDER"));
    try std.testing.expectEqual(@as(?u8, null), try nameToLetter("PUBLIC"));
}

test "letter to name mapping follows IRCX table" {
    try std.testing.expectEqualStrings("OWNER", try letterToName('q'));
    try std.testing.expectEqualStrings("HOST", try letterToName('o'));
    try std.testing.expectEqualStrings("VOICE", try letterToName('v'));
    try std.testing.expectEqualStrings("TOPICOP", try letterToName('t'));
    try std.testing.expectEqualStrings("FOUNDER", try letterToName('Q'));
}

test "parse member +OWNER into normalized change" {
    var changes: [4]ModeChange = undefined;
    const request = try parseCommand("MODEX #team,alice +OWNER", &changes);

    try std.testing.expect(!request.isQuery());
    try std.testing.expectEqualStrings("#team", request.target.channel);
    try std.testing.expectEqualStrings("alice", request.target.member.?);
    try std.testing.expectEqual(@as(usize, 1), request.changes.len);
    try std.testing.expectEqual(ModeOp.add, request.changes[0].op);
    try std.testing.expectEqualStrings("OWNER", request.changes[0].mode_name);
    try std.testing.expectEqual(@as(?u8, 'q'), request.changes[0].letter);
    try std.testing.expectEqualStrings("alice", request.changes[0].param.?);
}

test "parse channel query request" {
    var changes: [2]ModeChange = undefined;
    const request = try parseCommand("MODEX #team", &changes);

    try std.testing.expect(request.isQuery());
    try std.testing.expectEqualStrings("#team", request.target.channel);
    try std.testing.expectEqual(@as(?[]const u8, null), request.target.member);
}

test "query list builders emit 826 and 827" {
    const ctx = ReplyContext{ .server_name = "irc.example", .requester = "alice" };
    const modes = [_][]const u8{ "PUBLIC", "TOPICOP", "NOEXTERN" };
    var list_buf: [128]u8 = undefined;
    var end_buf: [128]u8 = undefined;

    const list = try writeModexList(&list_buf, ctx, "#team", &modes);
    const end = try writeModexEnd(&end_buf, ctx, "#team");

    try std.testing.expectEqualStrings(":irc.example 826 alice #team :PUBLIC TOPICOP NOEXTERN\r\n", list);
    try std.testing.expectEqualStrings(":irc.example 827 alice #team :End of modes\r\n", end);
}

test "unknown mode name is rejected" {
    var changes: [1]ModeChange = undefined;
    try std.testing.expectError(error.UnknownModeName, parseCommand("MODEX #team +NOTAMODE", &changes));
    try std.testing.expectError(error.UnknownModeName, nameToLetter("NOTAMODE"));
}

test "member and channel targets reject mismatched mode kinds" {
    var changes: [1]ModeChange = undefined;
    try std.testing.expectError(error.ModeTargetMismatch, parseCommand("MODEX #team +OWNER", &changes));
    try std.testing.expectError(error.ModeTargetMismatch, parseCommand("MODEX #team,alice +TOPICOP", &changes));
}

test "empty member mode list can be emitted" {
    const ctx = ReplyContext{ .server_name = "irc.example", .requester = "alice" };
    const modes = [_][]const u8{};
    var buf: [96]u8 = undefined;

    const list = try writeModexList(&buf, ctx, "#team,bob", &modes);
    try std.testing.expectEqualStrings(":irc.example 826 alice #team,bob :\r\n", list);
}
