// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC WHOWAS numeric reply builder.
//!
//! History storage and lookup policy live elsewhere. This module validates the
//! caller-provided historical records and emits the RFC WHOWAS wire
//! numerics into a caller-owned scratch buffer, one complete CRLF-terminated
//! line at a time.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_USER_BYTES: usize = 64;
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;
pub const DEFAULT_MAX_REALNAME_BYTES: usize = 512;
pub const DEFAULT_MAX_ENTRIES: usize = 20;

const whowas_user_code = numeric.Numeric.RPL_WHOWASUSER;
const whois_server_code = numeric.Numeric.RPL_WHOISSERVER;
const endofwhowas_code = numeric.Numeric.RPL_ENDOFWHOWAS;
const wasnosuchnick_code = numeric.Numeric.ERR_WASNOSUCHNICK;

pub const WhowasReplyError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    InvalidUser,
    UserTooLong,
    InvalidHost,
    HostTooLong,
    InvalidRealname,
    RealnameTooLong,
    NegativeSignoffTime,
    InvalidEntryLimit,
    OutputTooSmall,
};

/// Compile-time validation and line-size limits for WHOWAS reply emission.
pub const Params = struct {
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_user_bytes: usize = DEFAULT_MAX_USER_BYTES,
    max_host_bytes: usize = DEFAULT_MAX_HOST_BYTES,
    max_realname_bytes: usize = DEFAULT_MAX_REALNAME_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_server_bytes = limits.server_name_len,
            .max_nick_bytes = limits.nick_len,
            .max_user_bytes = limits.user_len,
            .max_host_bytes = limits.host_len,
            .max_realname_bytes = limits.realname_len,
        };
    }
};

/// Runtime emission controls for a WHOWAS response.
pub const EmitOptions = struct {
    /// Maximum history entries to emit from the provided slice.
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    /// Emit one RPL_WHOISSERVER (312) line per record containing signoff time.
    include_signoff: bool = true,
};

/// One historical identity returned by the caller's WHOWAS history store.
pub const HistoryEntry = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    realname: []const u8,
    /// Logged-in account at signoff. Empty omits RPL_WHOISLOGGEDIN (330).
    account: []const u8 = "",
    signoff_time: i64,
    server: []const u8,
};

/// Emit WHOWAS numerics to `sink.send(line)`, reusing `scratch` for each line.
///
/// When `entries` is empty, ERR_WASNOSUCHNICK (406) is emitted before the
/// mandatory RPL_ENDOFWHOWAS (369). Otherwise, at most `DEFAULT_MAX_ENTRIES`
/// entries are emitted in caller order.
pub fn emitWhowas(
    scratch: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    entries: []const HistoryEntry,
    sink: anytype,
) WhowasReplyError!void {
    return emitWhowasWith(.{}, scratch, server_name, requester_nick, target_nick, entries, .{}, sink);
}

/// Emit WHOWAS numerics using caller-selected limits and runtime options.
pub fn emitWhowasWith(
    comptime params: Params,
    scratch: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
    entries: []const HistoryEntry,
    options: EmitOptions,
    sink: anytype,
) WhowasReplyError!void {
    try validateContextWith(params, server_name, requester_nick, target_nick);
    if (options.max_entries == 0) return error.InvalidEntryLimit;

    if (entries.len == 0) {
        try sink.send(try writeWasNoSuchNickWith(params, scratch, server_name, requester_nick, target_nick));
        try sink.send(try writeEndOfWhowasWith(params, scratch, server_name, requester_nick, target_nick));
        return;
    }

    const limit = @min(entries.len, options.max_entries);
    for (entries[0..limit]) |entry| {
        try validateEntryWith(params, entry);
        try sink.send(try writeWhowasUserLineWith(params, scratch, server_name, requester_nick, entry));
        if (whowasAccountOk(entry.account)) {
            try sink.send(try writeWhowasAccountLineWith(params, scratch, server_name, requester_nick, entry));
        }
        if (options.include_signoff) {
            try sink.send(try writeWhowasServerLineWith(params, scratch, server_name, requester_nick, entry));
        }
    }

    try sink.send(try writeEndOfWhowasWith(params, scratch, server_name, requester_nick, target_nick));
}

/// Build `RPL_WHOWASUSER` (314): `<nick> <user> <host> * :<realname>`.
pub fn writeWhowasUserLine(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    entry: HistoryEntry,
) WhowasReplyError![]const u8 {
    return writeWhowasUserLineWith(.{}, out, server_name, requester_nick, entry);
}

/// Build `RPL_WHOWASUSER` using caller-selected limits.
pub fn writeWhowasUserLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    entry: HistoryEntry,
) WhowasReplyError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateEntryWith(params, entry);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(whowas_user_code, server_name, requester_nick);
    try b.spaceParam(entry.nick);
    try b.spaceParam(entry.user);
    try b.spaceParam(entry.host);
    try b.spaceParam("*");
    try b.spaceTrailing(entry.realname);
    try b.crlf();
    return b.slice();
}

/// Build `RPL_WHOISLOGGEDIN` (330): `<nick> <account> :is logged in as`.
pub fn writeWhowasAccountLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    entry: HistoryEntry,
) WhowasReplyError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, entry.nick);
    if (!whowasAccountOk(entry.account)) return error.InvalidNick;

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(numeric.Numeric.RPL_WHOISLOGGEDIN, server_name, requester_nick);
    try b.spaceParam(entry.nick);
    try b.spaceParam(entry.account);
    try b.spaceTrailing("is logged in as");
    try b.crlf();
    return b.slice();
}

fn whowasAccountOk(account: []const u8) bool {
    if (account.len == 0) return false;
    for (account) |ch| {
        if (!validParamByte(ch)) return false;
    }
    return true;
}

/// Build optional `RPL_WHOISSERVER` (312): `<nick> <server> :<signoff_time>`.
pub fn writeWhowasServerLine(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    entry: HistoryEntry,
) WhowasReplyError![]const u8 {
    return writeWhowasServerLineWith(.{}, out, server_name, requester_nick, entry);
}

/// Build optional `RPL_WHOISSERVER` using caller-selected limits.
pub fn writeWhowasServerLineWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    entry: HistoryEntry,
) WhowasReplyError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateEntryWith(params, entry);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(whois_server_code, server_name, requester_nick);
    try b.spaceParam(entry.nick);
    try b.spaceParam(entry.server);
    try b.appendBytes(" :");
    try b.appendUnsigned(@as(u64, @intCast(entry.signoff_time)));
    try b.crlf();
    return b.slice();
}

/// Build `ERR_WASNOSUCHNICK` (406) for a WHOWAS miss.
pub fn writeWasNoSuchNick(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhowasReplyError![]const u8 {
    return writeWasNoSuchNickWith(.{}, out, server_name, requester_nick, target_nick);
}

/// Build `ERR_WASNOSUCHNICK` using caller-selected limits.
pub fn writeWasNoSuchNickWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhowasReplyError![]const u8 {
    try validateContextWith(params, server_name, requester_nick, target_nick);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(wasnosuchnick_code, server_name, requester_nick);
    try b.spaceParam(target_nick);
    try b.spaceTrailing("There was no such nickname");
    try b.crlf();
    return b.slice();
}

/// Build `RPL_ENDOFWHOWAS` (369) for a completed WHOWAS lookup.
pub fn writeEndOfWhowas(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhowasReplyError![]const u8 {
    return writeEndOfWhowasWith(.{}, out, server_name, requester_nick, target_nick);
}

/// Build `RPL_ENDOFWHOWAS` using caller-selected limits.
pub fn writeEndOfWhowasWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhowasReplyError![]const u8 {
    try validateContextWith(params, server_name, requester_nick, target_nick);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(endofwhowas_code, server_name, requester_nick);
    try b.spaceParam(target_nick);
    try b.spaceTrailing("End of WHOWAS");
    try b.crlf();
    return b.slice();
}

pub fn validateEntry(entry: HistoryEntry) WhowasReplyError!void {
    return validateEntryWith(.{}, entry);
}

pub fn validateEntryWith(comptime params: Params, entry: HistoryEntry) WhowasReplyError!void {
    try validateNickWith(params, entry.nick);
    try validateUserWith(params, entry.user);
    try validateHostWith(params, entry.host);
    try validateRealnameWith(params, entry.realname);
    try validateServerNameWith(params, entry.server);
    if (entry.signoff_time < 0) return error.NegativeSignoffTime;
}

pub fn validateServerName(server_name: []const u8) WhowasReplyError!void {
    return validateServerNameWith(.{}, server_name);
}

pub fn validateServerNameWith(comptime params: Params, server_name: []const u8) WhowasReplyError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validHostByte(ch)) return error.InvalidServerName;
    }
}

pub fn validateNick(nick: []const u8) WhowasReplyError!void {
    return validateNickWith(.{}, nick);
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) WhowasReplyError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

pub fn validateUser(user: []const u8) WhowasReplyError!void {
    return validateUserWith(.{}, user);
}

pub fn validateUserWith(comptime params: Params, user: []const u8) WhowasReplyError!void {
    if (user.len == 0) return error.InvalidUser;
    if (user.len > params.max_user_bytes) return error.UserTooLong;
    for (user) |ch| {
        if (!validUserByte(ch)) return error.InvalidUser;
    }
}

pub fn validateHost(host: []const u8) WhowasReplyError!void {
    return validateHostWith(.{}, host);
}

pub fn validateHostWith(comptime params: Params, host: []const u8) WhowasReplyError!void {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > params.max_host_bytes) return error.HostTooLong;
    for (host) |ch| {
        if (!validHostByte(ch)) return error.InvalidHost;
    }
}

pub fn validateRealname(realname: []const u8) WhowasReplyError!void {
    return validateRealnameWith(.{}, realname);
}

pub fn validateRealnameWith(comptime params: Params, realname: []const u8) WhowasReplyError!void {
    if (realname.len > params.max_realname_bytes) return error.RealnameTooLong;
    for (realname) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidRealname;
    }
}

fn validateContextWith(
    comptime params: Params,
    server_name: []const u8,
    requester_nick: []const u8,
    target_nick: []const u8,
) WhowasReplyError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, target_nick);
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

fn validTrailingByte(ch: u8) bool {
    return ch != 0 and ch != '\r' and ch != '\n';
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester_nick: []const u8,
    ) WhowasReplyError!void {
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendParam(requester_nick);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) WhowasReplyError!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) WhowasReplyError!void {
        try self.appendBytes(" :");
        try self.appendTrailing(param);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) WhowasReplyError!void {
        for (param) |ch| {
            if (!validParamByte(ch)) return error.InvalidNick;
        }
        try self.appendBytes(param);
    }

    fn appendTrailing(self: *LineBuilder, param: []const u8) WhowasReplyError!void {
        for (param) |ch| {
            if (!validTrailingByte(ch)) return error.InvalidRealname;
        }
        try self.appendBytes(param);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) WhowasReplyError!void {
        var buf: [20]u8 = undefined;
        var n: usize = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn crlf(self: *LineBuilder) WhowasReplyError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) WhowasReplyError!void {
        if (bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        if (bytes.len > self.max_line_bytes - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) WhowasReplyError!void {
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        if (self.max_line_bytes - self.len < 1) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

fn sampleEntry() HistoryEntry {
    return .{
        .nick = "alice",
        .user = "auser",
        .host = "host.example",
        .realname = "Alice Example",
        .signoff_time = 1700000000,
        .server = "irc.remote.test",
    };
}

const CapturedLine = struct {
    bytes: []const u8,
};

const CapturingSink = struct {
    lines: []CapturedLine,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    fn send(self: *CapturingSink, line: []const u8) WhowasReplyError!void {
        if (self.count >= self.lines.len) return error.OutputTooSmall;
        if (line.len > self.storage.len - self.used) return error.OutputTooSmall;

        const start = self.used;
        @memcpy(self.storage[start .. start + line.len], line);
        self.used += line.len;
        self.lines[self.count] = .{ .bytes = self.storage[start..self.used] };
        self.count += 1;
    }

    fn slice(self: *const CapturingSink) []const CapturedLine {
        return self.lines[0..self.count];
    }
};

test "single entry emits 314 optional 312 and 369" {
    var scratch: [256]u8 = undefined;
    var storage: [512]u8 = undefined;
    var lines_storage: [3]CapturedLine = undefined;
    var sink = CapturingSink{ .lines = &lines_storage, .storage = &storage };

    try emitWhowas(&scratch, "irc.example", "dan", "alice", &.{sampleEntry()}, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings(
        ":irc.example 314 dan alice auser host.example * :Alice Example\r\n",
        lines[0].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example 312 dan alice irc.remote.test :1700000000\r\n",
        lines[1].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example 369 dan alice :End of WHOWAS\r\n",
        lines[2].bytes,
    );
}

test "multi entry response is capped in caller order" {
    const entries = [_]HistoryEntry{
        sampleEntry(),
        .{
            .nick = "alice",
            .user = "second",
            .host = "second.example",
            .realname = "Alice Second",
            .signoff_time = 1700000001,
            .server = "irc.two.test",
        },
        .{
            .nick = "alice",
            .user = "third",
            .host = "third.example",
            .realname = "Alice Third",
            .signoff_time = 1700000002,
            .server = "irc.three.test",
        },
    };

    var scratch: [256]u8 = undefined;
    var storage: [512]u8 = undefined;
    var lines_storage: [3]CapturedLine = undefined;
    var sink = CapturingSink{ .lines = &lines_storage, .storage = &storage };

    try emitWhowasWith(
        .{},
        &scratch,
        "irc.example",
        "dan",
        "alice",
        &entries,
        .{ .max_entries = 2, .include_signoff = false },
        &sink,
    );

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings(":irc.example 314 dan alice auser host.example * :Alice Example\r\n", lines[0].bytes);
    try std.testing.expectEqualStrings(":irc.example 314 dan alice second second.example * :Alice Second\r\n", lines[1].bytes);
    try std.testing.expectEqualStrings(":irc.example 369 dan alice :End of WHOWAS\r\n", lines[2].bytes);
}

test "no history emits 406 and 369" {
    var scratch: [128]u8 = undefined;
    var storage: [256]u8 = undefined;
    var lines_storage: [2]CapturedLine = undefined;
    var sink = CapturingSink{ .lines = &lines_storage, .storage = &storage };

    try emitWhowas(&scratch, "irc.example", "dan", "missing", &.{}, &sink);

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings(
        ":irc.example 406 dan missing :There was no such nickname\r\n",
        lines[0].bytes,
    );
    try std.testing.expectEqualStrings(
        ":irc.example 369 dan missing :End of WHOWAS\r\n",
        lines[1].bytes,
    );
}

test "individual line format matches WHOWAS numerics" {
    var out: [256]u8 = undefined;
    const user_line = try writeWhowasUserLine(&out, "irc.example", "dan", sampleEntry());
    try std.testing.expectEqualStrings(
        ":irc.example 314 dan alice auser host.example * :Alice Example\r\n",
        user_line,
    );

    const end_line = try writeEndOfWhowas(&out, "irc.example", "dan", "alice");
    try std.testing.expectEqualStrings(
        ":irc.example 369 dan alice :End of WHOWAS\r\n",
        end_line,
    );
}

test "invalid bytes and limits are rejected without panic" {
    var bad = sampleEntry();
    bad.realname = "bad\rname";
    try std.testing.expectError(error.InvalidRealname, validateEntry(bad));

    bad = sampleEntry();
    bad.signoff_time = -1;
    try std.testing.expectError(error.NegativeSignoffTime, validateEntry(bad));

    var out: [16]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        writeWhowasUserLine(&out, "irc.example", "dan", sampleEntry()),
    );
}
