// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCX command gate.
//!
//! This module owns no session state. Callers supply the current IRCX opt-in
//! bit and the parsed IRC command name; the gate returns only a decision and
//! can render the deterministic denial reply into caller-owned storage.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const NEED_IRCX_TEXT: []const u8 = "IRCX command requires ISIRCX";
pub const NEED_IRCX_CODE: u16 = @intFromEnum(numeric.Numeric.ERR_UNKNOWNCOMMAND);

pub const Decision = enum {
    Allowed,
    NeedIrcx,

    pub fn isAllowed(self: Decision) bool {
        return self == .Allowed;
    }
};

pub const GateResult = Decision;
pub const Allowed = Decision.Allowed;
pub const NeedIrcx = Decision.NeedIrcx;

pub const ErrorContext = struct {
    server_name: []const u8,
    recipient_nick: []const u8,
};

pub const BuildError = error{
    InvalidToken,
    OutputTooSmall,
};

const gated_commands = [_][]const u8{
    "CREATE",
    "DATA",
    "REQUEST",
    "REPLY",
    "PROP",
    "ACCESS",
    "EVENT",
    "MODEX",
    "WHISPER",
    "LISTX",
    "AUTH",
    "SACCESS",
    "E2EEGROUP",
};

/// Return whether `name` is one of the IRCX commands guarded by this module.
///
/// `IRCX` and `ISIRCX` are intentionally not included: they are opt-in commands
/// that establish the state this predicate consumes.
pub fn isIrcxCommand(name: []const u8) bool {
    for (gated_commands) |command| {
        if (std.ascii.eqlIgnoreCase(name, command)) return true;
    }
    return false;
}

/// Decide whether `name` is permitted for a session with the supplied IRCX bit.
pub fn gate(session_is_ircx: bool, name: []const u8) Decision {
    if (session_is_ircx or !isIrcxCommand(name)) return .Allowed;
    return .NeedIrcx;
}

/// Build the denial reply for a `.NeedIrcx` gate decision.
///
/// The wire shape deliberately uses `ERR_UNKNOWNCOMMAND` (421): to a client that
/// has not opted into IRCX, the guarded command surface is not available yet.
pub fn buildNeedIrcxReply(
    out: []u8,
    context: ErrorContext,
    command_name: []const u8,
) BuildError![]const u8 {
    return buildErrorReply(out, context, command_name);
}

pub fn buildErrorReply(
    out: []u8,
    context: ErrorContext,
    command_name: []const u8,
) BuildError![]const u8 {
    return buildCustomErrorReply(out, context, command_name, NEED_IRCX_TEXT);
}

pub fn buildNeedIrcxErrorReply(
    out: []u8,
    context: ErrorContext,
    command_name: []const u8,
) BuildError![]const u8 {
    return buildErrorReply(out, context, command_name);
}

pub fn buildGateErrorReply(
    out: []u8,
    context: ErrorContext,
    command_name: []const u8,
) BuildError![]const u8 {
    return buildErrorReply(out, context, command_name);
}

pub fn buildCustomErrorReply(
    out: []u8,
    context: ErrorContext,
    command_name: []const u8,
    text: []const u8,
) BuildError![]const u8 {
    try validateToken(context.server_name);
    try validateToken(context.recipient_nick);
    try validateToken(command_name);
    try validateText(text);

    var writer = BufferWriter.init(out);
    try writer.append(":");
    try writer.append(context.server_name);
    try writer.append(" ");
    var code_buf: [3]u8 = undefined;
    try writer.append(numeric.formatCode(.ERR_UNKNOWNCOMMAND, &code_buf));
    try writer.append(" ");
    try writer.append(context.recipient_nick);
    try writer.append(" ");
    try writer.append(command_name);
    try writer.append(" :");
    try writer.append(text);
    try writer.crlf();
    return writer.slice();
}

fn validateToken(token: []const u8) BuildError!void {
    if (token.len == 0) return error.InvalidToken;
    for (token) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', ':' => return error.InvalidToken,
            else => {},
        }
    }
}

fn validateText(text: []const u8) BuildError!void {
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidToken,
            else => {},
        }
    }
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn append(self: *BufferWriter, bytes: []const u8) BuildError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) {
            return error.OutputTooSmall;
        }
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn crlf(self: *BufferWriter) BuildError!void {
        try self.append("\r\n");
    }
};

test "ircx commands are gated when the session has not opted in" {
    const allocator = std.testing.allocator;
    const commands = try allocator.dupe([]const u8, &gated_commands);
    defer allocator.free(commands);

    for (commands) |command| {
        try std.testing.expect(isIrcxCommand(command));
        try std.testing.expectEqual(.NeedIrcx, gate(false, command));
    }

    try std.testing.expect(isIrcxCommand("create"));
    try std.testing.expectEqual(.NeedIrcx, gate(false, "whisper"));
}

test "ircx commands are allowed after opt-in" {
    const allocator = std.testing.allocator;
    const commands = try allocator.dupe([]const u8, &gated_commands);
    defer allocator.free(commands);

    for (commands) |command| {
        try std.testing.expectEqual(.Allowed, gate(true, command));
    }
}

test "non-ircx commands are always allowed" {
    const allocator = std.testing.allocator;
    const commands = try allocator.dupe([]const u8, &.{
        "IRCX",
        "ISIRCX",
        "PRIVMSG",
        "JOIN",
        "AUTHENTICATE",
    });
    defer allocator.free(commands);

    for (commands) |command| {
        try std.testing.expect(!isIrcxCommand(command));
        try std.testing.expectEqual(.Allowed, gate(false, command));
        try std.testing.expectEqual(.Allowed, gate(true, command));
    }
}

test "need-ircx error reply bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 128);
    defer allocator.free(out);

    const reply = try buildNeedIrcxReply(
        out,
        .{ .server_name = "irc.example", .recipient_nick = "alice" },
        "CREATE",
    );
    try std.testing.expectEqualStrings(
        ":irc.example 421 alice CREATE :IRCX command requires ISIRCX\r\n",
        reply,
    );

    try std.testing.expectError(
        error.OutputTooSmall,
        buildNeedIrcxReply(out[0..16], .{ .server_name = "irc.example", .recipient_nick = "alice" }, "CREATE"),
    );
}
