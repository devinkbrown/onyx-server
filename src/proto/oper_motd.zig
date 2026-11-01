// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator message-of-the-day storage and numeric reply rendering.
const std = @import("std");

/// OPERMOTD numeric replies and errors.
pub const OperMotdNumeric = enum(u16) {
    RPL_OMOTDSTART = 720,
    RPL_OMOTD = 721,
    RPL_ENDOFOMOTD = 722,
    ERR_NOOPERMOTD = 425,

    /// Return the integer IRC numeric code.
    pub fn code(self: OperMotdNumeric) u16 {
        return @backingInt(self);
    }

    /// Format the numeric as a three-digit IRC code into caller-owned storage.
    pub fn format(self: OperMotdNumeric, buf: []u8) []const u8 {
        if (buf.len < 3) return buf[0..0];
        const value = self.code();
        buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
        buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
        buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
        return buf[0..3];
    }
};

/// Storage and rendering bounds for OPERMOTD.
pub const Params = struct {
    max_lines: usize = 128,
    max_line_bytes: usize = 400,
    max_server_name_bytes: usize = 255,
    max_nick_bytes: usize = 64,
};

/// OPERMOTD storage and rendering errors.
pub const OperMotdError = std.mem.Allocator.Error || error{
    TooManyLines,
    LineTooLong,
    InvalidLine,
    InvalidServerName,
    ServerNameTooLong,
    InvalidNick,
    NickTooLong,
    OutputTooSmall,
};

/// Owned operator message-of-the-day lines.
pub const OperMotd = struct {
    allocator: std.mem.Allocator,
    params: Params,
    line_items: std.ArrayListUnmanaged([]u8) = .empty,

    /// Initialize an empty OPERMOTD store with default limits.
    pub fn init(allocator: std.mem.Allocator) OperMotd {
        return initWithParams(allocator, .{});
    }

    /// Initialize an empty OPERMOTD store with explicit limits.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) OperMotd {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    /// Free all memory owned by the OPERMOTD store.
    pub fn deinit(self: *OperMotd) void {
        self.clear();
        self.line_items.deinit(self.allocator);
        self.* = undefined;
    }

    /// Remove all stored lines while keeping list capacity for reuse.
    pub fn clear(self: *OperMotd) void {
        for (self.line_items.items) |line| {
            self.allocator.free(line);
        }
        self.line_items.clearRetainingCapacity();
    }

    /// Replace stored lines by splitting `text` on LF and duplicating each line.
    pub fn setFromText(self: *OperMotd, text: []const u8) OperMotdError!void {
        var replacement = std.ArrayListUnmanaged([]u8).empty;
        errdefer freeLineList(self.allocator, &replacement);

        if (text.len != 0) {
            var start: usize = 0;
            while (true) {
                const end = std.mem.indexOfScalarPos(u8, text, start, '\n') orelse text.len;
                const line = text[start..end];
                try validateMotdLineWith(self.params, line);
                if (replacement.items.len >= self.params.max_lines) return error.TooManyLines;

                const owned = try self.allocator.dupe(u8, line);
                replacement.append(self.allocator, owned) catch |err| {
                    self.allocator.free(owned);
                    return err;
                };

                if (end == text.len) break;
                start = end + 1;
            }
        }

        self.clear();
        self.line_items.deinit(self.allocator);
        self.line_items = replacement;
    }

    /// Return the stored lines in input order.
    pub fn lines(self: *const OperMotd) []const []const u8 {
        return @as([]const []const u8, @ptrCast(self.line_items.items));
    }

    /// Return true when no OPERMOTD lines are stored.
    pub fn isEmpty(self: *const OperMotd) bool {
        return self.line_items.items.len == 0;
    }
};

/// Stateless OPERMOTD numeric reply formatter.
pub const Formatter = struct {
    params: Params,

    /// Initialize a formatter with explicit limits.
    pub fn init(params: Params) Formatter {
        return .{ .params = params };
    }

    /// Build the RPL_OMOTDSTART reply into `out`.
    pub fn buildStart(
        self: Formatter,
        out: []u8,
        server_name: []const u8,
        requester_nick: []const u8,
    ) OperMotdError![]const u8 {
        return buildOperMotdStartWith(self.params, out, server_name, requester_nick);
    }

    /// Build one RPL_OMOTD body reply into `out`.
    pub fn buildLine(
        self: Formatter,
        out: []u8,
        server_name: []const u8,
        requester_nick: []const u8,
        line: []const u8,
    ) OperMotdError![]const u8 {
        return buildOperMotdLineWith(self.params, out, server_name, requester_nick, line);
    }

    /// Build the RPL_ENDOFOMOTD reply into `out`.
    pub fn buildEnd(
        self: Formatter,
        out: []u8,
        server_name: []const u8,
        requester_nick: []const u8,
    ) OperMotdError![]const u8 {
        return buildOperMotdEndWith(self.params, out, server_name, requester_nick);
    }

    /// Build the ERR_NOOPERMOTD reply into `out`.
    pub fn buildEmpty(
        self: Formatter,
        out: []u8,
        server_name: []const u8,
        requester_nick: []const u8,
    ) OperMotdError![]const u8 {
        return buildNoOperMotdWith(self.params, out, server_name, requester_nick);
    }
};

/// Build the default RPL_OMOTDSTART reply into `out`.
pub fn buildOperMotdStart(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    return buildOperMotdStartWith(.{}, out, server_name, requester_nick);
}

/// Build a bounded RPL_OMOTDSTART reply into `out`.
pub fn buildOperMotdStartWith(
    params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    try validateReplyContextWith(params, server_name, requester_nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_OMOTDSTART, server_name, requester_nick);
    try writer.appendBytes(" :- ");
    try writer.appendBytes(server_name);
    try writer.appendBytes(" Operator MOTD -\r\n");
    return writer.slice();
}

/// Build the default RPL_OMOTD body reply into `out`.
pub fn buildOperMotdLine(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    line: []const u8,
) OperMotdError![]const u8 {
    return buildOperMotdLineWith(.{}, out, server_name, requester_nick, line);
}

/// Build a bounded RPL_OMOTD body reply into `out`.
pub fn buildOperMotdLineWith(
    params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    line: []const u8,
) OperMotdError![]const u8 {
    try validateReplyContextWith(params, server_name, requester_nick);
    try validateMotdLineWith(params, line);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_OMOTD, server_name, requester_nick);
    try writer.appendBytes(" :- ");
    try writer.appendBytes(line);
    try writer.appendBytes("\r\n");
    return writer.slice();
}

/// Build the default RPL_ENDOFOMOTD reply into `out`.
pub fn buildOperMotdEnd(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    return buildOperMotdEndWith(.{}, out, server_name, requester_nick);
}

/// Build a bounded RPL_ENDOFOMOTD reply into `out`.
pub fn buildOperMotdEndWith(
    params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    try validateReplyContextWith(params, server_name, requester_nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_ENDOFOMOTD, server_name, requester_nick);
    try writer.appendBytes(" :End of OPERMOTD\r\n");
    return writer.slice();
}

/// Build the default ERR_NOOPERMOTD reply into `out`.
pub fn buildNoOperMotd(
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    return buildNoOperMotdWith(.{}, out, server_name, requester_nick);
}

/// Build a bounded ERR_NOOPERMOTD reply into `out`.
pub fn buildNoOperMotdWith(
    params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError![]const u8 {
    try validateReplyContextWith(params, server_name, requester_nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .ERR_NOOPERMOTD, server_name, requester_nick);
    try writer.appendBytes(" :OPERMOTD is empty\r\n");
    return writer.slice();
}

fn freeLineList(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged([]u8)) void {
    for (list.items) |line| {
        allocator.free(line);
    }
    list.deinit(allocator);
}

fn validateReplyContextWith(
    params: Params,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError!void {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
}

fn validateMotdLineWith(params: Params, line: []const u8) OperMotdError!void {
    if (line.len > params.max_line_bytes) return error.LineTooLong;
    for (line) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return error.InvalidLine;
    }
}

fn validateServerNameWith(params: Params, server_name: []const u8) OperMotdError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |byte| {
        if (!validServerNameByte(byte)) return error.InvalidServerName;
    }
}

fn validateNickWith(params: Params, nick: []const u8) OperMotdError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |byte| {
        if (!validNickByte(byte)) return error.InvalidNick;
    }
}

fn writeNumericHeader(
    writer: *BufferWriter,
    reply_numeric: OperMotdNumeric,
    server_name: []const u8,
    requester_nick: []const u8,
) OperMotdError!void {
    var code_buf: [3]u8 = undefined;
    const code_text = reply_numeric.format(&code_buf);

    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendByte(' ');
    try writer.appendBytes(code_text);
    try writer.appendByte(' ');
    try writer.appendBytes(requester_nick);
}

fn validServerNameByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']' => true,
        else => false,
    };
}

fn validNickByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
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

    fn appendBytes(self: *BufferWriter, bytes: []const u8) OperMotdError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) OperMotdError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "numeric code and formatting are exact" {
    // Arrange.
    var buf: [3]u8 = undefined;

    // Act and assert.
    try std.testing.expectEqual(@as(u16, 720), OperMotdNumeric.RPL_OMOTDSTART.code());
    try std.testing.expectEqual(@as(u16, 721), OperMotdNumeric.RPL_OMOTD.code());
    try std.testing.expectEqual(@as(u16, 722), OperMotdNumeric.RPL_ENDOFOMOTD.code());
    try std.testing.expectEqual(@as(u16, 425), OperMotdNumeric.ERR_NOOPERMOTD.code());
    try std.testing.expectEqualStrings("720", OperMotdNumeric.RPL_OMOTDSTART.format(&buf));
    try std.testing.expectEqualStrings("425", OperMotdNumeric.ERR_NOOPERMOTD.format(&buf));
}

test "setFromText splits owns and round trips line slices" {
    // Arrange.
    var motd = OperMotd.init(std.testing.allocator);
    defer motd.deinit();
    const source = "first line\nsecond line\n";

    // Act.
    try motd.setFromText(source);
    const stored = motd.lines();

    // Assert.
    try std.testing.expect(!motd.isEmpty());
    try std.testing.expectEqual(@as(usize, 3), stored.len);
    try std.testing.expectEqualStrings("first line", stored[0]);
    try std.testing.expectEqualStrings("second line", stored[1]);
    try std.testing.expectEqualStrings("", stored[2]);
    try std.testing.expect(stored[0].ptr != source[0.."first line".len].ptr);
}

test "setFromText replaces old lines and frees prior allocation" {
    // Arrange.
    var motd = OperMotd.init(std.testing.allocator);
    defer motd.deinit();
    try motd.setFromText("old one\nold two");

    // Act.
    try motd.setFromText("new one");
    const stored = motd.lines();

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), stored.len);
    try std.testing.expectEqualStrings("new one", stored[0]);
}

test "empty text clears store and drives empty error reply path" {
    // Arrange.
    var motd = OperMotd.init(std.testing.allocator);
    defer motd.deinit();
    try motd.setFromText("visible before clear");
    var out: [128]u8 = undefined;

    // Act.
    try motd.setFromText("");
    const reply = try buildNoOperMotd(&out, "irc.example.test", "alice");

    // Assert.
    try std.testing.expect(motd.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), motd.lines().len);
    try std.testing.expectEqualStrings(":irc.example.test 425 alice :OPERMOTD is empty\r\n", reply);
}

test "formatting builds start body and end replies" {
    // Arrange.
    var start_out: [256]u8 = undefined;
    var body_out: [256]u8 = undefined;
    var end_out: [256]u8 = undefined;
    const formatter = Formatter.init(.{});

    // Act.
    const start = try formatter.buildStart(&start_out, "irc.example.test", "alice");
    const body = try formatter.buildLine(&body_out, "irc.example.test", "alice", "operators only");
    const end = try formatter.buildEnd(&end_out, "irc.example.test", "alice");

    // Assert.
    try std.testing.expectEqualStrings(":irc.example.test 720 alice :- irc.example.test Operator MOTD -\r\n", start);
    try std.testing.expectEqualStrings(":irc.example.test 721 alice :- operators only\r\n", body);
    try std.testing.expectEqualStrings(":irc.example.test 722 alice :End of OPERMOTD\r\n", end);
}

test "limits reject too many lines and oversize line bytes" {
    // Arrange.
    var motd = OperMotd.initWithParams(std.testing.allocator, .{
        .max_lines = 2,
        .max_line_bytes = 4,
    });
    defer motd.deinit();

    // Act and assert.
    try motd.setFromText("one\ntwo");
    try std.testing.expectError(error.TooManyLines, motd.setFromText("one\ntwo\ntri"));
    try std.testing.expectError(error.LineTooLong, motd.setFromText("abcde"));
}

test "formatting validates line context and output capacity" {
    // Arrange.
    var out: [128]u8 = undefined;
    const limits = Params{ .max_line_bytes = 16, .max_server_name_bytes = 8, .max_nick_bytes = 5 };

    // Act and assert.
    try std.testing.expectError(error.LineTooLong, buildOperMotdLineWith(limits, &out, "irc.test", "alice", "this line is too long"));
    try std.testing.expectError(error.InvalidLine, buildOperMotdLineWith(limits, &out, "irc.test", "alice", "bad\rline"));
    try std.testing.expectError(error.ServerNameTooLong, buildOperMotdStartWith(limits, &out, "server.too.long", "alice"));
    try std.testing.expectError(error.NickTooLong, buildOperMotdStartWith(limits, &out, "irc.test", "toolong"));
    try std.testing.expectError(error.OutputTooSmall, buildOperMotdEnd(out[0..8], "irc.test", "alice"));
}

test "all reply builders work with empty body line and no leaks" {
    // Arrange.
    var motd = OperMotd.init(std.testing.allocator);
    defer motd.deinit();
    var out: [256]u8 = undefined;

    // Act.
    try motd.setFromText("\n");
    const lines = motd.lines();
    const first = try buildOperMotdLine(&out, "irc.example.test", "bob", lines[0]);
    const second = try buildOperMotdLine(&out, "irc.example.test", "bob", lines[1]);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings(":irc.example.test 721 bob :- \r\n", first);
    try std.testing.expectEqualStrings(":irc.example.test 721 bob :- \r\n", second);
}
