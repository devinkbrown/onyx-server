// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCv3 CHATHISTORY command parser and response builder.
//!
//! Parse results borrow slices from the input command line. Response builders
//! write only into caller-provided buffers.
const std = @import("std");

pub const max_target_len: usize = 128;
pub const max_msgid_len: usize = 128;
pub const max_batch_ref_len: usize = 64;
pub const max_sender_len: usize = 256;
pub const max_line_body: usize = 8191;
pub const targets_batch_type = "draft/chathistory-targets";

pub const FailCode = enum {
    INVALID_PARAMS,
    NEED_MORE_PARAMS,
    INVALID_TARGET,
};

pub const ParseError = error{
    INVALID_PARAMS,
    NEED_MORE_PARAMS,
    INVALID_TARGET,
};

pub fn failCode(err: ParseError) FailCode {
    return switch (err) {
        error.INVALID_PARAMS => .INVALID_PARAMS,
        error.NEED_MORE_PARAMS => .NEED_MORE_PARAMS,
        error.INVALID_TARGET => .INVALID_TARGET,
    };
}

pub const ParseOptions = struct {
    max_limit: u16 = std.math.maxInt(u16),
    max_target_bytes: usize = max_target_len,
    max_msgid_bytes: usize = max_msgid_len,
};

pub const Selector = union(enum) {
    timestamp: u64,
    msgid: []const u8,
};

pub const Latest = struct {
    target: []const u8,
    lower_bound: ?Selector,
    limit: u16,
};

pub const Bound = struct {
    target: []const u8,
    selector: Selector,
    limit: u16,
};

pub const Range = struct {
    target: []const u8,
    start: Selector,
    end: Selector,
    limit: u16,
};

pub const Around = struct {
    target: []const u8,
    center: Selector,
    second: ?Selector = null,
    limit: u16,
};

pub const Request = union(enum) {
    latest: Latest,
    before: Bound,
    after: Bound,
    between: Range,
    around: Around,
};

pub const LatestMode = enum {
    unbounded,
    before_bound,
};

pub const RangeDirection = enum {
    forward,
    reverse,
};

pub fn requestTarget(request: Request) []const u8 {
    return switch (request) {
        .latest => |r| r.target,
        .before => |r| r.target,
        .after => |r| r.target,
        .between => |r| r.target,
        .around => |r| r.target,
    };
}

pub fn latestMode(latest: Latest) LatestMode {
    return if (latest.lower_bound == null) .unbounded else .before_bound;
}

pub fn rangeDirection(start: u64, end: u64) RangeDirection {
    return if (start <= end) .forward else .reverse;
}

pub fn channelHistoryTargetAllowed(channel_exists: bool, is_member: bool, is_visible: bool) bool {
    return channel_exists and (is_member or is_visible);
}

pub fn parse(line: []const u8) ParseError!Request {
    return parseWithOptions(line, .{});
}

pub fn parseWithOptions(line: []const u8, options: ParseOptions) ParseError!Request {
    const trimmed = trimLineEnd(line);
    var tokens: [8][]const u8 = undefined;
    var count: usize = 0;

    var it = std.mem.tokenizeScalar(u8, trimmed, ' ');
    while (it.next()) |token| {
        if (count == tokens.len) return error.INVALID_PARAMS;
        tokens[count] = token;
        count += 1;
    }

    if (count < 4) return error.NEED_MORE_PARAMS;
    if (!std.ascii.eqlIgnoreCase(tokens[0], "CHATHISTORY")) return error.INVALID_PARAMS;

    const subcommand = tokens[1];
    const target = tokens[2];
    try validateTarget(target, options.max_target_bytes);

    if (std.ascii.eqlIgnoreCase(subcommand, "LATEST")) {
        if (count < 5) return error.NEED_MORE_PARAMS;
        if (count != 5) return error.INVALID_PARAMS;
        const limit = try parseLimit(tokens[4], options.max_limit);
        const lower_bound: ?Selector = if (std.mem.eql(u8, tokens[3], "*"))
            null
        else
            try parseSelector(tokens[3], options);
        return .{ .latest = .{ .target = target, .lower_bound = lower_bound, .limit = limit } };
    }

    if (std.ascii.eqlIgnoreCase(subcommand, "BEFORE")) {
        if (count < 5) return error.NEED_MORE_PARAMS;
        if (count != 5) return error.INVALID_PARAMS;
        return .{ .before = .{
            .target = target,
            .selector = try parseSelector(tokens[3], options),
            .limit = try parseLimit(tokens[4], options.max_limit),
        } };
    }

    if (std.ascii.eqlIgnoreCase(subcommand, "AFTER")) {
        if (count < 5) return error.NEED_MORE_PARAMS;
        if (count != 5) return error.INVALID_PARAMS;
        return .{ .after = .{
            .target = target,
            .selector = try parseSelector(tokens[3], options),
            .limit = try parseLimit(tokens[4], options.max_limit),
        } };
    }

    if (std.ascii.eqlIgnoreCase(subcommand, "BETWEEN")) {
        if (count < 6) return error.NEED_MORE_PARAMS;
        if (count != 6) return error.INVALID_PARAMS;
        return .{ .between = .{
            .target = target,
            .start = try parseSelector(tokens[3], options),
            .end = try parseSelector(tokens[4], options),
            .limit = try parseLimit(tokens[5], options.max_limit),
        } };
    }

    if (std.ascii.eqlIgnoreCase(subcommand, "AROUND")) {
        if (count < 5) return error.NEED_MORE_PARAMS;
        if (count != 5 and count != 6) return error.INVALID_PARAMS;
        return .{ .around = .{
            .target = target,
            .center = try parseSelector(tokens[3], options),
            .second = if (count == 6) try parseSelector(tokens[4], options) else null,
            .limit = try parseLimit(tokens[if (count == 6) 5 else 4], options.max_limit),
        } };
    }

    return error.INVALID_PARAMS;
}

pub fn parseTimestamp(value: []const u8) ParseError!u64 {
    if (value.len != "YYYY-MM-DDThh:mm:ss.sssZ".len) return error.INVALID_PARAMS;
    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or
        value[13] != ':' or value[16] != ':' or value[19] != '.' or value[23] != 'Z')
    {
        return error.INVALID_PARAMS;
    }

    const year = try parseDigits(u16, value[0..4]);
    const month = try parseDigits(u8, value[5..7]);
    const day = try parseDigits(u8, value[8..10]);
    const hour = try parseDigits(u8, value[11..13]);
    const minute = try parseDigits(u8, value[14..16]);
    const second = try parseDigits(u8, value[17..19]);
    const millis = try parseDigits(u16, value[20..23]);

    if (year < 1970 or month < 1 or month > 12) return error.INVALID_PARAMS;
    if (hour > 23 or minute > 59 or second > 59) return error.INVALID_PARAMS;
    const month_enum: std.time.epoch.Month = @enumFromInt(month);
    const days_in_month = std.time.epoch.getDaysInMonth(year, month_enum);
    if (day < 1 or day > days_in_month) return error.INVALID_PARAMS;

    var days: u64 = 0;
    var cursor_year: u16 = 1970;
    while (cursor_year < year) : (cursor_year += 1) {
        days += std.time.epoch.getDaysInYear(cursor_year);
    }

    var cursor_month: u8 = 1;
    while (cursor_month < month) : (cursor_month += 1) {
        const cursor_enum: std.time.epoch.Month = @enumFromInt(cursor_month);
        days += std.time.epoch.getDaysInMonth(year, cursor_enum);
    }
    days += day - 1;

    const seconds = (((days * 24 + hour) * 60 + minute) * 60) + second;
    return seconds * 1000 + millis;
}

pub const Message = struct {
    timestamp_ms: u64,
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    /// IRC command to replay this entry as. Defaults to PRIVMSG; draft/
    /// event-playback entries (e.g. TOPIC) carry their own command.
    command: []const u8 = "PRIVMSG",
};

pub const BuildError = error{
    INVALID_PARAMS,
    INVALID_TARGET,
    OutputTooSmall,
    MessageTooLong,
};

pub const ResponseBuilder = struct {
    writer: BufferWriter,
    max_body_bytes: usize = max_line_body,

    pub fn init(out: []u8) ResponseBuilder {
        return .{ .writer = BufferWriter.init(out) };
    }

    pub fn withMaxBodyBytes(self: ResponseBuilder, max_body_bytes: usize) ResponseBuilder {
        var next = self;
        next.max_body_bytes = max_body_bytes;
        return next;
    }

    pub fn slice(self: *const ResponseBuilder) []const u8 {
        return self.writer.slice();
    }

    pub fn writeBatch(
        self: *ResponseBuilder,
        ref: []const u8,
        target: []const u8,
        messages: []const Message,
    ) BuildError![]const u8 {
        try validateBatchRef(ref);
        try validateTargetBuild(target);

        try self.writeOpen(ref, target);
        for (messages) |message| try self.writeMessage(ref, target, message);
        try self.writeClose(ref);
        return self.slice();
    }

    fn writeOpen(self: *ResponseBuilder, ref: []const u8, target: []const u8) BuildError!void {
        const start = self.writer.len;
        try self.writer.append("BATCH +");
        try self.writer.append(ref);
        try self.writer.append(" chathistory ");
        try self.writer.append(target);
        try self.writer.crlf();
        try self.checkLineLen(start);
    }

    fn writeMessage(self: *ResponseBuilder, ref: []const u8, target: []const u8, message: Message) BuildError!void {
        try validateMessage(message);
        var timestamp_buf: [24]u8 = undefined;
        const timestamp = try formatTimestamp(message.timestamp_ms, &timestamp_buf);

        const start = self.writer.len;
        try self.writer.append("@batch=");
        try self.writer.append(ref);
        try self.writer.append(";time=");
        try self.writer.append(timestamp);
        try self.writer.append(";msgid=");
        try self.writer.append(message.msgid);
        try self.writer.append(" :");
        try self.writer.append(message.sender);
        try self.writer.append(" ");
        try self.writer.append(message.command);
        if (isEventCommand(message.command)) {
            // draft/event-playback entry: `text` is the full post-command body
            // (target + params, e.g. "#chan +o nick" or "#chan :a new topic"),
            // so the line renders verbatim as `:sender <CMD> <body>`.
            try self.writer.append(" ");
            try self.writer.append(message.text);
        } else {
            // Ordinary message: `:sender PRIVMSG <target> :<body>`.
            try self.writer.append(" ");
            try self.writer.append(target);
            try self.writer.append(" :");
            try self.writer.append(message.text);
        }
        try self.writer.crlf();
        try self.checkLineLen(start);
    }

    /// A history entry is a draft/event-playback EVENT (rather than an ordinary
    /// message) when its replay command is neither PRIVMSG nor NOTICE.
    fn isEventCommand(command: []const u8) bool {
        return !std.mem.eql(u8, command, "PRIVMSG") and !std.mem.eql(u8, command, "NOTICE");
    }

    fn writeClose(self: *ResponseBuilder, ref: []const u8) BuildError!void {
        const start = self.writer.len;
        try self.writer.append("BATCH -");
        try self.writer.append(ref);
        try self.writer.crlf();
        try self.checkLineLen(start);
    }

    fn checkLineLen(self: *const ResponseBuilder, line_start: usize) BuildError!void {
        const line_len = self.writer.len - line_start;
        if (line_len < 2 or line_len - 2 > self.max_body_bytes) return error.MessageTooLong;
    }
};

pub fn writeBatch(
    out: []u8,
    ref: []const u8,
    target: []const u8,
    messages: []const Message,
) BuildError![]const u8 {
    var builder = ResponseBuilder.init(out);
    return builder.writeBatch(ref, target, messages);
}

pub fn formatTimestamp(epoch_ms: u64, out: *[24]u8) BuildError![]const u8 {
    const seconds = epoch_ms / 1000;
    const millis: u16 = @intCast(epoch_ms % 1000);
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    return std.fmt.bufPrint(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        millis,
    }) catch error.OutputTooSmall;
}

fn parseSelector(token: []const u8, options: ParseOptions) ParseError!Selector {
    const timestamp_prefix = "timestamp=";
    const msgid_prefix = "msgid=";
    if (std.mem.startsWith(u8, token, timestamp_prefix)) {
        return .{ .timestamp = try parseTimestamp(token[timestamp_prefix.len..]) };
    }
    if (std.mem.startsWith(u8, token, msgid_prefix)) {
        const msgid = token[msgid_prefix.len..];
        try validateMsgid(msgid, options.max_msgid_bytes);
        return .{ .msgid = msgid };
    }
    return error.INVALID_PARAMS;
}

fn parseLimit(token: []const u8, max_limit: u16) ParseError!u16 {
    if (token.len == 0) return error.INVALID_PARAMS;
    const limit = std.fmt.parseUnsigned(u16, token, 10) catch return error.INVALID_PARAMS;
    if (limit > max_limit) return error.INVALID_PARAMS;
    return limit;
}

fn parseDigits(comptime T: type, bytes: []const u8) ParseError!T {
    if (bytes.len == 0) return error.INVALID_PARAMS;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.INVALID_PARAMS;
    }
    return std.fmt.parseUnsigned(T, bytes, 10) catch error.INVALID_PARAMS;
}

fn validateTarget(target: []const u8, max_len: usize) ParseError!void {
    if (!validTarget(target, max_len)) return error.INVALID_TARGET;
}

fn validateTargetBuild(target: []const u8) BuildError!void {
    if (!validTarget(target, max_target_len)) return error.INVALID_TARGET;
}

fn validTarget(target: []const u8, max_len: usize) bool {
    if (target.len == 0 or target.len > max_len) return false;
    if (std.mem.eql(u8, target, "*")) return false;
    for (target) |byte| {
        if (byte <= ' ' or byte == 0x7f or byte == ',') return false;
    }
    return true;
}

fn validateMsgid(msgid: []const u8, max_len: usize) ParseError!void {
    if (!validMsgid(msgid, max_len)) return error.INVALID_PARAMS;
}

fn validMsgid(msgid: []const u8, max_len: usize) bool {
    if (msgid.len == 0 or msgid.len > max_len) return false;
    for (msgid) |byte| {
        if (byte <= ' ' or byte == 0x7f or byte == ';' or byte == '\\') return false;
    }
    return true;
}

fn validateBatchRef(ref: []const u8) BuildError!void {
    if (ref.len == 0 or ref.len > max_batch_ref_len) return error.INVALID_PARAMS;
    for (ref) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
        else => return error.INVALID_PARAMS,
    };
}

fn validateMessage(message: Message) BuildError!void {
    if (!validMsgid(message.msgid, max_msgid_len)) return error.INVALID_PARAMS;
    if (!validAtom(message.sender, max_sender_len)) return error.INVALID_PARAMS;
    if (!validCommand(message.command)) return error.INVALID_PARAMS;
    if (!validText(message.text)) return error.INVALID_PARAMS;
}

fn validCommand(command: []const u8) bool {
    if (command.len == 0) return false;
    for (command) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return false;
    }
    return true;
}

fn validAtom(atom: []const u8, max_len: usize) bool {
    if (atom.len == 0 or atom.len > max_len) return false;
    for (atom) |byte| {
        if (byte <= ' ' or byte == 0x7f) return false;
    }
    return true;
}

fn validText(text: []const u8) bool {
    for (text) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return false;
    }
    return true;
}

fn trimLineEnd(line: []const u8) []const u8 {
    if (std.mem.endsWith(u8, line, "\r\n")) return line[0 .. line.len - 2];
    if (line.len != 0 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n')) {
        return line[0 .. line.len - 1];
    }
    return line;
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
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn crlf(self: *BufferWriter) BuildError!void {
        try self.append("\r\n");
    }
};

test "parse latest star and selector forms" {
    const latest_star = try parse("CHATHISTORY LATEST #channel * 50");
    try std.testing.expectEqualStrings("#channel", latest_star.latest.target);
    try std.testing.expect(latest_star.latest.lower_bound == null);
    try std.testing.expectEqual(@as(u16, 50), latest_star.latest.limit);

    const latest_ts = try parse("CHATHISTORY LATEST #channel timestamp=2015-06-26T19:40:31.230Z 10");
    try std.testing.expectEqual(@as(u64, 1435347631230), latest_ts.latest.lower_bound.?.timestamp);

    const latest_msgid = try parse("CHATHISTORY LATEST #channel msgid=abcdef 10");
    try std.testing.expectEqualStrings("abcdef", latest_msgid.latest.lower_bound.?.msgid);
}

test "parse before after between and around" {
    const before = try parse("CHATHISTORY BEFORE #channel timestamp=2015-06-26T19:40:31.230Z 20");
    try std.testing.expectEqual(@as(u64, 1435347631230), before.before.selector.timestamp);

    const after = try parse("CHATHISTORY AFTER #channel msgid=1234 20");
    try std.testing.expectEqualStrings("1234", after.after.selector.msgid);

    const between = try parse(
        "CHATHISTORY BETWEEN #channel timestamp=2015-06-26T19:40:31.230Z timestamp=2015-06-26T19:43:53.410Z 20",
    );
    try std.testing.expectEqual(@as(u64, 1435347631230), between.between.start.timestamp);
    try std.testing.expectEqual(@as(u64, 1435347833410), between.between.end.timestamp);

    const around_one = try parse("CHATHISTORY AROUND #channel msgid=1234 11");
    try std.testing.expectEqualStrings("1234", around_one.around.center.msgid);
    try std.testing.expect(around_one.around.second == null);

    const around_two = try parse("CHATHISTORY AROUND #channel msgid=1234 timestamp=2015-06-26T19:43:53.410Z 11");
    try std.testing.expectEqualStrings("1234", around_two.around.center.msgid);
    try std.testing.expectEqual(@as(u64, 1435347833410), around_two.around.second.?.timestamp);
}

test "request target helper covers all chathistory subcommands" {
    const latest = try parse("CHATHISTORY LATEST #channel * 50");
    try std.testing.expectEqualStrings("#channel", requestTarget(latest));

    const before = try parse("CHATHISTORY BEFORE #before timestamp=2015-06-26T19:40:31.230Z 20");
    try std.testing.expectEqualStrings("#before", requestTarget(before));

    const after = try parse("CHATHISTORY AFTER #after msgid=1234 20");
    try std.testing.expectEqualStrings("#after", requestTarget(after));

    const between = try parse(
        "CHATHISTORY BETWEEN #between timestamp=2015-06-26T19:40:31.230Z timestamp=2015-06-26T19:43:53.410Z 20",
    );
    try std.testing.expectEqualStrings("#between", requestTarget(between));

    const around = try parse("CHATHISTORY AROUND #around msgid=1234 11");
    try std.testing.expectEqualStrings("#around", requestTarget(around));
}

test "channel history target policy denies non-member hidden channels" {
    try std.testing.expect(channelHistoryTargetAllowed(true, true, false));
    try std.testing.expect(channelHistoryTargetAllowed(true, false, true));
    try std.testing.expect(!channelHistoryTargetAllowed(true, false, false));
    try std.testing.expect(!channelHistoryTargetAllowed(false, false, true));
}

test "latest mode honors selector bound" {
    const latest_star = try parse("CHATHISTORY LATEST #channel * 50");
    try std.testing.expectEqual(LatestMode.unbounded, latestMode(latest_star.latest));

    const latest_ts = try parse("CHATHISTORY LATEST #channel timestamp=2015-06-26T19:40:31.230Z 10");
    try std.testing.expectEqual(LatestMode.before_bound, latestMode(latest_ts.latest));
}

test "between range direction preserves requested order" {
    try std.testing.expectEqual(RangeDirection.forward, rangeDirection(1, 2));
    try std.testing.expectEqual(RangeDirection.forward, rangeDirection(2, 2));
    try std.testing.expectEqual(RangeDirection.reverse, rangeDirection(3, 2));
}

test "targets batch type uses the draft token" {
    try std.testing.expectEqualStrings("draft/chathistory-targets", targets_batch_type);
}

test "reject malformed and oversized requests" {
    try std.testing.expectError(error.NEED_MORE_PARAMS, parse("CHATHISTORY BEFORE #channel"));
    try std.testing.expectError(error.INVALID_TARGET, parse("CHATHISTORY LATEST * * 50"));
    try std.testing.expectError(
        error.INVALID_PARAMS,
        parse("CHATHISTORY BEFORE #channel timestamp=2015-02-29T19:40:31.230Z 20"),
    );
    try std.testing.expectError(error.INVALID_PARAMS, parse("CHATHISTORY AFTER #channel msgid=bad;id 20"));
    try std.testing.expectError(error.INVALID_PARAMS, parse("CHATHISTORY LATEST #channel * 70000"));
    try std.testing.expectError(
        error.INVALID_PARAMS,
        parseWithOptions("CHATHISTORY LATEST #channel * 51", .{ .max_limit = 50 }),
    );
}

test "response builder writes exact chathistory batch bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 512);
    defer allocator.free(out);

    const line = try writeBatch(out, "sxtUfAeXBgNoD", "#channel", &.{
        .{
            .timestamp_ms = 1435347631230,
            .msgid = "abc123",
            .sender = "foo!foo@example.com",
            .text = "I like turtles.",
        },
    });

    try std.testing.expectEqualStrings(
        "BATCH +sxtUfAeXBgNoD chathistory #channel\r\n" ++
            "@batch=sxtUfAeXBgNoD;time=2015-06-26T19:40:31.230Z;msgid=abc123 :foo!foo@example.com PRIVMSG #channel :I like turtles.\r\n" ++
            "BATCH -sxtUfAeXBgNoD\r\n",
        line,
    );
}

test "response builder rejects bad output and fields" {
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, writeBatch(&tiny, "ref", "#channel", &.{}));

    var out: [256]u8 = undefined;
    try std.testing.expectError(error.INVALID_TARGET, writeBatch(&out, "ref", "*", &.{}));
    _ = try writeBatch(&out, "safe-ref-1", "#channel", &.{});
    for ([_][]const u8{ "", "bad ref", "bad;ref", "bad=ref", "bad/ref", "bad_ref", "bad.ref", "bad\x7fref" }) |bad_ref| {
        try std.testing.expectError(error.INVALID_PARAMS, writeBatch(&out, bad_ref, "#channel", &.{}));
    }
    var overlong_ref: [max_batch_ref_len + 1]u8 = undefined;
    @memset(&overlong_ref, 'a');
    try std.testing.expectError(error.INVALID_PARAMS, writeBatch(&out, &overlong_ref, "#channel", &.{}));
    try std.testing.expectError(error.INVALID_PARAMS, writeBatch(&out, "ref", "#channel", &.{
        .{ .timestamp_ms = 0, .msgid = "bad;id", .sender = "foo", .text = "hi" },
    }));
    try std.testing.expectError(error.INVALID_PARAMS, writeBatch(&out, "ref", "#channel", &.{
        .{ .timestamp_ms = 0, .msgid = "m1", .sender = "foo", .command = "PRIVMSG\r\nNOTICE", .text = "hi" },
    }));
    try std.testing.expectError(error.INVALID_PARAMS, writeBatch(&out, "ref", "#channel", &.{
        .{ .timestamp_ms = 0, .msgid = "m1", .sender = "foo", .command = "BAD COMMAND", .text = "hi" },
    }));
}
