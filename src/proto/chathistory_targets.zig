// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 `CHATHISTORY TARGETS <a> <b> <limit>` model.
//!
//! The TARGETS subcommand answers a different question than the message-replay
//! subcommands (LATEST/BEFORE/AFTER/AROUND/BETWEEN): instead of returning
//! messages from one conversation, it returns the *set of conversations*
//! (channels and DM correspondents) that saw activity in a time window, each
//! annotated with the timestamp of its most recent message. A reconnecting
//! client uses this to rebuild its conversation list before fetching message
//! history per target.
//!
//! This module is PURE: it owns a small target-name -> latest-timestamp index,
//! parses the textual request form, filters/sorts/truncates the index into a
//! caller-supplied output slice, and formats a single per-target reply line.
//! It deliberately reuses the `timestamp=<ISO8601>` token style and the
//! validation conventions of the sibling chathistory parser rather than
//! reimplementing message storage.
const std = @import("std");

/// Wall-clock milliseconds since the Unix epoch (UTC). Negative values predate
/// the epoch and are accepted so the model stays agnostic about clock origin.
pub const Millis = i64;

/// Bounds that keep attacker-controlled input from exhausting memory.
///
/// `max_targets` caps distinct conversations tracked by a `TargetIndex`.
/// `max_target_bytes` caps a single target name. `max_query_limit` caps how
/// many targets a single query may request.
pub const Params = struct {
    max_targets: usize = 4096,
    max_target_bytes: usize = 128,
    max_query_limit: usize = 1000,
};

/// One conversation target with the timestamp of its latest activity.
///
/// `name` borrows from the owning `TargetIndex` and stays valid until the index
/// is mutated (a `touch` that inserts, or `deinit`).
pub const Target = struct {
    name: []const u8,
    latest_ms: Millis,
};

/// Errors raised while parsing a `TARGETS <a> <b> <limit>` request.
pub const ParseError = error{
    /// Wrong token count, or a non-`TARGETS` request.
    InvalidParams,
    /// Too few tokens to form a complete request.
    NeedMoreParams,
    /// A timestamp token was malformed or not a `timestamp=`/`*` form.
    InvalidTimestamp,
    /// The limit token was empty, non-numeric, or zero.
    InvalidLimit,
    /// The requested limit exceeded `Params.max_query_limit`.
    LimitTooLarge,
};

/// Errors raised while inserting or updating an index entry.
pub const IndexError = std.mem.Allocator.Error || error{
    /// Target name was empty, oversized, or contained forbidden bytes.
    InvalidTarget,
    /// The index already holds `Params.max_targets` distinct targets.
    TargetLimitExceeded,
};

/// Errors raised while running a query into a caller-provided slice.
pub const QueryError = error{
    /// The output slice is smaller than the effective limit.
    OutputTooSmall,
    /// `from_ms` was greater than `to_ms`.
    InvalidRange,
};

/// Errors raised while formatting a per-target reply line.
pub const FormatError = error{
    /// The destination buffer could not hold the formatted line.
    OutputTooSmall,
};

/// A parsed `CHATHISTORY TARGETS` request.
///
/// `from_ms` and `to_ms` form an inclusive `[from, to]` window. The IRCv3 form
/// allows the two timestamp arguments in either order; `parse` normalizes them
/// so `from_ms <= to_ms` always holds. `limit` is the maximum number of targets
/// the client wants and is always non-zero after a successful parse.
pub const TargetsQuery = struct {
    from_ms: Millis,
    to_ms: Millis,
    limit: usize,

    /// Parse a full request line of the form
    /// `CHATHISTORY TARGETS <a> <b> <limit>`, where each of `<a>`/`<b>` is
    /// either `timestamp=<ISO8601>` or `*` (open bound), matching the sibling
    /// parser's selector token style.
    ///
    /// A trailing CR/LF is tolerated. Bounds are normalized so the returned
    /// `from_ms <= to_ms`. Uses default `Params`.
    pub fn parse(line: []const u8) ParseError!TargetsQuery {
        return parseWithParams(line, .{});
    }

    /// Like `parse` but enforces `params.max_query_limit`.
    pub fn parseWithParams(line: []const u8, params: Params) ParseError!TargetsQuery {
        const trimmed = trimLineEnd(line);
        var tokens: [6][]const u8 = undefined;
        var count: usize = 0;

        var it = std.mem.tokenizeScalar(u8, trimmed, ' ');
        while (it.next()) |token| {
            if (count == tokens.len) return error.InvalidParams;
            tokens[count] = token;
            count += 1;
        }

        if (count < 5) return error.NeedMoreParams;
        if (count != 5) return error.InvalidParams;
        if (!std.ascii.eqlIgnoreCase(tokens[0], "CHATHISTORY")) return error.InvalidParams;
        if (!std.ascii.eqlIgnoreCase(tokens[1], "TARGETS")) return error.InvalidParams;

        const a = try parseBound(tokens[2], .open_low);
        const b = try parseBound(tokens[3], .open_high);
        const limit = try parseLimit(tokens[4], params.max_query_limit);

        const from_ms = @min(a, b);
        const to_ms = @max(a, b);
        return .{ .from_ms = from_ms, .to_ms = to_ms, .limit = limit };
    }
};

/// Which open bound a bare `*` token represents.
const OpenSide = enum { open_low, open_high };

/// Parse a single bound token: `timestamp=<ISO8601>` or `*`.
fn parseBound(token: []const u8, side: OpenSide) ParseError!Millis {
    if (std.mem.eql(u8, token, "*")) {
        return switch (side) {
            .open_low => std.math.minInt(Millis),
            .open_high => std.math.maxInt(Millis),
        };
    }

    const prefix = "timestamp=";
    if (!std.mem.startsWith(u8, token, prefix)) return error.InvalidTimestamp;
    return parseTimestamp(token[prefix.len..]);
}

/// Parse the trailing limit token into a non-zero count bounded by `max`.
fn parseLimit(token: []const u8, max: usize) ParseError!usize {
    if (token.len == 0) return error.InvalidLimit;
    const limit = std.fmt.parseUnsigned(usize, token, 10) catch return error.InvalidLimit;
    if (limit == 0) return error.InvalidLimit;
    if (limit > max) return error.LimitTooLarge;
    return limit;
}

/// Parse an ISO 8601 UTC datetime `YYYY-MM-DDThh:mm:ss.sssZ` into epoch
/// milliseconds. The exact fixed-width form matches the sibling command parser.
pub fn parseTimestamp(value: []const u8) ParseError!Millis {
    const expected_len = "YYYY-MM-DDThh:mm:ss.sssZ".len;
    if (value.len != expected_len) return error.InvalidTimestamp;
    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or
        value[13] != ':' or value[16] != ':' or value[19] != '.' or value[23] != 'Z')
    {
        return error.InvalidTimestamp;
    }

    const year = try parseDigits(u16, value[0..4]);
    const month = try parseDigits(u8, value[5..7]);
    const day = try parseDigits(u8, value[8..10]);
    const hour = try parseDigits(u8, value[11..13]);
    const minute = try parseDigits(u8, value[14..16]);
    const second = try parseDigits(u8, value[17..19]);
    const millis = try parseDigits(u16, value[20..23]);

    if (year < 1970 or month < 1 or month > 12) return error.InvalidTimestamp;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTimestamp;
    const month_enum: std.time.epoch.Month = @fromBackingInt(@intCast(month));
    const days_in_month = std.time.epoch.getDaysInMonth(year, month_enum);
    if (day < 1 or day > days_in_month) return error.InvalidTimestamp;

    var days: i64 = 0;
    var cursor_year: u16 = 1970;
    while (cursor_year < year) : (cursor_year += 1) {
        days += std.time.epoch.getDaysInYear(cursor_year);
    }
    var cursor_month: u8 = 1;
    while (cursor_month < month) : (cursor_month += 1) {
        const cursor_enum: std.time.epoch.Month = @fromBackingInt(@intCast(cursor_month));
        days += std.time.epoch.getDaysInMonth(year, cursor_enum);
    }
    days += @as(i64, day) - 1;

    const seconds = (((days * 24 + hour) * 60 + minute) * 60) + second;
    return seconds * 1000 + millis;
}

/// Parse an exact-width run of ASCII digits into `T`, rejecting any non-digit.
fn parseDigits(comptime T: type, bytes: []const u8) ParseError!T {
    if (bytes.len == 0) return error.InvalidTimestamp;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidTimestamp;
    }
    return std.fmt.parseUnsigned(T, bytes, 10) catch error.InvalidTimestamp;
}

/// Strip a single trailing `\r\n`, `\r`, or `\n` from a request line.
fn trimLineEnd(line: []const u8) []const u8 {
    if (std.mem.endsWith(u8, line, "\r\n")) return line[0 .. line.len - 2];
    if (line.len != 0 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n')) {
        return line[0 .. line.len - 1];
    }
    return line;
}

/// Reject empty, oversized, or control/separator-bearing target names.
fn validTarget(name: []const u8, max_len: usize) bool {
    if (name.len == 0 or name.len > max_len) return false;
    if (std.mem.eql(u8, name, "*")) return false;
    for (name) |byte| {
        if (byte <= ' ' or byte == 0x7f or byte == ',') return false;
    }
    return true;
}

/// Owned-key, case-insensitive index of conversation targets to their latest
/// activity timestamp.
///
/// Keys are normalized to lowercase and owned by the index, so `touch("#Zig")`
/// and `touch("#zig")` address the same entry. `query` borrows the stored keys;
/// returned `Target.name` slices stay valid until the next inserting `touch` or
/// `deinit`.
pub const TargetIndex = struct {
    allocator: std.mem.Allocator,
    params: Params,
    map: std.StringHashMapUnmanaged(Millis),

    /// Create an empty index using `allocator` for owned keys and the map.
    pub fn init(allocator: std.mem.Allocator, params: Params) TargetIndex {
        return .{
            .allocator = allocator,
            .params = params,
            .map = .empty,
        };
    }

    /// Free every owned key and the backing map.
    pub fn deinit(self: *TargetIndex) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit(self.allocator);
    }

    /// Number of distinct targets currently tracked.
    pub fn count(self: *const TargetIndex) usize {
        return self.map.count();
    }

    /// Record activity for `target` at `ts`.
    ///
    /// If the target is unseen it is inserted (subject to `max_targets`). If it
    /// already exists, its timestamp advances only when `ts` is strictly newer,
    /// so out-of-order replays never roll the latest-activity marker backward.
    /// Target keys are matched case-insensitively.
    pub fn touch(self: *TargetIndex, target: []const u8, ts: Millis) IndexError!void {
        if (!validTarget(target, self.params.max_target_bytes)) return error.InvalidTarget;

        var lower_buf: [256]u8 = undefined;
        const key = lowerInto(&lower_buf, target, self.params.max_target_bytes) orelse
            return error.InvalidTarget;

        if (self.map.getPtr(key)) |existing| {
            if (ts > existing.*) existing.* = ts;
            return;
        }

        if (self.map.count() >= self.params.max_targets) return error.TargetLimitExceeded;

        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.map.put(self.allocator, owned, ts);
    }

    /// Look up the latest-activity timestamp for `target`, case-insensitively.
    pub fn latestFor(self: *const TargetIndex, target: []const u8) ?Millis {
        var lower_buf: [256]u8 = undefined;
        const key = lowerInto(&lower_buf, target, self.params.max_target_bytes) orelse return null;
        return self.map.get(key);
    }

    /// Collect targets whose latest activity falls within `[from_ms, to_ms]`,
    /// sorted by `latest_ms` ascending (ties broken by name), truncated to
    /// `limit`, into `out`.
    ///
    /// `out` must hold at least `min(limit, max_query_limit)` entries. Returned
    /// `Target.name` slices borrow the index's owned keys.
    pub fn query(
        self: *const TargetIndex,
        q: TargetsQuery,
        out: []Target,
    ) QueryError![]const Target {
        if (q.from_ms > q.to_ms) return error.InvalidRange;

        const effective_limit = @min(q.limit, self.params.max_query_limit);
        if (effective_limit == 0) return out[0..0];
        if (effective_limit > out.len) return error.OutputTooSmall;

        var written: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const latest = entry.value_ptr.*;
            if (latest < q.from_ms or latest > q.to_ms) continue;
            const candidate = Target{ .name = entry.key_ptr.*, .latest_ms = latest };
            insertSorted(out[0..written], candidate, effective_limit, &written);
        }

        return out[0..written];
    }
};

/// Insert `candidate` into a bounded, ascending-sorted prefix.
///
/// `slice` is the already-filled, sorted region; `len` tracks its length and is
/// updated in place. The region never grows past `cap`; when full, a candidate
/// only displaces the current maximum if it sorts earlier, preserving the
/// `cap` smallest entries by `(latest_ms, name)`.
fn insertSorted(slice: []Target, candidate: Target, cap: usize, len: *usize) void {
    const buf_ptr = slice.ptr;
    if (len.* < cap) {
        var i: usize = len.*;
        while (i > 0 and targetLess(candidate, buf_ptr[i - 1])) : (i -= 1) {
            buf_ptr[i] = buf_ptr[i - 1];
        }
        buf_ptr[i] = candidate;
        len.* += 1;
        return;
    }

    // Full: only keep the candidate if it precedes the current maximum.
    const last = buf_ptr[cap - 1];
    if (!targetLess(candidate, last)) return;

    var i: usize = cap - 1;
    while (i > 0 and targetLess(candidate, buf_ptr[i - 1])) : (i -= 1) {
        buf_ptr[i] = buf_ptr[i - 1];
    }
    buf_ptr[i] = candidate;
}

/// Ascending order on `latest_ms`, with target name as a stable tiebreaker.
fn targetLess(a: Target, b: Target) bool {
    if (a.latest_ms != b.latest_ms) return a.latest_ms < b.latest_ms;
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Lowercase `value` into `buf`, returning the written slice, or `null` when it
/// exceeds `max_len` or the buffer.
fn lowerInto(buf: []u8, value: []const u8, max_len: usize) ?[]const u8 {
    if (value.len > max_len or value.len > buf.len) return null;
    for (value, 0..) |ch, i| buf[i] = std.ascii.toLower(ch);
    return buf[0..value.len];
}

/// Format one per-target reply line into `out`, returning the written slice.
///
/// The line carries the target name and its latest activity timestamp as an
/// ISO 8601 `server-time` value, matching the format used by message replies:
/// `<target> timestamp=<ISO8601>`.
pub fn formatTargetLine(out: []u8, target: Target) FormatError![]const u8 {
    var ts_buf: [24]u8 = undefined;
    const ts = formatTimestamp(target.latest_ms, &ts_buf) catch return error.OutputTooSmall;

    return std.fmt.bufPrint(out, "{s} timestamp={s}", .{ target.name, ts }) catch
        error.OutputTooSmall;
}

/// Format epoch milliseconds as ISO 8601 `YYYY-MM-DDThh:mm:ss.sssZ` into a
/// 24-byte buffer. Negative (pre-epoch) values are not representable.
pub fn formatTimestamp(epoch_ms: Millis, out: *[24]u8) FormatError![]const u8 {
    if (epoch_ms < 0) return error.OutputTooSmall;
    const total_ms: u64 = @intCast(epoch_ms);
    const seconds = total_ms / 1000;
    const millis: u16 = @intCast(total_ms % 1000);
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

test "touch inserts new targets and advances only on newer timestamps" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();

    // Act
    try index.touch("#zig", 1000);
    try index.touch("#zig", 500); // older, must not regress
    try index.touch("#zig", 2000); // newer, must advance

    // Assert
    try std.testing.expectEqual(@as(usize, 1), index.count());
    try std.testing.expectEqual(@as(Millis, 2000), index.latestFor("#zig").?);
}

test "touch treats target keys case-insensitively" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();

    // Act
    try index.touch("#Zig", 1000);
    try index.touch("#zIg", 3000);

    // Assert
    try std.testing.expectEqual(@as(usize, 1), index.count());
    try std.testing.expectEqual(@as(Millis, 3000), index.latestFor("#ZIG").?);
}

test "touch rejects invalid targets and enforces the target cap" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{ .max_targets = 2 });
    defer index.deinit();

    // Act / Assert
    try std.testing.expectError(error.InvalidTarget, index.touch("", 1));
    try std.testing.expectError(error.InvalidTarget, index.touch("bad,name", 1));
    try std.testing.expectError(error.InvalidTarget, index.touch("*", 1));

    try index.touch("#a", 1);
    try index.touch("#b", 2);
    try std.testing.expectError(error.TargetLimitExceeded, index.touch("#c", 3));
    // Existing targets still update past the cap.
    try index.touch("#a", 100);
    try std.testing.expectEqual(@as(Millis, 100), index.latestFor("#a").?);
}

test "query filters by window and sorts ascending by latest" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();
    try index.touch("#early", 1000);
    try index.touch("#mid", 2000);
    try index.touch("#late", 3000);
    try index.touch("#way-late", 9000);

    // Act
    var out: [8]Target = undefined;
    const q = TargetsQuery{ .from_ms = 1500, .to_ms = 3500, .limit = 8 };
    const result = try index.query(q, &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("#mid", result[0].name);
    try std.testing.expectEqual(@as(Millis, 2000), result[0].latest_ms);
    try std.testing.expectEqualStrings("#late", result[1].name);
    try std.testing.expectEqual(@as(Millis, 3000), result[1].latest_ms);
}

test "query truncates to the limit keeping the earliest targets" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();
    try index.touch("#t1", 1000);
    try index.touch("#t2", 2000);
    try index.touch("#t3", 3000);
    try index.touch("#t4", 4000);

    // Act
    var out: [2]Target = undefined;
    const q = TargetsQuery{ .from_ms = 0, .to_ms = 10000, .limit = 2 };
    const result = try index.query(q, &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("#t1", result[0].name);
    try std.testing.expectEqualStrings("#t2", result[1].name);
}

test "query rejects inverted range and too-small output" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();
    try index.touch("#a", 1000);

    // Act / Assert
    var out: [4]Target = undefined;
    try std.testing.expectError(
        error.InvalidRange,
        index.query(.{ .from_ms = 5000, .to_ms = 1000, .limit = 4 }, &out),
    );

    var tiny: [1]Target = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        index.query(.{ .from_ms = 0, .to_ms = 9000, .limit = 4 }, &tiny),
    );
}

test "query orders ties by name" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{});
    defer index.deinit();
    try index.touch("#bravo", 2000);
    try index.touch("#alpha", 2000);
    try index.touch("#charlie", 2000);

    // Act
    var out: [8]Target = undefined;
    const result = try index.query(.{ .from_ms = 0, .to_ms = 9000, .limit = 8 }, &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("#alpha", result[0].name);
    try std.testing.expectEqualStrings("#bravo", result[1].name);
    try std.testing.expectEqualStrings("#charlie", result[2].name);
}

test "parse accepts timestamp bounds and a limit" {
    // Arrange / Act
    const q = try TargetsQuery.parse(
        "CHATHISTORY TARGETS timestamp=2015-06-26T19:40:31.230Z timestamp=2015-06-26T19:43:53.410Z 50",
    );

    // Assert
    try std.testing.expectEqual(@as(Millis, 1435347631230), q.from_ms);
    try std.testing.expectEqual(@as(Millis, 1435347833410), q.to_ms);
    try std.testing.expectEqual(@as(usize, 50), q.limit);
}

test "parse normalizes swapped bounds" {
    // Arrange / Act
    const q = try TargetsQuery.parse(
        "CHATHISTORY TARGETS timestamp=2015-06-26T19:43:53.410Z timestamp=2015-06-26T19:40:31.230Z 10",
    );

    // Assert
    try std.testing.expectEqual(@as(Millis, 1435347631230), q.from_ms);
    try std.testing.expectEqual(@as(Millis, 1435347833410), q.to_ms);
}

test "parse supports open star bounds" {
    // Arrange / Act
    const both_open = try TargetsQuery.parse("CHATHISTORY TARGETS * * 100");
    const low_open = try TargetsQuery.parse("CHATHISTORY TARGETS * timestamp=2015-06-26T19:40:31.230Z 5");

    // Assert
    try std.testing.expectEqual(std.math.minInt(Millis), both_open.from_ms);
    try std.testing.expectEqual(std.math.maxInt(Millis), both_open.to_ms);
    try std.testing.expectEqual(std.math.minInt(Millis), low_open.from_ms);
    try std.testing.expectEqual(@as(Millis, 1435347631230), low_open.to_ms);
}

test "parse rejects malformed requests" {
    try std.testing.expectError(error.NeedMoreParams, TargetsQuery.parse("CHATHISTORY TARGETS * *"));
    try std.testing.expectError(error.InvalidParams, TargetsQuery.parse("CHATHISTORY LATEST * * 5"));
    try std.testing.expectError(
        error.InvalidTimestamp,
        TargetsQuery.parse("CHATHISTORY TARGETS bogus * 5"),
    );
    try std.testing.expectError(
        error.InvalidTimestamp,
        TargetsQuery.parse("CHATHISTORY TARGETS timestamp=2015-02-29T00:00:00.000Z * 5"),
    );
    try std.testing.expectError(error.InvalidLimit, TargetsQuery.parse("CHATHISTORY TARGETS * * 0"));
    try std.testing.expectError(error.InvalidLimit, TargetsQuery.parse("CHATHISTORY TARGETS * * x"));
    try std.testing.expectError(
        error.LimitTooLarge,
        TargetsQuery.parseWithParams("CHATHISTORY TARGETS * * 9999", .{ .max_query_limit = 100 }),
    );
}

test "parse tolerates trailing crlf" {
    // Arrange / Act
    const q = try TargetsQuery.parse("CHATHISTORY TARGETS * * 7\r\n");

    // Assert
    try std.testing.expectEqual(@as(usize, 7), q.limit);
}

test "formatTargetLine renders name and iso timestamp" {
    // Arrange
    var buf: [64]u8 = undefined;
    const target = Target{ .name = "#zig", .latest_ms = 1435347631230 };

    // Act
    const line = try formatTargetLine(&buf, target);

    // Assert
    try std.testing.expectEqualStrings("#zig timestamp=2015-06-26T19:40:31.230Z", line);
}

test "formatTargetLine reports too-small buffers" {
    // Arrange
    var tiny: [4]u8 = undefined;
    const target = Target{ .name = "#zig", .latest_ms = 1435347631230 };

    // Act / Assert
    try std.testing.expectError(error.OutputTooSmall, formatTargetLine(&tiny, target));
}

test "query caps at max_query_limit even when request asks for more" {
    // Arrange
    var index = TargetIndex.init(std.testing.allocator, .{ .max_query_limit = 2 });
    defer index.deinit();
    try index.touch("#a", 1000);
    try index.touch("#b", 2000);
    try index.touch("#c", 3000);

    // Act
    var out: [2]Target = undefined;
    const result = try index.query(.{ .from_ms = 0, .to_ms = 9000, .limit = 1000 }, &out);

    // Assert: capped to 2, keeping the earliest two.
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("#a", result[0].name);
    try std.testing.expectEqualStrings("#b", result[1].name);
}
