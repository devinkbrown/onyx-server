// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure operator session/connection list view.
//!
//! Command handlers pass borrowed connection facts in, parse an operator query
//! string, build a bounded sorted view into caller-owned storage, and render
//! real IRC numeric replies. This file intentionally has no daemon imports and
//! never models services as fake users.
const std = @import("std");

pub const max_sort_keys = 4;
pub const max_filter_bytes = 512;
pub const max_pattern_bytes = 128;
pub const max_line_bytes = 512;

pub const Error = error{
    EmptyValue,
    FilterTooLong,
    InvalidNumber,
    InvalidParam,
    OutputTooSmall,
    PatternTooLong,
    TooManyMatches,
    TooManySortKeys,
    UnknownSortKey,
    UnknownToken,
};

pub const TraceNumeric = enum(u16) {
    RPL_TRACEOPERATOR = 204,
    RPL_TRACEUSER = 205,
    RPL_ENDOFTRACE = 262,

    pub fn code(self: TraceNumeric) u16 {
        return @backingInt(self);
    }

    pub fn format(self: TraceNumeric, out: []u8) Error![]const u8 {
        if (out.len < 3) return error.OutputTooSmall;
        const value: u16 = @backingInt(self);
        out[0] = '0' + @as(u8, @intCast((value / 100) % 10));
        out[1] = '0' + @as(u8, @intCast((value / 10) % 10));
        out[2] = '0' + @as(u8, @intCast(value % 10));
        return out[0..3];
    }
};

pub const ConnectionFact = struct {
    nick: []const u8,
    account: ?[]const u8 = null,
    ip: []const u8,
    connected_ms: u64,
    is_oper: bool = false,
    is_tls: bool = false,
};

pub const BoolFilter = enum {
    any,
    yes,
    no,

    fn matches(self: BoolFilter, value: bool) bool {
        return switch (self) {
            .any => true,
            .yes => value,
            .no => !value,
        };
    }
};

pub const AccountFilter = union(enum) {
    any,
    logged_in,
    none,
    glob: []const u8,

    fn matches(self: AccountFilter, account: ?[]const u8) bool {
        return switch (self) {
            .any => true,
            .logged_in => account != null,
            .none => account == null,
            .glob => |pattern| if (account) |value| globMatch(pattern, value) else false,
        };
    }
};

pub const Filter = struct {
    nick: ?[]const u8 = null,
    account: AccountFilter = .any,
    ip: ?[]const u8 = null,
    oper: BoolFilter = .any,
    tls: BoolFilter = .any,
    min_connected_ms: ?u64 = null,
    max_connected_ms: ?u64 = null,
    limit: ?usize = null,

    pub fn matches(self: Filter, fact: ConnectionFact) bool {
        if (self.nick) |pattern| {
            if (!globMatch(pattern, fact.nick)) return false;
        }
        if (!self.account.matches(fact.account)) return false;
        if (self.ip) |pattern| {
            if (!globMatch(pattern, fact.ip)) return false;
        }
        if (!self.oper.matches(fact.is_oper)) return false;
        if (!self.tls.matches(fact.is_tls)) return false;
        if (self.min_connected_ms) |min| {
            if (fact.connected_ms < min) return false;
        }
        if (self.max_connected_ms) |max| {
            if (fact.connected_ms > max) return false;
        }
        return true;
    }
};

pub const SortKey = enum {
    nick,
    account,
    ip,
    connected_ms,
    oper,
    tls,
};

pub const SortDirection = enum {
    asc,
    desc,
};

pub const SortSpec = struct {
    key: SortKey = .nick,
    direction: SortDirection = .asc,
};

pub const Query = struct {
    filter: Filter = .{},
    sort: [max_sort_keys]SortSpec = @splat(.{}),
    sort_len: usize = 1,

    pub fn sortSpecs(self: *const Query) []const SortSpec {
        return self.sort[0..self.sort_len];
    }
};

pub const View = struct {
    rows: []const ConnectionFact,
};

pub fn parseFilter(raw: []const u8) Error!Query {
    if (raw.len > max_filter_bytes) return error.FilterTooLong;

    var query = Query{};
    var tokens = std.mem.tokenizeAny(u8, raw, " \t\r\n");
    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, "")) continue;

        if (std.ascii.eqlIgnoreCase(token, "oper")) {
            query.filter.oper = .yes;
        } else if (std.ascii.eqlIgnoreCase(token, "user")) {
            query.filter.oper = .no;
        } else if (std.ascii.eqlIgnoreCase(token, "tls")) {
            query.filter.tls = .yes;
        } else if (std.ascii.eqlIgnoreCase(token, "clear") or std.ascii.eqlIgnoreCase(token, "plain")) {
            query.filter.tls = .no;
        } else if (splitKeyValue(token)) |kv| {
            try applyKeyValue(&query, kv.key, kv.value);
        } else {
            try validatePattern(token);
            query.filter.nick = token;
        }
    }
    return query;
}

pub fn buildView(facts: []const ConnectionFact, query: Query, out: []ConnectionFact) Error!View {
    var count: usize = 0;
    const limit = query.filter.limit orelse out.len;
    const bounded_by_limit = query.filter.limit != null and limit <= out.len;
    const capacity = @min(limit, out.len);

    for (facts) |fact| {
        if (!query.filter.matches(fact)) continue;
        if (count < capacity) {
            insertSorted(out[0..capacity], &count, fact, query.sortSpecs());
        } else if (bounded_by_limit) {
            if (capacity > 0 and compareRows(fact, out[capacity - 1], query.sortSpecs()) < 0) {
                count -= 1;
                insertSorted(out[0..capacity], &count, fact, query.sortSpecs());
            }
        } else {
            return error.TooManyMatches;
        }
    }

    return .{ .rows = out[0..count] };
}

pub const Formatter = struct {
    server_name: []const u8,
    requester_nick: []const u8,
    class: []const u8 = "sessions",

    pub fn init(server_name: []const u8, requester_nick: []const u8) Formatter {
        return .{ .server_name = server_name, .requester_nick = requester_nick };
    }

    /// Render one TRACE-style client line:
    /// `:server 20x opernick <Oper|User> sessions nick (ip) seconds flags account`
    pub fn traceLine(self: Formatter, out: []u8, fact: ConnectionFact) Error![]const u8 {
        var b = LineBuilder.init(out);
        try b.numericPrefix(if (fact.is_oper) .RPL_TRACEOPERATOR else .RPL_TRACEUSER, self.server_name, self.requester_nick);
        try b.appendByte(' ');
        try b.appendParam(if (fact.is_oper) "Oper" else "User");
        try b.spaceParam(self.class);
        try b.spaceParam(fact.nick);
        try b.appendBytes(" (");
        try b.appendParam(fact.ip);
        try b.appendBytes(") ");
        try b.appendUnsigned(fact.connected_ms / 1000);
        try b.appendBytes(" 0 ");
        try b.appendParam(if (fact.is_tls) "tls" else "clear");
        try b.appendByte(' ');
        try b.appendParam(fact.account orelse "*");
        try b.crlf();
        return b.slice();
    }

    pub fn endOfTrace(self: Formatter, out: []u8, target: []const u8) Error![]const u8 {
        var b = LineBuilder.init(out);
        try b.numericPrefix(.RPL_ENDOFTRACE, self.server_name, self.requester_nick);
        try b.spaceParam(if (target.len == 0) "SESSION" else target);
        try b.appendBytes(" :End of SESSION view");
        try b.crlf();
        return b.slice();
    }
};

const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

fn splitKeyValue(token: []const u8) ?KeyValue {
    const eq = std.mem.indexOfScalar(u8, token, '=') orelse return null;
    return .{ .key = token[0..eq], .value = token[eq + 1 ..] };
}

fn applyKeyValue(query: *Query, key: []const u8, value: []const u8) Error!void {
    if (value.len == 0) return error.EmptyValue;

    if (std.ascii.eqlIgnoreCase(key, "nick")) {
        try validatePattern(value);
        query.filter.nick = value;
    } else if (std.ascii.eqlIgnoreCase(key, "account") or std.ascii.eqlIgnoreCase(key, "acct")) {
        query.filter.account = try parseAccountFilter(value);
    } else if (std.ascii.eqlIgnoreCase(key, "ip") or std.ascii.eqlIgnoreCase(key, "host")) {
        try validatePattern(value);
        query.filter.ip = value;
    } else if (std.ascii.eqlIgnoreCase(key, "oper")) {
        query.filter.oper = try parseBool(value);
    } else if (std.ascii.eqlIgnoreCase(key, "tls")) {
        query.filter.tls = try parseBool(value);
    } else if (std.ascii.eqlIgnoreCase(key, "min-ms") or std.ascii.eqlIgnoreCase(key, "min_connected_ms")) {
        query.filter.min_connected_ms = try parseU64(value);
    } else if (std.ascii.eqlIgnoreCase(key, "max-ms") or std.ascii.eqlIgnoreCase(key, "max_connected_ms")) {
        query.filter.max_connected_ms = try parseU64(value);
    } else if (std.ascii.eqlIgnoreCase(key, "limit")) {
        const parsed = try parseU64(value);
        query.filter.limit = std.math.cast(usize, parsed) orelse return error.InvalidNumber;
    } else if (std.ascii.eqlIgnoreCase(key, "sort")) {
        try parseSortList(query, value);
    } else {
        return error.UnknownToken;
    }
}

fn parseAccountFilter(value: []const u8) Error!AccountFilter {
    if (std.ascii.eqlIgnoreCase(value, "any")) return .any;
    if (std.mem.eql(u8, value, "*")) return .logged_in;
    if (std.ascii.eqlIgnoreCase(value, "none") or std.mem.eql(u8, value, "-") or std.mem.eql(u8, value, "0")) return .none;
    try validatePattern(value);
    return .{ .glob = value };
}

fn parseBool(value: []const u8) Error!BoolFilter {
    if (std.ascii.eqlIgnoreCase(value, "any")) return .any;
    if (std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "on"))
    {
        return .yes;
    }
    if (std.ascii.eqlIgnoreCase(value, "no") or
        std.ascii.eqlIgnoreCase(value, "false") or
        std.mem.eql(u8, value, "0") or
        std.ascii.eqlIgnoreCase(value, "off"))
    {
        return .no;
    }
    return error.UnknownToken;
}

fn parseSortList(query: *Query, value: []const u8) Error!void {
    var len: usize = 0;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw_part| {
        if (raw_part.len == 0) return error.EmptyValue;
        if (len >= max_sort_keys) return error.TooManySortKeys;

        var part = raw_part;
        var direction: SortDirection = .asc;
        if (part[0] == '-') {
            direction = .desc;
            part = part[1..];
        } else if (part[0] == '+') {
            part = part[1..];
        }
        if (part.len == 0) return error.EmptyValue;

        query.sort[len] = .{ .key = try parseSortKey(part), .direction = direction };
        len += 1;
    }
    query.sort_len = len;
}

fn parseSortKey(value: []const u8) Error!SortKey {
    if (std.ascii.eqlIgnoreCase(value, "nick")) return .nick;
    if (std.ascii.eqlIgnoreCase(value, "account") or std.ascii.eqlIgnoreCase(value, "acct")) return .account;
    if (std.ascii.eqlIgnoreCase(value, "ip") or std.ascii.eqlIgnoreCase(value, "host")) return .ip;
    if (std.ascii.eqlIgnoreCase(value, "connected") or std.ascii.eqlIgnoreCase(value, "connected_ms")) return .connected_ms;
    if (std.ascii.eqlIgnoreCase(value, "oper")) return .oper;
    if (std.ascii.eqlIgnoreCase(value, "tls")) return .tls;
    return error.UnknownSortKey;
}

fn parseU64(value: []const u8) Error!u64 {
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidNumber;
}

fn validatePattern(value: []const u8) Error!void {
    if (value.len == 0) return error.EmptyValue;
    if (value.len > max_pattern_bytes) return error.PatternTooLong;
    try validateParam(value);
}

pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_t: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |star_pos| {
            p = star_pos + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

pub fn sortRows(rows: []ConnectionFact, specs: []const SortSpec) void {
    var i: usize = 1;
    while (i < rows.len) : (i += 1) {
        const item = rows[i];
        var j = i;
        while (j > 0 and compareRows(item, rows[j - 1], specs) < 0) : (j -= 1) {
            rows[j] = rows[j - 1];
        }
        rows[j] = item;
    }
}

fn insertSorted(rows: []ConnectionFact, count: *usize, item: ConnectionFact, specs: []const SortSpec) void {
    var j = count.*;
    while (j > 0 and compareRows(item, rows[j - 1], specs) < 0) : (j -= 1) {
        rows[j] = rows[j - 1];
    }
    rows[j] = item;
    count.* += 1;
}

pub fn compareRows(a: ConnectionFact, b: ConnectionFact, specs: []const SortSpec) i8 {
    for (specs) |spec| {
        var cmp = compareByKey(a, b, spec.key);
        if (spec.direction == .desc) cmp = -cmp;
        if (cmp != 0) return cmp;
    }
    return compareAscii(a.nick, b.nick);
}

fn compareByKey(a: ConnectionFact, b: ConnectionFact, key: SortKey) i8 {
    return switch (key) {
        .nick => compareAscii(a.nick, b.nick),
        .account => compareAscii(a.account orelse "", b.account orelse ""),
        .ip => compareAscii(a.ip, b.ip),
        .connected_ms => compareU64(a.connected_ms, b.connected_ms),
        .oper => compareBool(a.is_oper, b.is_oper),
        .tls => compareBool(a.is_tls, b.is_tls),
    };
}

fn compareAscii(a: []const u8, b: []const u8) i8 {
    var i: usize = 0;
    while (i < a.len and i < b.len) : (i += 1) {
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[i]);
        if (ca < cb) return -1;
        if (ca > cb) return 1;
    }
    return compareUsize(a.len, b.len);
}

fn compareU64(a: u64, b: u64) i8 {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

fn compareUsize(a: usize, b: usize) i8 {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

fn compareBool(a: bool, b: bool) i8 {
    return compareU64(if (a) 1 else 0, if (b) 1 else 0);
}

fn validateParam(param: []const u8) Error!void {
    if (param.len == 0) return error.InvalidParam;
    for (param) |ch| {
        switch (ch) {
            0, ' ', '\t', '\r', '\n' => return error.InvalidParam,
            else => {},
        }
    }
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) LineBuilder {
        return .{ .out = out };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: TraceNumeric, server_name: []const u8, requester_nick: []const u8) Error!void {
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');
        try self.appendCode(code.code());
        try self.appendByte(' ');
        try self.appendParam(requester_nick);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) Error!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) Error!void {
        try validateParam(param);
        try self.appendBytes(param);
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) Error!void {
        if (self.len + bytes.len > self.out.len or self.len + bytes.len > max_line_bytes) return error.OutputTooSmall;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) Error!void {
        if (self.len + 1 > self.out.len or self.len + 1 > max_line_bytes) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }

    fn appendCode(self: *LineBuilder, value: u16) Error!void {
        if (value > 999) return error.InvalidParam;
        try self.appendByte('0' + @as(u8, @intCast((value / 100) % 10)));
        try self.appendByte('0' + @as(u8, @intCast((value / 10) % 10)));
        try self.appendByte('0' + @as(u8, @intCast(value % 10)));
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) Error!void {
        var buf: [20]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
        try self.appendBytes(text);
    }

    fn crlf(self: *LineBuilder) Error!void {
        try self.appendBytes("\r\n");
    }
};

const testing = std.testing;

fn sampleFacts() []const ConnectionFact {
    return &.{
        .{ .nick = "RootOper", .account = "root", .ip = "198.51.100.7", .connected_ms = 90_000, .is_oper = true, .is_tls = true },
        .{ .nick = "alice", .account = "alice", .ip = "203.0.113.8", .connected_ms = 30_000, .is_tls = true },
        .{ .nick = "Bob", .account = null, .ip = "203.0.113.9", .connected_ms = 60_000 },
        .{ .nick = "carol", .account = "staff-carol", .ip = "2001:db8::1", .connected_ms = 15_000, .is_oper = true },
    };
}

test "parse empty query keeps safe defaults" {
    const q = try parseFilter("");
    try testing.expectEqual(@as(usize, 1), q.sort_len);
    try testing.expectEqual(SortKey.nick, q.sort[0].key);
    try testing.expect(q.filter.matches(sampleFacts()[0]));
}

test "parse bare token as nick glob" {
    const q = try parseFilter("a*");
    try testing.expect(q.filter.matches(sampleFacts()[1]));
    try testing.expect(!q.filter.matches(sampleFacts()[2]));
}

test "parse key value filters" {
    const q = try parseFilter("nick=*o* account=staff-* ip=2001:* oper tls=false");
    try testing.expect(q.filter.matches(sampleFacts()[3]));
    try testing.expect(!q.filter.matches(sampleFacts()[0]));
}

test "account star means logged in and dash means no account" {
    const logged_in = try parseFilter("account=*");
    try testing.expect(logged_in.filter.matches(sampleFacts()[0]));
    try testing.expect(!logged_in.filter.matches(sampleFacts()[2]));

    const none = try parseFilter("account=-");
    try testing.expect(none.filter.matches(sampleFacts()[2]));
    try testing.expect(!none.filter.matches(sampleFacts()[1]));
}

test "parse booleans and millisecond range" {
    const q = try parseFilter("oper=false tls=1 min-ms=20000 max-ms=70000");
    try testing.expect(q.filter.matches(sampleFacts()[1]));
    try testing.expect(!q.filter.matches(sampleFacts()[2]));
    try testing.expect(!q.filter.matches(sampleFacts()[0]));
    try testing.expect(!q.filter.matches(sampleFacts()[3]));
}

test "parse sort list with directions" {
    const q = try parseFilter("sort=-connected,nick,+account");
    try testing.expectEqual(@as(usize, 3), q.sort_len);
    try testing.expectEqual(SortKey.connected_ms, q.sort[0].key);
    try testing.expectEqual(SortDirection.desc, q.sort[0].direction);
    try testing.expectEqual(SortKey.nick, q.sort[1].key);
    try testing.expectEqual(SortDirection.asc, q.sort[1].direction);
}

test "parse rejects unknown and unbounded input" {
    try testing.expectError(error.UnknownToken, parseFilter("wat=yes"));
    try testing.expectError(error.UnknownSortKey, parseFilter("sort=nope"));
    try testing.expectError(error.InvalidNumber, parseFilter("limit=not-a-number"));

    const long = &@as([(max_filter_bytes + 1)]u8, @splat('x'));
    try testing.expectError(error.FilterTooLong, parseFilter(long));
}

test "glob matching is case insensitive and iterative" {
    try testing.expect(globMatch("r??t*", "RootOper"));
    try testing.expect(globMatch("*DB8::*", "2001:db8::1"));
    try testing.expect(!globMatch("a?c", "abbbc"));
}

test "build view filters and sorts by connected descending" {
    const q = try parseFilter("sort=-connected");
    var out: [4]ConnectionFact = undefined;
    const view = try buildView(sampleFacts(), q, &out);

    try testing.expectEqual(@as(usize, 4), view.rows.len);
    try testing.expectEqualStrings("RootOper", view.rows[0].nick);
    try testing.expectEqualStrings("Bob", view.rows[1].nick);
    try testing.expectEqualStrings("alice", view.rows[2].nick);
    try testing.expectEqualStrings("carol", view.rows[3].nick);
}

test "build view applies limit as sorted top-n" {
    const q = try parseFilter("limit=2 sort=nick");
    var out: [4]ConnectionFact = undefined;
    const view = try buildView(sampleFacts(), q, &out);

    try testing.expectEqual(@as(usize, 2), view.rows.len);
    try testing.expectEqualStrings("alice", view.rows[0].nick);
    try testing.expectEqualStrings("Bob", view.rows[1].nick);
}

test "build view reports too many matches for small caller buffer" {
    const q = try parseFilter("oper=false");
    var out: [1]ConnectionFact = undefined;
    try testing.expectError(error.TooManyMatches, buildView(sampleFacts(), q, &out));
}

test "multi-key sort is stable with fallback nick order" {
    const facts = [_]ConnectionFact{
        .{ .nick = "zed", .account = "same", .ip = "10.0.0.3", .connected_ms = 5 },
        .{ .nick = "Ann", .account = "same", .ip = "10.0.0.1", .connected_ms = 5 },
        .{ .nick = "mid", .account = "other", .ip = "10.0.0.2", .connected_ms = 5 },
    };
    const q = try parseFilter("sort=account");
    var out: [3]ConnectionFact = undefined;
    const view = try buildView(&facts, q, &out);

    try testing.expectEqualStrings("mid", view.rows[0].nick);
    try testing.expectEqualStrings("Ann", view.rows[1].nick);
    try testing.expectEqualStrings("zed", view.rows[2].nick);
}

test "numeric formatting uses real TRACE reply numbers" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualStrings("204", try TraceNumeric.RPL_TRACEOPERATOR.format(&buf));
    try testing.expectEqualStrings("205", try TraceNumeric.RPL_TRACEUSER.format(&buf));
    try testing.expectEqualStrings("262", try TraceNumeric.RPL_ENDOFTRACE.format(&buf));
}

test "formatter renders operator and user trace-style lines" {
    const fmt = Formatter.init("irc.example.test", "RootOper");
    var buf: [256]u8 = undefined;

    try testing.expectEqualStrings(
        ":irc.example.test 204 RootOper Oper sessions RootOper (198.51.100.7) 90 0 tls root\r\n",
        try fmt.traceLine(&buf, sampleFacts()[0]),
    );
    try testing.expectEqualStrings(
        ":irc.example.test 205 RootOper User sessions Bob (203.0.113.9) 60 0 clear *\r\n",
        try fmt.traceLine(&buf, sampleFacts()[2]),
    );
}

test "formatter renders SESSION terminator as numeric" {
    const fmt = Formatter.init("irc.example.test", "RootOper");
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        ":irc.example.test 262 RootOper SESSION :End of SESSION view\r\n",
        try fmt.endOfTrace(&buf, ""),
    );
}

test "formatter rejects invalid params and too-small output" {
    const fmt = Formatter.init("irc.example.test", "RootOper");
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, fmt.traceLine(&tiny, sampleFacts()[0]));

    var buf: [256]u8 = undefined;
    const bad = ConnectionFact{ .nick = "bad nick", .ip = "127.0.0.1", .connected_ms = 1 };
    try testing.expectError(error.InvalidParam, fmt.traceLine(&buf, bad));
}

test "end to end parse view render keeps rows pure over input slices" {
    const q = try parseFilter("account=* sort=-oper,nick");
    var rows: [4]ConnectionFact = undefined;
    const view = try buildView(sampleFacts(), q, &rows);
    try testing.expectEqual(@as(usize, 3), view.rows.len);
    try testing.expectEqualStrings("carol", view.rows[0].nick);
    try testing.expectEqualStrings("RootOper", view.rows[1].nick);
    try testing.expectEqualStrings("alice", view.rows[2].nick);

    const fmt = Formatter.init("onyx.test", "RootOper");
    var line: [256]u8 = undefined;
    try testing.expectEqualStrings(
        ":onyx.test 204 RootOper Oper sessions RootOper (198.51.100.7) 90 0 tls root\r\n",
        try fmt.traceLine(&line, view.rows[1]),
    );
}
