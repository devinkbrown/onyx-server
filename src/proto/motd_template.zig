// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Personalized MOTD template engine.
//!
//! The MOTD text (configured `[motd] text` or the built-in default) is treated
//! as a template expanded per connection, so a single MOTD greets each client
//! by name, reflects their login/oper state, and shows live network figures.
//!
//! Substitution: `{key}` is replaced from `Vars`; an unknown key is left
//! verbatim. `{key|fallback}` uses the fallback when the value is missing or
//! empty (and for an unknown key). `{{` and `}}` emit literal braces. Values
//! are copied with CR, LF, and NUL turned into spaces so a realname or away
//! message cannot break out of its MOTD line.
//!
//! `{plural:key:one:many}` picks a word from a numeric variable (`1` uses
//! `one`). `{if:COND}` supports the flags below, `{if:!flag}` / `{if:not:flag}`
//! negation, and numeric comparisons (`users>1`, `channels_here=0`,
//! `hour>=18`, `servers!=1`). Conditionals nest and may contain substitutions.
//!
//! Pure `std`; allocation-free (caller supplies the output buffer); natively
//! unit-tested.
const std = @import("std");

/// Per-connection values available to a MOTD template.
pub const Vars = struct {
    nick: []const u8 = "",
    /// Account name, or null when the client is not logged in.
    account: ?[]const u8 = null,
    host: []const u8 = "",
    network: []const u8 = "",
    server: []const u8 = "",
    version: []const u8 = "",
    /// Preformatted local time / date strings (caller-rendered).
    time: []const u8 = "",
    date: []const u8 = "",
    users: u64 = 0,
    opers: u64 = 0,
    channels: u64 = 0,
    /// Mesh nodes visible from this server, including this one.
    servers: u64 = 0,
    /// Users homed on this node (the mesh-wide total is `users`).
    local_users: u64 = 0,
    /// Channels this connection is in right now.
    channels_here: u64 = 0,
    is_oper: bool = false,
    /// Whether the client is on a TLS (secure) link.
    secure: bool = false,
    /// Hour [0,23] for `{greeting}`. Callers pass solar time from the client's
    /// longitude when they know it, otherwise UTC.
    hour: u8 = 12,
    /// USER ident. Empty when the session has none.
    username: []const u8 = "",
    /// USER realname. Empty when the session has none.
    realname: []const u8 = "",
    /// AWAY text. Empty when the client is not away.
    away: []const u8 = "",
    /// GeoIP place names. Empty when the address has no record.
    city: []const u8 = "",
    region: []const u8 = "",
    country: []const u8 = "",
    /// Preformatted server uptime, for example `3d 4h`.
    uptime: []const u8 = "",
    /// Preformatted time since this connection was accepted.
    online: []const u8 = "",
    /// English weekday of `date` in UTC.
    weekday: []const u8 = "",
    /// Pre-rendered, locale-correct weather line (empty = unavailable).
    weather: []const u8 = "",
    /// Pre-rendered news headline(s) line (empty = unavailable).
    news: []const u8 = "",
};

/// Hour of `epoch_s` shifted by solar time at `longitude` (degrees, east
/// positive). Missing or out-of-range longitude stays on UTC. The offset is
/// `round(longitude / 15)` clamped to [-12, +14]; it is not a civil timezone
/// and does not apply daylight saving.
pub fn solarHour(epoch_s: u64, longitude: ?f64) u8 {
    const utc: i64 = @intCast((epoch_s / 3600) % 24);
    const lon = longitude orelse return @intCast(utc);
    if (!std.math.isFinite(lon) or lon < -180.0 or lon > 180.0) return @intCast(utc);
    var off: i64 = @intFromFloat(std.math.round(lon / 15.0));
    if (off < -12) off = -12;
    if (off > 14) off = 14;
    return @intCast(@mod(utc + off + 48, 24));
}

/// `YYYY-MM-DD` in UTC. Empty when `buf` cannot hold the 10 bytes.
pub fn formatDate(epoch_s: u64, buf: []u8) []const u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = epoch_s };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        yd.year, md.month.numeric(), @as(u16, md.day_index) + 1,
    }) catch "";
}

/// `HH:MM:SS UTC`. Empty when `buf` cannot hold it.
pub fn formatClock(epoch_s: u64, buf: []u8) []const u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = epoch_s };
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch "";
}

/// English weekday. 1970-01-01 was a Thursday.
pub fn weekdayName(epoch_s: u64) []const u8 {
    const names = [_][]const u8{ "Thursday", "Friday", "Saturday", "Sunday", "Monday", "Tuesday", "Wednesday" };
    return names[@intCast((epoch_s / 86400) % 7)];
}

/// Compact duration: `12s`, `4m 2s`, `2h 15m`, or `3d 4h`.
pub fn formatSpan(secs: u64, buf: []u8) []const u8 {
    const days = secs / 86400;
    const hours = (secs % 86400) / 3600;
    const mins = (secs % 3600) / 60;
    const rem = secs % 60;
    if (days > 0) return std.fmt.bufPrint(buf, "{d}d {d}h", .{ days, hours }) catch "";
    if (hours > 0) return std.fmt.bufPrint(buf, "{d}h {d}m", .{ hours, mins }) catch "";
    if (mins > 0) return std.fmt.bufPrint(buf, "{d}m {d}s", .{ mins, rem }) catch "";
    return std.fmt.bufPrint(buf, "{d}s", .{secs}) catch "";
}

pub const Error = error{ BufTooSmall, MalformedTemplate };

/// A time-of-day greeting for `hour` (0..23).
pub fn greetingFor(hour: u8) []const u8 {
    return if (hour < 5)
        "Good evening"
    else if (hour < 12)
        "Good morning"
    else if (hour < 18)
        "Good afternoon"
    else
        "Good evening";
}

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *Writer, bytes: []const u8) Error!void {
        if (self.len + bytes.len > self.buf.len) return error.BufTooSmall;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn writeU64(self: *Writer, v: u64) Error!void {
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch return error.BufTooSmall;
        try self.write(s);
    }

    /// Copy `bytes`, turning CR, LF, and NUL into a single space so a value
    /// cannot open a new MOTD line or truncate the IRC reply.
    fn writeClean(self: *Writer, bytes: []const u8) Error!void {
        var start: usize = 0;
        for (bytes, 0..) |c, i| {
            if (c != '\n' and c != '\r' and c != 0) continue;
            if (i > start) try self.write(bytes[start..i]);
            try self.write(" ");
            start = i + 1;
        }
        if (start < bytes.len) try self.write(bytes[start..]);
    }
};

/// Expand `template` into `out` using `vars`, returning the written slice.
pub fn expand(template: []const u8, vars: Vars, out: []u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try expandRange(template, vars, &w, 0);
    return w.buf[0..w.len];
}

const max_depth: usize = 16;

fn expandRange(tmpl: []const u8, vars: Vars, w: *Writer, depth: usize) Error!void {
    if (depth > max_depth) return error.MalformedTemplate;
    var i: usize = 0;
    while (i < tmpl.len) {
        const c = tmpl[i];
        if (c == '}' and i + 1 < tmpl.len and tmpl[i + 1] == '}') {
            try w.write("}");
            i += 2;
            continue;
        }
        if (c != '{') {
            try w.write(tmpl[i .. i + 1]);
            i += 1;
            continue;
        }
        // c == '{'
        if (i + 1 < tmpl.len and tmpl[i + 1] == '{') {
            try w.write("{");
            i += 2;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, tmpl, i, '}') orelse {
            // No closing brace: emit the rest verbatim.
            try w.write(tmpl[i..]);
            return;
        };
        const tag = tmpl[i + 1 .. close];

        if (std.mem.startsWith(u8, tag, "if:")) {
            const cond = tag["if:".len..];
            const block = try findIfBlock(tmpl, i);
            const taken = if (evalCond(cond, vars)) block.then_text else block.else_text;
            try expandRange(taken, vars, w, depth + 1);
            i = block.after;
            continue;
        }
        if (std.mem.eql(u8, tag, "else") or std.mem.eql(u8, tag, "/if")) {
            // A stray else/endif outside a block: emit verbatim.
            try w.write(tmpl[i .. close + 1]);
            i = close + 1;
            continue;
        }

        if (try writePlural(tag, vars, w)) {
            i = close + 1;
            continue;
        }

        // Plain substitution; unknown keys without a fallback stay verbatim.
        const parts = splitFallback(tag);
        if (try substitute(parts.key, vars, w, parts.fallback)) {
            i = close + 1;
        } else {
            try w.write(tmpl[i .. close + 1]);
            i = close + 1;
        }
    }
}

fn splitFallback(tag: []const u8) struct { key: []const u8, fallback: ?[]const u8 } {
    const bar = std.mem.indexOfScalar(u8, tag, '|') orelse return .{ .key = tag, .fallback = null };
    return .{ .key = tag[0..bar], .fallback = tag[bar + 1 ..] };
}

fn evalCond(cond: []const u8, vars: Vars) bool {
    if (std.mem.startsWith(u8, cond, "not:") and cond.len > 4) return !evalCond(cond[4..], vars);
    if (cond.len > 1 and cond[0] == '!') return !evalCond(cond[1..], vars);
    if (compareNumeric(cond, vars)) |result| return result;
    return evalFlag(cond, vars);
}

fn evalFlag(cond: []const u8, vars: Vars) bool {
    if (std.mem.eql(u8, cond, "oper")) return vars.is_oper;
    if (std.mem.eql(u8, cond, "account")) {
        const name = vars.account orelse return false;
        return name.len != 0;
    }
    if (std.mem.eql(u8, cond, "secure")) return vars.secure;
    if (std.mem.eql(u8, cond, "weather")) return vars.weather.len != 0;
    if (std.mem.eql(u8, cond, "news")) return vars.news.len != 0;
    if (std.mem.eql(u8, cond, "away")) return vars.away.len != 0;
    if (std.mem.eql(u8, cond, "place")) return vars.city.len != 0 or vars.region.len != 0 or vars.country.len != 0;
    if (std.mem.eql(u8, cond, "city")) return vars.city.len != 0;
    if (std.mem.eql(u8, cond, "region")) return vars.region.len != 0;
    if (std.mem.eql(u8, cond, "country")) return vars.country.len != 0;
    if (std.mem.eql(u8, cond, "channels")) return vars.channels_here != 0;
    return false;
}

const Cmp = enum { gt, lt, ge, le, eq, ne };

fn compareNumeric(cond: []const u8, vars: Vars) ?bool {
    const found = findCmp(cond) orelse return null;
    const key = cond[0..found.at];
    const rhs_text = cond[found.after..];
    if (key.len == 0 or rhs_text.len == 0) return false;
    const value = numericValue(key, vars) orelse return false;
    const rhs = parseU64(rhs_text) orelse return false;
    return switch (found.op) {
        .gt => value > rhs,
        .lt => value < rhs,
        .ge => value >= rhs,
        .le => value <= rhs,
        .eq => value == rhs,
        .ne => value != rhs,
    };
}

fn findCmp(cond: []const u8) ?struct { at: usize, after: usize, op: Cmp } {
    var i: usize = 0;
    while (i < cond.len) : (i += 1) {
        if (i + 1 < cond.len) {
            const two = cond[i..][0..2];
            if (std.mem.eql(u8, two, ">=")) return .{ .at = i, .after = i + 2, .op = .ge };
            if (std.mem.eql(u8, two, "<=")) return .{ .at = i, .after = i + 2, .op = .le };
            if (std.mem.eql(u8, two, "!=")) return .{ .at = i, .after = i + 2, .op = .ne };
            if (std.mem.eql(u8, two, "==")) return .{ .at = i, .after = i + 2, .op = .eq };
        }
        switch (cond[i]) {
            '>' => return .{ .at = i, .after = i + 1, .op = .gt },
            '<' => return .{ .at = i, .after = i + 1, .op = .lt },
            '=' => return .{ .at = i, .after = i + 1, .op = .eq },
            else => {},
        }
    }
    return null;
}

fn parseU64(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    var n: u64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = std.math.mul(u64, n, 10) catch return null;
        n = std.math.add(u64, n, c - '0') catch return null;
    }
    return n;
}

fn numericValue(key: []const u8, vars: Vars) ?u64 {
    if (std.mem.eql(u8, key, "users")) return vars.users;
    if (std.mem.eql(u8, key, "opers")) return vars.opers;
    if (std.mem.eql(u8, key, "channels")) return vars.channels;
    if (std.mem.eql(u8, key, "servers")) return vars.servers;
    if (std.mem.eql(u8, key, "local_users")) return vars.local_users;
    if (std.mem.eql(u8, key, "channels_here")) return vars.channels_here;
    if (std.mem.eql(u8, key, "hour")) return vars.hour;
    return null;
}

fn writePlural(tag: []const u8, vars: Vars, w: *Writer) Error!bool {
    if (!std.mem.startsWith(u8, tag, "plural:")) return false;
    var it = std.mem.splitScalar(u8, tag, ':');
    _ = it.next();
    const key = it.next() orelse return false;
    const one = it.next() orelse return false;
    const many = it.next() orelse return false;
    if (it.next() != null) return false;
    const n = numericValue(key, vars) orelse return false;
    try w.writeClean(if (n == 1) one else many);
    return true;
}

fn writeText(w: *Writer, value: []const u8, fallback: ?[]const u8) Error!void {
    if (value.len == 0) {
        if (fallback) |fb| try w.writeClean(fb);
        return;
    }
    try w.writeClean(value);
}

/// Replace a known `{key}` into `w`. `fallback` is used when the value is
/// missing or empty, including an unknown key. Returns false only when the
/// key is unknown and there is no fallback, so the caller can keep the tag.
fn substitute(key: []const u8, vars: Vars, w: *Writer, fallback: ?[]const u8) Error!bool {
    if (std.mem.eql(u8, key, "nick")) {
        try writeText(w, vars.nick, fallback);
    } else if (std.mem.eql(u8, key, "account")) {
        if (vars.account) |name| {
            if (name.len == 0) {
                if (fallback) |fb| try w.writeClean(fb);
            } else {
                try w.writeClean(name);
            }
        } else if (fallback) |fb| {
            try w.writeClean(fb);
        } else {
            try w.write("*");
        }
    } else if (std.mem.eql(u8, key, "host")) {
        try writeText(w, vars.host, fallback);
    } else if (std.mem.eql(u8, key, "network")) {
        try writeText(w, vars.network, fallback);
    } else if (std.mem.eql(u8, key, "server")) {
        try writeText(w, vars.server, fallback);
    } else if (std.mem.eql(u8, key, "version")) {
        try writeText(w, vars.version, fallback);
    } else if (std.mem.eql(u8, key, "time")) {
        try writeText(w, vars.time, fallback);
    } else if (std.mem.eql(u8, key, "date")) {
        try writeText(w, vars.date, fallback);
    } else if (std.mem.eql(u8, key, "weekday")) {
        try writeText(w, vars.weekday, fallback);
    } else if (std.mem.eql(u8, key, "greeting")) {
        try w.write(greetingFor(vars.hour));
    } else if (std.mem.eql(u8, key, "username")) {
        try writeText(w, vars.username, fallback);
    } else if (std.mem.eql(u8, key, "realname")) {
        try writeText(w, vars.realname, fallback);
    } else if (std.mem.eql(u8, key, "away")) {
        try writeText(w, vars.away, fallback);
    } else if (std.mem.eql(u8, key, "city")) {
        try writeText(w, vars.city, fallback);
    } else if (std.mem.eql(u8, key, "region")) {
        try writeText(w, vars.region, fallback);
    } else if (std.mem.eql(u8, key, "country")) {
        try writeText(w, vars.country, fallback);
    } else if (std.mem.eql(u8, key, "uptime")) {
        try writeText(w, vars.uptime, fallback);
    } else if (std.mem.eql(u8, key, "online")) {
        try writeText(w, vars.online, fallback);
    } else if (std.mem.eql(u8, key, "weather")) {
        try writeText(w, vars.weather, fallback);
    } else if (std.mem.eql(u8, key, "news")) {
        try writeText(w, vars.news, fallback);
    } else if (numericValue(key, vars)) |n| {
        try w.writeU64(n);
    } else if (fallback) |fb| {
        try w.writeClean(fb);
    } else {
        return false;
    }
    return true;
}

const IfBlock = struct {
    /// Template text of the `then` branch (between `{if:...}` and `{else}`/`{/if}`).
    then_text: []const u8,
    /// Template text of the `else` branch (empty when no `{else}`).
    else_text: []const u8,
    /// Index in the source template just past the matching `{/if}`.
    after: usize,
};

/// Locate the branches and end of the `{if:...}` block that starts at `open`
/// (the index of its `{`). Honors nested `{if}`/`{/if}` pairs.
fn findIfBlock(tmpl: []const u8, open: usize) Error!IfBlock {
    const body_start = (std.mem.indexOfScalarPos(u8, tmpl, open, '}') orelse return error.MalformedTemplate) + 1;
    var depth: usize = 1;
    var i: usize = body_start;
    var else_at: ?usize = null; // index of the top-level {else}'s '{'
    while (i < tmpl.len) {
        if (tmpl[i] != '{') {
            i += 1;
            continue;
        }
        if (i + 1 < tmpl.len and tmpl[i + 1] == '{') {
            i += 2;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, tmpl, i, '}') orelse return error.MalformedTemplate;
        const tag = tmpl[i + 1 .. close];
        if (std.mem.startsWith(u8, tag, "if:")) {
            depth += 1;
        } else if (std.mem.eql(u8, tag, "/if")) {
            depth -= 1;
            if (depth == 0) {
                const then_end = else_at orelse i;
                const then_text = tmpl[body_start..then_end];
                const else_text = if (else_at) |e|
                    tmpl[(std.mem.indexOfScalarPos(u8, tmpl, e, '}').? + 1)..i]
                else
                    "";
                return .{ .then_text = then_text, .else_text = else_text, .after = close + 1 };
            }
        } else if (std.mem.eql(u8, tag, "else") and depth == 1 and else_at == null) {
            else_at = i;
        }
        i = close + 1;
    }
    return error.MalformedTemplate;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectExpand(template: []const u8, vars: Vars, want: []const u8) !void {
    var buf: [512]u8 = undefined;
    const got = try expand(template, vars, &buf);
    try testing.expectEqualStrings(want, got);
}

test "substitutes known variables" {
    try expectExpand(
        "Hi {nick} on {network} ({users} users)",
        .{ .nick = "alice", .network = "ExampleNet", .users = 42 },
        "Hi alice on ExampleNet (42 users)",
    );
}

test "unknown keys and braces are left verbatim" {
    try expectExpand("a {bogus} b {{lit}} c", .{}, "a {bogus} b {lit} c");
}

test "weather and news substitute, with conditional gating on presence" {
    try expectExpand(
        "{if:account}{account}{else}guest{/if} — {weather}",
        .{ .account = "alice", .weather = "Austin: 72°F, wind 8 mph" },
        "alice — Austin: 72°F, wind 8 mph",
    );
    // Absent weather/news expand to empty.
    try expectExpand("[{weather}][{news}]", .{}, "[][]");
}

test "greeting reflects the hour" {
    try expectExpand("{greeting}", .{ .hour = 9 }, "Good morning");
    try expectExpand("{greeting}", .{ .hour = 14 }, "Good afternoon");
    try expectExpand("{greeting}", .{ .hour = 21 }, "Good evening");
    try expectExpand("{greeting}", .{ .hour = 2 }, "Good evening");
}

test "account substitutes name or * when absent" {
    try expectExpand("acct={account}", .{ .account = "bob" }, "acct=bob");
    try expectExpand("acct={account}", .{ .account = null }, "acct=*");
}

test "if:oper selects branch" {
    try expectExpand("{if:oper}OPER{/if}done", .{ .is_oper = true }, "OPERdone");
    try expectExpand("{if:oper}OPER{/if}done", .{ .is_oper = false }, "done");
}

test "if:account with else" {
    try expectExpand(
        "{if:account}Welcome back, {account}!{else}Please register.{/if}",
        .{ .account = "carol" },
        "Welcome back, carol!",
    );
    try expectExpand(
        "{if:account}Welcome back, {account}!{else}Please register.{/if}",
        .{ .account = null },
        "Please register.",
    );
}

test "nested conditionals expand the right branches" {
    const t = "{if:oper}op{if:secure}+tls{else}+plain{/if}{else}user{/if}";
    try expectExpand(t, .{ .is_oper = true, .secure = true }, "op+tls");
    try expectExpand(t, .{ .is_oper = true, .secure = false }, "op+plain");
    try expectExpand(t, .{ .is_oper = false }, "user");
}

test "reports a too-small output buffer" {
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.BufTooSmall, expand("{nick}", .{ .nick = "longname" }, &tiny));
}

test "malformed (unterminated) if is reported" {
    var buf: [128]u8 = undefined;
    try testing.expectError(error.MalformedTemplate, expand("{if:oper}x", .{}, &buf));
}

test "stray else and endif emit verbatim outside a block" {
    try expectExpand("a {else} b {/if} c", .{}, "a {else} b {/if} c");
}

test "personalized motd fallback, plural, and negation" {
    try expectExpand("{city|somewhere}", .{}, "somewhere");
    try expectExpand("{account|guest}", .{ .account = null }, "guest");
    try expectExpand("{account}", .{ .account = null }, "*");
    try expectExpand("{nick|friend}", .{ .nick = "" }, "friend");
    try expectExpand("{bogus}", .{}, "{bogus}");
    try expectExpand("{users} {plural:users:person:people}", .{ .users = 1 }, "1 person");
    try expectExpand("{users} {plural:users:person:people}", .{ .users = 0 }, "0 people");
    try expectExpand("{if:!secure}plaintext{else}tls{/if}", .{ .secure = false }, "plaintext");
    try expectExpand("{if:not:oper}user{/if}", .{ .is_oper = false }, "user");
    try expectExpand("{if:users>1}busy{else}quiet{/if}", .{ .users = 2 }, "busy");
    try expectExpand("{if:channels_here=0}none{/if}", .{ .channels_here = 0 }, "none");
    try expectExpand("{if:servers!=1}mesh{/if}", .{ .servers = 2 }, "mesh");
    try expectExpand("{if:!users>1}few{/if}", .{ .users = 4 }, "");
    try expectExpand("{if:place}{city}, {country}{/if}", .{ .city = "Dallas", .country = "United States" }, "Dallas, United States");
    try expectExpand("{if:away}away: {away}{/if}", .{ .away = "lunch" }, "away: lunch");
}

test "personalized motd values cannot break the line" {
    try expectExpand("[{realname}]", .{ .realname = "a\r\nb\x00c" }, "[a  b c]");
}

test "personalized motd solar time and span" {
    // 1970-01-01 00:00 UTC. Dallas longitude rounds to UTC-6, so 18:00 solar.
    try std.testing.expectEqual(@as(u8, 0), solarHour(0, null));
    try std.testing.expectEqual(@as(u8, 18), solarHour(0, -96.9));
    try std.testing.expectEqual(@as(u8, 0), solarHour(0, std.math.nan(f64)));
    try std.testing.expectEqualStrings("Good evening", greetingFor(solarHour(0, -96.9)));
    try std.testing.expectEqualStrings("Thursday", weekdayName(0));
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1970-01-01", formatDate(0, &buf));
    try std.testing.expectEqualStrings("00:00:00 UTC", formatClock(0, &buf));
    try std.testing.expectEqualStrings("3d 4h", formatSpan(3 * 86400 + 4 * 3600, &buf));
    try std.testing.expectEqualStrings("45s", formatSpan(45, &buf));
}
