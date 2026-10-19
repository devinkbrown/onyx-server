// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key-free weather + news acquisition: HTTP/1.1 request builders and response
//! parsers for two no-API-key sources.
//!
//!   * Weather — `wttr.in`, plain HTTP, `?format=j1` (metric JSON, no key).
//!     The one-line `%t|%w|%C|%l` body is still accepted as a fallback.
//!     Callers re-localize per the requesting user's country via `weather_units`.
//!   * News — any RSS/Atom feed. Item titles, publication times, and a short
//!     description are kept; the channel/feed title is not a headline.
//!
//! This module is pure `std`: it builds request bytes into caller storage and
//! parses response bodies into slices that borrow the input. The actual socket
//! I/O lives in `daemon/geo_services.zig` (a background thread), so nothing here
//! blocks or allocates.
const std = @import("std");
const http1_client = @import("http1_client.zig");
const weather_units = @import("weather_units.zig");

pub const Error = error{
    BufferTooSmall,
    InvalidLocation,
    ParseFailed,
};

/// Default weather host. Plain HTTP (no TLS, no key) is supported by wttr.in.
pub const weather_host = "wttr.in";

/// A parsed wttr.in reading plus its echoed location, borrowing the response
/// body. Numbers are metric so the caller localizes via `weather_units`.
pub const Weather = struct {
    reading: weather_units.Reading,
    location: []const u8,
};

/// Current conditions plus up to three civil days. String slices borrow the
/// response body (or the one-line fallback body).
pub const WeatherReport = struct {
    reading: weather_units.Reading = .{},
    location: []const u8 = "",
    region: []const u8 = "",
    days: [weather_units.max_days]weather_units.Day = .{ .{}, .{}, .{} },
    day_count: usize = 0,
};

/// One RSS/Atom item. Slices borrow the feed body.
pub const RssItem = struct {
    title: []const u8,
    /// Unix seconds, or 0 when the feed omitted a usable date.
    published_unix: i64 = 0,
    deck: []const u8 = "",
};

/// Bounded append cursor over caller storage. Every write is length-checked so
/// request construction never overflows on attacker-influenced input.
const Cursor = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *Cursor, s: []const u8) Error!void {
        if (self.len + s.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
    }

    fn byte(self: *Cursor, b: u8) Error!void {
        if (self.len + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn hexByte(self: *Cursor, b: u8) Error!void {
        const hex = "0123456789ABCDEF";
        try self.byte('%');
        try self.byte(hex[b >> 4]);
        try self.byte(hex[b & 0x0f]);
    }

    fn written(self: *const Cursor) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build a GET request for `http://<host>/<location>?format=j1`.
/// The location path segment is percent-encoded. `j1` is wttr.in's key-free
/// metric JSON document (current conditions plus three civil days).
pub fn buildWeatherRequest(buf: []u8, host: []const u8, location: []const u8) Error![]const u8 {
    if (location.len == 0) return error.InvalidLocation;
    var c = Cursor{ .buf = buf };
    try c.write("GET /");
    try writePercentEncoded(&c, location);
    try c.write("?format=j1 HTTP/1.1\r\nHost: ");
    try c.write(host);
    // wttr.in serves the document to curl-like User-Agents. No Accept-Encoding,
    // so the body stays identity-coded for the parser below.
    try c.write("\r\nUser-Agent: curl/8\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    return c.written();
}

/// Build a GET request for an arbitrary RSS feed path on `host`.
pub fn buildNewsRequest(buf: []u8, host: []const u8, path: []const u8) Error![]const u8 {
    var c = Cursor{ .buf = buf };
    try c.write("GET ");
    try c.write(if (path.len == 0) "/" else path);
    try c.write(" HTTP/1.1\r\nHost: ");
    try c.write(host);
    try c.write("\r\nUser-Agent: onyx-server-news/1\r\nAccept: application/rss+xml, application/xml, text/xml\r\nConnection: close\r\n\r\n");
    return c.written();
}

/// Return the body of an HTTP response (everything after the CRLFCRLF header
/// terminator). Returns the whole input if no terminator is present. This does
/// not decode `Transfer-Encoding: chunked`. Callers that parse a live response
/// use `httpPayload`.
pub fn httpBody(response: []const u8) []const u8 {
    if (std.mem.indexOf(u8, response, "\r\n\r\n")) |i| return response[i + 4 ..];
    if (std.mem.indexOf(u8, response, "\n\n")) |i| return response[i + 2 ..];
    return response;
}

/// Decode one complete HTTP/1.0 or 1.1 response in place and return the body.
/// Chunked framing and `Content-Length` are honored. A non-2xx status, a
/// truncated message, or too many headers returns null. The slice aliases
/// `response`.
pub fn httpPayload(response: []u8) ?[]const u8 {
    var headers: [64]http1_client.Header = undefined;
    const parsed = http1_client.parseResponse(response, &headers) catch return null;
    if (parsed.status < 200 or parsed.status > 299) return null;
    return parsed.body;
}

/// Parse either a wttr.in `j1` document or the legacy one-line body.
pub fn parseWeatherReport(body: []const u8) Error!WeatherReport {
    const trimmed = std.mem.trimStart(u8, body, " \t\r\n");
    if (trimmed.len != 0 and trimmed[0] == '{') return parseWeatherJson(trimmed);
    const legacy = try parseWeather(trimmed);
    var report = WeatherReport{ .reading = legacy.reading, .location = legacy.location };
    report.reading.flags |= weather_units.flag_rich;
    return report;
}

/// Parse a wttr.in one-line body (`+33°C|↑21km/h|Partly cloudy|Austin`) into a
/// metric `Weather`. Tolerates trailing whitespace/newlines and missing fields.
pub fn parseWeather(body: []const u8) Error!Weather {
    const line = firstLine(body);
    if (line.len == 0) return error.ParseFailed;

    var it = std.mem.splitScalar(u8, line, '|');
    const temp_field = it.next() orelse return error.ParseFailed;
    const wind_field = it.next() orelse "";
    const desc_field = it.next() orelse "";
    const loc_field = it.next() orelse "";

    const temp_c = parseLeadingNumber(temp_field) orelse return error.ParseFailed;
    const wind_kph = parseLeadingNumber(wind_field) orelse 0;

    return .{
        .reading = .{
            .temp_c = temp_c,
            .wind_kph = wind_kph,
            .precip_mm = 0,
            .desc = std.mem.trim(u8, desc_field, " \t\r\n"),
        },
        .location = std.mem.trim(u8, loc_field, " \t\r\n"),
    };
}

/// Extract up to `out.len` headline titles from an RSS/Atom body. Only the first
/// `<title>` *inside each `<item>` (RSS) or `<entry>` (Atom)* is taken, so the
/// channel/feed and `<image>` titles are never mistaken for headlines. CDATA
/// wrappers are unwrapped; titles are emitted verbatim (trimmed). Returned slices
/// borrow `body`. Returns the filled prefix of `out`.
pub fn parseRssTitles(body: []const u8, out: [][]const u8) [][]const u8 {
    var count: usize = 0;
    var cursor: usize = 0;
    while (count < out.len) {
        // Advance to the next item/entry element.
        const item = nextItemStart(body, cursor) orelse break;
        // Bound the search to this item so we take its own <title>, not a later one.
        const item_end = itemEnd(body, item.content_start);
        cursor = item_end;

        const region = body[item.content_start..item_end];
        const title = firstTitle(region) orelse continue;
        if (title.len == 0) continue;
        out[count] = title;
        count += 1;
    }
    return out[0..count];
}

/// Like `parseRssTitles`, plus the first publication time and description deck
/// inside each item. Deck text still contains markup; `packHeadline` strips it.
pub fn parseRssItems(body: []const u8, out: []RssItem) []RssItem {
    var count: usize = 0;
    var cursor: usize = 0;
    while (count < out.len) {
        const item = nextItemStart(body, cursor) orelse break;
        const item_end = itemEnd(body, item.content_start);
        cursor = item_end;
        const region = body[item.content_start..item_end];
        const title = firstTitle(region) orelse continue;
        if (title.len == 0) continue;
        const deck = firstTagText(region, &.{ "description", "summary" }) orelse "";
        const when = firstTagText(region, &.{ "pubDate", "updated", "published", "dc:date" }) orelse "";
        out[count] = .{
            .title = title,
            .deck = deck,
            .published_unix = parseRssTime(when),
        };
        count += 1;
    }
    return out[0..count];
}

/// Pack a headline into `buf` as either a plain title or `epoch\ttitle\tdeck`.
/// Tabs and newlines in the text become spaces. The title keeps the bytes it
/// needs; the deck is clipped to about 80 characters with whatever remains.
/// The result borrows `buf`.
pub fn packHeadline(buf: []u8, epoch: i64, title: []const u8, deck: []const u8) []const u8 {
    var title_buf: [160]u8 = undefined;
    var deck_buf: [120]u8 = undefined;
    const clean_title = cleanText(title, &title_buf);
    var clean_deck = cleanText(deck, &deck_buf);
    if (clean_deck.len > 80) clean_deck = clipUtf8(clean_deck, 80);
    if (epoch <= 0 and clean_deck.len == 0) {
        const n = clipUtf8(clean_title, buf.len).len;
        @memcpy(buf[0..n], clean_title[0..n]);
        return buf[0..n];
    }
    var prefix: [24]u8 = undefined;
    const head = std.fmt.bufPrint(&prefix, "{d}\t", .{if (epoch > 0) epoch else 0}) catch return buf[0..0];
    if (head.len >= buf.len) return buf[0..0];
    @memcpy(buf[0..head.len], head);
    const available = buf.len - head.len;
    const title_n = clipUtf8(clean_title, available).len;
    @memcpy(buf[head.len..][0..title_n], clean_title[0..title_n]);
    var n = head.len + title_n;
    if (clean_deck.len != 0 and n + 1 < buf.len) {
        buf[n] = '\t';
        n += 1;
        const deck_n = clipUtf8(clean_deck, buf.len - n).len;
        @memcpy(buf[n..][0..deck_n], clean_deck[0..deck_n]);
        n += deck_n;
    }
    return buf[0..n];
}

pub const HeadlineView = struct {
    title: []const u8,
    deck: []const u8 = "",
    epoch: i64 = 0,
};

/// Inverse of `packHeadline`. A line with no epoch prefix is a plain title.
pub fn unpackHeadline(line: []const u8) HeadlineView {
    const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return .{ .title = line };
    const first = line[0..tab];
    if (first.len == 0 or !allDigits(first)) return .{ .title = line };
    const epoch = std.fmt.parseInt(i64, first, 10) catch return .{ .title = line };
    const rest = line[tab + 1 ..];
    if (std.mem.indexOfScalar(u8, rest, '\t')) |split| {
        return .{ .epoch = epoch, .title = rest[0..split], .deck = rest[split + 1 ..] };
    }
    return .{ .epoch = epoch, .title = rest };
}

/// Short age label ("now", "5m", "2h", "3d") or "" when the instant is unknown.
pub fn formatAge(epoch: i64, now: i64, buf: []u8) []const u8 {
    if (epoch <= 0 or now <= 0) return "";
    const delta = now - epoch;
    if (delta < 0) return if (delta > -3600) "now" else "";
    if (delta < 45) return "now";
    if (delta < 3600) return std.fmt.bufPrint(buf, "{d}m", .{@divFloor(delta, 60)}) catch "";
    if (delta < 36 * 3600) return std.fmt.bufPrint(buf, "{d}h", .{@divFloor(delta, 3600)}) catch "";
    const days = @divFloor(delta, 86400);
    if (days > 99) return "99d+";
    return std.fmt.bufPrint(buf, "{d}d", .{days}) catch "";
}

/// `  1. [2h] Title - deck`, with control bytes turned into spaces.
pub fn formatHeadline(buf: []u8, index: usize, line: []const u8, now: i64) []const u8 {
    var body: [240]u8 = undefined;
    const text = formatHeadlineBody(&body, line, now);
    return copyVisible(buf, std.fmt.bufPrint(buf, "  {d}. {s}", .{ index, text }) catch buf[0..0]);
}

/// `[2h] Title - deck` with no index. Borrows `buf`.
pub fn formatHeadlineBody(buf: []u8, line: []const u8, now: i64) []const u8 {
    const item = unpackHeadline(line);
    var age_buf: [8]u8 = undefined;
    const age = formatAge(item.epoch, now, &age_buf);
    const written = if (age.len != 0 and item.deck.len != 0)
        std.fmt.bufPrint(buf, "[{s}] {s} - {s}", .{ age, item.title, item.deck }) catch buf[0..0]
    else if (age.len != 0)
        std.fmt.bufPrint(buf, "[{s}] {s}", .{ age, item.title }) catch buf[0..0]
    else if (item.deck.len != 0)
        std.fmt.bufPrint(buf, "{s} - {s}", .{ item.title, item.deck }) catch buf[0..0]
    else
        std.fmt.bufPrint(buf, "{s}", .{item.title}) catch buf[0..0];
    return copyVisible(buf, written);
}

const ItemStart = struct { content_start: usize };

/// Find the next `<item`/`<entry` element opening at or after `from`.
fn nextItemStart(body: []const u8, from: usize) ?ItemStart {
    var best: ?usize = null;
    inline for (.{ "<item", "<entry" }) |tag| {
        if (std.mem.indexOf(u8, body[from..], tag)) |rel| {
            const at = from + rel;
            if (best == null or at < best.?) best = at;
        }
    }
    const open = best orelse return null;
    const gt_rel = std.mem.indexOfScalar(u8, body[open..], '>') orelse return null;
    return .{ .content_start = open + gt_rel + 1 };
}

/// End offset of the item beginning at `start` (its closing tag or EOF).
fn itemEnd(body: []const u8, start: usize) usize {
    var end = body.len;
    inline for (.{ "</item>", "</entry>" }) |tag| {
        if (std.mem.indexOf(u8, body[start..], tag)) |rel| {
            const at = start + rel;
            if (at < end) end = at;
        }
    }
    return end;
}

/// First `<title>...</title>` content within `region`, CDATA-unwrapped + trimmed.
fn firstTitle(region: []const u8) ?[]const u8 {
    const open = std.mem.indexOf(u8, region, "<title") orelse return null;
    const gt_rel = std.mem.indexOfScalar(u8, region[open..], '>') orelse return null;
    const content_start = open + gt_rel + 1;
    const close_rel = std.mem.indexOf(u8, region[content_start..], "</title>") orelse return null;
    const raw = region[content_start .. content_start + close_rel];
    return std.mem.trim(u8, unwrapCdata(std.mem.trim(u8, raw, " \t\r\n")), " \t\r\n");
}

// ---- internals --------------------------------------------------------------

fn parseWeatherJson(body: []const u8) Error!WeatherReport {
    const current_arr = arrayInterior(body, "current_condition", 1) orelse return error.ParseFailed;
    const current = firstObjectInterior(current_arr) orelse return error.ParseFailed;
    const temp = parseJsonNumber(stringField(current, "temp_C", 0) orelse return error.ParseFailed) orelse return error.ParseFailed;
    var reading = weather_units.Reading{ .temp_c = temp, .flags = weather_units.flag_rich };
    if (stringField(current, "FeelsLikeC", 0)) |raw| if (parseJsonNumber(raw)) |v| {
        reading.feels_c = v;
        reading.flags |= weather_units.flag_feels;
    };
    if (stringField(current, "humidity", 0)) |raw| if (parseSmallInt(raw, 255)) |v| {
        reading.humidity_pct = @intCast(v);
        reading.flags |= weather_units.flag_humidity;
    };
    if (stringField(current, "precipMM", 0)) |raw| if (parseJsonNumber(raw)) |v| {
        reading.precip_mm = v;
        reading.flags |= weather_units.flag_precip;
    };
    if (stringField(current, "pressure", 0)) |raw| if (parseSmallInt(raw, 65535)) |v| {
        reading.pressure_hpa = @intCast(v);
        reading.flags |= weather_units.flag_pressure;
    };
    if (stringField(current, "uvIndex", 0)) |raw| if (parseSmallInt(raw, 255)) |v| {
        reading.uv_index = @intCast(v);
        reading.flags |= weather_units.flag_uv;
    };
    if (stringField(current, "visibility", 0)) |raw| if (parseSmallInt(raw, 65535)) |v| {
        reading.visibility_km = @intCast(v);
        reading.flags |= weather_units.flag_visibility;
    };
    if (stringField(current, "windspeedKmph", 0)) |raw| if (parseJsonNumber(raw)) |v| {
        reading.wind_kph = v;
    };
    if (stringField(current, "cloudcover", 0)) |raw| if (parseSmallInt(raw, 100)) |v| {
        reading.cloud_pct = @intCast(v);
        reading.has_cloud = true;
    };
    reading.obs = std.mem.trim(u8, stringField(current, "observation_time", 0) orelse "", " \t\r\n");
    reading.wind_dir = std.mem.trim(u8, stringField(current, "winddir16Point", 0) orelse "", " \t\r\n");
    if (reading.wind_dir.len != 0) reading.flags |= weather_units.flag_wind_dir;
    reading.desc = std.mem.trim(u8, nestedValue(current, "weatherDesc") orelse "", " \t\r\n");

    var report = WeatherReport{ .reading = reading };
    if (arrayInterior(body, "nearest_area", 1)) |area_arr| if (firstObjectInterior(area_arr)) |area| {
        report.location = std.mem.trim(u8, nestedValue(area, "areaName") orelse "", " \t\r\n");
        report.region = std.mem.trim(u8, nestedValue(area, "region") orelse "", " \t\r\n");
    };
    if (report.location.len == 0) report.location = report.region;

    if (arrayInterior(body, "weather", 1)) |days_arr| {
        var cursor: usize = 0;
        while (report.day_count < weather_units.max_days) {
            const day_inner = nextObjectInterior(days_arr, &cursor) orelse break;
            var day = weather_units.Day{};
            day.label = stringField(day_inner, "date", 0) orelse "";
            if (stringField(day_inner, "mintempC", 0)) |raw| day.min_c = parseJsonNumber(raw) orelse day.min_c;
            if (stringField(day_inner, "maxtempC", 0)) |raw| day.max_c = parseJsonNumber(raw) orelse day.max_c;
            if (arrayInterior(day_inner, "hourly", 0)) |hourly| fillHourly(&day, hourly);
            if (arrayInterior(day_inner, "astronomy", 0)) |astro_arr| if (firstObjectInterior(astro_arr)) |astro| {
                day.sunrise = std.mem.trim(u8, stringField(astro, "sunrise", 0) orelse "", " \t\r\n");
                day.sunset = std.mem.trim(u8, stringField(astro, "sunset", 0) orelse "", " \t\r\n");
            };
            if (day.label.len == 0 and day.desc.len == 0) continue;
            report.days[report.day_count] = day;
            report.day_count += 1;
        }
    }
    if (report.day_count != 0) {
        report.reading.rain_pct = report.days[0].rain_pct;
        report.reading.snow_pct = report.days[0].snow_pct;
        report.reading.thunder_pct = report.days[0].thunder_pct;
    }
    return report;
}

fn fillHourly(day: *weather_units.Day, hourly: []const u8) void {
    var cursor: usize = 0;
    var best: i32 = std.math.maxInt(i32);
    var precip: f64 = 0;
    var saw = false;
    while (nextObjectInterior(hourly, &cursor)) |hour| {
        if (stringField(hour, "precipMM", 0)) |raw| if (parseJsonNumber(raw)) |v| {
            precip += v;
            saw = true;
        };
        noteChance(&day.rain_pct, stringField(hour, "chanceofrain", 0));
        noteChance(&day.snow_pct, stringField(hour, "chanceofsnow", 0));
        noteChance(&day.thunder_pct, stringField(hour, "chanceofthunder", 0));
        const desc = std.mem.trim(u8, nestedValue(hour, "weatherDesc") orelse "", " \t\r\n");
        const clock = std.fmt.parseInt(i32, stringField(hour, "time", 0) orelse "", 10) catch {
            if (day.desc.len == 0 and desc.len != 0) day.desc = desc;
            continue;
        };
        const dist = if (clock >= 1200) clock - 1200 else 1200 - clock;
        if (desc.len != 0 and dist < best) {
            best = dist;
            day.desc = desc;
        }
    }
    if (saw) {
        day.precip_mm = precip;
        day.has_precip = precip != 0;
    }
}

fn noteChance(dst: *u8, raw: ?[]const u8) void {
    const text = raw orelse return;
    const v = parseSmallInt(text, 100) orelse return;
    const pct: u8 = @intCast(v);
    if (pct > dst.*) dst.* = pct;
}

fn arrayInterior(s: []const u8, key: []const u8, depth: usize) ?[]const u8 {
    const at = findKey(s, key, depth) orelse return null;
    if (at >= s.len or s[at] != '[') return null;
    const end = containerEnd(s, at) orelse return null;
    return s[at + 1 .. end];
}

fn stringField(s: []const u8, key: []const u8, depth: usize) ?[]const u8 {
    const at = findKey(s, key, depth) orelse return null;
    if (at >= s.len or s[at] != '"') return null;
    const end = stringEnd(s, at) orelse return null;
    return s[at + 1 .. end];
}

fn nestedValue(obj: []const u8, key: []const u8) ?[]const u8 {
    const arr = arrayInterior(obj, key, 0) orelse return null;
    const inner = firstObjectInterior(arr) orelse return null;
    return stringField(inner, "value", 0);
}

fn firstObjectInterior(s: []const u8) ?[]const u8 {
    var cursor: usize = 0;
    return nextObjectInterior(s, &cursor);
}

fn nextObjectInterior(s: []const u8, cursor: *usize) ?[]const u8 {
    var i = cursor.*;
    while (i < s.len) {
        if (s[i] == '"') {
            i = (stringEnd(s, i) orelse return null) + 1;
            continue;
        }
        if (s[i] == '{') {
            const end = containerEnd(s, i) orelse return null;
            cursor.* = end + 1;
            return s[i + 1 .. end];
        }
        i += 1;
    }
    cursor.* = i;
    return null;
}

fn findKey(s: []const u8, key: []const u8, depth_want: usize) ?usize {
    var i: usize = 0;
    var depth: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '"') {
            const end = stringEnd(s, i) orelse return null;
            if (depth == depth_want and std.mem.eql(u8, s[i + 1 .. end], key)) {
                const colon = skipWs(s, end + 1);
                if (colon < s.len and s[colon] == ':') return skipWs(s, colon + 1);
            }
            i = end + 1;
            continue;
        }
        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            if (depth == 0) return null;
            depth -= 1;
        }
        i += 1;
    }
    return null;
}

fn containerEnd(s: []const u8, open: usize) ?usize {
    var braces: i32 = 0;
    var brackets: i32 = 0;
    if (s[open] == '{') braces = 1 else if (s[open] == '[') brackets = 1 else return null;
    var i = open + 1;
    while (i < s.len) {
        const c = s[i];
        if (c == '"') {
            i = (stringEnd(s, i) orelse return null) + 1;
            continue;
        }
        if (c == '{') braces += 1 else if (c == '}') braces -= 1 else if (c == '[') brackets += 1 else if (c == ']') brackets -= 1;
        if (braces == 0 and brackets == 0) return i;
        i += 1;
    }
    return null;
}

fn stringEnd(s: []const u8, open_quote: usize) ?usize {
    var i = open_quote + 1;
    while (i < s.len) : (i += 1) {
        if (s[i] == '\\') {
            if (i + 1 >= s.len) return null;
            i += 1;
            continue;
        }
        if (s[i] == '"') return i;
    }
    return null;
}

fn skipWs(s: []const u8, i: usize) usize {
    var n = i;
    while (n < s.len and (s[n] == ' ' or s[n] == '\t' or s[n] == '\n' or s[n] == '\r')) n += 1;
    return n;
}

fn parseJsonNumber(s: []const u8) ?f64 {
    return parseLeadingNumber(std.mem.trim(u8, s, " \t\r\n"));
}

fn parseSmallInt(s: []const u8, max: i32) ?i32 {
    const v = parseJsonNumber(s) orelse return null;
    if (v < 0 or v > @as(f64, @floatFromInt(max))) return null;
    return @intFromFloat(@round(v));
}

fn firstTagText(region: []const u8, names: []const []const u8) ?[]const u8 {
    var best: ?usize = null;
    for (names) |name| {
        var needle: [40]u8 = undefined;
        if (name.len + 1 > needle.len) continue;
        needle[0] = '<';
        @memcpy(needle[1..][0..name.len], name);
        if (indexOfIgnoreCase(region, needle[0 .. name.len + 1])) |at| {
            const boundary_at = at + 1 + name.len;
            if (boundary_at >= region.len) continue;
            const boundary = region[boundary_at];
            if (!(boundary == '>' or boundary == ' ' or boundary == '/' or boundary == '\t' or boundary == '\r' or boundary == '\n')) continue;
            if (best == null or at < best.?) best = at;
        }
    }
    const open = best orelse return null;
    const gt = std.mem.indexOfScalarPos(u8, region, open, '>') orelse return null;
    const content_start = gt + 1;
    const body = std.mem.trim(u8, region[content_start..], " \t\r\n");
    if (std.mem.startsWith(u8, body, "<![CDATA[")) {
        const inner = body["<![CDATA[".len..];
        const end = std.mem.indexOf(u8, inner, "]]>") orelse return null;
        return std.mem.trim(u8, inner[0..end], " \t\r\n");
    }
    const close = indexOfIgnoreCase(region[content_start..], "</") orelse return null;
    const raw = region[content_start .. content_start + close];
    return std.mem.trim(u8, unwrapCdata(std.mem.trim(u8, raw, " \t\r\n")), " \t\r\n");
}

fn parseRssTime(text: []const u8) i64 {
    const raw = std.mem.trim(u8, unwrapCdata(std.mem.trim(u8, text, " \t\r\n")), " \t\r\n");
    if (raw.len == 0) return 0;
    if (parseIso8601(raw)) |instant| return instant;
    if (parseRfc822(raw)) |instant| return instant;
    return 0;
}

fn parseIso8601(s: []const u8) ?i64 {
    if (s.len < 10 or s[4] != '-' or s[7] != '-') return null;
    const year = std.fmt.parseInt(i32, s[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u32, s[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u32, s[8..10], 10) catch return null;
    var hour: u32 = 0;
    var minute: u32 = 0;
    var second: u32 = 0;
    var rest: []const u8 = s[10..];
    if (rest.len != 0 and (rest[0] == 'T' or rest[0] == 't' or rest[0] == ' ')) {
        rest = rest[1..];
        if (rest.len < 5 or rest[2] != ':') return null;
        hour = std.fmt.parseInt(u32, rest[0..2], 10) catch return null;
        minute = std.fmt.parseInt(u32, rest[3..5], 10) catch return null;
        rest = rest[5..];
        if (rest.len >= 3 and rest[0] == ':') {
            second = std.fmt.parseInt(u32, rest[1..3], 10) catch return null;
            rest = rest[3..];
        }
    }
    const local = weather_units.civilUnix(year, month, day, hour, minute, second) orelse return null;
    return applyZone(local, rest);
}

fn parseRfc822(s: []const u8) ?i64 {
    var rest = s;
    if (std.mem.indexOfScalar(u8, rest, ',')) |comma| rest = std.mem.trim(u8, rest[comma + 1 ..], " \t");
    if (rest.len < 11 or rest[2] != ' ') return null;
    const day = std.fmt.parseInt(u32, rest[0..2], 10) catch return null;
    const month = monthNum(rest[3..]) orelse return null;
    rest = std.mem.trim(u8, rest[6..], " ");
    if (rest.len < 4) return null;
    const year = std.fmt.parseInt(i32, rest[0..4], 10) catch return null;
    rest = std.mem.trim(u8, rest[4..], " ");
    var hour: u32 = 0;
    var minute: u32 = 0;
    var second: u32 = 0;
    if (rest.len >= 5 and rest[2] == ':') {
        hour = std.fmt.parseInt(u32, rest[0..2], 10) catch return null;
        minute = std.fmt.parseInt(u32, rest[3..5], 10) catch return null;
        rest = rest[5..];
        if (rest.len >= 3 and rest[0] == ':') {
            second = std.fmt.parseInt(u32, rest[1..3], 10) catch return null;
            rest = rest[3..];
        }
    }
    const local = weather_units.civilUnix(year, month, day, hour, minute, second) orelse return null;
    return applyZone(local, std.mem.trim(u8, rest, " \t"));
}

fn applyZone(local: i64, zone: []const u8) ?i64 {
    if (zone.len == 0) return local;
    if (zone[0] == 'Z' or zone[0] == 'z') return local;
    if (std.ascii.eqlIgnoreCase(zone, "GMT") or std.ascii.eqlIgnoreCase(zone, "UTC") or std.ascii.eqlIgnoreCase(zone, "UT")) return local;
    if (zone[0] != '+' and zone[0] != '-') return local;
    const sign: i64 = if (zone[0] == '-') -1 else 1;
    const body = zone[1..];
    const hh = std.fmt.parseInt(i64, body[0..@min(2, body.len)], 10) catch return local;
    var mm: i64 = 0;
    if (body.len >= 5 and body[2] == ':') mm = std.fmt.parseInt(i64, body[3..5], 10) catch 0 else if (body.len >= 4) mm = std.fmt.parseInt(i64, body[2..4], 10) catch 0;
    return local - sign * (hh * 3600 + mm * 60);
}

fn monthNum(s: []const u8) ?u32 {
    const names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    if (s.len < 3) return null;
    for (names, 1..) |name, index| if (std.ascii.eqlIgnoreCase(s[0..3], name)) return @intCast(index);
    return null;
}

fn indexOfIgnoreCase(hay: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or hay.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn cleanText(src: []const u8, buf: []u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len and n < buf.len) {
        if (src[i] == '<') {
            if (std.mem.indexOfScalarPos(u8, src, i, '>')) |end| {
                i = end + 1;
                pushSpace(buf, &n);
                continue;
            }
        }
        if (src[i] == '&') {
            if (decodeEntity(src[i..])) |ent| {
                if (ent.cp < 0x20 or ent.cp == 0x7f) {
                    pushSpace(buf, &n);
                } else if (!appendCp(buf, &n, ent.cp)) break;
                i += ent.len;
                continue;
            }
        }
        const c = src[i];
        if (c <= 0x20 or c == 0x7f) {
            pushSpace(buf, &n);
        } else {
            buf[n] = c;
            n += 1;
        }
        i += 1;
    }
    return std.mem.trim(u8, buf[0..n], " ");
}

fn pushSpace(buf: []u8, n: *usize) void {
    if (n.* == 0 or n.* >= buf.len or buf[n.* - 1] == ' ') return;
    buf[n.*] = ' ';
    n.* += 1;
}

const Entity = struct { cp: u21, len: usize };

fn decodeEntity(s: []const u8) ?Entity {
    const names = [_]struct { name: []const u8, cp: u21 }{
        .{ .name = "&amp;", .cp = '&' },
        .{ .name = "&lt;", .cp = '<' },
        .{ .name = "&gt;", .cp = '>' },
        .{ .name = "&quot;", .cp = '"' },
        .{ .name = "&apos;", .cp = '\'' },
        .{ .name = "&nbsp;", .cp = 0xA0 },
        .{ .name = "&rsquo;", .cp = 0x2019 },
        .{ .name = "&lsquo;", .cp = 0x2018 },
        .{ .name = "&rdquo;", .cp = 0x201D },
        .{ .name = "&ldquo;", .cp = 0x201C },
        .{ .name = "&hellip;", .cp = 0x2026 },
        .{ .name = "&ndash;", .cp = 0x2013 },
        .{ .name = "&mdash;", .cp = 0x2014 },
        .{ .name = "&#39;", .cp = '\'' },
    };
    for (names) |ent| if (std.ascii.startsWithIgnoreCase(s, ent.name)) return .{ .cp = ent.cp, .len = ent.name.len };
    return decodeNumericEntity(s);
}

fn decodeNumericEntity(s: []const u8) ?Entity {
    if (s.len < 4 or s[0] != '&' or s[1] != '#') return null;
    var i: usize = 2;
    const hex = i < s.len and (s[i] == 'x' or s[i] == 'X');
    if (hex) i += 1;
    const start = i;
    var cp: u32 = 0;
    var digits: usize = 0;
    while (i < s.len and digits < 6) {
        const c = s[i];
        if (c == ';') break;
        const digit: u32 = if (hex) switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        } else switch (c) {
            '0'...'9' => c - '0',
            else => return null,
        };
        const base: u32 = if (hex) 16 else 10;
        if (cp > (0x10FFFF - digit) / base) return null;
        cp = cp * base + digit;
        digits += 1;
        i += 1;
    }
    if (digits == 0 or i >= s.len or s[i] != ';' or i == start) return null;
    if (cp == 0 or cp > 0x10FFFF or (cp >= 0xD800 and cp <= 0xDFFF)) return null;
    return .{ .cp = @intCast(cp), .len = i + 1 };
}

fn appendCp(buf: []u8, n: *usize, cp: u21) bool {
    var tmp: [4]u8 = undefined;
    const written = std.unicode.utf8Encode(cp, &tmp) catch return false;
    if (n.* + written > buf.len) return false;
    @memcpy(buf[n.*..][0..written], tmp[0..written]);
    n.* += written;
    return true;
}

pub fn clipUtf8(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var n = max;
    while (n > 0 and (s[n] & 0xC0) == 0x80) n -= 1;
    return s[0..n];
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

fn copyVisible(buf: []u8, written: []const u8) []const u8 {
    const n = @min(written.len, buf.len);
    for (buf[0..n]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = ' ';
    };
    return buf[0..n];
}

fn unwrapCdata(s: []const u8) []const u8 {
    const open = "<![CDATA[";
    const close = "]]>";
    if (std.mem.startsWith(u8, s, open) and std.mem.endsWith(u8, s, close)) {
        return s[open.len .. s.len - close.len];
    }
    return s;
}

fn firstLine(s: []const u8) []const u8 {
    const trimmed = std.mem.trimStart(u8, s, " \t\r\n");
    const end = std.mem.indexOfScalar(u8, trimmed, '\n') orelse trimmed.len;
    return std.mem.trim(u8, trimmed[0..end], " \t\r\n");
}

/// Parse the first signed decimal number embedded in `s` (skipping a leading
/// direction arrow or '+'), e.g. "+33°C" -> 33, "↑21km/h" -> 21, "-4°C" -> -4.
fn parseLeadingNumber(s: []const u8) ?f64 {
    var i: usize = 0;
    // Find the first digit or a sign immediately preceding a digit.
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '-' or c == '+') {
            if (i + 1 < s.len and isDigit(s[i + 1])) break;
        } else if (isDigit(c)) {
            break;
        }
    }
    if (i >= s.len) return null;
    var j = i;
    if (s[j] == '-' or s[j] == '+') j += 1;
    while (j < s.len and (isDigit(s[j]) or s[j] == '.')) j += 1;
    return std.fmt.parseFloat(f64, s[i..j]) catch null;
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// Percent-encode everything except RFC 3986 unreserved characters, so a free
/// text location ("San Francisco") is a valid single path segment.
fn writePercentEncoded(c: *Cursor, s: []const u8) Error!void {
    for (s) |ch| {
        if (isUnreserved(ch)) {
            try c.byte(ch);
        } else {
            try c.hexByte(ch);
        }
    }
}

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~' or c == ',';
}

// ---- tests ------------------------------------------------------------------

test "buildWeatherRequest percent-encodes the location and forces metric" {
    var buf: [256]u8 = undefined;
    const req = try buildWeatherRequest(&buf, weather_host, "San Francisco");
    try std.testing.expect(std.mem.startsWith(u8, req, "GET /San%20Francisco?format=j1 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: wttr.in\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, req, "\r\n\r\n"));
}

test "buildWeatherRequest rejects an empty location" {
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidLocation, buildWeatherRequest(&buf, weather_host, ""));
}

test "parseWeather parses a wttr.in one-line body (metric)" {
    const w = try parseWeather("+33°C|↑21km/h|Partly cloudy|Austin\n");
    try std.testing.expectEqual(@as(f64, 33), w.reading.temp_c);
    try std.testing.expectEqual(@as(f64, 21), w.reading.wind_kph);
    try std.testing.expectEqualStrings("Partly cloudy", w.reading.desc);
    try std.testing.expectEqualStrings("Austin", w.location);
}

test "parseWeather handles a negative temperature and missing fields" {
    const w = try parseWeather("-4°C|↓7km/h|Snow|Oslo");
    try std.testing.expectEqual(@as(f64, -4), w.reading.temp_c);
    try std.testing.expectEqual(@as(f64, 7), w.reading.wind_kph);
    try std.testing.expectEqualStrings("Snow", w.reading.desc);
}

test "parseWeather then localize to US imperial round-trips through weather_units" {
    const w = try parseWeather("+22°C|↑20km/h|Partly cloudy|Austin");
    var buf: [128]u8 = undefined;
    const line = weather_units.renderLine(&buf, w.location, w.reading, weather_units.forCountry("US"));
    try std.testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", line);
}

test "parseRssTitles skips the feed title and returns headlines" {
    const body =
        \\<?xml version="1.0"?><rss><channel>
        \\<title>Example News</title>
        \\<item><title>First headline</title></item>
        \\<item><title><![CDATA[Second & headline]]></title></item>
        \\<item><title>Third headline</title></item>
        \\</channel></rss>
    ;
    var out: [2][]const u8 = undefined;
    const titles = parseRssTitles(body, &out);
    try std.testing.expectEqual(@as(usize, 2), titles.len);
    try std.testing.expectEqualStrings("First headline", titles[0]);
    try std.testing.expectEqualStrings("Second & headline", titles[1]);
}

test "parseWeatherReport reads wttr j1 current conditions and the midday forecast" {
    const body =
        \\{"current_condition":[{"temp_C":"22","FeelsLikeC":"21","humidity":"50","precipMM":"1.5","pressure":"1013","uvIndex":"3","visibility":"10","cloudcover":"75","observation_time":"12:11 PM","windspeedKmph":"20","winddir16Point":"N","weatherDesc":[{"value":"Partly cloudy "}]}],"nearest_area":[{"areaName":[{"value":"Austin"}],"region":[{"value":"Texas"}]}],"weather":[{"date":"2026-10-19","maxtempC":"25","mintempC":"14","astronomy":[{"sunrise":"07:36 AM","sunset":"06:55 PM"}],"hourly":[{"time":"0","precipMM":"0.5","chanceofsnow":"10","weatherDesc":[{"value":"Cloud"}]},{"time":"1200","precipMM":"1.0","chanceofrain":"40","chanceofthunder":"5","weatherDesc":[{"value":"Rain"}]}]}]}
    ;
    const report = try parseWeatherReport(body);
    try std.testing.expectEqual(@as(f64, 22), report.reading.temp_c);
    try std.testing.expectEqual(@as(f64, 21), report.reading.feels_c);
    try std.testing.expectEqual(@as(u8, 50), report.reading.humidity_pct);
    try std.testing.expectEqual(@as(f64, 1.5), report.reading.precip_mm);
    try std.testing.expectEqual(@as(u16, 1013), report.reading.pressure_hpa);
    try std.testing.expectEqual(@as(u8, 3), report.reading.uv_index);
    try std.testing.expectEqual(@as(u16, 10), report.reading.visibility_km);
    try std.testing.expectEqual(@as(f64, 20), report.reading.wind_kph);
    try std.testing.expectEqualStrings("N", report.reading.wind_dir);
    try std.testing.expectEqualStrings("Partly cloudy", report.reading.desc);
    try std.testing.expectEqualStrings("Austin", report.location);
    try std.testing.expectEqualStrings("Texas", report.region);
    try std.testing.expect((report.reading.flags & weather_units.flag_rich) != 0);
    try std.testing.expectEqual(@as(usize, 1), report.day_count);
    try std.testing.expectEqualStrings("2026-10-19", report.days[0].label);
    try std.testing.expectEqual(@as(f64, 14), report.days[0].min_c);
    try std.testing.expectEqual(@as(f64, 25), report.days[0].max_c);
    try std.testing.expectEqual(@as(f64, 1.5), report.days[0].precip_mm);
    try std.testing.expectEqualStrings("Rain", report.days[0].desc);
    try std.testing.expect(report.days[0].has_precip);
    try std.testing.expect(report.reading.has_cloud);
    try std.testing.expectEqual(@as(u8, 75), report.reading.cloud_pct);
    try std.testing.expectEqualStrings("12:11 PM", report.reading.obs);
    try std.testing.expectEqual(@as(u8, 40), report.days[0].rain_pct);
    try std.testing.expectEqual(@as(u8, 10), report.days[0].snow_pct);
    try std.testing.expectEqual(@as(u8, 5), report.days[0].thunder_pct);
    try std.testing.expectEqual(@as(u8, 40), report.reading.rain_pct);
    try std.testing.expectEqualStrings("07:36 AM", report.days[0].sunrise);
    try std.testing.expectEqualStrings("06:55 PM", report.days[0].sunset);
}

test "parseWeatherReport reads a pretty-printed three-day j1 document" {
    const body =
        \\{
        \\  "current_condition": [
        \\    {
        \\      "temp_C": "14",
        \\      "FeelsLikeC": "12",
        \\      "humidity": "46",
        \\      "precipMM": "0.0",
        \\      "pressure": "1023",
        \\      "uvIndex": "0",
        \\      "visibility": "10",
        \\      "cloudcover": "100",
        \\      "windspeedKmph": "4",
        \\      "winddir16Point": "SE",
        \\      "weatherDesc": [ { "value": "Overcast " } ]
        \\    }
        \\  ],
        \\  "nearest_area": [ { "areaName": [ { "value": "Austin" } ], "region": [ { "value": "Texas" } ] } ],
        \\  "weather": [
        \\    {
        \\      "date": "2026-10-19",
        \\      "maxtempC": "24",
        \\      "mintempC": "14",
        \\      "astronomy": [ { "sunrise": "07:36 AM", "sunset": "06:55 PM" } ],
        \\      "hourly": [
        \\        { "time": "0", "precipMM": "0.0", "chanceofrain": "2", "weatherDesc": [ { "value": "Cloudy" } ] },
        \\        { "time": "1200", "precipMM": "0.0", "chanceofrain": "11", "chanceofthunder": "1", "weatherDesc": [ { "value": "Overcast" } ] }
        \\      ]
        \\    },
        \\    {
        \\      "date": "2026-10-20",
        \\      "maxtempC": "28",
        \\      "mintempC": "16",
        \\      "hourly": [ { "time": "1200", "precipMM": "0.0", "chanceofrain": "0", "chanceofsnow": "40", "chanceofthunder": "5", "weatherDesc": [ { "value": "Snow" } ] } ]
        \\    },
        \\    {
        \\      "date": "2026-10-21",
        \\      "maxtempC": "29",
        \\      "mintempC": "19",
        \\      "hourly": [ { "time": "900", "precipMM": "1.0", "chanceofrain": "10", "chanceofthunder": "30", "weatherDesc": [ { "value": "Thunder" } ] } ]
        \\    }
        \\  ]
        \\}
    ;
    const report = try parseWeatherReport(body);
    try std.testing.expectEqualStrings("Austin", report.location);
    try std.testing.expectEqual(@as(f64, 14), report.reading.temp_c);
    try std.testing.expect((report.reading.flags & weather_units.flag_uv) != 0);
    try std.testing.expectEqual(@as(u8, 0), report.reading.uv_index);
    try std.testing.expect((report.reading.flags & weather_units.flag_precip) != 0);
    try std.testing.expectEqual(@as(f64, 0), report.reading.precip_mm);
    try std.testing.expectEqual(@as(u8, 11), report.reading.rain_pct);
    try std.testing.expectEqual(@as(usize, 3), report.day_count);
    try std.testing.expect(!report.days[0].has_precip);
    try std.testing.expectEqualStrings("Overcast", report.days[0].desc);
    try std.testing.expectEqual(@as(u8, 11), report.days[0].rain_pct);
    try std.testing.expectEqual(@as(u8, 40), report.days[1].snow_pct);
    try std.testing.expectEqual(@as(u8, 30), report.days[2].thunder_pct);
    try std.testing.expect(report.days[2].has_precip);
    try std.testing.expectEqual(@as(f64, 1.0), report.days[2].precip_mm);
}

test "parseWeatherReport accepts the legacy one-line body" {
    const report = try parseWeatherReport("+22°C|↑20km/h|Partly cloudy|Austin");
    try std.testing.expectEqual(@as(f64, 22), report.reading.temp_c);
    try std.testing.expect((report.reading.flags & weather_units.flag_rich) != 0);
    try std.testing.expect((report.reading.flags & weather_units.flag_feels) == 0);
    try std.testing.expectEqual(@as(usize, 0), report.day_count);
}

test "parseRssItems keeps the publication time and description" {
    const body =
        \\<?xml version="1.0"?><rss><channel><title>Feed</title>
        \\<item><title>First headline</title><pubDate>Mon, 19 Oct 2026 15:04:05 GMT</pubDate><description><![CDATA[<p>A short deck</p>]]></description></item>
        \\<item><title>Second</title><updated>2026-10-19T13:04:05Z</updated></item>
        \\</channel></rss>
    ;
    var items: [4]RssItem = undefined;
    const got = parseRssItems(body, &items);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("First headline", got[0].title);
    try std.testing.expectEqual(@as(i64, 1792422245), got[0].published_unix);
    try std.testing.expect(std.mem.indexOf(u8, got[0].deck, "A short deck") != null);
    try std.testing.expectEqual(@as(i64, 1792422245 - 7200), got[1].published_unix);

    var packed_line: [180]u8 = undefined;
    const line = packHeadline(&packed_line, got[0].published_unix, got[0].title, got[0].deck);
    const view = unpackHeadline(line);
    try std.testing.expectEqualStrings("First headline", view.title);
    try std.testing.expectEqualStrings("A short deck", view.deck);
    try std.testing.expectEqual(got[0].published_unix, view.epoch);
    var shown: [128]u8 = undefined;
    try std.testing.expectEqualStrings("  1. [2h] First headline - A short deck", formatHeadline(&shown, 1, line, got[0].published_unix + 7200));
    try std.testing.expectEqualStrings("Plain title", unpackHeadline("Plain title").title);
}

test "httpBody splits on the header terminator" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n+10°C|↑5km/h|Clear|Paris";
    try std.testing.expectEqualStrings("+10°C|↑5km/h|Clear|Paris", httpBody(resp));
}

test "httpPayload decodes a chunked body and rejects a non-2xx status" {
    const json = "{\"current_condition\":[{\"temp_C\":\"14\",\"weatherDesc\":[{\"value\":\"Overcast\"}]}],\"nearest_area\":[{\"areaName\":[{\"value\":\"Austin\"}]}],\"weather\":[{\"date\":\"2026-10-19\",\"maxtempC\":\"24\",\"mintempC\":\"14\",\"hourly\":[{\"time\":\"1200\",\"precipMM\":\"0.0\",\"chanceofrain\":\"11\",\"weatherDesc\":[{\"value\":\"Overcast\"}]}]}]}";
    const split = 40;
    var raw: [1400]u8 = undefined;
    const msg = std.fmt.bufPrint(&raw, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n{x}\r\n{s}\r\n0\r\n\r\n", .{
        split,
        json[0..split],
        json.len - split,
        json[split..],
    }) catch unreachable;
    try std.testing.expect(httpBody(msg)[0] != '{');
    const body = httpPayload(msg) orelse return error.ParseFailed;
    const report = try parseWeatherReport(body);
    try std.testing.expectEqualStrings("Austin", report.location);
    try std.testing.expectEqual(@as(f64, 14), report.reading.temp_c);
    try std.testing.expectEqual(@as(usize, 1), report.day_count);
    try std.testing.expectEqual(@as(u8, 11), report.days[0].rain_pct);
    try std.testing.expect((report.reading.flags & weather_units.flag_rich) != 0);

    var missing = ("HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}").*;
    try std.testing.expect(httpPayload(&missing) == null);
    var framed = ("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntrueJUNK").*;
    try std.testing.expectEqualStrings("true", httpPayload(&framed).?);
}

test "packHeadline decodes markup, entities, and collapsed space" {
    var packed_line: [180]u8 = undefined;
    const line = packHeadline(&packed_line, 1792422245, "Tom&#8217;s win", "<p>Jane&rsquo;s note&hellip;</p>  <b>today</b>");
    const view = unpackHeadline(line);
    try std.testing.expectEqualStrings("Tom’s win", view.title);
    try std.testing.expectEqualStrings("Jane’s note… today", view.deck);
}
