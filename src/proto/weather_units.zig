// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Locale-correct weather unit formatting.
//!
//! Weather readings are stored canonically in metric (°C, km/h, mm) and rendered
//! into the units a given country/region actually uses, so a US client sees
//! "72°F, wind 8 mph" while a French client sees "22°C, vent 13 km/h" from the
//! same reading. Pure `std`, allocation-free (caller supplies the buffer);
//! natively unit-tested.
const std = @import("std");

/// The unit convention to render with.
///   * metric   — °C, km/h, mm        (most of the world)
///   * imperial — °F, mph, in         (US + a handful of territories)
///   * uk       — °C, mph, mm         (UK: metric temperature, imperial wind)
pub const UnitSystem = enum { metric, imperial, uk };

/// Pick the unit system for an ISO 3166-1 alpha-2 country code (case-insensitive).
/// US states all map to `imperial` via the "US" code. Unknown codes default to
/// metric (the global norm).
pub fn forCountry(cc: []const u8) UnitSystem {
    var up: [2]u8 = .{ ' ', ' ' };
    if (cc.len >= 1) up[0] = std.ascii.toUpper(cc[0]);
    if (cc.len >= 2) up[1] = std.ascii.toUpper(cc[1]);
    const code = up[0..2];

    // United Kingdom: Celsius temperatures but miles-per-hour winds.
    if (std.mem.eql(u8, code, "GB") or std.mem.eql(u8, code, "UK")) return .uk;

    // Countries that report weather in imperial units (US + small territories
    // that follow US conventions).
    const imperial_codes = [_][]const u8{ "US", "BS", "BZ", "KY", "PW", "FM", "MH", "LR", "MM" };
    for (imperial_codes) |ic| {
        if (std.mem.eql(u8, code, ic)) return .imperial;
    }
    return .metric;
}

/// Bits on `Reading.flags`. Absent bits stay zero so a classic temp/wind/desc
/// row (and a Helix geo snapshot from the previous image) still renders as the
/// original one-liner. `flag_rich` means this process parsed a current report.
pub const flag_feels: u8 = 1 << 0;
pub const flag_humidity: u8 = 1 << 1;
pub const flag_precip: u8 = 1 << 2;
pub const flag_pressure: u8 = 1 << 3;
pub const flag_uv: u8 = 1 << 4;
pub const flag_visibility: u8 = 1 << 5;
pub const flag_wind_dir: u8 = 1 << 6;
pub const flag_rich: u8 = 1 << 7;

pub const max_days = 3;

/// A canonical (metric) weather reading.
pub const Reading = struct {
    temp_c: f64 = 0,
    wind_kph: f64 = 0,
    precip_mm: f64 = 0,
    feels_c: f64 = 0,
    humidity_pct: u8 = 0,
    pressure_hpa: u16 = 0,
    uv_index: u8 = 0,
    visibility_km: u16 = 0,
    flags: u8 = 0,
    /// Free-text condition (e.g. "Partly cloudy"); rendered verbatim.
    desc: []const u8 = "",
    /// 16-point compass from the source ("N", "ESE"); empty when unknown.
    wind_dir: []const u8 = "",
};

/// One civil day of a forecast. Temperatures are metric. `label` is `YYYY-MM-DD`
/// when the source gave a date.
pub const Day = struct {
    label: []const u8 = "",
    min_c: f64 = 0,
    max_c: f64 = 0,
    precip_mm: f64 = 0,
    desc: []const u8 = "",
    has_precip: bool = false,
};

fn roundI(v: f64) i64 {
    return @intFromFloat(@round(v));
}

/// Format a temperature into `buf`, e.g. "72°F" or "22°C".
pub fn formatTemp(temp_c: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d}°F", .{roundI(temp_c * 9.0 / 5.0 + 32.0)}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d}°C", .{roundI(temp_c)}) catch buf[0..0],
    };
}

/// Format a wind speed into `buf`, e.g. "8 mph" or "13 km/h".
pub fn formatWind(wind_kph: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial, .uk => std.fmt.bufPrint(buf, "{d} mph", .{roundI(wind_kph * 0.621371)}) catch buf[0..0],
        .metric => std.fmt.bufPrint(buf, "{d} km/h", .{roundI(wind_kph)}) catch buf[0..0],
    };
}

/// Format a precipitation amount into `buf`, e.g. "0.2 in" or "5 mm".
pub fn formatPrecip(precip_mm: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d:.2} in", .{precip_mm / 25.4}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d} mm", .{roundI(precip_mm)}) catch buf[0..0],
    };
}

/// Station pressure. Imperial uses inches of mercury; everyone else uses hPa.
pub fn formatPressure(hpa: u16, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d:.2} inHg", .{@as(f64, @floatFromInt(hpa)) / 33.8638866667}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d} hPa", .{hpa}) catch buf[0..0],
    };
}

/// Horizontal visibility. `km` is the canonical unit.
pub fn formatVisibility(km: u16, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d} mi", .{roundI(@as(f64, @floatFromInt(km)) * 0.621371)}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d} km", .{km}) catch buf[0..0],
    };
}

/// Unix seconds for a civil UTC time, or null when the date is not a real day.
pub fn civilUnix(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) ?i64 {
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    const days = daysFromCivil(year, month, day);
    return @as(i64, days) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

/// Resolve a unit system from a config override and a country code. `units` is
/// one of "metric"/"imperial"/"uk"; anything else (incl. "auto"/"") falls back
/// to the country mapping.
pub fn resolveSystem(units: []const u8, country: []const u8) UnitSystem {
    if (std.ascii.eqlIgnoreCase(units, "metric")) return .metric;
    if (std.ascii.eqlIgnoreCase(units, "imperial")) return .imperial;
    if (std.ascii.eqlIgnoreCase(units, "uk")) return .uk;
    return forCountry(country);
}

/// A weather reading parsed from a source file, with its location/country.
pub const Forecast = struct {
    reading: Reading = .{},
    location: []const u8 = "",
    country: []const u8 = "",
    days: [max_days]Day = .{ .{}, .{}, .{} },
    day_count: usize = 0,
};

/// Parse a simple `key=value` source file (one pair per line) into a `Forecast`.
/// Recognized keys: temp_c, wind_kph, precip_mm, desc, location, country.
/// Unknown keys and malformed numbers are ignored; slices borrow `text`.
pub fn parseForecast(text: []const u8) Forecast {
    var f = Forecast{};
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.eql(u8, key, "temp_c")) {
            f.reading.temp_c = std.fmt.parseFloat(f64, val) catch f.reading.temp_c;
        } else if (std.mem.eql(u8, key, "wind_kph")) {
            f.reading.wind_kph = std.fmt.parseFloat(f64, val) catch f.reading.wind_kph;
        } else if (std.mem.eql(u8, key, "precip_mm")) {
            f.reading.precip_mm = std.fmt.parseFloat(f64, val) catch f.reading.precip_mm;
            f.reading.flags |= flag_precip;
        } else if (std.mem.eql(u8, key, "feels_c")) {
            f.reading.feels_c = std.fmt.parseFloat(f64, val) catch f.reading.feels_c;
            f.reading.flags |= flag_feels;
        } else if (std.mem.eql(u8, key, "humidity_pct")) {
            f.reading.humidity_pct = parseU8(val) orelse f.reading.humidity_pct;
            f.reading.flags |= flag_humidity;
        } else if (std.mem.eql(u8, key, "pressure_hpa")) {
            f.reading.pressure_hpa = parseU16(val) orelse f.reading.pressure_hpa;
            f.reading.flags |= flag_pressure;
        } else if (std.mem.eql(u8, key, "uv")) {
            f.reading.uv_index = parseU8(val) orelse f.reading.uv_index;
            f.reading.flags |= flag_uv;
        } else if (std.mem.eql(u8, key, "visibility_km")) {
            f.reading.visibility_km = parseU16(val) orelse f.reading.visibility_km;
            f.reading.flags |= flag_visibility;
        } else if (std.mem.eql(u8, key, "wind_dir")) {
            f.reading.wind_dir = val;
            f.reading.flags |= flag_wind_dir;
        } else if (std.mem.eql(u8, key, "desc")) {
            f.reading.desc = val;
        } else if (std.mem.eql(u8, key, "location")) {
            f.location = val;
        } else if (std.mem.eql(u8, key, "country")) {
            f.country = val;
        } else if (dayIndex(key)) |slot| {
            const day = &f.days[slot.index];
            if (slot.index + 1 > f.day_count) f.day_count = slot.index + 1;
            if (std.mem.eql(u8, slot.field, "label")) {
                day.label = val;
            } else if (std.mem.eql(u8, slot.field, "min_c")) {
                day.min_c = std.fmt.parseFloat(f64, val) catch day.min_c;
            } else if (std.mem.eql(u8, slot.field, "max_c")) {
                day.max_c = std.fmt.parseFloat(f64, val) catch day.max_c;
            } else if (std.mem.eql(u8, slot.field, "precip_mm")) {
                day.precip_mm = std.fmt.parseFloat(f64, val) catch day.precip_mm;
                day.has_precip = true;
            } else if (std.mem.eql(u8, slot.field, "desc")) {
                day.desc = val;
            }
        }
    }
    if (f.reading.flags != 0) f.reading.flags |= flag_rich;
    return f;
}

/// Render a one-line localized weather summary into `buf`, e.g.
/// "Austin: 72°F, Partly cloudy, wind 8 mph". An empty `desc` is omitted.
pub fn renderLine(buf: []u8, location: []const u8, reading: Reading, sys: UnitSystem) []const u8 {
    var tb: [16]u8 = undefined;
    var wb: [16]u8 = undefined;
    const temp = formatTemp(reading.temp_c, sys, &tb);
    const wind = formatWind(reading.wind_kph, sys, &wb);
    if (reading.desc.len != 0) {
        return std.fmt.bufPrint(buf, "{s}: {s}, {s}, wind {s}", .{ location, temp, reading.desc, wind }) catch buf[0..0];
    }
    return std.fmt.bufPrint(buf, "{s}: {s}, wind {s}", .{ location, temp, wind }) catch buf[0..0];
}

pub const Report = struct {
    primary: []const u8 = "",
    detail: []const u8 = "",
};

/// Current conditions. A reading with no detail flags uses `renderLine` so a
/// classic cache row stays byte-identical. Feels-like and compass go on the
/// primary line; humidity, precip, pressure, UV, and visibility go on `detail`.
pub fn renderReport(primary: []u8, detail: []u8, location: []const u8, reading: Reading, sys: UnitSystem) Report {
    const extra = reading.flags & (flag_feels | flag_wind_dir | flag_humidity | flag_precip | flag_pressure | flag_uv | flag_visibility);
    if (extra == 0) {
        return .{ .primary = renderLine(primary, location, reading, sys), .detail = detail[0..0] };
    }
    var tb: [16]u8 = undefined;
    var fb: [16]u8 = undefined;
    var wb: [16]u8 = undefined;
    const temp = formatTemp(reading.temp_c, sys, &tb);
    const wind = formatWind(reading.wind_kph, sys, &wb);
    var line: []const u8 = undefined;
    if ((reading.flags & flag_feels) != 0) {
        const feels = formatTemp(reading.feels_c, sys, &fb);
        if ((reading.flags & flag_wind_dir) != 0 and reading.wind_dir.len != 0 and reading.desc.len != 0) {
            line = std.fmt.bufPrint(primary, "{s}: {s} (feels {s}), {s}, wind {s} {s}", .{ location, temp, feels, reading.desc, reading.wind_dir, wind }) catch primary[0..0];
        } else if ((reading.flags & flag_wind_dir) != 0 and reading.wind_dir.len != 0) {
            line = std.fmt.bufPrint(primary, "{s}: {s} (feels {s}), wind {s} {s}", .{ location, temp, feels, reading.wind_dir, wind }) catch primary[0..0];
        } else if (reading.desc.len != 0) {
            line = std.fmt.bufPrint(primary, "{s}: {s} (feels {s}), {s}, wind {s}", .{ location, temp, feels, reading.desc, wind }) catch primary[0..0];
        } else {
            line = std.fmt.bufPrint(primary, "{s}: {s} (feels {s}), wind {s}", .{ location, temp, feels, wind }) catch primary[0..0];
        }
    } else if ((reading.flags & flag_wind_dir) != 0 and reading.wind_dir.len != 0 and reading.desc.len != 0) {
        line = std.fmt.bufPrint(primary, "{s}: {s}, {s}, wind {s} {s}", .{ location, temp, reading.desc, reading.wind_dir, wind }) catch primary[0..0];
    } else if ((reading.flags & flag_wind_dir) != 0 and reading.wind_dir.len != 0) {
        line = std.fmt.bufPrint(primary, "{s}: {s}, wind {s} {s}", .{ location, temp, reading.wind_dir, wind }) catch primary[0..0];
    } else {
        line = renderLine(primary, location, reading, sys);
    }

    var n: usize = 0;
    if ((reading.flags & flag_humidity) != 0) {
        var piece: [24]u8 = undefined;
        appendPiece(detail, &n, std.fmt.bufPrint(&piece, "humidity {d}%", .{reading.humidity_pct}) catch "");
    }
    if ((reading.flags & flag_precip) != 0) {
        var pb: [16]u8 = undefined;
        const precip = formatPrecip(reading.precip_mm, sys, &pb);
        var piece: [32]u8 = undefined;
        appendPiece(detail, &n, std.fmt.bufPrint(&piece, "precip {s}", .{precip}) catch "");
    }
    if ((reading.flags & flag_pressure) != 0) {
        var pb: [16]u8 = undefined;
        appendPiece(detail, &n, formatPressure(reading.pressure_hpa, sys, &pb));
    }
    if ((reading.flags & flag_uv) != 0) {
        var piece: [16]u8 = undefined;
        appendPiece(detail, &n, std.fmt.bufPrint(&piece, "UV {d}", .{reading.uv_index}) catch "");
    }
    if ((reading.flags & flag_visibility) != 0) {
        var vb: [16]u8 = undefined;
        const vis = formatVisibility(reading.visibility_km, sys, &vb);
        var piece: [24]u8 = undefined;
        appendPiece(detail, &n, std.fmt.bufPrint(&piece, "vis {s}", .{vis}) catch "");
    }
    return .{ .primary = line, .detail = detail[0..n] };
}

/// One forecast day, e.g. "Mon 19: 78/62°F, Partly cloudy, precip 0.10 in".
/// The unit is written once after the high/low pair.
pub fn renderDay(buf: []u8, day: Day, sys: UnitSystem) []const u8 {
    var label_buf: [16]u8 = undefined;
    const label = formatDayLabel(day.label, &label_buf);
    var pair: [24]u8 = undefined;
    const temps = formatTempPair(day.max_c, day.min_c, sys, &pair);
    if (day.desc.len != 0 and day.has_precip) {
        var pb: [16]u8 = undefined;
        const precip = formatPrecip(day.precip_mm, sys, &pb);
        return std.fmt.bufPrint(buf, "{s}: {s}, {s}, precip {s}", .{ label, temps, day.desc, precip }) catch buf[0..0];
    }
    if (day.desc.len != 0) {
        return std.fmt.bufPrint(buf, "{s}: {s}, {s}", .{ label, temps, day.desc }) catch buf[0..0];
    }
    if (day.has_precip) {
        var pb: [16]u8 = undefined;
        const precip = formatPrecip(day.precip_mm, sys, &pb);
        return std.fmt.bufPrint(buf, "{s}: {s}, precip {s}", .{ label, temps, precip }) catch buf[0..0];
    }
    return std.fmt.bufPrint(buf, "{s}: {s}", .{ label, temps }) catch buf[0..0];
}

fn formatTempPair(max_c: f64, min_c: f64, sys: UnitSystem, buf: []u8) []const u8 {
    const hi = switch (sys) {
        .imperial => max_c * 9.0 / 5.0 + 32.0,
        .metric, .uk => max_c,
    };
    const lo = switch (sys) {
        .imperial => min_c * 9.0 / 5.0 + 32.0,
        .metric, .uk => min_c,
    };
    const unit: []const u8 = if (sys == .imperial) "°F" else "°C";
    return std.fmt.bufPrint(buf, "{d}/{d}{s}", .{ roundI(hi), roundI(lo), unit }) catch buf[0..0];
}

/// `YYYY-MM-DD` becomes "Mon 19". Any other label is returned unchanged.
pub fn formatDayLabel(label: []const u8, buf: []u8) []const u8 {
    if (!(label.len == 10 and label[4] == '-' and label[7] == '-')) return label;
    const year = std.fmt.parseInt(i32, label[0..4], 10) catch return label;
    const month = std.fmt.parseInt(u32, label[5..7], 10) catch return label;
    const day = std.fmt.parseInt(u32, label[8..10], 10) catch return label;
    if (month < 1 or month > 12 or day < 1 or day > 31) return label;
    const names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const weekday = weekdaySun0(year, month, day);
    return std.fmt.bufPrint(buf, "{s} {d}", .{ names[weekday], day }) catch label;
}

fn appendPiece(buf: []u8, n: *usize, piece: []const u8) void {
    if (piece.len == 0) return;
    const sep: usize = if (n.* == 0) 0 else 2;
    if (n.* + sep + piece.len > buf.len) return;
    if (sep != 0) {
        buf[n.*] = ',';
        buf[n.* + 1] = ' ';
    }
    @memcpy(buf[n.* + sep ..][0..piece.len], piece);
    n.* += sep + piece.len;
}

fn parseU8(s: []const u8) ?u8 {
    return std.fmt.parseInt(u8, s, 10) catch null;
}

fn parseU16(s: []const u8) ?u16 {
    return std.fmt.parseInt(u16, s, 10) catch null;
}

const DayKey = struct { index: usize, field: []const u8 };

fn dayIndex(key: []const u8) ?DayKey {
    if (key.len < 6 or key[0] != 'd' or key[1] != 'a' or key[2] != 'y' or key[4] != '_') return null;
    const index: usize = switch (key[3]) {
        '1' => 0,
        '2' => 1,
        '3' => 2,
        else => return null,
    };
    return .{ .index = index, .field = key[5..] };
}

/// Howard Hinnant's civil-from-days, inverted. Day 0 is 1970-01-01.
fn daysFromCivil(year: i32, month: u32, day: u32) i32 {
    var y = year;
    if (month <= 2) y -= 1;
    const era: i32 = @divFloor(y, 400);
    const yoe: u32 = @intCast(y - era * 400);
    const mp: i32 = @intCast(month);
    const adj: i32 = if (month > 2) -3 else 9;
    const doy: u32 = @intCast(@divFloor(153 * (mp + adj) + 2, 5) + @as(i32, @intCast(day)) - 1);
    const doe: u32 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + @as(i32, @intCast(doe)) - 719468;
}

fn weekdaySun0(year: i32, month: u32, day: u32) usize {
    const days = daysFromCivil(year, month, day);
    return @intCast(@mod(days + 4, 7));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "country code maps to the right unit system" {
    try testing.expectEqual(UnitSystem.imperial, forCountry("US"));
    try testing.expectEqual(UnitSystem.imperial, forCountry("us"));
    try testing.expectEqual(UnitSystem.imperial, forCountry("MM"));
    try testing.expectEqual(UnitSystem.uk, forCountry("GB"));
    try testing.expectEqual(UnitSystem.uk, forCountry("uk"));
    try testing.expectEqual(UnitSystem.metric, forCountry("FR"));
    try testing.expectEqual(UnitSystem.metric, forCountry("JP"));
    try testing.expectEqual(UnitSystem.metric, forCountry(""));
}

test "temperature renders per system" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("22°C", formatTemp(22.0, .metric, &b));
    try testing.expectEqualStrings("22°C", formatTemp(22.0, .uk, &b));
    try testing.expectEqualStrings("72°F", formatTemp(22.0, .imperial, &b)); // 22C ≈ 71.6 -> 72
    try testing.expectEqualStrings("32°F", formatTemp(0.0, .imperial, &b));
}

test "wind renders per system, including the UK mph quirk" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("20 km/h", formatWind(20.0, .metric, &b));
    try testing.expectEqualStrings("12 mph", formatWind(20.0, .imperial, &b)); // 20kph ≈ 12.4 -> 12
    try testing.expectEqualStrings("12 mph", formatWind(20.0, .uk, &b));
}

test "precip renders per system" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("5 mm", formatPrecip(5.0, .metric, &b));
    try testing.expectEqualStrings("0.20 in", formatPrecip(5.08, .imperial, &b));
}

test "renderLine produces a localized one-liner" {
    var b: [128]u8 = undefined;
    const r = Reading{ .temp_c = 22.0, .wind_kph = 20.0, .desc = "Partly cloudy" };
    try testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", renderLine(&b, "Austin", r, .imperial));
    try testing.expectEqualStrings("Paris: 22°C, Partly cloudy, wind 20 km/h", renderLine(&b, "Paris", r, .metric));
}

test "renderLine omits an empty description" {
    var b: [128]u8 = undefined;
    const r = Reading{ .temp_c = 10.0, .wind_kph = 0 };
    try testing.expectEqualStrings("Oslo: 10°C, wind 0 km/h", renderLine(&b, "Oslo", r, .metric));
}

test "resolveSystem honors override then country" {
    try testing.expectEqual(UnitSystem.imperial, resolveSystem("imperial", "FR"));
    try testing.expectEqual(UnitSystem.metric, resolveSystem("metric", "US"));
    try testing.expectEqual(UnitSystem.uk, resolveSystem("UK", "US"));
    try testing.expectEqual(UnitSystem.imperial, resolveSystem("auto", "US"));
    try testing.expectEqual(UnitSystem.metric, resolveSystem("", "DE"));
}

test "civil dates and forecast labels" {
    try testing.expectEqual(@as(i64, 0), civilUnix(1970, 1, 1, 0, 0, 0).?);
    try testing.expectEqual(@as(i64, 946684800), civilUnix(2000, 1, 1, 0, 0, 0).?);
    try testing.expectEqual(@as(i64, 1792422245), civilUnix(2026, 10, 19, 15, 4, 5).?);
    var label: [16]u8 = undefined;
    try testing.expectEqualStrings("Mon 19", formatDayLabel("2026-10-19", &label));
    try testing.expectEqualStrings("Sun 18", formatDayLabel("2026-10-18", &label));
    try testing.expect(civilUnix(2026, 13, 1, 0, 0, 0) == null);
}

test "renderReport adds feels-like and a detail line without changing the classic line" {
    var primary: [160]u8 = undefined;
    var detail: [160]u8 = undefined;
    const classic = Reading{ .temp_c = 22.0, .wind_kph = 20.0, .desc = "Partly cloudy" };
    const plain = renderReport(&primary, &detail, "Austin", classic, .imperial);
    try testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", plain.primary);
    try testing.expectEqual(@as(usize, 0), plain.detail.len);

    const rich = Reading{
        .temp_c = 22.0,
        .wind_kph = 20.0,
        .feels_c = 23.0,
        .humidity_pct = 45,
        .precip_mm = 5.08,
        .pressure_hpa = 1013,
        .uv_index = 6,
        .visibility_km = 10,
        .flags = flag_feels | flag_humidity | flag_precip | flag_pressure | flag_uv | flag_visibility | flag_wind_dir | flag_rich,
        .desc = "Partly cloudy",
        .wind_dir = "N",
    };
    const report = renderReport(&primary, &detail, "Austin", rich, .imperial);
    try testing.expectEqualStrings("Austin: 72°F (feels 73°F), Partly cloudy, wind N 12 mph", report.primary);
    try testing.expectEqualStrings("humidity 45%, precip 0.20 in, 29.91 inHg, UV 6, vis 6 mi", report.detail);

    const day = Day{ .label = "2026-10-19", .min_c = 14, .max_c = 25, .precip_mm = 1.5, .desc = "Rain", .has_precip = true };
    var day_buf: [96]u8 = undefined;
    try testing.expectEqualStrings("Mon 19: 77/57°F, Rain, precip 0.06 in", renderDay(&day_buf, day, .imperial));
}

test "parseForecast reads key=value source and renders localized" {
    const src =
        \\# sample source written by an external updater
        \\location=Austin
        \\country=US
        \\temp_c=22.0
        \\wind_kph=20
        \\desc=Partly cloudy
        \\feels_c=23
        \\day1_label=2026-10-19
        \\day1_min_c=14
        \\day1_max_c=25
        \\day1_desc=Rain
        \\
    ;
    const f = parseForecast(src);
    try testing.expect((f.reading.flags & flag_feels) != 0);
    try testing.expectEqual(@as(usize, 1), f.day_count);
    try testing.expectEqualStrings("2026-10-19", f.days[0].label);
    try testing.expectEqualStrings("Rain", f.days[0].desc);
    try testing.expectEqualStrings("Austin", f.location);
    try testing.expectEqualStrings("US", f.country);
    try testing.expectEqualStrings("Partly cloudy", f.reading.desc);
    try testing.expectEqual(@as(f64, 22.0), f.reading.temp_c);

    var b: [128]u8 = undefined;
    const sys = resolveSystem("auto", f.country);
    try testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", renderLine(&b, f.location, f.reading, sys));
}
