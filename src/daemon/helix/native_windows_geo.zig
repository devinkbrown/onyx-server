// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for Geo weather/news slots and FIFO fetch work.
//! The outer handoff authenticates these bytes. No thread or process pointer is
//! serialized, and source capture requires its real pause and producer fence.
const std = @import("std");
const geo = @import("../geo_services.zig");
const weather_units = @import("../../proto/weather_units.zig");
const runtime_pause = @import("../runtime_pause.zig");

const magic = "HXGE";
const version_v1: u16 = 1;
const version_v2: u16 = 2;
const header_len: usize = 64;
/// Frozen v1 weather row. v2 appends `weather_tail_len` and is what this image writes.
const weather_len_v1: usize = 28 + geo.max_key + geo.max_loc + geo.max_desc;
const day_len: usize = 70;
const weather_tail_len: usize = 32 + weather_units.max_days * day_len;
const weather_len: usize = weather_len_v1 + weather_tail_len;
const news_len: usize = 22 + geo.max_key + geo.max_headline * geo.max_headlines;
const job_len: usize = 2 + geo.max_key;
pub const max_capture_bytes: usize = @sizeOf(geo.Snapshot) +
    geo.weather_slots * @sizeOf(geo.WeatherCarry) +
    geo.news_slots * @sizeOf(geo.NewsCarry) +
    geo.job_capacity * @sizeOf(geo.JobCarry);
pub const max_checkpoint_bytes: usize = header_len +
    geo.weather_slots * weather_len + geo.news_slots * news_len +
    geo.job_capacity * job_len;
pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, ConfigMismatch, TooLarge };

comptime {
    if (geo.max_key > std.math.maxInt(u8) or geo.max_loc > std.math.maxInt(u8) or
        geo.max_desc > std.math.maxInt(u8) or geo.max_headlines > std.math.maxInt(u8) or
        geo.weather_slots > std.math.maxInt(u16) or geo.news_slots > std.math.maxInt(u16) or
        geo.job_capacity > std.math.maxInt(u16) or max_checkpoint_bytes > std.math.maxInt(u32))
        @compileError("Windows Geo checkpoint exceeds its wire bounds");
}

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

fn weatherLenOf(bytes: []const u8) error{InvalidSnapshot}!usize {
    if (bytes.len < 6 or !isCheckpoint(bytes)) return error.InvalidSnapshot;
    return switch (std.mem.readInt(u16, bytes[4..6], .big)) {
        version_v1 => weather_len_v1,
        version_v2 => weather_len,
        else => error.InvalidSnapshot,
    };
}

fn countJobs(bytes: []const u8) error{InvalidSnapshot}!usize {
    const row_len = try weatherLenOf(bytes);
    if (bytes.len < header_len + geo.weather_slots * row_len + geo.news_slots * news_len or
        bytes.len > max_checkpoint_bytes or
        !std.mem.allEqual(u8, bytes[6..8], 0) or
        std.mem.readInt(u16, bytes[8..10], .big) != geo.weather_slots or
        std.mem.readInt(u16, bytes[10..12], .big) != geo.news_slots or
        bytes[15] != 0 or !std.mem.allEqual(u8, bytes[60..64], 0) or
        std.mem.readInt(u32, bytes[56..60], .big) != bytes.len)
        return error.InvalidSnapshot;
    const count: usize = std.mem.readInt(u16, bytes[12..14], .big);
    if (count > geo.job_capacity or
        bytes.len != header_len + geo.weather_slots * row_len + geo.news_slots * news_len + count * job_len or
        std.enums.fromInt(geo.Execution, bytes[14]) == null)
        return error.InvalidSnapshot;
    return count;
}

/// Validate every bounded row, unused tail, enum, and duplicate without an
/// allocator. Config equality is checked separately against the candidate.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const job_count = try countJobs(bytes);
    const row_len = try weatherLenOf(bytes);
    var seen_weather: [geo.weather_slots][]const u8 = undefined;
    var weather_count: usize = 0;
    var seen_news: [geo.news_slots][]const u8 = undefined;
    var news_count: usize = 0;
    var seen_jobs: [geo.job_capacity]struct { kind: geo.JobKind, key: []const u8 } = undefined;
    var pos: usize = header_len;
    for (0..geo.weather_slots) |_| {
        const row = bytes[pos..][0..row_len];
        const state = std.enums.fromInt(geo.State, row[0]) orelse return error.InvalidSnapshot;
        const key_len: usize = row[1];
        const loc_len: usize = row[2];
        const desc_len: usize = row[3];
        const key = row[28..][0..geo.max_key];
        const loc = row[28 + geo.max_key ..][0..geo.max_loc];
        const desc = row[28 + geo.max_key + geo.max_loc ..][0..geo.max_desc];
        if (key_len > geo.max_key or loc_len > geo.max_loc or desc_len > geo.max_desc or
            !std.mem.allEqual(u8, key[key_len..], 0) or
            !std.mem.allEqual(u8, loc[loc_len..], 0) or
            !std.mem.allEqual(u8, desc[desc_len..], 0)) return error.InvalidSnapshot;
        if (state == .empty) {
            if (!std.mem.allEqual(u8, row[1..], 0)) return error.InvalidSnapshot;
        } else {
            if (key_len == 0) return error.InvalidSnapshot;
            for (seen_weather[0..weather_count]) |prior| if (std.mem.eql(u8, prior, key[0..key_len])) return error.InvalidSnapshot;
            seen_weather[weather_count] = key[0..key_len];
            weather_count += 1;
            if (row_len == weather_len) try validateWeatherTail(row[weather_len_v1..]);
        }
        pos += row_len;
    }
    for (0..geo.news_slots) |_| {
        const row = bytes[pos..][0..news_len];
        const state = std.enums.fromInt(geo.State, row[0]) orelse return error.InvalidSnapshot;
        const key_len: usize = row[1];
        const count: usize = row[2];
        if (row[3] != 0 or key_len > geo.max_key or count > geo.max_headlines) return error.InvalidSnapshot;
        const key = row[22..][0..geo.max_key];
        const text = row[22 + geo.max_key ..][0 .. geo.max_headline * geo.max_headlines];
        if (!std.mem.allEqual(u8, key[key_len..], 0)) return error.InvalidSnapshot;
        var text_len: usize = 0;
        for (0..geo.max_headlines) |i| {
            const len: usize = std.mem.readInt(u16, row[12 + 2 * i ..][0..2], .big);
            if ((i >= count and len != 0) or len > geo.max_headline) return error.InvalidSnapshot;
            text_len += len;
        }
        if (!std.mem.allEqual(u8, text[text_len..], 0)) return error.InvalidSnapshot;
        if (state == .empty) {
            if (!std.mem.allEqual(u8, row[1..], 0)) return error.InvalidSnapshot;
        } else {
            if (key_len == 0) return error.InvalidSnapshot;
            for (seen_news[0..news_count]) |prior| if (std.mem.eql(u8, prior, key[0..key_len])) return error.InvalidSnapshot;
            seen_news[news_count] = key[0..key_len];
            news_count += 1;
        }
        pos += news_len;
    }
    for (0..job_count) |i| {
        const row = bytes[pos..][0..job_len];
        const kind = std.enums.fromInt(geo.JobKind, row[0]) orelse return error.InvalidSnapshot;
        const key_len: usize = row[1];
        const key = row[2..];
        if (key_len == 0 or key_len > geo.max_key or !std.mem.allEqual(u8, key[key_len..], 0)) return error.InvalidSnapshot;
        for (seen_jobs[0..i]) |prior| if (prior.kind == kind and std.mem.eql(u8, prior.key, key[0..key_len])) return error.InvalidSnapshot;
        seen_jobs[i] = .{ .kind = kind, .key = key[0..key_len] };
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
}

fn checkSnapshot(snapshot: *const geo.Snapshot, opts: geo.Options) Error!void {
    snapshot.validate(opts, max_capture_bytes) catch |err| switch (err) {
        error.ConfigMismatch => return error.ConfigMismatch,
        error.Capacity => return error.TooLarge,
        else => return error.InvalidSnapshot,
    };
}

/// Serialize initialized fields only, preserving every physical cache slot.
pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: *const geo.Snapshot, opts: geo.Options) Error![]u8 {
    try checkSnapshot(snapshot, opts);
    const total = header_len + geo.weather_slots * weather_len + geo.news_slots * news_len + snapshot.jobs.len * job_len;
    const bytes = try allocator.alloc(u8, total);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version_v2, .big);
    std.mem.writeInt(u16, bytes[8..10], geo.weather_slots, .big);
    std.mem.writeInt(u16, bytes[10..12], geo.news_slots, .big);
    std.mem.writeInt(u16, bytes[12..14], @intCast(snapshot.jobs.len), .big);
    bytes[14] = @intFromEnum(snapshot.execution);
    std.mem.writeInt(u64, bytes[16..24], @bitCast(snapshot.captured_monotonic_ms), .big);
    @memcpy(bytes[24..56], &snapshot.options_digest);
    std.mem.writeInt(u32, bytes[56..60], @intCast(total), .big);
    var pos: usize = header_len;
    for (snapshot.weather) |entry| {
        const row = bytes[pos..][0..weather_len];
        row[0] = @intFromEnum(entry.state);
        row[1] = @intCast(entry.key_len);
        row[2] = @intCast(entry.loc_len);
        row[3] = @intCast(entry.desc_len);
        std.mem.writeInt(u64, row[4..12], entry.temp_c_bits, .big);
        std.mem.writeInt(u64, row[12..20], entry.wind_kph_bits, .big);
        std.mem.writeInt(u64, row[20..28], @bitCast(entry.fetched_ms), .big);
        @memcpy(row[28..][0..entry.key_len], entry.key[0..entry.key_len]);
        @memcpy(row[28 + geo.max_key ..][0..entry.loc_len], entry.location[0..entry.loc_len]);
        @memcpy(row[28 + geo.max_key + geo.max_loc ..][0..entry.desc_len], entry.description[0..entry.desc_len]);
        writeWeatherTail(row[weather_len_v1..], entry);
        pos += weather_len;
    }
    for (snapshot.news) |entry| {
        const row = bytes[pos..][0..news_len];
        row[0] = @intFromEnum(entry.state);
        row[1] = @intCast(entry.key_len);
        row[2] = entry.count;
        std.mem.writeInt(u64, row[4..12], @bitCast(entry.fetched_ms), .big);
        var text_len: usize = 0;
        for (entry.lens, 0..) |len, i| {
            std.mem.writeInt(u16, row[12 + 2 * i ..][0..2], len, .big);
            text_len += len;
        }
        @memcpy(row[22..][0..entry.key_len], entry.key[0..entry.key_len]);
        @memcpy(row[22 + geo.max_key ..][0..text_len], entry.text[0..text_len]);
        pos += news_len;
    }
    for (snapshot.jobs) |entry| {
        const row = bytes[pos..][0..job_len];
        row[0] = @intFromEnum(entry.kind);
        row[1] = @intCast(entry.key_len);
        @memcpy(row[2..][0..entry.key_len], entry.key[0..entry.key_len]);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    try validateCheckpoint(bytes);
    return bytes;
}

/// Decode into detached owned arrays; a malformed or mismatched image cannot
/// alter the candidate service, and allocation failure frees partial state.
pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8, opts: geo.Options) Error!geo.Snapshot {
    try validateCheckpoint(bytes);
    const digest = geo.optionsDigest(opts) catch return error.ConfigMismatch;
    if (!std.crypto.timing_safe.eql([32]u8, digest, bytes[24..56].*)) return error.ConfigMismatch;
    const job_count: usize = std.mem.readInt(u16, bytes[12..14], .big);
    const row_len = try weatherLenOf(bytes);
    const weather = try allocator.alloc(geo.WeatherCarry, geo.weather_slots);
    errdefer allocator.free(weather);
    const news = try allocator.alloc(geo.NewsCarry, geo.news_slots);
    errdefer allocator.free(news);
    const jobs = try allocator.alloc(geo.JobCarry, job_count);
    errdefer allocator.free(jobs);
    var pos: usize = header_len;
    for (weather) |*entry| {
        const row = bytes[pos..][0..row_len];
        entry.* = .{ .state = std.enums.fromInt(geo.State, row[0]).?, .key_len = row[1], .loc_len = row[2], .desc_len = row[3], .temp_c_bits = std.mem.readInt(u64, row[4..12], .big), .wind_kph_bits = std.mem.readInt(u64, row[12..20], .big), .fetched_ms = @bitCast(std.mem.readInt(u64, row[20..28], .big)) };
        @memcpy(&entry.key, row[28..][0..geo.max_key]);
        @memcpy(&entry.location, row[28 + geo.max_key ..][0..geo.max_loc]);
        @memcpy(&entry.description, row[28 + geo.max_key + geo.max_loc ..][0..geo.max_desc]);
        if (row_len == weather_len) readWeatherTail(row[weather_len_v1..], entry);
        pos += row_len;
    }
    for (news) |*entry| {
        const row = bytes[pos..][0..news_len];
        entry.* = .{ .state = std.enums.fromInt(geo.State, row[0]).?, .key_len = row[1], .count = row[2], .fetched_ms = @bitCast(std.mem.readInt(u64, row[4..12], .big)) };
        for (&entry.lens, 0..) |*len, i| len.* = std.mem.readInt(u16, row[12 + 2 * i ..][0..2], .big);
        @memcpy(&entry.key, row[22..][0..geo.max_key]);
        @memcpy(&entry.text, row[22 + geo.max_key ..][0 .. geo.max_headline * geo.max_headlines]);
        pos += news_len;
    }
    for (jobs) |*entry| {
        const row = bytes[pos..][0..job_len];
        entry.* = .{ .kind = std.enums.fromInt(geo.JobKind, row[0]).?, .key_len = row[1] };
        @memcpy(&entry.key, row[2..]);
        pos += job_len;
    }
    std.debug.assert(pos == bytes.len);
    const snapshot: geo.Snapshot = .{ .allocator = allocator, .weather = weather, .news = news, .jobs = jobs, .options_digest = bytes[24..56].*, .execution = std.enums.fromInt(geo.Execution, bytes[14]).?, .captured_monotonic_ms = @bitCast(std.mem.readInt(u64, bytes[16..24], .big)) };
    try checkSnapshot(&snapshot, opts);
    return snapshot;
}

pub fn captureFrozenEncoded(allocator: std.mem.Allocator, owner: *geo.Service, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) ![]u8 {
    var snapshot = try owner.captureFrozen(allocator, fence, token, max_capture_bytes);
    defer snapshot.deinit();
    return encodeSnapshot(allocator, &snapshot, owner.opts);
}

pub fn restoreEncoded(allocator: std.mem.Allocator, owner: *geo.Service, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner.opts);
    defer snapshot.deinit();
    try owner.restoreSnapshot(&snapshot, max_capture_bytes);
}

pub fn restoreEncodedParked(allocator: std.mem.Allocator, owner: *geo.Service, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner.opts);
    defer snapshot.deinit();
    try owner.restoreSnapshotParked(&snapshot, max_capture_bytes);
}

fn writeWeatherTail(tail: []u8, entry: geo.WeatherCarry) void {
    tail[0] = entry.flags;
    tail[1] = entry.humidity;
    tail[2] = entry.uv;
    tail[3] = entry.wind_dir_len;
    @memcpy(tail[4..7], &entry.wind_dir);
    std.mem.writeInt(u16, tail[8..10], entry.visibility, .big);
    std.mem.writeInt(u16, tail[10..12], entry.pressure, .big);
    std.mem.writeInt(u64, tail[12..20], entry.feels_bits, .big);
    std.mem.writeInt(u64, tail[20..28], entry.precip_bits, .big);
    tail[28] = entry.day_count;
    for (entry.days, 0..) |day, i| {
        const slot = tail[32 + i * day_len ..][0..day_len];
        slot[0] = day.flags;
        slot[1] = day.desc_len;
        slot[2] = day.label_len;
        std.mem.writeInt(u64, slot[4..12], day.min_bits, .big);
        std.mem.writeInt(u64, slot[12..20], day.max_bits, .big);
        std.mem.writeInt(u64, slot[20..28], day.precip_bits, .big);
        @memcpy(slot[28..38], &day.label);
        @memcpy(slot[38..70], &day.desc);
    }
}

fn readWeatherTail(tail: []const u8, entry: *geo.WeatherCarry) void {
    entry.flags = tail[0];
    entry.humidity = tail[1];
    entry.uv = tail[2];
    entry.wind_dir_len = tail[3];
    @memcpy(&entry.wind_dir, tail[4..7]);
    entry.visibility = std.mem.readInt(u16, tail[8..10], .big);
    entry.pressure = std.mem.readInt(u16, tail[10..12], .big);
    entry.feels_bits = std.mem.readInt(u64, tail[12..20], .big);
    entry.precip_bits = std.mem.readInt(u64, tail[20..28], .big);
    entry.day_count = tail[28];
    for (&entry.days, 0..) |*day, i| {
        const slot = tail[32 + i * day_len ..][0..day_len];
        day.flags = slot[0];
        day.desc_len = slot[1];
        day.label_len = slot[2];
        day.min_bits = std.mem.readInt(u64, slot[4..12], .big);
        day.max_bits = std.mem.readInt(u64, slot[12..20], .big);
        day.precip_bits = std.mem.readInt(u64, slot[20..28], .big);
        @memcpy(&day.label, slot[28..38]);
        @memcpy(&day.desc, slot[38..70]);
    }
}

fn validateWeatherTail(tail: []const u8) error{InvalidSnapshot}!void {
    if (tail.len != weather_tail_len or tail[7] != 0 or !std.mem.allEqual(u8, tail[29..32], 0)) return error.InvalidSnapshot;
    const flags = tail[0];
    const wind_len: usize = tail[3];
    if (wind_len > 3 or !std.mem.allEqual(u8, tail[4 + wind_len .. 7], 0)) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_humidity) == 0 and tail[1] != 0) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_uv) == 0 and tail[2] != 0) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_wind_dir) == 0 and wind_len != 0) return error.InvalidSnapshot;
    const visibility = std.mem.readInt(u16, tail[8..10], .big);
    const pressure = std.mem.readInt(u16, tail[10..12], .big);
    const feels = std.mem.readInt(u64, tail[12..20], .big);
    const precip = std.mem.readInt(u64, tail[20..28], .big);
    if ((flags & weather_units.flag_visibility) == 0 and visibility != 0) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_pressure) == 0 and pressure != 0) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_feels) == 0 and feels != 0) return error.InvalidSnapshot;
    if ((flags & weather_units.flag_precip) == 0 and precip != 0) return error.InvalidSnapshot;
    const day_count: usize = tail[28];
    if (day_count > weather_units.max_days) return error.InvalidSnapshot;
    for (0..weather_units.max_days) |i| {
        const slot = tail[32 + i * day_len ..][0..day_len];
        if (i >= day_count) {
            if (!std.mem.allEqual(u8, slot, 0)) return error.InvalidSnapshot;
            continue;
        }
        if ((slot[0] & ~@as(u8, 1)) != 0 or slot[3] != 0) return error.InvalidSnapshot;
        const desc_len: usize = slot[1];
        const label_len: usize = slot[2];
        if (desc_len > 32 or label_len > 10) return error.InvalidSnapshot;
        if (!std.mem.allEqual(u8, slot[28 + label_len .. 38], 0) or !std.mem.allEqual(u8, slot[38 + desc_len .. 70], 0)) return error.InvalidSnapshot;
        const day_precip = std.mem.readInt(u64, slot[20..28], .big);
        if ((slot[0] & 1) == 0 and day_precip != 0) return error.InvalidSnapshot;
    }
}

fn fixture(allocator: std.mem.Allocator, opts: geo.Options) !geo.Snapshot {
    const weather = try allocator.alloc(geo.WeatherCarry, geo.weather_slots);
    errdefer allocator.free(weather);
    const news = try allocator.alloc(geo.NewsCarry, geo.news_slots);
    errdefer allocator.free(news);
    const jobs = try allocator.alloc(geo.JobCarry, 2);
    errdefer allocator.free(jobs);
    for (weather) |*entry| entry.* = .{};
    for (news) |*entry| entry.* = .{};
    weather[7].state = .ready;
    weather[7].key_len = 4;
    @memcpy(weather[7].key[0..4], "oslo");
    weather[7].loc_len = 4;
    @memcpy(weather[7].location[0..4], "Oslo");
    weather[7].desc_len = 6;
    @memcpy(weather[7].description[0..6], "Clouds");
    weather[7].temp_c_bits = @bitCast(@as(f64, 5.5));
    weather[7].wind_kph_bits = @bitCast(@as(f64, 12.0));
    weather[7].fetched_ms = 123;
    weather[7].flags = weather_units.flag_feels | weather_units.flag_wind_dir | weather_units.flag_rich;
    weather[7].feels_bits = @bitCast(@as(f64, 4.0));
    weather[7].wind_dir_len = 1;
    weather[7].wind_dir[0] = 'N';
    weather[7].day_count = 1;
    weather[7].days[0].flags = 1;
    weather[7].days[0].label_len = 10;
    @memcpy(weather[7].days[0].label[0..10], "2026-10-19");
    weather[7].days[0].desc_len = 4;
    @memcpy(weather[7].days[0].desc[0..4], "Rain");
    weather[7].days[0].min_bits = @bitCast(@as(f64, 1.0));
    weather[7].days[0].max_bits = @bitCast(@as(f64, 6.0));
    news[3].state = .ready;
    news[3].key_len = 7;
    @memcpy(news[3].key[0..7], "src:bbc");
    news[3].count = 2;
    news[3].lens[0] = 5;
    news[3].lens[1] = 6;
    @memcpy(news[3].text[0..11], "firstsecond");
    news[3].fetched_ms = 456;
    jobs[0] = .{ .kind = .news, .key_len = 7 };
    @memcpy(jobs[0].key[0..7], "src:bbc");
    jobs[1] = .{ .kind = .weather, .key_len = 4 };
    @memcpy(jobs[1].key[0..4], "oslo");
    return .{ .allocator = allocator, .weather = weather, .news = news, .jobs = jobs, .options_digest = try geo.optionsDigest(opts), .execution = .unstarted, .captured_monotonic_ms = 789 };
}

fn decodeAllocation(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoded = try decodeSnapshot(allocator, bytes, .{});
    defer decoded.deinit();
    try std.testing.expectEqualStrings("oslo", decoded.weather[7].key[0..decoded.weather[7].key_len]);
}

test "Windows GEO checkpoint preserves physical cache slots and FIFO with malformed and OOM refusal" {
    const allocator = std.testing.allocator;
    var snapshot = try fixture(allocator, .{});
    defer snapshot.deinit();
    const bytes = try encodeSnapshot(allocator, &snapshot, .{});
    defer allocator.free(bytes);
    try validateCheckpoint(bytes);
    try std.testing.checkAllAllocationFailures(allocator, decodeAllocation, .{bytes});
    var decoded = try decodeSnapshot(allocator, bytes, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(geo.State.ready, decoded.weather[7].state);
    try std.testing.expectEqual(geo.State.empty, decoded.weather[0].state);
    try std.testing.expectEqualStrings("firstsecond", decoded.news[3].text[0..11]);
    try std.testing.expectEqual(geo.JobKind.news, decoded.jobs[0].kind);
    try std.testing.expectEqual(geo.JobKind.weather, decoded.jobs[1].kind);
    try std.testing.expectEqual(@as(i64, 789), decoded.captured_monotonic_ms);
    try std.testing.expectEqual(weather_units.flag_feels | weather_units.flag_wind_dir | weather_units.flag_rich, decoded.weather[7].flags);
    try std.testing.expectEqual(@as(u8, 1), decoded.weather[7].day_count);
    try std.testing.expectEqualStrings("2026-10-19", decoded.weather[7].days[0].label[0..10]);
    try std.testing.expectEqualStrings("Rain", decoded.weather[7].days[0].desc[0..4]);
    try std.testing.expectEqual(@as(u64, @bitCast(@as(f64, 4.0))), decoded.weather[7].feels_bits);
    const cleared = try allocator.dupe(u8, bytes);
    defer allocator.free(cleared);
    cleared[header_len + 7 * weather_len + weather_len_v1] = weather_units.flag_rich;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(cleared));
    var changed: geo.Options = .{};
    changed.weather_ttl_ms += 1;
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(allocator, bytes, changed));

    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[header_len + 1] = 1; // noncanonical empty weather slot
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    bad[header_len + 1] = 0;
    const active = header_len + 7 * weather_len;
    const duplicate = header_len + 8 * weather_len;
    @memcpy(bad[duplicate..][0..weather_len], bad[active..][0..weather_len]);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
}

test "v1 geo checkpoint decodes with detail flags clear" {
    const allocator = std.testing.allocator;
    const total = header_len + geo.weather_slots * weather_len_v1 + geo.news_slots * news_len;
    const bytes = try allocator.alloc(u8, total);
    defer allocator.free(bytes);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], magic);
    std.mem.writeInt(u16, bytes[4..6], version_v1, .big);
    std.mem.writeInt(u16, bytes[8..10], geo.weather_slots, .big);
    std.mem.writeInt(u16, bytes[10..12], geo.news_slots, .big);
    bytes[14] = @intFromEnum(geo.Execution.unstarted);
    const digest = try geo.optionsDigest(.{});
    @memcpy(bytes[24..56], &digest);
    std.mem.writeInt(u32, bytes[56..60], @intCast(total), .big);
    const row = bytes[header_len + 7 * weather_len_v1 ..][0..weather_len_v1];
    row[0] = @intFromEnum(geo.State.ready);
    row[1] = 4;
    row[2] = 4;
    std.mem.writeInt(u64, row[4..12], @bitCast(@as(f64, 5.5)), .big);
    std.mem.writeInt(u64, row[20..28], @bitCast(@as(i64, 123)), .big);
    @memcpy(row[28..][0..4], "oslo");
    @memcpy(row[28 + geo.max_key ..][0..4], "Oslo");
    try validateCheckpoint(bytes);
    var decoded = try decodeSnapshot(allocator, bytes, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(geo.State.ready, decoded.weather[7].state);
    try std.testing.expectEqual(@as(u8, 0), decoded.weather[7].flags);
    try std.testing.expectEqual(@as(u8, 0), decoded.weather[7].day_count);
    try std.testing.expectEqual(@as(u64, @bitCast(@as(f64, 5.5))), decoded.weather[7].temp_c_bits);
    try std.testing.expectEqualStrings("oslo", decoded.weather[7].key[0..4]);
}

test "Windows GEO checkpoint source fence and candidate parked Gate restore" {
    const allocator = std.testing.allocator;
    var snapshot = try fixture(allocator, .{});
    defer snapshot.deinit();
    var source = geo.Service.init(allocator, .{});
    defer source.stop();
    try source.restoreSnapshot(&snapshot, max_capture_bytes);
    const fence = try source.fenceProducers();
    defer source.resumeProducers(fence) catch unreachable;
    const bytes = try captureFrozenEncoded(allocator, &source, fence, null);
    defer allocator.free(bytes);

    var candidate = geo.Service.init(allocator, .{});
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .geo, .instance = 0, .owner_identity = &candidate }};
    const gate = try runtime_pause.start_gate.create(allocator, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        candidate.stop();
        gate.control.destroyJoined();
    }
    try std.testing.expectError(error.NotPrepared, restoreEncodedParked(allocator, &candidate, bytes));
    try std.testing.expectEqual(@as(usize, 0), candidate.job_count);
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.geo, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try restoreEncodedParked(allocator, &candidate, bytes);
    try std.testing.expectEqual(@as(usize, 2), candidate.job_count);
    try std.testing.expectEqual(geo.State.ready, candidate.weather[7].state);
    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[header_len + 1] = 1;
    try std.testing.expectError(error.InvalidSnapshot, restoreEncodedParked(allocator, &candidate, bad));
    try std.testing.expectEqual(@as(usize, 2), candidate.job_count);
    try candidate.requireParked();
}
