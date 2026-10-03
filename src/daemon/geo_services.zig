// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background weather/news cache for the `!weather`/`!news` fantasy commands.
//!
//! A single dedicated OS thread owns all outbound HTTP (via `http_fetch`, which
//! never touches the reactor io_uring); reactor threads only ever read/write the
//! mutex-guarded cache. A request that misses or finds a stale entry enqueues a
//! refresh job and returns "not ready" so the caller can say *"fetching… try
//! again"* — the classic fantasy-bot behaviour, but in-process.
//!
//!   * Weather: wttr.in (plain HTTP, no key); cached metric reading re-localized
//!     per the requesting user's country at serve time.
//!   * News: the `news_sources` RSS feeds (HTTPS via tls_client); cached
//!     headlines keyed by source key (`src:bbc`) or country (`cc:US`).
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const http_fetch = @import("http_fetch.zig");
const geo_fetch = @import("../proto/geo_fetch.zig");
const weather_units = @import("../proto/weather_units.zig");
const news_sources = @import("../proto/news_sources.zig");
const platform = @import("../substrate/platform.zig");

const max_key = 80;
const max_loc = 64;
const max_desc = 48;
const max_headline = 180;
const max_headlines = 5;
const weather_slots = 64;
const news_slots = 64;
const job_capacity = 128;

const State = enum { empty, pending, ready };

pub const Options = struct {
    weather_ttl_ms: i64 = 10 * 60 * 1000, // weather cache TTL 600s
    news_ttl_ms: i64 = 5 * 60 * 1000, // news cache TTL 300s
    weather_enabled: bool = true,
    news_enabled: bool = true,
    /// Skip TLS cert verification for news feeds (public read-only data). Lets
    /// the best-effort clean-room TLS reach more hosts; off by default.
    news_insecure_tls: bool = false,
    /// Directory of headline files written by a key-free updater (tools/
    /// news_update.sh: one headline per line, file `<key>.txt` where key is the
    /// cache key with ':' -> '_', e.g. `src_bbc.txt` / `cc_us.txt`). When set,
    /// news is served from these files instead of in-daemon TLS fetches — robust
    /// full coverage of all feeds regardless of the clean-room TLS reach.
    news_cache_dir: []const u8 = "",
    max_headlines: u8 = 3,
};

const WeatherEntry = struct {
    state: State = .empty,
    key_buf: [max_key]u8 = undefined,
    key_len: usize = 0,
    loc_buf: [max_loc]u8 = undefined,
    loc_len: usize = 0,
    desc_buf: [max_desc]u8 = undefined,
    desc_len: usize = 0,
    temp_c: f64 = 0,
    wind_kph: f64 = 0,
    fetched_ms: i64 = 0,

    fn key(self: *const WeatherEntry) []const u8 {
        return self.key_buf[0..self.key_len];
    }
};

const NewsEntry = struct {
    state: State = .empty,
    key_buf: [max_key]u8 = undefined,
    key_len: usize = 0,
    // Headlines packed back-to-back; `lens` gives each length.
    text: [max_headline * max_headlines]u8 = undefined,
    lens: [max_headlines]u16 = @splat(0),
    count: usize = 0,
    fetched_ms: i64 = 0,

    fn key(self: *const NewsEntry) []const u8 {
        return self.key_buf[0..self.key_len];
    }
};

const JobKind = enum { weather, news };

const Job = struct {
    kind: JobKind,
    key_buf: [max_key]u8 = undefined,
    key_len: usize = 0,

    fn key(self: *const Job) []const u8 {
        return self.key_buf[0..self.key_len];
    }
};

/// A weather reading copied into caller storage (so it stays valid after the
/// cache lock is released).
pub const WeatherView = struct {
    reading: weather_units.Reading,
    location: []const u8,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    mutex: std.atomic.Mutex = .unlocked,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    weather: [weather_slots]WeatherEntry = @splat(WeatherEntry{}),
    news: [news_slots]NewsEntry = @splat(NewsEntry{}),
    jobs: [job_capacity]Job = undefined,
    job_head: usize = 0,
    job_tail: usize = 0,
    job_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, opts: Options) Service {
        return .{ .allocator = allocator, .opts = opts };
    }

    /// Spawn the fetcher thread. Safe to call once; a failure leaves the service
    /// usable but inert (requests just never become ready).
    pub fn start(self: *Service) void {
        if (self.thread != null) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
    }

    pub fn stop(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    // ---- reactor-side API (mutex-guarded, never blocks on network) ----------

    /// Look up cached weather for `location`. Copies the reading + echoed
    /// location into the caller buffers and returns a view; on miss/stale it
    /// enqueues a refresh and returns null (stale data is still returned while a
    /// refresh runs, so users see *something*).
    pub fn getWeather(self: *Service, location: []const u8, loc_out: []u8, desc_out: []u8) ?WeatherView {
        if (!self.opts.weather_enabled) return null;
        var keybuf: [max_key]u8 = undefined;
        const k = normalizeKey(location, &keybuf);
        if (k.len == 0) return null;

        lockSpin(&self.mutex);
        defer self.mutex.unlock();

        const now = platform.monotonicMillis();
        if (self.findWeather(k)) |e| {
            const fresh = (now - e.fetched_ms) < self.opts.weather_ttl_ms;
            if (e.state == .ready) {
                if (!fresh) self.enqueue(.weather, k); // refresh in background, serve stale now
                const loc = copyInto(loc_out, e.loc_buf[0..e.loc_len]);
                const desc = copyInto(desc_out, e.desc_buf[0..e.desc_len]);
                return .{ .reading = .{ .temp_c = e.temp_c, .wind_kph = e.wind_kph, .precip_mm = 0, .desc = desc }, .location = loc };
            }
            return null; // pending
        }
        self.enqueue(.weather, k);
        return null;
    }

    /// Copy cached headlines for `cache_key` (e.g. "src:bbc" / "cc:US") into
    /// `out` as up to `max` NUL-free lines, returning the slices (borrowing
    /// `out`). Null on miss/stale-without-data (a refresh is enqueued).
    pub fn getNews(self: *Service, cache_key: []const u8, out: []u8, lines: [][]const u8) ?[][]const u8 {
        if (!self.opts.news_enabled) return null;
        var keybuf: [max_key]u8 = undefined;
        const k = normalizeKey(cache_key, &keybuf);
        if (k.len == 0) return null;

        lockSpin(&self.mutex);
        defer self.mutex.unlock();

        const now = platform.monotonicMillis();
        if (self.findNews(k)) |e| {
            const fresh = (now - e.fetched_ms) < self.opts.news_ttl_ms;
            if (e.state == .ready and e.count > 0) {
                if (!fresh) self.enqueue(.news, k);
                return copyHeadlines(e, out, lines);
            }
            return null;
        }
        self.enqueue(.news, k);
        return null;
    }

    // ---- internals ----------------------------------------------------------

    fn findWeather(self: *Service, k: []const u8) ?*WeatherEntry {
        for (&self.weather) |*e| {
            if (e.state != .empty and std.mem.eql(u8, e.key(), k)) return e;
        }
        return null;
    }

    fn findNews(self: *Service, k: []const u8) ?*NewsEntry {
        for (&self.news) |*e| {
            if (e.state != .empty and std.mem.eql(u8, e.key(), k)) return e;
        }
        return null;
    }

    /// Reserve (or reuse) a weather slot for `k`, marking it pending.
    fn reserveWeather(self: *Service, k: []const u8) *WeatherEntry {
        if (self.findWeather(k)) |e| return e;
        const e = self.victimWeather();
        e.* = .{};
        e.key_len = copyKey(&e.key_buf, k);
        e.state = .pending;
        return e;
    }

    fn reserveNews(self: *Service, k: []const u8) *NewsEntry {
        if (self.findNews(k)) |e| return e;
        const e = self.victimNews();
        e.* = .{};
        e.key_len = copyKey(&e.key_buf, k);
        e.state = .pending;
        return e;
    }

    fn victimWeather(self: *Service) *WeatherEntry {
        var oldest: *WeatherEntry = &self.weather[0];
        for (&self.weather) |*e| {
            if (e.state == .empty) return e;
            if (e.fetched_ms < oldest.fetched_ms) oldest = e;
        }
        return oldest;
    }

    fn victimNews(self: *Service) *NewsEntry {
        var oldest: *NewsEntry = &self.news[0];
        for (&self.news) |*e| {
            if (e.state == .empty) return e;
            if (e.fetched_ms < oldest.fetched_ms) oldest = e;
        }
        return oldest;
    }

    /// Enqueue a fetch job for `k` unless one is already queued or the matching
    /// entry is already pending. Caller holds the mutex.
    fn enqueue(self: *Service, kind: JobKind, k: []const u8) void {
        // Mark the target entry pending so repeated requests don't pile up.
        switch (kind) {
            .weather => _ = self.reserveWeather(k),
            .news => _ = self.reserveNews(k),
        }
        if (self.job_count >= job_capacity) return;
        // De-dupe against queued jobs.
        var i: usize = 0;
        var idx = self.job_head;
        while (i < self.job_count) : (i += 1) {
            const j = &self.jobs[idx];
            if (j.kind == kind and std.mem.eql(u8, j.key(), k)) return;
            idx = (idx + 1) % job_capacity;
        }
        var job = Job{ .kind = kind };
        job.key_len = copyKey(&job.key_buf, k);
        self.jobs[self.job_tail] = job;
        self.job_tail = (self.job_tail + 1) % job_capacity;
        self.job_count += 1;
    }

    fn worker(self: *Service) void {
        while (!self.stop_flag.load(.acquire)) {
            const job = self.takeJob() orelse {
                sleepMs(100); // low-rate work: poll for jobs, observe the stop flag
                continue;
            };
            // Network I/O happens OUTSIDE the lock.
            switch (job.kind) {
                .weather => self.fetchWeather(job.key()),
                .news => self.fetchNews(job.key()),
            }
        }
    }

    /// Pop the next queued job (mutex-guarded), or null if the queue is empty.
    fn takeJob(self: *Service) ?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.job_count == 0) return null;
        const job = self.jobs[self.job_head];
        self.job_head = (self.job_head + 1) % job_capacity;
        self.job_count -= 1;
        return job;
    }

    fn fetchWeather(self: *Service, k: []const u8) void {
        var req_buf: [512]u8 = undefined;
        const req = geo_fetch.buildWeatherRequest(&req_buf, geo_fetch.weather_host, k) catch return;
        const resp = http_fetch.get(self.allocator, geo_fetch.weather_host, 80, false, req, .{
            .max_response_bytes = 64 * 1024,
        }) catch return;
        defer self.allocator.free(resp);
        const parsed = geo_fetch.parseWeather(geo_fetch.httpBody(resp)) catch return;

        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const e = self.reserveWeather(k);
        e.temp_c = parsed.reading.temp_c;
        e.wind_kph = parsed.reading.wind_kph;
        e.loc_len = copyClamp(&e.loc_buf, if (parsed.location.len != 0) parsed.location else k);
        e.desc_len = copyClamp(&e.desc_buf, parsed.reading.desc);
        e.fetched_ms = platform.monotonicMillis();
        e.state = .ready;
    }

    fn fetchNews(self: *Service, k: []const u8) void {
        // File-cache path (preferred when configured): read headlines an external
        // key-free updater has written. Robust full coverage, no in-daemon TLS.
        if (self.opts.news_cache_dir.len != 0) {
            self.fetchNewsFromFile(k);
            return;
        }
        // Live path: in-daemon RSS-over-TLS fetch. crypto/tls_client verifies
        // both ECDSA and RSA leaf certs (the RSA leaf-key dangle that previously
        // failed rsa_pss hosts like NPR/Guardian is fixed). It is TLS-1.3 only,
        // so a TLS-1.2-only host would still fail — `news_cache_dir` +
        // tools/news_update.sh remain available for guaranteed full coverage.
        const url = newsUrlForKey(k) orelse return;
        const u = http_fetch.parseUrl(url) catch return;
        var req_buf: [1024]u8 = undefined;
        const req = geo_fetch.buildNewsRequest(&req_buf, u.host, u.path) catch return;
        const resp = http_fetch.get(self.allocator, u.host, u.port, u.tls, req, .{
            .insecure_skip_verify = self.opts.news_insecure_tls,
            .max_response_bytes = 1024 * 1024,
        }) catch return;
        defer self.allocator.free(resp);

        var titles: [max_headlines][]const u8 = undefined;
        const got = geo_fetch.parseRssTitles(geo_fetch.httpBody(resp), &titles);
        self.storeNews(k, got);
    }

    /// Read `<news_cache_dir>/<key with ':'->'_'>.txt` (one headline per line,
    /// `#` comments skipped) and cache its headlines. Thread-safe blocking file
    /// read (raw syscalls; never touches the reactor io).
    fn fetchNewsFromFile(self: *Service, k: []const u8) void {
        var name_buf: [max_key]u8 = undefined;
        const fname = fileKey(k, &name_buf);
        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrintSentinel(&path_buf, "{s}/{s}.txt", .{ self.opts.news_cache_dir, fname }, 0) catch return;

        var file_buf: [16 * 1024]u8 = undefined;
        const contents = readFileZ(path, &file_buf) orelse return;

        var titles: [max_headlines][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, contents, '\n');
        while (it.next()) |raw| {
            if (n >= titles.len) break;
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            titles[n] = line;
            n += 1;
        }
        self.storeNews(k, titles[0..n]);
    }

    /// Copy `headlines` into the news cache entry for `k` (mutex-guarded). No-op
    /// when empty, so a failed fetch leaves any prior data intact.
    fn storeNews(self: *Service, k: []const u8, headlines: []const []const u8) void {
        if (headlines.len == 0) return;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const e = self.reserveNews(k);
        e.count = 0;
        var off: usize = 0;
        const want = @min(headlines.len, @as(usize, self.opts.max_headlines));
        for (headlines[0..want]) |t| {
            const clipped = t[0..@min(t.len, max_headline)];
            if (off + clipped.len > e.text.len) break;
            @memcpy(e.text[off .. off + clipped.len], clipped);
            e.lens[e.count] = @intCast(clipped.len);
            off += clipped.len;
            e.count += 1;
        }
        e.fetched_ms = platform.monotonicMillis();
        e.state = .ready;
    }
};

/// Map a cache key ("src:bbc"/"cc:us") to its file stem ("src_bbc"/"cc_us").
fn fileKey(k: []const u8, buf: []u8) []const u8 {
    const n = @min(buf.len, k.len);
    for (k[0..n], 0..) |c, i| buf[i] = if (c == ':') '_' else c;
    return buf[0..n];
}

/// Finite regular-cache acquisition. NONBLOCK prevents a configured FIFO from
/// trapping shutdown/pause before type validation; the held descriptor, not an
/// earlier pathname stat, supplies the regular-file proof.
fn readFileZ(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) return null;
    const sys = posix.system;
    const flags: posix.O = .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true };
    const raw = if (comptime builtin.os.tag == .linux)
        sys.open(path, flags, 0)
    else
        sys.open(path, flags, @as(posix.mode_t, 0));
    if (posix.errno(raw) != .SUCCESS) return null;
    const fd: posix.fd_t = @intCast(raw);
    defer _ = sys.close(fd);
    if (comptime builtin.os.tag == .linux) {
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        if (posix.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat)) != .SUCCESS or !stat.mask.TYPE or (stat.mode & posix.S.IFMT) != posix.S.IFREG) return null;
    } else {
        var stat: posix.Stat = undefined;
        if (posix.errno(sys.fstat(fd, &stat)) != .SUCCESS or (stat.mode & posix.S.IFMT) != posix.S.IFREG) return null;
    }
    var total: usize = 0;
    while (total < buf.len) {
        const result = sys.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(result)) {
            .SUCCESS => {
                const count: usize = @intCast(result);
                if (count == 0) break;
                total += count;
            },
            .INTR => continue,
            else => return null,
        }
    }
    return buf[0..total];
}

/// Blocking acquire on the tryLock-only `std.atomic.Mutex` (codebase idiom).
/// Cache contention is near-zero (one fetcher thread vs. rare fantasy commands).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag != .linux) {
        @import("os_runtime.zig").sleepMillis(ms);
        return;
    }
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

/// Resolve a news cache key ("src:<key>" / "cc:<CC>") to a feed URL.
pub fn newsUrlForKey(k: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, k, "src:")) {
        const s = news_sources.sourceByKey(k["src:".len..]) orelse return null;
        return s.url;
    }
    if (std.mem.startsWith(u8, k, "cc:")) {
        const f = news_sources.countryFeed(k["cc:".len..]) orelse return null;
        return f.url;
    }
    return null;
}

fn copyHeadlines(e: *const NewsEntry, out: []u8, lines: [][]const u8) ?[][]const u8 {
    var off: usize = 0;
    var n: usize = 0;
    var src_off: usize = 0;
    while (n < e.count and n < lines.len) : (n += 1) {
        const len = e.lens[n];
        if (off + len > out.len) break;
        @memcpy(out[off .. off + len], e.text[src_off .. src_off + len]);
        lines[n] = out[off .. off + len];
        off += len;
        src_off += len;
    }
    if (n == 0) return null;
    return lines[0..n];
}

fn copyInto(dst: []u8, src: []const u8) []const u8 {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return dst[0..n];
}

fn copyKey(dst: *[max_key]u8, src: []const u8) usize {
    const n = @min(max_key, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

fn copyClamp(dst: anytype, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

/// Lowercase + trim a key into `buf` (weather locations are case-insensitive;
/// news keys keep their `src:`/`cc:` prefix lowercased which is fine).
fn normalizeKey(s: []const u8, buf: []u8) []const u8 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    const n = @min(buf.len, trimmed.len);
    for (trimmed[0..n], 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..n];
}

// ---- tests ------------------------------------------------------------------

test "newsUrlForKey resolves source and country keys" {
    try std.testing.expectEqualStrings("https://feeds.bbci.co.uk/news/rss.xml", newsUrlForKey("src:bbc").?);
    try std.testing.expectEqualStrings("https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml", newsUrlForKey("cc:JP").?);
    try std.testing.expect(newsUrlForKey("src:nope") == null);
    try std.testing.expect(newsUrlForKey("garbage") == null);
}

test "cache miss enqueues and reports not-ready" {
    var svc = Service.init(std.testing.allocator, .{});
    // No worker thread started: requests just enqueue and return null.
    var loc: [max_loc]u8 = undefined;
    var desc: [max_desc]u8 = undefined;
    try std.testing.expect(svc.getWeather("Austin", &loc, &desc) == null);
    // Same key again must not double-enqueue (entry now pending).
    try std.testing.expect(svc.getWeather("austin", &loc, &desc) == null);
    try std.testing.expectEqual(@as(usize, 1), svc.job_count);
}

test "ready weather entry is served and localized by caller" {
    var svc = Service.init(std.testing.allocator, .{});
    {
        lockSpin(&svc.mutex);
        defer svc.mutex.unlock();
        const e = svc.reserveWeather("austin");
        e.temp_c = 22;
        e.wind_kph = 20;
        e.loc_len = copyClamp(&e.loc_buf, "Austin");
        e.desc_len = copyClamp(&e.desc_buf, "Partly cloudy");
        e.fetched_ms = platform.monotonicMillis();
        e.state = .ready;
    }
    var loc: [max_loc]u8 = undefined;
    var desc: [max_desc]u8 = undefined;
    const v = svc.getWeather("Austin", &loc, &desc).?;
    var line: [128]u8 = undefined;
    const out = weather_units.renderLine(&line, v.location, v.reading, weather_units.forCountry("US"));
    try std.testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", out);
}

test "ready news entry returns its headlines" {
    var svc = Service.init(std.testing.allocator, .{});
    {
        lockSpin(&svc.mutex);
        defer svc.mutex.unlock();
        const e = svc.reserveNews("src:bbc");
        const items = [_][]const u8{ "First", "Second" };
        var off: usize = 0;
        for (items, 0..) |t, i| {
            @memcpy(e.text[off .. off + t.len], t);
            e.lens[i] = @intCast(t.len);
            off += t.len;
            e.count += 1;
        }
        e.fetched_ms = platform.monotonicMillis();
        e.state = .ready;
    }
    var buf: [256]u8 = undefined;
    var lines: [max_headlines][]const u8 = undefined;
    const got = svc.getNews("src:bbc", &buf, &lines).?;
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("First", got[0]);
    try std.testing.expectEqualStrings("Second", got[1]);
}
