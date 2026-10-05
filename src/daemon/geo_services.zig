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
pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};

pub const max_key = 80;
pub const max_loc = 64;
pub const max_desc = 48;
pub const max_headline = 180;
pub const max_headlines = 5;
pub const weather_slots = 64;
pub const news_slots = 64;
pub const job_capacity = 128;

pub const State = enum(u8) { empty, pending, ready };

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

pub const JobKind = enum(u8) { weather, news };

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
    producers: runtime_pause.ProducerState = .{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    lifecycle_mutex: std.atomic.Mutex = .unlocked,
    lazy_pause_epoch: u64 = 0,

    weather: [weather_slots]WeatherEntry = @splat(WeatherEntry{}),
    news: [news_slots]NewsEntry = @splat(NewsEntry{}),
    jobs: [job_capacity]Job = undefined,
    job_head: usize = 0,
    job_tail: usize = 0,
    job_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, opts: Options) Service {
        return .{ .allocator = allocator, .opts = opts };
    }

    pub fn prepareColdResources(self: *Service, io: std.Io) !void {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        _ = try optionsDigest(self.opts);
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .geo, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .geo, 0, self, dormant_spawn_options);
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.thread != null) return error.AlreadyStarted;
        if (!self.opts.weather_enabled and !self.opts.news_enabled) return error.NotConfigured;
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .geo, 0, Service, self, worker, dormant_spawn_options);
    }
    /// Signals this owner only. Runtime Control owns all actual joins.
    pub fn requestStopAndWake(self: *Service) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *Service) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *Service) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *Service) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn fenceProducers(self: *Service) !runtime_pause.ProducerFence {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.producers.freezeLocked();
    }
    pub fn requireProducersFrozen(self: *Service, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
    }
    pub fn resumeProducers(self: *Service, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.resumeLocked(fence);
    }
    pub fn inspectFrozen(self: *Service, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) !struct { execution: Execution, queued: usize } {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
        return .{ .execution = try self.requireCaptureCut(token), .queued = self.job_count };
    }
    pub fn requestPause(self: *Service, epoch: u64) !runtime_pause.Token {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        const token = try self.runtime.pause.request(epoch);
        self.lazy_pause_epoch = epoch; // same lock as actual lazy Thread creation
        return token;
    }
    pub fn pauseExecution(self: *Service, token: runtime_pause.Token) !Execution {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        try self.runtime.pause.requireRequested(token);
        if (self.lazy_pause_epoch != token.epoch) return error.InvalidToken;
        return if (self.thread != null or self.runtime.view != null) .paused else .unstarted;
    }
    pub fn awaitPaused(self: *Service, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        if (try self.pauseExecution(token) == .unstarted) return error.NotRunning;
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *Service, token: runtime_pause.Token) !void {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        try self.runtime.pause.resumePaused(token);
        if (self.lazy_pause_epoch == token.epoch) self.lazy_pause_epoch = 0;
    }
    pub fn capturePaused(self: *Service, allocator: std.mem.Allocator, token: runtime_pause.Token, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, token, null, max_bytes);
    }
    pub fn captureUnstarted(self: *Service, allocator: std.mem.Allocator, max_bytes: usize) !Snapshot {
        return self.captureCut(allocator, null, null, max_bytes);
    }
    fn requireCaptureCut(self: *Service, token: ?runtime_pause.Token) !Execution {
        if (token) |actual| {
            if (self.thread == null and self.runtime.view == null) return error.NotRunning;
            try self.runtime.pause.requirePaused(actual);
            return .paused;
        }
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return .unstarted;
    }
    /// Source-issued producer fence is rechecked under the exact data lock
    /// used for capture; no unlocked empty-queue observation grants custody.
    pub fn captureFrozen(self: *Service, allocator: std.mem.Allocator, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token, max_bytes: usize) !Snapshot {
        try self.requireProducersFrozen(fence);
        return self.captureCut(allocator, token, fence, max_bytes);
    }
    fn captureCut(self: *Service, allocator: std.mem.Allocator, token: ?runtime_pause.Token, fence: ?runtime_pause.ProducerFence, max_bytes: usize) !Snapshot {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        const execution = try self.requireCaptureCut(token);
        const digest = try optionsDigest(self.opts);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (fence) |proof| try self.producers.requireLocked(proof);
        if (self.job_count > job_capacity) return error.InvalidState;
        const bytes = @sizeOf(Snapshot) + weather_slots * @sizeOf(WeatherCarry) + news_slots * @sizeOf(NewsCarry) + self.job_count * @sizeOf(JobCarry);
        if (bytes > max_bytes) return error.Capacity;
        const weather = try allocator.alloc(WeatherCarry, weather_slots);
        errdefer allocator.free(weather);
        const news = try allocator.alloc(NewsCarry, news_slots);
        errdefer allocator.free(news);
        const jobs = try allocator.alloc(JobCarry, self.job_count);
        errdefer allocator.free(jobs);
        for (&self.weather, weather) |entry, *out| {
            if (entry.key_len > max_key or entry.loc_len > max_loc or entry.desc_len > max_desc) return error.InvalidState;
            out.* = .{ .state = entry.state, .key_len = @intCast(entry.key_len), .loc_len = @intCast(entry.loc_len), .desc_len = @intCast(entry.desc_len), .temp_c_bits = @bitCast(entry.temp_c), .wind_kph_bits = @bitCast(entry.wind_kph), .fetched_ms = entry.fetched_ms };
            @memcpy(out.key[0..entry.key_len], entry.key_buf[0..entry.key_len]);
            @memcpy(out.location[0..entry.loc_len], entry.loc_buf[0..entry.loc_len]);
            @memcpy(out.description[0..entry.desc_len], entry.desc_buf[0..entry.desc_len]);
        }
        for (&self.news, news) |entry, *out| {
            if (entry.key_len > max_key or entry.count > max_headlines) return error.InvalidState;
            out.* = .{ .state = entry.state, .key_len = @intCast(entry.key_len), .count = @intCast(entry.count), .fetched_ms = entry.fetched_ms };
            @memcpy(out.key[0..entry.key_len], entry.key_buf[0..entry.key_len]);
            var off: usize = 0;
            for (entry.lens[0..entry.count], 0..) |len, i| {
                if (len > max_headline or off + len > entry.text.len) return error.InvalidState;
                out.lens[i] = len;
                @memcpy(out.text[off..][0..len], entry.text[off..][0..len]);
                off += len;
            }
        }
        for (jobs, 0..) |*out, i| {
            const job = self.jobs[(self.job_head + i) % job_capacity];
            if (job.key_len > max_key) return error.InvalidState;
            out.* = .{ .kind = job.kind, .key_len = @intCast(job.key_len) };
            @memcpy(out.key[0..job.key_len], job.key_buf[0..job.key_len]);
        }
        const result: Snapshot = .{ .allocator = allocator, .weather = weather, .news = news, .jobs = jobs, .options_digest = digest, .execution = execution, .captured_monotonic_ms = platform.monotonicMillis() };
        try result.validate(self.opts, max_bytes);
        return result;
    }
    pub fn restoreSnapshot(self: *Service, snapshot: *const Snapshot, max_bytes: usize) !void {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        try snapshot.validate(self.opts, max_bytes);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (snapshot.weather, &self.weather) |entry, *out| {
            out.* = .{ .state = entry.state, .key_len = entry.key_len, .loc_len = entry.loc_len, .desc_len = entry.desc_len, .temp_c = @bitCast(entry.temp_c_bits), .wind_kph = @bitCast(entry.wind_kph_bits), .fetched_ms = entry.fetched_ms };
            @memcpy(out.key_buf[0..entry.key_len], entry.key[0..entry.key_len]);
            @memcpy(out.loc_buf[0..entry.loc_len], entry.location[0..entry.loc_len]);
            @memcpy(out.desc_buf[0..entry.desc_len], entry.description[0..entry.desc_len]);
        }
        for (snapshot.news, &self.news) |entry, *out| {
            out.* = .{ .state = entry.state, .key_len = entry.key_len, .count = entry.count, .lens = entry.lens, .fetched_ms = entry.fetched_ms };
            @memcpy(out.key_buf[0..entry.key_len], entry.key[0..entry.key_len]);
            var off: usize = 0;
            for (entry.lens[0..entry.count]) |len| off += len;
            @memcpy(out.text[0..off], entry.text[0..off]);
        }
        for (snapshot.jobs, 0..) |job, i| {
            self.jobs[i] = .{ .kind = job.kind, .key_len = job.key_len };
            @memcpy(self.jobs[i].key_buf[0..job.key_len], job.key[0..job.key_len]);
        }
        self.job_head = 0;
        self.job_count = snapshot.jobs.len;
        self.job_tail = snapshot.jobs.len % job_capacity;
    }

    /// Spawn the fetcher thread. Safe to call once; a failure leaves the service
    /// usable but inert (requests just never become ready).
    pub fn start(self: *Service) void {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.thread != null or self.runtime.view != null or self.lazy_pause_epoch != 0) return;
        // Publish the actual lazy worker under the same producer exclusion.
        // A fence cannot return between checking frozen and assigning Thread.
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch null;
    }

    /// Eager startup for explicitly enabled geo service. Preserve the same
    /// lifecycle/producer exclusion as lazy start, but surface spawn refusal.
    pub fn startChecked(self: *Service) !void {
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        if (self.thread != null or self.runtime.view != null or self.lazy_pause_epoch != 0) return error.AlreadyStarted;
        if (!self.opts.weather_enabled and !self.opts.news_enabled) return error.NotConfigured;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen) return error.ProducersFrozen;
        self.stop_flag.store(false, .release);
        errdefer self.stop_flag.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
    }

    pub fn stop(self: *Service) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        lockSpin(&self.lifecycle_mutex);
        defer self.lifecycle_mutex.unlock();
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        self.lazy_pause_epoch = 0;
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
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return;
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
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (!self.stop_flag.load(.acquire)) {
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
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
        // getNews accepts a client-supplied key. Only catalogue entries may
        // become filenames below the configured cache directory.
        if (newsUrlForKey(k) == null) return;
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
    if (comptime builtin.os.tag == .windows) return readFileWindows(path, buf);
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

const windows_invalid_handle = std.math.maxInt(usize);
const windows_file_type_disk: u32 = 1;
const windows_file_attribute_reparse_point: u32 = 0x400;
const WindowsFileBasicInfo = extern struct {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
};
extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, sharing: u32, security: ?*anyopaque, disposition: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) usize;
extern "kernel32" fn GetFileType(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn ReadFile(handle: usize, bytes: [*]u8, len: u32, count: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

fn readFileWindows(path: [*:0]const u8, buf: []u8) ?[]u8 {
    if (comptime @import("builtin").os.tag != .windows) return null;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, std.mem.span(path)) catch return null;
    defer std.heap.page_allocator.free(wide);
    // OPEN_REPARSE_POINT makes the final-file check apply to the opened link
    // rather than silently reading a target outside the configured cache.
    const handle = CreateFileW(wide.ptr, 0x80000000, 0x7, null, 3, 0x00200000, null);
    if (handle == windows_invalid_handle) return null;
    defer _ = CloseHandle(handle);
    if (GetFileType(handle) != windows_file_type_disk) return null;
    var basic: WindowsFileBasicInfo = undefined;
    if (GetFileInformationByHandleEx(handle, 0, &basic, @sizeOf(WindowsFileBasicInfo)) == 0 or
        (basic.attributes & windows_file_attribute_reparse_point) != 0) return null;
    var total: usize = 0;
    while (total < buf.len) {
        var count: u32 = 0;
        if (ReadFile(handle, buf[total..].ptr, @intCast(@min(buf.len - total, std.math.maxInt(u32))), &count, null) == 0) return null;
        if (count == 0) break;
        total += @intCast(count);
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

test "Windows geo checked startup refuses disabled and frozen workers then starts" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var disabled = Service.init(std.testing.allocator, .{ .weather_enabled = false, .news_enabled = false });
    try std.testing.expectError(error.NotConfigured, disabled.startChecked());
    var service = Service.init(std.testing.allocator, .{ .weather_enabled = false });
    const fence = try service.fenceProducers();
    try std.testing.expectError(error.ProducersFrozen, service.startChecked());
    try service.resumeProducers(fence);
    try service.startChecked();
    defer service.stop();
    try std.testing.expect(service.thread != null);
    try std.testing.expectError(error.AlreadyStarted, service.startChecked());
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

pub const Execution = enum(u8) { unstarted, paused };
pub const WeatherCarry = struct {
    state: State = .empty,
    key: [max_key]u8 = @splat(0),
    key_len: u16 = 0,
    location: [max_loc]u8 = @splat(0),
    loc_len: u16 = 0,
    description: [max_desc]u8 = @splat(0),
    desc_len: u16 = 0,
    temp_c_bits: u64 = 0,
    wind_kph_bits: u64 = 0,
    fetched_ms: i64 = 0,
};
pub const NewsCarry = struct {
    state: State = .empty,
    key: [max_key]u8 = @splat(0),
    key_len: u16 = 0,
    text: [max_headline * max_headlines]u8 = @splat(0),
    lens: [max_headlines]u16 = @splat(0),
    count: u8 = 0,
    fetched_ms: i64 = 0,
};
pub const JobCarry = struct {
    kind: JobKind,
    key: [max_key]u8 = @splat(0),
    key_len: u16 = 0,
};
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    weather: []WeatherCarry,
    news: []NewsCarry,
    jobs: []JobCarry,
    options_digest: [32]u8,
    execution: Execution,
    captured_monotonic_ms: i64,
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.weather);
        self.allocator.free(self.news);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, opts: Options, max_bytes: usize) !void {
        if (self.weather.len != weather_slots or self.news.len != news_slots or self.jobs.len > job_capacity) return error.InvalidState;
        if (!std.mem.eql(u8, &self.options_digest, &try optionsDigest(opts))) return error.ConfigMismatch;
        const bytes = @sizeOf(Snapshot) + weather_slots * @sizeOf(WeatherCarry) + news_slots * @sizeOf(NewsCarry) + self.jobs.len * @sizeOf(JobCarry);
        if (bytes > max_bytes) return error.Capacity;
        for (self.weather, 0..) |entry, i| {
            try validateKey(&entry.key, entry.key_len, entry.state == .empty);
            if (entry.loc_len > max_loc or entry.desc_len > max_desc) return error.InvalidState;
            if (!std.mem.allEqual(u8, entry.location[entry.loc_len..], 0) or !std.mem.allEqual(u8, entry.description[entry.desc_len..], 0)) return error.InvalidState;
            if (entry.state == .empty and (entry.loc_len != 0 or entry.desc_len != 0 or entry.temp_c_bits != 0 or entry.wind_kph_bits != 0 or entry.fetched_ms != 0)) return error.InvalidState;
            if (entry.state != .empty) for (self.weather[0..i]) |prior| {
                if (prior.state != .empty and std.mem.eql(u8, entry.key[0..entry.key_len], prior.key[0..prior.key_len])) return error.InvalidState;
            };
        }
        for (self.news, 0..) |entry, i| {
            try validateKey(&entry.key, entry.key_len, entry.state == .empty);
            if (entry.count > max_headlines) return error.InvalidState;
            var off: usize = 0;
            for (entry.lens[0..entry.count]) |len| {
                if (len > max_headline) return error.InvalidState;
                off += len;
            }
            if (!std.mem.allEqual(u16, entry.lens[entry.count..], 0) or !std.mem.allEqual(u8, entry.text[off..], 0)) return error.InvalidState;
            if (entry.state == .empty and (entry.count != 0 or entry.fetched_ms != 0)) return error.InvalidState;
            if (entry.state != .empty) for (self.news[0..i]) |prior| {
                if (prior.state != .empty and std.mem.eql(u8, entry.key[0..entry.key_len], prior.key[0..prior.key_len])) return error.InvalidState;
            };
        }
        for (self.jobs, 0..) |job, i| {
            try validateKey(&job.key, job.key_len, false);
            for (self.jobs[0..i]) |prior| if (prior.kind == job.kind and std.mem.eql(u8, prior.key[0..prior.key_len], job.key[0..job.key_len])) return error.InvalidState;
        }
    }
};
fn validateKey(key: *const [max_key]u8, len: usize, empty: bool) !void {
    if (len > max_key or (empty and len != 0) or (!empty and len == 0)) return error.InvalidState;
    if (!std.mem.allEqual(u8, key[len..], 0)) return error.InvalidState;
}
pub fn optionsDigest(opts: Options) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/geo-config/v1");
    var numbers: [16]u8 = undefined;
    std.mem.writeInt(i64, numbers[0..8], opts.weather_ttl_ms, .big);
    std.mem.writeInt(i64, numbers[8..16], opts.news_ttl_ms, .big);
    hash.update(&numbers);
    hash.update(&.{ @intFromBool(opts.weather_enabled), @intFromBool(opts.news_enabled), @intFromBool(opts.news_insecure_tls), opts.max_headlines });
    try runtime_pause.hashBytes(&hash, opts.news_cache_dir);
    return hash.finalResult();
}

fn geoCaptureAllocation(allocator: std.mem.Allocator, service: *Service, token: runtime_pause.Token) !void {
    var snapshot = try service.capturePaused(allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
    try std.testing.expectEqual(@as(u8, 2), snapshot.news[0].count);
}

test "companion runtime GEO unstarted lazy membership is fenced without invented arrival" {
    var service = Service.init(std.testing.allocator, .{});
    try service.prepareColdResources(std.testing.io);
    defer service.stop();
    var loc: [max_loc]u8 = undefined;
    var desc: [max_desc]u8 = undefined;
    try std.testing.expect(service.getWeather("New York", &loc, &desc) == null);
    const token = try service.requestPause(1);
    try std.testing.expectEqual(Execution.unstarted, try service.pauseExecution(token));
    service.start(); // actual lazy entry is blocked under the same lifecycle gate
    try std.testing.expect(service.thread == null);
    try std.testing.expectError(error.NotRunning, service.awaitPaused(token, std.Io.Clock.Timestamp.now(std.testing.io, .awake)));
    var snapshot = try service.captureUnstarted(std.testing.allocator, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(Execution.unstarted, snapshot.execution);
    try std.testing.expectEqual(@as(usize, 1), snapshot.jobs.len);
    try std.testing.expectEqual(State.pending, snapshot.weather[0].state);
    try service.resumePaused(token);
    try std.testing.expectEqual(@as(u64, 0), service.lazy_pause_epoch);
}

test "companion runtime GEO real gated pause carries all caches news FIFO and OOM retry" {
    var service = Service.init(std.testing.allocator, .{});
    try service.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .geo, .instance = 0, .owner_identity = &service }};
    const gate = runtime_pause.start_gate.create(std.testing.allocator, std.testing.io, &specs) catch |err| {
        service.stop();
        return err;
    };
    defer {
        service.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        service.detachAfterJoined() catch unreachable;
        service.stop();
        gate.control.destroyJoined();
    }
    service.enqueue(.weather, "oslo");
    service.storeNews("src:bbc", &.{ "first title", "second title" });
    service.enqueue(.news, "src:bbc");
    const token = try service.requestPause(1);
    try service.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.geo, 0, &service));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectError(error.NotPrepared, service.requireActivated());
    gate.control.releaseAll();
    try service.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try service.requireActivated();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, geoCaptureAllocation, .{ &service, token });
    var snapshot = try service.capturePaused(std.testing.allocator, token, 1024 * 1024);
    defer snapshot.deinit();
    var restored = Service.init(std.testing.allocator, .{});
    defer restored.stop();
    try restored.restoreSnapshot(&snapshot, 1024 * 1024);
    try std.testing.expectEqual(@as(usize, 2), restored.job_count);
    try std.testing.expectEqualStrings("oslo", restored.jobs[0].key());
    try std.testing.expectEqualStrings("src:bbc", restored.jobs[1].key());
    try std.testing.expectEqual(@as(usize, 2), restored.news[0].count);
    try std.testing.expectEqualSlices(u8, "first titlesecond title", restored.news[0].text[0.."first titlesecond title".len]);
    snapshot.news[0].count = max_headlines + 1;
    try std.testing.expectError(error.InvalidState, restored.restoreSnapshot(&snapshot, 1024 * 1024));
    try std.testing.expectEqual(@as(usize, 2), restored.news[0].count);
    snapshot.news[0].count = 2;
    snapshot.options_digest[0] ^= 1;
    try std.testing.expectError(error.ConfigMismatch, restored.restoreSnapshot(&snapshot, 1024 * 1024));
    snapshot.options_digest[0] ^= 1;
    try std.testing.expectError(error.Capacity, service.capturePaused(std.testing.allocator, token, 1));
    try std.testing.expectEqual(@as(usize, 2), service.job_count);
}

fn cacheReadChildExit(code: u8) noreturn {
    if (comptime @import("builtin").os.tag == .linux) std.os.linux.exit_group(code) else std.posix.system._exit(code);
}
fn cacheReadChildWait(pid: std.posix.pid_t, status: *i32, nohang: bool) !bool {
    const options: u32 = if (nohang) std.posix.W.NOHANG else 0;
    if (comptime @import("builtin").os.tag == .linux) {
        const result = std.os.linux.wait4(pid, status, options, null);
        return switch (std.posix.errno(result)) {
            .SUCCESS => result != 0,
            .INTR => false,
            else => error.TestUnexpectedResult,
        };
    } else {
        const result = std.posix.system.waitpid(pid, status, @intCast(options));
        if (result < 0) {
            if (std.posix.errno(result) == .INTR) return false;
            return error.TestUnexpectedResult;
        }
        return result != 0;
    }
}
test "companion runtime geo cache regular control and FIFO finite refusal" {
    // Fork/exec-based child reads; no `fork` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const control = try tmp.dir.createFile(std.testing.io, "cache-control", .{});
    try control.writePositionalAll(std.testing.io, "actual regular", 0);
    control.close(std.testing.io);
    var fifo_buf: [256]u8 = undefined;
    const fifo_path = try std.fmt.bufPrint(&fifo_buf, ".zig-cache/tmp/{s}/cache-fifo", .{tmp.sub_path});
    const made = try std.process.run(std.testing.allocator, std.testing.io, .{ .argv = &.{ "mkfifo", fifo_path } });
    defer std.testing.allocator.free(made.stdout);
    defer std.testing.allocator.free(made.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, made.term);
    for ([_][]const u8{ "cache-control", "cache-fifo" }, 0..) |name, index| {
        var path_buf: [256]u8 = undefined;
        const printed = try std.fmt.bufPrint(path_buf[0 .. path_buf.len - 1], ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
        path_buf[printed.len] = 0;
        const path = path_buf[0..printed.len :0];
        const pid: std.posix.pid_t = if (comptime @import("builtin").os.tag == .linux) block: {
            const result = std.os.linux.fork();
            if (std.posix.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
            break :block @intCast(result);
        } else std.posix.system.fork();
        if (pid < 0) return error.TestUnexpectedResult;
        if (pid == 0) {
            // The function is raw syscall-only; no inherited std.Io/thread locks.
            var buf: [64]u8 = undefined;
            const actual = readFileZ(path, &buf);
            if (index == 0) {
                const bytes = actual orelse cacheReadChildExit(12);
                if (!std.mem.eql(u8, bytes, "actual regular")) cacheReadChildExit(13);
            } else if (actual != null) cacheReadChildExit(14);
            cacheReadChildExit(0);
        }
        var reaped = false;
        defer if (!reaped) cacheReadKillReap(pid);
        const deadline = platform.monotonicMillis() + 2000;
        var status: i32 = 0;
        while (!(try cacheReadChildWait(pid, &status, true))) {
            if (platform.monotonicMillis() >= deadline) return error.TestUnexpectedResult;
            try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
        }
        reaped = true;
        try std.testing.expectEqual(@as(i32, 0), status);
    }
}

test "Windows geo news cache reads regular UTF-8 files and rejects reparse points" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const control = try tmp.dir.createFile(std.testing.io, "src_bbc.txt", .{});
    try control.writePositionalAll(std.testing.io, "# updater note\r\nFirst headline\r\nSecond headline\n", 0);
    control.close(std.testing.io);
    const unicode = try tmp.dir.createFile(std.testing.io, "news-東京.txt", .{});
    try unicode.writePositionalAll(std.testing.io, "UTF-8 path", 0);
    unicode.close(std.testing.io);

    const cache_dir = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(cache_dir);
    var service = Service.init(std.testing.allocator, .{ .news_cache_dir = cache_dir });
    service.fetchNewsFromFile("src:bbc");
    var output: [256]u8 = undefined;
    var lines: [max_headlines][]const u8 = undefined;
    const headlines = service.getNews("src:bbc", &output, &lines) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), headlines.len);
    try std.testing.expectEqualStrings("First headline", headlines[0]);
    try std.testing.expectEqualStrings("Second headline", headlines[1]);
    service.fetchNewsFromFile("src:../../escape");
    try std.testing.expect(service.findNews("src:../../escape") == null);

    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrintSentinel(&path_buf, "{s}/news-東京.txt", .{cache_dir}, 0);
    var read_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("UTF-8 path", readFileZ(path, &read_buf) orelse return error.TestUnexpectedResult);
    const directory = try std.fmt.bufPrintSentinel(&path_buf, "{s}", .{cache_dir}, 0);
    try std.testing.expect(readFileZ(directory, &read_buf) == null);

    const linked = blk: {
        tmp.dir.symLink(std.testing.io, "src_bbc.txt", "src_guardian.txt", .{}) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied => break :blk false,
            else => return err,
        };
        break :blk true;
    };
    if (linked) {
        const link_path = try std.fmt.bufPrintSentinel(&path_buf, "{s}/src_guardian.txt", .{cache_dir}, 0);
        try std.testing.expect(readFileZ(link_path, &read_buf) == null);
    }
}

fn cacheReadKillReap(pid: std.posix.pid_t) void {
    _ = std.posix.system.kill(pid, std.posix.SIG.KILL);
    var status: i32 = 0;
    while (true) {
        const done = cacheReadChildWait(pid, &status, false) catch return;
        if (done) return;
    }
}

test "companion runtime producer fence GEO carries accepted lazy FIFO and prevents late worker start" {
    var service = Service.init(std.testing.allocator, .{});
    try service.prepareColdResources(std.testing.io);
    defer service.stop();
    var loc: [max_loc]u8 = undefined;
    var desc: [max_desc]u8 = undefined;
    try std.testing.expect(service.getWeather("New York", &loc, &desc) == null);
    const fence = try service.fenceProducers();
    try std.testing.expect(service.getWeather("London", &loc, &desc) == null);
    service.start();
    try std.testing.expect(service.thread == null);
    try std.testing.expect(service.findWeather("london") == null);
    const cut = try service.inspectFrozen(fence, null);
    try std.testing.expectEqual(Execution.unstarted, cut.execution);
    try std.testing.expectEqual(@as(usize, 1), cut.queued);
    var snapshot = try service.captureFrozen(std.testing.allocator, fence, null, 1024 * 1024);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.jobs.len);
    try service.resumeProducers(fence);
    try std.testing.expect(service.getWeather("London", &loc, &desc) == null);
    const next = try service.fenceProducers();
    try std.testing.expectError(error.InvalidProducerFence, service.inspectFrozen(fence, null));
    try std.testing.expectEqual(@as(usize, 2), (try service.inspectFrozen(next, null)).queued);
}
