// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web Push delivery (Roadmap: "reach you with the tab closed").
//!
//! The pure message crypto (RFC 8291/8292) lives in `crypto/webpush.zig`;
//! this module is the daemon glue:
//!
//!   * `Subscription` + codec — bounded per-account subscription lists,
//!     serialized into the durable store's `.props` family under
//!     `wps\x00<account>` (same pattern as mirrored metadata).
//!   * `Vapid` — the server's ES256 key pair, load-or-create at a state path
//!     (survives restarts and Helix upgrades; rotating it invalidates every
//!     subscription, so it is created exactly once).
//!   * `Worker` — a background thread draining a job queue: per job it mints
//!     a VAPID JWT for the endpoint's origin, encrypts the payload, and POSTs
//!     it. Reactor threads only ever enqueue — network I/O never blocks them.
//!     Endpoints answering 404/410 land on a dead-list the server drains to
//!     prune stale subscriptions.
const std = @import("std");
const builtin = @import("builtin");
const dlog = @import("dlog.zig");
const wp_crypto = @import("../crypto/webpush.zig");
const ecdsa = @import("../crypto/ecdsa_p256.zig");
const acme_runner = @import("acme_runner.zig");
const http1 = @import("../proto/http1_client.zig");
const platform = @import("../substrate/platform.zig");
const services_mod = @import("services.zig");
pub const runtime_pause = @import("runtime_pause.zig");

const Allocator = std.mem.Allocator;
const net = std.Io.net;
const b64url = std.base64.url_safe_no_pad;

/// Real HTTPS and hybrid key exchange frames require this source-owned stack
/// policy. Inventory registration and both spawn paths use this exact value.
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{ .stack_size = 2 * 1024 * 1024 };

pub const max_subscriptions_per_account: usize = 3;
/// Length of the base64url-unpadded VAPID public key (65 SEC1 bytes).
pub const vapid_pub_b64_len: usize = b64url.Encoder.calcSize(65);
pub const max_endpoint_len: usize = 512;
/// Push TTL we request: the service holds an undelivered push this long.
pub const push_ttl_seconds: u32 = 12 * 60 * 60;
/// VAPID JWT lifetime (must be ≤ 24h; short keeps a leaked token boring).
pub const vapid_jwt_ttl_seconds: i64 = 12 * 60 * 60;
/// Bound on queued jobs. A full queue drops the new push, counts it, and
/// leaves an oper event. Jobs already queued stay queued. The cap stays 256.
pub const max_queued_jobs: usize = 256;
/// Oper text published when `enqueue` drops because the queue is full.
pub const overflow_oper_message = "WEBPUSH queue full; dropped a push";
/// Printed by the non-Linux boot path. Wave 6 keeps this explicit disable.
pub const portable_disable_reason = "web push is Linux-only; disabled";

pub const Config = struct {
    /// Master gate: off = command rejected, no worker, nothing advertised.
    enabled: bool = false,
    /// VAPID `sub` claim — a contact for the push service operator.
    subject: []const u8 = "mailto:ops@eshmaki.me",

    pub fn applyToml(cfg: *Config, doc: anytype) void {
        if (doc.getBool("webpush.enabled")) |v| cfg.enabled = v;
        if (doc.getString("webpush.subject")) |v| {
            if (v.len > 0) cfg.subject = v;
        }
    }
};

// ── Subscriptions + codec ────────────────────────────────────────────────────

pub const Subscription = struct {
    /// HTTPS push-service endpoint URL (owned).
    endpoint: []u8,
    /// Browser's P-256 key (`p256dh`), uncompressed SEC1.
    ua_public: [wp_crypto.ua_public_length]u8,
    /// Subscription auth secret (`auth`).
    auth: [wp_crypto.auth_secret_length]u8,

    pub fn deinit(self: *Subscription, allocator: Allocator) void {
        allocator.free(self.endpoint);
    }
};

pub const CodecError = error{MalformedRecord} || Allocator.Error;

/// Serialize a subscription list for the durable store. One record per line:
/// `<endpoint>\t<p256dh-b64url>\t<auth-b64url>\n`. Endpoints are validated
/// URL-ish at SUBSCRIBE time and can never contain tab/newline.
pub fn encodeList(allocator: Allocator, subs: []const Subscription) Allocator.Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    for (subs) |s| {
        var key_b64: [b64url.Encoder.calcSize(wp_crypto.ua_public_length)]u8 = undefined;
        _ = b64url.Encoder.encode(&key_b64, &s.ua_public);
        var auth_b64: [b64url.Encoder.calcSize(wp_crypto.auth_secret_length)]u8 = undefined;
        _ = b64url.Encoder.encode(&auth_b64, &s.auth);
        try out.appendSlice(allocator, s.endpoint);
        try out.append(allocator, '\t');
        try out.appendSlice(allocator, &key_b64);
        try out.append(allocator, '\t');
        try out.appendSlice(allocator, &auth_b64);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Parse a stored subscription list. Caller owns the result (each endpoint is
/// an owned copy); a malformed record fails the whole decode (the value is
/// only ever written by `encodeList`).
pub fn decodeList(allocator: Allocator, text: []const u8) CodecError![]Subscription {
    var subs: std.ArrayListUnmanaged(Subscription) = .empty;
    errdefer {
        for (subs.items) |*s| s.deinit(allocator);
        subs.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const endpoint = fields.next() orelse return error.MalformedRecord;
        const key_b64 = fields.next() orelse return error.MalformedRecord;
        const auth_b64 = fields.next() orelse return error.MalformedRecord;
        if (fields.next() != null) return error.MalformedRecord;
        if (endpoint.len == 0 or endpoint.len > max_endpoint_len) return error.MalformedRecord;

        const ua_public = wp_crypto.decodeFixed(wp_crypto.ua_public_length, key_b64) catch
            return error.MalformedRecord;
        const auth = wp_crypto.decodeFixed(wp_crypto.auth_secret_length, auth_b64) catch
            return error.MalformedRecord;

        const owned = try allocator.dupe(u8, endpoint);
        errdefer allocator.free(owned);
        try subs.append(allocator, .{ .endpoint = owned, .ua_public = ua_public, .auth = auth });
    }
    return subs.toOwnedSlice(allocator);
}

pub fn freeList(allocator: Allocator, subs: []Subscription) void {
    for (subs) |*s| s.deinit(allocator);
    allocator.free(subs);
}

/// Parse a client-supplied `p256dh` value (base64url, 65-byte SEC1 point).
pub fn decodeKey65(text: []const u8) error{InvalidSubscriptionKey}![wp_crypto.ua_public_length]u8 {
    return wp_crypto.decodeFixed(wp_crypto.ua_public_length, text);
}

/// Parse a client-supplied `auth` value (base64url, 16 bytes).
pub fn decodeAuth16(text: []const u8) error{InvalidSubscriptionKey}![wp_crypto.auth_secret_length]u8 {
    return wp_crypto.decodeFixed(wp_crypto.auth_secret_length, text);
}

/// Validate a client-supplied endpoint: absolute https URL, sane length, no
/// characters that could break the codec or an HTTP request line.
pub fn validEndpoint(endpoint: []const u8) bool {
    if (endpoint.len == 0 or endpoint.len > max_endpoint_len) return false;
    if (!std.mem.startsWith(u8, endpoint, "https://")) return false;
    if (endpoint.len == "https://".len) return false;
    for (endpoint) |c| {
        if (c <= 0x20 or c == 0x7f) return false; // ctl, space
    }
    return true;
}

// ── SSRF guard for outbound push delivery ────────────────────────────────────

/// True when a resolved IPv4 target sits in a range a client must never be able
/// to aim the daemon at: unspecified, private (RFC 1918), loopback, link-local
/// (cloud-metadata `169.254.169.254`), or the limited broadcast.
fn isDisallowedIp4(b: [4]u8) bool {
    return switch (b[0]) {
        0 => true, // 0.0.0.0/8 (incl. unspecified)
        10 => true, // 10.0.0.0/8 private
        127 => true, // 127.0.0.0/8 loopback
        169 => b[1] == 254, // 169.254.0.0/16 link-local
        172 => b[1] >= 16 and b[1] <= 31, // 172.16.0.0/12 private
        192 => b[1] == 168, // 192.168.0.0/16 private
        255 => b[1] == 255 and b[2] == 255 and b[3] == 255, // 255.255.255.255 broadcast
        else => false,
    };
}

/// SSRF guard: reject a RESOLVED push target in loopback / private / link-local
/// / ULA / unspecified space. Applied on the exact address the connect uses (one
/// resolution, checked inline), so a DNS-rebinding answer cannot slip a public
/// hostname past the block; IP-literal endpoints hit the same check.
pub fn isDisallowedPushAddr(addr: net.IpAddress) bool {
    switch (addr) {
        .ip4 => |a| return isDisallowedIp4(a.bytes),
        .ip6 => |a| {
            // An IPv4-mapped address (::ffff:a.b.c.d) is screened as its IPv4.
            if (net.Ip4Address.fromIp6(a)) |mapped| return isDisallowedIp4(mapped.bytes);
            const b = a.bytes;
            var hi_zero = true;
            for (b[0..12]) |x| {
                if (x != 0) {
                    hi_zero = false;
                    break;
                }
            }
            if (hi_zero) return true; // ::, ::1, and the deprecated ::a.b.c.d space
            if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
            if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7 ULA
            return false;
        },
    }
}

/// Wraps a resolver so every resolved push target is SSRF-screened inline with
/// the single resolution the connect performs. Scoped to the webpush delivery
/// path — ACME keeps its own unguarded resolver (it may legitimately reach
/// arbitrary hosts / configured internal endpoints).
const GuardedResolver = struct {
    inner: acme_runner.Resolver,

    fn resolveThunk(ctx: *anyopaque, host: []const u8, port: u16) anyerror!net.IpAddress {
        const self: *GuardedResolver = @ptrCast(@alignCast(ctx));
        const addr = try self.inner.resolveFn(self.inner.ctx, host, port);
        if (isDisallowedPushAddr(addr)) return error.DisallowedPushEndpoint;
        return addr;
    }

    fn resolver(self: *GuardedResolver) acme_runner.Resolver {
        return .{ .ctx = @ptrCast(self), .resolveFn = resolveThunk };
    }
};

// ── VAPID key persistence ────────────────────────────────────────────────────

pub const Vapid = struct {
    key_pair: ecdsa.KeyPair,

    /// Load the VAPID key from `sub_path`, or create + persist a fresh one.
    /// Format on disk: 64 lowercase hex chars of the P-256 secret scalar.
    pub fn loadOrCreate(io: std.Io, allocator: Allocator, dir: std.Io.Dir, sub_path: []const u8) !Vapid {
        if (dir.readFileAlloc(io, sub_path, allocator, .limited(256))) |text| {
            defer allocator.free(text);
            const trimmed = std.mem.trim(u8, text, " \r\n\t");
            if (trimmed.len == 64) {
                var secret: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&secret, trimmed) catch return error.InvalidVapidKey;
                const sk = ecdsa.SecretKey.fromBytes(secret) catch return error.InvalidVapidKey;
                const kp = ecdsa.KeyPair.fromSecretKey(sk) catch return error.InvalidVapidKey;
                return .{ .key_pair = kp };
            }
            return error.InvalidVapidKey;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const kp = ecdsa.KeyPair.generate(io);
        const hex = std.fmt.bytesToHex(kp.secret_key.toBytes(), .lower);
        try dir.writeFile(io, .{ .sub_path = sub_path, .data = &hex });
        return .{ .key_pair = kp };
    }

    /// Native Helix staging may read identity material but never create it.
    pub fn loadExisting(io: std.Io, allocator: Allocator, dir: std.Io.Dir, sub_path: []const u8) !Vapid {
        const text = try dir.readFileAlloc(io, sub_path, allocator, .limited(256));
        defer {
            std.crypto.secureZero(u8, text);
            allocator.free(text);
        }
        const trimmed = std.mem.trim(u8, text, " \r\n\t");
        if (trimmed.len != 64) return error.InvalidVapidKey;
        var secret: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &secret);
        _ = std.fmt.hexToBytes(&secret, trimmed) catch return error.InvalidVapidKey;
        const sk = ecdsa.SecretKey.fromBytes(secret) catch return error.InvalidVapidKey;
        return .{ .key_pair = ecdsa.KeyPair.fromSecretKey(sk) catch return error.InvalidVapidKey };
    }

    /// The base64url public key clients pass to `pushManager.subscribe`.
    /// Buffer must hold 87 bytes.
    pub fn publicB64(self: *const Vapid, out: *[b64url.Encoder.calcSize(65)]u8) []const u8 {
        const sec1 = self.key_pair.public_key.toUncompressedSec1();
        return b64url.Encoder.encode(out, &sec1);
    }
};

// ── Delivery worker ──────────────────────────────────────────────────────────

pub const Job = struct {
    endpoint: []u8,
    ua_public: [wp_crypto.ua_public_length]u8,
    auth: [wp_crypto.auth_secret_length]u8,
    /// Cleartext payload (JSON); encrypted per-job on the worker thread.
    payload: []u8,

    fn deinit(self: *Job, allocator: Allocator) void {
        freeEndpoint(allocator, self.endpoint);
        freeEndpoint(allocator, self.payload);
        std.crypto.secureZero(u8, &self.auth);
    }
};

pub const Worker = struct {
    allocator: Allocator,
    vapid: ecdsa.KeyPair,
    subject: []const u8,
    resolver: acme_runner.Resolver,
    trust_anchors: []const []const u8,

    mutex: std.atomic.Mutex = .unlocked,
    queue: std.ArrayListUnmanaged(Job) = .empty,
    /// Endpoints the push service reported gone (404/410); the server drains
    /// this (under the world lock) and prunes the stored subscriptions.
    dead: std.ArrayListUnmanaged([]u8) = .empty,
    /// One worker reserves dead-list metadata before taking a job. The reactor
    /// cannot transfer that backing until the complete delivery has settled.
    delivery_inflight: bool = false,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    producers: runtime_pause.ProducerState = .{},
    system_resolver: ?*acme_runner.SystemResolver = null,
    delivery_fixture: if (builtin.is_test) ?*DeliveryFixture else void = if (builtin.is_test) null else {},

    /// Delivery stats (worker-thread writes, oper-command reads are racy-read
    /// tolerable: monotonically increasing counters).
    sent: usize = 0,
    failed: usize = 0,
    /// Jobs refused because the queue already held `max_queued_jobs`.
    /// Incremented on the enqueue thread; metrics scrapes load it atomically.
    dropped: std.atomic.Value(usize) = .init(0),
    /// Unpublished overflow oper events. Drained by `takeOverflowOperEvent`.
    overflow_events: usize = 0,

    /// Bind the actual supported SystemResolver callback/context before any
    /// thread escapes. An arbitrary callback is not silently treated as the
    /// default resolver, and no address/function pointer is serialized.
    pub fn prepareColdResources(self: *Worker, io: std.Io, resolver: *acme_runner.SystemResolver) !void {
        if (self.thread != null or self.runtime.view != null or self.system_resolver != null) return error.AlreadyStarted;
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        const actual = resolver.resolver();
        if (actual.ctx != self.resolver.ctx or actual.resolveFn != self.resolver.resolveFn) return error.ConfigMismatch;
        self.system_resolver = resolver;
        errdefer self.system_resolver = null;
        _ = try self.configDigest();
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *Worker, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .webpush, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        if (self.stop_flag.load(.acquire)) return error.Stopped;
    }
    pub fn prepareDormantWorker(self: *Worker, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.validateDormantRegistration(control, view, slot);
        try self.runtime.validatePreparation(control, view, slot, .webpush, 0, self, dormant_spawn_options);
        _ = try self.configDigest();
        try self.runtime.prepare(control, view, slot, .webpush, 0, Worker, self, run, dormant_spawn_options);
    }
    /// Request this source's normal FIFO drain and wake a retained pause. Only
    /// the runtime's Control owner joins the shared thread handles.
    pub fn requestStopAndWake(self: *Worker) void {
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
    }
    pub fn detachAfterJoined(self: *Worker) !void {
        try self.runtime.detachAfterJoined();
    }
    pub fn requireParked(self: *Worker) !void {
        try self.runtime.requireParked();
    }
    pub fn requireActivated(self: *Worker) !void {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        try self.runtime.requireActivated();
    }
    pub fn fenceProducers(self: *Worker) !runtime_pause.ProducerFence {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.producers.freezeLocked();
    }
    pub fn requireProducersFrozen(self: *Worker, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
    }
    pub fn resumeProducers(self: *Worker, fence: runtime_pause.ProducerFence) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.resumeLocked(fence);
    }
    /// Joined source fact, never a service stop receipt. Pending queue entries,
    /// dead subscription results and overflow notices keep their original
    /// custody until the owning runtime actually reconciles them.
    pub fn requireTerminalSettled(self: *Worker, fence: runtime_pause.ProducerFence) !void {
        const view = self.runtime.view orelse return error.NotPrepared;
        try view.requireSlotJoined(self.runtime.slot orelse return error.InvalidSlot);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.producers.requireLocked(fence);
        if (!self.stop_flag.load(.acquire) or !self.runtime.exited.load(.acquire)) return error.NotQuiescent;
        if (self.delivery_inflight or self.queue.items.len != 0 or self.dead.items.len != 0 or self.overflow_events != 0)
            return error.PendingOutput;
    }
    pub fn requestPause(self: *Worker, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *Worker, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *Worker, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    fn requireCaptureCut(self: *Worker, token: ?runtime_pause.Token) !Execution {
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        if (token) |actual| {
            if (self.thread == null and self.runtime.view == null) return error.NotRunning;
            try self.runtime.pause.requirePaused(actual);
            return .paused;
        }
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return .unstarted;
    }
    pub fn capturePaused(self: *Worker, allocator: Allocator, token: runtime_pause.Token, bounds: SnapshotBounds) !Snapshot {
        return self.captureCut(allocator, token, null, bounds);
    }
    pub fn captureUnstarted(self: *Worker, allocator: Allocator, bounds: SnapshotBounds) !Snapshot {
        return self.captureCut(allocator, null, null, bounds);
    }
    pub fn captureFrozen(self: *Worker, allocator: Allocator, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token, bounds: SnapshotBounds) !Snapshot {
        try self.requireProducersFrozen(fence);
        return self.captureCut(allocator, token, fence, bounds);
    }
    fn captureCut(self: *Worker, allocator: Allocator, token: ?runtime_pause.Token, fence: ?runtime_pause.ProducerFence, bounds: SnapshotBounds) !Snapshot {
        const execution = try self.requireCaptureCut(token);
        const digest = try self.configDigest();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (fence) |proof| try self.producers.requireLocked(proof);
        _ = try self.requireCaptureCut(token);
        if (self.delivery_inflight) return error.NotQuiescent;
        try checkSnapshotBounds(self.queue.items, self.dead.items, bounds);
        const jobs = try allocator.alloc(Job, self.queue.items.len);
        errdefer allocator.free(jobs);
        var copied: usize = 0;
        errdefer for (jobs[0..copied]) |*job| job.deinit(allocator);
        for (self.queue.items, jobs) |job, *out| {
            out.* = try clonePushJob(allocator, job);
            copied += 1;
        }
        const dead = try allocator.alloc([]u8, self.dead.items.len);
        errdefer allocator.free(dead);
        var dead_copied: usize = 0;
        errdefer for (dead[0..dead_copied]) |endpoint| freeEndpoint(allocator, endpoint);
        for (self.dead.items, dead) |endpoint, *out| {
            out.* = try allocator.dupe(u8, endpoint);
            dead_copied += 1;
        }
        return .{ .allocator = allocator, .jobs = jobs, .dead = dead, .sent = self.sent, .failed = self.failed, .dropped = self.dropped.load(.acquire), .overflow_events = self.overflow_events, .config_digest = digest, .execution = execution };
    }
    pub fn restoreSnapshot(self: *Worker, snapshot: *const Snapshot, bounds: SnapshotBounds) !void {
        // Construction/restore and source teardown require external exclusion
        // from all producer calls. The mutex also protects the whole clone/swap.
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.AlreadyStarted;
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        if (self.delivery_inflight) return error.NotQuiescent;
        try snapshot.validate(self, bounds);
        var jobs: std.ArrayListUnmanaged(Job) = .empty;
        errdefer {
            for (jobs.items) |*job| job.deinit(self.allocator);
            jobs.deinit(self.allocator);
        }
        try jobs.ensureTotalCapacityPrecise(self.allocator, snapshot.jobs.len);
        for (snapshot.jobs) |job| jobs.appendAssumeCapacity(try clonePushJob(self.allocator, job));
        var dead: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (dead.items) |endpoint| freeEndpoint(self.allocator, endpoint);
            dead.deinit(self.allocator);
        }
        try dead.ensureTotalCapacityPrecise(self.allocator, snapshot.dead.len);
        for (snapshot.dead) |endpoint| dead.appendAssumeCapacity(try self.allocator.dupe(u8, endpoint));
        for (self.queue.items) |*job| job.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        for (self.dead.items) |endpoint| freeEndpoint(self.allocator, endpoint);
        self.dead.deinit(self.allocator);
        self.queue = jobs;
        self.dead = dead;
        self.sent = snapshot.sent;
        self.failed = snapshot.failed;
        self.dropped.store(snapshot.dropped, .release);
        self.overflow_events = snapshot.overflow_events;
    }
    pub fn configDigest(self: *const Worker) ![32]u8 {
        const resolver = self.system_resolver orelse return error.NotPrepared;
        const actual = resolver.resolver();
        if (actual.ctx != self.resolver.ctx or actual.resolveFn != self.resolver.resolveFn) return error.ConfigMismatch;
        const derived = try ecdsa.KeyPair.fromSecretKey(self.vapid.secret_key);
        const public_key = self.vapid.public_key.toUncompressedSec1();
        const expected_key = derived.public_key.toUncompressedSec1();
        if (!std.mem.eql(u8, &public_key, &expected_key)) return error.ConfigMismatch;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("onyx/companion/webpush-config/v1");
        hash.update(&public_key);
        try runtime_pause.hashBytes(&hash, self.subject);
        const count = std.math.cast(u32, self.trust_anchors.len) orelse return error.Capacity;
        var numbers: [14]u8 = undefined;
        std.mem.writeInt(u32, numbers[0..4], count, .big);
        std.mem.writeInt(u64, numbers[4..12], std.math.cast(u64, resolver.resolv_conf_max_bytes) orelse return error.Capacity, .big);
        std.mem.writeInt(u16, numbers[12..14], resolver.dns_port, .big);
        hash.update(&numbers);
        for (self.trust_anchors) |anchor| try runtime_pause.hashBytes(&hash, anchor);
        return hash.finalResult();
    }

    pub fn spawn(self: *Worker) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (self.stop_flag.load(.acquire)) return error.Stopped;
        // The HTTPS client and hybrid key exchange have nested Debug frames
        // larger than 512 KiB. Reserve enough stack for real push delivery.
        self.thread = try std.Thread.spawn(dormant_spawn_options, run, .{self});
    }

    pub fn shutdown(self: *Worker) void {
        self.runtime.requireDetached() catch @panic("managed webpush worker must join and detach before shutdown");
        self.requestStopAndWake();
        if (self.thread) |t| t.join();
        self.thread = null;
        std.debug.assert(!self.delivery_inflight);
        for (self.queue.items) |*j| j.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        self.queue = .empty;
        for (self.dead.items) |e| freeEndpoint(self.allocator, e);
        self.dead.deinit(self.allocator);
        self.dead = .empty;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.vapid));
    }

    pub const EnqueueResult = enum { queued, dropped, stopped, nomem };

    /// Enqueue a push (copies everything). A full queue drops this job, counts
    /// it on `dropped`, and leaves an oper event for `takeOverflowOperEvent`.
    /// Jobs already queued stay queued so delivery is still attempted. Stop
    /// and allocation failure are not overflow. The memo remains the DM.
    pub fn enqueue(
        self: *Worker,
        endpoint: []const u8,
        ua_public: [wp_crypto.ua_public_length]u8,
        auth: [wp_crypto.auth_secret_length]u8,
        payload: []const u8,
    ) EnqueueResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.producers.frozen or self.stop_flag.load(.acquire)) return .stopped;
        if (self.queue.items.len >= max_queued_jobs) {
            self.dropped.store(self.dropped.load(.monotonic) +| 1, .monotonic);
            self.overflow_events +|= 1;
            return .dropped;
        }
        const ep = self.allocator.dupe(u8, endpoint) catch return .nomem;
        const pl = self.allocator.dupe(u8, payload) catch {
            freeEndpoint(self.allocator, ep);
            return .nomem;
        };
        self.queue.append(self.allocator, .{
            .endpoint = ep,
            .ua_public = ua_public,
            .auth = auth,
            .payload = pl,
        }) catch {
            freeEndpoint(self.allocator, ep);
            freeEndpoint(self.allocator, pl);
            return .nomem;
        };
        return .queued;
    }

    /// One pending overflow oper line, or null when none is waiting.
    /// The slice is the static `overflow_oper_message`.
    pub fn takeOverflowOperEvent(self: *Worker) ?[]const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.overflow_events == 0) return null;
        self.overflow_events -= 1;
        return overflow_oper_message;
    }

    /// Take ownership of the dead-endpoint list (freed with this worker's
    /// allocator by the caller).
    pub fn drainDead(self: *Worker) []const []u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.delivery_inflight) return &.{};
        return self.dead.toOwnedSlice(self.allocator) catch &.{};
    }

    /// Retain the original endpoint outcomes until the source consumer has
    /// reconciled every account. The callback must not reenter this Worker.
    /// A failed Store write leaves the exact list owned here for idempotent
    /// retry, including writes whose durable boundary became uncertain.
    pub fn reconcileDead(self: *Worker, context: anytype, comptime reconcile: fn (@TypeOf(context), []const []const u8) anyerror!void) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.dead.items.len == 0) return;
        try reconcile(context, self.dead.items);
        for (self.dead.items) |endpoint| freeEndpoint(self.allocator, endpoint);
        self.dead.clearRetainingCapacity();
    }

    /// Consume a notice only after accepted oper-event publication. On
    /// allocation or admission failure the original count remains retryable.
    /// The callback must not reenter this Worker.
    pub fn reconcileOverflow(self: *Worker, context: anytype, comptime publish: fn (@TypeOf(context), []const u8) anyerror!void) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        while (self.overflow_events != 0) {
            try publish(context, overflow_oper_message);
            self.overflow_events -= 1;
        }
    }

    fn beginDelivery(self: *Worker) Allocator.Error!?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(!self.delivery_inflight);
        if (self.queue.items.len == 0) return null;
        // Before dequeue or HTTP: failed admission leaves the exact job queued.
        try self.dead.ensureUnusedCapacity(self.allocator, 1);
        self.delivery_inflight = true;
        const job = self.queue.orderedRemove(0);
        // orderedRemove shifts the remaining jobs; erase the vacated auth copy.
        std.crypto.secureZero(u8, std.mem.asBytes(&self.queue.allocatedSlice()[self.queue.items.len]));
        return job;
    }
    fn finishDelivery(self: *Worker) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        std.debug.assert(self.delivery_inflight);
        self.delivery_inflight = false;
    }

    fn run(self: *Worker) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (true) {
            self.runtime.pause.boundary();
            const maybe_job = self.beginDelivery() catch {
                // No operation was admitted, so a pending pause can settle.
                // During final stop, remaining jobs retain the existing explicit
                // shutdown disposal policy instead of spinning forever on OOM.
                if (self.stop_flag.load(.acquire)) return;
                sleepMs(200);
                continue;
            };
            var job = maybe_job orelse {
                if (self.stop_flag.load(.acquire)) return;
                sleepMs(200);
                continue;
            };
            defer self.finishDelivery();
            defer job.deinit(self.allocator);
            if (builtin.is_test) if (self.delivery_fixture) |fixture| fixture.beforeDelivery();
            self.deliver(&job) catch |err| {
                self.failed +|= 1;
                dlog.log("webpush: delivery to {s} failed: {s}\n", .{ job.endpoint, @errorName(err) });
            };
        }
    }

    fn deliver(self: *Worker, job: *Job) !void {
        const url = try acme_runner.Url.parse(job.endpoint);

        // VAPID audience = scheme://host[:port] of the push service.
        var aud_buf: [max_endpoint_len]u8 = undefined;
        const aud = if (url.port == 443)
            try std.fmt.bufPrint(&aud_buf, "https://{s}", .{url.host})
        else
            try std.fmt.bufPrint(&aud_buf, "https://{s}:{d}", .{ url.host, url.port });

        const exp = @divTrunc(platform.realtimeMillis(), 1000) + vapid_jwt_ttl_seconds;
        const jwt = try wp_crypto.vapidJwt(self.allocator, aud, self.subject, exp, self.vapid);
        defer self.allocator.free(jwt);
        const auth_value = try wp_crypto.vapidAuthValue(
            self.allocator,
            jwt,
            self.vapid.public_key.toUncompressedSec1(),
        );
        defer self.allocator.free(auth_value);

        const body = try wp_crypto.encryptRandom(self.allocator, job.ua_public, job.auth, job.payload);
        defer self.allocator.free(body);

        var ttl_buf: [16]u8 = undefined;
        const ttl = std.fmt.bufPrint(&ttl_buf, "{d}", .{push_ttl_seconds}) catch unreachable;
        const extra = [_]http1.Header{
            .{ .name = "authorization", .value = auth_value },
            .{ .name = "content-encoding", .value = "aes128gcm" },
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "ttl", .value = ttl },
            .{ .name = "urgency", .value = "high" },
        };

        // SSRF guard: screen the resolved address inline with the single
        // resolution the connect uses, so a client-supplied endpoint can never
        // steer the daemon at an internal/loopback/metadata target.
        var guard = GuardedResolver{ .inner = self.resolver };
        const raw = try acme_runner.httpsRequest(
            self.allocator,
            guard.resolver(),
            self.trust_anchors,
            "POST",
            url,
            &extra,
            body,
            64 * 1024,
        );
        defer self.allocator.free(raw);

        var header_scratch: [64]http1.Header = undefined;
        const resp = try http1.parseResponse(raw, &header_scratch);
        self.recordResponseStatus(job, resp.status);
    }

    fn recordResponseStatus(self: *Worker, job: *Job, status: u16) void {
        if (status >= 200 and status < 300) {
            self.sent +|= 1;
            return;
        }
        if (status == 404 or status == 410) {
            // Transfer the existing endpoint into pre-admitted metadata. An
            // accepted removal outcome must not require another allocation.
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            std.debug.assert(self.delivery_inflight and self.dead.items.len < self.dead.capacity);
            self.dead.appendAssumeCapacity(job.endpoint);
            job.endpoint = &.{};
            self.failed +|= 1;
            return;
        }
        self.failed +|= 1;
        dlog.log("webpush: {s} answered {d}\n", .{ job.endpoint, status });
    }
};

/// Prometheus sample for jobs dropped because the delivery queue was full.
pub fn appendDroppedSample(out: *std.ArrayList(u8), allocator: Allocator, dropped: usize) Allocator.Error!void {
    try out.print(allocator, "# HELP onyx_webpush_dropped Web Push jobs dropped because the delivery queue was full\n", .{});
    try out.print(allocator, "# TYPE onyx_webpush_dropped counter\n", .{});
    try out.print(allocator, "onyx_webpush_dropped {d}\n", .{dropped});
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag != .linux) return @import("os_runtime.zig").sleepMillis(ms);
    const linux = std.os.linux;
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "subscription list encode/decode round-trip" {
    const ep1 = try testing.allocator.dupe(u8, "https://push.example.net/send/abc123");
    const ep2 = try testing.allocator.dupe(u8, "https://fcm.googleapis.com/fcm/send/xyz");
    var subs = [_]Subscription{
        .{ .endpoint = ep1, .ua_public = [_]u8{4} ++ @as([64]u8, @splat(1)), .auth = @as([16]u8, @splat(9)) },
        .{ .endpoint = ep2, .ua_public = [_]u8{4} ++ @as([64]u8, @splat(2)), .auth = @as([16]u8, @splat(8)) },
    };
    defer for (&subs) |*s| s.deinit(testing.allocator);

    const encoded = try encodeList(testing.allocator, &subs);
    defer testing.allocator.free(encoded);

    const decoded = try decodeList(testing.allocator, encoded);
    defer freeList(testing.allocator, decoded);

    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqualStrings(subs[0].endpoint, decoded[0].endpoint);
    try testing.expectEqualSlices(u8, &subs[1].ua_public, &decoded[1].ua_public);
    try testing.expectEqualSlices(u8, &subs[0].auth, &decoded[0].auth);
}

test "decodeList rejects malformed records" {
    try testing.expectError(error.MalformedRecord, decodeList(testing.allocator, "no-tabs-here\n"));
    try testing.expectError(error.MalformedRecord, decodeList(testing.allocator, "https://x\tnot-b64!!\tAAAAAAAAAAAAAAAAAAAAAA\n"));
    // Empty value decodes to an empty list.
    const empty = try decodeList(testing.allocator, "");
    defer freeList(testing.allocator, empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "validEndpoint enforces https, length and character rules" {
    try testing.expect(validEndpoint("https://updates.push.services.mozilla.com/wpush/v2/token"));
    try testing.expect(!validEndpoint("http://plaintext.example/send"));
    try testing.expect(!validEndpoint("https://"));
    try testing.expect(!validEndpoint("https://x.example/a b"));
    try testing.expect(!validEndpoint("https://x.example/a\tb"));
    const long = "https://x.example/" ++ &@as([(max_endpoint_len)]u8, @splat('a'));
    try testing.expect(!validEndpoint(long));
}

test "webpush tls SSRF guard classifies push endpoint addresses" {
    const ip4 = struct {
        fn a(b: [4]u8) net.IpAddress {
            return .{ .ip4 = .{ .bytes = b, .port = 443 } };
        }
    }.a;
    // Disallowed: loopback / metadata / RFC-1918 / broadcast / unspecified.
    try testing.expect(isDisallowedPushAddr(ip4(.{ 127, 0, 0, 1 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 169, 254, 169, 254 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 10, 0, 0, 5 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 172, 16, 0, 1 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 172, 31, 255, 255 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 192, 168, 1, 1 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 0, 0, 0, 0 })));
    try testing.expect(isDisallowedPushAddr(ip4(.{ 255, 255, 255, 255 })));
    // Allowed: public IPv4 (example.com) and a neighbouring 172.x outside /12.
    try testing.expect(!isDisallowedPushAddr(ip4(.{ 93, 184, 216, 34 })));
    try testing.expect(!isDisallowedPushAddr(ip4(.{ 172, 32, 0, 1 })));
    try testing.expect(!isDisallowedPushAddr(ip4(.{ 8, 8, 8, 8 })));

    // IPv6: ::1 loopback, fe80:: link-local, fc00:: ULA, and ::ffff-mapped
    // internal all blocked; a public v6 allowed.
    var lo6: [16]u8 = @splat(0);
    lo6[15] = 1;
    try testing.expect(isDisallowedPushAddr(.{ .ip6 = .{ .bytes = lo6, .port = 443 } }));
    var ll6: [16]u8 = @splat(0);
    ll6[0] = 0xfe;
    ll6[1] = 0x80;
    try testing.expect(isDisallowedPushAddr(.{ .ip6 = .{ .bytes = ll6, .port = 443 } }));
    var ula6: [16]u8 = @splat(0);
    ula6[0] = 0xfd;
    try testing.expect(isDisallowedPushAddr(.{ .ip6 = .{ .bytes = ula6, .port = 443 } }));
    var mapped: [16]u8 = @splat(0);
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 169;
    mapped[13] = 254;
    mapped[14] = 169;
    mapped[15] = 254;
    try testing.expect(isDisallowedPushAddr(.{ .ip6 = .{ .bytes = mapped, .port = 443 } }));
    var pub6: [16]u8 = @splat(0);
    pub6[0] = 0x2a; // 2a00::/… global unicast
    try testing.expect(!isDisallowedPushAddr(.{ .ip6 = .{ .bytes = pub6, .port = 443 } }));
}

test "webpush tls SSRF guard refuses an internal-IP endpoint before connect" {
    const FakeInner = struct {
        addr: net.IpAddress,
        fn resolve(ctx: *anyopaque, _: []const u8, _: u16) anyerror!net.IpAddress {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            return self.addr;
        }
    };
    // A client-supplied metadata endpoint is refused at resolution — before any
    // socket/connect — so delivery never touches the internal target.
    var meta = FakeInner{ .addr = .{ .ip4 = .{ .bytes = .{ 169, 254, 169, 254 }, .port = 443 } } };
    var g_bad = GuardedResolver{ .inner = .{ .ctx = @ptrCast(&meta), .resolveFn = FakeInner.resolve } };
    const r_bad = g_bad.resolver();
    try testing.expectError(error.DisallowedPushEndpoint, r_bad.resolveFn(r_bad.ctx, "metadata.internal", 443));

    // A public target passes through unchanged.
    var good = FakeInner{ .addr = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 443 } } };
    var g_ok = GuardedResolver{ .inner = .{ .ctx = @ptrCast(&good), .resolveFn = FakeInner.resolve } };
    const r_ok = g_ok.resolver();
    const got = try r_ok.resolveFn(r_ok.ctx, "push.example.net", 443);
    try testing.expect(got == .ip4);
    try testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &got.ip4.bytes);
}

test "Vapid.loadOrCreate persists and reloads the same key" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var v1 = try Vapid.loadOrCreate(testing.io, testing.allocator, tmp.dir, "vapid.key");
    var v2 = try Vapid.loadOrCreate(testing.io, testing.allocator, tmp.dir, "vapid.key");

    var b1: [87]u8 = undefined;
    var b2: [87]u8 = undefined;
    try testing.expectEqualStrings(v1.publicB64(&b1), v2.publicB64(&b2));
}

test "worker enqueue/shutdown never blocks and bounds the queue" {
    // No network in tests: spawn the thread, enqueue against a dead resolver,
    // and shut down. Exercises the queue/lifecycle paths (delivery itself is
    // covered by the crypto KATs + live verification).
    const FailResolver = struct {
        fn resolve(_: *anyopaque, _: []const u8, _: u16) anyerror!@import("std").Io.net.IpAddress {
            return error.TemporaryNameServerFailure;
        }
    };
    var ctx_byte: u8 = 0;
    var w = Worker{
        .allocator = testing.allocator,
        .vapid = ecdsa.KeyPair.generate(testing.io),
        .subject = "mailto:t@example.net",
        .resolver = .{ .ctx = @ptrCast(&ctx_byte), .resolveFn = FailResolver.resolve },
        .trust_anchors = &.{},
    };
    try w.spawn();
    const ua = try @import("../crypto/ecdh_p256.zig").generate();
    _ = w.enqueue("https://push.example.net/send/1", ua.public_sec1, @as([16]u8, @splat(1)), "{\"type\":\"dm\"}");
    sleepMs(50);
    w.shutdown();
    // The lone job either failed (dead resolver) or was still queued at
    // shutdown; both are fine — nothing hung, nothing leaked.
    try testing.expect(w.sent == 0);
}

test "DST GAP-D8 webpush queue overflow increments a metric and emits an oper event" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try services_mod.OroStore.open(testing.allocator, testing.io, tmp.dir, "d8-webpush.wal");
    defer store.deinit();
    var svc = services_mod.Services.init(&store, null);

    const endpoint = "https://push.example.net/send/kept";
    var subs = [_]Subscription{
        .{
            .endpoint = try testing.allocator.dupe(u8, endpoint),
            .ua_public = [_]u8{4} ++ @as([64]u8, @splat(1)),
            .auth = @as([16]u8, @splat(7)),
        },
    };
    defer subs[0].deinit(testing.allocator);
    const blob = try encodeList(testing.allocator, &subs);
    defer testing.allocator.free(blob);
    try svc.webpushPut("alice", blob);

    var ctx_byte: u8 = 0;
    const FailResolver = struct {
        fn resolve(_: *anyopaque, _: []const u8, _: u16) anyerror!net.IpAddress {
            return error.TemporaryNameServerFailure;
        }
    };
    var w = Worker{
        .allocator = testing.allocator,
        .vapid = ecdsa.KeyPair.generate(testing.io),
        .subject = "mailto:t@example.net",
        .resolver = .{ .ctx = @ptrCast(&ctx_byte), .resolveFn = FailResolver.resolve },
        .trust_anchors = &.{},
    };
    // No worker thread: a live drain would hide the full-queue drop.
    defer w.shutdown();

    var i: usize = 0;
    while (i < max_queued_jobs) : (i += 1) {
        try testing.expectEqual(Worker.EnqueueResult.queued, w.enqueue(endpoint, subs[0].ua_public, subs[0].auth, "{\"type\":\"dm\"}"));
    }
    try testing.expectEqual(@as(usize, 0), w.dropped.load(.monotonic));
    try testing.expect(w.takeOverflowOperEvent() == null);
    try testing.expectEqual(max_queued_jobs, w.queue.items.len);

    try testing.expectEqual(Worker.EnqueueResult.dropped, w.enqueue(endpoint, subs[0].ua_public, subs[0].auth, "{\"type\":\"dm\"}"));
    try testing.expectEqual(@as(usize, 1), w.dropped.load(.monotonic));
    try testing.expectEqual(max_queued_jobs, w.queue.items.len);
    try testing.expectEqualStrings(endpoint, w.queue.items[0].endpoint);
    try testing.expectEqualStrings(endpoint, w.queue.items[max_queued_jobs - 1].endpoint);
    try testing.expectEqualStrings(overflow_oper_message, w.takeOverflowOperEvent() orelse "");
    try testing.expect(w.takeOverflowOperEvent() == null);

    try testing.expectEqual(Worker.EnqueueResult.dropped, w.enqueue(endpoint, subs[0].ua_public, subs[0].auth, "{\"type\":\"dm\"}"));
    try testing.expectEqual(@as(usize, 2), w.dropped.load(.monotonic));
    try testing.expectEqual(max_queued_jobs, w.queue.items.len);
    try testing.expectEqualStrings(overflow_oper_message, w.takeOverflowOperEvent() orelse "");

    var metric: std.ArrayList(u8) = .empty;
    defer metric.deinit(testing.allocator);
    try appendDroppedSample(&metric, testing.allocator, w.dropped.load(.monotonic));
    try testing.expect(std.mem.indexOf(u8, metric.items, "# TYPE onyx_webpush_dropped counter\n") != null);
    try testing.expect(std.mem.indexOf(u8, metric.items, "onyx_webpush_dropped 2\n") != null);
    var zero: std.ArrayList(u8) = .empty;
    defer zero.deinit(testing.allocator);
    try appendDroppedSample(&zero, testing.allocator, 0);
    try testing.expect(std.mem.indexOf(u8, zero.items, "onyx_webpush_dropped 0\n") != null);

    const kept = svc.webpushGetAlloc(testing.allocator, "alice") orelse return error.MissingSubscription;
    defer testing.allocator.free(kept);
    try testing.expectEqualSlices(u8, blob, kept);
    try testing.expectEqualStrings(portable_disable_reason, "web push is Linux-only; disabled");

    std.debug.print("GAP-D8 branch=full webpush queue increments onyx_webpush_dropped and emits an oper event; subscription rows in props stay; live mail stays off; non-Linux keeps the explicit disable\n", .{});
}

pub const Execution = enum(u8) { unstarted, paused };
pub const SnapshotBounds = struct { max_bytes: usize, max_dead_entries: usize };
pub const Snapshot = struct {
    allocator: Allocator,
    jobs: []Job,
    dead: [][]u8,
    sent: usize,
    failed: usize,
    dropped: usize,
    overflow_events: usize,
    config_digest: [32]u8,
    execution: Execution,
    pub fn deinit(self: *Snapshot) void {
        for (self.jobs) |*job| job.deinit(self.allocator);
        // Preserve the explicit secret wipe through the allocator handoff.
        if (self.jobs.len != 0) self.allocator.rawFree(std.mem.sliceAsBytes(self.jobs), .fromByteUnits(@alignOf(Job)), @returnAddress());
        for (self.dead) |endpoint| freeEndpoint(self.allocator, endpoint);
        self.allocator.free(self.dead);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, worker: *const Worker, bounds: SnapshotBounds) !void {
        if (!std.mem.eql(u8, &self.config_digest, &try worker.configDigest())) return error.ConfigMismatch;
        try checkSnapshotBounds(self.jobs, self.dead, bounds);
    }
};
fn checkSnapshotBounds(jobs: []const Job, dead: []const []const u8, bounds: SnapshotBounds) !void {
    if (jobs.len > max_queued_jobs or dead.len > bounds.max_dead_entries) return error.Capacity;
    var bytes: usize = @sizeOf(Snapshot);
    bytes = std.math.add(usize, bytes, std.math.mul(usize, jobs.len, @sizeOf(Job)) catch return error.Capacity) catch return error.Capacity;
    bytes = std.math.add(usize, bytes, std.math.mul(usize, dead.len, @sizeOf([]u8)) catch return error.Capacity) catch return error.Capacity;
    for (jobs) |job| {
        bytes = std.math.add(usize, bytes, job.endpoint.len) catch return error.Capacity;
        bytes = std.math.add(usize, bytes, job.payload.len) catch return error.Capacity;
    }
    for (dead) |endpoint| bytes = std.math.add(usize, bytes, endpoint.len) catch return error.Capacity;
    if (bytes > bounds.max_bytes) return error.Capacity;
}
fn clonePushJob(allocator: Allocator, job: Job) !Job {
    const endpoint = try allocator.dupe(u8, job.endpoint);
    errdefer freeEndpoint(allocator, endpoint);
    const payload = try allocator.dupe(u8, job.payload);
    return .{ .endpoint = endpoint, .payload = payload, .ua_public = job.ua_public, .auth = job.auth };
}

fn freeEndpoint(allocator: Allocator, endpoint: []u8) void {
    std.crypto.secureZero(u8, endpoint);
    if (endpoint.len != 0) allocator.rawFree(endpoint, .fromByteUnits(1), @returnAddress());
}

const DeliveryFixture = if (builtin.is_test) struct {
    entered: std.Io.Event = .unset,
    proceed: std.Io.Event = .unset,
    calls: std.atomic.Value(usize) = .init(0),
    fn beforeDelivery(self: *@This()) void {
        if (self.calls.fetchAdd(1, .acq_rel) != 0) return;
        self.entered.set(testing.io);
        self.proceed.waitUncancelable(testing.io);
    }
} else void;

fn retainedTestWorker(allocator: Allocator, resolver: *acme_runner.SystemResolver) !Worker {
    const secret = try ecdsa.SecretKey.fromBytes(@splat(1));
    return .{ .allocator = allocator, .vapid = try ecdsa.KeyPair.fromSecretKey(secret), .subject = "mailto:retained@example.invalid", .resolver = resolver.resolver(), .trust_anchors = &.{} };
}
fn retainedTestSeed(worker: *Worker) !void {
    const key = worker.vapid.public_key.toUncompressedSec1();
    if (worker.enqueue("https://127.0.0.1/first", key, @splat(1), "first-payload") != .queued) return error.OutOfMemory;
    if (worker.enqueue("https://127.0.0.1/second", key, @splat(2), "second-payload") != .queued) return error.OutOfMemory;
    for ([_][]const u8{ "https://dead.invalid/one", "https://dead.invalid/two", "https://dead.invalid/three" }) |value| {
        const owned = try worker.allocator.dupe(u8, value);
        errdefer freeEndpoint(worker.allocator, owned);
        try worker.dead.append(worker.allocator, owned);
    }
    worker.sent = 31;
    worker.failed = 17;
    worker.dropped.store(9, .monotonic);
    worker.overflow_events = 4;
}
const retained_test_bounds: SnapshotBounds = .{ .max_bytes = 65536, .max_dead_entries = 32 };

test "webpush lifecycle: failed output reconciliation retains exact endpoints and unaccepted notices for retry" {
    const Consumer = struct {
        refuse: bool = true,
        dead_calls: usize = 0,
        notices: usize = 0,
        fn dead(self: *@This(), endpoints: []const []const u8) anyerror!void {
            self.dead_calls += 1;
            try testing.expectEqual(@as(usize, 3), endpoints.len);
            try testing.expectEqualStrings("https://dead.invalid/three", endpoints[2]);
            if (self.refuse) return error.DurableBoundaryUncertain;
        }
        fn notice(self: *@This(), message: []const u8) anyerror!void {
            try testing.expectEqualStrings(overflow_oper_message, message);
            if (self.refuse and self.notices == 1) return error.OutOfMemory;
            self.notices += 1;
        }
    };
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    try retainedTestSeed(&worker);
    const original = worker.dead.items[2].ptr;
    var consumer: Consumer = .{};
    try testing.expectError(error.DurableBoundaryUncertain, worker.reconcileDead(&consumer, Consumer.dead));
    try testing.expectEqual(@as(usize, 3), worker.dead.items.len);
    try testing.expect(worker.dead.items[2].ptr == original);
    try testing.expectError(error.OutOfMemory, worker.reconcileOverflow(&consumer, Consumer.notice));
    try testing.expectEqual(@as(usize, 3), worker.overflow_events);
    consumer.refuse = false;
    try worker.reconcileDead(&consumer, Consumer.dead);
    try worker.reconcileOverflow(&consumer, Consumer.notice);
    try testing.expectEqual(@as(usize, 2), consumer.dead_calls);
    try testing.expectEqual(@as(usize, 4), consumer.notices);
    try testing.expectEqual(@as(usize, 0), worker.dead.items.len);
    try testing.expectEqual(@as(usize, 0), worker.overflow_events);
    try testing.expectEqual(@as(usize, 2), worker.queue.items.len);
    try worker.reconcileDead(&consumer, Consumer.dead);
    try worker.reconcileOverflow(&consumer, Consumer.notice);
    try testing.expectEqual(@as(usize, 2), consumer.dead_calls);
    try testing.expectEqual(@as(usize, 4), consumer.notices);
}

test "webpush lifecycle: original producer fence rejects enqueue and foreign or resumed snapshot authority" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&worker);
    var other = try retainedTestWorker(testing.allocator, &resolver);
    defer other.shutdown();
    const foreign = try other.fenceProducers();
    const fence = try worker.fenceProducers();
    const key = worker.vapid.public_key.toUncompressedSec1();
    try testing.expectEqual(Worker.EnqueueResult.stopped, worker.enqueue("https://127.0.0.1/refused", key, @splat(3), "refused"));
    try testing.expectError(error.InvalidProducerFence, worker.captureFrozen(testing.allocator, foreign, null, retained_test_bounds));
    var snapshot = try worker.captureFrozen(testing.allocator, fence, null, retained_test_bounds);
    defer snapshot.deinit();
    try testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
    try testing.expectEqual(@as(usize, 3), snapshot.dead.len);
    try testing.expectEqual(@as(usize, 4), snapshot.overflow_events);
    try expectRetainedSeed(&worker);
    try worker.resumeProducers(fence);
    try testing.expectError(error.ProducersNotFrozen, worker.captureFrozen(testing.allocator, fence, null, retained_test_bounds));
    const next = try worker.fenceProducers();
    try testing.expectError(error.InvalidProducerFence, worker.requireProducersFrozen(fence));
    try worker.requireProducersFrozen(next);
}

test "webpush lifecycle: joined OOM worker retains queued output and refuses terminal settlement" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(allocator.allocator(), &resolver);
    var cleanup_transferred = false;
    defer if (!cleanup_transferred) worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    const key = worker.vapid.public_key.toUncompressedSec1();
    try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("https://127.0.0.1/retained", key, @splat(1), "original-payload"));
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    cleanup_transferred = true;
    defer {
        worker.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        worker.detachAfterJoined() catch unreachable;
        worker.shutdown();
        gate.control.destroyJoined();
    }
    const slot = try gate.view.slot(.webpush, 0, &worker);
    try worker.prepareDormantWorker(gate.control, gate.view, slot);
    try gate.control.awaitAllParked(retainedTestDeadline(5000));
    const fence = try worker.fenceProducers();
    try testing.expectError(error.NotJoined, worker.requireTerminalSettled(fence));
    // beginDelivery must reserve dead-output metadata before consuming a job.
    // Fail that exact next allocation; stopping must retain the original job.
    allocator.fail_index = allocator.alloc_index;
    allocator.resize_fail_index = allocator.resize_index;
    worker.requestStopAndWake();
    gate.control.releaseAll();
    try gate.control.joinParticipant(slot);
    try testing.expect(allocator.has_induced_failure);
    try testing.expectError(error.PendingOutput, worker.requireTerminalSettled(fence));
    try testing.expectEqual(@as(usize, 1), worker.queue.items.len);
    try testing.expectEqualStrings("original-payload", worker.queue.items[0].payload);
    try testing.expect(!worker.delivery_inflight);
    try testing.expectEqual(@as(usize, 0), worker.sent);
    try testing.expectEqual(@as(usize, 0), worker.failed);
}

fn expectRetainedSeed(worker: *Worker) !void {
    try testing.expectEqual(@as(usize, 2), worker.queue.items.len);
    try testing.expectEqualStrings("https://127.0.0.1/first", worker.queue.items[0].endpoint);
    try testing.expectEqualStrings("first-payload", worker.queue.items[0].payload);
    try testing.expectEqualStrings("second-payload", worker.queue.items[1].payload);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(2)), &worker.queue.items[1].auth);
    try testing.expectEqual(@as(usize, 3), worker.dead.items.len);
    try testing.expectEqualStrings("https://dead.invalid/three", worker.dead.items[2]);
    try testing.expectEqual(@as(usize, 31), worker.sent);
    try testing.expectEqual(@as(usize, 17), worker.failed);
    try testing.expectEqual(@as(usize, 9), worker.dropped.load(.acquire));
    try testing.expectEqual(@as(usize, 4), worker.overflow_events);
}
fn captureRetainedOom(allocator: Allocator) !void {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var source = try retainedTestWorker(testing.allocator, &resolver);
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&source);
    const original = source.queue.items[0].endpoint.ptr;
    var snapshot = source.captureUnstarted(allocator, retained_test_bounds) catch |err| {
        try expectRetainedSeed(&source);
        try testing.expect(source.queue.items[0].endpoint.ptr == original);
        var retry = try source.captureUnstarted(testing.allocator, retained_test_bounds);
        retry.deinit();
        return err;
    };
    defer snapshot.deinit();
    try testing.expectEqual(Execution.unstarted, snapshot.execution);
    try testing.expect(snapshot.jobs[0].endpoint.ptr != original);
    try expectRetainedSeed(&source);
    var target = try retainedTestWorker(testing.allocator, &resolver);
    defer target.shutdown();
    try target.prepareColdResources(testing.io, &resolver);
    try target.restoreSnapshot(&snapshot, retained_test_bounds);
    try expectRetainedSeed(&target);
    try testing.expect(target.queue.items[0].endpoint.ptr != snapshot.jobs[0].endpoint.ptr);
    try testing.expect(target.dead.items[2].ptr != snapshot.dead[2].ptr);
}

test "webpush retained capture owns full FIFO dead events secrets counters and every OOM retry" {
    try testing.checkAllAllocationFailures(testing.allocator, captureRetainedOom, .{});
    try captureRetainedOom(testing.allocator);
}

test "webpush restore every allocation failure preserves target and same-owner retry" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var source = try retainedTestWorker(testing.allocator, &resolver);
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&source);
    var snapshot = try source.captureUnstarted(testing.allocator, retained_test_bounds);
    defer snapshot.deinit();
    var index: usize = 0;
    while (index < 100) : (index += 1) {
        var fail = testing.FailingAllocator.init(testing.allocator, .{});
        var target = try retainedTestWorker(fail.allocator(), &resolver);
        defer target.shutdown();
        try target.prepareColdResources(testing.io, &resolver);
        const key = target.vapid.public_key.toUncompressedSec1();
        try testing.expectEqual(Worker.EnqueueResult.queued, target.enqueue("https://old.invalid/kept", key, @splat(7), "OLD-target"));
        const old_queue = target.queue.items.ptr;
        const old_endpoint = target.queue.items[0].endpoint.ptr;
        target.sent = 91;
        fail.fail_index = fail.alloc_index + index;
        fail.resize_fail_index = fail.resize_index; // never hide an allocation behind resize
        if (target.restoreSnapshot(&snapshot, retained_test_bounds)) |_| {
            try expectRetainedSeed(&target);
            try testing.expect(index > 0);
            return;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(@as(usize, 1), target.queue.items.len);
            try testing.expectEqualStrings("OLD-target", target.queue.items[0].payload);
            try testing.expect(target.queue.items.ptr == old_queue and target.queue.items[0].endpoint.ptr == old_endpoint);
            try testing.expectEqual(@as(usize, 91), target.sent);
            try testing.expectEqual(@as(usize, 0), target.dead.items.len);
            fail.fail_index = std.math.maxInt(usize);
            fail.resize_fail_index = std.math.maxInt(usize);
            try target.restoreSnapshot(&snapshot, retained_test_bounds);
            try expectRetainedSeed(&target);
        }
    }
    return error.MissingSuccessfulAllocationFrontier;
}

test "webpush snapshot bounds and configuration mismatches refuse before clone" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var source = try retainedTestWorker(testing.allocator, &resolver);
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&source);
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.Capacity, source.captureUnstarted(fail.allocator(), .{ .max_bytes = 65536, .max_dead_entries = 2 }));
    try testing.expectError(error.Capacity, source.captureUnstarted(fail.allocator(), .{ .max_bytes = 1, .max_dead_entries = 32 }));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
    var snapshot = try source.captureUnstarted(testing.allocator, retained_test_bounds);
    defer snapshot.deinit();
    var target = try retainedTestWorker(fail.allocator(), &resolver);
    defer target.shutdown();
    try target.prepareColdResources(testing.io, &resolver);
    target.subject = "mailto:different@example.invalid";
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    target.subject = source.subject;
    target.trust_anchors = &.{"different DER anchor"};
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    target.trust_anchors = &.{};
    resolver.dns_port += 1;
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    resolver.dns_port -= 1;
    resolver.resolv_conf_max_bytes += 1;
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    resolver.resolv_conf_max_bytes -= 1;
    target.vapid = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(2)));
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    target.vapid.secret_key = source.vapid.secret_key; // inconsistent key pair must also refuse
    try testing.expectError(error.ConfigMismatch, target.restoreSnapshot(&snapshot, retained_test_bounds));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
    try expectRetainedSeed(&source);
}

test "webpush dead response transfers admitted endpoint with no allocation or lost drain" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    for ([_]u16{ 404, 410 }) |status| {
        var fail = testing.FailingAllocator.init(testing.allocator, .{});
        var worker = try retainedTestWorker(fail.allocator(), &resolver);
        defer worker.shutdown();
        const key = worker.vapid.public_key.toUncompressedSec1();
        try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("https://dead.invalid/exact", key, @splat(3), "secret"));
        const original = worker.queue.items[0].endpoint.ptr;
        fail.fail_index = fail.alloc_index;
        fail.resize_fail_index = fail.resize_index;
        try testing.expectError(error.OutOfMemory, worker.beginDelivery());
        try testing.expectEqual(@as(usize, 1), worker.queue.items.len);
        try testing.expect(worker.queue.items[0].endpoint.ptr == original);
        try testing.expect(!worker.delivery_inflight);
        fail.fail_index = std.math.maxInt(usize);
        fail.resize_fail_index = std.math.maxInt(usize);
        var job = (try worker.beginDelivery()).?;
        defer {
            job.deinit(worker.allocator);
            worker.finishDelivery();
        }
        const before_allocations = fail.alloc_index;
        const before_resizes = fail.resize_index;
        fail.fail_index = before_allocations;
        fail.resize_fail_index = before_resizes;
        try testing.expectEqual(@as(usize, 0), worker.drainDead().len);
        worker.recordResponseStatus(&job, status);
        try testing.expectEqual(@as(usize, 0), job.endpoint.len);
        try testing.expectEqual(@as(usize, 1), worker.dead.items.len);
        try testing.expect(worker.dead.items[0].ptr == original);
        try testing.expectEqualStrings("https://dead.invalid/exact", worker.dead.items[0]);
        try testing.expectEqual(@as(usize, 1), worker.failed);
        try testing.expectEqual(before_allocations, fail.alloc_index);
        try testing.expectEqual(before_resizes, fail.resize_index);
    }
}

fn retainedTestDeadline(ms: i64) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(ms) });
}

test "webpush actual Gate worker pauses after one settled delivery and retains exact remaining FIFO" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    var cleanup_transferred = false;
    defer if (!cleanup_transferred) worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    var fixture: DeliveryFixture = .{};
    worker.delivery_fixture = &fixture;
    const key = worker.vapid.public_key.toUncompressedSec1();
    try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("https://127.0.0.1/first", key, @splat(1), "first"));
    try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("https://127.0.0.1/second", key, @splat(2), "second"));
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    cleanup_transferred = true;
    defer {
        fixture.proceed.set(testing.io);
        worker.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        worker.detachAfterJoined() catch unreachable;
        worker.shutdown();
        gate.control.destroyJoined();
    }
    const slot = try gate.view.slot(.webpush, 0, &worker);
    try worker.prepareDormantWorker(gate.control, gate.view, slot);
    try gate.control.awaitAllParked(retainedTestDeadline(5000));
    try worker.requireParked();
    try testing.expectEqual(@as(usize, 0), fixture.calls.load(.acquire));
    try testing.expectError(error.NotPrepared, worker.requireActivated());
    try testing.expectError(error.NotQuiescent, worker.captureUnstarted(testing.allocator, retained_test_bounds));
    gate.control.releaseAll();
    try fixture.entered.waitTimeout(testing.io, .{ .deadline = retainedTestDeadline(5000) });
    try worker.requireActivated();
    const token = try worker.requestPause(1);
    try testing.expectError(error.Timeout, worker.awaitPaused(token, retainedTestDeadline(0)));
    try testing.expectError(error.NotPaused, worker.capturePaused(testing.allocator, token, retained_test_bounds));
    fixture.proceed.set(testing.io);
    try worker.awaitPaused(token, retainedTestDeadline(5000));
    var snapshot = try worker.capturePaused(testing.allocator, token, retained_test_bounds);
    defer snapshot.deinit();
    try testing.expectEqual(Execution.paused, snapshot.execution);
    try testing.expectEqual(@as(usize, 1), snapshot.failed); // actual crypto + guarded resolver refusal, no socket connect
    try testing.expectEqual(@as(usize, 1), snapshot.jobs.len);
    try testing.expectEqualStrings("https://127.0.0.1/second", snapshot.jobs[0].endpoint);
    try testing.expectEqualStrings("second", snapshot.jobs[0].payload);
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    try worker.resumePaused(token);
    worker.requestStopAndWake(); // same worker drains the second accepted job
    gate.control.joinAll();
    try worker.detachAfterJoined();
    worker.shutdown();
    try testing.expectEqual(@as(usize, 2), worker.failed);
    try testing.expectEqual(@as(usize, 2), fixture.calls.load(.acquire));
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().joined);
    try testing.expectEqual(@as(usize, 1), snapshot.jobs.len); // independently owned after source shutdown
    try testing.expectError(error.Stopped, worker.captureUnstarted(testing.allocator, retained_test_bounds));
}

test "webpush snapshot and stopped owner wipe secret copies in retained allocator storage" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var source = try retainedTestWorker(testing.allocator, &resolver);
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&source);
    var bytes: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&bytes);
    var snapshot = try source.captureUnstarted(fba.allocator(), retained_test_bounds);
    const endpoint = snapshot.jobs[0].endpoint;
    const payload = snapshot.jobs[0].payload;
    const auth = &snapshot.jobs[0].auth;
    const dead = snapshot.dead[0];
    snapshot.deinit();
    for (endpoint) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (payload) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (auth) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (dead) |byte| try testing.expectEqual(@as(u8, 0), byte);
    source.shutdown();
    for (std.mem.asBytes(&source.vapid)) |byte| try testing.expectEqual(@as(u8, 0), byte);
    try testing.expectError(error.Stopped, source.spawn());
}

test "webpush configured resolver rejects foreign identity before binding and retries exact owner" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var other: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    const expected = resolver.resolver();
    worker.resolver = other.resolver();
    try testing.expectError(error.ConfigMismatch, worker.prepareColdResources(testing.io, &resolver));
    try testing.expect(worker.system_resolver == null and worker.runtime.pause.io == null);
    const Foreign = struct {
        fn resolve(_: *anyopaque, _: []const u8, _: u16) anyerror!net.IpAddress {
            return error.TestUnexpectedResolution;
        }
    };
    worker.resolver = .{ .ctx = expected.ctx, .resolveFn = Foreign.resolve };
    try testing.expectError(error.ConfigMismatch, worker.prepareColdResources(testing.io, &resolver));
    try testing.expect(worker.system_resolver == null and worker.runtime.pause.io == null);
    worker.resolver = expected;
    try worker.prepareColdResources(testing.io, &resolver);
    try testing.expect(worker.system_resolver.? == &resolver);
    try testing.expectError(error.AlreadyStarted, worker.prepareColdResources(testing.io, &resolver));
}

test "webpush dormant cancellation joins without entering delivery or consuming accepted state" {
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    var cleanup_transferred = false;
    defer if (!cleanup_transferred) worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&worker);
    var fixture: DeliveryFixture = .{};
    worker.delivery_fixture = &fixture;
    const old_endpoint = worker.queue.items[0].endpoint.ptr;
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    cleanup_transferred = true;
    defer {
        fixture.proceed.set(testing.io);
        worker.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        worker.detachAfterJoined() catch unreachable;
        worker.shutdown();
        gate.control.destroyJoined();
    }
    try worker.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.webpush, 0, &worker));
    try gate.control.awaitAllParked(retainedTestDeadline(5000));
    try worker.requireParked();
    gate.control.cancelAllAndJoin();
    try testing.expectEqual(@as(usize, 0), fixture.calls.load(.acquire));
    try testing.expect(!worker.runtime.entered.load(.acquire));
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().joined);
    try expectRetainedSeed(&worker);
    try testing.expect(worker.queue.items[0].endpoint.ptr == old_endpoint);
    try testing.expectError(error.NotPrepared, worker.requireActivated());
    try testing.expectError(error.SharedGateOwned, worker.runtime.requireDetached());
    try worker.detachAfterJoined();
    worker.shutdown();
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().joined);
}

fn loadExistingRetainedOom(allocator: Allocator, dir: std.Io.Dir) !void {
    var value = try Vapid.loadExisting(testing.io, allocator, dir, "retained.key");
    defer std.crypto.secureZero(u8, std.mem.asBytes(&value));
    const expected = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(1)));
    try testing.expectEqualSlices(u8, &expected.public_key.toUncompressedSec1(), &value.key_pair.public_key.toUncompressedSec1());
}

test "webpush inherited VAPID identity is read only and every allocation failure permits exact retry" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try testing.expectError(error.FileNotFound, Vapid.loadExisting(testing.io, testing.allocator, tmp.dir, "retained.key"));
    try testing.expectError(error.FileNotFound, tmp.dir.openFile(testing.io, "retained.key", .{}));
    const encoded = "0101010101010101010101010101010101010101010101010101010101010101\n";
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "retained.key", .data = encoded });
    try testing.checkAllAllocationFailures(testing.allocator, loadExistingRetainedOom, .{tmp.dir});
    try loadExistingRetainedOom(testing.allocator, tmp.dir);
    const after = try tmp.dir.readFileAlloc(testing.io, "retained.key", testing.allocator, .limited(256));
    defer freeEndpoint(testing.allocator, after);
    try testing.expectEqualStrings(encoded, after);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "retained.key", .data = "invalid" });
    try testing.expectError(error.InvalidVapidKey, Vapid.loadExisting(testing.io, testing.allocator, tmp.dir, "retained.key"));
    const invalid = try tmp.dir.readFileAlloc(testing.io, "retained.key", testing.allocator, .limited(256));
    defer freeEndpoint(testing.allocator, invalid);
    try testing.expectEqualStrings("invalid", invalid);
}

test "webpush dormant registration demands source stack and allocator before retaining any row" {
    const start = runtime_pause.start_gate;
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&worker);
    const endpoint = worker.queue.items[0].endpoint.ptr;
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const wrong_options = [_]std.Thread.SpawnConfig{
        .{},
        .{ .stack_size = 4 * 1024 * 1024 },
        .{ .stack_size = dormant_spawn_options.stack_size, .allocator = fail.allocator() },
    };
    for (wrong_options) |options| {
        const specs = [_]start.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = options }};
        const gate = try start.create(testing.allocator, testing.io, &specs);
        defer {
            gate.control.cancelAllAndJoin();
            worker.detachAfterJoined() catch unreachable;
            gate.control.destroyJoined();
        }
        const slot = try gate.view.slot(.webpush, 0, &worker);
        try testing.expectError(error.InvalidOptions, worker.validateDormantRegistration(gate.control, gate.view, slot));
        try testing.expectError(error.InvalidOptions, worker.prepareDormantWorker(gate.control, gate.view, slot));
        try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
        try testing.expect(worker.runtime.view == null and worker.runtime.slot == null);
        try testing.expect(!worker.stop_flag.load(.acquire));
        try testing.expect(!worker.runtime.entered.load(.acquire));
        try expectRetainedSeed(&worker);
        try testing.expect(worker.queue.items[0].endpoint.ptr == endpoint);
    }
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
}

test "webpush registration rejects foreign control slot and owner without changing source custody" {
    const start = runtime_pause.start_gate;
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    var other = try retainedTestWorker(testing.allocator, &resolver);
    defer other.shutdown();
    const specs = [_]start.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const foreign_specs = [_]start.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &other, .options = dormant_spawn_options }};
    const gate = try start.create(testing.allocator, testing.io, &specs);
    defer {
        worker.requestStopAndWake();
        gate.control.cancelAllAndJoin();
        worker.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    const foreign = try start.create(testing.allocator, testing.io, &foreign_specs);
    defer {
        foreign.control.cancelAllAndJoin();
        foreign.control.destroyJoined();
    }
    const slot = try gate.view.slot(.webpush, 0, &worker);
    const other_slot = try foreign.view.slot(.webpush, 0, &other);
    try worker.validateDormantRegistration(gate.control, gate.view, slot);
    try testing.expectError(error.NotPrepared, worker.prepareDormantWorker(gate.control, gate.view, slot));
    try worker.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&worker);
    const endpoint = worker.queue.items[0].endpoint.ptr;
    try testing.expectError(error.InvalidGate, worker.prepareDormantWorker(foreign.control, gate.view, slot));
    try testing.expectError(error.InvalidSlot, worker.prepareDormantWorker(gate.control, gate.view, other_slot));
    try testing.expectError(error.InvalidSlot, worker.prepareDormantWorker(foreign.control, foreign.view, other_slot));
    try testing.expect(worker.runtime.view == null and worker.runtime.slot == null);
    try testing.expect(!worker.stop_flag.load(.acquire));
    try expectRetainedSeed(&worker);
    try testing.expect(worker.queue.items[0].endpoint.ptr == endpoint);
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
    try testing.expectEqual(@as(usize, 0), foreign.view.inspect().spawned);
    try worker.prepareDormantWorker(gate.control, gate.view, slot);
    try gate.control.awaitAllParked(retainedTestDeadline(5000));
    try testing.expect(worker.runtime.view.? == gate.view);
    try testing.expectError(error.NotJoined, worker.detachAfterJoined());
    try testing.expectError(error.SharedGateOwned, worker.runtime.requireDetached());
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().joined);
    try testing.expectEqual(start.Phase.preparing, gate.view.inspect().phase);
    gate.control.cancelAllAndJoin();
    try worker.detachAfterJoined();
    try worker.runtime.requireDetached();
    try expectRetainedSeed(&worker);
}

test "webpush failed managed spawn retains its row until coordinator cancellation and detach" {
    const start = runtime_pause.start_gate;
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    try retainedTestSeed(&worker);
    const endpoint = worker.queue.items[0].endpoint.ptr;
    const specs = [_]start.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const gate = try start.create(testing.allocator, testing.io, &specs);
    defer {
        worker.requestStopAndWake();
        gate.control.cancelAllAndJoin();
        worker.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    start.Fixture.failSpawn(gate.control, 0);
    const slot = try gate.view.slot(.webpush, 0, &worker);
    try testing.expectError(error.SystemResources, worker.prepareDormantWorker(gate.control, gate.view, slot));
    try testing.expect(worker.runtime.view.? == gate.view);
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().spawned);
    try testing.expectError(error.NotJoined, worker.detachAfterJoined());
    try testing.expectError(error.SharedGateOwned, worker.runtime.requireDetached());
    try expectRetainedSeed(&worker);
    try testing.expect(worker.queue.items[0].endpoint.ptr == endpoint);
    gate.control.cancelAllAndJoin();
    try testing.expectError(error.SharedGateOwned, worker.runtime.requireDetached());
    try worker.detachAfterJoined();
    try worker.runtime.requireDetached();
    try testing.expect(!worker.runtime.entered.load(.acquire));
    try expectRetainedSeed(&worker);
}

test "webpush retained paused worker drains accepted FIFO on source stop before external join" {
    const start = runtime_pause.start_gate;
    var resolver: acme_runner.SystemResolver = .{ .allocator = testing.allocator, .io = testing.io };
    var worker = try retainedTestWorker(testing.allocator, &resolver);
    defer worker.shutdown();
    try worker.prepareColdResources(testing.io, &resolver);
    const specs = [_]start.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &worker, .options = dormant_spawn_options }};
    const gate = try start.create(testing.allocator, testing.io, &specs);
    defer {
        worker.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        worker.detachAfterJoined() catch unreachable;
        gate.control.destroyJoined();
    }
    const token = try worker.requestPause(1);
    try worker.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.webpush, 0, &worker));
    try gate.control.awaitAllParked(retainedTestDeadline(5000));
    gate.control.releaseAll();
    try worker.awaitPaused(token, retainedTestDeadline(5000));
    try worker.requireActivated();
    const key = worker.vapid.public_key.toUncompressedSec1();
    try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("invalid-first", key, @splat(1), "first"));
    try testing.expectEqual(Worker.EnqueueResult.queued, worker.enqueue("invalid-second", key, @splat(2), "second"));
    var snapshot = try worker.capturePaused(testing.allocator, token, retained_test_bounds);
    defer snapshot.deinit();
    try testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
    try testing.expectEqualStrings("invalid-first", snapshot.jobs[0].endpoint);
    try testing.expectEqualStrings("invalid-second", snapshot.jobs[1].endpoint);
    worker.requestStopAndWake();
    try testing.expectError(error.Stopped, worker.requireActivated());
    try testing.expectEqual(Worker.EnqueueResult.stopped, worker.enqueue("refused", key, @splat(3), "third"));
    try testing.expectEqual(@as(usize, 0), gate.view.inspect().joined);
    try testing.expectError(error.NotJoined, worker.detachAfterJoined());
    gate.control.joinAll();
    try testing.expectEqual(@as(usize, 2), worker.failed); // actual URL refusal; no network dependency
    try testing.expectEqual(@as(usize, 0), worker.queue.items.len);
    try testing.expect(!worker.delivery_inflight);
    try testing.expect(worker.runtime.exited.load(.acquire));
    try testing.expectError(error.SharedGateOwned, worker.runtime.requireDetached());
    try worker.detachAfterJoined();
    worker.shutdown();
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    try testing.expectEqual(@as(usize, 1), gate.view.inspect().joined);
    try testing.expectEqual(@as(usize, 2), snapshot.jobs.len);
}
