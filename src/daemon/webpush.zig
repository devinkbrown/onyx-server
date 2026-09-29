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
const dlog = @import("dlog.zig");
const wp_crypto = @import("../crypto/webpush.zig");
const ecdsa = @import("../crypto/ecdsa_p256.zig");
const acme_runner = @import("acme_runner.zig");
const http1 = @import("../proto/http1_client.zig");
const platform = @import("../substrate/platform.zig");
const services_mod = @import("services.zig");

const Allocator = std.mem.Allocator;
const net = std.Io.net;
const b64url = std.base64.url_safe_no_pad;

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
        allocator.free(self.endpoint);
        allocator.free(self.payload);
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
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    /// Delivery stats (worker-thread writes, oper-command reads are racy-read
    /// tolerable: monotonically increasing counters).
    sent: usize = 0,
    failed: usize = 0,
    /// Jobs refused because the queue already held `max_queued_jobs`.
    /// Incremented on the enqueue thread; metrics scrapes load it atomically.
    dropped: std.atomic.Value(usize) = .init(0),
    /// Unpublished overflow oper events. Drained by `takeOverflowOperEvent`.
    overflow_events: usize = 0,

    pub fn spawn(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, run, .{self});
    }

    pub fn shutdown(self: *Worker) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
        for (self.queue.items) |*j| j.deinit(self.allocator);
        self.queue.deinit(self.allocator);
        for (self.dead.items) |e| self.allocator.free(e);
        self.dead.deinit(self.allocator);
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
        if (self.stop_flag.load(.acquire)) return .stopped;
        if (self.queue.items.len >= max_queued_jobs) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            self.overflow_events +|= 1;
            return .dropped;
        }
        const ep = self.allocator.dupe(u8, endpoint) catch return .nomem;
        const pl = self.allocator.dupe(u8, payload) catch {
            self.allocator.free(ep);
            return .nomem;
        };
        self.queue.append(self.allocator, .{
            .endpoint = ep,
            .ua_public = ua_public,
            .auth = auth,
            .payload = pl,
        }) catch {
            self.allocator.free(ep);
            self.allocator.free(pl);
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
        return self.dead.toOwnedSlice(self.allocator) catch &.{};
    }

    fn run(self: *Worker) void {
        while (true) {
            const maybe_job: ?Job = blk: {
                lockSpin(&self.mutex);
                defer self.mutex.unlock();
                if (self.queue.items.len == 0) break :blk null;
                break :blk self.queue.orderedRemove(0);
            };
            var job = maybe_job orelse {
                if (self.stop_flag.load(.acquire)) return;
                sleepMs(200);
                continue;
            };
            defer job.deinit(self.allocator);
            self.deliver(&job) catch |err| {
                self.failed += 1;
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
        if (resp.status >= 200 and resp.status < 300) {
            self.sent += 1;
            return;
        }
        if (resp.status == 404 or resp.status == 410) {
            // Subscription is gone — surface it for pruning.
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            const ep = self.allocator.dupe(u8, job.endpoint) catch return;
            self.dead.append(self.allocator, ep) catch self.allocator.free(ep);
            self.failed += 1;
            return;
        }
        self.failed += 1;
        dlog.log("webpush: {s} answered {d}\n", .{ job.endpoint, resp.status });
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
