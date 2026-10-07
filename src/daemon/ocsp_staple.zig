// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-daemon OCSP-staple fetch/verify/cache/refresh scheduler.
//!
//! Mirrors `acme_renewal.Service`: a dedicated OS thread that never touches live
//! TLS listener state. Each cycle it re-reads the leaf + issuer from the
//! configured cert file, builds an OCSP request for the leaf's AIA responder URL,
//! POSTs it over the off-reactor blocking `http_fetch` transport, verifies +
//! freshness-gates the response with `ocsp.isStapleServableForCertId`, and — only on a
//! good, in-window, issuer-signed response — hands the raw DER to the server via
//! `publishOcspStaple`, which reactor 0 swaps into `config.tls_ocsp_staple`.
//!
//! Failure is non-fatal and non-destructive: on any fetch/verify/freshness error
//! the previously published staple keeps serving until it actually expires (the
//! server never clears a good staple on our behalf). A `revoked` response for our
//! own leaf is logged CRITICAL and never stapled.

const std = @import("std");
const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const dlog = @import("dlog.zig");
const linux = std.os.linux;

const config_format = @import("config_format.zig");
const http_fetch = @import("http_fetch.zig");
const http1 = @import("../proto/http1_client.zig");
const ocsp = @import("../crypto/ocsp.zig");
const platform = @import("../substrate/platform.zig");
const server_mod = @import("server.zig");
const tls_certs = @import("tls_certs.zig");
const x509 = @import("../crypto/x509.zig");

const wake_poll_ms: u64 = 1000;
const ocsp_request_content_type = "application/ocsp-request";
/// DER serials are <= 20 bytes (RFC 5280 §4.1.2.2) plus a possible sign octet.
const max_serial_len = 24;

/// Tunables for the fetch scheduler. `main.zig` populates these from the
/// `[ocsp]` config section; defaults are safe for a Let's Encrypt-style leaf.
pub const Options = struct {
    /// How often the worker wakes to check whether a (re)fetch is due. The actual
    /// responder is only contacted when the cached staple is stale or missing.
    check_interval_ms: u64 = 15 * 60 * 1000,
    /// Never re-contact the responder more often than this after a success.
    min_refresh_seconds: i64 = 5 * 60,
    /// Re-contact the responder at least this often even if nextUpdate is distant.
    max_refresh_seconds: i64 = 24 * 60 * 60,
    /// Clock-skew tolerance applied to thisUpdate/nextUpdate freshness checks.
    skew_seconds: i64 = ocsp.default_staple_skew_seconds,
    connect_timeout_ms: u31 = 5000,
    recv_timeout_ms: u31 = 10000,
    max_response_bytes: usize = 64 * 1024,
};

/// Seconds until the next responder contact for a staple valid over
/// `[this_update, next_update)`, evaluated at `now`. Standard stapling practice
/// refreshes at the halfway point; the result is clamped to `[min_s, max_s]` so a
/// long-lived response is still re-checked and a near-expiry one is not hammered.
pub fn refreshDelaySeconds(
    this_update: i64,
    next_update: i64,
    now: i64,
    min_s: i64,
    max_s: i64,
) i64 {
    const halfway = this_update + @divTrunc(next_update - this_update, 2);
    const delay = halfway - now;
    return std.math.clamp(delay, min_s, max_s);
}

/// Retry delay after `failures` consecutive responder-fetch failures: exponential
/// backoff starting at `min_s` and doubling each additional failure, clamped to
/// `max_s`. `failures == 0/1` yields `min_s`. Keeps a down responder from being
/// hammered every check interval while still recovering within `max_s`.
pub fn backoffSeconds(failures: u32, min_s: i64, max_s: i64) i64 {
    var delay = min_s;
    var n: u32 = 1;
    while (n < failures and delay < max_s) : (n += 1) {
        // Guard against i64 overflow on an absurd `max_s`; we clamp anyway.
        if (delay > @divTrunc(std.math.maxInt(i64), 2)) {
            delay = max_s;
            break;
        }
        delay *= 2;
    }
    return std.math.clamp(delay, min_s, max_s);
}

/// Transport options for an OCSP POST. Verification uses `trust_anchors`
/// (the daemon trust store). A bad responder certificate fails the fetch;
/// the caller keeps the previous staple.
pub fn ocspTransportOptions(trust_anchors: []const []const u8, opts: Options) http_fetch.Options {
    return .{
        .trust_anchors = trust_anchors,
        .insecure_skip_verify = false,
        .connect_timeout_ms = opts.connect_timeout_ms,
        .recv_timeout_ms = opts.recv_timeout_ms,
        .max_response_bytes = opts.max_response_bytes,
    };
}

/// Reactor-0 publication and Helix adoption must bind a fetched response to
/// the certificate that is actually serving, rather than to the on-disk leaf
/// the worker happened to read. ACME can replace that file before its separate
/// TLS reload signal is consumed. Call while holding the server's World lock;
/// this function only borrows the live chain and allocates nothing. A returned
/// deadline is exclusive: the staple must not be served at or after that Unix
/// second, even if a refresh has not yet succeeded.
pub fn stapleValidUntilForChain(der: []const u8, live_chain: []const []const u8, now_unix: i64, skew_seconds: i64) ?i64 {
    if (live_chain.len < 2 or der.len == 0 or skew_seconds < 0) return null;
    const leaf = x509.parse(live_chain[0]) catch return null;
    const issuer = x509.parse(live_chain[1]) catch return null;
    if (!std.mem.eql(u8, leaf.issuer_der, issuer.subject_der)) return null;
    const identity: ocsp.CertIdInput = .{
        .issuer_name_der = issuer.subject_der,
        .issuer_key_bytes = issuer.subject_public_key,
        .serial_der = leaf.serial_der,
    };
    // Keep the existing strict gate for signature, delegated signer authority,
    // complete CertID, good status, and freshness before extracting the bound.
    if (!ocsp.isStapleServableForCertId(der, issuer.spki_der, identity, now_unix, skew_seconds)) return null;
    const parsed = ocsp.parse(der) catch return null;
    const single = ocsp.singleForCertId(parsed, identity) orelse return null;
    const next_update = single.next_update orelse return null;
    const next_epoch = x509.generalizedTimeToEpoch(next_update) catch return null;
    return next_epoch +| skew_seconds;
}

pub fn stapleServableForChain(der: []const u8, live_chain: []const []const u8, now_unix: i64, skew_seconds: i64) bool {
    return stapleValidUntilForChain(der, live_chain, now_unix, skew_seconds) != null;
}

/// Outcome of one responder fetch. `.keep` means the previous staple stays
/// (transport failure, bad certificate, bad signature, or a revoked leaf).
/// `.publish` is an owned DER body the caller hands to the server.
pub const StapleDecision = union(enum) {
    keep,
    publish: []u8,
};

/// POST `request_der` and decide whether the body may replace the staple.
/// This is the function `Service.fetchAndPublish` uses. A TLS failure,
/// including an untrusted responder certificate, returns `.keep`.
pub fn fetchAndDecide(
    allocator: std.mem.Allocator,
    url: http_fetch.Url,
    request_der: []const u8,
    trust_anchors: []const []const u8,
    opts: Options,
    issuer_spki: []const u8,
    identity: ocsp.CertIdInput,
    now: i64,
) StapleDecision {
    const http_resp = http_fetch.post(allocator, url, ocsp_request_content_type, request_der, ocspTransportOptions(trust_anchors, opts)) catch |err| {
        dlog.log("onyx-server: ocsp fetch failed ({s}); keeping current staple\n", .{@errorName(err)});
        return .keep;
    };
    defer allocator.free(http_resp);

    const der = extractOcspBody(http_resp) orelse {
        dlog.log("onyx-server: ocsp fetch: responder returned no usable OCSPResponse body\n", .{});
        return .keep;
    };

    // Signature checks are unchanged: a revoked verdict is honored only when
    // the response is issuer-signed (or signed by an issuer-authorized
    // delegated responder). An unsigned body cannot forge a revocation.
    if (ocsp.parse(der)) |parsed| {
        if (ocsp.verifyResponseSignatureWithChain(parsed, issuer_spki, now)) {
            if (ocsp.singleForCertId(parsed, identity)) |single| {
                if (single.cert_status == .revoked) {
                    dlog.log("onyx-server: CRITICAL ocsp responder reports THIS server's certificate REVOKED — not stapling\n", .{});
                    return .keep;
                }
            }
        }
    } else |_| {}

    if (!ocsp.isStapleServableForCertId(der, issuer_spki, identity, now, opts.skew_seconds)) {
        dlog.log("onyx-server: ocsp response not servable (bad sig/status/freshness); keeping current staple\n", .{});
        return .keep;
    }

    const owned = allocator.dupe(u8, der) catch {
        dlog.log("onyx-server: ocsp staple skipped: out of memory copying response\n", .{});
        return .keep;
    };
    return .{ .publish = owned };
}

/// Extract the DER OCSPResponse body from a complete HTTP response, or null if
/// the status is not 200 or the body is empty. `http_response` is decoded in
/// place (chunked/Content-Length framing); the returned slice aliases it.
pub fn extractOcspBody(http_response: []u8) ?[]const u8 {
    var header_storage: [32]http1.Header = undefined;
    const resp = http1.parseResponse(http_response, &header_storage) catch return null;
    if (resp.status != 200) return null;
    if (resp.body.len == 0) return null;
    return resp.body;
}

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *server_mod.Server,
    tls: *const config_format.Config.Tls,
    opts: Options,
    /// Daemon trust store (DER anchors). HTTPS OCSP fetches verify against
    /// this set. Empty fails closed; `insecure_skip_verify` is not used.
    /// Borrowed for the process lifetime (same store as ACME / Web Push).
    trust_anchors: []const []const u8 = &.{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    next_check_ms: i64 = 0,
    completed_checks: u64 = 0,

    // Bookkeeping so a fresh, still-valid staple isn't re-fetched every wake.
    last_serial: [max_serial_len]u8 = undefined,
    last_serial_len: usize = 0,
    next_refresh_unix: i64 = 0,
    // Exponential-backoff state so a down responder isn't re-contacted every check
    // interval. Reset on a successful publish or a leaf-serial change.
    fail_count: u32 = 0,
    next_retry_unix: i64 = 0,
    // One-shot log gates for persistent skip conditions (avoid per-wake spam).
    warned_no_issuer: bool = false,
    warned_no_aia: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: *server_mod.Server,
        tls: *const config_format.Config.Tls,
        opts: Options,
    ) Service {
        return .{
            .allocator = allocator,
            .io = io,
            .server = server,
            .tls = tls,
            .opts = opts,
        };
    }

    pub fn start(self: *Service) void {
        if (self.thread != null or self.runtime.view != null) return;
        self.startChecked() catch |err| {
            dlog.log("onyx-server: ocsp stapler start failed ({s}); stapling disabled\n", .{@errorName(err)});
        };
    }

    /// Strict boot path for an explicitly configured staple worker.
    pub fn startChecked(self: *Service) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        try validateOptions(self.opts);
        self.stop_flag.store(false, .release);
        errdefer self.stop_flag.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
        dlog.log("onyx-server: ocsp staple scheduler enabled (check interval {d}ms)\n", .{self.opts.check_interval_ms});
    }

    pub fn stop(self: *Service) void {
        self.runtime.requireDetached() catch @panic("managed stop requires Runtime Control join and source detach");
        self.stop_flag.store(true, .release);
        self.runtime.wakeForStop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    pub fn prepareColdResources(self: *Service, io: std.Io) !void {
        if (io.userdata != self.io.userdata or io.vtable != self.io.vtable) return error.IoMismatch;
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        try validateOptions(self.opts);
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .ocsp, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .ocsp, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        try validateOptions(self.opts);
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .ocsp, 0, Service, self, worker, dormant_spawn_options);
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
    pub fn requestPause(self: *Service, epoch: u64) !runtime_pause.Token {
        return self.runtime.pause.request(epoch);
    }
    pub fn awaitPaused(self: *Service, token: runtime_pause.Token, deadline: std.Io.Clock.Timestamp) !void {
        try self.runtime.pause.awaitPaused(token, deadline);
    }
    pub fn resumePaused(self: *Service, token: runtime_pause.Token) !void {
        try self.runtime.pause.resumePaused(token);
    }
    pub fn capturePaused(self: *Service, token: runtime_pause.Token) !Snapshot {
        if (self.thread == null and self.runtime.view == null) return error.NotRunning;
        try self.runtime.pause.requirePaused(token);
        return self.captureCut(.paused);
    }
    pub fn captureUnstarted(self: *Service) !Snapshot {
        if (self.thread != null or self.runtime.view != null) return error.NotQuiescent;
        return self.captureCut(.unstarted);
    }
    fn captureCut(self: *Service, execution: Execution) !Snapshot {
        if (self.last_serial_len > max_serial_len) return error.InvalidSnapshot;
        var serial: [max_serial_len]u8 = @splat(0);
        @memcpy(serial[0..self.last_serial_len], self.last_serial[0..self.last_serial_len]);
        return .{ .config_digest = try configDigest(self.tls, self.opts, self.trust_anchors), .last_serial = serial, .last_serial_len = @intCast(self.last_serial_len), .next_refresh_unix = self.next_refresh_unix, .fail_count = self.fail_count, .next_retry_unix = self.next_retry_unix, .warned_no_issuer = self.warned_no_issuer, .warned_no_aia = self.warned_no_aia, .next_check_ms = self.next_check_ms, .completed_checks = self.completed_checks, .captured_monotonic_ms = platform.monotonicMillis(), .execution = execution };
    }
    /// Server-owned current/pending DER and publication generation MUST be
    /// joined separately. This row preserves the scheduler; it never fabricates
    /// a staple or claims the reactor has consumed a pending publication.
    pub fn restoreSnapshot(self: *Service, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.NotQuiescent;
        try snapshot.validate(self.tls, self.opts, self.trust_anchors);
        self.publishSnapshot(snapshot);
    }
    /// Gate-prepared candidate restore: the worker is parked before and after
    /// config/shape validation, and the final scalar copy cannot fail.
    pub fn restoreSnapshotParked(self: *Service, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.pause.request_epoch != 0) return error.NotQuiescent;
        try self.requireParked();
        try snapshot.validate(self.tls, self.opts, self.trust_anchors);
        try self.requireParked();
        self.publishSnapshot(snapshot);
    }
    fn publishSnapshot(self: *Service, snapshot: *const Snapshot) void {
        self.last_serial = snapshot.last_serial;
        self.last_serial_len = snapshot.last_serial_len;
        self.next_refresh_unix = snapshot.next_refresh_unix;
        self.fail_count = snapshot.fail_count;
        self.next_retry_unix = snapshot.next_retry_unix;
        self.warned_no_issuer = snapshot.warned_no_issuer;
        self.warned_no_aia = snapshot.warned_no_aia;
        self.next_check_ms = snapshot.next_check_ms;
        self.completed_checks = snapshot.completed_checks;
    }
    fn worker(self: *Service) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (!self.stop_flag.load(.acquire)) {
            // All checkOnce allocations have been freed and its Server outcome
            // has been handed off before arrival. Reactor consumption is a
            // separate final graph barrier, not inferred from this arrival.
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
            if (self.resetIfRejected()) self.next_check_ms = 0;
            const now = platform.monotonicMillis();
            if (now < self.next_check_ms) {
                sleepMs(@intCast(@min(self.next_check_ms - now, wake_poll_ms)));
                continue;
            }
            if (self.completed_checks == std.math.maxInt(u64)) {
                self.stop_flag.store(true, .release);
                break;
            }
            self.checkOnce();
            self.completed_checks += 1;
            self.next_check_ms = platform.monotonicMillis() +| @as(i64, @intCast(self.opts.check_interval_ms));
        }
    }

    fn resetIfRejected(self: *Service) bool {
        const full_server = @import("builtin").os.tag == .linux or @import("builtin").os.tag == .openbsd or @import("builtin").os.tag == .windows;
        if (comptime full_server) {
            if (self.server.takeOcspStapleRejected()) {
                self.last_serial = @splat(0);
                self.last_serial_len = 0;
                self.next_refresh_unix = 0;
                self.next_retry_unix = 0;
                self.fail_count = 0;
                return true;
            }
        }
        return false;
    }

    fn checkOnce(self: *Service) void {
        const cert_path = self.tls.cert_path orelse return;

        const chain = tls_certs.loadCertChain(self.allocator, self.io, cert_path) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot read cert file {s} ({s})\n", .{ cert_path, @errorName(err) });
            return;
        };
        defer {
            for (chain) |der| self.allocator.free(der);
            self.allocator.free(chain);
        }
        if (chain.len < 2) {
            if (!self.warned_no_issuer) {
                dlog.log("onyx-server: ocsp staple disabled: cert file {s} has no issuer cert (need fullchain)\n", .{cert_path});
                self.warned_no_issuer = true;
            }
            return;
        }
        self.warned_no_issuer = false;

        const leaf = x509.parse(chain[0]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse leaf cert ({s})\n", .{@errorName(err)});
            return;
        };
        const issuer = x509.parse(chain[1]) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot parse issuer cert ({s})\n", .{@errorName(err)});
            return;
        };
        if (!std.mem.eql(u8, leaf.issuer_der, issuer.subject_der)) {
            dlog.log("onyx-server: ocsp staple skipped: issuer cert does not name the leaf's issuer\n", .{});
            return;
        }
        if (leaf.aia_ocsp_url.len == 0) {
            if (!self.warned_no_aia) {
                dlog.log("onyx-server: ocsp staple disabled: leaf has no AIA OCSP responder URL\n", .{});
                self.warned_no_aia = true;
            }
            return;
        }
        self.warned_no_aia = false;

        const now = @divTrunc(platform.realtimeMillis(), 1000);

        // A successful live TLS reload can discard the prior staple when the
        // new leaf needs a fresh response. Cancel the previous scheduler
        // receipt and retry against the new disk leaf promptly.
        _ = self.resetIfRejected();

        // A cert rotation (new serial vs the last published one) deserves a fresh
        // attempt, not the backoff accumulated against the previous leaf.
        if (self.last_serial_len != 0 and
            !std.mem.eql(u8, self.last_serial[0..self.last_serial_len], leaf.serial_der))
        {
            self.fail_count = 0;
            self.next_retry_unix = 0;
        }

        // A still-valid staple for this exact serial doesn't need re-fetching yet.
        if (self.hasFreshStapleFor(leaf.serial_der, now)) return;
        // Back off after consecutive failures instead of re-hammering a down
        // responder every check interval.
        if (now < self.next_retry_unix) return;

        if (!self.fetchAndPublish(leaf, issuer, now)) self.noteFetchFailure(now);
    }

    /// Record a failed fetch and schedule the next attempt with exponential
    /// backoff (`backoffSeconds`). Bounded so the counter can't wrap.
    fn noteFetchFailure(self: *Service, now: i64) void {
        if (self.fail_count < std.math.maxInt(u32)) self.fail_count += 1;
        const delay = backoffSeconds(self.fail_count, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
        self.next_retry_unix = now + delay;
        dlog.log("onyx-server: ocsp fetch retry backing off {d}s after {d} consecutive failure(s)\n", .{ delay, self.fail_count });
    }

    /// Returns true when a fresh, servable staple was published; false on any
    /// failure (so the caller can apply backoff).
    fn fetchAndPublish(self: *Service, leaf: x509.Certificate, issuer: x509.Certificate, now: i64) bool {
        const req = ocsp.buildRequestForCerts(self.allocator, leaf, issuer) catch |err| {
            dlog.log("onyx-server: ocsp staple skipped: cannot build request ({s})\n", .{@errorName(err)});
            return false;
        };
        defer self.allocator.free(req);

        const url = http_fetch.parseUrl(leaf.aia_ocsp_url) catch {
            dlog.log("onyx-server: ocsp staple skipped: malformed AIA URL\n", .{});
            return false;
        };
        const identity: ocsp.CertIdInput = .{
            .issuer_name_der = issuer.subject_der,
            .issuer_key_bytes = issuer.subject_public_key,
            .serial_der = leaf.serial_der,
        };
        const decision = fetchAndDecide(self.allocator, url, req, self.trust_anchors, self.opts, issuer.spki_der, identity, now);
        switch (decision) {
            .keep => return false,
            .publish => |owned| {
                self.recordPublished(owned, identity, now);
                // The full server takes ownership of the verified DER and
                // publishes it on reactor 0, including its Windows backend.
                const full_server = @import("builtin").os.tag == .linux or @import("builtin").os.tag == .openbsd or @import("builtin").os.tag == .windows;
                if (comptime full_server) {
                    self.server.publishOcspStaple(owned);
                    return true;
                }
                self.allocator.free(owned);
                return false;
            },
        }
    }

    /// True when the last published staple covers `serial` and it is not yet time
    /// to refresh — lets the worker wake frequently without hammering responders.
    fn hasFreshStapleFor(self: *Service, serial: []const u8, now: i64) bool {
        if (self.last_serial_len == 0) return false;
        if (!std.mem.eql(u8, self.last_serial[0..self.last_serial_len], serial)) return false;
        return now < self.next_refresh_unix;
    }

    /// Record the serial + schedule the next responder contact from the freshly
    /// published response's thisUpdate/nextUpdate (falls back to min interval).
    fn recordPublished(self: *Service, der: []const u8, identity: ocsp.CertIdInput, now: i64) void {
        // A successful publish clears the failure backoff.
        self.fail_count = 0;
        self.next_retry_unix = 0;
        if (identity.serial_der.len <= max_serial_len) {
            @memcpy(self.last_serial[0..identity.serial_der.len], identity.serial_der);
            self.last_serial_len = identity.serial_der.len;
        } else {
            self.last_serial_len = 0; // unexpectedly long serial: always re-fetch
        }

        var delay = self.opts.min_refresh_seconds;
        if (ocsp.parse(der)) |parsed| {
            if (ocsp.singleForCertId(parsed, identity)) |single| {
                if (single.next_update) |next_bytes| {
                    const this_e = x509.generalizedTimeToEpoch(single.this_update) catch now;
                    const next_e = x509.generalizedTimeToEpoch(next_bytes) catch (now + self.opts.min_refresh_seconds);
                    delay = refreshDelaySeconds(this_e, next_e, now, self.opts.min_refresh_seconds, self.opts.max_refresh_seconds);
                }
            }
        } else |_| {}
        self.next_refresh_unix = now + delay;
        dlog.log("onyx-server: ocsp staple published ({d} bytes); next refresh in {d}s\n", .{ der.len, delay });
    }
};

fn sleepInterruptible(total_ms: u64, stop_flag: *std.atomic.Value(bool)) bool {
    var remaining = total_ms;
    while (remaining > 0) {
        if (stop_flag.load(.acquire)) return false;
        const chunk = @min(remaining, wake_poll_ms);
        sleepMs(@intCast(chunk));
        remaining -= chunk;
    }
    return !stop_flag.load(.acquire);
}

fn sleepMs(ms: u32) void {
    if (comptime @import("builtin").os.tag != .linux) return @import("os_runtime.zig").sleepMillis(ms);
    var req = linux.timespec{ .sec = @divTrunc(ms, 1000), .nsec = @as(isize, ms % 1000) * 1_000_000 };
    _ = linux.nanosleep(&req, null);
}

test "refreshDelaySeconds halves the validity window, clamped" {
    const this_u: i64 = 1_700_000_000;
    const next_u: i64 = this_u + 4000; // 4000s window, halfway at +2000

    // Fetched at thisUpdate: refresh in ~half the window.
    try std.testing.expectEqual(@as(i64, 2000), refreshDelaySeconds(this_u, next_u, this_u, 60, 86_400));

    // Past the halfway point clamps up to the minimum, never negative.
    try std.testing.expectEqual(@as(i64, 60), refreshDelaySeconds(this_u, next_u, this_u + 3000, 60, 86_400));

    // A very long window clamps down to the daily ceiling.
    const long_next = this_u + 30 * 24 * 60 * 60;
    try std.testing.expectEqual(@as(i64, 86_400), refreshDelaySeconds(this_u, long_next, this_u, 60, 86_400));
}

test "backoffSeconds doubles per failure, clamped to [min,max]" {
    // 0/1 failures → the minimum.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(0, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 86_400));
    // Then doubles each additional failure.
    try std.testing.expectEqual(@as(i64, 600), backoffSeconds(2, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 1200), backoffSeconds(3, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 2400), backoffSeconds(4, 300, 86_400));
    // Clamps to max once the doubling would exceed it, and stays there.
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(20, 300, 86_400));
    try std.testing.expectEqual(@as(i64, 86_400), backoffSeconds(std.math.maxInt(u32), 300, 86_400));
    // A tiny window never returns below min even for 1 failure.
    try std.testing.expectEqual(@as(i64, 300), backoffSeconds(1, 300, 300));
}

test "extractOcspBody returns body only for a 200 with content" {
    const allocator = std.testing.allocator;

    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 5\r\n\r\n\x30\x03\x0a\x01\x00");
        defer allocator.free(raw);
        const body = extractOcspBody(raw).?;
        try std.testing.expectEqualSlices(u8, "\x30\x03\x0a\x01\x00", body);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nbad");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
    {
        const raw = try allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        defer allocator.free(raw);
        try std.testing.expect(extractOcspBody(raw) == null);
    }
}

test "Windows OCSP worker starts and joins without a certificate path" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    const server = try std.testing.allocator.create(server_mod.Server);
    defer std.testing.allocator.destroy(server);
    const tls: config_format.Config.Tls = .{};
    var service = Service.init(std.testing.allocator, std.testing.io, server, &tls, .{});
    try service.startChecked();
    defer service.stop();
    try std.testing.expect(service.thread != null);
    try std.testing.expectError(error.AlreadyStarted, service.startChecked());
    const start = platform.monotonicMillis();
    service.stop();
    try std.testing.expect(platform.monotonicMillis() - start < 2000);
    try std.testing.expect(service.thread == null);
    try std.testing.expect(service.runtime.entered.load(.acquire));
    try std.testing.expect(service.runtime.exited.load(.acquire));
}

const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const tls_conn = @import("tls_conn.zig");
const posix = std.posix;

const OcspStub = struct {
    listen_fd: linux.fd_t,
    der: []const u8,
    kp: Ed25519.KeyPair,
    stop: *std.atomic.Value(bool),
    app_posts: *std.atomic.Value(u32),
};

fn ocspWriteAll(fd: linux.fd_t, bytes: []const u8) void {
    if (comptime @import("builtin").os.tag == .openbsd) {
        @import("native_network.zig").writeAll(fd, bytes) catch {};
        return;
    }
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;
        off += n;
    }
}

fn ocspListenLoopback() !struct { fd: linux.fd_t, port: u16 } {
    if (comptime @import("builtin").os.tag == .openbsd) {
        const opened = try @import("io_backend.zig").listenTcp("127.0.0.1", 0);
        return .{ .fd = opened.fd, .port = opened.port };
    }
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.Socket;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);
    var yes: u32 = 1;
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(u32));
    var addr = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.Bind;
    if (posix.errno(linux.listen(fd, 8)) != .SUCCESS) return error.Listen;
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.Bind;
    const bound: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

fn ocspStubServe(alloc: std.mem.Allocator, fd: linux.fd_t, stub: *OcspStub) void {
    defer @import("io_backend.zig").closeSocket(fd);
    if (comptime @import("builtin").os.tag == .openbsd) {
        @import("native_network.zig").setBlocking(fd) catch return;
        @import("native_network.zig").setTimeout(fd, 2000) catch return;
    } else {
        const rtv = linux.timeval{ .sec = 2, .usec = 0 };
        _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&rtv), @sizeOf(linux.timeval));
    }
    var conn = tls_conn.TlsConn.init(alloc, .{ .cert_chain = &.{stub.der}, .signing_key = stub.kp }) catch return;
    defer conn.deinit();
    var buf: [16 * 1024]u8 = undefined;
    var plain_acc: [4096]u8 = undefined;
    var plain_len: usize = 0;
    while (!stub.stop.load(.acquire)) {
        const rc = if (comptime @import("builtin").os.tag == .openbsd)
            std.c.read(fd, &buf, buf.len)
        else
            linux.read(fd, &buf, buf.len);
        if (posix.errno(rc) != .SUCCESS) return;
        const n: usize = @intCast(rc);
        if (n == 0) return;
        const out = conn.onInbound(buf[0..n]) catch |err| {
            if (conn.takeAlert(err)) |alert| {
                defer alloc.free(alert);
                ocspWriteAll(fd, alert);
            }
            return;
        };
        if (out.handshake_bytes.len != 0) {
            const flight = alloc.dupe(u8, out.handshake_bytes) catch return;
            defer alloc.free(flight);
            ocspWriteAll(fd, flight);
        }
        if (out.plaintext.len != 0 and plain_len < plain_acc.len) {
            const take = @min(out.plaintext.len, plain_acc.len - plain_len);
            @memcpy(plain_acc[plain_len..][0..take], out.plaintext[0..take]);
            plain_len += take;
        }
        if (conn.handshakeDone() and std.mem.indexOf(u8, plain_acc[0..plain_len], "\r\n\r\n") != null) {
            _ = stub.app_posts.fetchAdd(1, .monotonic);
            const body = "nope";
            var hdr_buf: [160]u8 = undefined;
            const hdr = std.fmt.bufPrint(&hdr_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
            const cipher = conn.write(hdr) catch return;
            const owned = alloc.dupe(u8, cipher) catch return;
            defer alloc.free(owned);
            ocspWriteAll(fd, owned);
            return;
        }
    }
}

fn ocspStubAccept(stub: *OcspStub) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const alloc = arena_state.allocator();
    if (comptime @import("builtin").os.tag == .openbsd) {
        while (!stub.stop.load(.acquire)) {
            var ready = [_]posix.pollfd{.{ .fd = stub.listen_fd, .events = posix.POLL.IN, .revents = 0 }};
            const polled = std.c.poll(&ready, 1, 50);
            if (polled < 0) {
                if (posix.errno(polled) == .INTR) continue;
                return;
            }
            if (polled == 0) continue;
            const fd = std.c.accept(stub.listen_fd, null, null);
            switch (posix.errno(fd)) {
                .SUCCESS => ocspStubServe(alloc, fd, stub),
                .AGAIN, .INTR, .CONNABORTED => continue,
                else => return,
            }
        }
        return;
    }
    const tv = linux.timeval{ .sec = 0, .usec = 200_000 };
    _ = linux.setsockopt(stub.listen_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    while (!stub.stop.load(.acquire)) {
        const rc = linux.accept4(stub.listen_fd, null, null, posix.SOCK.CLOEXEC);
        switch (posix.errno(rc)) {
            .SUCCESS => ocspStubServe(alloc, @intCast(rc), stub),
            .AGAIN, .INTR, .CONNABORTED => continue,
            else => return,
        }
    }
}

test "tls ocsp fetch uses the daemon trust store and a bad certificate keeps the previous staple" {
    if (comptime @import("builtin").os.tag != .linux and @import("builtin").os.tag != .openbsd) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const good_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x41)));
    const bad_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42)));
    var good_buf: [1400]u8 = undefined;
    var bad_buf: [1400]u8 = undefined;
    const good_der = try x509_selfsign.buildSelfSigned(&good_buf, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x01, 0x02 },
        .key_pair = good_kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });
    const bad_der = try x509_selfsign.buildSelfSigned(&bad_buf, .{
        .common_name = "127.0.0.1",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x03, 0x04 },
        .key_pair = bad_kp,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
    });

    const listener = try ocspListenLoopback();
    var stop = std.atomic.Value(bool).init(false);
    var posts = std.atomic.Value(u32).init(0);
    var stub = OcspStub{
        .listen_fd = listener.fd,
        .der = good_der,
        .kp = good_kp,
        .stop = &stop,
        .app_posts = &posts,
    };
    const thread = try std.Thread.spawn(.{}, ocspStubAccept, .{&stub});
    defer {
        stop.store(true, .release);
        thread.join();
        @import("io_backend.zig").closeSocket(listener.fd);
    }

    const url_text = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/ocsp", .{listener.port});
    defer allocator.free(url_text);
    const url = try http_fetch.parseUrl(url_text);
    const opts = Options{ .connect_timeout_ms = 2000, .recv_timeout_ms = 3000 };
    const previous = "previous-staple";
    const transport = ocspTransportOptions(&.{good_der}, opts);
    try std.testing.expect(!transport.insecure_skip_verify);
    try std.testing.expectEqual(@as(usize, 1), transport.trust_anchors.len);
    try std.testing.expectEqual(good_der.ptr, transport.trust_anchors[0].ptr);

    const test_identity: ocsp.CertIdInput = .{ .issuer_name_der = "issuer-name", .issuer_key_bytes = "issuer-key", .serial_der = "serial" };
    const untrusted = fetchAndDecide(allocator, url, "ocsp-request", &.{bad_der}, opts, "issuer-spki", test_identity, 1_700_000_000);
    try std.testing.expect(untrusted == .keep);
    try std.testing.expectEqual(@as(u32, 0), posts.load(.monotonic));

    const trusted_garbage = fetchAndDecide(allocator, url, "ocsp-request", &.{good_der}, opts, "issuer-spki", test_identity, 1_700_000_000);
    switch (trusted_garbage) {
        .keep => {},
        .publish => |owned| {
            allocator.free(owned);
            return error.TestUnexpectedResult;
        },
    }
    try std.testing.expect(posts.load(.monotonic) >= 1);
    try std.testing.expectEqualStrings("previous-staple", previous);
    std.debug.print("GAP-A8 branch=trust-store bad-cert=keep signature-fail=keep previous={s}\n", .{previous});
}

const WindowsOcspResponder = struct {
    const invalid_socket = std.math.maxInt(usize);
    const sol_socket: i32 = 0xffff;
    const so_rcvtimeo: i32 = 0x1006;
    const so_sndtimeo: i32 = 0x1005;
    const FdSet = extern struct {
        count: u32 = 1,
        pad: u32 = 0,
        sockets: [64]usize = @splat(0),
    };
    const Timeval = extern struct { seconds: i32, microseconds: i32 };

    extern "ws2_32" fn accept(socket: usize, address: ?*anyopaque, address_len: ?*i32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn ioctlsocket(socket: usize, command: u32, value: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn select(nfds: i32, readfds: ?*FdSet, writefds: ?*FdSet, exceptfds: ?*FdSet, timeout: *Timeval) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;

    listener: usize,
    cert: []const u8,
    key: Ed25519.KeyPair,
    request_der: []const u8,
    response_der: []const u8,
    request_seen: bool = false,
    failure: ?anyerror = null,

    fn run(self: *WindowsOcspResponder) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *WindowsOcspResponder) !void {
        const tls_server = @import("../crypto/tls_server.zig");
        const allocator = std.heap.page_allocator;
        var readable = FdSet{};
        readable.sockets[0] = self.listener;
        var timeout = Timeval{ .seconds = 3, .microseconds = 0 };
        if (select(0, &readable, null, null, &timeout) != 1) return error.TestUnexpectedResult;
        const fd = accept(self.listener, null, null);
        if (fd == invalid_socket) return error.TestUnexpectedResult;
        defer _ = closesocket(fd);
        var blocking: u32 = 0;
        if (ioctlsocket(fd, 0x8004667e, &blocking) != 0) return error.TestUnexpectedResult;
        const finite_ms: u32 = 3000;
        if (setsockopt(fd, sol_socket, so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
            setsockopt(fd, sol_socket, so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
            return error.TestUnexpectedResult;

        var tls = try tls_server.Server.init(allocator, .{ .cert_chain = &.{self.cert}, .signing_key = self.key });
        defer tls.deinit();
        var record_buf: [17 * 1024]u8 = undefined;
        while (!tls.handshakeDone()) {
            switch (try tls.feed(try readRecord(fd, &record_buf))) {
                .bytes_to_send => |bytes| {
                    defer allocator.free(bytes);
                    try writeAll(fd, bytes);
                },
                .need_more => {},
            }
        }
        const request = try tls.decrypt(try readRecord(fd, &record_buf));
        defer allocator.free(request);
        const separator = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.TestUnexpectedResult;
        self.request_seen = std.mem.startsWith(u8, request, "POST /ocsp HTTP/1.1\r\n") and
            std.mem.indexOf(u8, request[0..separator], "Content-Type: application/ocsp-request") != null and
            std.mem.eql(u8, request[separator + 4 ..], self.request_der);
        if (!self.request_seen) return error.TestUnexpectedResult;

        const header = try std.fmt.allocPrint(allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{self.response_der.len});
        defer allocator.free(header);
        const plain = try allocator.alloc(u8, header.len + self.response_der.len);
        defer allocator.free(plain);
        @memcpy(plain[0..header.len], header);
        @memcpy(plain[header.len..], self.response_der);
        const encrypted = try tls.encrypt(plain);
        defer allocator.free(encrypted);
        try writeAll(fd, encrypted);
    }

    fn readRecord(fd: usize, out: []u8) ![]u8 {
        try readExact(fd, out[0..5]);
        const length = 5 + @as(usize, std.mem.readInt(u16, out[3..5], .big));
        if (length > out.len) return error.TestUnexpectedResult;
        try readExact(fd, out[5..length]);
        return out[0..length];
    }

    fn readExact(fd: usize, out: []u8) !void {
        var off: usize = 0;
        while (off < out.len) {
            const n = recv(fd, out[off..].ptr, @intCast(out.len - off), 0);
            if (n <= 0) return error.TestUnexpectedResult;
            off += @intCast(n);
        }
    }

    fn writeAll(fd: usize, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = send(fd, bytes[off..].ptr, @intCast(bytes.len - off), 0);
            if (n <= 0) return error.TestUnexpectedResult;
            off += @intCast(n);
        }
    }
};

test "Windows OCSP service accepts current issuer-signed HTTPS response and hands off staple" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const asn1_time = @import("../proto/asn1_time.zig");
    const metrics = @import("metrics_http.zig");
    const pem = @import("../proto/pem.zig");
    var snapshot = metrics.MetricsSnapshot.init(allocator);
    defer snapshot.deinit();
    // The metrics listener supplies a native Winsock loopback socket. Its
    // normal metrics worker is not started; the responder above owns accepts.
    var listener = try metrics.MetricsServer.init(&snapshot, 0);
    defer listener.shutdown();

    const key = try Ed25519.KeyPair.generateDeterministic(@splat(0x6c));
    const now = @divFloor(platform.realtimeMillis(), 1000);
    var cert_buf: [2048]u8 = undefined;
    const aia = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/ocsp", .{listener.port});
    defer allocator.free(aia);
    const cert_der = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "127.0.0.1",
        .not_before = now - 3600,
        .not_after = now + 86_400,
        .serial = &.{ 0x6c, 0x01 },
        .key_pair = key,
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .is_ca = true,
        .ocsp_url = aia,
    });
    const cert = try x509.parse(cert_der);
    try std.testing.expectEqualStrings(aia, cert.aia_ocsp_url);
    const identity: ocsp.CertIdInput = .{
        .issuer_name_der = cert.subject_der,
        .issuer_key_bytes = cert.subject_public_key,
        .serial_der = cert.serial_der,
    };
    var produced_buf: [asn1_time.generalized_der_len]u8 = undefined;
    var this_buf: [asn1_time.generalized_der_len]u8 = undefined;
    var next_buf: [asn1_time.generalized_der_len]u8 = undefined;
    const response = try ocsp.testSignedOcspResponseForCertIdAt(
        allocator,
        key,
        identity,
        .good,
        (try asn1_time.encodeGeneralizedTime(&produced_buf, now - 60)).value,
        (try asn1_time.encodeGeneralizedTime(&this_buf, now - 60)).value,
        (try asn1_time.encodeGeneralizedTime(&next_buf, now + 3600)).value,
    );
    defer allocator.free(response);
    // This small fixture uses the same self-signed cert as leaf and issuer. A
    // two-block fullchain exercises the real on-disk chain loader and CertID.
    const chain = [_][]const u8{ cert_der, cert_der };
    try std.testing.expect(stapleServableForChain(response, &chain, now, 0));
    const request_der = try ocsp.buildRequestForCerts(allocator, cert, cert);
    defer allocator.free(request_der);
    var pem_buf: [4096]u8 = undefined;
    const block = try pem.encode(&pem_buf, "CERTIFICATE", cert_der);
    const fullchain = try allocator.alloc(u8, block.len * 2);
    defer allocator.free(fullchain);
    @memcpy(fullchain[0..block.len], block);
    @memcpy(fullchain[block.len..], block);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fullchain.pem", .data = fullchain });
    const cert_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/fullchain.pem", .{tmp.sub_path});
    defer allocator.free(cert_path);

    var server = try server_mod.Server.init(allocator, .{
        .host = "127.0.0.1",
        .port = 0,
        .tls_port = 0,
        .tls_cert_chain = &chain,
        .tls_signing_key = key,
    });
    defer server.deinit();
    const tls: config_format.Config.Tls = .{ .enabled = true, .cert_path = cert_path };
    var service = Service.init(allocator, std.testing.io, &server, &tls, .{ .connect_timeout_ms = 2000, .recv_timeout_ms = 3000 });
    service.trust_anchors = &.{cert_der};
    var responder = WindowsOcspResponder{
        .listener = listener.listen_fd,
        .cert = cert_der,
        .key = key,
        .request_der = request_der,
        .response_der = response,
    };
    const thread = try std.Thread.spawn(.{}, WindowsOcspResponder.run, .{&responder});
    var joined = false;
    defer if (!joined) thread.join();
    service.checkOnce();
    thread.join();
    joined = true;
    if (responder.failure) |err| return err;
    try std.testing.expect(responder.request_seen);
    try std.testing.expectEqual(@as(u32, 0), service.fail_count);
    try std.testing.expectEqualSlices(u8, cert.serial_der, service.last_serial[0..service.last_serial_len]);
    try std.testing.expect(service.next_refresh_unix > now);
    try std.testing.expect(server.ocsp_staple_pending.load(.acquire));
    try std.testing.expectEqualSlices(u8, response, server.ocsp_staple_incoming.?);
    try std.testing.expect(server.ocsp_staple_incoming.?.ptr != response.ptr);
}

test "OCSP publication refuses missing issuer, malformed live leaf, and malformed response" {
    try std.testing.expect(!stapleServableForChain("der", &.{}, 1_700_000_000, 0));
    try std.testing.expect(!stapleServableForChain("der", &.{"leaf"}, 1_700_000_000, 0));
    try std.testing.expect(!stapleServableForChain("der", &.{ "bad-leaf", "bad-issuer" }, 1_700_000_000, 0));
    try std.testing.expect(!stapleServableForChain("", &.{ "bad-leaf", "bad-issuer" }, 1_700_000_000, 0));
    try std.testing.expect(!stapleServableForChain("der", &.{ "bad-leaf", "bad-issuer" }, 1_700_000_000, -1));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain("der", &.{ "bad-leaf", "bad-issuer" }, 1_700_000_000, 0));
}

test "OCSP publication binds a signed response to the live leaf and issuer CertID" {
    const allocator = std.testing.allocator;
    const key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x6b));
    var leaf_buf: [1024]u8 = undefined;
    const leaf = try x509_selfsign.buildSelfSigned(&leaf_buf, .{
        .common_name = "ocsp.example",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x44},
        .key_pair = key,
        .dns_names = &.{"ocsp.example"},
        .is_ca = true,
    });
    const cert = try x509.parse(leaf);
    const identity: ocsp.CertIdInput = .{
        .issuer_name_der = cert.subject_der,
        .issuer_key_bytes = cert.subject_public_key,
        .serial_der = cert.serial_der,
    };
    const response = try ocsp.testSignedOcspResponseForCertId(allocator, key, identity, .good, "20260202030405Z");
    defer allocator.free(response);
    const now = try x509.generalizedTimeToEpoch("20260115030405Z");
    const next_epoch = try x509.generalizedTimeToEpoch("20260202030405Z");
    try std.testing.expect(stapleServableForChain(response, &.{ leaf, leaf }, now, 0));
    try std.testing.expectEqual(@as(?i64, next_epoch), stapleValidUntilForChain(response, &.{ leaf, leaf }, now, 0));
    try std.testing.expectEqual(@as(?i64, next_epoch + 300), stapleValidUntilForChain(response, &.{ leaf, leaf }, next_epoch + 299, 300));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(response, &.{ leaf, leaf }, next_epoch + 300, 300));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(response, &.{ leaf, leaf }, now, -1));

    const no_next = try ocsp.testSignedOcspResponseForCertId(allocator, key, identity, .good, null);
    defer allocator.free(no_next);
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(no_next, &.{ leaf, leaf }, now, 0));
    const revoked = try ocsp.testSignedOcspResponseForCertId(allocator, key, identity, .revoked, "20260202030405Z");
    defer allocator.free(revoked);
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(revoked, &.{ leaf, leaf }, now, 0));
    const tampered = try allocator.dupe(u8, response);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(tampered, &.{ leaf, leaf }, now, 0));

    var rotated_buf: [1024]u8 = undefined;
    const rotated = try x509_selfsign.buildSelfSigned(&rotated_buf, .{
        .common_name = "ocsp.example",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x45},
        .key_pair = key,
        .dns_names = &.{"ocsp.example"},
        .is_ca = true,
    });
    try std.testing.expect(!stapleServableForChain(response, &.{ rotated, rotated }, now, 0));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(response, &.{ rotated, rotated }, now, 0));

    // The same issuer key and leaf serial still authenticate the signature,
    // but a different issuer Name hash must invalidate the signed CertID.
    const wrong_name = try ocsp.testSignedOcspResponseForCertId(allocator, key, .{
        .issuer_name_der = "different-issuer-name",
        .issuer_key_bytes = cert.subject_public_key,
        .serial_der = cert.serial_der,
    }, .good, "20260202030405Z");
    defer allocator.free(wrong_name);
    try std.testing.expect(ocsp.verifyResponseSignature(try ocsp.parse(wrong_name), cert.spki_der));
    try std.testing.expect(!stapleServableForChain(wrong_name, &.{ leaf, leaf }, now, 0));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(wrong_name, &.{ leaf, leaf }, now, 0));

    const wrong_key = try ocsp.testSignedOcspResponseForCertId(allocator, key, .{
        .issuer_name_der = cert.subject_der,
        .issuer_key_bytes = "different-issuer-key",
        .serial_der = cert.serial_der,
    }, .good, "20260202030405Z");
    defer allocator.free(wrong_key);
    try std.testing.expect(ocsp.verifyResponseSignature(try ocsp.parse(wrong_key), cert.spki_der));
    try std.testing.expect(!stapleServableForChain(wrong_key, &.{ leaf, leaf }, now, 0));
    try std.testing.expectEqual(@as(?i64, null), stapleValidUntilForChain(wrong_key, &.{ leaf, leaf }, now, 0));
}

test {
    std.testing.refAllDecls(@This());
}

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
pub const Snapshot = struct {
    config_digest: [32]u8,
    last_serial: [max_serial_len]u8,
    last_serial_len: u8,
    next_refresh_unix: i64,
    fail_count: u32,
    next_retry_unix: i64,
    warned_no_issuer: bool,
    warned_no_aia: bool,
    next_check_ms: i64,
    completed_checks: u64,
    captured_monotonic_ms: i64,
    execution: Execution,
    pub fn validate(self: *const Snapshot, tls: *const config_format.Config.Tls, opts: Options, anchors: []const []const u8) !void {
        try validateOptions(opts);
        if (self.last_serial_len > max_serial_len or self.next_check_ms < 0 or self.captured_monotonic_ms < 0) return error.InvalidSnapshot;
        for (self.last_serial[self.last_serial_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(tls, opts, anchors))) return error.ConfigMismatch;
    }
};
fn validateOptions(opts: Options) !void {
    if (opts.check_interval_ms == 0 or opts.check_interval_ms > std.math.maxInt(i64) or
        opts.min_refresh_seconds <= 0 or opts.max_refresh_seconds < opts.min_refresh_seconds or opts.skew_seconds < 0 or
        opts.connect_timeout_ms == 0 or opts.recv_timeout_ms == 0 or opts.max_response_bytes == 0) return error.InvalidConfig;
}
pub fn configDigest(tls: *const config_format.Config.Tls, opts: Options, anchors: []const []const u8) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/ocsp/config/1");
    try runtime_pause.hashOptional(&hash, tls.cert_path);
    try runtime_pause.hashConfigValue(&hash, opts);
    try runtime_pause.hashConfigValue(&hash, std.math.cast(u32, anchors.len) orelse return error.Capacity);
    for (anchors) |der| try runtime_pause.hashBytes(&hash, der);
    return hash.finalResult();
}

test "companion runtime ocsp real retained worker preserves scheduler backoff and serial" {
    // No certificate path: the actual checkOnce returns before touching Server.
    // This proves scheduler/pause custody, not a successful DER publication.
    var server: server_mod.Server = undefined;
    const tls: config_format.Config.Tls = .{};
    var service = Service.init(std.testing.allocator, std.testing.io, &server, &tls, .{});
    service.last_serial = @splat(0);
    service.last_serial[0] = 13;
    service.last_serial_len = 1;
    service.fail_count = 5;
    service.next_retry_unix = 1710000007;
    service.next_refresh_unix = 1710000021;
    service.warned_no_aia = true;
    try service.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .ocsp, .instance = 0, .owner_identity = &service }};
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
    const token = try service.requestPause(1);
    try service.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.ocsp, 0, &service));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    gate.control.releaseAll();
    try service.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try service.requireActivated();
    var carry = try service.capturePaused(token);
    try std.testing.expectEqual(@as(u32, 5), carry.fail_count);
    try std.testing.expectEqual(@as(i64, 1710000007), carry.next_retry_unix);
    try std.testing.expectEqual(@as(i64, 1710000021), carry.next_refresh_unix);
    try std.testing.expectEqual(@as(u8, 13), carry.last_serial[0]);
    try std.testing.expect(carry.warned_no_aia);
    var restored = Service.init(std.testing.allocator, std.testing.io, &server, &tls, .{});
    try restored.restoreSnapshot(&carry);
    try std.testing.expectEqual(carry.next_retry_unix, restored.next_retry_unix);
    try std.testing.expectEqual(carry.last_serial_len, restored.last_serial_len);
    carry.last_serial[23] = 1;
    try std.testing.expectError(error.InvalidSnapshot, restored.restoreSnapshot(&carry));
    carry.last_serial[23] = 0;
    const wrong_tls: config_format.Config.Tls = .{ .cert_path = "changed.pem" };
    try std.testing.expectError(error.ConfigMismatch, carry.validate(&wrong_tls, .{}, &.{}));
    try service.resumePaused(token);
    // Request the next epoch only once the actual worker has departed epoch1.
    const deadline = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    const next = while (true) {
        const result = service.requestPause(2) catch |err| {
            if (err != error.Busy) return err;
            if (std.Io.Clock.Timestamp.now(std.testing.io, .awake).raw.nanoseconds >= deadline.raw.nanoseconds) return error.TestUnexpectedResult;
            std.Thread.yield() catch {};
            continue;
        };
        break result;
    };
    try service.awaitPaused(next, deadline);
    const after = try service.capturePaused(next);
    try std.testing.expectEqual(@as(usize, 1), gate.view.inspect().spawned);
    try std.testing.expectEqual(@as(u32, 5), after.fail_count);
    try std.testing.expectEqual(@as(i64, 1710000007), after.next_retry_unix);
}
