// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-daemon ACME certificate renewal scheduler.
//!
//! The ACME issuance driver is blocking by design, so renewal runs on a
//! dedicated OS thread and never touches live TLS listener state. The thread
//! checks the configured certificate file's leaf expiry, renews through
//! `acme_runner.issue` when the configured threshold is reached, then only
//! signals the server reactor to hot-reload the same `[tls]` cert/key paths
//! REHASH uses.

const std = @import("std");
const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};
const dlog = @import("dlog.zig");
const linux = std.os.linux;

const acme_cli = @import("acme_cli.zig");
const acme_runner = @import("acme_runner.zig");
const config_format = @import("config_format.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const http01 = @import("acme_http01_server.zig");
const listener = @import("acme_http01_listener.zig");
const pem = @import("../proto/pem.zig");
const platform = @import("../substrate/platform.zig");
const server_mod = @import("server.zig");
const x509 = @import("../crypto/x509.zig");

const seconds_per_day: i64 = 24 * 60 * 60;
const wake_poll_ms: u64 = 1000;
const max_cert_file_bytes: usize = 256 * 1024;

/// Pure renewal predicate: renew when the leaf is expired or when its remaining
/// lifetime is at or below the configured threshold.
pub fn shouldRenew(not_after_unix: i64, now_unix: i64, renew_before_days: u16) bool {
    if (now_unix >= not_after_unix) return true;
    const threshold_seconds: i64 = @as(i64, renew_before_days) * seconds_per_day;
    return (not_after_unix - now_unix) <= threshold_seconds;
}

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *server_mod.Server,
    acme: config_format.Config.Acme,
    tls: *const config_format.Config.Tls,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    runtime: runtime_pause.WorkerState = .{},
    next_check_ms: i64 = 0,
    completed_checks: u64 = 0,
    last_outcome: Outcome = .none,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        server: *server_mod.Server,
        acme: config_format.Config.Acme,
        tls: *const config_format.Config.Tls,
    ) Service {
        return .{
            .allocator = allocator,
            .io = io,
            .server = server,
            .acme = acme,
            .tls = tls,
            .next_check_ms = platform.monotonicMillis() +| (std.math.cast(i64, acme.check_interval_ms) orelse std.math.maxInt(i64)),
        };
    }

    pub fn start(self: *Service) void {
        if (self.thread != null or self.runtime.view != null) return;
        self.startChecked() catch |err| {
            dlog.log("onyx-server: acme scheduler start failed ({s}); renewal disabled\n", .{@errorName(err)});
        };
    }

    /// Strict boot path for an explicitly configured renewal worker.
    pub fn startChecked(self: *Service) !void {
        if (self.thread != null or self.runtime.view != null) return error.AlreadyStarted;
        if (!self.acme.enabled) return error.NotConfigured;
        try validateConfig(self.acme);
        self.stop_flag.store(false, .release);
        errdefer self.stop_flag.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
        dlog.log("onyx-server: acme renewal scheduler enabled (interval {d}ms, threshold {d}d)\n", .{
            self.acme.check_interval_ms,
            self.acme.renew_before_days,
        });
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
        try validateConfig(self.acme);
        try self.runtime.pause.bindIo(io);
    }
    pub fn validateDormantRegistration(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validateRegistration(control, view, slot, .acme, 0, self, dormant_spawn_options);
    }
    pub fn prepareDormantWorker(self: *Service, control: *runtime_pause.start_gate.Control, view: *const runtime_pause.start_gate.View, slot: runtime_pause.start_gate.Slot) !void {
        try self.runtime.validatePreparation(control, view, slot, .acme, 0, self, dormant_spawn_options);
        if (self.thread != null) return error.AlreadyStarted;
        if (!self.acme.enabled) return error.NotConfigured;
        try validateConfig(self.acme);
        self.stop_flag.store(false, .release);
        try self.runtime.prepare(control, view, slot, .acme, 0, Service, self, worker, dormant_spawn_options);
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
        return .{ .config_digest = try configDigest(self.acme, self.tls), .next_check_ms = self.next_check_ms, .completed_checks = self.completed_checks, .last_outcome = self.last_outcome, .captured_monotonic_ms = platform.monotonicMillis(), .execution = execution };
    }
    /// Source arrival proves there is no live runIssue child: its deferred
    /// challenge.shutdown/join and TokenStore/key/anchor cleanup have finished.
    /// Server reload intent/material and file namespace remain separately joined
    /// mandatory state; this scheduler row is not a TLS publication receipt.
    pub fn restoreSnapshot(self: *Service, snapshot: *const Snapshot) !void {
        if (self.thread != null or self.runtime.view != null or self.runtime.pause.request_epoch != 0) return error.NotQuiescent;
        try snapshot.validate(self.acme, self.tls);
        self.next_check_ms = snapshot.next_check_ms;
        self.completed_checks = snapshot.completed_checks;
        self.last_outcome = snapshot.last_outcome;
    }
    fn worker(self: *Service) void {
        self.runtime.markEntered();
        defer self.runtime.markExited();
        while (!self.stop_flag.load(.acquire)) {
            // This is after the preceding complete operation, all nested child
            // cleanup and the Server reload callback. No in-flight issuance is
            // encoded as an empty snapshot when the pause deadline expires.
            self.runtime.pause.boundary();
            if (self.stop_flag.load(.acquire)) break;
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
            self.next_check_ms = platform.monotonicMillis() +| (std.math.cast(i64, self.acme.check_interval_ms) orelse std.math.maxInt(i64));
        }
    }

    fn checkOnce(self: *Service) void {
        self.last_outcome = .skipped;
        const domain = self.acme.domain orelse {
            dlog.log("onyx-server: acme renewal skipped: [acme].domain is not configured\n", .{});
            return;
        };
        if (domain.len == 0) {
            dlog.log("onyx-server: acme renewal skipped: [acme].domain is empty\n", .{});
            return;
        }
        const cert_path = self.tls.cert_path orelse {
            dlog.log("onyx-server: acme renewal skipped: [tls].cert_path is required\n", .{});
            return;
        };
        const key_path = self.tls.key_path orelse {
            dlog.log("onyx-server: acme renewal skipped: [tls].key_path is required\n", .{});
            return;
        };

        const now = @divTrunc(platform.realtimeMillis(), 1000);
        const not_after = certFileLeafNotAfterUnix(self.allocator, self.io, cert_path) catch |err| {
            self.last_outcome = .failed;
            dlog.log("onyx-server: acme renewal skipped: cannot read TLS cert file {s} ({s})\n", .{ cert_path, @errorName(err) });
            return;
        };
        const remaining_days: i64 = if (not_after > now) @divTrunc(not_after - now, seconds_per_day) else 0;
        if (!shouldRenew(not_after, now, self.acme.renew_before_days)) {
            self.last_outcome = .not_due;
            dlog.log("onyx-server: acme renewal not due for {s}: leaf expires in {d}d\n", .{ domain, remaining_days });
            return;
        }

        dlog.log("onyx-server: acme renewal due for {s}: leaf expires in {d}d\n", .{ domain, remaining_days });
        const wrote = self.runIssue(domain, cert_path, key_path) catch |err| {
            self.last_outcome = .failed;
            dlog.log("onyx-server: acme renewal failed for {s} ({s})\n", .{ domain, @errorName(err) });
            return;
        };
        if (!wrote) {
            self.last_outcome = .not_written;
            dlog.log("onyx-server: acme renewal completed for {s} without writing a certificate\n", .{domain});
            return;
        }

        const full_server = @import("builtin").os.tag == .linux or @import("builtin").os.tag == .openbsd or @import("builtin").os.tag == .windows;
        if (comptime full_server) {
            self.server.requestAcmeTlsReload();
            self.last_outcome = .reload_requested;
            dlog.log("onyx-server: acme renewal wrote certs for {s}; TLS reload requested on reactor 0\n", .{domain});
        } else {
            self.last_outcome = .failed;
            dlog.log("onyx-server: acme renewal wrote certs for {s} but TLS reload is unsupported on this platform\n", .{domain});
        }
    }

    fn runIssue(self: *Service, domain: []const u8, cert_path: []const u8, key_path: []const u8) !bool {
        const bundle_text = try std.Io.Dir.cwd().readFileAlloc(self.io, self.acme.ca_bundle_path, self.allocator, .limited(@intCast(self.acme.ca_bundle_max_bytes)));
        defer self.allocator.free(bundle_text);

        var anchors = try acme_cli.loadTrustAnchors(self.allocator, bundle_text);
        defer freeTrustAnchors(self.allocator, &anchors);
        if (anchors.items.len == 0) return error.NoTrustAnchors;
        dlog.log("onyx-server: acme loaded {d} trust anchors from {s}\n", .{ anchors.items.len, self.acme.ca_bundle_path });

        const account_key = ecdsa_p256.KeyPair.generate(self.io);
        const cert_key = ecdsa_p256.KeyPair.generate(self.io);

        var store = http01.TokenStore.init(self.allocator);
        defer store.deinit();
        var challenge = try listener.ChallengeServer.initWithConfig(&store, self.acme.challenge_port, .{
            .listen_backlog = @intCast(self.acme.http01_listen_backlog),
            .accept_poll_ms = self.acme.http01_accept_poll_ms,
            .conn_read_timeout_sec = self.acme.http01_conn_read_timeout_sec,
        });
        try challenge.spawn();
        defer challenge.shutdown();
        dlog.log("onyx-server: acme HTTP-01 listener on 127.0.0.1:{d}\n", .{challenge.port});

        const domains = [_][]const u8{domain};
        var contacts_storage: [1][]const u8 = undefined;
        const contacts: []const []const u8 = if (self.acme.contact) |contact| blk: {
            contacts_storage[0] = contact;
            break :blk contacts_storage[0..1];
        } else &.{};

        const result = try acme_runner.issue(self.allocator, self.io, .{
            .directory_url = self.acme.directory_url,
            .domains = &domains,
            .contacts = contacts,
            .trust_anchors = anchors.items,
            .cert_out_path = cert_path,
            .key_out_path = key_path,
            .max_steps = self.acme.max_steps,
            .debug = self.acme.debug,
            .max_response_bytes = @intCast(self.acme.max_response_bytes),
            .error_body_preview_bytes = @intCast(self.acme.error_body_preview_bytes),
            .resolv_conf_max_bytes = @intCast(self.acme.resolv_conf_max_bytes),
            .dns_port = self.acme.dns_port,
        }, account_key, cert_key, &store, null);
        return result.cert_written;
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

pub fn certFileLeafNotAfterUnix(allocator: std.mem.Allocator, io: std.Io, cert_path: []const u8) !i64 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, cert_path, allocator, .limited(max_cert_file_bytes));
    defer allocator.free(raw);

    if (isPem(raw)) {
        const der_buf = try allocator.alloc(u8, raw.len);
        defer allocator.free(der_buf);
        const der = try pem.decode(raw, "CERTIFICATE", der_buf);
        const cert = try x509.parse(der);
        return cert.not_after.epoch_seconds;
    }

    const cert = try x509.parse(raw);
    return cert.not_after.epoch_seconds;
}

fn isPem(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "-----BEGIN") != null;
}

fn freeTrustAnchors(allocator: std.mem.Allocator, anchors: *std.ArrayList([]u8)) void {
    for (anchors.items) |anchor| allocator.free(anchor);
    anchors.deinit(allocator);
}

test "shouldRenew: due inside threshold and at the boundary" {
    const now: i64 = 1_700_000_000;
    const thirty_days = 30 * seconds_per_day;

    try std.testing.expect(shouldRenew(now + thirty_days - 1, now, 30));
    try std.testing.expect(shouldRenew(now + thirty_days, now, 30));
    try std.testing.expect(!shouldRenew(now + thirty_days + 1, now, 30));
}

test "shouldRenew: expired leaves are due" {
    const now: i64 = 1_700_000_000;

    try std.testing.expect(shouldRenew(now, now, 30));
    try std.testing.expect(shouldRenew(now - 1, now, 30));
}

test "shouldRenew: handles large timestamps without addition overflow" {
    const not_after = std.math.maxInt(i64);

    try std.testing.expect(shouldRenew(not_after, not_after - seconds_per_day, 1));
    try std.testing.expect(!shouldRenew(not_after, not_after - (2 * seconds_per_day), 1));
}

test "Windows ACME renewal worker starts and joins without a certificate path" {
    if (comptime @import("builtin").os.tag != .windows) return error.SkipZigTest;
    const server = try std.testing.allocator.create(server_mod.Server);
    defer std.testing.allocator.destroy(server);
    const tls: config_format.Config.Tls = .{};
    var service = Service.init(std.testing.allocator, std.testing.io, server, .{ .enabled = true }, &tls);
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

test "certFileLeafNotAfterUnix reads the leaf expiry from a PEM certificate file" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const Ed25519 = std.crypto.sign.Ed25519;
    const allocator = std.testing.allocator;
    const expected_not_after: i64 = 1_735_689_599;

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x88)));
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "acme.test",
        .not_before = 1_704_067_200,
        .not_after = expected_not_after,
        .serial = &.{ 0x88, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"acme.test"},
        .is_ca = true,
    });

    var pem_buf: [4096]u8 = undefined;
    const cert_pem = try pem.encode(&pem_buf, "CERTIFICATE", der);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf.pem", .data = cert_pem });
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path});
    defer allocator.free(path);

    try std.testing.expectEqual(expected_not_after, try certFileLeafNotAfterUnix(allocator, std.testing.io, path));
}

test {
    std.testing.refAllDecls(@This());
}

pub const Execution = enum(u8) { unstarted = 0, paused = 1 };
pub const Outcome = enum(u8) { none = 0, skipped = 1, not_due = 2, failed = 3, not_written = 4, reload_requested = 5 };
pub const Snapshot = struct {
    config_digest: [32]u8,
    next_check_ms: i64,
    completed_checks: u64,
    last_outcome: Outcome,
    captured_monotonic_ms: i64,
    execution: Execution,
    pub fn validate(self: *const Snapshot, acme: config_format.Config.Acme, tls: *const config_format.Config.Tls) !void {
        try validateConfig(acme);
        if (self.next_check_ms < 0 or self.captured_monotonic_ms < 0 or (self.completed_checks == 0 and self.last_outcome != .none)) return error.InvalidSnapshot;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(acme, tls))) return error.ConfigMismatch;
    }
};
fn validateConfig(acme: config_format.Config.Acme) !void {
    if (acme.check_interval_ms == 0 or acme.check_interval_ms > std.math.maxInt(i64) or acme.http01_accept_poll_ms == 0 or
        acme.http01_conn_read_timeout_sec == 0 or acme.max_steps == 0 or acme.max_response_bytes == 0 or
        acme.ca_bundle_max_bytes == 0 or acme.resolv_conf_max_bytes == 0 or acme.http01_listen_backlog > std.math.maxInt(u31)) return error.InvalidConfig;
}
pub fn configDigest(acme: config_format.Config.Acme, tls: *const config_format.Config.Tls) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/acme/config/1");
    try runtime_pause.hashConfigValue(&hash, acme);
    try runtime_pause.hashOptional(&hash, tls.cert_path);
    try runtime_pause.hashOptional(&hash, tls.key_path);
    return hash.finalResult();
}

test "companion runtime acme retained worker carries deadline and actual skipped outcome" {
    // Missing domain exercises the actual source checkOnce skip path without
    // any file/network/Server access. No successful issuance/reload is claimed.
    var server: server_mod.Server = undefined;
    const tls: config_format.Config.Tls = .{};
    const acme: config_format.Config.Acme = .{ .enabled = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &server, acme, &tls);
    service.checkOnce();
    service.completed_checks = 1;
    const original_deadline = service.next_check_ms;
    try service.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .acme, .instance = 0, .owner_identity = &service }};
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
    try service.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.acme, 0, &service));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    gate.control.releaseAll();
    try service.awaitPaused(token, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try service.requireActivated();
    var carry = try service.capturePaused(token);
    try std.testing.expectEqual(original_deadline, carry.next_check_ms);
    try std.testing.expectEqual(Outcome.skipped, carry.last_outcome);
    try std.testing.expectEqual(@as(u64, 1), carry.completed_checks);
    var restored = Service.init(std.testing.allocator, std.testing.io, &server, acme, &tls);
    try restored.restoreSnapshot(&carry);
    try std.testing.expectEqual(original_deadline, restored.next_check_ms);
    try std.testing.expectEqual(Outcome.skipped, restored.last_outcome);
    carry.next_check_ms = -1;
    try std.testing.expectError(error.InvalidSnapshot, restored.restoreSnapshot(&carry));
    try std.testing.expectEqual(original_deadline, restored.next_check_ms);
    carry.next_check_ms = original_deadline;
    var changed = acme;
    changed.http01_listen_backlog += 1;
    try std.testing.expectError(error.ConfigMismatch, carry.validate(changed, &tls));
    carry.completed_checks = 0;
    try std.testing.expectError(error.InvalidSnapshot, carry.validate(acme, &tls));
}
