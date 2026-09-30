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
        };
    }

    pub fn start(self: *Service) void {
        if (self.thread != null) return;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, worker, .{self}) catch |err| {
            dlog.log("onyx-server: acme scheduler start failed ({s}); renewal disabled\n", .{@errorName(err)});
            return;
        };
        dlog.log("onyx-server: acme renewal scheduler enabled (interval {d}ms, threshold {d}d)\n", .{
            self.acme.check_interval_ms,
            self.acme.renew_before_days,
        });
    }

    pub fn stop(self: *Service) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn worker(self: *Service) void {
        while (!self.stop_flag.load(.acquire)) {
            if (!sleepInterruptible(self.acme.check_interval_ms, &self.stop_flag)) break;
            self.checkOnce();
        }
    }

    fn checkOnce(self: *Service) void {
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
            dlog.log("onyx-server: acme renewal skipped: cannot read TLS cert file {s} ({s})\n", .{ cert_path, @errorName(err) });
            return;
        };
        const remaining_days: i64 = if (not_after > now) @divTrunc(not_after - now, seconds_per_day) else 0;
        if (!shouldRenew(not_after, now, self.acme.renew_before_days)) {
            dlog.log("onyx-server: acme renewal not due for {s}: leaf expires in {d}d\n", .{ domain, remaining_days });
            return;
        }

        dlog.log("onyx-server: acme renewal due for {s}: leaf expires in {d}d\n", .{ domain, remaining_days });
        const wrote = self.runIssue(domain, cert_path, key_path) catch |err| {
            dlog.log("onyx-server: acme renewal failed for {s} ({s})\n", .{ domain, @errorName(err) });
            return;
        };
        if (!wrote) {
            dlog.log("onyx-server: acme renewal completed for {s} without writing a certificate\n", .{domain});
            return;
        }

        self.server.requestAcmeTlsReload();
        dlog.log("onyx-server: acme renewal wrote certs for {s}; TLS reload requested on reactor 0\n", .{domain});
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
