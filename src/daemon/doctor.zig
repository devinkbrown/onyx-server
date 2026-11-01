// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only, fixed preflight checks for an already loaded configuration.
const std = @import("std");
const config_boot = @import("config_boot.zig");
const tls_certs = @import("tls_certs.zig");
const x509 = @import("../crypto/x509.zig");
const http_fetch = @import("http_fetch.zig");
const http1 = @import("../proto/http1_client.zig");
const diagnostics = @import("diagnostics.zig");

pub const EventCount = struct {
    event: diagnostics.Event,
    count: ?u64 = null,
};

/// Fixed-cardinality numeric observations, never fetched labels or text.
pub const Observations = struct {
    tcp_active: ?u64 = null,
    /// Legacy key retained as unknown: links_active includes plaintext links.
    secured_links: ?u64 = null,
    established_links: ?u64 = null,
    peers_up: ?u64 = null,
    peers_total: ?u64 = null,
    quorum: ?u64 = null,
    components: ?u64 = null,
    freshness: []const u8 = "unknown; metric source has no verified sample time",
    service_readiness: []const u8 = "unknown; metrics do not prove service readiness",
    partitioned: ?u64 = null,
    connection_events: [diagnostics.event_count]EventCount = emptyEventCounts(),
};

fn emptyEventCounts() [diagnostics.event_count]EventCount {
    var counts: [diagnostics.event_count]EventCount = undefined;
    inline for (std.meta.tags(diagnostics.Event), 0..) |event, i| counts[i] = .{ .event = event };
    return counts;
}

fn unsignedCount(value: []const u8) ?u64 {
    if (value.len == 0) return null;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(u64, value, 10) catch null;
}

fn observeMetrics(body: []const u8) error{MetricsTooLarge}!Observations {
    if (body.len > 1024 * 1024) return error.MetricsTooLarge;
    var result: Observations = .{};
    var seen: [7 + diagnostics.event_count]bool = @splat(false);
    var rows = std.mem.splitScalar(u8, body, '\n');
    while (rows.next()) |row| {
        var fields = std.mem.tokenizeAny(u8, row, " \t\r");
        const name = fields.next() orelse continue;
        const raw = fields.next() orelse "";
        const count = if (fields.next() == null) unsignedCount(raw) else null;
        const scalar_names = .{ "onyx_s2s_tcp_active", "onyx_s2s_links_active", "onyx_mesh_partitioned", "onyx_mesh_peers_up", "onyx_mesh_peers_total", "onyx_mesh_quorum", "onyx_mesh_components" };
        inline for (scalar_names, .{ "tcp_active", "established_links", "partitioned", "peers_up", "peers_total", "quorum", "components" }, 0..) |metric, field, index| {
            if (std.mem.eql(u8, name, metric)) {
                @field(result, field) = if (seen[index]) null else count;
                seen[index] = true;
            }
        }
        inline for (@typeInfo(diagnostics.Event).@"enum".field_names, 0..) |event, index| {
            const metric = "onyx_connection_diagnostics_total{event=\"" ++ event ++ "\"}";
            if (std.mem.eql(u8, name, metric)) {
                result.connection_events[index].count = if (seen[7 + index]) null else count;
                seen[7 + index] = true;
            }
        }
    }
    if (result.quorum != null and result.quorum.? > 1) result.quorum = null;
    if (result.partitioned != null and result.partitioned.? > 1) result.partitioned = null;
    return result;
}

pub const FetchFn = *const fn (std.mem.Allocator, []const u8) anyerror![]u8;
pub const Check = struct {
    status: []const u8,
    id: []const u8,
    source: []const u8,
    detail: []const u8,
};
/// Fixed capability names derived only from local configuration fields
/// doctor already inspects. Never negotiated or live peer capabilities.
pub const capability_allowlist = [_][]const u8{
    "mesh_peers_configured",
    "mesh_require_secured",
    "mesh_require_signed_frames",
    "mesh_cloak_configured",
    "cloak_account",
    "cloak_anon_rotation",
    "tls_configured",
    "ocsp_configured",
};

pub const CapabilityEntry = struct {
    name: []const u8,
    configured: bool = false,
};

pub const CapabilitySummary = struct {
    source: []const u8 = "local-config",
    peer_live_verified: bool = false,
    entries: [capability_allowlist.len]CapabilityEntry = defaultCapabilityEntries(),
};

fn defaultCapabilityEntries() [capability_allowlist.len]CapabilityEntry {
    var entries: [capability_allowlist.len]CapabilityEntry = undefined;
    inline for (capability_allowlist, 0..) |name, i| entries[i] = .{ .name = name };
    return entries;
}

fn capabilitySummary(loaded: *const config_boot.Loaded) CapabilitySummary {
    const parsed = loaded.parsed;
    var summary: CapabilitySummary = .{};
    summary.entries[0].configured = parsed.mesh.connect.len != 0 or parsed.listen.s2s != 0;
    summary.entries[1].configured = parsed.mesh.require_secured;
    summary.entries[2].configured = parsed.mesh.require_signed_frames;
    summary.entries[3].configured = parsed.cloak.secret != null;
    summary.entries[4].configured = parsed.cloak.account_cloak;
    summary.entries[5].configured = parsed.cloak.anon_epoch_secs != 0;
    summary.entries[6].configured = parsed.tls.enabled;
    summary.entries[7].configured = parsed.ocsp.enabled;
    return summary;
}

pub const max_diagnostics_traces = 8;

pub const DiagnosticsTrace = struct {
    id: []const u8,
    status: []const u8,
};

/// Bounded summary of doctor's own check outcomes. A live
/// `diagnostics.Diagnostics` snapshot is not available to offline
/// preflight, so traces carry only fixed check ids and statuses;
/// sources, details, and any configured values are excluded.
pub const DiagnosticsSummary = struct {
    source: []const u8 = "doctor-checks",
    total: usize = 0,
    passed: usize = 0,
    failed: usize = 0,
    skipped: usize = 0,
    other: usize = 0,
    truncated: bool = false,
    connection_event_kinds: usize = diagnostics.event_count,
    traces: []const DiagnosticsTrace = &.{},
};

pub const Result = struct {
    lines: []u8,
    checks: []Check,
    failed: bool,
    observations: ?Observations = null,
    capabilities: CapabilitySummary = .{},
    cadence_detail: ?[]u8 = null,
    service_environment: @import("service_environment.zig").Environment = .{},
    pub fn deinit(self: Result, allocator: std.mem.Allocator) void {
        allocator.free(self.lines);
        allocator.free(self.checks);
        if (self.cadence_detail) |detail| allocator.free(detail);
    }

    /// Only bounded check identifiers and server-defined explanations are
    /// exported, including the nonsecret anonymous cadence. No URLs, labels,
    /// addresses or bearer credentials enter it.
    fn diagnosticsSummary(self: Result, trace_buf: *[max_diagnostics_traces]DiagnosticsTrace) DiagnosticsSummary {
        var summary: DiagnosticsSummary = .{ .total = self.checks.len, .truncated = self.checks.len > max_diagnostics_traces };
        for (self.checks) |check| {
            if (std.mem.eql(u8, check.status, "pass")) {
                summary.passed += 1;
            } else if (std.mem.eql(u8, check.status, "fail")) {
                summary.failed += 1;
            } else if (std.mem.eql(u8, check.status, "skipped")) {
                summary.skipped += 1;
            } else {
                summary.other += 1;
            }
        }
        const n = @min(max_diagnostics_traces, self.checks.len);
        for (self.checks[0..n], 0..) |check, i| trace_buf[i] = .{ .id = check.id, .status = check.status };
        summary.traces = trace_buf[0..n];
        return summary;
    }

    pub fn toJson(self: Result, allocator: std.mem.Allocator) ![]u8 {
        var trace_buf: [max_diagnostics_traces]DiagnosticsTrace = undefined;
        return std.json.Stringify.valueAlloc(allocator, .{
            .schema_version = @as(u8, 1),
            .mode = "preflight",
            .readiness = "unknown",
            // Reporting binary, not an assertion about a remote metrics source.
            .report_build_version = @import("build_info").version,
            .failed = self.failed,
            .checks = self.checks,
            .capabilities = self.capabilities,
            .diagnostics = self.diagnosticsSummary(&trace_buf),
            .observations = self.observations,
            .service_environment = self.service_environment,
            .service_plan = @import("service_environment.zig").servicePlan(self.service_environment, null),
        }, .{ .whitespace = .indent_2 });
    }
};

fn line(out: *std.ArrayList(u8), checks: *std.ArrayList(Check), allocator: std.mem.Allocator, failed: *bool, status: []const u8, id: []const u8, citation: []const u8, detail: []const u8) !void {
    if (std.mem.eql(u8, status, "fail")) failed.* = true;
    const formatted = try std.fmt.allocPrint(allocator, "doctor {s} {s} {s} {s}\n", .{ status, id, citation, detail });
    defer allocator.free(formatted);
    try out.appendSlice(allocator, formatted);
    try checks.append(allocator, .{ .status = status, .id = id, .source = citation, .detail = detail });
}

/// The optional body is for offline fixtures. With a URL, fetch is invoked
/// exactly once; no other network path exists in this module.
pub fn report(allocator: std.mem.Allocator, io: std.Io, loaded: *const config_boot.Loaded, metrics_url: ?[]const u8, metrics_body: ?[]const u8, fetch: ?FetchFn) !Result {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var checks: std.ArrayList(Check) = .empty;
    errdefer checks.deinit(allocator);
    var failed = false;

    const io_reason = config_boot.configCheckError(loaded.io, .off);
    try line(&out, &checks, allocator, &failed, if (io_reason == null) "pass" else "fail", "sqpoll_defer_taskrun", "src/daemon/config_boot.zig", io_reason orelse "configCheckError allowed io flags");
    const ktls_reason = config_boot.configCheckError(.{}, loaded.tls.ktls);
    try line(&out, &checks, allocator, &failed, if (ktls_reason == null) "pass" else "fail", "ktls_txrx", "src/daemon/config_boot.zig", ktls_reason orelse "configCheckError allowed kTLS mode");
    const mesh_reason = config_boot.unsecuredMeshPeerError(loaded.parsed.mesh.connect.len, loaded.parsed.mesh.require_secured);
    try line(&out, &checks, allocator, &failed, if (mesh_reason == null) "pass" else "fail", "mesh_security", "mesh.require_secured", mesh_reason orelse "configured peer security requirement satisfied");
    try line(&out, &checks, allocator, &failed, if (loaded.parsed.meshCloakSecretMissing()) "fail" else "pass", "mesh_cloak", "cloak.secret", if (loaded.parsed.meshCloakSecretMissing()) "meshed nodes require the same configured cloak secret" else "static cloak configuration requirement satisfied; cross-node equality not verified");

    const cadence = loaded.parsed.cloak.anon_epoch_secs;
    const cadence_detail = try std.fmt.allocPrint(allocator, "{s}; {d} seconds; authenticated clients do not use anonymous rotation{s}", .{
        if (cadence == 0)
            "anonymous rotation disabled"
        else if (cadence == 86_400)
            "anonymous rotation is daily; review whether to retain it or use the 14-day default"
        else if (cadence == 1_209_600)
            "anonymous rotation is 14 days (default cadence)"
        else
            "anonymous rotation uses a nondefault cadence",
        cadence,
        if (loaded.parsed.cloak.account_cloak) "; account cloaks enabled" else "; account cloaks disabled",
    });
    errdefer allocator.free(cadence_detail);
    try line(&out, &checks, allocator, &failed, "pass", "cloak_anon_cadence", "cloak.anon_epoch_secs", cadence_detail);

    if (!loaded.parsed.ocsp.enabled) {
        try line(&out, &checks, allocator, &failed, "skipped", "ocsp_leaf_uri", "ocsp.enabled", "false");
    } else if (loaded.parsed.tls.cert_path) |path| {
        if (path.len == 0) {
            try line(&out, &checks, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
        } else {
            const chain = tls_certs.loadCertChain(allocator, io, path) catch |err| blk: {
                try line(&out, &checks, allocator, &failed, "skipped", "ocsp_leaf_uri", "tls.cert_path", @errorName(err));
                break :blk null;
            };
            if (chain) |certs| {
                defer {
                    for (certs) |der| allocator.free(der);
                    allocator.free(certs);
                }
                if (certs.len == 0) {
                    try line(&out, &checks, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
                } else if (x509.parse(certs[0])) |leaf| {
                    if (leaf.aia_ocsp_url.len == 0) {
                        try line(&out, &checks, allocator, &failed, "fail", "ocsp_leaf_uri", "aia_ocsp_url", "leaf has no AIA OCSP responder URL");
                    } else {
                        try line(&out, &checks, allocator, &failed, "pass", "ocsp_leaf_uri", "aia_ocsp_url", "leaf contains an AIA OCSP responder URL");
                    }
                } else |err| {
                    try line(&out, &checks, allocator, &failed, "skipped", "ocsp_leaf_uri", "tls.cert_path", @errorName(err));
                }
            }
        }
    } else {
        try line(&out, &checks, allocator, &failed, "fail", "ocsp_leaf_uri", "tls.cert_path", "missing leaf");
    }

    var owned_body: ?[]u8 = null;
    defer if (owned_body) |body| allocator.free(body);
    var body = metrics_body;
    var fetch_error: ?[]const u8 = null;
    if (metrics_url) |url| {
        if (fetch) |get| {
            owned_body = get(allocator, url) catch |err| blk: {
                fetch_error = @errorName(err);
                break :blk null;
            };
            body = owned_body;
        } else {
            fetch_error = "no fetch function";
            body = null;
        }
    }
    var observations: ?Observations = null;
    if (body) |metrics| {
        observations = try observeMetrics(metrics);
        const tcp = observations.?.tcp_active;
        const links = observations.?.established_links;
        if (tcp == null) {
            try line(&out, &checks, allocator, &failed, "skipped", "s2s_handshake", "onyx_s2s_tcp_active", "missing gauge");
        } else if (links == null) {
            try line(&out, &checks, allocator, &failed, "skipped", "s2s_handshake", "onyx_s2s_links_active", "missing gauge");
        } else {
            const stuck = tcp.? > 0 and links.? == 0;
            try line(&out, &checks, allocator, &failed, if (stuck) "fail" else "pass", "s2s_handshake", "onyx_s2s_tcp_active,onyx_s2s_links_active", if (stuck) "TCP active but no established S2S link (secured or plaintext)" else "gauges do not show a stuck handshake");
        }
        const partitioned = observations.?.partitioned;
        if (partitioned) |value| {
            try line(&out, &checks, allocator, &failed, if (value == 0) "pass" else "fail", "mesh_partition", "onyx_mesh_partitioned", if (value == 0) "node does not report a partition" else "node reports a partition; inspect link security and peer health");
        } else {
            try line(&out, &checks, allocator, &failed, "skipped", "mesh_partition", "onyx_mesh_partitioned", "missing or invalid gauge");
        }
    } else {
        try line(&out, &checks, allocator, &failed, "skipped", "s2s_handshake", if (metrics_url == null) "no metrics URL" else "metrics endpoint", fetch_error orelse "no metrics body");
    }
    try line(&out, &checks, allocator, &failed, "skipped", "mesh_transport_security", "metrics", "unknown; established links may be secured or plaintext");
    try line(&out, &checks, allocator, &failed, "skipped", "mesh_capabilities", "metrics", "unknown; negotiated peer capabilities are not exposed by these gauges");
    try line(&out, &checks, allocator, &failed, "skipped", "service_readiness", "metrics", "unknown; these observations do not prove service readiness or freshness");
    const service_env = @import("service_environment.zig").detect(io);
    const service_plan = @import("service_environment.zig").servicePlan(service_env, null);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_manager", "shipped template; host status unknown", @tagName(service_plan.selected));
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_executable", "shipped template; host status unknown", service_plan.template.executable);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_config", "shipped template; host status unknown", service_plan.template.config);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_identity", "shipped template; host status unknown", service_plan.template.identity);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_working_directory", "shipped template; host status unknown", service_plan.template.working_directory);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_preflight", "shipped template; host status unknown", service_plan.template.preflight_policy);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_preflight_arg0", "shipped template; host status unknown", service_plan.template.preflight_argv[0]);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_preflight_arg1", "shipped template; host status unknown", service_plan.template.preflight_argv[1]);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_preflight_arg2", "shipped template; host status unknown", service_plan.template.preflight_argv[2]);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_start_arg0", "shipped template; host status unknown", service_plan.template.start_argv[0]);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_start_arg1", "shipped template; host status unknown", service_plan.template.start_argv[1]);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_restart", "shipped template; host status unknown", service_plan.template.restart);
    try line(&out, &checks, allocator, &failed, "skipped", "service_plan_logging", "shipped template; host status unknown", service_plan.template.logging);
    const lines = try out.toOwnedSlice(allocator);
    errdefer allocator.free(lines);
    return .{ .lines = lines, .checks = try checks.toOwnedSlice(allocator), .failed = failed, .observations = observations, .capabilities = capabilitySummary(loaded), .cadence_detail = cadence_detail, .service_environment = service_env };
}

/// Privileged, offline comparison of two already-resolved configurations.
/// Outputs only fixed category names and statuses, never values or digests.
fn secretEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return std.crypto.timing_safe.compare(u8, a, b, .big) == .eq;
}

pub fn cloakComparison(allocator: std.mem.Allocator, local: *const config_boot.Loaded, peer: *const config_boot.Loaded) !Result {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var checks: std.ArrayList(Check) = .empty;
    errdefer checks.deinit(allocator);
    var failed = false;
    const a = local.parsed.cloak;
    const b = peer.parsed.cloak;
    try line(&out, &checks, allocator, &failed, "pass", "cloak_scope", "local configurations", "configuration comparison only; running peer not verified");
    const current_equal = if (a.secret) |left| if (b.secret) |right| secretEqual(left, right) else false else false;
    try line(&out, &checks, allocator, &failed, if (current_equal) "pass" else "fail", "cloak_current", "cloak.secret", if (current_equal) "equal" else "mismatch or missing");
    const prior_status: []const u8 = if (a.previous_secret == null and b.previous_secret == null) "skipped" else if (a.previous_secret != null and b.previous_secret != null and secretEqual(a.previous_secret.?, b.previous_secret.?)) "pass" else "fail";
    try line(&out, &checks, allocator, &failed, prior_status, "cloak_previous", "cloak.previous_secret", if (std.mem.eql(u8, prior_status, "skipped")) "not configured on either side" else if (std.mem.eql(u8, prior_status, "pass")) "equal" else "mismatch or missing");
    const cloak = @import("../proto/cloak.zig");
    var abuf: [cloak.max_hostname_len]u8 = undefined;
    var bbuf: [cloak.max_hostname_len]u8 = undefined;
    const asuffix = cloak.normalizeSuffix(&abuf, a.suffix orelse cloak.default_suffix) catch return error.InvalidCloakSuffix;
    const bsuffix = cloak.normalizeSuffix(&bbuf, b.suffix orelse cloak.default_suffix) catch return error.InvalidCloakSuffix;
    const suffix_equal = std.mem.eql(u8, asuffix, bsuffix);
    const amode = if (a.mode) |m| std.mem.eql(u8, m, "opaque") else false;
    const bmode = if (b.mode) |m| std.mem.eql(u8, m, "opaque") else false;
    const values = [_]struct { id: []const u8, source: []const u8, equal: bool }{
        .{ .id = "cloak_suffix", .source = "cloak.suffix", .equal = suffix_equal },
        .{ .id = "cloak_mode", .source = "cloak.mode", .equal = amode == bmode },
        .{ .id = "cloak_account", .source = "cloak.account_cloak", .equal = a.account_cloak == b.account_cloak },
        .{ .id = "cloak_cadence", .source = "cloak.anon_epoch_secs", .equal = a.anon_epoch_secs == b.anon_epoch_secs },
    };
    for (values) |item| try line(&out, &checks, allocator, &failed, if (item.equal) "pass" else "fail", item.id, item.source, if (item.equal) "equal" else "mismatch");
    const lines = try out.toOwnedSlice(allocator);
    errdefer allocator.free(lines);
    return .{ .lines = lines, .checks = try checks.toOwnedSlice(allocator), .failed = failed, .capabilities = capabilitySummary(local) };
}

pub fn cloakComparisonUnavailable(allocator: std.mem.Allocator) !Result {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var checks: std.ArrayList(Check) = .empty;
    errdefer checks.deinit(allocator);
    var failed = false;
    try line(&out, &checks, allocator, &failed, "fail", "cloak_comparison", "local configurations", "configuration unavailable or invalid; running peer not verified");
    const lines = try out.toOwnedSlice(allocator);
    errdefer allocator.free(lines);
    return .{ .lines = lines, .checks = try checks.toOwnedSlice(allocator), .failed = failed };
}

/// One explicit GET. The caller never invokes this without a metrics URL.
pub fn fetchMetrics(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const target = try http_fetch.parseUrl(url);
    var request_buf: [2048]u8 = undefined;
    const req = try http1.buildRequest(&request_buf, "GET", target.host, target.path, &.{}, "");
    const response = try http_fetch.get(allocator, target.host, target.port, target.tls, req, .{ .max_response_bytes = 1024 * 1024 });
    defer allocator.free(response);
    var storage: [32]http1.Header = undefined;
    const parsed = try http1.parseResponse(response, &storage);
    if (parsed.status != 200) return error.MetricsHttpStatus;
    return allocator.dupe(u8, parsed.body);
}

test "GAP-O4 branch=doctor read-only fixed checks" {
    std.debug.print("GAP-O4 branch=doctor read-only fixed checks\n", .{});
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const fixture = "onyx_s2s_tcp_active 2\nonyx_s2s_links_active 0\n";
    const Counter = struct {
        var calls: usize = 0;
        var last_url: []const u8 = "";
        fn fetch(a: std.mem.Allocator, url: []const u8) ![]u8 {
            calls += 1;
            last_url = url;
            return a.dupe(u8, fixture);
        }
    };
    Counter.calls = 0;
    const offline = try report(allocator, std.testing.io, &loaded, null, fixture, Counter.fetch);
    defer offline.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), Counter.calls);
    try std.testing.expect(offline.failed);
    try std.testing.expect(std.mem.indexOf(u8, offline.lines, "doctor fail s2s_handshake") != null);
    const online = try report(allocator, std.testing.io, &loaded, "http://example.test/metrics", null, Counter.fetch);
    defer online.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), Counter.calls);
    try std.testing.expectEqualStrings("http://example.test/metrics", Counter.last_url);
    try std.testing.expect(online.failed);
    const skipped = try report(allocator, std.testing.io, &loaded, null, null, Counter.fetch);
    defer skipped.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), Counter.calls);
    try std.testing.expect(!skipped.failed);
    try std.testing.expect(std.mem.indexOf(u8, skipped.lines, "no metrics URL") != null);
}

test "GAP-O4 config failures, missing gauges, and parsed OCSP leaf" {
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[io]\nsqpoll=true\ndefer_taskrun=true\n[tls]\nktls=\"txrx\"\n[ocsp]\nenabled=true\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const missing = try report(allocator, std.testing.io, &loaded, null, "onyx_s2s_tcp_active 1\n", null);
    defer missing.deinit(allocator);
    try std.testing.expect(missing.failed);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, config_boot.sqpoll_defer_taskrun_reason) != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, "doctor pass ktls_txrx src/daemon/config_boot.zig configCheckError allowed kTLS mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, "doctor fail ocsp_leaf_uri tls.cert_path missing leaf") != null);
    try std.testing.expect(std.mem.indexOf(u8, missing.lines, "doctor skipped s2s_handshake onyx_s2s_links_active missing gauge") != null);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const leaf_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
        \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
        \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
        \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
        \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
        \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
        \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
        \\Lw0=
        \\-----END CERTIFICATE-----
    ;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf.pem", .data = leaf_pem });
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/leaf.pem", .{tmp.sub_path});
    defer allocator.free(path);
    const config_text = try std.fmt.allocPrint(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\ncert_path=\"{s}\"\n[ocsp]\nenabled=true\n", .{path});
    defer allocator.free(config_text);
    var cert_loaded = try config_boot.loadFromText(allocator, config_text, .{ .port = 6680 }, .{});
    defer cert_loaded.deinit(allocator);
    const parsed = try report(allocator, std.testing.io, &cert_loaded, null, "onyx_s2s_tcp_active 1\nonyx_s2s_links_active 1\n", null);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.failed);
    try std.testing.expect(std.mem.indexOf(u8, parsed.lines, "doctor fail ocsp_leaf_uri aia_ocsp_url leaf has no AIA OCSP responder URL") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.lines, "doctor pass s2s_handshake") != null);
}

test "doctor structured checks redact endpoint and certificate paths" {
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromTextQuiet(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\ncert_path=\"private-secret-path\\u001b.pem\"\n[ocsp]\nenabled=true\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const Fetch = struct {
        fn fail(_: std.mem.Allocator, _: []const u8) ![]u8 {
            return error.ConnectionRefused;
        }
    };
    const result = try report(allocator, std.testing.io, &loaded, "http://private-secret-endpoint/secret", null, Fetch.fail);
    defer result.deinit(allocator);
    const json = try result.toJson(allocator);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("unknown", parsed.value.object.get("readiness").?.string);
    try std.testing.expectEqual(result.checks.len, parsed.value.object.get("checks").?.array.items.len);
    for ([_][]const u8{ result.lines, json }) |output| {
        try std.testing.expect(std.mem.indexOf(u8, output, "private-secret") == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
        try std.testing.expect(std.mem.indexOf(u8, output, "ConnectionRefused") != null);
    }
}

test "doctor json exports fixed local-config capabilities and bounded diagnostics" {
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromTextQuiet(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[mesh]\nconnect=[\"127.0.0.1:6900\"]\nrequire_secured=true\nrequire_signed_frames=true\n[cloak]\nsecret=\"private-capability-secret\"\naccount_cloak=true\nanon_epoch_secs=0\n[tls]\nenabled=true\n[ocsp]\nenabled=true\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const result = try report(allocator, std.testing.io, &loaded, null, null, null);
    defer result.deinit(allocator);
    const json = try result.toJson(allocator);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const caps = parsed.value.object.get("capabilities").?.object;
    try std.testing.expectEqualStrings("local-config", caps.get("source").?.string);
    try std.testing.expectEqual(false, caps.get("peer_live_verified").?.bool);
    const entries = caps.get("entries").?.array.items;
    try std.testing.expectEqual(capability_allowlist.len, entries.len);
    for (entries, capability_allowlist) |entry, name| {
        try std.testing.expectEqualStrings(name, entry.object.get("name").?.string);
    }
    var configured = std.StringHashMap(bool).init(allocator);
    defer configured.deinit();
    for (entries) |entry| try configured.put(entry.object.get("name").?.string, entry.object.get("configured").?.bool);
    try std.testing.expectEqual(true, configured.get("mesh_peers_configured").?);
    try std.testing.expectEqual(true, configured.get("mesh_require_secured").?);
    try std.testing.expectEqual(true, configured.get("mesh_require_signed_frames").?);
    try std.testing.expectEqual(true, configured.get("mesh_cloak_configured").?);
    try std.testing.expectEqual(true, configured.get("cloak_account").?);
    try std.testing.expectEqual(false, configured.get("cloak_anon_rotation").?);
    try std.testing.expectEqual(true, configured.get("tls_configured").?);
    try std.testing.expectEqual(true, configured.get("ocsp_configured").?);

    const diag = parsed.value.object.get("diagnostics").?.object;
    try std.testing.expectEqualStrings("doctor-checks", diag.get("source").?.string);
    try std.testing.expectEqual(@as(i64, @intCast(result.checks.len)), diag.get("total").?.integer);
    const counted = diag.get("passed").?.integer + diag.get("failed").?.integer + diag.get("skipped").?.integer + diag.get("other").?.integer;
    try std.testing.expectEqual(diag.get("total").?.integer, counted);
    const traces = diag.get("traces").?.array.items;
    try std.testing.expectEqual(@min(max_diagnostics_traces, result.checks.len), traces.len);
    try std.testing.expectEqual(result.checks.len > max_diagnostics_traces, diag.get("truncated").?.bool);
    for (traces, result.checks[0..traces.len]) |trace, check| {
        try std.testing.expectEqual(@as(usize, 2), trace.object.count());
        try std.testing.expectEqualStrings(check.id, trace.object.get("id").?.string);
        try std.testing.expectEqualStrings(check.status, trace.object.get("status").?.string);
    }
    try std.testing.expect(std.mem.indexOf(u8, json, "private-capability-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "127.0.0.1:6900") == null);
}

test "doctor json canary secrets never appear in capabilities or diagnostics" {
    const allocator = std.testing.allocator;
    const canary = "CANARY_SECRET_9f3d7a1b_DO_NOT_EXPORT";
    const config = try std.fmt.allocPrint(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[mesh]\nconnect=[\"{s}.example:6900\"]\nrequire_secured=true\n[cloak]\nsecret=\"{s}\"\nprevious_secret=\"{s}-prior\"\n[tls]\ncert_path=\"{s}.pem\"\nkey_path=\"{s}.key\"\n[ocsp]\nenabled=true\n", .{ canary, canary, canary, canary, canary });
    defer allocator.free(config);
    var loaded = try config_boot.loadFromTextQuiet(allocator, config, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const result = try report(allocator, std.testing.io, &loaded, null, "onyx_s2s_tcp_active 1\nonyx_s2s_links_active 1\n", null);
    defer result.deinit(allocator);
    const json = try result.toJson(allocator);
    defer allocator.free(json);
    for ([_][]const u8{ result.lines, json }) |output| {
        try std.testing.expect(std.mem.indexOf(u8, output, canary) == null);
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const caps_json = try std.json.Stringify.valueAlloc(allocator, parsed.value.object.get("capabilities").?, .{});
    defer allocator.free(caps_json);
    const diag_json = try std.json.Stringify.valueAlloc(allocator, parsed.value.object.get("diagnostics").?, .{});
    defer allocator.free(diag_json);
    try std.testing.expect(std.mem.indexOf(u8, caps_json, canary) == null);
    try std.testing.expect(std.mem.indexOf(u8, diag_json, canary) == null);
}

test "doctor gauges reject negative fractional and nonfinite counts and expose partitions" {
    for ([_][]const u8{ "-1", "0.5", "nan", "inf", "-inf", "junk" }) |value| {
        try std.testing.expectEqual(@as(?u64, null), unsignedCount(value));
    }
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromTextQuiet(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const result = try report(allocator, std.testing.io, &loaded, null, "onyx_s2s_tcp_active 1\nonyx_s2s_links_active 1\nonyx_mesh_partitioned 1\n", null);
    defer result.deinit(allocator);
    try std.testing.expect(result.failed);
    try std.testing.expect(std.mem.indexOf(u8, result.lines, "doctor fail mesh_partition") != null);
}

fn allocationReport(allocator: std.mem.Allocator) !void {
    var loaded = try config_boot.loadFromTextQuiet(std.testing.allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(std.testing.allocator);
    const result = try report(allocator, std.testing.io, &loaded, null, null, null);
    defer result.deinit(allocator);
    const json = try result.toJson(allocator);
    defer allocator.free(json);
}

test "doctor structured allocation failures release partial report and retry" {
    // A successful in-place remap depends on allocator page placement, making
    // the number of allocation calls differ between otherwise identical runs.
    // Force the allocating fallback so every ownership transition is swept.
    var relocating = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
    try std.testing.checkAllAllocationFailures(relocating.allocator(), allocationReport, .{});
}

test "doctor numeric observations retain only fixed names and reject ambiguous counts" {
    const observed = try observeMetrics(
        "onyx_s2s_tcp_active 2\n" ++
            "onyx_s2s_links_active 1\n" ++
            "onyx_mesh_partitioned 0\n" ++
            "onyx_connection_diagnostics_total{event=\"recv_eof\"} 17\n" ++
            "onyx_connection_diagnostics_total{event=\"closed\",account=\"PRIVATE_SECRET\"} 99\n" ++
            "arbitrary_PRIVATE_SECRET{host=\"PRIVATE_SECRET\"} 123\n",
    );
    try std.testing.expectEqual(@as(?u64, 2), observed.tcp_active);
    try std.testing.expectEqual(@as(?u64, 1), observed.established_links);
    try std.testing.expectEqual(@as(?u64, null), observed.secured_links);
    try std.testing.expectEqual(@as(?u64, 0), observed.partitioned);
    for (observed.connection_events) |event| {
        try std.testing.expectEqual(if (event.event == .recv_eof) @as(?u64, 17) else null, event.count);
    }
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, observed, .{});
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "PRIVATE_SECRET") == null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "account") == null);

    const duplicate = try observeMetrics(
        "onyx_s2s_tcp_active 1\nonyx_s2s_tcp_active 2\nonyx_s2s_tcp_active 3\n" ++
            "onyx_connection_diagnostics_total{event=\"recv_eof\"} 1\n" ++
            "onyx_connection_diagnostics_total{event=\"recv_eof\"} 2\n",
    );
    try std.testing.expectEqual(@as(?u64, null), duplicate.tcp_active);
    for (duplicate.connection_events) |event| try std.testing.expectEqual(@as(?u64, null), event.count);
    for ([_][]const u8{ "", "-1", "+1", "0.5", "1e3", "nan", "inf", "18446744073709551616" }) |value| {
        try std.testing.expectEqual(@as(?u64, null), unsignedCount(value));
    }
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), unsignedCount("18446744073709551615"));
}

test "doctor observations are absent offline and oversized metrics unwind owned report" {
    const allocator = std.testing.allocator;
    var loaded = try config_boot.loadFromTextQuiet(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const offline = try report(allocator, std.testing.io, &loaded, null, null, null);
    defer offline.deinit(allocator);
    try std.testing.expectEqual(@as(?Observations, null), offline.observations);
    const json = try offline.toJson(allocator);
    defer allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(@import("build_info").version, parsed.value.object.get("report_build_version").?.string);
    try std.testing.expect(parsed.value.object.get("observations").? == .null);
    const oversized = try allocator.alloc(u8, 1024 * 1024 + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');
    try std.testing.expectError(error.MetricsTooLarge, report(allocator, std.testing.io, &loaded, null, oversized, null));
}

test "doctor cloak comparison effective defaults mismatch roles and redaction" {
    const a = std.testing.allocator;
    const local_text = "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret = \"private-primary-example\"\nprevious_secret = \"private-prior-example\"\n";
    const equivalent = "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret = \"private-primary-example\"\nprevious_secret = \"private-prior-example\"\nsuffix = \"OnYx\"\nmode = \"hierarchical\"\naccount_cloak = false\nanon_epoch_secs = 1209600\n";
    const reversed = "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret = \"private-prior-example\"\nprevious_secret = \"private-primary-example\"\nsuffix = \"other\"\nmode = \"opaque\"\naccount_cloak = true\nanon_epoch_secs = 0\n";
    var local = try config_boot.loadFromTextQuiet(a, local_text, .{ .port = 6680 }, .{});
    defer local.deinit(a);
    var same = try config_boot.loadFromTextQuiet(a, equivalent, .{ .port = 6680 }, .{});
    defer same.deinit(a);
    var different = try config_boot.loadFromTextQuiet(a, reversed, .{ .port = 6680 }, .{});
    defer different.deinit(a);
    const good = try cloakComparison(a, &local, &same);
    defer good.deinit(a);
    try std.testing.expect(!good.failed);
    const bad = try cloakComparison(a, &local, &different);
    defer bad.deinit(a);
    try std.testing.expect(bad.failed);
    for ([_][]const u8{ "cloak_current", "cloak_previous", "cloak_suffix", "cloak_mode", "cloak_account", "cloak_cadence" }) |id| {
        var found = false;
        for (bad.checks) |check| if (std.mem.eql(u8, check.id, id) and std.mem.eql(u8, check.status, "fail")) {
            found = true;
        };
        try std.testing.expect(found);
    }
    for ([_]Result{ good, bad }) |result| {
        const json = try result.toJson(a);
        defer a.free(json);
        for ([_][]const u8{ result.lines, json }) |text| {
            try std.testing.expect(std.mem.indexOf(u8, text, "private-primary-example") == null);
            try std.testing.expect(std.mem.indexOf(u8, text, "private-prior-example") == null);
            try std.testing.expect(std.mem.indexOf(u8, text, "running peer not verified") != null);
        }
    }
    var absent = try config_boot.loadFromTextQuiet(a, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer absent.deinit(a);
    const unknown = try cloakComparison(a, &absent, &absent);
    defer unknown.deinit(a);
    try std.testing.expect(unknown.failed);
    try std.testing.expect(std.mem.indexOf(u8, unknown.lines, "cloak_previous cloak.previous_secret not configured on either side") != null);
    var without_previous = try config_boot.loadFromTextQuiet(a, "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret = \"private-primary-example\"\n", .{ .port = 6680 }, .{});
    defer without_previous.deinit(a);
    const incomplete = try cloakComparison(a, &local, &without_previous);
    defer incomplete.deinit(a);
    try std.testing.expect(incomplete.failed);
    try std.testing.expect(std.mem.indexOf(u8, incomplete.lines, "doctor fail cloak_previous") != null);
    const no_prior = try cloakComparison(a, &without_previous, &without_previous);
    defer no_prior.deinit(a);
    try std.testing.expect(!no_prior.failed);
    try std.testing.expect(std.mem.indexOf(u8, no_prior.lines, "not configured on either side") != null);
    const unavailable = try cloakComparisonUnavailable(a);
    defer unavailable.deinit(a);
    try std.testing.expect(unavailable.failed);
}

test "doctor anonymous cadence reports choices without failing or leaking secrets" {
    const a = std.testing.allocator;
    const cases = [_]struct { config: []const u8, detail: []const u8 }{
        .{ .config = "", .detail = "14 days (default cadence); 1209600 seconds" },
        .{ .config = "anon_epoch_secs=86400\n", .detail = "daily; review whether to retain it or use the 14-day default; 86400 seconds" },
        .{ .config = "anon_epoch_secs=0\n", .detail = "rotation disabled; 0 seconds" },
        .{ .config = "anon_epoch_secs=3600\naccount_cloak=true\n", .detail = "nondefault cadence; 3600 seconds" },
    };
    for (cases) |case| {
        const config = try std.fmt.allocPrint(a, "[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret=\"private-cadence-secret\"\n{s}", .{case.config});
        defer a.free(config);
        var loaded = try config_boot.loadFromTextQuiet(a, config, .{ .port = 6680 }, .{});
        defer loaded.deinit(a);
        const result = try report(a, std.testing.io, &loaded, null, null, null);
        defer result.deinit(a);
        try std.testing.expect(!result.failed);
        try std.testing.expect(std.mem.indexOf(u8, result.lines, case.detail) != null);
        const json = try result.toJson(a);
        defer a.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "private-cadence-secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, case.detail) != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "authenticated clients do not use anonymous rotation") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, if (std.mem.indexOf(u8, case.config, "account_cloak=true") != null) "account cloaks enabled" else "account cloaks disabled") != null);
        var found = false;
        for (result.checks) |check| {
            if (std.mem.eql(u8, check.id, "cloak_anon_cadence")) {
                try std.testing.expectEqualStrings("pass", check.status);
                found = true;
            }
        }
        try std.testing.expect(found);
    }
}

test "doctor observations distinguish established links from unknown transport security" {
    const observed = try observeMetrics("onyx_s2s_tcp_active 3\nonyx_s2s_links_active 2\nonyx_mesh_peers_up 2\nonyx_mesh_peers_total 3\nonyx_mesh_partitioned 1\nonyx_mesh_quorum 0\nonyx_mesh_components 2\n");
    try std.testing.expectEqual(@as(?u64, 2), observed.established_links);
    try std.testing.expectEqual(@as(?u64, null), observed.secured_links);
    try std.testing.expectEqual(@as(?u64, 3), observed.peers_total);
    try std.testing.expectEqual(@as(?u64, 0), observed.quorum);
    try std.testing.expectEqual(@as(?u64, 2), observed.components);
    const invalid = try observeMetrics("onyx_mesh_quorum 2\nonyx_mesh_partitioned 3\n");
    try std.testing.expectEqual(@as(?u64, null), invalid.quorum);
    try std.testing.expectEqual(@as(?u64, null), invalid.partitioned);
}
