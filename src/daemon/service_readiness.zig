// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure service readiness verdict shared by the setup wizard and doctor.
//!
//! The verdict is a function of evidence only (configuration preflight plus an
//! optional metrics gauge sample with explicit provenance). The supervisor mode never
//! changes the verdict: OpenRC, systemd, container and foreground runs that
//! present identical evidence receive an identical state and reason. Mode only
//! selects the fixed supervisor-evidence sentence, which states what the
//! supervisor itself does and does not prove. No I/O, allocation, paths or
//! secrets are involved.
//!
//! `ready` means the configuration preflight passed and a complete, internally
//! consistent gauge sample, fetched live from the local endpoint during this
//! same invocation, shows no stuck handshake, partition, lost quorum or absent
//! peer. A sample of unverified provenance (offline fixture body, saved file,
//! non-local URL) can never reach `ready`: it is capped at `unknown`, because
//! such a body is equally consistent with a stopped or crash-looping daemon or
//! another node. `ready` still does not prove link security or real client
//! participation; those remain separate checks.
const std = @import("std");
const service_environment = @import("service_environment.zig");

pub const Mode = enum { openrc, systemd, container, foreground };

/// One precedence rule, shared with `service_environment.servicePlan`:
/// an explicit request wins; otherwise a unique manager hint (OpenRC or
/// systemd) wins, so a systemd-in-container or OpenRC-in-container host names
/// the same supervisor in the readiness mode and in the service plan; only
/// when no unique manager is hinted does a present container marker select
/// container. Unknown or ambiguous evidence falls back to foreground. The
/// requested `service_environment.Service` has no container variant, so
/// container mode is detected, never requested; its service plan is the
/// foreground plan run under the container's own supervisor.
pub fn modeFor(env: service_environment.Environment, requested: ?service_environment.Service) Mode {
    if (requested) |service| return switch (service) {
        .openrc => .openrc,
        .systemd => .systemd,
        .foreground => .foreground,
    };
    return switch (env.manager_hint) {
        .openrc => .openrc,
        .systemd => .systemd,
        .unknown => if (env.container_marker == .present) .container else .foreground,
    };
}

pub const ConfigPreflight = enum { not_run, pass, fail };
/// Provenance of the gauge sample. The hub must map to `live_local_fetch` only
/// when the sample came from a successful fetch of the local metrics endpoint
/// performed in this invocation; every other body (offline fixture, file, remote
/// URL) is `unverified`.
pub const MetricsSource = enum { not_configured, unreachable_source, unverified, live_local_fetch };

/// Field names match doctor.Observations so the hub can copy them directly.
pub const Gauges = struct {
    tcp_active: ?u64 = null,
    established_links: ?u64 = null,
    peers_up: ?u64 = null,
    peers_total: ?u64 = null,
    quorum: ?u64 = null,
    partitioned: ?u64 = null,
};

pub const Evidence = struct {
    config_preflight: ConfigPreflight = .not_run,
    metrics: MetricsSource = .not_configured,
    /// Consulted only when `metrics == .live_local_fetch`.
    gauges: Gauges = .{},
};

pub const State = enum { ready, degraded, not_ready, unknown };

pub const Reason = enum {
    healthy,
    config_preflight_failed,
    config_not_checked,
    metrics_not_configured,
    metrics_unreachable,
    metrics_unverified,
    metrics_incomplete,
    handshake_stuck,
    mesh_partitioned,
    mesh_quorum_lost,
    mesh_peers_down,
};

pub const Verdict = struct {
    state: State,
    reason: Reason,

    pub fn detail(self: Verdict) []const u8 {
        return switch (self.reason) {
            .healthy => "configuration preflight passed and complete gauges show no stuck handshake, partition, lost quorum or absent peer",
            .config_preflight_failed => "configuration preflight failed",
            .config_not_checked => "unknown; configuration preflight was not run",
            .metrics_not_configured => "unknown; no metrics source was configured",
            .metrics_unreachable => "unknown; the metrics source could not be read",
            .metrics_unverified => "unknown; the metrics sample is not a live fetch of the local endpoint and cannot prove readiness",
            .metrics_incomplete => "unknown; required gauges are missing, invalid or inconsistent",
            .handshake_stuck => "TCP active but no established S2S link",
            .mesh_partitioned => "node reports a mesh partition",
            .mesh_quorum_lost => "node reports lost mesh quorum",
            .mesh_peers_down => "fewer mesh peers are established than are tracked",
        };
    }
};

fn isFlag(value: ?u64) bool {
    return if (value) |v| v <= 1 else false;
}

/// Required gauges present, boolean gauges in {0,1}, and peers_up <= peers_total.
fn gaugesComplete(g: Gauges) bool {
    if (g.tcp_active == null or g.established_links == null) return false;
    if (!isFlag(g.partitioned)) return false;
    if (g.quorum != null and !isFlag(g.quorum)) return false;
    if (g.peers_up != null and g.peers_total != null and g.peers_up.? > g.peers_total.?) return false;
    // A lone peer count cannot be reconciled.
    if ((g.peers_up == null) != (g.peers_total == null)) return false;
    return true;
}

/// Mode-independent by construction.
pub fn verdict(evidence: Evidence) Verdict {
    switch (evidence.config_preflight) {
        .fail => return .{ .state = .not_ready, .reason = .config_preflight_failed },
        .not_run => return .{ .state = .unknown, .reason = .config_not_checked },
        .pass => {},
    }
    switch (evidence.metrics) {
        .not_configured => return .{ .state = .unknown, .reason = .metrics_not_configured },
        .unreachable_source => return .{ .state = .unknown, .reason = .metrics_unreachable },
        .unverified => return .{ .state = .unknown, .reason = .metrics_unverified },
        .live_local_fetch => {},
    }
    const g = evidence.gauges;
    if (!gaugesComplete(g)) return .{ .state = .unknown, .reason = .metrics_incomplete };
    if (g.tcp_active.? > 0 and g.established_links.? == 0) return .{ .state = .not_ready, .reason = .handshake_stuck };
    if (g.partitioned.? == 1) return .{ .state = .degraded, .reason = .mesh_partitioned };
    if (g.quorum) |q| if (q == 0) return .{ .state = .degraded, .reason = .mesh_quorum_lost };
    if (g.peers_up) |up| if (up < g.peers_total.?) return .{ .state = .degraded, .reason = .mesh_peers_down };
    return .{ .state = .ready, .reason = .healthy };
}

/// Fixed text: what the supervisor itself proves. Contains no paths or secrets.
/// Statements about units and images describe the SHIPPED templates only
/// (etc/init.d, etc/systemd and packaging/Dockerfile), never the host's
/// installed unit or running image, which an operator may have overridden.
pub fn supervisorEvidence(mode: Mode) []const u8 {
    return switch (mode) {
        .openrc => "shipped template: OpenRC supervise-daemon only respawns an exited process; a started service does not prove daemon readiness",
        .systemd => "shipped template: the unit is Type=exec and sends no sd_notify readiness; host overrides are not inspected; an active unit does not prove daemon readiness",
        .container => "shipped template: the image defines no health check and runtime policy is external; host images are not inspected; a running container does not prove daemon readiness",
        .foreground => "no supervisor; a running foreground process does not prove daemon readiness",
    };
}

pub const Report = struct {
    mode: Mode,
    verdict: Verdict,
    supervisor_evidence: []const u8,
};

pub fn assess(mode: Mode, evidence: Evidence) Report {
    return .{ .mode = mode, .verdict = verdict(evidence), .supervisor_evidence = supervisorEvidence(mode) };
}

const test_values = [_]?u64{ null, 0, 1, 2 };

fn healthy() Gauges {
    return .{ .tcp_active = 1, .established_links = 1, .peers_up = 1, .peers_total = 1, .quorum = 1, .partitioned = 0 };
}

test "service readiness: identical evidence yields identical verdict across all modes" {
    var checked: usize = 0;
    var ready_seen: usize = 0;
    for (std.meta.tags(ConfigPreflight)) |config| for (std.meta.tags(MetricsSource)) |source| {
        for (test_values) |tcp| for (test_values) |links| for (test_values) |up| for (test_values) |total| for (test_values) |quorum| for (test_values) |partitioned| {
            const evidence: Evidence = .{ .config_preflight = config, .metrics = source, .gauges = .{
                .tcp_active = tcp,
                .established_links = links,
                .peers_up = up,
                .peers_total = total,
                .quorum = quorum,
                .partitioned = partitioned,
            } };
            const first = assess(.openrc, evidence);
            inline for (.{ Mode.systemd, Mode.container, Mode.foreground }) |mode| {
                const other = assess(mode, evidence);
                try std.testing.expectEqual(first.verdict, other.verdict);
            }
            if (first.verdict.state == .ready) {
                ready_seen += 1;
                try std.testing.expectEqual(ConfigPreflight.pass, config);
                try std.testing.expectEqual(MetricsSource.live_local_fetch, source);
                try std.testing.expect(gaugesComplete(evidence.gauges));
                try std.testing.expect(!(tcp.? > 0 and links.? == 0));
                try std.testing.expectEqual(@as(u64, 0), partitioned.?);
            }
            checked += 1;
        };
    };
    try std.testing.expectEqual(@as(usize, 3 * 4 * 4096), checked);
    try std.testing.expect(ready_seen != 0);
}

test "service readiness: config preflight fail is not_ready and not_run is unknown in every mode" {
    for (std.meta.tags(Mode)) |mode| {
        const failed = assess(mode, .{ .config_preflight = .fail, .metrics = .live_local_fetch, .gauges = healthy() });
        try std.testing.expectEqual(State.not_ready, failed.verdict.state);
        try std.testing.expectEqual(Reason.config_preflight_failed, failed.verdict.reason);
        const failed_blind = assess(mode, .{ .config_preflight = .fail });
        try std.testing.expectEqual(State.not_ready, failed_blind.verdict.state);
        const unrun = assess(mode, .{ .config_preflight = .not_run, .metrics = .live_local_fetch, .gauges = healthy() });
        try std.testing.expectEqual(State.unknown, unrun.verdict.state);
        try std.testing.expectEqual(Reason.config_not_checked, unrun.verdict.reason);
    }
}

test "service readiness: absent or unreachable metrics are unknown with distinct reasons and never ready" {
    for (std.meta.tags(Mode)) |mode| {
        // Gauges supplied alongside a non-live source must be ignored.
        const none = assess(mode, .{ .config_preflight = .pass, .metrics = .not_configured, .gauges = healthy() });
        const down = assess(mode, .{ .config_preflight = .pass, .metrics = .unreachable_source, .gauges = healthy() });
        try std.testing.expectEqual(State.unknown, none.verdict.state);
        try std.testing.expectEqual(State.unknown, down.verdict.state);
        try std.testing.expectEqual(Reason.metrics_not_configured, none.verdict.reason);
        try std.testing.expectEqual(Reason.metrics_unreachable, down.verdict.reason);
        try std.testing.expect(!std.mem.eql(u8, none.verdict.detail(), down.verdict.detail()));
    }
}

test "service readiness: unverified metrics provenance is capped at unknown in every mode" {
    for (std.meta.tags(Mode)) |mode| {
        // Even a perfectly healthy offline or non-local body must not read as ready.
        const report = assess(mode, .{ .config_preflight = .pass, .metrics = .unverified, .gauges = healthy() });
        try std.testing.expectEqual(State.unknown, report.verdict.state);
        try std.testing.expectEqual(Reason.metrics_unverified, report.verdict.reason);
        // Unverified bodies never launder a failed preflight into anything better.
        const failed = assess(mode, .{ .config_preflight = .fail, .metrics = .unverified, .gauges = healthy() });
        try std.testing.expectEqual(State.not_ready, failed.verdict.state);
        // Unverified is distinguishable from other unknown reasons.
        const live = assess(mode, .{ .config_preflight = .pass, .metrics = .live_local_fetch, .gauges = healthy() });
        try std.testing.expectEqual(State.ready, live.verdict.state);
        try std.testing.expect(!std.mem.eql(u8, report.verdict.detail(), live.verdict.detail()));
    }
    // Unhealthy gauges in an unverified body are also not trusted to assert not_ready/degraded.
    var bad = healthy();
    bad.partitioned = 1;
    const v = verdict(.{ .config_preflight = .pass, .metrics = .unverified, .gauges = bad });
    try std.testing.expectEqual(State.unknown, v.state);
}

test "service readiness: incomplete hostile or inconsistent gauges fail closed to unknown" {
    const base: Evidence = .{ .config_preflight = .pass, .metrics = .live_local_fetch, .gauges = healthy() };
    var cases: [7]Evidence = @splat(base);
    cases[0].gauges.tcp_active = null;
    cases[1].gauges.established_links = null;
    cases[2].gauges.partitioned = null;
    cases[3].gauges.partitioned = 2;
    cases[4].gauges.quorum = 7;
    cases[5].gauges.peers_up = 3; // exceeds peers_total
    cases[6].gauges.peers_total = null; // lone peer count
    for (cases) |evidence| {
        const v = verdict(evidence);
        try std.testing.expectEqual(State.unknown, v.state);
        try std.testing.expectEqual(Reason.metrics_incomplete, v.reason);
    }
    // Quorum and peer counts are optional only when both peer counts are absent.
    var no_mesh = base;
    no_mesh.gauges = .{ .tcp_active = 0, .established_links = 0, .partitioned = 0 };
    try std.testing.expectEqual(State.ready, verdict(no_mesh).state);
}

test "service readiness: partition stuck handshake lost quorum and absent peer are consistent in every mode" {
    const Case = struct { mutate: *const fn (*Gauges) void, state: State, reason: Reason };
    const cases = [_]Case{
        .{ .mutate = struct {
            fn f(g: *Gauges) void {
                g.partitioned = 1;
            }
        }.f, .state = .degraded, .reason = .mesh_partitioned },
        .{ .mutate = struct {
            fn f(g: *Gauges) void {
                g.tcp_active = 2;
                g.established_links = 0;
            }
        }.f, .state = .not_ready, .reason = .handshake_stuck },
        .{ .mutate = struct {
            fn f(g: *Gauges) void {
                g.quorum = 0;
            }
        }.f, .state = .degraded, .reason = .mesh_quorum_lost },
        .{ .mutate = struct {
            fn f(g: *Gauges) void {
                g.peers_up = 0;
            }
        }.f, .state = .degraded, .reason = .mesh_peers_down },
        // Stuck handshake outranks a simultaneous partition.
        .{ .mutate = struct {
            fn f(g: *Gauges) void {
                g.tcp_active = 1;
                g.established_links = 0;
                g.partitioned = 1;
            }
        }.f, .state = .not_ready, .reason = .handshake_stuck },
    };
    for (std.meta.tags(Mode)) |mode| for (cases) |case| {
        var gauges = healthy();
        case.mutate(&gauges);
        const report = assess(mode, .{ .config_preflight = .pass, .metrics = .live_local_fetch, .gauges = gauges });
        try std.testing.expectEqual(case.state, report.verdict.state);
        try std.testing.expectEqual(case.reason, report.verdict.reason);
    };
}

test "service readiness: complete healthy gauges are ready in every mode" {
    for (std.meta.tags(Mode)) |mode| {
        const report = assess(mode, .{ .config_preflight = .pass, .metrics = .live_local_fetch, .gauges = healthy() });
        try std.testing.expectEqual(State.ready, report.verdict.state);
        try std.testing.expectEqual(Reason.healthy, report.verdict.reason);
    }
}

test "service readiness: modeFor precedence is request, unique manager, container marker, foreground" {
    try std.testing.expectEqual(Mode.container, modeFor(.{ .container_marker = .present }, null));
    // A unique manager hint outranks the container marker (systemd or OpenRC in a container).
    try std.testing.expectEqual(Mode.systemd, modeFor(.{ .container_marker = .present, .manager_hint = .systemd }, null));
    try std.testing.expectEqual(Mode.openrc, modeFor(.{ .container_marker = .present, .manager_hint = .openrc }, null));
    try std.testing.expectEqual(Mode.systemd, modeFor(.{ .container_marker = .present }, .systemd));
    try std.testing.expectEqual(Mode.openrc, modeFor(.{ .container_marker = .present }, .openrc));
    try std.testing.expectEqual(Mode.foreground, modeFor(.{ .container_marker = .present, .manager_hint = .openrc }, .foreground));
    try std.testing.expectEqual(Mode.openrc, modeFor(.{ .manager_hint = .openrc }, null));
    try std.testing.expectEqual(Mode.systemd, modeFor(.{ .manager_hint = .systemd, .container_marker = .absent }, null));
    // Ambiguous or unknown evidence is foreground, never a guessed supervisor.
    try std.testing.expectEqual(Mode.foreground, modeFor(.{}, null));
    try std.testing.expectEqual(Mode.foreground, modeFor(.{ .openrc_marker = .present, .systemd_marker = .present }, null));
    try std.testing.expectEqual(Mode.foreground, modeFor(.{ .container_marker = .unknown }, null));
    // One report never names two supervisors: for every environment and
    // request, a manager mode equals the service plan's selection, and a
    // container mode pairs only with the foreground plan.
    const observations = [_]service_environment.Observation{ .unknown, .absent, .present };
    const managers = [_]service_environment.Manager{ .openrc, .systemd, .unknown };
    const requests = [_]?service_environment.Service{ null, .openrc, .systemd, .foreground };
    for (observations) |container| for (managers) |hint| for (requests) |requested| {
        const env: service_environment.Environment = .{ .container_marker = container, .manager_hint = hint };
        const plan = service_environment.servicePlan(env, requested);
        switch (modeFor(env, requested)) {
            .container => try std.testing.expectEqual(service_environment.Service.foreground, plan.selected),
            else => |mode| try std.testing.expectEqualStrings(@tagName(plan.selected), @tagName(mode)),
        }
    };
}

test "service readiness: supervisor evidence differs per mode without paths or secrets" {
    const modes = std.meta.tags(Mode);
    for (modes, 0..) |a, i| {
        const text = supervisorEvidence(a);
        try std.testing.expect(text.len != 0 and text.len < 200);
        try std.testing.expect(std.mem.indexOfScalar(u8, text, '/') == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "password") == null);
        for (modes[i + 1 ..]) |b| try std.testing.expect(!std.mem.eql(u8, text, supervisorEvidence(b)));
    }
    const systemd = supervisorEvidence(.systemd);
    try std.testing.expect(std.mem.indexOf(u8, systemd, "no sd_notify") != null);
    for (modes) |mode| try std.testing.expect(std.mem.indexOf(u8, supervisorEvidence(mode), "does not prove daemon readiness") != null);
    // Unit and image claims are qualified as shipped-template facts, never host facts.
    for ([_]Mode{ .openrc, .systemd, .container }) |mode| {
        try std.testing.expect(std.mem.startsWith(u8, supervisorEvidence(mode), "shipped template: "));
    }
    try std.testing.expect(std.mem.indexOf(u8, supervisorEvidence(.foreground), "shipped") == null);
}

test "service readiness: every verdict detail is fixed text without paths" {
    for (std.meta.tags(Reason)) |reason| {
        const text = (Verdict{ .state = .unknown, .reason = reason }).detail();
        try std.testing.expect(text.len != 0);
        try std.testing.expect(std.mem.indexOfScalar(u8, text, '/') == null);
    }
}
