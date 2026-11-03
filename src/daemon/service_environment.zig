// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed, read-only filesystem markers. These do not prove supervisor or daemon readiness.
const std = @import("std");
const builtin = @import("builtin");

pub const Observation = enum { present, absent, unknown };
pub const Manager = enum { openrc, systemd, unknown };
pub const Environment = struct {
    openrc_marker: Observation = .unknown,
    systemd_marker: Observation = .unknown,
    container_marker: Observation = .unknown,
    manager_hint: Manager = .unknown,
};

fn marker(io: std.Io, root: std.Io.Dir, path: []const u8, directory: bool) Observation {
    const stat = root.statFile(io, path, .{ .follow_symlinks = false }) catch |err| return switch (err) {
        error.FileNotFound => .absent,
        else => .unknown,
    };
    if (directory and stat.kind != .directory) return .unknown;
    if (!directory and stat.kind != .file) return .unknown;
    return .present;
}
fn either(a: Observation, b: Observation) Observation {
    if (a == .present or b == .present) return .present;
    if (a == .absent and b == .absent) return .absent;
    return .unknown;
}
/// Root-relative entry point also permits private filesystem fixtures.
pub fn detectAt(io: std.Io, root: std.Io.Dir) Environment {
    const openrc = marker(io, root, "run/openrc", true);
    const systemd = marker(io, root, "run/systemd/system", true);
    return .{
        .openrc_marker = openrc,
        .systemd_marker = systemd,
        .container_marker = either(marker(io, root, ".dockerenv", false), marker(io, root, "run/.containerenv", false)),
        .manager_hint = if (openrc == .present and systemd == .absent) .openrc else if (systemd == .present and openrc == .absent) .systemd else .unknown,
    };
}
pub fn detect(io: std.Io) Environment {
    if (comptime builtin.os.tag != .linux) return .{};
    const root = std.Io.Dir.openDirAbsolute(io, "/", .{}) catch return .{};
    defer root.close(io);
    return detectAt(io, root);
}

test "service environment uses bounded markers and reports ambiguous evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var result = detectAt(io, tmp.dir);
    try std.testing.expectEqual(Manager.unknown, result.manager_hint);
    try std.testing.expectEqual(Observation.absent, result.container_marker);
    try tmp.dir.createDirPath(io, "run/openrc");
    result = detectAt(io, tmp.dir);
    try std.testing.expectEqual(Manager.openrc, result.manager_hint);
    try tmp.dir.createDirPath(io, "run/systemd/system");
    result = detectAt(io, tmp.dir);
    try std.testing.expectEqual(Manager.unknown, result.manager_hint);
    const file = try tmp.dir.createFile(io, ".dockerenv", .{});
    file.close(io);
    try std.testing.expectEqual(Observation.present, detectAt(io, tmp.dir).container_marker);
    try std.testing.expectEqual(Observation.unknown, either(.absent, .unknown));
    var other = std.testing.tmpDir(.{});
    defer other.cleanup();
    try other.dir.createDirPath(io, "run/systemd/system");
    try std.testing.expectEqual(Manager.systemd, detectAt(io, other.dir).manager_hint);
    const wrong_type = try other.dir.createFile(io, "run/openrc", .{});
    wrong_type.close(io);
    const uncertain = detectAt(io, other.dir);
    try std.testing.expectEqual(Observation.unknown, uncertain.openrc_marker);
    try std.testing.expectEqual(Manager.unknown, uncertain.manager_hint);
}

/// Template facts only: these are shipped defaults, not observed host state.
/// Candidate paths and credentials are intentionally excluded.
pub const Service = enum { openrc, systemd, foreground };
pub const Template = struct {
    source: []const u8,
    executable: []const u8,
    config: []const u8,
    identity: []const u8,
    working_directory: []const u8,
    preflight_argv: []const []const u8,
    preflight_policy: []const u8,
    start_argv: []const []const u8,
    restart: []const u8,
    logging: []const u8,
};
pub const Plan = struct {
    selected: Service,
    selection_basis: []const u8,
    template: Template,
    container_template: Template,
    host_paths: []const u8 = "unknown; template paths have not been inspected",
    runtime_identity_access: []const u8 = "unknown; runtime user and file access have not been checked",
    manager_status: []const u8 = "unknown; markers do not prove a supervisor is running",
    daemon_readiness: []const u8 = "unknown; no daemon or client observation",
    network_reachability: []const u8 = "unknown; no network probes",
    resource_ceilings: []const u8 = "unknown; no host CPU, memory, or bandwidth ceiling established",
    validation: []const u8 = "typed configuration checks are separate; run --check-config and doctor as the intended runtime user",
};

const openrc_template = Template{
    .source = "etc/openrc/onyx-server and onyx-server.confd (shipped defaults)",
    .executable = "/usr/bin/onyx-server",
    .config = "/etc/onyx-server/onyx-server.toml",
    .identity = "onyx-server:onyx-server",
    .working_directory = "/var/lib/onyx-server",
    .preflight_argv = &.{ "/usr/bin/onyx-server", "--check-config", "/etc/onyx-server/onyx-server.toml" },
    .start_argv = &.{ "/usr/bin/onyx-server", "/etc/onyx-server/onyx-server.toml" },
    .preflight_policy = "start and Helix reload validate as command_user with its primary/supplementary groups in the working directory; requires util-linux setpriv",
    .restart = "supervise-daemon respawn: delay 5 seconds, maximum 3 per 60 seconds",
    .logging = "stdout/stderr use logger daemon.info/daemon.err; configurable in conf.d",
};
const systemd_template = Template{
    .source = "etc/systemd/onyx-server.service (shipped defaults)",
    .executable = "/usr/local/bin/onyx-server",
    .config = "/etc/onyx-server/onyx-server.toml",
    .identity = "onyx-server:onyx-server",
    .working_directory = "/var/lib/onyx-server",
    .preflight_argv = &.{ "/usr/local/bin/onyx-server", "--check-config", "/etc/onyx-server/onyx-server.toml" },
    .start_argv = &.{ "/usr/local/bin/onyx-server", "/etc/onyx-server/onyx-server.toml" },
    .preflight_policy = "start and Helix reload validate with the runtime identity, working directory and sandbox",
    .restart = "on failure after 2 seconds, maximum 5 starts per 60 seconds; validated SIGUSR2 upgrade request is asynchronous",
    .logging = "stdout/stderr use journal identifier onyx-server; actual retention is host policy",
};
const foreground_template = Template{
    .source = "foreground invocation; choose executable and config explicitly",
    .executable = "<reviewed-executable>",
    .config = "<reviewed-config>",
    .identity = "unknown; chosen by operator",
    .working_directory = "unknown; chosen by operator",
    .preflight_argv = &.{ "<reviewed-executable>", "--check-config", "<reviewed-config>" },
    .start_argv = &.{ "<reviewed-executable>", "<reviewed-config>" },
    .preflight_policy = "recommended explicit preflight; not automatic",
    .restart = "unknown; controlled by operator or external supervisor",
    .logging = "inherited stdout/stderr; destination unknown",
};
const container_template = Template{
    .source = "packaging/Dockerfile (shipped defaults; not detected installation)",
    .executable = "/usr/local/bin/onyx-server",
    .config = "/data/onyx-server.toml",
    .identity = "10001:10001",
    .working_directory = "/data",
    .preflight_argv = &.{ "/usr/local/bin/onyx-server", "--check-config", "/data/onyx-server.toml" },
    .start_argv = &.{ "/usr/local/bin/onyx-server", "/data/onyx-server.toml" },
    .preflight_policy = "recommended explicit preflight; Dockerfile does not invoke it",
    .restart = "unknown; container runtime policy is external",
    .logging = "inherited stdout/stderr; runtime logging configuration unknown",
};

/// null selects from conservative filesystem hints; explicit selection wins.
pub fn servicePlan(environment: Environment, requested: ?Service) Plan {
    const selected = requested orelse switch (environment.manager_hint) {
        .openrc => Service.openrc,
        .systemd => Service.systemd,
        .unknown => Service.foreground,
    };
    return .{
        .selected = selected,
        .selection_basis = if (requested != null) "explicit selection" else "filesystem marker hint only; unknown or ambiguous falls back to foreground",
        .template = switch (selected) {
            .openrc => openrc_template,
            .systemd => systemd_template,
            .foreground => foreground_template,
        },
        .container_template = container_template,
    };
}

test "service plan uses template facts without asserting observed readiness" {
    for ([_]struct { env: Environment, selected: Service, executable: []const u8 }{
        .{ .env = .{ .manager_hint = .openrc }, .selected = .openrc, .executable = "/usr/bin/onyx-server" },
        .{ .env = .{ .manager_hint = .systemd }, .selected = .systemd, .executable = "/usr/local/bin/onyx-server" },
        .{ .env = .{}, .selected = .foreground, .executable = "<reviewed-executable>" },
    }) |case| {
        const plan = servicePlan(case.env, null);
        try std.testing.expectEqual(case.selected, plan.selected);
        try std.testing.expectEqualStrings(case.executable, plan.template.executable);
        try std.testing.expectEqualStrings("--check-config", plan.template.preflight_argv[1]);
        try std.testing.expectEqualStrings(plan.template.config, plan.template.start_argv[1]);
        try std.testing.expect(std.mem.startsWith(u8, plan.daemon_readiness, "unknown"));
        try std.testing.expect(std.mem.startsWith(u8, plan.manager_status, "unknown"));
        try std.testing.expectEqualStrings("10001:10001", plan.container_template.identity);
    }
    try std.testing.expectEqual(Service.foreground, servicePlan(.{ .manager_hint = .openrc }, .foreground).selected);
}
