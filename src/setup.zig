// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installation planning and explicit new candidate/checkpoint publication.
//! No service control, secret generation, subprocesses, or network access.
const std = @import("std");

pub const workflow = @import("setup_workflow.zig");
pub const media_assessment = @import("setup_media_assessment.zig");
pub const network_assessment = @import("setup_network_assessment.zig");
pub const usage =
    "usage: onyx-server setup --maintenance --interactive <config> --pid <pid> --target <binary> --backup <dir> --restore-into <new-private-dir> [--linear]\n" ++
    "           Existing local Linux foreground runtime, same UID; use absolute paths. Explicit reviewed apply only; no OpenRC/systemd maintenance adapter.\n" ++
    "       onyx-server setup <config> [--service auto|openrc|systemd|foreground] [--json]\n" ++
    "       onyx-server setup --interactive [--linear]  (choose a new profile or existing-network review)\n" ++
    "           --linear uses plain sequential text for screen-reader workflows; interactive setup needs a terminal.\n" ++
    "           For redirected output use setup --new --json or setup <config> --json.\n" ++
    "       onyx-server setup --new [--profile private|community|media] [--interactive]\n" ++
    "           [--service auto|openrc|systemd|foreground] [--export <new.toml> | --draft <new.json> | --bundle <new-dir>] [--json]\n" ++
    "           [--hostname <dns-name>] [--listen <ip>] [--irc-port <port>] [--node-id <id>]\n" ++
    "           [--tls] [--tls-port <port>] [--max-clients <count>] [--media-port <port>]\n" ++
    "           [--bootstrap-account <name>] [--oper-privileges none|<comma-separated names>]\n" ++
    "           [--password-file <owner-private-file> | --password-fd <inherited-nonterminal-fd>]\n" ++
    "           Headless --bundle requires --json --review-stdin for prepublication review.\n" ++
    "       onyx-server setup --resume <private-draft.json> [--interactive] [--export <new.toml> | --draft <new.json> | --bundle <new-dir>] [--json]\n" ++
    "           [--password-file <owner-private-file> | --password-fd <inherited-nonterminal-fd>]\n";
pub const Service = workflow.Service;
pub const Options = struct {
    config: []const u8 = "",
    maintenance: bool = false,
    maintenance_pid: ?i32 = null,
    maintenance_target: ?[]const u8 = null,
    maintenance_backup: ?[]const u8 = null,
    maintenance_restore: ?[]const u8 = null,
    service: Service = .auto,
    json: bool = false,
    new_install: bool = false,
    profile: workflow.Profile = .existing,
    interactive: bool = false,
    linear: bool = false,
    review_stdin: bool = false,
    existing_allowed: bool = false,
    resume_path: ?[]const u8 = null,
    draft: ?[]const u8 = null,
    export_path: ?[]const u8 = null,
    bundle_path: ?[]const u8 = null,
    settings: workflow.Settings = .{},
    password_file: ?[]const u8 = null,
    password_fd: ?i32 = null,
};

pub fn parse(args: []const []const u8) error{InvalidArguments}!Options {
    var opts: Options = .{};
    var seen_service = false;
    var seen_profile = false;
    var settings_mask: u16 = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const setting_flags = [_][]const u8{ "--hostname", "--listen", "--irc-port", "--node-id", "--tls-port", "--max-clients", "--media-port", "--bootstrap-account", "--oper-privileges" };
        var matched_setting = false;
        for (setting_flags, 0..) |flag, bit| {
            if (!std.mem.eql(u8, arg, flag)) continue;
            const mask = @as(u16, 1) << @intCast(bit);
            if (settings_mask & mask != 0) return error.InvalidArguments;
            settings_mask |= mask;
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            opts.settings.assign(if (bit == 7) "account" else if (bit == 8) "privileges" else flag[2..], args[i]) catch return error.InvalidArguments;
            matched_setting = true;
            break;
        }
        if (matched_setting) continue;
        if (std.mem.eql(u8, arg, "--maintenance") and !opts.maintenance) {
            opts.maintenance = true;
        } else if (std.mem.eql(u8, arg, "--pid") and opts.maintenance_pid == null) {
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            opts.maintenance_pid = std.fmt.parseInt(i32, args[i], 10) catch return error.InvalidArguments;
            if (opts.maintenance_pid.? <= 1) return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--target") or std.mem.eql(u8, arg, "--backup") or std.mem.eql(u8, arg, "--restore-into")) {
            const value = if (std.mem.eql(u8, arg, "--target")) &opts.maintenance_target else if (std.mem.eql(u8, arg, "--backup")) &opts.maintenance_backup else &opts.maintenance_restore;
            i += 1;
            if (i == args.len or args[i].len == 0 or args[i][0] == '-' or value.* != null) return error.InvalidArguments;
            value.* = args[i];
        } else if (std.mem.eql(u8, arg, "--tls") and settings_mask & 512 == 0) {
            opts.settings.tls_enabled = true;
            settings_mask |= 512;
        } else if (std.mem.eql(u8, arg, "--password-file") and opts.password_file == null) {
            i += 1;
            if (i == args.len or args[i].len == 0 or args[i][0] == '-') return error.InvalidArguments;
            opts.password_file = args[i];
        } else if (std.mem.eql(u8, arg, "--password-fd") and opts.password_fd == null) {
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            opts.password_fd = std.fmt.parseInt(i32, args[i], 10) catch return error.InvalidArguments;
            if (opts.password_fd.? < 3) return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--json") and !opts.json) {
            opts.json = true;
        } else if (std.mem.eql(u8, arg, "--review-stdin") and !opts.review_stdin) {
            opts.review_stdin = true;
        } else if (std.mem.eql(u8, arg, "--new") and !opts.new_install) {
            opts.new_install = true;
        } else if (std.mem.eql(u8, arg, "--interactive") and !opts.interactive) {
            opts.interactive = true;
        } else if (std.mem.eql(u8, arg, "--linear") and !opts.linear) {
            opts.linear = true;
        } else if (std.mem.eql(u8, arg, "--service") and !seen_service) {
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            opts.service = std.meta.stringToEnum(Service, args[i]) orelse return error.InvalidArguments;
            seen_service = true;
        } else if (std.mem.eql(u8, arg, "--profile") and !seen_profile) {
            i += 1;
            if (i == args.len) return error.InvalidArguments;
            opts.profile = std.meta.stringToEnum(workflow.Profile, args[i]) orelse return error.InvalidArguments;
            if (opts.profile == .existing) return error.InvalidArguments;
            seen_profile = true;
        } else if (std.mem.eql(u8, arg, "--resume") or std.mem.eql(u8, arg, "--draft") or std.mem.eql(u8, arg, "--export") or std.mem.eql(u8, arg, "--bundle")) {
            i += 1;
            if (i == args.len or args[i].len == 0 or args[i][0] == '-') return error.InvalidArguments;
            const target = if (std.mem.eql(u8, arg, "--resume")) &opts.resume_path else if (std.mem.eql(u8, arg, "--draft")) &opts.draft else if (std.mem.eql(u8, arg, "--export")) &opts.export_path else &opts.bundle_path;
            if (target.* != null) return error.InvalidArguments;
            target.* = args[i];
        } else if (arg.len > 0 and arg[0] != '-' and opts.config.len == 0) {
            opts.config = arg;
        } else return error.InvalidArguments;
    }
    if (opts.maintenance) {
        if (!opts.interactive or opts.config.len == 0 or opts.maintenance_pid == null or opts.maintenance_target == null or
            opts.maintenance_backup == null or opts.maintenance_restore == null or opts.json or opts.review_stdin or
            opts.new_install or opts.resume_path != null or seen_profile or settings_mask != 0 or opts.draft != null or
            opts.export_path != null or opts.bundle_path != null or opts.password_file != null or opts.password_fd != null or
            (opts.service != .auto and opts.service != .foreground)) return error.InvalidArguments;
        opts.profile = .existing;
        opts.service = .foreground;
        return opts;
    }
    if (opts.maintenance_pid != null or opts.maintenance_target != null or opts.maintenance_backup != null or opts.maintenance_restore != null) return error.InvalidArguments;
    if (opts.resume_path != null and (opts.new_install or seen_profile or seen_service or settings_mask != 0)) return error.InvalidArguments;
    opts.existing_allowed = opts.interactive and !opts.new_install and !seen_profile and settings_mask == 0 and opts.resume_path == null and opts.draft == null and opts.export_path == null and opts.bundle_path == null and opts.password_file == null and opts.password_fd == null;
    opts.new_install = opts.new_install or opts.resume_path != null or opts.interactive;
    if (opts.new_install) {
        if (opts.config.len != 0) return error.InvalidArguments;
        if (opts.profile == .existing) opts.profile = .private;
    } else if (opts.config.len == 0 or seen_profile or opts.draft != null or opts.export_path != null or opts.bundle_path != null or settings_mask != 0) return error.InvalidArguments;
    if (opts.interactive and opts.json) return error.InvalidArguments;
    if (opts.linear and !opts.interactive) return error.InvalidArguments;
    if (opts.review_stdin and (opts.interactive or !opts.json or opts.bundle_path == null)) return error.InvalidArguments;
    if (opts.bundle_path != null and !opts.interactive and !opts.review_stdin) return error.InvalidArguments;
    const actions = @as(u8, @intFromBool(opts.draft != null)) + @intFromBool(opts.export_path != null) + @intFromBool(opts.bundle_path != null);
    if (actions > 1) return error.InvalidArguments;
    if (opts.bundle_path != null) opts.settings.tls_enabled = true;
    opts.settings.validate() catch return error.InvalidArguments;
    if (opts.password_file != null and opts.password_fd != null) return error.InvalidArguments;
    if (!opts.new_install and (opts.password_file != null or opts.password_fd != null)) return error.InvalidArguments;
    if (opts.settings.bootstrap.enabled() and opts.export_path != null) return error.InvalidArguments;
    return opts;
}

/// Directory markers are hints, not evidence that a supervisor is PID 1 or
/// running. Ambiguous/no markers select a portable foreground plan.
pub fn selectService(requested: Service, openrc: bool, systemd: bool) Service {
    if (requested != .auto) return requested;
    if (openrc == systemd) return .foreground;
    return if (openrc) .openrc else .systemd;
}

pub fn useColor(tty: bool, no_color_present: bool, term: ?[]const u8) bool {
    if (!tty or no_color_present) return false;
    const value = term orelse return false;
    return value.len != 0 and !std.mem.eql(u8, value, "dumb");
}

const common_steps = [_][]const u8{
    "Review the candidate configuration and retain existing configuration, node identity, and secrets for recovery.",
    "Provision the service account and private config/key/state directories; verify access as the intended runtime user.",
    "Run onyx-server --check-config <candidate> and onyx-server doctor <candidate> as the intended runtime user before starting; filesystem, certificate, and identity preflights remain outstanding.",
    "After an authorized start, verify metrics, secured mesh links, and real client participation; preview does not prove readiness or Internet reachability.",
};

/// Nonsecret values from the authoritative boot projection of an existing file.
pub const ExistingSummary = struct {
    network: []const u8,
    server: []const u8,
    listen_host: []const u8,
    irc_port: u16,
    max_clients: u31,
    media_enabled: bool,
};

pub const Plan = struct {
    schema_version: u8 = 4,
    mode: []const u8 = "preview",
    config: []const u8,
    service: Service,
    service_environment: @import("onyx_server").daemon.service_environment.Environment = .{},
    service_explicit: bool = false,
    service_plan: ?@import("onyx_server").daemon.service_environment.Plan = null,
    service_basis: []const u8,
    validation: []const u8 = "typed configuration and static startup checks passed",
    readiness: []const u8 = "unknown",
    changes_applied: bool = false,
    profile: workflow.Profile = .existing,
    purpose: []const u8 = "existing_network_review",
    enrollment: []const u8 = "Enrollment is not performed by setup; no network contact or readiness is established.",
    profile_values: []const u8 = workflow.description(.existing),
    effective_profile: ?workflow.EffectiveProfile = null,
    existing_summary: ?ExistingSummary = null,
    profile_diff_baseline: workflow.Profile = .existing,
    profile_diff_basis: []const u8 = "Existing configuration is preserved without profile projection.",
    profile_diff: []const u8 = "Existing configuration preserved.",
    artifact: ?[]const u8 = null,
    settings: ?workflow.Settings = null,
    media_assessment: ?media_assessment.Assessment = null,
    network_assessment: ?network_assessment.Assessment = null,
    provisioning: []const u8 = "none; preview does not create identity or secrets",
    node_public_key: ?[]const u8 = null,
    certificate_expires_unix: ?i64 = null,
    bootstrap_account: ?[]const u8 = null,
    operator_privileges: []const u8 = "none",
    authentication_mechanisms: []const []const u8 = &.{},
    tls_provenance: []const u8 = "not provisioned; trust and reachability unknown",
    service_guidance: []const u8,
    recovery: []const u8 = "Preview leaves the installation unchanged. Before any later upgrade, retain the previous artifact and a compatible private configuration/state backup; follow the release runbook for recovery.",
    steps: []const []const u8 = &common_steps,

    pub fn init(config: []const u8, requested: Service, openrc: bool, systemd: bool) Plan {
        const service = selectService(requested, openrc, systemd);
        return .{
            .config = config,
            .service = service,
            .service_explicit = requested != .auto,
            .service_environment = .{ .manager_hint = if (openrc == systemd) .unknown else if (openrc) .openrc else .systemd },
            .service_basis = if (requested != .auto) "explicit operator selection" else "runtime directory hints only; verify supervisor before installation",
            .service_guidance = switch (service) {
                .openrc => "Review staged etc/init.d/onyx-server and etc/conf.d/onyx-server. Defaults: /usr/bin/onyx-server, /etc/onyx-server/onyx-server.toml, /var/lib/onyx-server, account onyx-server:onyx-server. Provision config before enabling OpenRC; see docs/guide/alpine.md.",
                .systemd => "Review etc/systemd/onyx-server.service and its executable, config, state, and account paths for this host before installing or enabling the unit.",
                .foreground => "Use the reviewed executable and candidate config in the foreground or under the container's supervisor. Arrange private persistent state and graceful signal handling.",
                .auto => unreachable,
            },
        };
    }
};

/// Both presentations serialize the same plan. JSON quoting keeps untrusted
/// paths and terminal control characters inert in the human-readable output.
pub fn render(allocator: std.mem.Allocator, plan: Plan, json: bool, color: bool) error{OutOfMemory}![]u8 {
    var output_plan = plan;
    const service_env = @import("onyx_server").daemon.service_environment;
    const requested: ?service_env.Service = if (plan.service_explicit) switch (plan.service) {
        .openrc => .openrc,
        .systemd => .systemd,
        .foreground => .foreground,
        .auto => null,
    } else null;
    output_plan.service_plan = service_env.servicePlan(plan.service_environment, requested);
    output_plan.effective_profile = if (plan.settings) |settings| workflow.effectiveProfile(plan.profile, settings) else null;
    if (output_plan.media_assessment == null) output_plan.media_assessment = if (plan.settings) |settings|
        media_assessment.assess(plan.profile, settings.media_port)
    else
        media_assessment.assess(.existing, 0);
    if (json) return std.json.Stringify.valueAlloc(allocator, output_plan, .{ .whitespace = .indent_2 });
    const effective = try std.json.Stringify.valueAlloc(allocator, if (output_plan.effective_profile == null) @as(?workflow.EffectiveProfile, null) else output_plan.effective_profile, .{});
    defer allocator.free(effective);
    const existing_summary = try std.json.Stringify.valueAlloc(allocator, plan.existing_summary, .{});
    defer allocator.free(existing_summary);
    const network = try std.json.Stringify.valueAlloc(allocator, plan.network_assessment, .{});
    defer allocator.free(network);
    const media = try std.json.Stringify.valueAlloc(allocator, output_plan.media_assessment, .{ .emit_null_optional_fields = false });
    defer allocator.free(media);
    const service_plan = try std.json.Stringify.valueAlloc(allocator, output_plan.service_plan.?, .{});
    defer allocator.free(service_plan);
    const environment = try std.json.Stringify.valueAlloc(allocator, plan.service_environment, .{});
    defer allocator.free(environment);
    const path = try std.json.Stringify.valueAlloc(allocator, plan.config, .{});
    defer allocator.free(path);
    const artifact = try std.json.Stringify.valueAlloc(allocator, plan.artifact, .{});
    defer allocator.free(artifact);
    const settings = try std.json.Stringify.valueAlloc(allocator, plan.settings, .{});
    defer allocator.free(settings);
    const identity = try std.json.Stringify.valueAlloc(allocator, .{ .public_key = plan.node_public_key, .certificate_expires_unix = plan.certificate_expires_unix, .bootstrap_account = plan.bootstrap_account, .operator_privileges = plan.operator_privileges, .authentication_mechanisms = plan.authentication_mechanisms }, .{});
    defer allocator.free(identity);
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const existing = plan.profile == .existing;
    out.writer.print("{s}Onyx Server setup preview{s}\nConfig: {s}\nService: {s}\nService environment: {s}\nSelection: {s}\nValidation: {s}\nReadiness: {s}\nChanges applied: {s}\nPurpose: {s}\nEnrollment: {s}\nProfile: {s}\nProfile defaults: {s}\nEffective profile: {s}\nComparison baseline: {s}\nComparison basis: {s}\nDiff: {s}\nArtifact: {s}\n\n{s}\n\n", .{
        if (color) "\x1b[1;36m" else "",                                                  if (color) "\x1b[0m" else "",                                                    path,
        @tagName(plan.service),                                                           environment,                                                                     plan.service_basis,
        plan.validation,                                                                  plan.readiness,                                                                  if (plan.changes_applied) "true" else "false",
        if (existing) "Review an existing network configuration" else "New installation", plan.enrollment,                                                                 @tagName(plan.profile),
        plan.profile_values,                                                              if (existing) "not applicable; existing configuration preserved" else effective, @tagName(plan.profile_diff_baseline),
        plan.profile_diff_basis,                                                          plan.profile_diff,                                                               if (plan.artifact == null) "not applicable" else artifact,
        plan.service_guidance,
    }) catch return error.OutOfMemory;
    out.writer.print("Service plan (shipped template facts, host state unknown): {s}\n", .{service_plan}) catch return error.OutOfMemory;
    if (existing) out.writer.print("Existing configuration summary: {s}\n", .{if (plan.existing_summary == null) "not available" else existing_summary}) catch return error.OutOfMemory;
    out.writer.print("Network assessment: {s}\n", .{if (plan.network_assessment == null) "not available" else network}) catch return error.OutOfMemory;
    out.writer.print("Media assessment: {s}\n", .{media}) catch return error.OutOfMemory;
    if (output_plan.media_assessment.?.configured == null) out.writer.writeAll("Configured media details: unknown; no configuration was assessed\n") catch return error.OutOfMemory;
    out.writer.print("Settings (override profile defaults): {s}\nProvisioning: {s}\nTLS: {s}\nPublic identity: {s}\nReachability: unknown; no listeners or network probes started\nCapacity: configured limit only; no benchmark estimate\n\n", .{ if (existing) "not applicable; existing configuration preserved" else settings, plan.provisioning, plan.tls_provenance, if (existing) "not provisioned" else identity }) catch return error.OutOfMemory;
    for (plan.steps, 1..) |step, i| out.writer.print("{d}. {s}\n", .{ i, step }) catch return error.OutOfMemory;
    out.writer.print("\nRecovery: {s}\n", .{plan.recovery}) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

test "setup rejects ambiguous options and never interprets commit flags" {
    const opts = try parse(&.{ "node.toml", "--json", "--service", "openrc" });
    try std.testing.expectEqual(Service.openrc, opts.service);
    try std.testing.expect(opts.json);
    for ([_][]const []const u8{ &.{}, &.{"--commit"}, &.{ "node.toml", "--commit" }, &.{ "node.toml", "--service" }, &.{ "node.toml", "--json", "--json" }, &.{ "node.toml", "--service", "unknown" }, &.{ "node.toml", "other.toml" } }) |args| {
        try std.testing.expectError(error.InvalidArguments, parse(args));
    }
}

test "setup documented TLS and resumed password options are accepted" {
    const tls = try parse(&.{ "--new", "--tls", "--tls-port", "7001" });
    try std.testing.expect(tls.settings.tls_enabled);
    try std.testing.expectEqual(@as(u16, 7001), tls.settings.tls_port);
    const resumed = try parse(&.{ "--resume", "draft.json", "--password-file", "private-input", "--bundle", "new-dir", "--json", "--review-stdin" });
    try std.testing.expectEqualStrings("private-input", resumed.password_file.?);
    try std.testing.expectEqualStrings("new-dir", resumed.bundle_path.?);
}

test "setup service detection is conservative and explicit selection wins" {
    try std.testing.expectEqual(Service.openrc, selectService(.auto, true, false));
    try std.testing.expectEqual(Service.systemd, selectService(.auto, false, true));
    try std.testing.expectEqual(Service.foreground, selectService(.auto, false, false));
    try std.testing.expectEqual(Service.foreground, selectService(.auto, true, true));
    try std.testing.expectEqual(Service.openrc, selectService(.openrc, false, true));
}

test "setup color honors NO_COLOR redirected output and dumb terminals" {
    try std.testing.expect(useColor(true, false, "xterm-256color"));
    try std.testing.expect(!useColor(false, false, "xterm"));
    try std.testing.expect(!useColor(true, true, "xterm"));
    try std.testing.expect(!useColor(true, false, "dumb"));
    try std.testing.expect(!useColor(true, false, null));
}

test "setup text and headless plan retain recovery and escape untrusted paths" {
    const allocator = std.testing.allocator;
    const plan = Plan.init("secret\x1b[31m\n\".toml", .openrc, false, false);
    const json = try render(allocator, plan, true, true);
    defer allocator.free(json);
    const decoded = try std.json.parseFromSlice(Plan, allocator, json, .{});
    defer decoded.deinit();
    try std.testing.expectEqualStrings(plan.config, decoded.value.config);
    try std.testing.expect(!decoded.value.changes_applied);
    try std.testing.expectEqualStrings("unknown", decoded.value.readiness);
    const text = try render(allocator, plan, false, false);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOfScalar(u8, text, 0x1b) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, json, 0x1b) == null);
    for (plan.steps) |step| try std.testing.expect(std.mem.indexOf(u8, text, step) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, decoded.value.recovery) != null);
}

fn allocationProbe(allocator: std.mem.Allocator) !void {
    const plan = Plan.init("candidate.toml", .openrc, false, false);
    const text = try render(allocator, plan, false, true);
    defer allocator.free(text);
    const json = try render(allocator, plan, true, false);
    defer allocator.free(json);
}

// Test-only backing: make every growth requiring new storage an alloc cut,
// independent of allocator-specific resize/remap success between sweep runs.
const SetupAllocationSweepBacking = struct {
    backing: std.mem.Allocator,
    fn allocator(self: *SetupAllocationSweepBacking) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *SetupAllocationSweepBacking = @ptrCast(@alignCast(raw));
        return self.backing.rawAlloc(len, alignment, ra);
    }
    fn free(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *SetupAllocationSweepBacking = @ptrCast(@alignCast(raw));
        self.backing.rawFree(memory, alignment, ra);
    }
};

test "setup allocation failures leave the immutable plan retryable" {
    var backing = SetupAllocationSweepBacking{ .backing = std.testing.allocator };
    try std.testing.checkAllAllocationFailures(backing.allocator(), allocationProbe, .{});
}

test "setup new and resume actions require explicit unambiguous artifacts" {
    const opts = try parse(&.{ "--new", "--profile", "media", "--service", "openrc", "--export", "new.toml", "--json" });
    try std.testing.expect(opts.new_install);
    try std.testing.expectEqual(workflow.Profile.media, opts.profile);
    try std.testing.expectEqualStrings("new.toml", opts.export_path.?);
    const resumed = try parse(&.{ "--resume", "draft.json", "--interactive", "--export", "new.toml" });
    try std.testing.expect(resumed.new_install and resumed.interactive);
    for ([_][]const []const u8{
        &.{ "old.toml", "--new" },                            &.{ "old.toml", "--export", "new.toml" },
        &.{ "--new", "--draft", "draft", "--export", "new" }, &.{ "--new", "--profile", "existing" },
        &.{ "--resume", "draft", "--profile", "media" },      &.{ "--resume", "draft", "--service", "auto" },
        &.{ "--interactive", "--json" },                      &.{ "--new", "--export" },
    }) |args| try std.testing.expectError(error.InvalidArguments, parse(args));
}

test "setup configurable fields are bounded and headless order independent" {
    const opts = try parse(&.{ "--new", "--hostname", "irc.example.test", "--listen", "::1", "--tls-port", "6680", "--irc-port", "7000", "--node-id", "72", "--max-clients", "256", "--media-port", "7100", "--bundle", "private-node", "--json", "--review-stdin" });
    try std.testing.expect(opts.settings.tls_enabled);
    try std.testing.expectEqual(@as(u16, 7000), opts.settings.irc_port);
    try std.testing.expectEqual(@as(u64, 72), opts.settings.node_id);
    for ([_][]const []const u8{
        &.{ "existing.toml", "--hostname", "foo.test" }, &.{ "--new", "--hostname", "bad\nname" },
        &.{ "--new", "--listen", "not-an-ip" },          &.{ "--new", "--irc-port", "0" },
        &.{ "--new", "--tls-port", "6680" },             &.{ "--new", "--max-clients", "32768" },
        &.{ "--new", "--node-id", "0" },                 &.{ "--new", "--bundle", "a", "--export", "b" },
    }) |args| try std.testing.expectError(error.InvalidArguments, parse(args));
}

test "setup account intent stays separate from transient password sources" {
    const opts = try parse(&.{ "--new", "--bootstrap-account", "Alice", "--oper-privileges", "server_rehash,audit_read", "--password-file", "missing-private-input", "--draft", "choices.json" });
    try std.testing.expectEqualStrings("Alice", opts.settings.bootstrap.account);
    try std.testing.expectEqual(@as(usize, 2), (try opts.settings.bootstrap.permissions()).count());
    const resumed = try parse(&.{ "--resume", "choices.json", "--password-fd", "3", "--bundle", "node", "--json", "--review-stdin" });
    try std.testing.expectEqual(@as(?i32, 3), resumed.password_fd);
    for ([_][]const []const u8{
        &.{ "--new", "--oper-privileges", "server_admin" },
        &.{ "--new", "--bootstrap-account", "Alice", "--oper-privileges", "server_admin,server_admin" },
        &.{ "--new", "--bootstrap-account", "Alice", "--oper-privileges", "unknown" },
        &.{ "--new", "--bootstrap-account", "Alice", "--export", "no-account-store.toml" },
        &.{ "--new", "--password-fd", "0" },
        &.{ "--new", "--password-fd", "3", "--password-file", "private" },
    }) |args| try std.testing.expectError(error.InvalidArguments, parse(args));
}

test "setup plan media assessment agrees with review for generated and existing profiles" {
    const a = std.testing.allocator;
    const cases = [_]struct { profile: workflow.Profile, settings: ?workflow.Settings }{
        .{ .profile = .media, .settings = .{ .media_port = 0 } },
        .{ .profile = .media, .settings = .{ .media_port = 7100 } },
        .{ .profile = .private, .settings = .{ .media_port = 7100 } },
        .{ .profile = .community, .settings = .{} },
        .{ .profile = .existing, .settings = null },
    };
    for (cases) |case| {
        var plan = Plan.init("candidate", .foreground, false, false);
        plan.profile = case.profile;
        plan.settings = case.settings;
        const expected = if (case.settings) |settings| media_assessment.assess(case.profile, settings.media_port) else media_assessment.assess(.existing, 0);
        const json = try render(a, plan, true, false);
        defer a.free(json);
        const parsed = try std.json.parseFromSlice(Plan, a, json, .{});
        defer parsed.deinit();
        const actual = parsed.value.media_assessment.?;
        try std.testing.expectEqualStrings(expected.enabled, actual.enabled);
        try std.testing.expectEqualStrings(expected.socket, actual.socket);
        try std.testing.expectEqualStrings(expected.native_socket, actual.native_socket);
        try std.testing.expectEqualStrings(expected.candidate, actual.candidate);
        try std.testing.expectEqualStrings(expected.network, actual.network);
        try std.testing.expectEqualStrings(expected.fallback, actual.fallback);
        const text = try render(a, plan, false, false);
        defer a.free(text);
        for ([_][]const u8{ expected.enabled, expected.socket, expected.native_socket, expected.candidate, expected.network, expected.fallback }) |field_value| {
            try std.testing.expect(std.mem.indexOf(u8, text, field_value) != null);
        }
        try std.testing.expectEqualStrings("unknown", parsed.value.readiness);
    }
}

test "setup plan displays effective comparison baseline in JSON and human output" {
    const a = std.testing.allocator;
    const selected: workflow.Settings = .{ .max_clients = 512 };
    var buffer: [128]u8 = undefined;
    var plan = Plan.init("<generated candidate>", .foreground, false, false);
    plan.profile = .media;
    plan.settings = selected;
    plan.profile_diff_baseline = .community;
    plan.profile_diff_basis = "Current settings and overrides apply to both profiles.";
    plan.profile_diff = try workflow.diff(&buffer, .community, .media, selected);
    for ([_]bool{ false, true }) |color| {
        const text = try render(a, plan, false, color);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "Comparison baseline: community") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "media.enabled: false -> true") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "128 -> 1024") == null);
    }
    const json = try render(a, plan, true, false);
    defer a.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"profile_diff_baseline\": \"community\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"max_clients\": 512") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Current settings and overrides apply to both profiles.") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "media.enabled: false -> true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "128 -> 1024") == null);
}

test "setup existing network purpose disallows discarded new choices" {
    const plain = try parse(&.{"--interactive"});
    try std.testing.expect(plain.existing_allowed);
    const service = try parse(&.{ "--interactive", "--service", "foreground" });
    try std.testing.expect(service.existing_allowed);
    for ([_][]const []const u8{
        &.{ "--new", "--interactive" },
        &.{ "--interactive", "--profile", "media" },
        &.{ "--interactive", "--max-clients", "512" },
        &.{ "--interactive", "--export", "out.toml" },
        &.{ "--interactive", "--draft", "draft.json" },
        &.{ "--interactive", "--bundle", "bundle" },
        &.{ "--resume", "draft.json", "--interactive" },
        &.{ "--interactive", "--password-file", "password" },
    }) |args| {
        const result = try parse(args);
        try std.testing.expect(!result.existing_allowed);
    }
    const a = std.testing.allocator;
    const plan = Plan.init("source.toml", .foreground, false, false);
    for ([_]bool{ false, true }) |color| {
        const text = try render(a, plan, false, color);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "Review an existing network configuration") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Enrollment is not performed") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "null") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Configured media details: unknown") != null);
    }
    const json = try render(a, plan, true, false);
    defer a.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"effective_profile\": null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"configured\": null") != null);
}

test "setup linear mode requires interactive and disables no output options" {
    const opts = try parse(&.{ "--interactive", "--linear" });
    try std.testing.expect(opts.interactive and opts.linear);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--new", "--linear" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--interactive", "--linear", "--linear" }));
}

test "headless bundle requires explicit JSON review channel" {
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--new", "--bundle", "node", "--json" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--new", "--bundle", "node", "--review-stdin" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--new", "--json", "--review-stdin" }));
    const options = try parse(&.{ "--new", "--bundle", "node", "--json", "--review-stdin" });
    try std.testing.expect(options.review_stdin);
}

test "setup service plans retain explicit selection and unknown host state" {
    const a = std.testing.allocator;
    var plan = Plan.init("existing.toml", .systemd, true, false);
    plan.service_environment = .{ .manager_hint = .openrc };
    const json = try render(a, plan, true, false);
    defer a.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();
    const obj = parsed.value.object.get("service_plan").?.object;
    try std.testing.expectEqualStrings("systemd", obj.get("selected").?.string);
    try std.testing.expectEqualStrings("unknown; no daemon or client observation", obj.get("daemon_readiness").?.string);
    const template = obj.get("template").?.object;
    try std.testing.expectEqualStrings("/usr/local/bin/onyx-server", template.get("executable").?.string);
    try std.testing.expectEqualStrings("--check-config", template.get("preflight_argv").?.array.items[1].string);
    try std.testing.expectEqualStrings("/etc/onyx-server/onyx-server.toml", template.get("start_argv").?.array.items[1].string);
}

test "maintenance setup grammar is explicit existing local runtime only" {
    const t = std.testing;
    const args = [_][]const u8{ "--maintenance", "--interactive", "runtime.toml", "--pid", "123", "--target", "candidate", "--backup", "backup", "--restore-into", "scratch" };
    const options = try parse(&args);
    try t.expect(options.maintenance and options.profile == .existing and !options.new_install);
    try t.expectEqual(@as(i32, 123), options.maintenance_pid.?);
    try t.expectEqual(Service.foreground, options.service);
    try t.expectError(error.InvalidArguments, parse(args[0 .. args.len - 2]));
    try t.expectError(error.InvalidArguments, parse(&.{ "--maintenance", "--pid", "123", "runtime.toml" }));
    try t.expectError(error.InvalidArguments, parse(&.{ "--pid", "123", "runtime.toml" }));
    var extended: [args.len + 1][]const u8 = undefined;
    @memcpy(extended[0..args.len], &args);
    extended[args.len] = "--new";
    try t.expectError(error.InvalidArguments, parse(&extended));
}
