// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Narrow, secret-free interactive review of selected setup choices.
const std = @import("std");
const setup = @import("setup.zig");
const workflow = setup.workflow;
const media_assessment = @import("setup_media_assessment.zig");

pub const Action = enum { preview, draft, export_config, bundle };

pub fn normalizedWidth(raw: usize) usize {
    return if (raw < 20 or raw > 4096) 38 else @min(raw, 120);
}

pub fn fallbackWidth(columns: ?[]const u8) usize {
    const raw = std.fmt.parseInt(usize, columns orelse return 38, 10) catch return 38;
    return normalizedWidth(raw);
}

// Wrap at word boundaries where possible; long tokens are split only when
// necessary. Control bytes are escaped and ANSI styling is balanced per line.
fn escapedLength(c: u8) usize {
    return if (c >= 0x20 and c <= 0x7e and c != '\\') 1 else 4;
}
fn breakLine(writer: *std.Io.Writer, indent: usize, color: bool) !void {
    if (color) try writer.writeAll("\x1b[0m");
    try writer.writeByte('\n');
    if (color) try writer.writeAll("\x1b[1;36m");
    if (indent != 0) try writer.writeAll("  ");
}
pub fn wrapped(writer: *std.Io.Writer, value: []const u8, width: usize, indent: usize, color: bool) !void {
    const digits = "0123456789abcdef";
    if (color) try writer.writeAll("\x1b[1;36m");
    if (indent != 0) try writer.writeAll("  ");
    var column: usize = indent;
    var pos: usize = 0;
    while (pos < value.len) {
        if (value[pos] == ' ') {
            if (column + 1 > width) {
                try breakLine(writer, indent, color);
                column = indent;
            }
            try writer.writeByte(' ');
            column += 1;
            pos += 1;
            continue;
        }
        var end = pos;
        var word_len: usize = 0;
        while (end < value.len and value[end] != ' ') : (end += 1) word_len += escapedLength(value[end]);
        if (column > indent and column + word_len > width) {
            try breakLine(writer, indent, color);
            column = indent;
        }
        for (value[pos..end]) |byte| {
            var buf: [4]u8 = undefined;
            const token: []const u8 = if (escapedLength(byte) == 1) blk: {
                buf[0] = byte;
                break :blk buf[0..1];
            } else blk: {
                buf = .{ '\\', 'x', digits[byte >> 4], digits[byte & 15] };
                break :blk &buf;
            };
            if (column + token.len > width) {
                try breakLine(writer, indent, color);
                column = indent;
            }
            try writer.writeAll(token);
            column += token.len;
        }
        pos = end;
    }
    if (color) try writer.writeAll("\x1b[0m");
    try writer.writeByte('\n');
}
/// Trusted message newlines are structural; untrusted bytes remain escaped.
pub fn renderMessage(allocator: std.mem.Allocator, text: []const u8, raw_width: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 and lines.index == null) break;
        try wrapped(&out.writer, line, normalizedWidth(raw_width), 0, false);
    }
    return out.toOwnedSlice();
}

fn section(writer: *std.Io.Writer, label: []const u8, color: bool, width: usize) !void {
    try writer.writeByte('\n');
    try wrapped(writer, label, width, 0, color);
}

fn field(writer: *std.Io.Writer, label: []const u8, value: []const u8, width: usize) !void {
    try wrapped(writer, label, width, 0, false);
    try wrapped(writer, value, width, 2, false);
}

fn number(writer: *std.Io.Writer, label: []const u8, value: anytype, width: usize) !void {
    var buf: [32]u8 = undefined;
    try field(writer, label, try std.fmt.bufPrint(&buf, "{d}", .{value}), width);
}

fn profileChange(writer: *std.Io.Writer, previous: workflow.Profile, profile: workflow.Profile, settings: workflow.Settings, width: usize) !void {
    try field(writer, "Comparison baseline", @tagName(previous), width);
    try field(writer, "Comparison basis", if (previous == .existing or profile == .existing) "Existing configuration preserved." else "Current settings and overrides apply to both profiles.", width);
    var buffer: [128]u8 = undefined;
    try field(writer, "Profile change", try workflow.diff(&buffer, previous, profile, settings), width);
}

fn networkFields(w: *std.Io.Writer, assessment: setup.network_assessment.Assessment, width: usize) !void {
    try section(w, "Network checks", false, width);
    try field(w, "Hostname", assessment.hostname, width);
    try field(w, "Candidate validation", assessment.candidate_validation, width);
    try field(w, "Hostname validation", assessment.hostname_check, width);
    try field(w, "DNS resolution", assessment.hostname_resolution, width);
    try field(w, "Listen address", assessment.listen_host, width);
    try field(w, "Address syntax", assessment.address_check, width);
    try field(w, "Address ownership", assessment.address_ownership, width);
    try number(w, "IRC port", assessment.irc_port, width);
    try field(w, "TLS enabled", if (assessment.tls_enabled) "yes" else "no", width);
    try number(w, "TLS port", assessment.tls_port, width);
    try field(w, "Port validation", assessment.port_check, width);
    try field(w, "Port availability", assessment.port_availability, width);
    try field(w, "Public reachability", assessment.public_reachability, width);
}
fn mediaConfiguredFields(w: *std.Io.Writer, media: media_assessment.Assessment, width: usize) !void {
    if (media.configured) |config| {
        try field(w, "Configured media", if (config.enabled) "enabled" else "disabled", width);
        try number(w, "Configured media UDP port (0 means ephemeral)", config.media_port, width);
        try number(w, "Configured native UDP port (0 means ephemeral)", config.native_media_port, width);
        try field(w, "Configured advertised host", config.advertised_host, width);
        try field(w, "Configured STUN host", if (config.stun_host.len == 0) "not configured" else config.stun_host, width);
        try number(w, "Configured STUN port", config.stun_port, width);
        try number(w, "Configured WebSocket port (0 means disabled)", config.websocket_port, width);
        try field(w, "Configured WebSocket media", if (config.websocket_media_relay) "enabled" else "disabled", width);
    }
    try field(w, "Relay observation", media.relay, width);
    try field(w, "Media observation", media.observation, width);
}
fn serviceTemplateFields(w: *std.Io.Writer, label: []const u8, template: @import("onyx_server").daemon.service_environment.Template, width: usize) !void {
    try field(w, "Template", label, width);
    try field(w, "Template source", template.source, width);
    try field(w, "Executable", template.executable, width);
    try field(w, "Config path", template.config, width);
    try field(w, "Identity", template.identity, width);
    try field(w, "Working directory", template.working_directory, width);
    var command: [1024]u8 = undefined;
    try field(w, "Preflight argv", try std.fmt.bufPrint(&command, "{s} --check-config {s}", .{ template.preflight_argv[0], template.preflight_argv[2] }), width);
    try field(w, "Preflight policy", template.preflight_policy, width);
    try field(w, "Start argv", try std.fmt.bufPrint(&command, "{s} {s}", .{ template.start_argv[0], template.start_argv[1] }), width);
    try field(w, "Restart", template.restart, width);
    try field(w, "Logging", template.logging, width);
}
fn serviceFields(w: *std.Io.Writer, choice: workflow.Service, width: usize) !void {
    const service_env = @import("onyx_server").daemon.service_environment;
    try section(w, "Service plan", false, width);
    try field(w, "Selection", if (choice == .auto) "auto; markers will be evaluated at completion, host manager unknown" else @tagName(choice), width);
    try field(w, "Template paths", "shipped examples only; they are not the selected candidate or verified host paths", width);
    if (choice == .auto) {
        inline for (.{ service_env.Service.openrc, service_env.Service.systemd, service_env.Service.foreground }) |service| {
            const p = service_env.servicePlan(.{}, service);
            try serviceTemplateFields(w, @tagName(service), p.template, width);
        }
    } else {
        const selected: service_env.Service = switch (choice) {
            .openrc => .openrc,
            .systemd => .systemd,
            .foreground => .foreground,
            .auto => unreachable,
        };
        const plan = service_env.servicePlan(.{}, selected);
        try serviceTemplateFields(w, @tagName(selected), plan.template, width);
    }
    const plan = service_env.servicePlan(.{}, .foreground);
    try serviceTemplateFields(w, "container example; not a selected supervisor", plan.container_template, width);
    try field(w, "Host and runtime", "unknown; template paths, access, supervisor, daemon, network and host resource ceilings are not verified", width);
}
/// A05: the same shared verdict doctor reports. Choices are not validated
/// yet and no metrics are read, so the evidence is preflight not_run and the
/// verdict is always unknown. Mode follows the shared precedence.
fn readinessFields(w: *std.Io.Writer, service: workflow.Service, width: usize) !void {
    const readiness = @import("onyx_server").daemon.service_readiness;
    const report = readiness.assess(readiness.modeFor(.{}, switch (service) {
        .auto => null,
        .openrc => .openrc,
        .systemd => .systemd,
        .foreground => .foreground,
    }), .{});
    var verdict_buf: [256]u8 = undefined;
    try field(w, "Readiness verdict", try std.fmt.bufPrint(&verdict_buf, "{s} ({s}); {s}", .{ @tagName(report.verdict.state), @tagName(report.verdict.reason), report.verdict.detail() }), width);
    if (service != .auto) try field(w, "Supervisor evidence", report.supervisor_evidence, width);
}
pub fn render(allocator: std.mem.Allocator, profile: workflow.Profile, previous: workflow.Profile, reviewing: bool, settings: workflow.Settings, service: workflow.Service, action: Action, artifact: ?[]const u8, color: bool, raw_width: usize) ![]u8 {
    return renderAssessed(allocator, profile, previous, reviewing, settings, service, action, artifact, color, raw_width, null, null);
}
pub fn renderAssessed(allocator: std.mem.Allocator, profile: workflow.Profile, previous: workflow.Profile, reviewing: bool, settings: workflow.Settings, service: workflow.Service, action: Action, artifact: ?[]const u8, color: bool, raw_width: usize, network: ?setup.network_assessment.Assessment, configured_media: ?media_assessment.Assessment) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    const width = normalizedWidth(raw_width);
    try section(w, if (reviewing) "Review" else "Choices", color, width);
    try field(w, "Progress", if (reviewing) "Review" else "Choices", width);
    if (reviewing) try serviceFields(w, service, width);
    if (profile == .existing) {
        try field(w, "Purpose", "Review an existing network configuration", width);
        try field(w, "Configuration", artifact orelse "Set a path with: set config <path>", width);
        try field(w, "Enrollment", "Setup does not enroll this node or contact the network; review trust and deployment separately.", width);
        try field(w, "Source", "Existing configuration remains unchanged.", width);
        try section(w, "Media and runtime readiness", color, width);
        if (network) |check| try networkFields(w, check, width);
        const media = configured_media orelse media_assessment.assess(.existing, 0);
        try field(w, "Media enabled", media.enabled, width);
        try field(w, "Media UDP", media.socket, width);
        try field(w, "Native media UDP", media.native_socket, width);
        try field(w, "Advertised media address", media.candidate, width);
        try field(w, "Media network", media.network, width);
        try field(w, "Constrained networks", media.fallback, width);
        try mediaConfiguredFields(w, media, width);
        try field(w, "Readiness", "unknown; no network checks", width);
        try readinessFields(w, service, width);
        try field(w, "Next", if (reviewing) "done continues; back edits; cancel exits" else "set config <path>; review; back selects a profile; cancel exits", width);
        return out.toOwnedSlice();
    }
    try field(w, "Profile", @tagName(profile), width);
    try profileChange(w, previous, profile, settings, width);
    try field(w, "Service selection", @tagName(service), width);
    if (network) |check| try networkFields(w, check, width);
    try section(w, "Identity and listeners", color, width);
    try field(w, "Hostname", settings.hostname, width);
    try number(w, "Node ID", settings.node_id, width);
    try field(w, "Listen address", settings.listen_host, width);
    try number(w, "IRC port", settings.irc_port, width);
    try field(w, "TLS enabled", if (settings.tls_enabled) "yes" else "no", width);
    try number(w, "TLS port", settings.tls_port, width);
    try section(w, "Capacity and media", color, width);
    if (workflow.effectiveProfile(profile, settings)) |effective| {
        try number(w, "Maximum clients", effective.max_clients, width);
    } else {
        try field(w, "Maximum clients", "unknown; existing configuration", width);
    }
    const media = configured_media orelse media_assessment.assess(profile, settings.media_port);
    try field(w, "Media enabled", media.enabled, width);
    if (profile == .existing) {
        try field(w, "Media port", "unknown; existing configuration", width);
    } else {
        try number(w, "Media port", settings.media_port, width);
    }
    try field(w, "Media UDP", media.socket, width);
    try field(w, "Native media UDP", media.native_socket, width);
    try field(w, "Advertised media address", media.candidate, width);
    try field(w, "Media network", media.network, width);
    try field(w, "Constrained networks", media.fallback, width);
    try mediaConfiguredFields(w, media, width);
    try field(w, "Network discoverable", "no", width);
    try section(w, "Bootstrap account", color, width);
    try field(w, "Account", if (settings.bootstrap.account.len == 0) "(none)" else settings.bootstrap.account, width);
    try field(w, "Operator privileges", settings.bootstrap.privileges, width);
    try section(w, "Requested action", color, width);
    try field(w, "Action", switch (action) {
        .preview => "preview only",
        .draft => "save private choices draft",
        .export_config => "export candidate configuration",
        .bundle => "prepare and review private bundle",
    }, width);
    if (artifact) |path| try field(w, "New destination", path, width);
    if (action == .bundle) {
        try field(w, "Bundle privacy", "directory 0700; files 0600", width);
        try field(w, "Bundle material", "node identity, cloak secret and self-signed TLS generated; client trust or pinning required", width);
        try field(w, "Bundle review", "existing paths refused; material review follows", width);
    }
    if (action == .bundle and !settings.tls_enabled) try field(w, "Bundle requires", "TLS enabled; change with set tls on", width);
    try section(w, "Validation and readiness", color, width);
    try field(w, "Current status", "choices only; validation pending", width);
    try field(w, "Readiness", "unknown; no network checks", width);
    try readinessFields(w, service, width);
    if (reviewing) {
        try field(w, "Next", if (action == .draft) "done or save continues; back edits; cancel exits" else "done continues; back edits; cancel exits", width);
    } else {
        try field(w, "Next", "review continues; help lists commands; cancel exits", width);
    }
    return out.toOwnedSlice();
}

test "setup review effective defaults overrides and safe narrow output" {
    const a = std.testing.allocator;
    const plain = try render(a, .community, .private, false, .{}, .auto, .preview, null, false, 38);
    defer a.free(plain);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Maximum clients\n  1024\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Media enabled\n  no\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Action\n  preview only\n") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, plain, 0x1b) == null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Readiness\n  unknown") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Readiness verdict\n  unknown (config_not_checked);") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Supervisor evidence") == null);
    try std.testing.expect(std.mem.startsWith(u8, plain, "\nChoices\n"));
    try std.testing.expect(std.mem.indexOf(u8, plain, "limits.max_clients: 128 -> 1024") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "review continues") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "done continues") == null);
    const default_candidate = try workflow.configuredCandidate(a, .community, .{}, null);
    defer a.free(default_candidate);
    try std.testing.expect(std.mem.indexOf(u8, default_candidate, "max_clients = 1024") != null);
    try std.testing.expect(std.mem.indexOf(u8, default_candidate, "[media]\nenabled = false") != null);
    const selected: workflow.Settings = .{ .hostname = "irc.example.test", .listen_host = "::1", .irc_port = 7000, .node_id = 7, .tls_enabled = true, .tls_port = 7001, .max_clients = 321, .media_port = 7002, .bootstrap = .{ .account = "Alice", .privileges = "audit_read" } };
    const output = try render(a, .media, .private, true, selected, .systemd, .bundle, "bad\x1b[31m\nname", false, 38);
    defer a.free(output);
    for ([_][]const u8{ "irc.example.test", "::1", "7000", "7001", "7002", "321", "Alice", "audit_read", "Media enabled\n  yes", "systemd", "prepare and review private bundle", "bad\\x1b[31m\\x0aname" }) |expected| try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
    try std.testing.expect(std.mem.startsWith(u8, output, "\nReview\n"));
    try std.testing.expect(std.mem.indexOf(u8, output, "media.enabled: false -> true") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "done continues") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Supervisor evidence\n  shipped template:") != null);
    const masked = try render(a, .community, .private, true, selected, .auto, .preview, null, false, 38);
    defer a.free(masked);
    try std.testing.expect(std.mem.indexOf(u8, masked, "No effective profile changes.") != null);
    try std.testing.expect(std.mem.indexOf(u8, masked, "128 -> 1024") == null);
    const from = try workflow.configuredCandidate(a, .private, selected, null);
    defer a.free(from);
    const to = try workflow.configuredCandidate(a, .community, selected, null);
    defer a.free(to);
    try std.testing.expect(std.mem.indexOf(u8, from, "max_clients = 321") != null);
    try std.testing.expect(std.mem.indexOf(u8, to, "max_clients = 321") != null);
    try std.testing.expect(std.mem.indexOf(u8, from, "[media]\nenabled = false") != null);
    try std.testing.expect(std.mem.indexOf(u8, to, "[media]\nenabled = false") != null);
    const generated = try workflow.configuredCandidate(a, .media, selected, null);
    defer a.free(generated);
    // Compare both displays against the actual generated candidate, including
    // the profile-driven media choice and an explicit capacity override.
    try std.testing.expect(std.mem.indexOf(u8, generated, "max_clients = 321") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Maximum clients\n  321") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "[media]\nenabled = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Media enabled\n  yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "irc = 7000") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "IRC port\n  7000") != null);
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| try std.testing.expect(line.len <= 38);
    const colored = try render(a, .private, .private, true, .{}, .foreground, .draft, "draft.json", true, 38);
    defer a.free(colored);
    try std.testing.expect(std.mem.indexOf(u8, colored, "\x1b[1;36m") != null);
    try std.testing.expect(std.mem.indexOf(u8, colored, "save private choices draft") != null);
    const bundle_off = try render(a, .private, .private, true, .{}, .auto, .bundle, "node", false, 38);
    defer a.free(bundle_off);
    try std.testing.expect(std.mem.indexOf(u8, bundle_off, "TLS enabled; change with set tls on") != null);
}

test "setup review adaptive width and escaped token integrity" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 38), fallbackWidth(null));
    try std.testing.expectEqual(@as(usize, 38), fallbackWidth("0"));
    try std.testing.expectEqual(@as(usize, 38), fallbackWidth("999999999999999999999999999999999"));
    try std.testing.expectEqual(@as(usize, 20), fallbackWidth("20"));
    try std.testing.expectEqual(@as(usize, 120), fallbackWidth("200"));
    try std.testing.expectEqual(@as(usize, 38), normalizedWidth(std.math.maxInt(usize)));
    for ([_]usize{ 20, 38, 80 }) |width| {
        const text = try render(a, .media, .private, true, .{ .max_clients = 321 }, .auto, .bundle, "012345678901234\x1bZ", false, width);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOfScalar(u8, text, 0x1b) == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "\\x1b") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "\\x\n") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Maximum clients\n  321") != null);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| try std.testing.expect(line.len <= width);
        const color = try render(a, .private, .private, true, .{}, .auto, .preview, null, true, width);
        defer a.free(color);
        var styled_lines = std.mem.splitScalar(u8, color, '\n');
        while (styled_lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "\x1b[1;36m")) {
                try std.testing.expect(std.mem.endsWith(u8, line, "\x1b[0m"));
                try std.testing.expect(line.len - "\x1b[1;36m".len - "\x1b[0m".len <= width);
            } else try std.testing.expect(line.len <= width);
        }
    }
}

test "setup review shows media assessment without claiming reachability" {
    const a = std.testing.allocator;
    for ([_]struct { profile: workflow.Profile, port: u16, expected: []const u8 }{
        .{ .profile = .media, .port = 0, .expected = "OS chooses an ephemeral port" },
        .{ .profile = .media, .port = 5000, .expected = "configured media port is used" },
        .{ .profile = .private, .port = 5000, .expected = "configured media port is not bound" },
        .{ .profile = .existing, .port = 0, .expected = "existing configuration is not assessed" },
    }) |case| {
        const text = try render(a, case.profile, case.profile, true, .{ .media_port = case.port, .listen_host = "invalid address" }, .auto, .preview, null, false, 120);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, case.expected) != null);
        const expected_network = if (case.profile == .media)
            "NAT, firewall and reachability unknown; STUN discovery does not prove media reachability"
        else
            "unknown; no reachability or NAT checks";
        try std.testing.expect(std.mem.indexOf(u8, text, expected_network) != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "unknown; no network checks") != null);
        try std.testing.expect(std.mem.indexOfScalar(u8, text, 0x1b) == null);
    }
    const settings: workflow.Settings = .{ .listen_host = "invalid address" };
    try std.testing.expectError(error.InvalidListenAddress, settings.validate());
}

test "setup review identifies profile baseline and override in plain and color" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |color| {
        const text = try render(a, .media, .community, true, .{ .max_clients = 512 }, .auto, .preview, null, color, 120);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "Comparison baseline\n  community") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Current settings and overrides apply to both profiles.") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "media.enabled: false -> true") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "limits.max_clients:") == null);
    }
}

test "existing network review renders path and no invented new-install values" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |color| {
        const text = try render(a, .existing, .private, true, .{}, .auto, .preview, "source.toml", color, 120);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "source.toml") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "does not enroll") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Existing configuration remains unchanged") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "existing configuration is not assessed") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "unknown; no reachability or NAT checks") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "unknown; no network checks") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "Maximum clients") == null);
    }
}

test "existing network review allocation failures are atomic" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            // checkAllAllocationFailures supplies this exact failing allocator.
            // Allocating Writer maps an induced allocation failure to WriteFailed;
            // keep unrelated writer failures visible rather than swallowing them.
            const failing: *std.testing.FailingAllocator = @ptrCast(@alignCast(allocator.ptr));
            const text = render(allocator, .existing, .private, true, .{}, .auto, .preview, "source.toml", false, 80) catch |err| {
                if (err == error.WriteFailed and failing.has_induced_failure) return error.OutOfMemory;
                return err;
            };
            defer allocator.free(text);
            try std.testing.expect(std.mem.indexOf(u8, text, "source.toml") != null);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "setup terminal words and escaped controls fit narrow lines" {
    const a = std.testing.allocator;
    const result = try renderMessage(a, "Welcome to existing network setup.\nUse set config path and search.\ninvalid\x1bvalue", 20);
    defer a.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "Welcome to existing \nnetwork setup.") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\\x1b") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, result, 0x1b) == null);
    var lines = std.mem.splitScalar(u8, result, '\n');
    while (lines.next()) |line| try std.testing.expect(line.len <= 20);
}

test "setup wrapping retains consecutive leading and trailing spaces" {
    const a = std.testing.allocator;
    const source = "  bundle  path  ";
    const text = try renderMessage(a, source, 20);
    defer a.free(text);
    try std.testing.expectEqualStrings("  bundle  path  \n", text);
    const metadata = try renderMessage(a, "files path: bundle  path", 20);
    defer a.free(metadata);
    var reconstructed: std.Io.Writer.Allocating = .init(a);
    defer reconstructed.deinit();
    for (metadata) |byte| if (byte != '\n') try reconstructed.writer.writeByte(byte);
    try std.testing.expectEqualStrings("files path: bundle  path", reconstructed.written());
}

test "existing review shows assessed TLS before continuing" {
    const a = std.testing.allocator;
    const net = setup.network_assessment.assess(.{ .hostname = "irc.example.test", .listen_host = "::1", .irc_port = 7000, .tls_enabled = true, .tls_port = 7444, .validated = true });
    const text = try renderAssessed(a, .existing, .existing, true, .{}, .auto, .preview, "source.toml", false, 120, net, null);
    defer a.free(text);
    const enabled = std.mem.indexOf(u8, text, "TLS enabled\n  yes") orelse return error.TestUnexpectedResult;
    const port = std.mem.indexOf(u8, text, "TLS port\n  7444") orelse return error.TestUnexpectedResult;
    const next = std.mem.indexOf(u8, text, "done continues") orelse return error.TestUnexpectedResult;
    try std.testing.expect(enabled < next and port < next);
}

test "service review presents selected template before continuation" {
    const a = std.testing.allocator;
    for ([_]workflow.Service{ .openrc, .systemd, .foreground, .auto }) |service| {
        const text = try render(a, .private, .private, true, .{}, service, .preview, null, false, 120);
        defer a.free(text);
        const source = std.mem.indexOf(u8, text, "Service plan") orelse return error.TestUnexpectedResult;
        const next = std.mem.indexOf(u8, text, "done continues") orelse return error.TestUnexpectedResult;
        try std.testing.expect(source < next);
        try std.testing.expect(std.mem.indexOf(u8, text, "--check-config") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "--foreground") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "host resource ceilings are not verified") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "/data/onyx-server.toml") != null);
    }
}

pub fn renderMaintenance(allocator: std.mem.Allocator, selection: @import("setup_maintenance_types.zig").Selection, review: ?@import("setup_maintenance_types.zig").Review, review_id: ?[]const u8, color: bool, raw_width: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    const width = normalizedWidth(raw_width);
    try section(w, "Existing runtime maintenance", color, width);
    try field(w, "Controller", "Linux foreground/runtime, same UID. OpenRC/systemd maintenance is unsupported in this lane", width);
    var pid_buf: [96]u8 = undefined;
    try field(w, "Selected PID", try std.fmt.bufPrint(&pid_buf, "{d}", .{selection.pid}), width);
    try field(w, "Configuration path", selection.config, width);
    try field(w, "Candidate executable", selection.target, width);
    try field(w, "Backup directory", selection.backup_dir, width);
    try field(w, "Verification scratch", selection.restore_into, width);
    try field(w, "Private evidence", "Verification scratch is retained after review, back, cancel or failure. Every new review requires a fresh path; use set restore-into <new-path> from choices", width);
    if (review) |r| {
        try section(w, "Maintenance review", color, width);
        try field(w, "Bound process", try std.fmt.bufPrint(&pid_buf, "uid={d} start_ticks={d} exe_inode={d}", .{ r.binding.uid, r.binding.start_ticks, r.binding.exe_inode }), width);
        try field(w, "Current executable capability probe", @tagName(r.static_checks.current_capabilities), width);
        const current_sha = std.fmt.bytesToHex(r.binding.current_sha256, .lower);
        const target_sha = std.fmt.bytesToHex(r.binding.target_sha256, .lower);
        try field(w, "Bound current executable SHA256", &current_sha, width);
        try field(w, "Bound target executable SHA256", &target_sha, width);
        try field(w, "Target capability probe", @tagName(r.static_checks.target_capabilities), width);
        try field(w, "Static configuration", @tagName(r.static_checks.candidate_config), width);
        try field(w, "Existing identity check", @tagName(r.static_checks.existing_identity), width);
        try field(w, "Runtime configuration", r.live_config, width);
        try field(w, "Backup restore drill", @tagName(r.backup.restore_drill), width);
        try field(w, "Backup generated Unix seconds", if (r.backup.generated_at_unix) |value| try std.fmt.bufPrint(&pid_buf, "{d}", .{value}) else "unknown", width);
        try field(w, "Backup observed Unix seconds", if (r.backup.observed_at_unix) |value| try std.fmt.bufPrint(&pid_buf, "{d}", .{value}) else "unknown", width);
        try field(w, "Maximum recorded backup age seconds", try std.fmt.bufPrint(&pid_buf, "{d}", .{r.backup.max_age_seconds}), width);
        try field(w, "Backup currency", "Only recorded manifest age is checked; equality with current live Store state remains unknown", width);
        try field(w, "Backup coverage", r.backup.coverage, width);
        try field(w, "Backup exclusions", r.backup.exclusions, width);
        try field(w, "Expected client impact", r.client_impact, width);
        try field(w, "Recovery boundary", r.recovery, width);
        try field(w, "Runtime executable", r.recovery_refs.runtime_executable, width);
        try field(w, "Previous artifact retention path", r.recovery_refs.previous_artifact, width);
        try field(w, "Maintenance journal", r.recovery_refs.journal, width);
        try field(w, "Verified backup copy", r.recovery_refs.verified_backup, width);
        try field(w, "Private configuration copy", r.recovery_refs.configuration_backup, width);
        try field(w, "Restore-drill output", r.recovery_refs.restore_drill, width);
        try field(w, "Cold recovery procedure", "Stop the selected runtime through its actual controller; clients disconnect. Inspect the operation journal and verify retained artifact hashes before restoring the previous executable to the displayed runtime path. Restore a compatible private configuration and separately retained identity sources; this drill does not archive referenced keys or environment. Start with strict existing identity, then validate real clients, mesh and media. An older image may reject the current schema; do not attempt automatic hot downgrade or overwrite after an ambiguous exec", width);
        if (review_id != null) {
            try field(w, "Retention state", "Previous artifact and journal are planned paths until apply; inspect the returned action receipt for actual custody", width);
            try field(w, "Reviewed apply", if (r.applicable()) "Explicit apply of the current review id only; all pinned inputs revalidated before stage/signal" else "Unavailable: required checks have not passed", width);
        } else try field(w, "Action receipt", "This records artifact custody references; it does not authorize another action or establish application readiness", width);
        if (review_id) |id| try field(w, "Review id", id, width);
    } else {
        try field(w, "Choices", "review, set restore-into <new-path>, cancel. Review creates retained private verification scratch; it never stages a runtime executable or signals the selected process", width);
    }
    return out.toOwnedSlice();
}

test "maintenance wizard review states compatibility backup impact and recovery without claiming live readiness" {
    const types = @import("setup_maintenance_types.zig");
    const selection: types.Selection = .{ .pid = 123, .config = "runtime.toml", .target = "candidate", .backup_dir = "backup", .restore_into = "scratch" };
    const binding: types.Binding = .{ .pid = 123, .uid = 1, .start_ticks = 2, .exe_device = 1, .exe_inode = 3, .current_sha256 = @splat(0), .config_sha256 = @splat(0), .target_sha256 = @splat(0), .backup_manifest_sha256 = @splat(0) };
    const review: types.Review = .{ .binding = binding, .static_checks = .{ .current_capabilities = .passed, .target_capabilities = .passed, .candidate_config = .unavailable, .existing_identity = .passed }, .backup = .{ .restore_drill = .passed } };
    const text = try renderMaintenance(std.testing.allocator, selection, review, "0123456789abcdef0123456789abcdef", false, 120);
    defer std.testing.allocator.free(text);
    for ([_][]const u8{ "Backup coverage", "Backup exclusions", "Expected client impact", "Recovery boundary", "unknown until daemon final guard", "downgrade", "Review id" }) |needle| try std.testing.expect(std.mem.indexOf(u8, text, needle) != null);
}
