// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Searchable HELP derived from the authoritative command and capability tables.
//!
//! `help_db` owns hand-written topic text and the numeric framing. This leaf
//! joins it to `module_manifest.Live.commands` (names, aliases, summaries,
//! categories, access, feature gates) and `live_cap_metadata.cap_specs`, so a
//! registered command is never answered with 524, `HELP ?query` searches the
//! registry, and an unavailable command says which support is missing.
//!
//! Availability mirrors `registry.dispatchGated` denial order (module gate,
//! feature toggle, IRCX opt-in, access level) and reports one category per
//! command. Reply text is static or registry-derived: the caller's query is
//! never echoed, and unavailable text never confirms whether any channel,
//! account or session exists. Every reply is built in one owned buffer; any
//! failure frees it, so callers either get a whole reply or an error.
const std = @import("std");
const help_db = @import("../proto/help_db.zig");
const ircx_gate = @import("../proto/ircx_gate.zig");
const live_caps = @import("../proto/live_cap_metadata.zig");
const registry = @import("registry.zig");
const module_manifest = @import("modules/manifest.zig");

const Live = module_manifest.Live;

pub const HelpError = help_db.HelpError;

/// Search result bound; a ninth match only adds the refine-search line.
pub const max_search_results: usize = 8;
/// Longest accepted search term, matching `help_db`.
pub const max_query_len: usize = 64;
/// Longest `help_long` body rendered per command.
const max_long_lines: usize = 12;
/// Whole-line IRC limit including CRLF.
const max_line_bytes: usize = 512;
/// Framing outside server, requester, topic and text: `:` ` ` code ` ` ` ` ` :` CRLF.
const frame_overhead: usize = 12;
/// Smallest text budget worth emitting; below it the framing is rejected.
const min_text_budget: usize = 32;

/// Why a command cannot run for a connection, in `dispatchGated` denial order.
pub const Availability = enum {
    available,
    module_not_running,
    feature_disabled,
    requires_ircx,
    requires_oper,
    requires_registration,

    /// Fixed explanation; carries no channel, account or session detail.
    pub fn text(self: Availability) ?[]const u8 {
        return switch (self) {
            .available => null,
            .module_not_running => "Unavailable: module not running.",
            .feature_disabled => "Unavailable: disabled by server configuration.",
            .requires_ircx => "Unavailable: requires IRCX; send IRCX first.",
            .requires_oper => "Unavailable: requires operator privileges.",
            .requires_registration => "Unavailable: requires completed registration.",
        };
    }
};

/// Classify `entry` for `caps` using exactly the checks and order of
/// `registry.dispatchGated`, so HELP can never promise what dispatch refuses.
pub fn availability(entry: registry.CommandEntry, caps: registry.DispatchCaps) Availability {
    if (caps.module_gate) |gate| {
        if (!gate.allows(entry.module_index)) return .module_not_running;
    }
    if (registry.featureDisabled(entry.spec.feature, caps)) return .feature_disabled;
    if (ircx_gate.gate(caps.ircx, entry.spec.name) == .NeedIrcx) return .requires_ircx;
    if (!registry.accessSatisfied(entry.spec.access, caps)) {
        return if (entry.spec.access == .oper) .requires_oper else .requires_registration;
    }
    return .available;
}

/// Build a complete HELP reply (704..706, 524 or a bounded `?query` search).
/// Static-topic and capability behaviour is unchanged when no registry command
/// matches; the owned slice is freed with `allocator`.
pub fn buildHelpReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    requested_topic: []const u8,
    caps: registry.DispatchCaps,
) HelpError![]u8 {
    if (std.mem.startsWith(u8, requested_topic, "?")) {
        return buildSearchReply(allocator, server_name, requester, requested_topic[1..]);
    }
    const entry = Live.lookupCommand(requested_topic) orelse
        return help_db.buildHelpLookupReply(allocator, server_name, requester, requested_topic);
    return buildCommandReply(allocator, server_name, requester, entry, requested_topic, caps);
}

fn buildCommandReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    entry: registry.CommandEntry,
    requested_topic: []const u8,
    caps: registry.DispatchCaps,
) HelpError![]u8 {
    const spec = entry.spec;
    // A hand-written topic for the requested name wins; otherwise the
    // canonical command's topic is used so aliases share one reply.
    const static_topic = help_db.lookup(requested_topic) orelse help_db.lookup(spec.name);
    const topic = if (static_topic) |st| st.topic else spec.name;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var first = true;

    if (static_topic) |st| {
        try appendRawLine(&out, allocator, server_name, requester, topic, st.lines[0], &first);
        for (st.lines[1..]) |line| try appendRawLine(&out, allocator, server_name, requester, topic, line, &first);
        if (spec.summary.len != 0) {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Registry summary: {s}", .{spec.summary});
        }
    } else {
        if (spec.summary.len != 0) {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "{s} - {s}", .{ spec.name, spec.summary });
        } else {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "{s} - {s} command", .{ spec.name, spec.category.token() });
        }
        try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Category: {s}; access: {s}.", .{ spec.category.token(), accessText(spec.access) });
        if (spec.min_params != 0) {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Needs at least {d} parameter(s).", .{spec.min_params});
        }
        if (spec.feature) |feature| {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Controlled by the {s} feature toggle.", .{feature});
        }
        if (spec.oper_privilege) |privilege| {
            try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Operator privilege: {s}.", .{@tagName(privilege)});
        }
    }
    try appendAliasLine(&out, allocator, server_name, requester, topic, spec, &first);
    if (spec.deprecated_by) |successor| {
        try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Deprecated; use {s} instead.", .{successor});
    }
    if (static_topic == null) try appendLongLines(&out, allocator, server_name, requester, topic, spec.help_long, &first);
    if (availability(entry, caps).text()) |line| {
        try appendRawLine(&out, allocator, server_name, requester, topic, line, &first);
    }
    try help_db.appendRplEndOfHelp(&out, allocator, server_name, requester, topic);
    return out.toOwnedSlice(allocator);
}

fn accessText(access: registry.Access) []const u8 {
    return switch (access) {
        .any => "any client",
        .registered => "registered user",
        .oper => "operator",
    };
}

/// First emitted line is 704 (start), every later line 705 (text).
fn appendRawLine(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
    first: *bool,
) HelpError!void {
    if (first.*) {
        try help_db.appendRplHelpStart(out, allocator, server_name, requester, topic, text);
        first.* = false;
    } else {
        try help_db.appendRplHelpTxt(out, allocator, server_name, requester, topic, text);
    }
}

/// Format registry-derived text, clipped to the IRC line budget and with
/// control bytes replaced, so table content can never break framing.
fn appendFmtLine(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    first: *bool,
    comptime fmt: []const u8,
    args: anytype,
) HelpError!void {
    var buf: [max_line_bytes]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..];
    try appendClipped(out, allocator, server_name, requester, topic, formatted, first);
}

fn appendClipped(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
    first: *bool,
) HelpError!void {
    const used = frame_overhead + server_name.len + requester.len + topic.len;
    if (used + min_text_budget > max_line_bytes) return error.InvalidParam;
    const budget = max_line_bytes - used;
    var clipped: [max_line_bytes]u8 = undefined;
    const n = @min(text.len, budget);
    for (text[0..n], clipped[0..n]) |src, *dst| dst.* = if (src < 0x20 or src == 0x7f) ' ' else src;
    try appendRawLine(out, allocator, server_name, requester, topic, clipped[0..n], first);
}

fn appendAliasLine(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    spec: registry.CommandSpec,
    first: *bool,
) HelpError!void {
    if (spec.aliases.len == 0) return;
    var buf: [max_line_bytes]u8 = undefined;
    var len: usize = 0;
    const prefix = "Aliases: ";
    @memcpy(buf[0..prefix.len], prefix);
    len = prefix.len;
    for (spec.aliases, 0..) |alias, i| {
        const sep: usize = if (i == 0) 0 else 2;
        if (len + sep + alias.len > buf.len) break;
        if (sep != 0) {
            @memcpy(buf[len..][0..2], ", ");
            len += 2;
        }
        @memcpy(buf[len..][0..alias.len], alias);
        len += alias.len;
    }
    try appendClipped(out, allocator, server_name, requester, topic, buf[0..len], first);
}

fn appendLongLines(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    help_long: []const u8,
    first: *bool,
) HelpError!void {
    var lines = std.mem.splitScalar(u8, help_long, '\n');
    var emitted: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (emitted == max_long_lines) break;
        try appendClipped(out, allocator, server_name, requester, topic, line, first);
        emitted += 1;
    }
}

// ---------------------------------------------------------------- search

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.findIgnoreCase(haystack, needle) != null;
}

fn validQuery(query: []const u8) bool {
    for (query) |ch| if (ch < 0x20 or ch == 0x7f) return false;
    return true;
}

fn commandMatches(spec: registry.CommandSpec, query: []const u8) bool {
    if (contains(spec.name, query) or contains(spec.summary, query) or contains(spec.help_long, query)) return true;
    for (spec.aliases) |alias| if (contains(alias, query)) return true;
    return false;
}

/// True when a hand-written topic exists for the command's name or any alias;
/// such commands are searched and listed through that topic only.
fn hasStaticTopic(spec: registry.CommandSpec) bool {
    if (help_db.lookup(spec.name) != null) return true;
    for (spec.aliases) |alias| if (help_db.lookup(alias) != null) return true;
    return false;
}

fn staticMatches(topic: help_db.HelpTopic, query: []const u8) bool {
    if (contains(topic.topic, query)) return true;
    for (topic.lines) |line| if (contains(line, query)) return true;
    if (Live.lookupCommand(topic.topic)) |entry| return commandMatches(entry.spec, query);
    return false;
}

/// Search static topics, registry commands and capability names. Output is
/// built only from table text; `query` never reaches the wire.
pub fn buildSearchReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    query: []const u8,
) HelpError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var first = true;
    const topic = "SEARCH";

    try appendClipped(&out, allocator, server_name, requester, topic, "Help search results:", &first);
    if (query.len == 0) {
        try appendClipped(&out, allocator, server_name, requester, topic, "Enter a search term after ?.", &first);
    } else if (query.len > max_query_len or !validQuery(query)) {
        try appendClipped(&out, allocator, server_name, requester, topic, "Invalid search term; use 1 to 64 printable bytes.", &first);
    } else {
        var count: usize = 0;
        var truncated = false;
        scan: {
            for (help_db.topics()) |entry| {
                if (!staticMatches(entry, query)) continue;
                if (count == max_search_results) {
                    truncated = true;
                    break :scan;
                }
                try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "{s}: {s}", .{ entry.topic, entry.lines[0] });
                count += 1;
            }
            for (Live.commands) |entry| {
                const spec = entry.spec;
                if (hasStaticTopic(spec) or !commandMatches(spec, query)) continue;
                if (count == max_search_results) {
                    truncated = true;
                    break :scan;
                }
                if (spec.summary.len != 0) {
                    try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "{s}: {s}", .{ spec.name, spec.summary });
                } else {
                    try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "{s}: {s} command", .{ spec.name, spec.category.token() });
                }
                count += 1;
            }
            for (live_caps.cap_specs) |spec| {
                if (!contains(spec.name, query)) continue;
                if (count == max_search_results) {
                    truncated = true;
                    break :scan;
                }
                try appendFmtLine(&out, allocator, server_name, requester, topic, &first, "Capability {s}; use CAP LS for current availability.", .{spec.name});
                count += 1;
            }
        }
        if (count == 0) try appendClipped(&out, allocator, server_name, requester, topic, "No matching help topics.", &first);
        if (truncated) try appendClipped(&out, allocator, server_name, requester, topic, "More matches exist; refine the search.", &first);
    }
    try help_db.appendRplEndOfHelp(&out, allocator, server_name, requester, topic);
    return out.toOwnedSlice(allocator);
}

// ----------------------------------------------------------------- tests

const t = std.testing;
const registered_caps = registry.DispatchCaps{ .registered = true, .oper = false, .ircx = true };
const oper_caps = registry.DispatchCaps{ .registered = true, .oper = true, .ircx = true };

fn countLines(reply: []const u8, code: []const u8) usize {
    var n: usize = 0;
    var lines = std.mem.splitSequence(u8, reply, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, ' ');
        _ = parts.next();
        if (std.mem.eql(u8, parts.next() orelse "", code)) n += 1;
    }
    return n;
}

fn expectFramed(reply: []const u8) !void {
    try t.expect(std.mem.startsWith(u8, reply, ":irc.example 704 alice "));
    try t.expect(std.mem.endsWith(u8, reply, "\r\n"));
    try t.expectEqual(@as(usize, 1), countLines(reply, "704"));
    try t.expectEqual(@as(usize, 1), countLines(reply, "706"));
    try t.expectEqual(@as(usize, 0), countLines(reply, "524"));
    var lines = std.mem.splitSequence(u8, reply, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try t.expect(line.len + 2 <= max_line_bytes);
    }
}

fn helpFor(topic: []const u8, caps: registry.DispatchCaps) ![]u8 {
    return buildHelpReply(t.allocator, "irc.example", "alice", topic, caps);
}

test "help catalog: every registry command and alias gets a 704..706 reply never 524" {
    for (Live.commands) |entry| {
        const spec = entry.spec;
        const reply = try helpFor(spec.name, oper_caps);
        defer t.allocator.free(reply);
        try expectFramed(reply);
        if (help_db.lookup(spec.name) == null) {
            const start = try std.fmt.allocPrint(t.allocator, ":irc.example 704 alice {s} :{s}", .{ spec.name, spec.name });
            defer t.allocator.free(start);
            try t.expect(std.mem.startsWith(u8, reply, start));
        }
        if (spec.summary.len != 0) try t.expect(std.mem.indexOf(u8, reply, spec.summary) != null);
        for (spec.aliases) |alias| {
            const via_alias = try helpFor(alias, oper_caps);
            defer t.allocator.free(via_alias);
            try expectFramed(via_alias);
            if (spec.summary.len != 0) try t.expect(std.mem.indexOf(u8, via_alias, spec.summary) != null);
        }
    }
}

test "help catalog: alias lookup resolves to the canonical reply and lists aliases" {
    const reply = try helpFor("modlist", oper_caps);
    defer t.allocator.free(reply);
    try expectFramed(reply);
    try t.expect(std.mem.indexOf(u8, reply, " 704 alice MODULES :") != null);
    try t.expect(std.mem.indexOf(u8, reply, "Aliases: ") != null);
    try t.expect(std.mem.indexOf(u8, reply, "MODLIST") != null);
    const canonical = Live.lookupCommand("MODLIST") orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings("MODULES", canonical.spec.name);
}

test "help catalog: query matches registry names aliases and summaries without echo or duplicates" {
    const discover = try helpFor("?discover", oper_caps);
    defer t.allocator.free(discover);
    try t.expect(std.mem.indexOf(u8, discover, "SEARCH :COMMANDS: ") != null);
    try t.expect(std.mem.indexOf(u8, discover, "?discover") == null);

    const alias_hit = try helpFor("?modlist", oper_caps);
    defer t.allocator.free(alias_hit);
    try t.expect(std.mem.indexOf(u8, alias_hit, "MODULES") != null);

    // A command that has a hand-written topic is listed once, not twice.
    const join = try helpFor("?JOIN", oper_caps);
    defer t.allocator.free(join);
    var joined: usize = 0;
    var lines = std.mem.splitSequence(u8, join, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "SEARCH :JOIN: ") != null) joined += 1;
    }
    try t.expectEqual(@as(usize, 1), joined);

    const echoed = try helpFor("?ZzUnKnOwNzZ", oper_caps);
    defer t.allocator.free(echoed);
    try t.expect(std.mem.indexOf(u8, echoed, "No matching help topics.") != null);
    try t.expect(std.mem.indexOf(u8, echoed, "ZzUnKnOwNzZ") == null);
}

test "help catalog: search is bounded and rejects hostile terms" {
    const broad = try helpFor("?e", oper_caps);
    defer t.allocator.free(broad);
    try t.expect(countLines(broad, "705") <= max_search_results + 1);
    try t.expect(std.mem.indexOf(u8, broad, "More matches exist; refine the search.") != null);

    const empty = try helpFor("?", oper_caps);
    defer t.allocator.free(empty);
    try t.expect(std.mem.indexOf(u8, empty, "Enter a search term") != null);

    const long_query: [max_query_len + 2]u8 = .{'?'} ++ @as([max_query_len + 1]u8, @splat('a'));
    const long = try helpFor(&long_query, oper_caps);
    defer t.allocator.free(long);
    try t.expect(std.mem.indexOf(u8, long, "Invalid search term") != null);
    try t.expect(std.mem.indexOf(u8, long, "aaaa") == null);

    const ctl = try helpFor("?a\x01b", oper_caps);
    defer t.allocator.free(ctl);
    try t.expect(std.mem.indexOf(u8, ctl, "Invalid search term") != null);
    try t.expect(std.mem.indexOf(u8, ctl, "\x01") == null);
}

test "help catalog: hostile server or requester framing fails closed" {
    try t.expectError(error.InvalidParam, buildHelpReply(t.allocator, "irc.example", "bad nick", "?join", oper_caps));
    try t.expectError(error.InvalidParam, buildHelpReply(t.allocator, "irc.example", &@as([500]u8, @splat('a')), "?join", oper_caps));
    try t.expectError(error.InvalidParam, buildHelpReply(t.allocator, "", "alice", "MODULES", oper_caps));
}

test "help catalog: unknown topics and capabilities keep help_db behaviour" {
    const missing = try helpFor("NOSUCHTOPIC", oper_caps);
    defer t.allocator.free(missing);
    try t.expect(std.mem.indexOf(u8, missing, " 524 ") != null);
    const cap = try helpFor(live_caps.cap_specs[0].name, oper_caps);
    defer t.allocator.free(cap);
    try t.expect(std.mem.indexOf(u8, cap, "Known capability definition.") != null);
}

test "help catalog: unavailable commands name the missing support" {
    const modules_reg = try helpFor("MODULES", registered_caps);
    defer t.allocator.free(modules_reg);
    try t.expect(std.mem.indexOf(u8, modules_reg, "requires operator privileges") != null);
    const modules_oper = try helpFor("MODULES", oper_caps);
    defer t.allocator.free(modules_oper);
    try t.expect(std.mem.indexOf(u8, modules_oper, "Unavailable") == null);

    const prop_plain = try helpFor("PROP", .{ .registered = true, .oper = false, .ircx = false });
    defer t.allocator.free(prop_plain);
    try t.expect(std.mem.indexOf(u8, prop_plain, "requires IRCX") != null);
    const prop_ircx = try helpFor("PROP", registered_caps);
    defer t.allocator.free(prop_ircx);
    try t.expect(std.mem.indexOf(u8, prop_ircx, "Unavailable") == null);

    const unreg = try helpFor("JOIN", .{ .registered = false, .oper = false });
    defer t.allocator.free(unreg);
    try t.expect(std.mem.indexOf(u8, unreg, "requires completed registration") != null);

    var featured: ?registry.CommandEntry = null;
    for (Live.commands) |entry| {
        if (entry.spec.feature != null and entry.spec.access != .oper and featured == null) featured = entry;
    }
    const f = featured orelse return error.TestUnexpectedResult;
    const off = registry.DispatchCaps{
        .registered = true,
        .oper = true,
        .ircx = true,
        .disabled_features = &.{f.spec.feature.?},
    };
    const disabled = try helpFor(f.spec.name, off);
    defer t.allocator.free(disabled);
    try t.expect(std.mem.indexOf(u8, disabled, "disabled by server configuration") != null);
}

const GateProbe = struct {
    denied_index: usize,
    fn allowed(ctx: *const anyopaque, module_index: usize) bool {
        const self: *const GateProbe = @ptrCast(@alignCast(ctx));
        return module_index != self.denied_index;
    }
    fn gate(self: *const GateProbe) registry.ModuleGate {
        return .{ .ctx = self, .available = allowed };
    }
};

test "help catalog: a denying module gate reports module not running" {
    const probe = GateProbe{ .denied_index = Live.lookupCommand("MODULES").?.module_index };
    const caps = registry.DispatchCaps{ .registered = true, .oper = true, .ircx = true, .module_gate = probe.gate() };
    const reply = try helpFor("MODULES", caps);
    defer t.allocator.free(reply);
    try t.expect(std.mem.indexOf(u8, reply, "module not running") != null);
    // Other modules stay available.
    const other = try helpFor("PING", caps);
    defer t.allocator.free(other);
    try t.expect(std.mem.indexOf(u8, other, "Unavailable") == null);
}

const ProbeCtx = struct { ran: usize = 0 };

fn probeHandler(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const self: *ProbeCtx = @ptrCast(@alignCast(ctx));
    self.ran += 1;
}

const probe_module = registry.Module{
    .id = "help_catalog.probe",
    .commands = &.{
        .{ .name = "PLAINCMD", .access = .any, .handler = probeHandler },
        .{ .name = "REGCMD", .access = .registered, .handler = probeHandler },
        .{ .name = "OPERCMD", .access = .oper, .handler = probeHandler },
        .{ .name = "FEATCMD", .access = .oper, .feature = "probe", .handler = probeHandler },
        .{ .name = "PROP", .access = .oper, .handler = probeHandler },
        .{ .name = "WHISPER", .access = .registered, .feature = "probe", .handler = probeHandler },
    },
};

test "help catalog: availability agrees with dispatchGated denial order under a caps matrix" {
    const Reg = registry.Registry(&.{probe_module});
    var ctx = ProbeCtx{};
    const gate_probe_open = GateProbe{ .denied_index = std.math.maxInt(usize) };
    const gate_probe_shut = GateProbe{ .denied_index = 0 };
    const features = [_][]const []const u8{ &.{}, &.{"probe"} };
    const gates = [_]?registry.ModuleGate{ null, gate_probe_open.gate(), gate_probe_shut.gate() };
    var checked: usize = 0;
    for ([_]bool{ false, true }) |registered| {
        for ([_]bool{ false, true }) |is_oper| {
            for ([_]bool{ false, true }) |ircx| {
                for (features) |disabled| {
                    for (gates) |gate| {
                        const caps = registry.DispatchCaps{
                            .registered = registered,
                            .oper = is_oper,
                            .ircx = ircx,
                            .disabled_features = disabled,
                            .module_gate = gate,
                        };
                        for (Reg.commands) |entry| {
                            const got = availability(entry, caps);
                            const result = try Reg.dispatchGated(&ctx, entry.spec.name, &.{}, caps);
                            const expected: Availability = switch (result) {
                                .handled => .available,
                                .disabled => if (gate != null and !gate.?.allows(entry.module_index)) .module_not_running else .feature_disabled,
                                .denied => |why| switch (why) {
                                    .needs_ircx => .requires_ircx,
                                    .needs_oper => .requires_oper,
                                    .needs_registered => .requires_registration,
                                },
                                .not_found, .too_few_params => return error.TestUnexpectedResult,
                            };
                            try t.expectEqual(expected, got);
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    try t.expectEqual(@as(usize, 2 * 2 * 2 * 2 * 3 * Reg.commands.len), checked);
}

test "help catalog: availability agrees with commandAvailable for every live command" {
    const gate_open = GateProbe{ .denied_index = std.math.maxInt(usize) };
    const matrix = [_]registry.DispatchCaps{
        .{ .registered = false, .oper = false },
        .{ .registered = true, .oper = false },
        .{ .registered = true, .oper = false, .ircx = true },
        .{ .registered = true, .oper = true, .ircx = true },
        .{ .registered = true, .oper = true, .ircx = true, .module_gate = gate_open.gate() },
    };
    for (matrix) |caps| {
        for (Live.commands) |entry| {
            const runnable = registry.commandAvailable(entry.spec, caps);
            try t.expectEqual(runnable, availability(entry, caps) == .available);
        }
    }
}

test "help catalog: availability text has no existence oracle phrases" {
    const forbidden = [_][]const u8{
        "does not exist",  "no such channel",   "no such account",
        "no such session", "is not registered", "not registered",
    };
    for (std.enums.values(Availability)) |value| {
        if (value.text()) |line| {
            for (forbidden) |phrase| try t.expect(!contains(line, phrase));
        }
    }
    for (Live.commands) |entry| {
        const reply = try helpFor(entry.spec.name, .{ .registered = false, .oper = false });
        defer t.allocator.free(reply);
        // Hand-written topics may carry their own conditional next-step text;
        // only the registry-derived Unavailable line is policed here.
        var lines = std.mem.splitSequence(u8, reply, "\r\n");
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, ":Unavailable:") == null) continue;
            for (forbidden) |phrase| try t.expect(!contains(line, phrase));
        }
    }
}

test "help catalog: every static topic is a registry command, capability or listed concept" {
    const Concept = struct { topic: []const u8, reason: []const u8 };
    const concepts = [_]Concept{
        // Filled from the observed drift; each entry pins why it is not a command.
    };
    var failures: usize = 0;
    var commands_seen: usize = 0;
    for (help_db.topics()) |topic| {
        if (Live.lookupCommand(topic.topic) != null) {
            commands_seen += 1;
            continue;
        }
        var is_cap = false;
        for (live_caps.cap_specs) |spec| {
            if (std.ascii.eqlIgnoreCase(spec.name, topic.topic)) is_cap = true;
        }
        if (is_cap) continue;
        var listed = false;
        for (concepts) |c| {
            if (std.ascii.eqlIgnoreCase(c.topic, topic.topic)) {
                try t.expect(c.reason.len != 0);
                listed = true;
            }
        }
        if (!listed) {
            std.debug.print("help topic {s} is not a command, capability or listed concept\n", .{topic.topic});
            failures += 1;
        }
    }
    for (concepts) |c| {
        // A concept entry that became a command must be dropped.
        try t.expect(Live.lookupCommand(c.topic) == null);
        try t.expect(help_db.lookup(c.topic) != null);
    }
    try t.expectEqual(@as(usize, 0), failures);
    // Non-vacuous: most hand-written topics are registry commands.
    try t.expect(commands_seen * 2 > help_db.topics().len);
}

fn requiredArgs(usage: []const u8) usize {
    var depth: usize = 0;
    var count: usize = 0;
    for (usage) |ch| switch (ch) {
        '[' => depth += 1,
        ']' => depth -|= 1,
        '<' => if (depth == 0) {
            count += 1;
        },
        else => {},
    };
    return count;
}

test "help catalog: static usage arity covers the registry min_params gate" {
    const Exempt = struct { topic: []const u8, reason: []const u8 };
    const exempt = [_]Exempt{
        // Filled from the observed drift; each entry pins why usage differs.
    };
    var failures: usize = 0;
    var compared: usize = 0;
    var gated: usize = 0;
    for (help_db.topics()) |topic| {
        const entry = Live.lookupCommand(topic.topic) orelse continue;
        compared += 1;
        if (entry.spec.min_params != 0) gated += 1;
        const required = requiredArgs(topic.lines[0]);
        if (required >= entry.spec.min_params) continue;
        var listed = false;
        for (exempt) |e| {
            if (std.ascii.eqlIgnoreCase(e.topic, topic.topic)) {
                try t.expect(e.reason.len != 0);
                listed = true;
            }
        }
        if (!listed) {
            std.debug.print("help topic {s} usage shows {d} required args but min_params is {d}: {s}\n", .{ topic.topic, required, entry.spec.min_params, topic.lines[0] });
            failures += 1;
        }
    }
    for (exempt) |e| {
        const entry = Live.lookupCommand(e.topic) orelse return error.TestUnexpectedResult;
        const topic = help_db.lookup(e.topic) orelse return error.TestUnexpectedResult;
        // Stale exemption: usage now covers the gate.
        try t.expect(requiredArgs(topic.lines[0]) < entry.spec.min_params);
    }
    try t.expectEqual(@as(usize, 0), failures);
    try t.expect(compared > 30);
    try t.expect(gated >= 3);
}

test "help catalog: required argument counter ignores optional and nested brackets" {
    try t.expectEqual(@as(usize, 1), requiredArgs("JOIN <channel>[,<channel>] [key[,key]]"));
    try t.expectEqual(@as(usize, 2), requiredArgs("MODE <target> <modes> [params]"));
    try t.expectEqual(@as(usize, 0), requiredArgs("HELP [topic]"));
}

test "help catalog: allocation failure at every index frees everything" {
    const topics = [_][]const u8{ "MODULES", "modlist", "JOIN", "?discover", "?e" };
    for (topics) |topic| {
        var index: usize = 0;
        while (true) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = index });
            const result = buildHelpReply(failing.allocator(), "irc.example", "alice", topic, registered_caps);
            if (result) |reply| {
                failing.allocator().free(reply);
                try t.expect(!failing.has_induced_failure);
                break;
            } else |err| {
                try t.expectEqual(error.OutOfMemory, err);
                try t.expect(failing.has_induced_failure);
            }
        }
        try t.expect(index > 0);
    }
}
