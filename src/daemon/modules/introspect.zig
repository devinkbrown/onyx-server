// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! diag.introspect module — MODULES / COMMANDS / OROWASM operator introspection.
//!
//! `MODULES` reports what the comptime SerpentRegistry assembled *and* what the
//! lifecycle driver has done with it at runtime: modules in dependency-resolved
//! load order with version, category, priority, runtime state, and the surface
//! each one contributes, plus a per-module detail view carrying dependencies,
//! conflicts, config blocks, reload/rollback counters, and the last phase
//! failure. Reads the comptime tables on `module_manifest.Live` and the runtime
//! health table on `module_lifecycle.Lifecycle`.
//!
//! `MODULES` is gated at the registry gate (`access = .oper`), not only inside
//! the handler, so the arity/access refusal is uniform with every other command.
//! See docs/architecture/MODULE-SYSTEM.md.
const std = @import("std");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");
const module_lifecycle = @import("../module_lifecycle.zig");
const module_manifest = @import("manifest.zig");
const wasm_abi = @import("../../wasm/host/abi.zig");
const wasm_bridge = @import("../../wasm/host/bridge.zig");

const Core = module_core.Core;

/// Runtime health view over exactly the live module set.
const Life = module_lifecycle.Lifecycle(&module_manifest.enabled);

/// Render `items` as a comma-separated list into `buf`, or "-" when empty.
/// Truncates with a trailing "..." rather than failing: this is an operator
/// display, and a clipped dependency list is better than no line at all.
fn writeList(buf: []u8, items: []const []const u8) []const u8 {
    if (items.len == 0) return "-";
    var used: usize = 0;
    for (items, 0..) |item, i| {
        const sep: usize = if (i == 0) 0 else 2;
        if (used + sep + item.len > buf.len) {
            // No room for this entry: mark truncation if we can.
            if (used + 3 <= buf.len) {
                @memcpy(buf[used..][0..3], "...");
                used += 3;
            }
            break;
        }
        if (i != 0) {
            @memcpy(buf[used..][0..2], ", ");
            used += 2;
        }
        @memcpy(buf[used..][0..item.len], item);
        used += item.len;
    }
    return buf[0..used];
}

/// MODULES [<id>] — module topology and lifecycle health.
fn modules(ctx: *anyopaque, inv: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);

    // Detail form: MODULES <id>.
    if (inv.params.len >= 1 and inv.params[0].len != 0) {
        const want = inv.params[0];
        inline for (module_manifest.enabled, 0..) |m, mi| {
            if (std.ascii.eqlIgnoreCase(m.id, want)) {
                const h = Life.health(mi);
                var buf: [400]u8 = undefined;
                var list_buf: [220]u8 = undefined;

                try core.reply(.RPL_INFOSTART, &.{}, std.fmt.bufPrint(&buf, "Module {s} v{d}.{d}.{d}", .{
                    m.id, m.version.major, m.version.minor, m.version.patch,
                }) catch m.id);

                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  category={s} priority={s} load_position={d} state={s}", .{
                    @tagName(m.category), @tagName(m.priority), h.load_position, h.state.token(),
                }) catch return);

                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  requires: {s}", .{
                    writeList(&list_buf, m.requires),
                }) catch return);
                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  optional: {s}", .{
                    writeList(&list_buf, m.optional_requires),
                }) catch return);
                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  conflicts: {s}", .{
                    writeList(&list_buf, m.conflicts),
                }) catch return);
                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  config blocks: {s}", .{
                    writeList(&list_buf, m.config_blocks),
                }) catch return);

                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  surface: {d} cmds, {d} caps, {d} hooks, {d} numerics, {d} stats", .{
                    m.commands.len, m.caps.len, m.hooks.len, m.numerics.len, m.stats.len,
                }) catch return);

                try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  reloads={d} rollbacks={d}", .{
                    h.reload_count, h.rollback_count,
                }) catch return);

                if (h.last_error) |err| {
                    try core.reply(.RPL_INFO, &.{}, std.fmt.bufPrint(&buf, "  last failure: {s} during {s}", .{
                        @errorName(err),
                        if (h.failed_phase) |p| p.token() else "unknown",
                    }) catch return);
                }

                try core.reply(.RPL_ENDOFINFO, &.{}, "End of MODULES");
                return;
            }
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "No such module");
        return;
    }

    try core.reply(.RPL_INFOSTART, &.{}, "SerpentRegistry - modules in load order");
    var buf: [400]u8 = undefined;

    // Dependency-resolved order, so the listing reads the way the daemon
    // actually brings modules up rather than in manifest order.
    inline for (Life.load_order) |mi| {
        const m = module_manifest.enabled[mi];
        const h = Life.health(mi);
        const line = std.fmt.bufPrint(&buf, "[{d}] {s} v{d}.{d}.{d} {s}/{s} state={s} {d} cmds, {d} caps, {d} hooks{s}", .{
            h.load_position,
            m.id,
            m.version.major,
            m.version.minor,
            m.version.patch,
            @tagName(m.category),
            @tagName(m.priority),
            h.state.token(),
            m.commands.len,
            m.caps.len,
            m.hooks.len,
            if (h.degraded()) " DEGRADED" else "",
        }) catch "module (format error)";
        try core.reply(.RPL_INFO, &.{}, line);
    }

    if (!Life.engaged()) {
        // Distinguish "nothing has been driven" from "everything is unhealthy":
        // the daemon still runs its own inline lifecycle sweep, so an unengaged
        // driver means unloaded states are expected, not a fault.
        try core.reply(.RPL_INFO, &.{}, "note: lifecycle driver not engaged; states reflect no driven phase");
    }

    const summary = std.fmt.bufPrint(&buf, "{d} modules, {d} commands, {d} aliases, {d} hooks, {d} degraded", .{
        module_manifest.enabled.len,
        module_manifest.Live.commands.len,
        module_manifest.Live.alias_count,
        module_manifest.Live.hooks.len,
        Life.degradedCount(),
    }) catch "summary (format error)";
    try core.reply(.RPL_ENDOFINFO, &.{}, summary);
}

/// COMMANDS — registry-driven command discovery. With no argument, list the
/// command names the caller may currently run (respecting access + feature
/// gates). With `COMMANDS <name>`, show that command's declarative metadata.
fn commands(ctx: *anyopaque, inv: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    const caps = registry.DispatchCaps{
        .registered = core.conn.session.registered(),
        .oper = core.conn.session.isOper(),
        .disabled_features = core.services.config.disabled_features,
    };

    // Detail form: COMMANDS <name>.
    if (inv.params.len >= 1 and inv.params[0].len != 0) {
        const want = inv.params[0];
        for (module_manifest.Live.commands) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.spec.name, want)) continue;
            const avail = registry.commandAvailable(entry.spec, caps);
            var buf: [320]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "{s} [{s}] access={s}{s}{s} params>={d} {s}{s}", .{
                entry.spec.name,
                entry.module_id,
                entry.spec.access.token(),
                if (entry.spec.feature) |_| " feature=" else "",
                entry.spec.feature orelse "",
                entry.spec.min_params,
                if (avail) "" else "(unavailable) ",
                entry.spec.summary,
            }) catch return;
            try core.reply(.RPL_INFO, &.{}, line);
            try core.reply(.RPL_ENDOFINFO, &.{}, "End of COMMANDS");
            return;
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "No such command");
        return;
    }

    // List form: compact, several names per line, only what the caller can run.
    try core.reply(.RPL_INFOSTART, &.{}, "Commands available to you");
    var buf: [400]u8 = undefined;
    var used: usize = 0;
    for (module_manifest.Live.commands) |entry| {
        if (!registry.commandAvailable(entry.spec, caps)) continue;
        const name = entry.spec.name;
        if (used + name.len + 1 > buf.len) {
            try core.reply(.RPL_INFO, &.{}, buf[0..used]);
            used = 0;
        }
        @memcpy(buf[used..][0..name.len], name);
        used += name.len;
        buf[used] = ' ';
        used += 1;
    }
    if (used > 0) try core.reply(.RPL_INFO, &.{}, buf[0 .. used - 1]);
    try core.reply(.RPL_ENDOFINFO, &.{}, "End of COMMANDS");
}

/// OROWASM [STATUS|ABI|WIT|PLUGINS] — oper runtime view of the OroWasm host ABI,
/// resource budgets, allowed host capabilities, and loaded plugin registrations.
fn orowasm(ctx: *anyopaque, inv: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    const view = if (inv.params.len >= 1 and inv.params[0].len != 0) inv.params[0] else "STATUS";
    const info = core.server.wasm.runtimeInfo();

    var caps_buf: [128]u8 = undefined;
    const caps = info.allowed_caps.writeTokens(&caps_buf);
    var intents_buf: [128]u8 = undefined;
    const intents = info.allowed_intents.writeTokens(&intents_buf);
    var line: [512]u8 = undefined;

    if (std.ascii.eqlIgnoreCase(view, "STATUS")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm runtime status");
        const status = std.fmt.bufPrint(&line, "plugins={d} commands={d} hooks={d} allowed_caps={s} allowed_intents={s} registry_pins={d} signed_pins={d} revoked_hashes={d} disabled_plugins={d} blocked_loads={d} plugin_dir={s}", .{
            info.plugin_count,
            info.command_count,
            info.hook_count,
            if (caps.len == 0) "(none)" else caps,
            if (intents.len == 0) "(none)" else intents,
            info.registry_pin_count,
            info.signed_registry_pin_count,
            info.revoked_hash_count,
            info.disabled_plugin_count,
            info.blocked_load_count,
            if (core.services.config.wasm_plugin_dir.len == 0) "(disabled)" else core.services.config.wasm_plugin_dir,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, status);
        const budgets = std.fmt.bufPrint(&line, "budgets max_plugin_bytes={d} max_memory_bytes={d} default_fuel={d}", .{
            info.max_plugin_bytes,
            info.max_memory_bytes,
            info.default_fuel,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, budgets);
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    if (std.ascii.eqlIgnoreCase(view, "ABI")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm ABI");
        const schema = std.fmt.bufPrint(&line, "manifest_schema={d}.{d} host_functions={d} allowed_caps={s} allowed_intents={s}", .{
            info.manifest_schema.major,
            info.manifest_schema.minor,
            info.host_function_count,
            if (caps.len == 0) "(none)" else caps,
            if (intents.len == 0) "(none)" else intents,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, schema);
        for (wasm_abi.host_functions) |func| {
            const row = std.fmt.bufPrint(&line, "hostcall {s} v{d}.{d} cap={s} min_tier={s}", .{
                func.name,
                func.version.major,
                func.version.minor,
                func.capability.token(),
                wasm_bridge.minTrustTierForCapability(func.capability).token(),
            }) catch continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        for (wasm_abi.all_intents) |intent| {
            const row = std.fmt.bufPrint(&line, "intent {s} min_tier={s}", .{
                intent.token(),
                wasm_bridge.minTrustTierForIntent(intent).token(),
            }) catch continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    if (std.ascii.eqlIgnoreCase(view, "WIT")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm ABI WIT v1");
        var it = std.mem.splitScalar(u8, wasm_abi.wit_v1, '\n');
        while (it.next()) |raw| {
            const row = std.mem.trim(u8, raw, "\r");
            if (row.len == 0) continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    if (std.ascii.eqlIgnoreCase(view, "PLUGINS")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm plugins");
        var i: usize = 0;
        while (core.server.wasm.pluginSummary(i)) |plugin| : (i += 1) {
            var grant_buf: [128]u8 = undefined;
            const grants = plugin.grants.writeTokens(&grant_buf);
            var intent_buf: [128]u8 = undefined;
            const granted_intents = plugin.intents.writeTokens(&intent_buf);
            const row = std.fmt.bufPrint(&line, "handle={d} name={s} tier={s} signed={s} commands={d} hooks={d} grants={s} intents={s}", .{
                plugin.handle,
                plugin.name,
                plugin.trust_tier.token(),
                if (plugin.publisher_signed) "true" else "false",
                plugin.command_count,
                plugin.hook_count,
                if (grants.len == 0) "(none)" else grants,
                if (granted_intents.len == 0) "(none)" else granted_intents,
            }) catch continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        if (i == 0) try core.reply(.RPL_INFO, &.{}, "no plugins loaded");
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    try core.reply(.RPL_ENDOFINFO, &.{}, "Usage: OROWASM [STATUS|ABI|WIT|PLUGINS]");
}

pub const module = registry.Module{
    .id = "diag.introspect",
    .category = .diagnostic,
    .commands = &.{
        .{
            .name = "MODULES",
            .access = .oper,
            .handler = modules,
            .aliases = &.{"MODLIST"},
            .category = .diagnostic,
            .warden_class = .free,
            .summary = "list loaded registry modules and lifecycle health",
            .help_long =
            \\MODULES            list every loaded module in dependency-resolved
            \\                   load order with version, category, priority,
            \\                   runtime state, and its command/cap/hook surface
            \\MODULES <id>       detail for one module: dependencies, conflicts,
            \\                   config blocks, reload/rollback counts, and the
            \\                   most recent lifecycle failure
            \\
            \\MODLIST is an alias of MODULES.
            ,
        },
        .{ .name = "COMMANDS", .access = .any, .handler = commands, .summary = "discover commands you can run" },
        .{ .name = "OROWASM", .access = .oper, .handler = orowasm, .summary = "inspect OroWasm ABI, WIT, budgets, and plugins" },
    },
};

test "introspect module declares MODULES and OROWASM, and the registry is visible" {
    var saw_modules = false;
    var saw_orowasm = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "MODULES")) saw_modules = true;
        if (std.ascii.eqlIgnoreCase(c.name, "OROWASM")) saw_orowasm = true;
    }
    try std.testing.expect(saw_modules);
    try std.testing.expect(saw_orowasm);
    try std.testing.expect(module_manifest.enabled.len >= 1);
}

test "introspect: MODLIST is a real alias of MODULES, not a second command row" {
    const Live = module_manifest.Live;

    // Both names resolve, and to the SAME canonical row.
    const via_name = Live.lookupCommand("MODULES") orelse return error.MissingCommand;
    const via_alias = Live.lookupCommand("MODLIST") orelse return error.MissingAlias;
    try std.testing.expectEqualStrings(via_name.spec.name, via_alias.spec.name);
    try std.testing.expectEqual(via_name.spec.handler, via_alias.spec.handler);

    // The alias is reported as an alias; the canonical name is not.
    try std.testing.expect(Live.isAlias("MODLIST"));
    try std.testing.expect(!Live.isAlias("MODULES"));

    // And MODLIST must NOT occupy its own row in the command table, or
    // COMMANDS would list the same verb twice.
    var rows: usize = 0;
    for (Live.commands) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.spec.name, "MODLIST")) rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), rows);
}

test "introspect: MODULES is oper-gated at the registry gate, not only in the handler" {
    const Live = module_manifest.Live;
    const entry = Live.lookupCommand("MODULES") orelse return error.MissingCommand;
    try std.testing.expectEqual(registry.Access.oper, entry.spec.access);

    // A registered non-oper is refused by the gate itself.
    const plain = registry.DispatchCaps{ .registered = true, .oper = false };
    try std.testing.expect(!registry.commandAvailable(entry.spec, plain));

    // The alias inherits the same gate — an alias must never be a weaker door.
    const alias = Live.lookupCommand("MODLIST") orelse return error.MissingAlias;
    try std.testing.expectEqual(registry.Access.oper, alias.spec.access);
    try std.testing.expect(!registry.commandAvailable(alias.spec, plain));
}

test "introspect: the lifecycle view covers exactly the live module set in load order" {
    const table = Life.healthTable();
    try std.testing.expectEqual(module_manifest.enabled.len, table.len);

    // load_order is a permutation of the manifest indices, and each health row
    // agrees with the position the driver assigned it.
    var seen: [module_manifest.enabled.len]bool = @splat(false);
    for (Life.load_order, 0..) |mi, position| {
        try std.testing.expect(!seen[mi]);
        seen[mi] = true;
        try std.testing.expectEqual(position, Life.health(mi).load_position);
    }
    for (seen) |s| try std.testing.expect(s);

    // Nothing has driven a phase in a unit test, so the display must say so
    // rather than implying every module is broken.
    try std.testing.expect(!Life.engaged());
    try std.testing.expectEqual(@as(usize, 0), Life.degradedCount());
}

test "introspect: writeList renders empty, single, multiple, and over-long lists" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("-", writeList(&buf, &.{}));
    try std.testing.expectEqualStrings("core", writeList(&buf, &.{"core"}));
    try std.testing.expectEqualStrings("core, proto", writeList(&buf, &.{ "core", "proto" }));

    // Over-long input is clipped with an ellipsis, never overrun.
    const many: []const []const u8 = &.{ "aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "dddddddddd" };
    const out = writeList(&buf, many);
    try std.testing.expect(out.len <= buf.len);
    try std.testing.expect(std.mem.endsWith(u8, out, "..."));
}
