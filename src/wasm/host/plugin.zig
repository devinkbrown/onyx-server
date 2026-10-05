// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OroWasm plugin store lifecycle and hostcall capability enforcement.
//!
//! The host owns every registration keyed by `PluginHandle`. Dropping a plugin
//! removes its command/hook rows and deinitializes its interpreter instance; no
//! guest pointer or executable mapping survives teardown.
const std = @import("std");
const abi = @import("abi.zig");
const interp = @import("interp.zig");
const registry = @import("../../daemon/registry.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PluginHandle = u32;

pub const Error = error{
    IncompatibleManifest,
    UnknownPlugin,
    UnknownHostFunction,
    CapabilityDenied,
} || std.mem.Allocator.Error || interp.Error;

pub const Policy = struct {
    allowed_caps: abi.CapabilitySet = .{},
    allowed_intents: abi.IntentSet = .{},
    max_memory_bytes: usize = 64 * 1024,
};

pub const HostCommandRegistration = struct {
    plugin: PluginHandle,
    name: []u8,
    min_params: usize,
    export_name: []u8,

    fn deinit(self: HostCommandRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.export_name);
    }
};

pub const HostHookRegistration = struct {
    plugin: PluginHandle,
    hook: []u8,
    priority: registry.HookPriority,
    export_name: []u8,

    fn deinit(self: HostHookRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.hook);
        allocator.free(self.export_name);
    }
};

const LoadedPlugin = struct {
    handle: PluginHandle,
    name: []u8,
    wasm: []u8,
    grants: abi.CapabilitySet,
    intents: abi.IntentSet,
    instance: interp.Instance,

    fn deinit(self: *LoadedPlugin, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        std.crypto.secureZero(u8, self.wasm);
        allocator.free(self.wasm);
        std.crypto.secureZero(u8, self.instance.memory);
        self.instance.deinit();
        self.* = undefined;
    }
};

/// Borrowed only while the owner is frozen at its Helix cut.
pub const CheckpointPlugin = struct {
    handle: PluginHandle,
    name: []const u8,
    wasm: []const u8,
    memory: []const u8,
};

pub const CheckpointState = struct {
    next_handle: PluginHandle,
    deterministic_rand: u64,
};

pub const HostcallResult = union(enum) {
    none,
    i64: i64,
    bytes_written: usize,
};

pub const PluginStore = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    next_handle: PluginHandle = 1,
    plugins: std.ArrayList(LoadedPlugin) = .empty,
    commands: std.ArrayList(HostCommandRegistration) = .empty,
    hooks: std.ArrayList(HostHookRegistration) = .empty,
    deterministic_rand: u64 = 0x6d697a75636869,

    pub fn init(allocator: std.mem.Allocator, policy: Policy) PluginStore {
        return .{ .allocator = allocator, .policy = policy };
    }

    pub fn deinit(self: *PluginStore) void {
        for (self.commands.items) |reg| reg.deinit(self.allocator);
        for (self.hooks.items) |reg| reg.deinit(self.allocator);
        for (self.plugins.items) |*plugin| plugin.deinit(self.allocator);
        self.commands.deinit(self.allocator);
        self.hooks.deinit(self.allocator);
        self.plugins.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn load(self: *PluginStore, manifest: abi.PluginManifest, wasm: []const u8) Error!PluginHandle {
        return self.loadWithAllowedCaps(manifest, wasm, self.policy.allowed_caps);
    }

    pub fn loadWithAllowedCaps(self: *PluginStore, manifest: abi.PluginManifest, wasm: []const u8, allowed_caps: abi.CapabilitySet) Error!PluginHandle {
        return self.loadWithPolicy(manifest, wasm, allowed_caps, self.policy.allowed_intents);
    }

    pub fn loadWithPolicy(self: *PluginStore, manifest: abi.PluginManifest, wasm: []const u8, allowed_caps: abi.CapabilitySet, allowed_intents: abi.IntentSet) Error!PluginHandle {
        const grant = abi.negotiate(manifest, .{ .allowed_caps = allowed_caps, .allowed_intents = allowed_intents });
        if (!grant.manifest_ok) return error.IncompatibleManifest;

        const handle = self.next_handle;
        self.next_handle += 1;
        {
            var instance = try interp.Instance.init(self.allocator, wasm, .{ .max_memory_bytes = self.policy.max_memory_bytes });
            errdefer instance.deinit();
            const name = try self.allocator.dupe(u8, manifest.name);
            errdefer self.allocator.free(name);
            const wasm_copy = try self.allocator.dupe(u8, wasm);
            errdefer self.allocator.free(wasm_copy);
            try self.plugins.append(self.allocator, .{
                .handle = handle,
                .name = name,
                .wasm = wasm_copy,
                .grants = grant.granted_caps,
                .intents = grant.granted_intents,
                .instance = instance,
            });
        }
        errdefer {
            var popped = self.plugins.pop().?;
            popped.deinit(self.allocator);
        }

        errdefer self.removeCommands(handle);
        errdefer self.removeHooks(handle);
        for (manifest.commands) |command| try self.addCommand(handle, command);
        for (manifest.hooks) |hook| try self.addHook(handle, hook);
        return handle;
    }

    pub fn checkpointState(self: *const PluginStore) CheckpointState {
        return .{ .next_handle = self.next_handle, .deterministic_rand = self.deterministic_rand };
    }

    pub fn checkpointPlugin(self: *const PluginStore, index: usize) ?CheckpointPlugin {
        if (index >= self.plugins.items.len) return null;
        const row = self.plugins.items[index];
        return .{ .handle = row.handle, .name = row.name, .wasm = row.wasm, .memory = row.instance.memory };
    }

    /// The staged bridge has parsed and authorized the exact module bytes.
    /// Install only the source's mutable linear memory; module structure stays
    /// derived from that validated module, never from the checkpoint's pointers.
    pub fn restoreCheckpointMemory(self: *PluginStore, index: usize, name: []const u8, wasm: []const u8, memory: []const u8) error{InvalidCheckpoint}!void {
        if (index >= self.plugins.items.len) return error.InvalidCheckpoint;
        const row = &self.plugins.items[index];
        if (!std.mem.eql(u8, row.name, name) or !std.mem.eql(u8, row.wasm, wasm) or row.instance.memory.len != memory.len) return error.InvalidCheckpoint;
        @memcpy(row.instance.memory, memory);
    }

    /// Restore handles after every module is loaded. The two registration
    /// tables refer to the temporary sequential handles until this no-alloc
    /// remap, and a later layout digest verifies their exact source order.
    pub fn restoreCheckpointIdentity(self: *PluginStore, handles: []const PluginHandle, state: CheckpointState) error{InvalidCheckpoint}!void {
        if (handles.len != self.plugins.items.len or state.next_handle == 0) return error.InvalidCheckpoint;
        var max_handle: PluginHandle = 0;
        for (handles, 0..) |handle, index| {
            if (handle == 0 or handle >= state.next_handle) return error.InvalidCheckpoint;
            for (handles[0..index]) |prior| if (prior == handle) return error.InvalidCheckpoint;
            max_handle = @max(max_handle, handle);
        }
        if (handles.len != 0 and state.next_handle <= max_handle) return error.InvalidCheckpoint;
        for (self.plugins.items, 0..) |*row, index| row.handle = handles[index];
        for (self.commands.items) |*row| {
            const index: usize = @intCast(row.plugin - 1);
            if (index >= handles.len) return error.InvalidCheckpoint;
            row.plugin = handles[index];
        }
        for (self.hooks.items) |*row| {
            const index: usize = @intCast(row.plugin - 1);
            if (index >= handles.len) return error.InvalidCheckpoint;
            row.plugin = handles[index];
        }
        self.next_handle = state.next_handle;
        self.deterministic_rand = state.deterministic_rand;
    }

    /// Names, grants, command/hook priority and registration order are part
    /// of execution semantics. The candidate compares this after re-parsing
    /// every original module, before it can publish the staged bridge.
    pub fn checkpointLayoutDigest(self: *const PluginStore) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update("onyx-orowasm-helix-layout-v1");
        digestU64(&hash, self.plugins.items.len);
        for (self.plugins.items) |row| {
            digestU64(&hash, row.handle);
            digestBytes(&hash, row.name);
            digestBytes(&hash, row.wasm);
            digestCaps(&hash, row.grants);
            digestIntents(&hash, row.intents);
        }
        digestU64(&hash, self.commands.items.len);
        for (self.commands.items) |row| {
            digestU64(&hash, row.plugin);
            digestBytes(&hash, row.name);
            digestU64(&hash, row.min_params);
            digestBytes(&hash, row.export_name);
        }
        digestU64(&hash, self.hooks.items.len);
        for (self.hooks.items) |row| {
            digestU64(&hash, row.plugin);
            digestBytes(&hash, row.hook);
            digestU64(&hash, @intFromEnum(row.priority));
            digestBytes(&hash, row.export_name);
        }
        var out: [32]u8 = undefined;
        hash.final(&out);
        return out;
    }

    pub fn unload(self: *PluginStore, handle: PluginHandle) Error!void {
        const index = self.findPluginIndex(handle) orelse return error.UnknownPlugin;
        self.removeCommands(handle);
        self.removeHooks(handle);
        var plugin = self.plugins.swapRemove(index);
        plugin.deinit(self.allocator);
    }

    pub fn callExport(self: *PluginStore, handle: PluginHandle, name: []const u8, args: []const interp.Value, fuel: u64) Error!?interp.Value {
        const plugin = self.findPlugin(handle) orelse return error.UnknownPlugin;
        return plugin.instance.call(name, args, fuel);
    }

    pub fn callExportWithHostcalls(self: *PluginStore, handle: PluginHandle, name: []const u8, args: []const interp.Value, fuel: u64, host: interp.HostCall) Error!?interp.Value {
        const plugin = self.findPlugin(handle) orelse return error.UnknownPlugin;
        return plugin.instance.callWithHostcalls(name, args, fuel, host);
    }

    pub fn hasCapability(self: *const PluginStore, handle: PluginHandle, cap: abi.Capability) Error!bool {
        const plugin = self.findPluginConst(handle) orelse return error.UnknownPlugin;
        return plugin.grants.has(cap);
    }

    pub fn hasIntent(self: *const PluginStore, handle: PluginHandle, intent: abi.Intent) Error!bool {
        const plugin = self.findPluginConst(handle) orelse return error.UnknownPlugin;
        return plugin.intents.has(intent);
    }

    pub fn dispatchHostcall(self: *PluginStore, handle: PluginHandle, name: []const u8, args: []const u64) Error!HostcallResult {
        const plugin = self.findPlugin(handle) orelse return error.UnknownPlugin;
        const func = abi.findHostFunction(name) orelse return error.UnknownHostFunction;
        if (!plugin.grants.has(func.capability)) return error.CapabilityDenied;
        return self.runPermittedHostcall(func, args);
    }

    pub fn commandCount(self: *const PluginStore, handle: PluginHandle) usize {
        var count: usize = 0;
        for (self.commands.items) |reg| {
            if (reg.plugin == handle) count += 1;
        }
        return count;
    }

    pub fn hookCount(self: *const PluginStore, handle: PluginHandle) usize {
        var count: usize = 0;
        for (self.hooks.items) |reg| {
            if (reg.plugin == handle) count += 1;
        }
        return count;
    }

    fn addCommand(self: *PluginStore, handle: PluginHandle, decl: abi.CommandDecl) Error!void {
        const name = try self.allocator.dupe(u8, decl.name);
        errdefer self.allocator.free(name);
        const export_name = try self.allocator.dupe(u8, decl.export_name);
        errdefer self.allocator.free(export_name);
        try self.commands.append(self.allocator, .{
            .plugin = handle,
            .name = name,
            .min_params = decl.min_params,
            .export_name = export_name,
        });
    }

    fn addHook(self: *PluginStore, handle: PluginHandle, decl: abi.HookDecl) Error!void {
        const hook = try self.allocator.dupe(u8, decl.hook);
        errdefer self.allocator.free(hook);
        const export_name = try self.allocator.dupe(u8, decl.export_name);
        errdefer self.allocator.free(export_name);
        try self.hooks.append(self.allocator, .{
            .plugin = handle,
            .hook = hook,
            .priority = toRegistryPriority(decl.priority),
            .export_name = export_name,
        });
    }

    fn removeCommands(self: *PluginStore, handle: PluginHandle) void {
        var i: usize = 0;
        while (i < self.commands.items.len) {
            if (self.commands.items[i].plugin == handle) {
                const reg = self.commands.swapRemove(i);
                reg.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    fn removeHooks(self: *PluginStore, handle: PluginHandle) void {
        var i: usize = 0;
        while (i < self.hooks.items.len) {
            if (self.hooks.items[i].plugin == handle) {
                const reg = self.hooks.swapRemove(i);
                reg.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    fn findPlugin(self: *PluginStore, handle: PluginHandle) ?*LoadedPlugin {
        if (self.findPluginIndex(handle)) |index| return &self.plugins.items[index];
        return null;
    }

    fn findPluginConst(self: *const PluginStore, handle: PluginHandle) ?*const LoadedPlugin {
        if (self.findPluginIndex(handle)) |index| return &self.plugins.items[index];
        return null;
    }

    fn findPluginIndex(self: *const PluginStore, handle: PluginHandle) ?usize {
        for (self.plugins.items, 0..) |plugin, i| {
            if (plugin.handle == handle) return i;
        }
        return null;
    }

    fn runPermittedHostcall(self: *PluginStore, func: abi.HostFunction, args: []const u64) HostcallResult {
        _ = args;
        if (std.mem.eql(u8, func.name, "now_ms")) return .{ .i64 = 0 };
        if (std.mem.eql(u8, func.name, "rand")) {
            self.deterministic_rand = self.deterministic_rand *% 6364136223846793005 +% 1;
            return .{ .i64 = @bitCast(self.deterministic_rand) };
        }
        if (std.mem.eql(u8, func.name, "store_get")) return .{ .bytes_written = 0 };
        if (std.mem.eql(u8, func.name, "net_connect")) return .{ .i64 = -1 };
        return .none;
    }
};

fn digestU64(hash: *Sha256, value: anytype) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn digestBytes(hash: *Sha256, value: []const u8) void {
    digestU64(hash, value.len);
    hash.update(value);
}

fn digestCaps(hash: *Sha256, caps: abi.CapabilitySet) void {
    for (abi.all_capabilities) |cap| {
        const bit = [_]u8{@intFromBool(caps.has(cap))};
        hash.update(&bit);
    }
}

fn digestIntents(hash: *Sha256, intents: abi.IntentSet) void {
    for (abi.all_intents) |intent| {
        const bit = [_]u8{@intFromBool(intents.has(intent))};
        hash.update(&bit);
    }
}

fn toRegistryPriority(priority: abi.HookPriority) registry.HookPriority {
    return switch (priority) {
        .first => .first,
        .early => .early,
        .normal => .normal,
        .late => .late,
        .last => .last,
    };
}

const empty_wasm = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
};

test "load exposes host-owned command and hook registrations" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .hooks }),
    });
    defer store.deinit();

    const manifest = abi.PluginManifest{
        .name = "control",
        .requested_caps = &.{ .reply, .hooks },
        .commands = &.{.{ .name = "PINGME", .export_name = "cmd_pingme" }},
        .hooks = &.{.{ .hook = "client.connect", .export_name = "on_connect" }},
    };
    const handle = try store.load(manifest, &empty_wasm);

    try std.testing.expectEqual(@as(usize, 1), store.commandCount(handle));
    try std.testing.expectEqual(@as(usize, 1), store.hookCount(handle));
}

test "hostcall dispatch enforces granted capabilities" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .net_outbound }),
    });
    defer store.deinit();

    const handle = try store.load(.{
        .name = "limited",
        .requested_caps = &.{ .reply, .time, .net_outbound },
    }, &empty_wasm);

    _ = try store.dispatchHostcall(handle, "reply", &.{});
    try std.testing.expectError(error.CapabilityDenied, store.dispatchHostcall(handle, "now_ms", &.{}));
    const denied_connect = try store.dispatchHostcall(handle, "net_connect", &.{});
    try std.testing.expectEqual(@as(i64, -1), denied_connect.i64);
}

test "intent grants are denied by default and require explicit policy" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{.reply}),
    });
    defer store.deinit();

    const denied = try store.load(.{
        .name = "reader",
        .requested_caps = &.{.reply},
        .requested_intents = &.{.message_content},
    }, &empty_wasm);
    try std.testing.expect(!try store.hasIntent(denied, .message_content));

    const granted = try store.loadWithPolicy(.{
        .name = "trusted-reader",
        .requested_caps = &.{.reply},
        .requested_intents = &.{.message_content},
    }, &empty_wasm, abi.CapabilitySet.initMany(&.{.reply}), abi.IntentSet.initMany(&.{.message_content}));
    try std.testing.expect(try store.hasIntent(granted, .message_content));
}

test "unload tears down all registrations for a plugin handle" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .hooks }),
    });
    defer store.deinit();

    const handle = try store.load(.{
        .name = "temporary",
        .requested_caps = &.{ .reply, .hooks },
        .commands = &.{.{ .name = "TEMP", .export_name = "cmd_temp" }},
        .hooks = &.{.{ .hook = "message", .export_name = "on_message" }},
    }, &empty_wasm);

    try store.unload(handle);
    try std.testing.expectEqual(@as(usize, 0), store.commandCount(handle));
    try std.testing.expectEqual(@as(usize, 0), store.hookCount(handle));
    try std.testing.expectError(error.UnknownPlugin, store.dispatchHostcall(handle, "reply", &.{}));
}
