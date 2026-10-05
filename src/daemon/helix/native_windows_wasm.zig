// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact OroWasm runtime custody for a native Windows Helix handoff.
//! Source capture requires the server's frozen World cut. A successor parses
//! and authorizes source plugin bytes, restores linear memory and RNG state,
//! and validates registration order before READY. It never reloads plugins
//! from a mutable directory after COMMIT.

const std = @import("std");
const frame = @import("native_windows_companion_wire.zig");
const wasm = @import("../../wasm/host/bridge.zig");
const plugin = @import("../../wasm/host/plugin.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'W', 'M' };
const domain = "onyx-native-windows-orowasm-v1";
const payload_header_len: usize = 96;
const row_header_len: usize = 16;
pub const max_checkpoint_bytes: usize = 128 * 1024 * 1024;
pub const max_plugins: usize = 256;
pub const max_plugin_name_bytes: usize = 255;
pub const max_plugin_dir_bytes: usize = 4096;
pub const Error = error{ InvalidSnapshot, ConfigMismatch, TooLarge } || std.mem.Allocator.Error;

pub const Owned = struct {
    value: ?wasm.Bridge,

    pub fn deinit(self: *Owned) void {
        if (self.value) |*bridge| bridge.deinit();
        self.value = null;
    }

    /// All validation and allocations have completed before the daemon uses
    /// this no-fail ownership transfer at its publication edge.
    pub fn release(self: *Owned) wasm.Bridge {
        const value = self.value.?;
        self.value = null;
        return value;
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

/// Linear memory can contain guest-held private data. Clear the handoff
/// plaintext after the envelope has been sealed or a candidate has staged it.
pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

/// Allocation-free frame and row validation for the Helix relation pass.
/// Module parsing and policy checks remain the candidate stage's job.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len > max_checkpoint_bytes or bytes.len < frame.header_len + payload_header_len + frame.checksum_len)
        return error.InvalidSnapshot;
    const payload_len = bytes.len - frame.header_len - frame.checksum_len;
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, payload_len);
    if (!std.mem.eql(u8, payload[90..96], &.{ 0, 0, 0, 0, 0, 0 })) return error.InvalidSnapshot;
    const count: usize = readU32(payload[84..88]);
    const dir_len: usize = readU16(payload[88..90]);
    const next_handle = readU32(payload[80..84]);
    if (count > max_plugins or dir_len > max_plugin_dir_bytes or next_handle == 0) return error.InvalidSnapshot;
    var reader = Reader{ .bytes = payload, .pos = payload_header_len };
    const dir = try reader.take(dir_len);
    for (dir) |byte| if (byte == 0) return error.InvalidSnapshot;
    var handles: [max_plugins]plugin.PluginHandle = undefined;
    var names: [max_plugins][]const u8 = undefined;
    for (0..count) |index| {
        const row = try reader.take(row_header_len);
        const handle = readU32(row[0..4]);
        const name_len: usize = readU16(row[4..6]);
        const wasm_len: usize = readU32(row[8..12]);
        const memory_len: usize = readU32(row[12..16]);
        if (!std.mem.eql(u8, row[6..8], &.{ 0, 0 }) or handle == 0 or
            handle >= next_handle or wasm_len == 0) return error.InvalidSnapshot;
        const name = try reader.take(name_len);
        validateName(name) catch return error.InvalidSnapshot;
        for (0..index) |prior| {
            if (handles[prior] == handle or std.ascii.eqlIgnoreCase(names[prior], name)) return error.InvalidSnapshot;
        }
        handles[index] = handle;
        names[index] = name;
        _ = try reader.take(wasm_len);
        _ = try reader.take(memory_len);
    }
    if (reader.pos != payload.len) return error.InvalidSnapshot;
}

fn checkedAdd(total: *usize, amount: usize) Error!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.TooLarge;
    if (total.* > max_checkpoint_bytes - frame.header_len - frame.checksum_len) return error.TooLarge;
}

fn validateName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > max_plugin_name_bytes) return error.InvalidSnapshot;
    for (name) |byte| if (byte == 0 or byte == '/' or byte == '\\') return error.InvalidSnapshot;
}

/// `plugin_dir` is the exact parsed directory selector, not a new disk read.
/// The source bridge retains its originally authorized module bytes.
pub fn encode(allocator: std.mem.Allocator, source: *const wasm.Bridge, plugin_dir: []const u8) Error![]u8 {
    if (plugin_dir.len > max_plugin_dir_bytes or source.count() > max_plugins or
        source.blocked_loads > std.math.maxInt(u64)) return error.TooLarge;
    const state = source.store.checkpointState();
    var payload_len: usize = payload_header_len;
    try checkedAdd(&payload_len, plugin_dir.len);
    for (0..source.count()) |index| {
        const row = source.store.checkpointPlugin(index).?;
        try validateName(row.name);
        if (row.wasm.len == 0 or row.wasm.len > source.options.max_plugin_bytes or
            row.wasm.len > std.math.maxInt(u32) or row.memory.len > source.options.max_memory_bytes or
            row.memory.len > std.math.maxInt(u32)) return error.InvalidSnapshot;
        try checkedAdd(&payload_len, row_header_len);
        try checkedAdd(&payload_len, row.name.len);
        try checkedAdd(&payload_len, row.wasm.len);
        try checkedAdd(&payload_len, row.memory.len);
    }
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer freeEncoded(allocator, bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    @memcpy(payload[0..32], &source.checkpointPolicyDigest());
    @memcpy(payload[32..64], &source.store.checkpointLayoutDigest());
    writeU64(payload[64..72], state.deterministic_rand);
    writeU64(payload[72..80], @intCast(source.blocked_loads));
    writeU32(payload[80..84], state.next_handle);
    writeU32(payload[84..88], @intCast(source.count()));
    writeU16(payload[88..90], @intCast(plugin_dir.len));
    @memset(payload[90..96], 0);
    var pos: usize = payload_header_len;
    @memcpy(payload[pos..][0..plugin_dir.len], plugin_dir);
    pos += plugin_dir.len;
    for (0..source.count()) |index| {
        const row = source.store.checkpointPlugin(index).?;
        writeU32(payload[pos..][0..4], row.handle);
        writeU16(payload[pos + 4 ..][0..2], @intCast(row.name.len));
        @memset(payload[pos + 6 ..][0..2], 0);
        writeU32(payload[pos + 8 ..][0..4], @intCast(row.wasm.len));
        writeU32(payload[pos + 12 ..][0..4], @intCast(row.memory.len));
        pos += row_header_len;
        @memcpy(payload[pos..][0..row.name.len], row.name);
        pos += row.name.len;
        @memcpy(payload[pos..][0..row.wasm.len], row.wasm);
        pos += row.wasm.len;
        @memcpy(payload[pos..][0..row.memory.len], row.memory);
        pos += row.memory.len;
    }
    std.debug.assert(pos == payload.len);
    frame.finish(bytes, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// Build an independent, disposable bridge before READY. The caller passes
/// candidate-owned parsed policy; no field in the checkpoint can grant itself
/// a capability or override a local registry/revocation rule.
pub fn stage(allocator: std.mem.Allocator, bytes: []const u8, options: wasm.Options, expected_plugin_dir: []const u8) anyerror!Owned {
    try validateCheckpoint(bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    const count: usize = readU32(payload[84..88]);
    const dir_len: usize = readU16(payload[88..90]);
    if (count > max_plugins or dir_len > max_plugin_dir_bytes or expected_plugin_dir.len != dir_len)
        return error.ConfigMismatch;
    var staged = wasm.Bridge.initWithOptions(allocator, options);
    errdefer staged.deinit();
    if (!std.mem.eql(u8, payload[0..32], &staged.checkpointPolicyDigest())) return error.ConfigMismatch;
    var reader = Reader{ .bytes = payload, .pos = payload_header_len };
    if (!std.mem.eql(u8, try reader.take(dir_len), expected_plugin_dir)) return error.ConfigMismatch;
    var handles: [max_plugins]plugin.PluginHandle = undefined;
    for (0..count) |index| {
        const row = try reader.take(row_header_len);
        const handle = readU32(row[0..4]);
        const name_len: usize = readU16(row[4..6]);
        const wasm_len: usize = readU32(row[8..12]);
        const memory_len: usize = readU32(row[12..16]);
        if (!std.mem.eql(u8, row[6..8], &.{ 0, 0 }) or
            wasm_len == 0 or wasm_len > options.max_plugin_bytes or
            memory_len > options.max_memory_bytes) return error.InvalidSnapshot;
        const name = try reader.take(name_len);
        try validateName(name);
        const module = try reader.take(wasm_len);
        const memory = try reader.take(memory_len);
        // Registry pins, revoked hashes, signatures and hostcall grants are
        // checked anew using candidate policy before any mutable state copies.
        try staged.loadBytes(name, module);
        try staged.store.restoreCheckpointMemory(index, name, module, memory);
        handles[index] = handle;
    }
    if (reader.pos != payload.len) return error.InvalidSnapshot;
    try staged.store.restoreCheckpointIdentity(handles[0..count], .{
        .next_handle = readU32(payload[80..84]),
        .deterministic_rand = readU64(payload[64..72]),
    });
    if (!std.mem.eql(u8, &staged.store.checkpointLayoutDigest(), payload[32..64])) return error.InvalidSnapshot;
    const blocked = readU64(payload[72..80]);
    if (blocked > std.math.maxInt(usize)) return error.InvalidSnapshot;
    staged.blocked_loads = @intCast(blocked);
    return .{ .value = staged };
}

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) error{InvalidSnapshot}![]const u8 {
        if (len > self.bytes.len - self.pos) return error.InvalidSnapshot;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }
};

fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .little);
}
fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .little);
}
fn writeU64(out: []u8, value: u64) void {
    std.mem.writeInt(u64, out[0..8], value, .little);
}
fn readU16(input: []const u8) u16 {
    return std.mem.readInt(u16, input[0..2], .little);
}
fn readU32(input: []const u8) u32 {
    return std.mem.readInt(u32, input[0..4], .little);
}
fn readU64(input: []const u8) u64 {
    return std.mem.readInt(u64, input[0..8], .little);
}

test "Windows OroWasm checkpoint preserves exact bytes memory ordering and RNG" {
    const testing = std.testing;
    var source = wasm.Bridge.init(testing.allocator);
    defer source.deinit();
    try source.loadBytes("first", wasm.testing.reply_plugin_wasm);
    try source.loadBytes("second", wasm.testing.reply_plugin_wasm);
    source.store.plugins.items[0].instance.memory[0] = 0xa1;
    source.store.plugins.items[1].instance.memory[1] = 0xb2;
    source.store.deterministic_rand = 0x123456789abcdef0;
    source.blocked_loads = 7;
    const wire = try encode(testing.allocator, &source, "plugins");
    defer freeEncoded(testing.allocator, wire);
    try validateCheckpoint(wire);
    var owned = try stage(testing.allocator, wire, source.options, "plugins");
    defer owned.deinit();
    const restored = &owned.value.?;
    try testing.expectEqual(@as(usize, 2), restored.count());
    try testing.expectEqual(@as(u8, 0xa1), restored.store.plugins.items[0].instance.memory[0]);
    try testing.expectEqual(@as(u8, 0xb2), restored.store.plugins.items[1].instance.memory[1]);
    try testing.expectEqual(source.store.deterministic_rand, restored.store.deterministic_rand);
    try testing.expectEqual(source.blocked_loads, restored.blocked_loads);
    try testing.expectEqualDeep(source.store.checkpointLayoutDigest(), restored.store.checkpointLayoutDigest());
    try testing.expectEqualStrings("first", restored.store.checkpointPlugin(0).?.name);
    try testing.expectEqualStrings("second", restored.store.checkpointPlugin(1).?.name);
    try testing.expectError(error.ConfigMismatch, stage(testing.allocator, wire, source.options, "other"));
    var changed_options = source.options;
    changed_options.default_fuel += 1;
    try testing.expectError(error.ConfigMismatch, stage(testing.allocator, wire, changed_options, "plugins"));
    const first_row = frame.header_len + payload_header_len + "plugins".len;
    writeU32(wire[first_row..][0..4], 0);
    frame.finish(wire, domain);
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire));
    writeU32(wire[first_row..][0..4], 1);
    frame.finish(wire, domain);
    try validateCheckpoint(wire);
    wire[wire.len - 1] ^= 1;
    try testing.expectError(error.InvalidSnapshot, stage(testing.allocator, wire, source.options, "plugins"));
}
