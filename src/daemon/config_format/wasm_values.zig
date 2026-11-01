// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wasm capability, intent, registry, and digest configuration values.

const std = @import("std");
const toml = @import("../../proto/toml.zig");
const crypto_sign = @import("../../crypto/sign.zig");
const wasm_abi = @import("../../wasm/host/abi.zig");
const wasm_bridge = @import("../../wasm/host/bridge.zig");
const Resolver = @import("contracts.zig").Resolver;
const TomlError = @import("contracts.zig").TomlError;
const parseHexArray = @import("values.zig").parseHexArray;
const resolveStr = @import("values.zig").resolveStr;

pub fn parseWasmCaps(arr: []const toml.Value) TomlError!wasm_abi.CapabilitySet {
    var caps = wasm_abi.CapabilitySet.empty;
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        const cap = wasm_abi.Capability.fromToken(raw) orelse return error.ParseError;
        caps.insert(cap);
    }
    return caps;
}

pub fn parseWasmIntents(arr: []const toml.Value) TomlError!wasm_abi.IntentSet {
    var intents = wasm_abi.IntentSet.empty;
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        const intent = wasm_abi.Intent.fromToken(raw) orelse return error.ParseError;
        intents.insert(intent);
    }
    return intents;
}

pub fn parseWasmRegistry(allocator: std.mem.Allocator, resolver: Resolver, arr: []const toml.Value) TomlError![]const wasm_bridge.RegistryPin {
    var list: std.ArrayList(wasm_bridge.RegistryPin) = .empty;
    errdefer {
        for (list.items) |pin| allocator.free(pin.name);
        list.deinit(allocator);
    }
    for (arr) |*item| {
        if (item.* != .table) return error.ParseError;
        const raw_name = item.getString("name") orelse return error.ParseError;
        const raw_hash = item.getString("blake3") orelse return error.ParseError;
        const raw_tier = item.getString("tier") orelse "listed";
        const raw_publisher = item.getString("publisher");
        const raw_signature = item.getString("signature");
        if (raw_hash.len != std.crypto.hash.Blake3.digest_length * 2) return error.ParseError;
        var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&digest, raw_hash) catch return error.ParseError;
        const tier = wasm_bridge.TrustTier.fromToken(raw_tier) orelse return error.ParseError;
        if ((raw_publisher == null) != (raw_signature == null)) return error.ParseError;
        const publisher = if (raw_publisher) |raw| try parseHexArray(crypto_sign.public_key_len, raw) else null;
        const signature = if (raw_signature) |raw| try parseHexArray(crypto_sign.signature_len, raw) else null;
        const name = try resolveStr(allocator, resolver, raw_name);
        errdefer allocator.free(name);
        try list.append(allocator, .{ .name = name, .blake3 = digest, .tier = tier, .publisher = publisher, .signature = signature });
    }
    return list.toOwnedSlice(allocator);
}

pub fn parseHexArrayList(comptime len: usize, allocator: std.mem.Allocator, arr: []const toml.Value) TomlError![]const [len]u8 {
    var list: std.ArrayList([len]u8) = .empty;
    errdefer list.deinit(allocator);
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        try list.append(allocator, try parseHexArray(len, raw));
    }
    return list.toOwnedSlice(allocator);
}

pub fn freeWasmRegistry(allocator: std.mem.Allocator, pins: []const wasm_bridge.RegistryPin) void {
    for (pins) |pin| allocator.free(pin.name);
    allocator.free(pins);
}
