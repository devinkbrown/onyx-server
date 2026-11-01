// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed scalar conversion and owned string/list operations.

const std = @import("std");
const toml = @import("../../proto/toml.zig");
const conn_class = @import("../conn_class.zig");
const Resolver = @import("contracts.zig").Resolver;
const TomlError = @import("contracts.zig").TomlError;

/// Read a class byte-size field: a string ("1M") parsed via `conn_class.parseSize`
/// or a bare integer (bytes). Missing → `current`.
pub fn classSize(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseSize(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class duration field (ms): a string ("120s") via `parseDurationMs` or a
/// bare integer (ms). Missing → `current`.
pub fn classDur(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseDurationMs(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class u32 count field. Missing → `current`.
pub fn classU32(item: *const toml.Value, key: []const u8, current: u32) TomlError!u32 {
    if (item.getInt(key)) |n| {
        if (n < 0 or n > std.math.maxInt(u32)) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Resolve a raw TOML string into an owned value, honoring `env:NAME` /
/// `@file:path` indirection; a plain string is duped verbatim.
pub fn resolveStr(allocator: std.mem.Allocator, resolver: Resolver, raw: []const u8) TomlError![]const u8 {
    if (std.mem.startsWith(u8, raw, "env:")) {
        const name = raw["env:".len..];
        if (name.len == 0) return error.ParseError;
        const func = resolver.env orelse return error.ParseError;
        return func(resolver.ctx, allocator, name) catch return error.ParseError;
    }
    if (std.mem.startsWith(u8, raw, "@file:")) {
        const path = raw["@file:".len..];
        if (path.len == 0) return error.ParseError;
        const func = resolver.file orelse return error.ParseError;
        return func(resolver.ctx, allocator, path) catch return error.ParseError;
    }
    return allocator.dupe(u8, raw);
}

/// Overlay an optional string field when the TOML supplies one.
pub fn setOpt(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *?[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    if (slot.*) |old| allocator.free(old);
    slot.* = owned;
}

/// Overlay a non-optional (default-duped) string field when supplied.
pub fn setStr(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    allocator.free(slot.*);
    slot.* = owned;
}

pub fn ownStringArray(allocator: std.mem.Allocator, resolver: Resolver, arr: []const toml.Value) TomlError![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| allocator.free(s);
        list.deinit(allocator);
    }
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        const owned = try resolveStr(allocator, resolver, raw);
        list.append(allocator, owned) catch |err| {
            allocator.free(owned);
            return err;
        };
    }
    return list.toOwnedSlice(allocator);
}

pub fn parseHexArray(comptime len: usize, raw: []const u8) TomlError![len]u8 {
    if (raw.len != len * 2) return error.ParseError;
    var out: [len]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, raw) catch return error.ParseError;
    return out;
}

/// Own a TOML field that may be either a single string OR an array of strings
/// (e.g. `certfp = "abc…"` or `certfp = ["abc…", "def…"]`). Returns an owned,
/// resolved string list; an absent field yields the empty slice.
pub fn ownStringOrArray(
    allocator: std.mem.Allocator,
    resolver: Resolver,
    item: *const toml.Value,
    key: []const u8,
) TomlError![]const []const u8 {
    if (item.getArray(key)) |arr| return ownStringArray(allocator, resolver, arr);
    if (item.getString(key)) |s| {
        var list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (list.items) |v| allocator.free(v);
            list.deinit(allocator);
        }
        const owned = try resolveStr(allocator, resolver, s);
        errdefer allocator.free(owned);
        try list.append(allocator, owned);
        return list.toOwnedSlice(allocator);
    }
    return &.{};
}

pub fn portField(doc: toml.Document, path: []const u8, current: u16) TomlError!u16 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0 or v > 65535) return error.ParseError;
    return @intCast(v);
}

pub fn uintField(doc: toml.Document, path: []const u8, current: u64, min: u64, max: u64) TomlError!u64 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0) return error.ParseError;
    const u: u64 = @intCast(v);
    if (u < min or u > max) return error.ParseError;
    return u;
}

pub fn floatField(doc: toml.Document, path: []const u8, current: f64, min: f64, max: f64) TomlError!f64 {
    const v = doc.getFloat(path) orelse return current;
    if (v < min or v > max) return error.ParseError;
    return v;
}

/// Parse a duration string ("500ms" | "30s" | "5m" | "2h") into milliseconds.
pub fn durationMs(text: []const u8) TomlError!u64 {
    const units = [_]struct { suffix: []const u8, scale: u64 }{
        .{ .suffix = "ms", .scale = 1 },
        .{ .suffix = "s", .scale = 1000 },
        .{ .suffix = "m", .scale = 60_000 },
        .{ .suffix = "h", .scale = 3_600_000 },
    };
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            const digits = text[0 .. text.len - unit.suffix.len];
            const n = std.fmt.parseInt(u64, digits, 10) catch return error.ParseError;
            if (n == 0 or n > std.math.maxInt(u64) / unit.scale) return error.ParseError;
            return n * unit.scale;
        }
    }
    return error.ParseError;
}

pub fn freeStringList(allocator: std.mem.Allocator, list: []const []const u8) void {
    for (list) |item| allocator.free(item);
    allocator.free(list);
}
