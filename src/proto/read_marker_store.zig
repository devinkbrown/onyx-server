// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocator-backed IRCv3 draft/read-marker storage and MARKREAD parsing.
const std = @import("std");
const wire = @import("read_marker.zig");
const limits_config = @import("limits_config.zig");

pub const Timestamp = wire.ReadTimestamp;
pub const Marker = wire.Marker;

pub const default_max_entries: usize = 1024;
pub const default_max_owner_bytes: usize = 128;
pub const default_max_target_bytes: usize = wire.default_max_target_bytes;

pub const Params = struct {
    max_entries: usize = default_max_entries,
    max_owner_bytes: usize = default_max_owner_bytes,
    max_target_bytes: usize = default_max_target_bytes,

    /// Derive `Params` from the central policy limits (config-driven).
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_entries = limits.read_marker_max_entries,
            .max_owner_bytes = limits.read_marker_owner_len,
            .max_target_bytes = limits.read_marker_target_len,
        };
    }
};

pub const ReadMarkerStoreError = wire.ReadMarkerError || error{
    InvalidOwner,
    OutOfMemory,
};

pub const Request = union(enum) {
    get: []const u8,
    set: SetRequest,
};

pub const SetRequest = struct {
    target: []const u8,
    marker: Marker,
};

pub const SetResult = struct {
    timestamp: Timestamp,
    changed: bool,
};

pub fn ReadMarkerStore(comptime params: Params) type {
    comptime {
        if (params.max_entries == 0) @compileError("read-marker store needs at least one entry");
        if (params.max_owner_bytes == 0) @compileError("read-marker owner ids need storage");
        if (params.max_target_bytes == 0) @compileError("read-marker targets need storage");
    }

    return struct {
        const Self = @This();
        const max_key_bytes = params.max_owner_bytes + 1 + params.max_target_bytes;

        allocator: std.mem.Allocator,
        entries: std.StringHashMap(Timestamp),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .entries = std.StringHashMap(Timestamp).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.entries.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            var it = self.entries.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            self.entries.clearRetainingCapacity();
        }

        pub fn count(self: *const Self) usize {
            return self.entries.count();
        }

        pub fn set(
            self: *Self,
            owner: []const u8,
            target: []const u8,
            timestamp: Timestamp,
        ) ReadMarkerStoreError!SetResult {
            var key_buf: [max_key_bytes]u8 = undefined;
            const key = try makeKey(owner, target, &key_buf);

            if (self.entries.getPtr(key)) |stored| {
                if (!timestamp.newerThan(stored.*)) {
                    return .{ .timestamp = stored.*, .changed = false };
                }

                stored.* = timestamp;
                return .{ .timestamp = timestamp, .changed = true };
            }

            if (self.entries.count() >= params.max_entries) return error.TargetLimitExceeded;

            const owned_key = self.allocator.dupe(u8, key) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_key);

            const gop = self.entries.getOrPut(owned_key) catch return error.OutOfMemory;
            if (gop.found_existing) {
                self.allocator.free(owned_key);
                if (!timestamp.newerThan(gop.value_ptr.*)) {
                    return .{ .timestamp = gop.value_ptr.*, .changed = false };
                }

                gop.value_ptr.* = timestamp;
                return .{ .timestamp = timestamp, .changed = true };
            }

            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = timestamp;
            return .{ .timestamp = timestamp, .changed = true };
        }

        pub fn get(
            self: *const Self,
            owner: []const u8,
            target: []const u8,
        ) ReadMarkerStoreError!?Timestamp {
            var key_buf: [max_key_bytes]u8 = undefined;
            const key = try makeKey(owner, target, &key_buf);
            return self.entries.get(key);
        }

        /// Visit every stored marker. `owner` and `target` borrow the map key for
        /// the callback only; `target` is the normalized form `set` stored.
        pub fn forEach(self: *const Self, context: anytype, comptime callback: anytype) !void {
            var it = self.entries.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                const sep = std.mem.indexOfScalar(u8, key, 0) orelse continue;
                try callback(context, key[0..sep], key[sep + 1 ..], entry.value_ptr.*);
            }
        }

        fn makeKey(
            owner: []const u8,
            target: []const u8,
            out: *[max_key_bytes]u8,
        ) ReadMarkerStoreError![]const u8 {
            try validateOwner(owner);
            if (!wire.validTarget(target, params.max_target_bytes)) return error.InvalidTarget;

            @memcpy(out[0..owner.len], owner);
            out[owner.len] = 0;
            for (target, 0..) |byte, index| {
                out[owner.len + 1 + index] = normalizeTargetByte(byte);
            }
            return out[0 .. owner.len + 1 + target.len];
        }

        fn validateOwner(owner: []const u8) ReadMarkerStoreError!void {
            if (owner.len == 0 or owner.len > params.max_owner_bytes) return error.InvalidOwner;
            for (owner) |byte| {
                if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidOwner;
            }
        }
    };
}

pub const DefaultStore = ReadMarkerStore(.{});

pub fn parse(params: []const []const u8) ReadMarkerStoreError!Request {
    return parseBounded(.{}, params);
}

pub fn parseBounded(comptime bounds: Params, params: []const []const u8) ReadMarkerStoreError!Request {
    if (params.len == 0) return error.MissingParameter;
    if (params.len > 2) return error.TooManyParameters;
    if (!wire.validTarget(params[0], bounds.max_target_bytes)) return error.InvalidTarget;

    if (params.len == 1) return .{ .get = params[0] };

    return .{ .set = .{
        .target = params[0],
        .marker = try parseMarkerParam(params[1]),
    } };
}

pub fn parseLine(line: []const u8) ReadMarkerStoreError!Request {
    return parseLineBounded(.{}, line);
}

pub fn parseLineBounded(comptime bounds: Params, line: []const u8) ReadMarkerStoreError!Request {
    var tokens: [3][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, line, " \r\n");

    const command = it.next() orelse return error.MissingParameter;
    if (!std.ascii.eqlIgnoreCase(command, "MARKREAD")) return error.MissingParameter;

    while (it.next()) |token| {
        if (count == tokens.len) return error.TooManyParameters;
        tokens[count] = token;
        count += 1;
    }

    return parseBounded(bounds, tokens[0..count]);
}

pub fn buildResponse(target: []const u8, marker: Marker, out: []u8) ReadMarkerStoreError![]const u8 {
    return wire.writeResponse(target, marker, out);
}

pub fn buildTimestampResponse(target: []const u8, timestamp: Timestamp, out: []u8) ReadMarkerStoreError![]const u8 {
    return buildResponse(target, .{ .timestamp = timestamp }, out);
}

fn parseMarkerParam(raw: []const u8) ReadMarkerStoreError!Marker {
    if (std.mem.eql(u8, raw, "*")) return .unset;
    return .{ .timestamp = try Timestamp.parseParam(raw) };
}

fn normalizeTargetByte(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        else => byte,
    };
}

test "set advances only forward and get returns latest" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const older = try Timestamp.parseParam("timestamp=2026-06-02T08:09:10.123Z");
    const newer = try Timestamp.parseParam("timestamp=2026-06-02T08:09:11.000Z");
    const oldest = try Timestamp.parseParam("timestamp=2026-06-02T08:09:09.999Z");

    try std.testing.expect((try store.set("acct", "#Suzu", older)).changed);
    try std.testing.expect((try store.set("acct", "#suzu", newer)).changed);

    const ignored = try store.set("acct", "#SUZU", oldest);
    try std.testing.expect(!ignored.changed);
    try std.testing.expectEqualStrings("2026-06-02T08:09:11.000Z", ignored.timestamp.slice());

    const got = (try store.get("acct", "#suzu")).?;
    try std.testing.expectEqualStrings("2026-06-02T08:09:11.000Z", got.slice());
    try std.testing.expectEqual(@as(?Timestamp, null), try store.get("other", "#suzu"));
}

test "parse GET SET and malformed MARKREAD" {
    const get_params = [_][]const u8{"#chan"};
    const got = try parse(&get_params);
    switch (got) {
        .get => |target| try std.testing.expectEqualStrings("#chan", target),
        .set => return error.InvalidTimestamp,
    }

    const set_params = [_][]const u8{ "#chan", "timestamp=2026-06-02T08:09:10.123Z" };
    const set = try parse(&set_params);
    switch (set) {
        .set => |req| {
            try std.testing.expectEqualStrings("#chan", req.target);
            const ts = switch (req.marker) {
                .timestamp => |value| value,
                .unset => return error.InvalidTimestamp,
            };
            try std.testing.expectEqualStrings("2026-06-02T08:09:10.123Z", ts.slice());
        },
        .get => return error.InvalidTimestamp,
    }

    const unset_line = try parseLine("MARKREAD #chan *\r\n");
    switch (unset_line) {
        .set => |req| try std.testing.expectEqual(.unset, req.marker),
        .get => return error.InvalidTimestamp,
    }

    const missing = [_][]const u8{};
    try std.testing.expectError(error.MissingParameter, parse(&missing));

    const bad_target = [_][]const u8{"#bad,target"};
    try std.testing.expectError(error.InvalidTarget, parse(&bad_target));

    const bad_date = [_][]const u8{ "#chan", "timestamp=2026-02-29T08:09:10.123Z" };
    try std.testing.expectError(error.InvalidTimestamp, parse(&bad_date));

    const too_many = [_][]const u8{ "#chan", "timestamp=2026-06-02T08:09:10.123Z", "extra" };
    try std.testing.expectError(error.TooManyParameters, parse(&too_many));
}

test "builder exact bytes" {
    const timestamp = try Timestamp.parseParam("timestamp=2026-06-02T08:09:10.123Z");

    var out: [96]u8 = undefined;
    const line = try buildTimestampResponse("#chan", timestamp, &out);
    try std.testing.expectEqualStrings(
        "MARKREAD #chan timestamp=2026-06-02T08:09:10.123Z\r\n",
        line,
    );
}

test "bounded store and no leak after clear" {
    var store = ReadMarkerStore(.{
        .max_entries = 2,
        .max_owner_bytes = 8,
        .max_target_bytes = 8,
    }).init(std.testing.allocator);
    defer store.deinit();

    const timestamp = try Timestamp.parseParam("timestamp=2026-06-02T08:09:10.123Z");

    _ = try store.set("owner", "#one", timestamp);
    _ = try store.set("owner", "#two", timestamp);
    try std.testing.expectError(error.TargetLimitExceeded, store.set("owner", "#three", timestamp));
    try std.testing.expectError(error.InvalidOwner, store.set("owner with space", "#one", timestamp));
    try std.testing.expectError(error.InvalidTarget, store.set("owner", "#target-too-long", timestamp));

    store.clear();
    try std.testing.expectEqual(@as(usize, 0), store.count());
    _ = try store.set("owner", "#after", timestamp);
}
