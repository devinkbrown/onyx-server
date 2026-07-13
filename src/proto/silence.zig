// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-side SILENCE ignore lists.
//!
//! Each owner has an allocator-owned list of nick!user@host masks. Incoming
//! PRIVMSG/NOTICE delivery can call `isSilenced(owner, sender_hostmask)` and
//! drop the message when any stored mask matches.
const std = @import("std");
const listx = @import("listx.zig");
const limits_config = @import("limits_config.zig");

pub const RPL_SILELIST: u16 = 271;
pub const RPL_ENDOFSILELIST: u16 = 272;

/// Upper bound on the owner-key normalization scratch buffer. Owner names are
/// nicks; `validateOwner` already bounds them by `max_owner_bytes` (64 by
/// default), so this comfortably covers every stored key.
const NORM_OWNER_MAX: usize = 512;

pub const DEFAULT_MAX_MASKS_PER_OWNER: usize = 32;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_OWNER_BYTES: usize = 64;
pub const DEFAULT_MAX_OPERATIONS: usize = 32;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;

pub const SilenceError = std.mem.Allocator.Error || error{
    InvalidCommand,
    InvalidParameter,
    InvalidOwner,
    InvalidMask,
    OwnerTooLong,
    MaskTooLong,
    LimitReached,
    TooManyOperations,
    OutputTooSmall,
    LineTooLong,
    InvalidServerName,
    InvalidRequester,
};

pub const Params = struct {
    max_masks_per_owner: usize = DEFAULT_MAX_MASKS_PER_OWNER,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_owner_bytes: usize = DEFAULT_MAX_OWNER_BYTES,
    max_operations: usize = DEFAULT_MAX_OPERATIONS,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire-framing budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_masks_per_owner = limits.silence_masks_per_owner,
            .max_mask_bytes = limits.list_mask_len,
            .max_operations = limits.silence_ops_per_command,
            .max_server_bytes = limits.server_name_len,
        };
    }
};

pub const OperationKind = enum {
    add,
    remove,
};

pub const Operation = struct {
    kind: OperationKind,
    mask: []const u8,
};

pub fn RequestType(comptime max_operations: usize) type {
    if (max_operations == 0) @compileError("SILENCE request needs at least one operation slot");

    return struct {
        const Self = @This();

        operations: [max_operations]Operation = undefined,
        count: usize = 0,

        pub fn slice(self: *const Self) []const Operation {
            return self.operations[0..self.count];
        }

        fn append(self: *Self, op: Operation) SilenceError!void {
            if (self.count >= self.operations.len) return error.TooManyOperations;
            self.operations[self.count] = op;
            self.count += 1;
        }
    };
}

pub const Request = RequestType(DEFAULT_MAX_OPERATIONS);

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    owners: std.StringHashMap(ClientList),

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithParams(allocator, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Store {
        return .{
            .allocator = allocator,
            .params = params,
            .owners = std.StringHashMap(ClientList).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.owners.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.owners.deinit();
        self.* = undefined;
    }

    /// Add `mask` to `owner`'s SILENCE list. Returns false for duplicates.
    pub fn add(self: *Store, owner: []const u8, mask: []const u8) SilenceError!bool {
        return self.addWithLimit(owner, mask, self.params.max_masks_per_owner);
    }

    /// As `add`, but `max_masks` replaces the store-wide `max_masks_per_owner`
    /// ceiling — the per-connection-class `silence` cap. Pass the global default
    /// to preserve the standard behavior.
    pub fn addWithLimit(self: *Store, owner: []const u8, mask: []const u8, max_masks: usize) SilenceError!bool {
        try validateOwner(owner, self.params.max_owner_bytes);
        try validateMask(mask, self.params.max_mask_bytes);

        var owner_buf: [NORM_OWNER_MAX]u8 = undefined;
        const key = normalizeOwner(owner, &owner_buf) orelse return error.OwnerTooLong;

        if (self.owners.getPtr(key)) |client_list| {
            return client_list.add(self.allocator, max_masks, mask);
        }

        const owner_copy = try self.allocator.dupe(u8, key);
        const gop = self.owners.getOrPut(key) catch |err| {
            self.allocator.free(owner_copy);
            return err;
        };
        if (gop.found_existing) {
            self.allocator.free(owner_copy);
            return gop.value_ptr.add(self.allocator, max_masks, mask);
        }

        gop.key_ptr.* = owner_copy;
        gop.value_ptr.* = .{};
        errdefer {
            const owned_key = gop.key_ptr.*;
            gop.value_ptr.deinit(self.allocator);
            self.owners.removeByPtr(gop.key_ptr);
            self.allocator.free(owned_key);
        }

        return gop.value_ptr.add(self.allocator, max_masks, mask);
    }

    /// Remove `mask` from `owner`'s SILENCE list. Returns false when absent.
    pub fn remove(self: *Store, owner: []const u8, mask: []const u8) SilenceError!bool {
        try validateOwner(owner, self.params.max_owner_bytes);
        try validateMask(mask, self.params.max_mask_bytes);

        var owner_buf: [NORM_OWNER_MAX]u8 = undefined;
        const key = normalizeOwner(owner, &owner_buf) orelse return false;
        const entry = self.owners.getEntry(key) orelse return false;
        const removed = entry.value_ptr.remove(self.allocator, mask);
        if (entry.value_ptr.masks.items.len == 0) {
            const owned_key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.owners.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
        }
        return removed;
    }

    /// Return true when `sender_hostmask` matches any mask owned by `owner`.
    pub fn isSilenced(self: *const Store, owner: []const u8, sender_hostmask: []const u8) bool {
        var owner_buf: [NORM_OWNER_MAX]u8 = undefined;
        const key = normalizeOwner(owner, &owner_buf) orelse return false;
        const client_list = self.owners.getPtr(key) orelse return false;
        for (client_list.masks.items) |mask| {
            if (listx.globMatch(mask, sender_hostmask)) return true;
        }
        return false;
    }

    /// Fill `out` with `owner`'s masks, returning how many were written
    /// (truncated to `out.len`). Slices borrow the store's storage — valid
    /// until the store is next mutated. Used by the Helix upgrade seal to
    /// carry the SILENCE list across a USR2.
    pub fn masksInto(self: *const Store, owner: []const u8, out: [][]const u8) usize {
        var owner_buf: [NORM_OWNER_MAX]u8 = undefined;
        const key = normalizeOwner(owner, &owner_buf) orelse return 0;
        const client = self.owners.getPtr(key) orelse return 0;
        var n: usize = 0;
        for (client.masks.items) |mask| {
            if (n >= out.len) break;
            out[n] = mask;
            n += 1;
        }
        return n;
    }

    /// Write `owner`'s masks as comma-separated bytes into caller storage.
    pub fn list(self: *const Store, owner: []const u8, out: []u8) SilenceError![]const u8 {
        try validateOwner(owner, self.params.max_owner_bytes);
        var owner_buf: [NORM_OWNER_MAX]u8 = undefined;
        const key = normalizeOwner(owner, &owner_buf) orelse return out[0..0];
        const masks = if (self.owners.getPtr(key)) |client| client.masks.items else return out[0..0];

        var len: usize = 0;
        for (masks, 0..) |mask, index| {
            if (index != 0) {
                if (len == out.len) return error.OutputTooSmall;
                out[len] = ',';
                len += 1;
            }
            if (len + mask.len > out.len) return error.OutputTooSmall;
            @memcpy(out[len .. len + mask.len], mask);
            len += mask.len;
        }
        return out[0..len];
    }
};

const ClientList = struct {
    masks: std.ArrayList([]u8) = .empty,

    fn deinit(self: *ClientList, allocator: std.mem.Allocator) void {
        for (self.masks.items) |mask| allocator.free(mask);
        self.masks.deinit(allocator);
    }

    fn add(
        self: *ClientList,
        allocator: std.mem.Allocator,
        max_masks: usize,
        mask: []const u8,
    ) SilenceError!bool {
        for (self.masks.items) |existing| {
            if (asciiEql(existing, mask)) return false;
        }
        if (self.masks.items.len >= max_masks) return error.LimitReached;

        const copy = try allocator.dupe(u8, mask);
        errdefer allocator.free(copy);
        try self.masks.append(allocator, copy);
        return true;
    }

    fn remove(self: *ClientList, allocator: std.mem.Allocator, mask: []const u8) bool {
        for (self.masks.items, 0..) |existing, index| {
            if (asciiEql(existing, mask)) {
                const owned = self.masks.orderedRemove(index);
                allocator.free(owned);
                return true;
            }
        }
        return false;
    }
};

pub fn parse(params: []const []const u8) SilenceError!Request {
    return parseWith(.{}, params);
}

pub fn parseWith(comptime params_config: Params, params: []const []const u8) SilenceError!RequestType(params_config.max_operations) {
    var request = RequestType(params_config.max_operations){};
    for (params) |param| {
        try parseOperationTextWith(params_config, param, &request);
    }
    return request;
}

pub fn parseLine(line: []const u8) SilenceError!Request {
    return parseLineWith(.{}, line);
}

pub fn parseLineWith(comptime params_config: Params, line: []const u8) SilenceError!RequestType(params_config.max_operations) {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len < "SILENCE".len) return error.InvalidCommand;
    const command = trimmed[0.."SILENCE".len];
    if (!asciiEql(command, "SILENCE")) return error.InvalidCommand;
    if (trimmed.len == "SILENCE".len) return RequestType(params_config.max_operations){};
    if (trimmed["SILENCE".len] != ' ' and trimmed["SILENCE".len] != '\t') return error.InvalidCommand;

    var request = RequestType(params_config.max_operations){};
    try parseOperationTextWith(params_config, std.mem.trim(u8, trimmed["SILENCE".len..], " \t"), &request);
    return request;
}

fn parseOperationTextWith(comptime params_config: Params, input: []const u8, request: anytype) SilenceError!void {
    if (input.len == 0) return error.InvalidParameter;

    var cursor: usize = 0;
    while (cursor < input.len) {
        while (cursor < input.len and input[cursor] == ' ') cursor += 1;
        if (cursor == input.len) break;

        var next = cursor;
        while (next < input.len and input[next] != ',' and input[next] != ' ') next += 1;
        try request.append(try parseOperationWith(params_config, input[cursor..next]));
        cursor = if (next < input.len) next + 1 else next;
    }
}

pub fn parseOperation(token: []const u8) SilenceError!Operation {
    return parseOperationWith(.{}, token);
}

pub fn parseOperationWith(comptime params_config: Params, token: []const u8) SilenceError!Operation {
    if (token.len < 2) return error.InvalidParameter;
    const kind: OperationKind = switch (token[0]) {
        '+' => .add,
        '-' => .remove,
        else => return error.InvalidParameter,
    };
    const mask = token[1..];
    try validateMask(mask, params_config.max_mask_bytes);
    return .{ .kind = kind, .mask = mask };
}

pub fn writeSileList(out: []u8, ctx: ReplyContext, mask: []const u8) SilenceError![]const u8 {
    return writeSileListWith(.{}, out, ctx, mask);
}

pub fn writeSileListWith(comptime params: Params, out: []u8, ctx: ReplyContext, mask: []const u8) SilenceError![]const u8 {
    try validateContext(params, ctx);
    try validateMask(mask, params.max_mask_bytes);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_SILELIST, ctx.server_name, ctx.requester);
    try b.spaceParam(mask);
    try b.spaceTrailing("is silenced");
    try b.crlf();
    return b.slice();
}

pub fn writeEndOfSileList(out: []u8, ctx: ReplyContext) SilenceError![]const u8 {
    return writeEndOfSileListWith(.{}, out, ctx);
}

pub fn writeEndOfSileListWith(comptime params: Params, out: []u8, ctx: ReplyContext) SilenceError![]const u8 {
    try validateContext(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_ENDOFSILELIST, ctx.server_name, ctx.requester);
    try b.spaceTrailing("End of Silence List");
    try b.crlf();
    return b.slice();
}

fn validateContext(comptime params: Params, ctx: ReplyContext) SilenceError!void {
    try validateParam(ctx.server_name, params.max_server_bytes, error.InvalidServerName);
    try validateParam(ctx.requester, params.max_requester_bytes, error.InvalidRequester);
}

fn validateOwner(owner: []const u8, max_owner_bytes: usize) SilenceError!void {
    if (owner.len == 0) return error.InvalidOwner;
    if (owner.len > max_owner_bytes) return error.OwnerTooLong;
    try validateParam(owner, max_owner_bytes, error.InvalidOwner);
}

fn validateMask(mask: []const u8, max_mask_bytes: usize) SilenceError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > max_mask_bytes) return error.MaskTooLong;
    for (mask) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidMask,
            else => {},
        }
    }
}

fn validateParam(bytes: []const u8, max_bytes: usize, comptime err: SilenceError) SilenceError!void {
    if (bytes.len == 0 or bytes.len > max_bytes or bytes[0] == ':') return err;
    for (bytes) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

/// Fold `owner` to a canonical (lowercase) form in `buf` for case-insensitive
/// keying. Nick routing is case-insensitive, so the SILENCE owner key must be
/// too — otherwise a silenced sender bypasses the ignore by varying the target
/// nick's case. Returns null only when `owner` exceeds the scratch buffer, in
/// which case no stored key (bounded by `max_owner_bytes`) could ever match.
fn normalizeOwner(owner: []const u8, buf: []u8) ?[]const u8 {
    if (owner.len > buf.len) return null;
    for (owner, 0..) |byte, index| buf[index] = asciiLower(byte);
    return buf[0..owner.len];
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: u16, server_name: []const u8, requester: []const u8) SilenceError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');
        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) SilenceError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) SilenceError!void {
        try self.appendBytes(" :");
        try self.appendBytes(param);
    }

    fn crlf(self: *LineBuilder) SilenceError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) SilenceError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) SilenceError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

fn formatCode(code: u16, buf: []u8) []const u8 {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((code / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code % 10));
    return buf[0..3];
}

test "add remove and list bytes" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("alice", "bad!*@example.test"));
    try std.testing.expect(try store.add("alice", "spam!*@*.net"));
    try std.testing.expect(!try store.add("alice", "BAD!*@example.test"));

    var out: [128]u8 = undefined;
    try std.testing.expectEqualStrings("bad!*@example.test,spam!*@*.net", try store.list("alice", &out));
    try std.testing.expect(try store.remove("alice", "bad!*@example.test"));
    try std.testing.expect(!try store.remove("alice", "bad!*@example.test"));
    try std.testing.expectEqualStrings("spam!*@*.net", try store.list("alice", &out));
}

test "glob silence match is case-insensitive" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("target", "BadNick!*@*.Example.Test"));
    try std.testing.expect(store.isSilenced("target", "badnick!user@chat.example.test"));
    try std.testing.expect(!store.isSilenced("target", "friend!user@chat.example.test"));
}

test "parse plus and minus forms" {
    const request = try parse(&.{"+bad!*@example.test,-old!*@*.net"});
    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(OperationKind.add, request.operations[0].kind);
    try std.testing.expectEqualStrings("bad!*@example.test", request.operations[0].mask);
    try std.testing.expectEqual(OperationKind.remove, request.operations[1].kind);
    try std.testing.expectEqualStrings("old!*@*.net", request.operations[1].mask);

    const line = try parseLine("SILENCE +one!*@host,-two!*@host");
    try std.testing.expectEqual(@as(usize, 2), line.count);
    try std.testing.expectError(error.InvalidParameter, parseOperation("bad!*@host"));
}

test "numeric builders emit silence replies" {
    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "alice" };
    var buf: [160]u8 = undefined;

    try std.testing.expectEqualStrings(
        ":irc.example.test 271 alice bad!*@example.test :is silenced\r\n",
        try writeSileList(&buf, ctx, "bad!*@example.test"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 272 alice :End of Silence List\r\n",
        try writeEndOfSileList(&buf, ctx),
    );
}

test "limit and buffer bounds" {
    var store = Store.initWithParams(std.testing.allocator, .{ .max_masks_per_owner = 1 });
    defer store.deinit();

    try std.testing.expect(try store.add("alice", "one!*@host"));
    try std.testing.expectError(error.LimitReached, store.add("alice", "two!*@host"));

    var short: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, store.list("alice", &short));
    try std.testing.expectError(error.TooManyOperations, parseWith(.{ .max_operations = 1 }, &.{ "+a!*@h", "-b!*@h" }));
}

test "addWithLimit overrides the store-wide silence cap per call" {
    // Store-wide cap is 1; a per-class override of 2 admits the second mask,
    // while the global `add` path still trips at 1.
    var store = Store.initWithParams(std.testing.allocator, .{ .max_masks_per_owner = 1 });
    defer store.deinit();

    try std.testing.expect(try store.addWithLimit("alice", "one!*@host", 2));
    try std.testing.expect(try store.addWithLimit("alice", "two!*@host", 2));
    try std.testing.expectError(error.LimitReached, store.addWithLimit("alice", "three!*@host", 2));
    // The default (global) cap still tightens back to 1 for a fresh owner.
    try std.testing.expect(try store.add("bob", "one!*@host"));
    try std.testing.expectError(error.LimitReached, store.add("bob", "two!*@host"));
}

test "owner key is case-insensitive so nick-case cannot bypass the ignore" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    // Added under the canonical (mixed-case) nick...
    try std.testing.expect(try store.add("Target", "bad!*@host"));
    // ...must be found regardless of how the owner nick is cased at lookup.
    try std.testing.expect(store.isSilenced("target", "bad!user@host"));
    try std.testing.expect(store.isSilenced("TARGET", "bad!user@host"));
    try std.testing.expect(!store.isSilenced("target", "good!user@host"));

    // list/remove key case-insensitively too (no duplicate owner rows).
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("bad!*@host", try store.list("tArGeT", &out));
    try std.testing.expect(!try store.add("target", "bad!*@host")); // dup across case
    try std.testing.expect(try store.remove("TARGET", "bad!*@host"));
    try std.testing.expect(!store.isSilenced("Target", "bad!user@host"));
}

test "no leak after owner removal" {
    var store = Store.init(std.testing.allocator);
    try std.testing.expect(try store.add("alice", "bad!*@host"));
    try std.testing.expect(try store.remove("alice", "bad!*@host"));
    store.deinit();
}

test "masksInto enumerates an owner's masks for the Helix upgrade seal" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expect(try store.add("Carrier", "bad!*@host"));
    try std.testing.expect(try store.add("Carrier", "worse!*@*"));

    var out: [8][]const u8 = undefined;
    const n = store.masksInto("carrier", &out); // owner lookup is case-insensitive
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("bad!*@host", out[0]);
    try std.testing.expectEqualStrings("worse!*@*", out[1]);

    // Truncates to the out buffer; unknown owner enumerates empty.
    var one: [1][]const u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), store.masksInto("Carrier", &one));
    try std.testing.expectEqual(@as(usize, 0), store.masksInto("nobody", &out));

    // Restore into a fresh store (the successor) via the normal add path.
    var succ = Store.init(std.testing.allocator);
    defer succ.deinit();
    for (out[0..n]) |m| _ = try succ.add("Carrier", m);
    try std.testing.expect(succ.isSilenced("carrier", "bad!x@host"));
}
