// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private Windows native Helix control transport. Two anonymous pipes carry
//! exact, ordered, HMAC-authenticated frames. The only inheritable pipe ends
//! are explicitly allowlisted when the candidate is created.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Key = [32]u8;
pub const Identity = struct { generation: u64, upgrade_id: [16]u8 };
pub const Kind = enum(u16) { hello = 1, capabilities, arena, descriptors, ack, ready, commit, abort, wal_custody, source_digest, commit_ack, metrics_custody, webhook_custody, history_custody, udp_custody, media_custody, webtransport_custody, active_media_udp_custody };
pub const max_body = 2048;
pub const header_len = 48;
pub const tag_len = Hmac.mac_length;
const prelude_len = 64;
const domain = "onyx-helix-windows-control-v1";
const pipe_capacity: u32 = 8192;
const duplicate_same_access: u32 = 2;

extern "kernel32" fn CreatePipe(read: *usize, write: *usize, attributes: ?*anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetHandleInformation(handle: usize, flags: *u32) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn PeekNamedPipe(handle: usize, buffer: ?*anyopaque, buffer_size: u32, read: ?*u32, available: ?*u32, left: ?*u32) callconv(.winapi) i32;
extern "kernel32" fn ReadFile(handle: usize, buffer: [*]u8, count: u32, read: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn WriteFile(handle: usize, buffer: [*]const u8, count: u32, written: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;

pub const Error = error{
    Unsupported,
    PipeFailed,
    DuplicateFailed,
    InvalidHandle,
    ReadFailed,
    WriteFailed,
    BrokenPipe,
    Timeout,
    TooLarge,
    Protocol,
    AuthenticationFailed,
    Poisoned,
};

fn closeOwned(handle: *usize) void {
    if (comptime builtin.os.tag == .windows) {
        if (handle.* != 0) _ = CloseHandle(handle.*);
    }
    handle.* = 0;
}

/// Both child ends are inheritable, while parent ends are never inheritable.
/// Until CreateProcessW completes, the caller retains custody of all four.
pub const Pair = struct {
    parent_read: usize = 0,
    parent_write: usize = 0,
    child_read: usize = 0,
    child_write: usize = 0,

    pub fn init() Error!Pair {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        var result = Pair{};
        errdefer result.deinit();
        const own = GetCurrentProcess();
        var source_read: usize = 0;
        var source_write: usize = 0;
        if (CreatePipe(&source_read, &source_write, null, pipe_capacity) == 0) return error.PipeFailed;
        defer closeOwned(&source_read);
        result.parent_write = source_write;
        source_write = 0;
        if (DuplicateHandle(own, source_read, own, &result.child_read, 0, 1, duplicate_same_access) == 0) return error.DuplicateFailed;
        closeOwned(&source_read);

        if (CreatePipe(&source_read, &source_write, null, pipe_capacity) == 0) return error.PipeFailed;
        result.parent_read = source_read;
        source_read = 0;
        defer closeOwned(&source_write);
        if (DuplicateHandle(own, source_write, own, &result.child_write, 0, 1, duplicate_same_access) == 0) return error.DuplicateFailed;
        return result;
    }

    pub fn closeChildCopies(self: *Pair) void {
        closeOwned(&self.child_read);
        closeOwned(&self.child_write);
    }

    pub fn takeParent(self: *Pair, identity: Identity, key: Key) Endpoint {
        const result = Endpoint{ .read_handle = self.parent_read, .write_handle = self.parent_write, .identity = identity, .key = key, .role = .parent };
        self.parent_read = 0;
        self.parent_write = 0;
        return result;
    }

    pub fn takeChild(self: *Pair, identity: Identity, key: Key) Endpoint {
        const result = Endpoint{ .read_handle = self.child_read, .write_handle = self.child_write, .identity = identity, .key = key, .role = .child };
        self.child_read = 0;
        self.child_write = 0;
        return result;
    }

    pub fn deinit(self: *Pair) void {
        closeOwned(&self.parent_read);
        closeOwned(&self.parent_write);
        self.closeChildCopies();
    }
};

fn writeAll(handle: usize, bytes: []const u8, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (handle == 0) return error.InvalidHandle;
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        var written: u32 = 0;
        if (WriteFile(handle, bytes[offset..].ptr, @intCast(bytes.len - offset), &written, null) == 0) return error.WriteFailed;
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

fn readExact(handle: usize, bytes: []u8, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (handle == 0) return error.InvalidHandle;
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        var available: u32 = 0;
        if (PeekNamedPipe(handle, null, 0, null, &available, null) == 0) return error.BrokenPipe;
        if (available == 0) {
            Sleep(1);
            continue;
        }
        var count: u32 = 0;
        if (ReadFile(handle, bytes[offset..].ptr, @intCast(@min(bytes.len - offset, @as(usize, available))), &count, null) == 0) return error.ReadFailed;
        if (count == 0) return error.BrokenPipe;
        offset += count;
    }
}

pub const Prelude = struct { identity: Identity, key: Key };

/// The bootstrap key is private because only the allowlisted child read end
/// receives it. Every subsequent frame has a direction-separated HMAC.
pub fn sendPrelude(handle: usize, prelude: Prelude, deadline: i64) Error!void {
    var bytes: [prelude_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    @memcpy(bytes[0..8], "HXWCBOOT");
    std.mem.writeInt(u64, bytes[8..16], prelude.identity.generation, .big);
    @memcpy(bytes[16..32], &prelude.identity.upgrade_id);
    @memcpy(bytes[32..64], &prelude.key);
    try writeAll(handle, &bytes, deadline);
}

pub fn receivePrelude(handle: usize, deadline: i64) Error!Prelude {
    var bytes: [prelude_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    try readExact(handle, &bytes, deadline);
    if (!std.mem.eql(u8, bytes[0..8], "HXWCBOOT")) return error.Protocol;
    return .{ .identity = .{ .generation = std.mem.readInt(u64, bytes[8..16], .big), .upgrade_id = bytes[16..32].* }, .key = bytes[32..64].* };
}

fn mac(key: *const Key, direction: u8, bytes: []const u8) [tag_len]u8 {
    var hmac = Hmac.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
    hmac.update(domain);
    hmac.update(&.{direction});
    hmac.update(bytes);
    var tag: [tag_len]u8 = undefined;
    hmac.final(&tag);
    return tag;
}

pub const Message = struct {
    kind: Kind,
    body: [max_body]u8 = undefined,
    length: usize = 0,

    pub fn bytes(self: *const Message) []const u8 {
        return self.body[0..self.length];
    }

    pub fn deinit(self: *Message) void {
        std.crypto.secureZero(u8, &self.body);
        self.length = 0;
    }
};

pub const Endpoint = struct {
    read_handle: usize,
    write_handle: usize,
    identity: Identity,
    key: Key,
    role: enum { parent, child },
    send_seq: u64 = 0,
    recv_seq: u64 = 0,
    awaiting_response: bool = false,
    poisoned: bool = false,

    pub fn deinit(self: *Endpoint) void {
        closeOwned(&self.read_handle);
        closeOwned(&self.write_handle);
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.identity.upgrade_id);
        self.poisoned = true;
    }

    /// Stop-and-wait framing keeps at most one frame queued in each pipe;
    /// every frame fits the requested pipe capacity before any peer response.
    pub fn send(self: *Endpoint, kind: Kind, body: []const u8, deadline: i64) Error!void {
        if (self.poisoned) return error.Poisoned;
        if (self.awaiting_response) return error.Protocol;
        if (body.len > max_body) return error.TooLarge;
        if (self.send_seq == std.math.maxInt(u64)) return error.Protocol;
        var wire: [header_len + max_body + tag_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &wire);
        @memcpy(wire[0..4], "HXWC");
        std.mem.writeInt(u16, wire[4..6], 1, .big);
        std.mem.writeInt(u16, wire[6..8], @intFromEnum(kind), .big);
        std.mem.writeInt(u64, wire[8..16], self.identity.generation, .big);
        @memcpy(wire[16..32], &self.identity.upgrade_id);
        std.mem.writeInt(u64, wire[32..40], self.send_seq, .big);
        std.mem.writeInt(u32, wire[40..44], @intCast(body.len), .big);
        std.mem.writeInt(u32, wire[44..48], 0, .big);
        @memcpy(wire[header_len..][0..body.len], body);
        const signed_len = header_len + body.len;
        const tag = mac(&self.key, if (self.role == .parent) 'P' else 'C', wire[0..signed_len]);
        @memcpy(wire[signed_len..][0..tag_len], &tag);
        writeAll(self.write_handle, wire[0 .. signed_len + tag_len], deadline) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.send_seq += 1;
        self.awaiting_response = true;
    }

    pub fn receive(self: *Endpoint, deadline: i64) Error!Message {
        if (self.poisoned) return error.Poisoned;
        if (self.recv_seq == std.math.maxInt(u64)) return error.Protocol;
        return self.receiveOne(deadline) catch |err| {
            self.poisoned = true;
            return err;
        };
    }

    fn receiveOne(self: *Endpoint, deadline: i64) Error!Message {
        var wire: [header_len + max_body + tag_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &wire);
        try readExact(self.read_handle, wire[0..header_len], deadline);
        if (!std.mem.eql(u8, wire[0..4], "HXWC") or
            std.mem.readInt(u16, wire[4..6], .big) != 1 or
            std.mem.readInt(u32, wire[44..48], .big) != 0)
            return error.Protocol;
        const length: usize = std.mem.readInt(u32, wire[40..44], .big);
        if (length > max_body) return error.TooLarge;
        try readExact(self.read_handle, wire[header_len .. header_len + length + tag_len], deadline);
        const signed_len = header_len + length;
        const expected = mac(&self.key, if (self.role == .parent) 'C' else 'P', wire[0..signed_len]);
        const actual: [tag_len]u8 = wire[signed_len..][0..tag_len].*;
        if (!std.crypto.timing_safe.eql([tag_len]u8, expected, actual)) return error.AuthenticationFailed;
        if (std.mem.readInt(u64, wire[8..16], .big) != self.identity.generation or
            !std.mem.eql(u8, wire[16..32], &self.identity.upgrade_id) or
            std.mem.readInt(u64, wire[32..40], .big) != self.recv_seq)
            return error.Protocol;
        const kind = std.enums.fromInt(Kind, std.mem.readInt(u16, wire[6..8], .big)) orelse return error.Protocol;
        var message = Message{ .kind = kind, .length = length };
        @memcpy(message.body[0..length], wire[header_len..][0..length]);
        self.recv_seq += 1;
        self.awaiting_response = false;
        return message;
    }
};

test "Windows Helix private control authenticates direction, identity, order and body" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try Pair.init();
    defer pair.deinit();
    for ([_]usize{ pair.parent_read, pair.parent_write }) |handle| {
        var flags: u32 = 0;
        try std.testing.expect(GetHandleInformation(handle, &flags) != 0);
        try std.testing.expectEqual(@as(u32, 0), flags & 1);
    }
    for ([_]usize{ pair.child_read, pair.child_write }) |handle| {
        var flags: u32 = 0;
        try std.testing.expect(GetHandleInformation(handle, &flags) != 0);
        try std.testing.expectEqual(@as(u32, 1), flags & 1);
    }
    const identity: Identity = .{ .generation = 11, .upgrade_id = @splat(5) };
    const key: Key = @splat(7);
    try sendPrelude(pair.parent_write, .{ .identity = identity, .key = key }, platform.monotonicMillis() + 1000);
    const prelude = try receivePrelude(pair.child_read, platform.monotonicMillis() + 1000);
    try std.testing.expectEqual(identity.generation, prelude.identity.generation);
    try std.testing.expectEqual(identity.upgrade_id, prelude.identity.upgrade_id);
    try std.testing.expectEqual(key, prelude.key);
    var parent = pair.takeParent(identity, key);
    defer parent.deinit();
    var child = pair.takeChild(identity, key);
    defer child.deinit();
    try parent.send(.hello, "capability", platform.monotonicMillis() + 1000);
    try std.testing.expectError(error.Protocol, parent.send(.arena, "second frame", platform.monotonicMillis() + 1000));
    var hello = try child.receive(platform.monotonicMillis() + 1000);
    defer hello.deinit();
    try std.testing.expectEqual(Kind.hello, hello.kind);
    try std.testing.expectEqualStrings("capability", hello.bytes());
    try child.send(.capabilities, "current", platform.monotonicMillis() + 1000);
    var reply = try parent.receive(platform.monotonicMillis() + 1000);
    defer reply.deinit();
    try std.testing.expectEqualStrings("current", reply.bytes());
    try parent.send(.arena, "authenticated", platform.monotonicMillis() + 1000);
    var arena = try child.receive(platform.monotonicMillis() + 1000);
    defer arena.deinit();
    try std.testing.expectEqualStrings("authenticated", arena.bytes());
}

test "Windows Helix private control refuses wrong key and deadline" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try Pair.init();
    defer pair.deinit();
    const identity: Identity = .{ .generation = 1, .upgrade_id = @splat(2) };
    var parent = pair.takeParent(identity, @splat(3));
    defer parent.deinit();
    var child = pair.takeChild(identity, @splat(4));
    defer child.deinit();
    try std.testing.expectError(error.Timeout, child.receive(platform.monotonicMillis() + 5));
    try std.testing.expectError(error.Poisoned, child.receive(platform.monotonicMillis() + 5));
    try parent.send(.hello, "tampered key", platform.monotonicMillis() + 1000);
    var another = Endpoint{ .read_handle = child.read_handle, .write_handle = 0, .identity = identity, .key = @splat(4), .role = .child };
    child.read_handle = 0;
    defer another.deinit();
    try std.testing.expectError(error.AuthenticationFailed, another.receive(platform.monotonicMillis() + 1000));
}

test "Windows Helix private control rejects a signed frame for another upgrade" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try Pair.init();
    defer pair.deinit();
    const original: Identity = .{ .generation = 3, .upgrade_id = @splat(8) };
    var parent = pair.takeParent(original, @splat(9));
    defer parent.deinit();
    var wrong = original;
    wrong.generation += 1;
    var child = pair.takeChild(wrong, @splat(9));
    defer child.deinit();
    try parent.send(.hello, "old generation", platform.monotonicMillis() + 1000);
    try std.testing.expectError(error.Protocol, child.receive(platform.monotonicMillis() + 1000));
}
