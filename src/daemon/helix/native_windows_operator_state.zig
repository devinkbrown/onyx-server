// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for mutable pre-registration challenge policy
//! and a pending two-person operator approval.

const std = @import("std");
const challenge = @import("../challenge.zig");
const frame = @import("native_windows_companion_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'O', 'P' };
const domain = "onyx-windows-operator-state-checkpoint-v1";
pub const max_target: usize = 256;
pub const max_identity: usize = 64;
const payload_len: usize = 27 + challenge.max_text + challenge.max_answer + max_target + max_identity;
pub const max_checkpoint_bytes: usize = frame.header_len + payload_len + frame.checksum_len;
pub const Error = error{InvalidSnapshot} || std.mem.Allocator.Error;

pub const PendingKind = enum(u8) { die = 1, restart = 2, ward_add = 3, ward_del = 4 };

pub const PendingView = struct {
    kind: PendingKind,
    target: []const u8,
    identity: []const u8,
    at_ms: i64,
};

pub const View = struct {
    method: challenge.Method,
    question: []const u8,
    answer: []const u8,
    issued: u64,
    pending: ?PendingView = null,
};

pub const Pending = struct {
    kind: PendingKind,
    target: [max_target]u8 = @splat(0),
    target_len: usize = 0,
    identity: [max_identity]u8 = @splat(0),
    identity_len: usize = 0,
    at_ms: i64 = 0,
};

pub const Decoded = struct {
    method: challenge.Method,
    question: [challenge.max_text]u8 = @splat(0),
    question_len: usize = 0,
    answer: [challenge.max_answer]u8 = @splat(0),
    answer_len: usize = 0,
    issued: u64 = 0,
    pending: ?Pending = null,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

pub fn encode(allocator: std.mem.Allocator, view: View) Error![]u8 {
    if (view.question.len > challenge.max_text or view.answer.len > challenge.max_answer) return error.InvalidSnapshot;
    if (view.pending) |pending| {
        if (pending.target.len > max_target or pending.identity.len == 0 or pending.identity.len > max_identity)
            return error.InvalidSnapshot;
    }
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer allocator.free(bytes);
    const body = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    @memset(body, 0);
    body[0] = @intFromEnum(view.method);
    std.mem.writeInt(u16, body[1..3], @intCast(view.question.len), .little);
    std.mem.writeInt(u16, body[3..5], @intCast(view.answer.len), .little);
    std.mem.writeInt(u64, body[5..13], view.issued, .little);
    @memcpy(body[27 .. 27 + view.question.len], view.question);
    @memcpy(body[187 .. 187 + view.answer.len], view.answer);
    if (view.pending) |pending| {
        body[13] = 1;
        body[14] = @intFromEnum(pending.kind);
        std.mem.writeInt(u16, body[15..17], @intCast(pending.target.len), .little);
        std.mem.writeInt(u16, body[17..19], @intCast(pending.identity.len), .little);
        std.mem.writeInt(i64, body[19..27], pending.at_ms, .little);
        @memcpy(body[251 .. 251 + pending.target.len], pending.target);
        @memcpy(body[507 .. 507 + pending.identity.len], pending.identity);
    }
    frame.finish(bytes, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const body = try frame.validateFrame(bytes, checkpoint_magic, domain, payload_len);
    _ = std.enums.fromInt(challenge.Method, body[0]) orelse return error.InvalidSnapshot;
    const question_len: usize = std.mem.readInt(u16, body[1..3], .little);
    const answer_len: usize = std.mem.readInt(u16, body[3..5], .little);
    if (question_len > challenge.max_text or answer_len > challenge.max_answer) return error.InvalidSnapshot;
    if (!allZero(body[27 + question_len .. 187]) or !allZero(body[187 + answer_len .. 251]))
        return error.InvalidSnapshot;
    if (body[13] > 1) return error.InvalidSnapshot;
    if (body[13] == 0) {
        if (!allZero(body[14..27]) or !allZero(body[251..])) return error.InvalidSnapshot;
    } else {
        _ = std.enums.fromInt(PendingKind, body[14]) orelse return error.InvalidSnapshot;
        const target_len: usize = std.mem.readInt(u16, body[15..17], .little);
        const identity_len: usize = std.mem.readInt(u16, body[17..19], .little);
        if (target_len > max_target or identity_len == 0 or identity_len > max_identity or
            !allZero(body[251 + target_len .. 507]) or !allZero(body[507 + identity_len ..]))
            return error.InvalidSnapshot;
    }
}

pub fn decode(bytes: []const u8) error{InvalidSnapshot}!Decoded {
    try validateCheckpoint(bytes);
    const body = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    var result = Decoded{ .method = std.enums.fromInt(challenge.Method, body[0]).? };
    result.question_len = std.mem.readInt(u16, body[1..3], .little);
    result.answer_len = std.mem.readInt(u16, body[3..5], .little);
    result.issued = std.mem.readInt(u64, body[5..13], .little);
    @memcpy(result.question[0..result.question_len], body[27 .. 27 + result.question_len]);
    @memcpy(result.answer[0..result.answer_len], body[187 .. 187 + result.answer_len]);
    if (body[13] == 1) {
        var pending = Pending{ .kind = std.enums.fromInt(PendingKind, body[14]).? };
        pending.target_len = std.mem.readInt(u16, body[15..17], .little);
        pending.identity_len = std.mem.readInt(u16, body[17..19], .little);
        pending.at_ms = std.mem.readInt(i64, body[19..27], .little);
        @memcpy(pending.target[0..pending.target_len], body[251 .. 251 + pending.target_len]);
        @memcpy(pending.identity[0..pending.identity_len], body[507 .. 507 + pending.identity_len]);
        result.pending = pending;
    }
    return result;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

test "HXOP carries operator challenge and pending approval exactly" {
    const allocator = std.testing.allocator;
    const bytes = try encode(allocator, .{
        .method = .question,
        .question = "What is Onyx?",
        .answer = "a network",
        .issued = 12345,
        .pending = .{ .kind = .ward_add, .target = "bad.example", .identity = "oper-a", .at_ms = 700 },
    });
    defer allocator.free(bytes);
    const decoded = try decode(bytes);
    try std.testing.expectEqual(challenge.Method.question, decoded.method);
    try std.testing.expectEqualStrings("What is Onyx?", decoded.question[0..decoded.question_len]);
    try std.testing.expectEqualStrings("a network", decoded.answer[0..decoded.answer_len]);
    try std.testing.expectEqual(@as(u64, 12345), decoded.issued);
    try std.testing.expectEqual(PendingKind.ward_add, decoded.pending.?.kind);
    try std.testing.expectEqualStrings("bad.example", decoded.pending.?.target[0..decoded.pending.?.target_len]);
    try std.testing.expectEqualStrings("oper-a", decoded.pending.?.identity[0..decoded.pending.?.identity_len]);
}

test "HXOP rejects tamper and noncanonical unused bytes" {
    const allocator = std.testing.allocator;
    const bytes = try encode(allocator, .{ .method = .pow, .question = "", .answer = "", .issued = 0 });
    defer allocator.free(bytes);
    bytes[frame.header_len + 14] = 1;
    frame.finish(bytes, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bytes));
    bytes[frame.header_len + 14] = 0;
    bytes[frame.header_len + 27] = 1;
    frame.finish(bytes, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bytes));
    bytes[frame.header_len + 27] = 0;
    bytes[frame.header_len + 13] = 2;
    frame.finish(bytes, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bytes));
}

test "HXOP encode allocation failure sweep" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const bytes = try encode(allocator, .{ .method = .pow, .question = "", .answer = "", .issued = 8 });
            defer allocator.free(bytes);
            try validateCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}
