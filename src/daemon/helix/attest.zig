// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helix health attestation and rollback policy.
//!
//! The old worker stays resumable until the replacement proves health. This file
//! contains only deterministic message encoding and decision logic; process
//! management belongs to the supervisor runtime.

const std = @import("std");
const coilpack = @import("../../proto/coilpack.zig");

const Allocator = std.mem.Allocator;

const magic = [_]u8{ 'H', 'A', 'T', '1' };

pub const Error = error{
    BadMagic,
    UnknownVerdict,
    InvalidEpoch,
    InvalidCounters,
    DeadlineExpired,
    TrailingBytes,
} || Allocator.Error || coilpack.DecodeError || coilpack.EncodeError;

pub const Verdict = enum(u8) {
    pending = 0,
    healthy = 1,
    failed = 2,

    pub fn fromByte(byte: u8) Error!Verdict {
        return switch (byte) {
            0 => .pending,
            1 => .healthy,
            2 => .failed,
            else => error.UnknownVerdict,
        };
    }
};

pub const Reason = enum(u8) {
    none = 0,
    capsule_validation = 1,
    fd_import = 2,
    reactor_start = 3,
    timeout = 4,
    worker_exit = 5,
    operator_abort = 6,
};

pub const Message = struct {
    worker_epoch: u64,
    monotonic_ms: i64,
    capsule_count: u32,
    fd_count: u32,
    verdict: Verdict,
    reason: Reason = .none,

    pub fn validate(self: Message, expected_epoch: u64, deadline_ms: i64) Error!void {
        if (self.worker_epoch != expected_epoch) return error.InvalidEpoch;
        if (self.monotonic_ms > deadline_ms) return error.DeadlineExpired;
        if (self.verdict == .healthy and self.reason != .none) return error.InvalidCounters;
        if (self.verdict == .healthy and (self.capsule_count == 0 and self.fd_count == 0)) {
            return error.InvalidCounters;
        }
    }
};

pub const Snapshot = struct {
    expected_epoch: u64,
    deadline_ms: i64,
    now_ms: i64,
    capsules_exported: u32 = 0,
    fds_handed_off: u32 = 0,
};

pub const Decision = enum {
    wait,
    commit,
    rollback,
};

pub fn decide(snapshot: Snapshot, message: ?Message) Decision {
    if (snapshot.now_ms >= snapshot.deadline_ms) return .rollback;
    const msg = message orelse return .wait;
    msg.validate(snapshot.expected_epoch, snapshot.deadline_ms) catch return .rollback;

    if (msg.capsule_count != snapshot.capsules_exported) return .rollback;
    if (msg.fd_count != snapshot.fds_handed_off) return .rollback;

    return switch (msg.verdict) {
        .pending => .wait,
        .healthy => .commit,
        .failed => .rollback,
    };
}

pub fn encode(allocator: Allocator, msg: Message) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, &magic);
    try appendU64(allocator, &out, msg.worker_epoch);
    try appendI64(allocator, &out, msg.monotonic_ms);
    try appendU32(allocator, &out, msg.capsule_count);
    try appendU32(allocator, &out, msg.fd_count);
    try out.append(allocator, @backingInt(msg.verdict));
    try out.append(allocator, @backingInt(msg.reason));
    return try out.toOwnedSlice(allocator);
}

pub fn decode(bytes: []const u8) Error!Message {
    var r = coilpack.Cbs.init(bytes);
    for (magic) |want| {
        const got = try r.readU8();
        if (got != want) return error.BadMagic;
    }
    const msg = Message{
        .worker_epoch = try r.readU64Le(),
        .monotonic_ms = @bitCast(try r.readU64Le()),
        .capsule_count = try r.readU32Le(),
        .fd_count = try r.readU32Le(),
        .verdict = try Verdict.fromByte(try r.readU8()),
        .reason = switch (try r.readU8()) {
            0 => .none,
            1 => .capsule_validation,
            2 => .fd_import,
            3 => .reactor_start,
            4 => .timeout,
            5 => .worker_exit,
            6 => .operator_abort,
            else => return error.UnknownVerdict,
        },
    };
    if (!r.done()) return error.TrailingBytes;
    return msg;
}

fn appendU32(allocator: Allocator, out: *std.ArrayList(u8), value: u32) Error!void {
    var buf: [4]u8 = undefined;
    var w = coilpack.Cbb.init(&buf);
    _ = try w.writeU32Le(value);
    try out.appendSlice(allocator, w.written());
}

fn appendU64(allocator: Allocator, out: *std.ArrayList(u8), value: u64) Error!void {
    var buf: [8]u8 = undefined;
    var w = coilpack.Cbb.init(&buf);
    _ = try w.writeU64Le(value);
    try out.appendSlice(allocator, w.written());
}

fn appendI64(allocator: Allocator, out: *std.ArrayList(u8), value: i64) Error!void {
    try appendU64(allocator, out, @bitCast(value));
}

test "healthy matching attestation commits before deadline" {
    const snap = Snapshot{
        .expected_epoch = 7,
        .deadline_ms = 5000,
        .now_ms = 1000,
        .capsules_exported = 3,
        .fds_handed_off = 9,
    };
    const msg = Message{
        .worker_epoch = 7,
        .monotonic_ms = 1200,
        .capsule_count = 3,
        .fd_count = 9,
        .verdict = .healthy,
    };
    try std.testing.expectEqual(Decision.commit, decide(snap, msg));
}

test "timeout and failed attestations roll back" {
    const snap = Snapshot{ .expected_epoch = 1, .deadline_ms = 10, .now_ms = 10 };
    try std.testing.expectEqual(Decision.rollback, decide(snap, null));

    const failed = Message{
        .worker_epoch = 1,
        .monotonic_ms = 2,
        .capsule_count = 0,
        .fd_count = 0,
        .verdict = .failed,
        .reason = .capsule_validation,
    };
    try std.testing.expectEqual(Decision.rollback, decide(.{ .expected_epoch = 1, .deadline_ms = 10, .now_ms = 2 }, failed));
}

test "attestation message round trips" {
    const allocator = std.testing.allocator;
    const msg = Message{
        .worker_epoch = 99,
        .monotonic_ms = -12,
        .capsule_count = 8,
        .fd_count = 21,
        .verdict = .pending,
        .reason = .none,
    };
    const encoded = try encode(allocator, msg);
    defer allocator.free(encoded);

    const decoded = try decode(encoded);
    try std.testing.expectEqual(msg.worker_epoch, decoded.worker_epoch);
    try std.testing.expectEqual(msg.monotonic_ms, decoded.monotonic_ms);
    try std.testing.expectEqual(msg.verdict, decoded.verdict);
}
