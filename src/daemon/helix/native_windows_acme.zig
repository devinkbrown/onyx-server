// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-size Windows Helix custody for the ACME renewal scheduler only.
//! TLS reload intent and certificate generations belong to the server graph.

const std = @import("std");
const acme = @import("../acme_renewal.zig");
const runtime_pause = @import("../runtime_pause.zig");
const frame = @import("native_windows_companion_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'A', 'C' };
pub const max_checkpoint_bytes: usize = frame.header_len + payload_len + frame.checksum_len;
pub const Error = frame.Error;
const domain = "onyx-windows-acme-scheduler-checkpoint-v1";
const payload_len: usize = 58;

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, payload_len);
    const next_check_ms = std.mem.readInt(i64, payload[32..40], .little);
    const completed_checks = std.mem.readInt(u64, payload[40..48], .little);
    const outcome = std.enums.fromInt(acme.Outcome, payload[48]) orelse return error.InvalidSnapshot;
    const captured_monotonic_ms = std.mem.readInt(i64, payload[49..57], .little);
    _ = std.enums.fromInt(acme.Execution, payload[57]) orelse return error.InvalidSnapshot;
    if (next_check_ms < 0 or captured_monotonic_ms < 0 or
        (completed_checks == 0 and outcome != .none)) return error.InvalidSnapshot;
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: *const acme.Snapshot, owner: *const acme.Service) Error![]u8 {
    snapshot.validate(owner.acme, owner.tls) catch |err| return convertValidation(err);
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer allocator.free(bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    @memcpy(payload[0..32], &snapshot.config_digest);
    std.mem.writeInt(i64, payload[32..40], snapshot.next_check_ms, .little);
    std.mem.writeInt(u64, payload[40..48], snapshot.completed_checks, .little);
    payload[48] = @intFromEnum(snapshot.last_outcome);
    std.mem.writeInt(i64, payload[49..57], snapshot.captured_monotonic_ms, .little);
    payload[57] = @intFromEnum(snapshot.execution);
    frame.finish(bytes, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decodeSnapshot(bytes: []const u8, owner: *const acme.Service) Error!acme.Snapshot {
    try validateCheckpoint(bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    const result = acme.Snapshot{
        .config_digest = payload[0..32].*,
        .next_check_ms = std.mem.readInt(i64, payload[32..40], .little),
        .completed_checks = std.mem.readInt(u64, payload[40..48], .little),
        .last_outcome = std.enums.fromInt(acme.Outcome, payload[48]).?,
        .captured_monotonic_ms = std.mem.readInt(i64, payload[49..57], .little),
        .execution = std.enums.fromInt(acme.Execution, payload[57]).?,
    };
    result.validate(owner.acme, owner.tls) catch |err| return convertValidation(err);
    return result;
}

pub fn capturePausedEncoded(allocator: std.mem.Allocator, owner: *acme.Service, token: runtime_pause.Token) ![]u8 {
    const snapshot = try owner.capturePaused(token);
    return encodeSnapshot(allocator, &snapshot, owner);
}

pub fn captureUnstartedEncoded(allocator: std.mem.Allocator, owner: *acme.Service) ![]u8 {
    const snapshot = try owner.captureUnstarted();
    return encodeSnapshot(allocator, &snapshot, owner);
}

pub fn restoreEncodedParked(owner: *acme.Service, bytes: []const u8) !void {
    const snapshot = try decodeSnapshot(bytes, owner);
    try owner.restoreSnapshotParked(&snapshot);
}

fn convertValidation(err: anyerror) Error {
    return if (err == error.ConfigMismatch) error.ConfigMismatch else error.InvalidSnapshot;
}

test "HXAC checkpoint preserves deadline outcome count and clock" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    const owner = acme.Service.init(alloc, std.testing.io, &server, .{ .enabled = true }, &tls);
    const snapshot = acme.Snapshot{
        .config_digest = try acme.configDigest(owner.acme, owner.tls),
        .next_check_ms = 123456,
        .completed_checks = 8,
        .last_outcome = .reload_requested,
        .captured_monotonic_ms = 123000,
        .execution = .paused,
    };
    const bytes = try encodeSnapshot(alloc, &snapshot, &owner);
    defer alloc.free(bytes);
    const decoded = try decodeSnapshot(bytes, &owner);
    try std.testing.expectEqualDeep(snapshot, decoded);
    var candidate = acme.Service.init(alloc, std.testing.io, &server, owner.acme, &tls);
    try candidate.restoreSnapshot(&decoded);
    try std.testing.expectEqual(snapshot.next_check_ms, candidate.next_check_ms);
    try std.testing.expectEqual(snapshot.last_outcome, candidate.last_outcome);
}

test "HXAC checkpoint rejects malformed enum, checksum, and config mismatch" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var owner = acme.Service.init(alloc, std.testing.io, &server, .{ .enabled = true }, &tls);
    const bytes = try captureUnstartedEncoded(alloc, &owner);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[frame.header_len + 48] = 255;
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    bad[frame.header_len + 48] = 0;
    bad[frame.header_len + 32] ^= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    const changed = acme.Service.init(alloc, std.testing.io, &server, .{ .enabled = true, .renew_before_days = 1 }, &tls);
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(bytes, &changed));
}

test "HXAC checkpoint encode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var owner = acme.Service.init(alloc, std.testing.io, &server, .{ .enabled = true }, &tls);
    const snapshot = try owner.captureUnstarted();
    const Sweep = struct {
        fn run(a: std.mem.Allocator, s: *const acme.Snapshot, o: *const acme.Service) !void {
            const encoded = try encodeSnapshot(a, s, o);
            defer a.free(encoded);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Sweep.run, .{ &snapshot, &owner });
}

test "HXAC checkpoint restores only into an actual parked Gate worker" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var source = acme.Service.init(alloc, std.testing.io, &server, .{ .enabled = true }, &tls);
    source.next_check_ms = 777;
    source.completed_checks = 2;
    source.last_outcome = .not_due;
    const bytes = try captureUnstartedEncoded(alloc, &source);
    defer alloc.free(bytes);
    var candidate = acme.Service.init(alloc, std.testing.io, &server, source.acme, &tls);
    try std.testing.expectError(error.NotPrepared, restoreEncodedParked(&candidate, bytes));
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .acme, .instance = 0, .owner_identity = &candidate }};
    const gate = try runtime_pause.start_gate.create(alloc, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        candidate.stop();
        gate.control.destroyJoined();
    }
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.acme, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try restoreEncodedParked(&candidate, bytes);
    try candidate.requireParked();
    try std.testing.expectEqual(@as(i64, 777), candidate.next_check_ms);
    try std.testing.expectEqual(@as(u64, 2), candidate.completed_checks);
    try std.testing.expectEqual(acme.Outcome.not_due, candidate.last_outcome);
}
