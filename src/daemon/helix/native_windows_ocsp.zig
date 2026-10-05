// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-size Windows Helix custody for the OCSP fetch scheduler only.
//! Current, pending, and retained DER staple generations belong to Server.

const std = @import("std");
const ocsp = @import("../ocsp_staple.zig");
const runtime_pause = @import("../runtime_pause.zig");
const frame = @import("native_windows_companion_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'O', 'C' };
pub const max_checkpoint_bytes: usize = frame.header_len + payload_len + frame.checksum_len;
pub const Error = frame.Error;
const domain = "onyx-windows-ocsp-scheduler-checkpoint-v1";
const payload_len: usize = 104;

pub fn isCheckpoint(bytes: []const u8) bool {
    return frame.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const payload = try frame.validateFrame(bytes, checkpoint_magic, domain, payload_len);
    const serial_len = payload[56];
    if (serial_len > 24) return error.InvalidSnapshot;
    for (payload[32 + @as(usize, serial_len) .. 56]) |byte| if (byte != 0) return error.InvalidSnapshot;
    if (payload[77] > 1 or payload[78] > 1) return error.InvalidSnapshot;
    if (std.mem.readInt(i64, payload[79..87], .little) < 0 or
        std.mem.readInt(i64, payload[95..103], .little) < 0) return error.InvalidSnapshot;
    _ = std.enums.fromInt(ocsp.Execution, payload[103]) orelse return error.InvalidSnapshot;
}

pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: *const ocsp.Snapshot, owner: *const ocsp.Service) Error![]u8 {
    snapshot.validate(owner.tls, owner.opts, owner.trust_anchors) catch |err| return convertValidation(err);
    const bytes = try frame.create(allocator, checkpoint_magic, payload_len);
    errdefer allocator.free(bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    @memcpy(payload[0..32], &snapshot.config_digest);
    @memcpy(payload[32..56], &snapshot.last_serial);
    payload[56] = snapshot.last_serial_len;
    std.mem.writeInt(i64, payload[57..65], snapshot.next_refresh_unix, .little);
    std.mem.writeInt(u32, payload[65..69], snapshot.fail_count, .little);
    std.mem.writeInt(i64, payload[69..77], snapshot.next_retry_unix, .little);
    payload[77] = @intFromBool(snapshot.warned_no_issuer);
    payload[78] = @intFromBool(snapshot.warned_no_aia);
    std.mem.writeInt(i64, payload[79..87], snapshot.next_check_ms, .little);
    std.mem.writeInt(u64, payload[87..95], snapshot.completed_checks, .little);
    std.mem.writeInt(i64, payload[95..103], snapshot.captured_monotonic_ms, .little);
    payload[103] = @intFromEnum(snapshot.execution);
    frame.finish(bytes, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decodeSnapshot(bytes: []const u8, owner: *const ocsp.Service) Error!ocsp.Snapshot {
    try validateCheckpoint(bytes);
    const payload = bytes[frame.header_len .. bytes.len - frame.checksum_len];
    const result = ocsp.Snapshot{
        .config_digest = payload[0..32].*,
        .last_serial = payload[32..56].*,
        .last_serial_len = payload[56],
        .next_refresh_unix = std.mem.readInt(i64, payload[57..65], .little),
        .fail_count = std.mem.readInt(u32, payload[65..69], .little),
        .next_retry_unix = std.mem.readInt(i64, payload[69..77], .little),
        .warned_no_issuer = payload[77] == 1,
        .warned_no_aia = payload[78] == 1,
        .next_check_ms = std.mem.readInt(i64, payload[79..87], .little),
        .completed_checks = std.mem.readInt(u64, payload[87..95], .little),
        .captured_monotonic_ms = std.mem.readInt(i64, payload[95..103], .little),
        .execution = std.enums.fromInt(ocsp.Execution, payload[103]).?,
    };
    result.validate(owner.tls, owner.opts, owner.trust_anchors) catch |err| return convertValidation(err);
    return result;
}

pub fn capturePausedEncoded(allocator: std.mem.Allocator, owner: *ocsp.Service, token: runtime_pause.Token) ![]u8 {
    const snapshot = try owner.capturePaused(token);
    return encodeSnapshot(allocator, &snapshot, owner);
}

pub fn captureUnstartedEncoded(allocator: std.mem.Allocator, owner: *ocsp.Service) ![]u8 {
    const snapshot = try owner.captureUnstarted();
    return encodeSnapshot(allocator, &snapshot, owner);
}

pub fn restoreEncodedParked(owner: *ocsp.Service, bytes: []const u8) !void {
    const snapshot = try decodeSnapshot(bytes, owner);
    try owner.restoreSnapshotParked(&snapshot);
}

fn convertValidation(err: anyerror) Error {
    return if (err == error.ConfigMismatch) error.ConfigMismatch else error.InvalidSnapshot;
}

test "HXOC checkpoint preserves serial, backoff, warnings, deadline, and clock" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    const owner = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    var serial: [24]u8 = @splat(0);
    serial[0] = 3;
    serial[1] = 7;
    const snapshot = ocsp.Snapshot{
        .config_digest = try ocsp.configDigest(owner.tls, owner.opts, owner.trust_anchors),
        .last_serial = serial,
        .last_serial_len = 2,
        .next_refresh_unix = -10,
        .fail_count = 5,
        .next_retry_unix = 1_700_000_007,
        .warned_no_issuer = true,
        .warned_no_aia = false,
        .next_check_ms = 123456,
        .completed_checks = 8,
        .captured_monotonic_ms = 123000,
        .execution = .paused,
    };
    const bytes = try encodeSnapshot(alloc, &snapshot, &owner);
    defer alloc.free(bytes);
    const decoded = try decodeSnapshot(bytes, &owner);
    try std.testing.expectEqualDeep(snapshot, decoded);
    var candidate = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    try candidate.restoreSnapshot(&decoded);
    try std.testing.expectEqual(snapshot.next_retry_unix, candidate.next_retry_unix);
    try std.testing.expectEqual(snapshot.last_serial_len, candidate.last_serial_len);
}

test "HXOC checkpoint rejects malformed serial and changed candidate policy" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var owner = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    const bytes = try captureUnstartedEncoded(alloc, &owner);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[frame.header_len + 56] = 25;
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    bad[frame.header_len + 56] = 0;
    bad[frame.header_len + 77] = 2;
    frame.finish(bad, domain);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    const changed = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{ .check_interval_ms = 1 });
    try std.testing.expectError(error.ConfigMismatch, decodeSnapshot(bytes, &changed));
}

test "HXOC checkpoint encode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var owner = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    const snapshot = try owner.captureUnstarted();
    const Sweep = struct {
        fn run(a: std.mem.Allocator, s: *const ocsp.Snapshot, o: *const ocsp.Service) !void {
            const encoded = try encodeSnapshot(a, s, o);
            defer a.free(encoded);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Sweep.run, .{ &snapshot, &owner });
}

test "HXOC checkpoint restores only into an actual parked Gate worker" {
    const alloc = std.testing.allocator;
    var server: @import("../server.zig").Server = undefined;
    const tls: @import("../config_format.zig").Config.Tls = .{};
    var source = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    source.last_serial[0] = 0x42;
    source.last_serial_len = 1;
    source.next_retry_unix = 333;
    source.fail_count = 4;
    const bytes = try captureUnstartedEncoded(alloc, &source);
    defer alloc.free(bytes);
    var candidate = ocsp.Service.init(alloc, std.testing.io, &server, &tls, .{});
    try std.testing.expectError(error.NotPrepared, restoreEncodedParked(&candidate, bytes));
    try candidate.prepareColdResources(std.testing.io);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .ocsp, .instance = 0, .owner_identity = &candidate }};
    const gate = try runtime_pause.start_gate.create(alloc, std.testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        candidate.stop();
        gate.control.destroyJoined();
    }
    try candidate.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.ocsp, 0, &candidate));
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try restoreEncodedParked(&candidate, bytes);
    try candidate.requireParked();
    try std.testing.expectEqual(@as(i64, 333), candidate.next_retry_unix);
    try std.testing.expectEqual(@as(u32, 4), candidate.fail_count);
    try std.testing.expectEqual(@as(u8, 0x42), candidate.last_serial[0]);
}
