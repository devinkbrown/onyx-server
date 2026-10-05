// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded Web Push worker custody for Windows Helix. The outer handoff must
//! authenticate and encrypt these bytes: jobs include cleartext and auth keys.
//! No callback, resolver pointer, TLS owner, or worker thread enters the wire.

const std = @import("std");
const webpush = @import("../webpush.zig");
const runtime_pause = @import("../runtime_pause.zig");

const magic = "HXWP";
const version: u16 = 1;
const header_len: usize = 88;
const checksum_len: usize = 32;
const job_header_len: usize = 4 + 4 + 65 + 16;
const checksum_domain = "onyx-windows-webpush-checkpoint-v1";

pub const snapshot_bounds: webpush.SnapshotBounds = .{
    .max_bytes = 4 * 1024 * 1024,
    .max_dead_entries = webpush.max_queued_jobs,
};
pub const max_checkpoint_bytes: usize = snapshot_bounds.max_bytes + 64 * 1024;

comptime {
    if (webpush.max_queued_jobs > std.math.maxInt(u16) or
        snapshot_bounds.max_dead_entries > std.math.maxInt(u16) or
        max_checkpoint_bytes > std.math.maxInt(u32) or
        @sizeOf(@FieldType(webpush.Job, "ua_public")) != 65 or
        @sizeOf(@FieldType(webpush.Job, "auth")) != 16)
        @compileError("Windows Web Push checkpoint exceeds its wire bounds");
}

pub const Error = std.mem.Allocator.Error || error{
    InvalidSnapshot,
    ConfigMismatch,
    TooLarge,
};

const Header = struct {
    jobs: usize,
    dead: usize,
    sent: usize,
    failed: usize,
    dropped: usize,
    overflow_events: usize,
    execution: webpush.Execution,
    config_digest: [32]u8,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

/// Validate all framing and content boundaries without allocating or reading
/// process-local pointers. The candidate config comparison happens at decode.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    const header = try parseHeader(bytes);
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (0..header.jobs) |_| {
        const endpoint_len = try reader.readU32();
        const payload_len = try reader.readU32();
        _ = try reader.take(65);
        _ = try reader.take(16);
        _ = try reader.take(endpoint_len);
        _ = try reader.take(payload_len);
    }
    for (0..header.dead) |_| {
        const endpoint_len = try reader.readU32();
        _ = try reader.take(endpoint_len);
    }
    if (reader.remaining() != 0) return error.InvalidSnapshot;
}

/// Encode only initialized fields of a real frozen snapshot. The caller owns
/// the returned sensitive bytes and must release them with `freeEncoded`.
pub fn encodeSnapshot(allocator: std.mem.Allocator, snapshot: *const webpush.Snapshot, owner: *const webpush.Worker) Error![]u8 {
    snapshot.validate(owner, snapshot_bounds) catch |err| switch (err) {
        error.Capacity => return error.TooLarge,
        else => return error.ConfigMismatch,
    };
    if (snapshot.jobs.len > webpush.max_queued_jobs or snapshot.dead.len > snapshot_bounds.max_dead_entries)
        return error.TooLarge;
    var total: usize = header_len + checksum_len;
    for (snapshot.jobs) |job| {
        try addLen(&total, job_header_len);
        try addLen(&total, job.endpoint.len);
        try addLen(&total, job.payload.len);
    }
    for (snapshot.dead) |endpoint| {
        try addLen(&total, 4);
        try addLen(&total, endpoint.len);
    }
    const sent = std.math.cast(u64, snapshot.sent) orelse return error.TooLarge;
    const failed = std.math.cast(u64, snapshot.failed) orelse return error.TooLarge;
    const dropped = std.math.cast(u64, snapshot.dropped) orelse return error.TooLarge;
    const overflow_events = std.math.cast(u64, snapshot.overflow_events) orelse return error.TooLarge;

    const out = try allocator.alloc(u8, total);
    errdefer freeEncoded(allocator, out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(magic);
    writer.writeU16(version);
    writer.writeU16(0);
    writer.writeU32(@intCast(total));
    writer.writeU16(@intCast(snapshot.jobs.len));
    writer.writeU16(@intCast(snapshot.dead.len));
    writer.writeByte(@intFromEnum(snapshot.execution));
    writer.writeBytes(&.{ 0, 0, 0, 0, 0, 0, 0 });
    writer.writeU64(sent);
    writer.writeU64(failed);
    writer.writeU64(dropped);
    writer.writeU64(overflow_events);
    writer.writeBytes(&snapshot.config_digest);
    for (snapshot.jobs) |job| {
        writer.writeU32(@intCast(job.endpoint.len));
        writer.writeU32(@intCast(job.payload.len));
        writer.writeBytes(&job.ua_public);
        writer.writeBytes(&job.auth);
        writer.writeBytes(job.endpoint);
        writer.writeBytes(job.payload);
    }
    for (snapshot.dead) |endpoint| {
        writer.writeU32(@intCast(endpoint.len));
        writer.writeBytes(endpoint);
    }
    std.debug.assert(writer.pos + checksum_len == out.len);
    var digest: [checksum_len]u8 = undefined;
    checksum(out[0..writer.pos], &digest);
    writer.writeBytes(&digest);
    try validateCheckpoint(out);
    return out;
}

/// Construct detached owned state after verifying the candidate's actual
/// VAPID/trust/resolver policy. `Worker.restoreSnapshot` can then stage it
/// before COMMIT while the candidate worker is still unstarted.
pub fn decodeSnapshot(allocator: std.mem.Allocator, bytes: []const u8, owner: *const webpush.Worker) Error!webpush.Snapshot {
    try validateCheckpoint(bytes);
    const header = try parseHeader(bytes);
    const expected = owner.configDigest() catch return error.ConfigMismatch;
    if (!std.crypto.timing_safe.eql([32]u8, expected, header.config_digest)) return error.ConfigMismatch;

    const jobs = try allocator.alloc(webpush.Job, header.jobs);
    var copied_jobs: usize = 0;
    errdefer {
        for (jobs[0..copied_jobs]) |*job| wipeJob(allocator, job);
        allocator.free(jobs);
    }
    const dead = try allocator.alloc([]u8, header.dead);
    var copied_dead: usize = 0;
    errdefer {
        for (dead[0..copied_dead]) |endpoint| wipeBytes(allocator, endpoint);
        allocator.free(dead);
    }
    var reader = Reader{ .bytes = bytes[header_len .. bytes.len - checksum_len] };
    for (jobs) |*job| {
        const endpoint_len = try reader.readU32();
        const payload_len = try reader.readU32();
        const public = (try reader.take(65))[0..65].*;
        const auth = (try reader.take(16))[0..16].*;
        const endpoint = try allocator.dupe(u8, try reader.take(endpoint_len));
        errdefer wipeBytes(allocator, endpoint);
        const payload = try allocator.dupe(u8, try reader.take(payload_len));
        job.* = .{ .endpoint = endpoint, .payload = payload, .ua_public = public, .auth = auth };
        copied_jobs += 1;
    }
    for (dead) |*endpoint| {
        const len = try reader.readU32();
        endpoint.* = try allocator.dupe(u8, try reader.take(len));
        copied_dead += 1;
    }
    std.debug.assert(reader.remaining() == 0);
    const snapshot = webpush.Snapshot{
        .allocator = allocator,
        .jobs = jobs,
        .dead = dead,
        .sent = header.sent,
        .failed = header.failed,
        .dropped = header.dropped,
        .overflow_events = header.overflow_events,
        .config_digest = header.config_digest,
        .execution = header.execution,
    };
    snapshot.validate(owner, snapshot_bounds) catch return error.InvalidSnapshot;
    return snapshot;
}

/// Capture only after the source worker has actually parked and producers have
/// been frozen at the server's accepted-event cut. A failed capture changes no
/// owner state; the caller retains the fence and pause until COMMIT or ABORT.
pub fn captureFrozenEncoded(allocator: std.mem.Allocator, owner: *webpush.Worker, fence: runtime_pause.ProducerFence, token: ?runtime_pause.Token) ![]u8 {
    var snapshot = try owner.captureFrozen(allocator, fence, token, snapshot_bounds);
    defer snapshot.deinit();
    return encodeSnapshot(allocator, &snapshot, owner);
}

/// Restore is internally allocation-failure atomic, but the caller must run it
/// before the process COMMIT edge while the candidate worker is still inert.
pub fn restoreEncoded(allocator: std.mem.Allocator, owner: *webpush.Worker, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner);
    defer snapshot.deinit();
    try owner.restoreSnapshot(&snapshot, snapshot_bounds);
}

/// Gate-prepared successor path. The worker's real thread remains parked until
/// the process COMMIT edge, and the owner rechecks that fact after staging.
pub fn restoreEncodedParked(allocator: std.mem.Allocator, owner: *webpush.Worker, bytes: []const u8) !void {
    var snapshot = try decodeSnapshot(allocator, bytes, owner);
    defer snapshot.deinit();
    try owner.restoreSnapshotParked(&snapshot, snapshot_bounds);
}

pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn parseHeader(bytes: []const u8) error{InvalidSnapshot}!Header {
    if (bytes.len < header_len + checksum_len or bytes.len > max_checkpoint_bytes or
        !isCheckpoint(bytes) or std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u16, bytes[6..8], .big) != 0 or
        @as(usize, std.mem.readInt(u32, bytes[8..12], .big)) != bytes.len or
        !std.mem.allEqual(u8, bytes[17..24], 0)) return error.InvalidSnapshot;
    const jobs: usize = std.mem.readInt(u16, bytes[12..14], .big);
    const dead: usize = std.mem.readInt(u16, bytes[14..16], .big);
    if (jobs > webpush.max_queued_jobs or dead > snapshot_bounds.max_dead_entries)
        return error.InvalidSnapshot;
    const execution = std.enums.fromInt(webpush.Execution, bytes[16]) orelse return error.InvalidSnapshot;
    const body_len = bytes.len - header_len - checksum_len;
    if (jobs > body_len / job_header_len) return error.InvalidSnapshot;
    var digest: [checksum_len]u8 = undefined;
    checksum(bytes[0 .. bytes.len - checksum_len], &digest);
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, bytes[bytes.len - checksum_len ..][0..checksum_len].*))
        return error.InvalidSnapshot;
    return .{
        .jobs = jobs,
        .dead = dead,
        .sent = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidSnapshot,
        .failed = std.math.cast(usize, std.mem.readInt(u64, bytes[32..40], .big)) orelse return error.InvalidSnapshot,
        .dropped = std.math.cast(usize, std.mem.readInt(u64, bytes[40..48], .big)) orelse return error.InvalidSnapshot,
        .overflow_events = std.math.cast(usize, std.mem.readInt(u64, bytes[48..56], .big)) orelse return error.InvalidSnapshot,
        .execution = execution,
        .config_digest = bytes[56..88].*,
    };
}

fn addLen(total: *usize, amount: usize) Error!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.TooLarge;
    if (total.* > max_checkpoint_bytes) return error.TooLarge;
}

fn checksum(bytes: []const u8, out: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checksum_domain);
    hasher.update(bytes);
    hasher.final(out);
}

fn wipeBytes(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

fn wipeJob(allocator: std.mem.Allocator, job: *webpush.Job) void {
    wipeBytes(allocator, job.endpoint);
    wipeBytes(allocator, job.payload);
    std.crypto.secureZero(u8, &job.auth);
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }
    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }
    fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .big);
        self.pos += 2;
    }
    fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .big);
        self.pos += 4;
    }
    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.pos;
    }
    fn take(self: *Reader, amount: usize) error{InvalidSnapshot}![]const u8 {
        if (amount > self.remaining()) return error.InvalidSnapshot;
        const slice = self.bytes[self.pos..][0..amount];
        self.pos += amount;
        return slice;
    }
    fn readU32(self: *Reader) error{InvalidSnapshot}!usize {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }
};

fn reseal(bytes: []u8) void {
    var digest: [checksum_len]u8 = undefined;
    checksum(bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}

const testing = std.testing;
const ecdsa = @import("../../crypto/ecdsa_p256.zig");
const acme_runner = @import("../acme_runner.zig");

fn testWorker(resolver: *acme_runner.SystemResolver, subject: []const u8) !webpush.Worker {
    const secret = try ecdsa.SecretKey.fromBytes(@splat(1));
    return .{
        .allocator = testing.allocator,
        .vapid = try ecdsa.KeyPair.fromSecretKey(secret),
        .subject = subject,
        .resolver = resolver.resolver(),
        .trust_anchors = &.{},
    };
}

test "Windows WebPush checkpoint preserves FIFO dead outcomes and exact counters" {
    var resolver = acme_runner.SystemResolver{ .allocator = testing.allocator, .io = testing.io };
    var source = try testWorker(&resolver, "mailto:push@example.invalid");
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/one", @splat(3), @splat(4), "one"));
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/two", @splat(5), @splat(6), "two"));
    try source.dead.append(testing.allocator, try testing.allocator.dupe(u8, "https://push.example/gone"));
    source.sent = 11;
    source.failed = 12;
    source.dropped.store(13, .release);
    source.overflow_events = 14;
    var captured = try source.captureUnstarted(testing.allocator, snapshot_bounds);
    defer captured.deinit();
    const bytes = try encodeSnapshot(testing.allocator, &captured, &source);
    defer freeEncoded(testing.allocator, bytes);
    try validateCheckpoint(bytes);

    var candidate = try testWorker(&resolver, "mailto:push@example.invalid");
    defer candidate.shutdown();
    try candidate.prepareColdResources(testing.io, &resolver);
    var decoded = try decodeSnapshot(testing.allocator, bytes, &candidate);
    defer decoded.deinit();
    try testing.expectEqual(webpush.Execution.unstarted, decoded.execution);
    try testing.expectEqual(@as(usize, 2), decoded.jobs.len);
    try testing.expectEqualStrings("https://push.example/one", decoded.jobs[0].endpoint);
    try testing.expectEqualStrings("two", decoded.jobs[1].payload);
    try testing.expectEqual(@as(u8, 6), decoded.jobs[1].auth[0]);
    try testing.expectEqualStrings("https://push.example/gone", decoded.dead[0]);
    try testing.expectEqual(@as(usize, 11), decoded.sent);
    try testing.expectEqual(@as(usize, 12), decoded.failed);
    try testing.expectEqual(@as(usize, 13), decoded.dropped);
    try testing.expectEqual(@as(usize, 14), decoded.overflow_events);
    try candidate.restoreSnapshot(&decoded, snapshot_bounds);
    try testing.expectEqualStrings("one", candidate.queue.items[0].payload);
    try testing.expectEqualStrings("two", candidate.queue.items[1].payload);
    try testing.expectEqual(@as(usize, 14), candidate.overflow_events);
}

test "Windows WebPush checkpoint rejects malformed bytes and mismatched policy" {
    var resolver = acme_runner.SystemResolver{ .allocator = testing.allocator, .io = testing.io };
    var source = try testWorker(&resolver, "mailto:push@example.invalid");
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/one", @splat(3), @splat(4), "payload"));
    var captured = try source.captureUnstarted(testing.allocator, snapshot_bounds);
    defer captured.deinit();
    const bytes = try encodeSnapshot(testing.allocator, &captured, &source);
    defer freeEncoded(testing.allocator, bytes);
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    var changed = try testing.allocator.dupe(u8, bytes);
    defer freeEncoded(testing.allocator, changed);
    changed[0] = 'X';
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    @memcpy(changed, bytes);
    changed[4] = 7;
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    @memcpy(changed, bytes);
    changed[17] = 1;
    reseal(changed);
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    @memcpy(changed, bytes);
    std.mem.writeInt(u32, changed[header_len..][0..4], std.math.maxInt(u32), .big);
    reseal(changed);
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));
    @memcpy(changed, bytes);
    changed[header_len + job_header_len] ^= 1;
    try testing.expectError(error.InvalidSnapshot, validateCheckpoint(changed));

    var candidate = try testWorker(&resolver, "mailto:other@example.invalid");
    defer candidate.shutdown();
    try candidate.prepareColdResources(testing.io, &resolver);
    try testing.expectError(error.ConfigMismatch, decodeSnapshot(testing.allocator, bytes, &candidate));
}

test "Windows WebPush checkpoint capture requires a live producer fence" {
    var resolver = acme_runner.SystemResolver{ .allocator = testing.allocator, .io = testing.io };
    var source = try testWorker(&resolver, "mailto:push@example.invalid");
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/one", @splat(3), @splat(4), "payload"));
    const fence = try source.fenceProducers();
    const bytes = try captureFrozenEncoded(testing.allocator, &source, fence, null);
    defer freeEncoded(testing.allocator, bytes);
    try validateCheckpoint(bytes);
    try source.resumeProducers(fence);
    try testing.expectError(error.ProducersNotFrozen, captureFrozenEncoded(testing.allocator, &source, fence, null));
    try testing.expectEqual(@as(usize, 1), source.queue.items.len);
}

test "Windows WebPush checkpoint restores into a real parked Gate owner atomically" {
    var resolver = acme_runner.SystemResolver{ .allocator = testing.allocator, .io = testing.io };
    var source = try testWorker(&resolver, "mailto:push@example.invalid");
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/one", @splat(3), @splat(4), "payload"));
    const fence = try source.fenceProducers();
    defer source.resumeProducers(fence) catch unreachable;
    const bytes = try captureFrozenEncoded(testing.allocator, &source, fence, null);
    defer freeEncoded(testing.allocator, bytes);

    var fail = testing.FailingAllocator.init(testing.allocator, .{});
    var candidate = try testWorker(&resolver, "mailto:push@example.invalid");
    candidate.allocator = fail.allocator();
    try candidate.prepareColdResources(testing.io, &resolver);
    const specs = [_]runtime_pause.start_gate.ParticipantSpec{.{ .kind = .webpush, .instance = 0, .owner_identity = &candidate, .options = webpush.dormant_spawn_options }};
    const gate = try runtime_pause.start_gate.create(testing.allocator, testing.io, &specs);
    defer {
        candidate.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        candidate.detachAfterJoined() catch unreachable;
        candidate.shutdown();
        gate.control.destroyJoined();
    }
    const slot = try gate.view.slot(.webpush, 0, &candidate);
    try candidate.prepareDormantWorker(gate.control, gate.view, slot);
    try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
    try candidate.requireParked();
    try testing.expectError(error.AlreadyStarted, restoreEncoded(testing.allocator, &candidate, bytes));
    fail.fail_index = fail.alloc_index;
    fail.resize_fail_index = fail.resize_index;
    try testing.expectError(error.OutOfMemory, restoreEncodedParked(testing.allocator, &candidate, bytes));
    try testing.expectEqual(@as(usize, 0), candidate.queue.items.len);
    fail.fail_index = std.math.maxInt(usize);
    fail.resize_fail_index = std.math.maxInt(usize);
    try restoreEncodedParked(testing.allocator, &candidate, bytes);
    try testing.expectEqual(@as(usize, 1), candidate.queue.items.len);
    try testing.expectEqualStrings("payload", candidate.queue.items[0].payload);
    try candidate.requireParked();
}

test "Windows WebPush checkpoint encode and detached decode survive every allocation failure" {
    var resolver = acme_runner.SystemResolver{ .allocator = testing.allocator, .io = testing.io };
    var source = try testWorker(&resolver, "mailto:push@example.invalid");
    defer source.shutdown();
    try source.prepareColdResources(testing.io, &resolver);
    try testing.expectEqual(webpush.Worker.EnqueueResult.queued, source.enqueue("https://push.example/one", @splat(3), @splat(4), "payload"));
    try source.dead.append(testing.allocator, try testing.allocator.dupe(u8, "https://push.example/gone"));
    var captured = try source.captureUnstarted(testing.allocator, snapshot_bounds);
    defer captured.deinit();
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, snapshot: *const webpush.Snapshot, owner: *const webpush.Worker) !void {
            const bytes = try encodeSnapshot(allocator, snapshot, owner);
            defer freeEncoded(allocator, bytes);
            try validateCheckpoint(bytes);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{ &captured, &source });
    const bytes = try encodeSnapshot(testing.allocator, &captured, &source);
    defer freeEncoded(testing.allocator, bytes);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, wire: []const u8, owner: *const webpush.Worker) !void {
            var decoded = try decodeSnapshot(allocator, wire, owner);
            defer decoded.deinit();
            try testing.expectEqual(@as(usize, 1), decoded.jobs.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ bytes, &source });
    try testing.expectEqual(@as(usize, 1), source.queue.items.len);
}
