// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replay and equivocation authority for origin-signed E2EEGROUP controls.
//!
//! This is deliberately a distinct guard instance and checkpoint family from
//! chat MESSAGE_V2. Its durable representation contains only origin public
//! keys, HLC retirement watermarks, and relay IDs. Opaque control payloads are
//! verified before admission and are never written to the checkpoint.

const std = @import("std");

const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");
const replay = @import("relay_v2_replay_guard.zig");

pub const PublicKey = [group_relay.pubkey_len]u8;
pub const RelayId = group_relay.RelayId;
pub const Config = replay.Config;
pub const Decision = replay.Decision;

pub const Admission = union(enum) {
    accepted: RelayId,
    duplicate: RelayId,
    equivocation,
    retired,
    origin_capacity,
};

pub const VerifiedRecord = struct {
    origin_pubkey: PublicKey,
    hlc: u64,
    relay_id: RelayId,
};

pub const Verification = union(enum) {
    verified: VerifiedRecord,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
    future_skew,
};

pub const InitError = replay.InitError;
pub const CheckpointError = replay.CheckpointError;

const magic = [_]u8{ 'E', 'G', 'R', 'G' };
const checkpoint_version: u8 = 1;
const header_len: usize = magic.len + 1 + 4;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const checkpoint_checksum_domain = "onyx-e2ee-group-replay-checkpoint-v1";

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(checkpoint_checksum_domain);
    hash.update(prefix);
    hash.final(out);
}

fn checkpointBody(bytes: []const u8) CheckpointError![]const u8 {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != checkpoint_version) return error.UnsupportedVersion;

    const body_len: usize = std.mem.readInt(u32, bytes[5..9], .big);
    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;

    var actual: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual);
    if (!std.mem.eql(u8, &actual, bytes[prefix_len..])) return error.ChecksumMismatch;
    return bytes[header_len..prefix_len];
}

/// Allocation-free validation for checkpoint selectors and handoff boundaries.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!Config {
    return replay.validateCheckpoint(try checkpointBody(bytes));
}

pub const Guard = struct {
    /// Kept private so E2EEGROUP and chat callers cannot accidentally share one
    /// HLC namespace even though they use the same proven window algorithm.
    inner: replay.Guard,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Guard {
        return .{
            .inner = try replay.Guard.init(allocator, config),
            .config = config,
        };
    }

    pub fn deinit(self: *Guard) void {
        self.inner.deinit();
        self.* = undefined;
    }

    pub fn admit(
        self: *Guard,
        pubkey: PublicKey,
        hlc: u64,
        relay_id: RelayId,
    ) std.mem.Allocator.Error!Decision {
        return self.inner.admit(pubkey, hlc, relay_id);
    }

    /// Authenticate and derive an immutable identity without mutating replay
    /// authority. The daemon must authorize the decoded record's channel
    /// membership and device ownership before passing this identity to
    /// `admitAuthorized`.
    pub fn verifyRecord(
        self: *Guard,
        record: group_relay.RelayRecord,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) std.mem.Allocator.Error!Verification {
        const relay_id = switch (try group_relay.verifyAndRelayId(self.inner.allocator, record)) {
            .verified => |id| id,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        // An exhausted packed HLC has no valid causal successor. Reject it
        // independently of skew arithmetic, including saturated caller bounds.
        if (record.hlc == std.math.maxInt(u64)) return .future_skew;
        const latest_physical = std.math.add(u64, now_ms, max_future_skew_ms) catch
            std.math.maxInt(u64);
        if (mesh_clock.MeshClock.physicalOf(record.hlc) > latest_physical)
            return .future_skew;
        const pubkey: PublicKey = record.origin_pubkey[0..@sizeOf(PublicKey)].*;
        return .{ .verified = .{
            .origin_pubkey = pubkey,
            .hlc = record.hlc,
            .relay_id = relay_id,
        } };
    }

    /// Commit a previously verified identity only after daemon authorization.
    /// Keeping authorization between these two calls prevents an unauthorized
    /// signed record from reserving an origin/HLC slot.
    pub fn admitAuthorized(
        self: *Guard,
        verified: VerifiedRecord,
    ) std.mem.Allocator.Error!Admission {
        return switch (try self.admit(
            verified.origin_pubkey,
            verified.hlc,
            verified.relay_id,
        )) {
            .accepted => .{ .accepted = verified.relay_id },
            .duplicate => .{ .duplicate = verified.relay_id },
            .equivocation => .equivocation,
            .retired => .retired,
            .origin_capacity => .origin_capacity,
        };
    }

    /// Canonical metadata-only checkpoint in an E2EEGROUP-specific envelope.
    pub fn encodeCheckpoint(
        self: *const Guard,
        allocator: std.mem.Allocator,
    ) CheckpointError![]u8 {
        const body = try self.inner.encodeCheckpoint(allocator);
        defer allocator.free(body);
        if (body.len > std.math.maxInt(u32)) return error.CheckpointTooLarge;

        const prefix_len = std.math.add(usize, header_len, body.len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);

        @memcpy(out[0..magic.len], &magic);
        out[magic.len] = checkpoint_version;
        std.mem.writeInt(u32, out[5..9], @intCast(body.len), .big);
        @memcpy(out[header_len..prefix_len], body);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) CheckpointError!Guard {
        return .{
            .inner = try replay.Guard.decodeCheckpoint(
                allocator,
                expected_config,
                try checkpointBody(bytes),
            ),
            .config = expected_config,
        };
    }

    /// Replacement is transactional: corruption, mismatch, and OOM leave the
    /// live authority untouched.
    pub fn replaceFromCheckpoint(self: *Guard, bytes: []const u8) CheckpointError!void {
        var replacement = try decodeCheckpoint(self.inner.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }
};

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

fn testKey(byte: u8) PublicKey {
    return @splat(byte);
}

fn testId(byte: u8) RelayId {
    return @splat(byte);
}

fn signedRecord(
    kp: *const sign.KeyPair,
    hlc: u64,
    payload: []const u8,
    pubkey: *[group_relay.pubkey_len]u8,
    signature: *[group_relay.sig_len]u8,
) !group_relay.RelayRecord {
    var record = group_relay.RelayRecord{
        .kind = .commit,
        .channel = "#root",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .payload = payload,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try group_relay.stampOrigin(testing.allocator, &record, kp, pubkey, signature);
    return record;
}

test "E2EEGROUP replay guard detects duplicates equivocation retirement and capacity" {
    var guard = try Guard.init(testing.allocator, .{ .window_size = 2, .max_origins = 1 });
    defer guard.deinit();
    const key = testKey(1);

    try testing.expectEqual(Decision.accepted, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.duplicate, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.equivocation, try guard.admit(key, 10, testId(11)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 20, testId(20)));
    try testing.expectEqual(Decision.accepted, try guard.admit(key, 30, testId(30)));
    try testing.expectEqual(Decision.retired, try guard.admit(key, 10, testId(10)));
    try testing.expectEqual(Decision.retired, try guard.admit(key, 5, testId(5)));
    try testing.expectEqual(Decision.origin_capacity, try guard.admit(testKey(2), 40, testId(40)));
}

test "E2EEGROUP admission verifies before reserving replay state" {
    var guard = try Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x73)));
    defer kp.deinit();
    var pubkey: [group_relay.pubkey_len]u8 = undefined;
    var signature: [group_relay.sig_len]u8 = undefined;
    const valid = try signedRecord(
        &kp,
        41,
        "b3BhcXVlLWNvbnRyb2wtbWF0ZXJpYWw",
        &pubkey,
        &signature,
    );

    var forged = valid;
    forged.payload = "Zm9yZ2VkLWNvbnRyb2wtbWF0ZXJpYWw";
    try testing.expectEqual(
        std.meta.Tag(Verification).bad_signature,
        std.meta.activeTag(try guard.verifyRecord(forged, 0, 0)),
    );
    const verified = switch (try guard.verifyRecord(valid, 0, 0)) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(try guard.admitAuthorized(verified)),
    );
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(try guard.admitAuthorized(verified)),
    );
}

test "E2EEGROUP authorization precedes replay mutation and future clocks fail closed" {
    var guard = try Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x75)));
    defer kp.deinit();
    var pubkey_a: [group_relay.pubkey_len]u8 = undefined;
    var signature_a: [group_relay.sig_len]u8 = undefined;
    const now_ms: u64 = 1_700_000_000_000;
    const hlc = (now_ms << mesh_clock.seq_bits) | 1;
    const unauthorized = try signedRecord(
        &kp,
        hlc,
        "dW5hdXRob3JpemVk",
        &pubkey_a,
        &signature_a,
    );
    const rejected_identity = switch (try guard.verifyRecord(
        unauthorized,
        now_ms,
        mesh_clock.default_max_future_skew_ms,
    )) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    _ = rejected_identity; // Membership/device policy rejects before admission.

    var pubkey_b: [group_relay.pubkey_len]u8 = undefined;
    var signature_b: [group_relay.sig_len]u8 = undefined;
    const authorized = try signedRecord(
        &kp,
        hlc,
        "YXV0aG9yaXplZA",
        &pubkey_b,
        &signature_b,
    );
    const accepted_identity = switch (try guard.verifyRecord(
        authorized,
        now_ms,
        mesh_clock.default_max_future_skew_ms,
    )) {
        .verified => |identity| identity,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(try guard.admitAuthorized(accepted_identity)),
    );

    var pubkey_future: [group_relay.pubkey_len]u8 = undefined;
    var signature_future: [group_relay.sig_len]u8 = undefined;
    const future = try signedRecord(
        &kp,
        std.math.maxInt(u64),
        "ZnV0dXJl",
        &pubkey_future,
        &signature_future,
    );
    try testing.expectEqual(
        std.meta.Tag(Verification).future_skew,
        std.meta.activeTag(try guard.verifyRecord(
            future,
            now_ms,
            mesh_clock.default_max_future_skew_ms,
        )),
    );
    try testing.expectEqual(
        std.meta.Tag(Verification).future_skew,
        std.meta.activeTag(try guard.verifyRecord(
            future,
            std.math.maxInt(u64),
            std.math.maxInt(u64),
        )),
    );
}

test "E2EEGROUP checkpoint is domain-separated metadata only and restores authority" {
    const cfg = Config{ .window_size = 2, .max_origins = 2 };
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x74)));
    defer kp.deinit();
    var pubkey: [group_relay.pubkey_len]u8 = undefined;
    var signature: [group_relay.sig_len]u8 = undefined;
    const payload = "RE8tTk9ULVBFUlNJU1QtT1BBUVVFLUUyRUUtQ09OVFJPTA";
    const record = try signedRecord(&kp, 51, payload, &pubkey, &signature);
    const identity = switch (try source.verifyRecord(record, 0, 0)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(
        std.meta.Tag(Admission).accepted,
        std.meta.activeTag(try source.admitAuthorized(identity)),
    );

    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    try testing.expect(isCheckpoint(checkpoint));
    try testing.expect(!replay.isCheckpoint(checkpoint));
    try testing.expect(std.mem.indexOf(u8, checkpoint, payload) == null);
    try testing.expectEqual(cfg.window_size, (try validateCheckpoint(checkpoint)).window_size);

    var restored = try Guard.decodeCheckpoint(testing.allocator, cfg, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(try restored.admitAuthorized(identity)),
    );

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[header_len] ^= 1;
    try testing.expectError(error.ChecksumMismatch, restored.replaceFromCheckpoint(corrupt));
    try testing.expectEqual(
        std.meta.Tag(Admission).duplicate,
        std.meta.activeTag(try restored.admitAuthorized(identity)),
    );
}

test "E2EEGROUP checkpoint allocation paths are leak-free and replacement is atomic" {
    const cfg = Config{ .window_size = 2, .max_origins = 2 };
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    try testing.expectEqual(Decision.accepted, try source.admit(testKey(1), 10, testId(10)));

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, guard: *const Guard) !void {
            const bytes = try guard.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        EncodeSweep.run,
        .{&source},
    );

    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const DecodeReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, expected: Config, bytes: []const u8) !void {
            var live = try Guard.init(allocator, expected);
            defer live.deinit();
            try testing.expectEqual(
                Decision.accepted,
                try live.admit(testKey(2), 20, testId(20)),
            );
            live.replaceFromCheckpoint(bytes) catch |err| {
                // Retrying the preexisting fact requires no allocation and
                // proves a failed replacement did not partially swap authority.
                try testing.expectEqual(
                    Decision.duplicate,
                    try live.admit(testKey(2), 20, testId(20)),
                );
                return err;
            };
            try testing.expectEqual(
                Decision.duplicate,
                try live.admit(testKey(1), 10, testId(10)),
            );
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        DecodeReplaceSweep.run,
        .{ cfg, checkpoint },
    );
}
