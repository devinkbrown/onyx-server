// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-only DPROP1 restore from an already-open OroStore.
//!
//! This leaf is deliberately unwired. It validates the authority and storage
//! admission bounds before consulting `.props`, returns a new empty owned state
//! only when the reserved row is absent, and otherwise propagates strict DPROP1
//! decode failures without reset, deletion, or fallback.

const std = @import("std");
const dprop = @import("durable_credential_props.zig");
const store_mod = @import("store.zig");
const sign = @import("../crypto/sign.zig");
const entity_prop_event = @import("../proto/entity_prop_event.zig");

pub const Error = dprop.Error || std.mem.Allocator.Error || error{
    StorageRecordLimitTooSmall,
    StorageWalLimitTooSmall,
};

/// Restore the locally-authoritative DPROP1 state from `.props`.
pub fn load(
    allocator: std.mem.Allocator,
    store: *const store_mod.OroStore,
    local_origin_node: u64,
) Error!dprop.State {
    if (local_origin_node == 0) return error.InvalidAuthorityConfig;
    const limits = store.admissionLimits();
    if (limits.max_record_bytes < dprop.max_store_payload_bytes)
        return error.StorageRecordLimitTooSmall;
    if (limits.max_wal_bytes < dprop.max_store_wal_record_bytes)
        return error.StorageWalLimitTooSmall;

    const config = dprop.Config{ .local_origin_node = local_origin_node };
    const image = store.get(.props, dprop.store_key) orelse return dprop.State.init(allocator, config);
    return dprop.decode(allocator, config, image);
}

const accepted_storage = store_mod.Config{
    .max_record_bytes = dprop.max_store_payload_bytes,
    .max_wal_bytes = dprop.max_store_wal_record_bytes,
};

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !store_mod.OroStore {
    return store_mod.OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        name,
        accepted_storage,
    );
}

fn signedEvent(seed_byte: u8) !entity_prop_event.EntityPropEvent {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
    defer kp.deinit();
    const origin = entity_prop_event.originShortId(kp.public_key);
    var event = entity_prop_event.EntityPropEvent{
        .present = true,
        .kind = .user,
        .origin_node = origin,
        .hlc = 1,
        .entity = "bootuser",
        .key = "e2ee.device.phone",
        .value = "mls-x25519:abcd+/=",
        .owner = "local",
    };
    const transcript = try entity_prop_event.originTranscript(std.testing.allocator, event);
    defer std.testing.allocator.free(transcript);
    const signature = try kp.signCtx(entity_prop_event.sign_domain, transcript);
    event.origin_pubkey = try std.testing.allocator.dupe(u8, &kp.public_key);
    errdefer std.testing.allocator.free(@constCast(event.origin_pubkey));
    event.origin_sig = try std.testing.allocator.dupe(u8, &signature);
    return event;
}

fn freeSignedEvent(event: entity_prop_event.EntityPropEvent) void {
    std.testing.allocator.free(@constCast(event.origin_pubkey));
    std.testing.allocator.free(@constCast(event.origin_sig));
}

fn imageForEvent(event: entity_prop_event.EntityPropEvent) ![]u8 {
    var state = try dprop.State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    defer state.deinit();
    var outcome = try state.prepare(event);
    switch (outcome) {
        .update => |*prepared| prepared.commitInto(&state),
        else => return error.InvalidFact,
    }
    return dprop.encode(std.testing.allocator, &state);
}

fn rewriteChecksum(image: []u8) void {
    const body = image[0 .. image.len - dprop.checksum_len];
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(dprop.checksum_domain);
    hash.update(&[_]u8{0});
    hash.update(body);
    hash.final(image[body.len..]);
}

test "DPROP boot validates authority and authoritative opened-store bounds" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "bounds.wal");
    defer store.deinit();

    try std.testing.expectError(error.InvalidAuthorityConfig, load(std.testing.allocator, &store, 0));
    var exact = try load(std.testing.allocator, &store, 1);
    defer exact.deinit();
    try std.testing.expectEqual(@as(usize, 0), exact.count());

    var below_record = accepted_storage;
    below_record.max_record_bytes -= 1;
    var record_store = try store_mod.OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "below-record.wal",
        below_record,
    );
    defer record_store.deinit();
    try std.testing.expectError(error.StorageRecordLimitTooSmall, load(std.testing.allocator, &record_store, 1));

    var below_wal = accepted_storage;
    below_wal.max_wal_bytes -= 1;
    var wal_store = try store_mod.OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "below-wal.wal",
        below_wal,
    );
    defer wal_store.deinit();
    try std.testing.expectError(error.StorageWalLimitTooSmall, load(std.testing.allocator, &wal_store, 1));
}

test "DPROP boot restores a valid owned snapshot and missing is empty" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "valid.wal");
    defer store.deinit();
    const event = try signedEvent(0x51);
    defer freeSignedEvent(event);

    var missing = try load(std.testing.allocator, &store, event.origin_node);
    defer missing.deinit();
    try std.testing.expectEqual(@as(usize, 0), missing.count());

    const image = try imageForEvent(event);
    defer std.testing.allocator.free(image);
    try store.put(.props, dprop.store_key, image);
    var restored = try load(std.testing.allocator, &store, event.origin_node);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), restored.count());
    try std.testing.expect(restored.get("bootuser", "e2ee.device.phone") != null);

    // The returned State owns its bytes independently of the OroStore row.
    try store.delete(.props, dprop.store_key);
    try std.testing.expect(restored.get("bootuser", "e2ee.device.phone") != null);
}

test "DPROP boot propagates corruption foreign origin and bad signature" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "invalid.wal");
    defer store.deinit();
    const event = try signedEvent(0x61);
    defer freeSignedEvent(event);
    const image = try imageForEvent(event);
    defer std.testing.allocator.free(image);

    var corrupt = try std.testing.allocator.dupe(u8, image);
    defer std.testing.allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try store.put(.props, dprop.store_key, corrupt);
    try std.testing.expectError(error.BadChecksum, load(std.testing.allocator, &store, event.origin_node));

    try store.put(.props, dprop.store_key, image);
    try std.testing.expectError(error.InvalidOrigin, load(std.testing.allocator, &store, event.origin_node +% 1));

    var bad_signature = try std.testing.allocator.dupe(u8, image);
    defer std.testing.allocator.free(bad_signature);
    bad_signature[bad_signature.len - dprop.checksum_len - 1] ^= 1;
    rewriteChecksum(bad_signature);
    try store.put(.props, dprop.store_key, bad_signature);
    try std.testing.expectError(error.InvalidSignature, load(std.testing.allocator, &store, event.origin_node));
}

test "DPROP boot allocation failure cleans partial restore" {
    const event = try signedEvent(0x71);
    defer freeSignedEvent(event);
    const image = try imageForEvent(event);
    defer std.testing.allocator.free(image);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "oom.wal");
    defer store.deinit();
    try store.put(.props, dprop.store_key, image);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, target: *const store_mod.OroStore, origin: u64) !void {
            var state = try load(allocator, target, origin);
            defer state.deinit();
            try std.testing.expectEqual(@as(usize, 1), state.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{ &store, event.origin_node });
}
