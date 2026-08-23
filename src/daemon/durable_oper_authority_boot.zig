// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict boot/initialization boundary for the inactive OCG2 durable authority.
//! Missing, partial, corrupt, or differently-authorized state is fatal; this
//! module never resets or silently manufactures state during `load`.

const std = @import("std");
const authority = @import("durable_oper_authority.zig");
const store_mod = @import("store.zig");

const StorePutError = @typeInfo(@typeInfo(@TypeOf(store_mod.OroStore.put)).@"fn".return_type.?).error_union.error_set;

pub const Error = authority.PrepareError || StorePutError || error{
    MissingInitMarker,
    MissingSnapshot,
    AlreadyInitialized,
    PartialInitialization,
    StorageRecordLimitTooSmall,
    StorageWalLimitTooSmall,
};

fn validateBounds(store: *const store_mod.OroStore) Error!void {
    const limits = store.admissionLimits();
    if (limits.max_record_bytes < authority.max_store_payload_bytes) return error.StorageRecordLimitTooSmall;
    if (limits.max_wal_bytes < authority.max_store_wal_record_bytes) return error.StorageWalLimitTooSmall;
}

pub fn initialize(
    allocator: std.mem.Allocator,
    store: *store_mod.OroStore,
    config: authority.Config,
) Error!authority.State {
    try validateBounds(store);
    const existing_marker = store.get(.props, authority.marker_key);
    const existing_snapshot = store.get(.props, authority.snapshot_key);
    if (existing_marker != null and existing_snapshot != null) return error.AlreadyInitialized;
    if (existing_marker != null or existing_snapshot != null) return error.PartialInitialization;
    var state = try authority.State.init(allocator, config);
    errdefer state.deinit();
    const snapshot = try authority.encode(allocator, &state);
    state.snapshot_bytes = snapshot;
    var marker_buf: [authority.marker_len]u8 = undefined;
    const marker_bytes = try authority.marker(config, &marker_buf);
    // A crash between these durable writes intentionally leaves a partial image
    // that strict `load` rejects. Automatic rollback cannot prove which write
    // crossed an ambiguous I/O boundary, so operator intervention/reopen wins.
    try store.put(.props, authority.marker_key, marker_bytes);
    try store.put(.props, authority.snapshot_key, snapshot);
    return state;
}

pub fn load(
    allocator: std.mem.Allocator,
    store: *const store_mod.OroStore,
    config: authority.Config,
) Error!authority.State {
    try validateBounds(store);
    const marker_bytes = store.get(.props, authority.marker_key) orelse return error.MissingInitMarker;
    try authority.validateMarker(marker_bytes, config);
    const snapshot = store.get(.props, authority.snapshot_key) orelse return error.MissingSnapshot;
    return authority.decode(allocator, config, snapshot);
}

const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

fn testConfig(seed: u8) !authority.Config {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
    const public_key = kp.public_key.toBytes();
    return .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
}

const accepted_storage = store_mod.Config{
    .max_record_bytes = authority.max_store_payload_bytes,
    .max_wal_bytes = authority.max_store_wal_record_bytes,
};

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !store_mod.OroStore {
    return store_mod.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, name, accepted_storage);
}

test "OCG2AUTH boot initialization restart and strict missing partial wrong authority corruption" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = try testConfig(0x91);
    const wrong = try testConfig(0x92);
    var store = try openTestStore(tmp, "ocg2auth-boot.wal");
    defer store.deinit();
    try std.testing.expectError(error.MissingInitMarker, load(std.testing.allocator, &store, config));
    var initialized = try initialize(std.testing.allocator, &store, config);
    defer initialized.deinit();
    try std.testing.expectError(error.AlreadyInitialized, initialize(std.testing.allocator, &store, config));
    var restored = try load(std.testing.allocator, &store, config);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), restored.count());
    const LoadSweep = struct {
        fn run(allocator: std.mem.Allocator, stable_store: *const store_mod.OroStore, cfg: authority.Config) !void {
            var state = try load(allocator, stable_store, cfg);
            defer state.deinit();
            try std.testing.expectEqual(@as(usize, 0), state.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, LoadSweep.run, .{ &store, config });
    try std.testing.expectError(error.InvalidAuthority, load(std.testing.allocator, &store, wrong));

    var wrong_state = try authority.State.init(std.testing.allocator, wrong);
    defer wrong_state.deinit();
    const wrong_snapshot = try authority.encode(std.testing.allocator, &wrong_state);
    defer std.testing.allocator.free(wrong_snapshot);
    try store.put(.props, authority.snapshot_key, wrong_snapshot);
    try std.testing.expectError(error.InvalidAuthority, load(std.testing.allocator, &store, config));
    try store.put(.props, authority.snapshot_key, initialized.snapshot());

    try store.delete(.props, authority.snapshot_key);
    try std.testing.expectError(error.MissingSnapshot, load(std.testing.allocator, &store, config));
    try std.testing.expectError(error.PartialInitialization, initialize(std.testing.allocator, &store, config));
}

test "OCG2AUTH boot rejects corrupt marker and snapshot plus undersized stores" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config = try testConfig(0x93);
    var store = try openTestStore(tmp, "ocg2auth-corrupt.wal");
    defer store.deinit();
    var initialized = try initialize(std.testing.allocator, &store, config);
    defer initialized.deinit();
    const snapshot = store.get(.props, authority.snapshot_key).?;
    var corrupt_snapshot = try std.testing.allocator.dupe(u8, snapshot);
    defer std.testing.allocator.free(corrupt_snapshot);
    corrupt_snapshot[corrupt_snapshot.len - 1] ^= 1;
    try store.put(.props, authority.snapshot_key, corrupt_snapshot);
    try std.testing.expectError(error.BadChecksum, load(std.testing.allocator, &store, config));

    var marker_buf: [authority.marker_len]u8 = undefined;
    const marker_bytes = try authority.marker(config, &marker_buf);
    marker_buf[marker_buf.len - 1] ^= 1;
    try store.put(.props, authority.marker_key, &marker_buf);
    try std.testing.expectError(error.InvalidAuthority, load(std.testing.allocator, &store, config));
    _ = marker_bytes;

    var too_small = accepted_storage;
    too_small.max_record_bytes -= 1;
    var small = try store_mod.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "ocg2auth-small.wal", too_small);
    defer small.deinit();
    try std.testing.expectError(error.StorageRecordLimitTooSmall, load(std.testing.allocator, &small, config));
}
