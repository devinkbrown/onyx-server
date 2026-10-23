// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key transparency regression tests.

const std = @import("std");
const key_transparency = @import("../key_transparency.zig");
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const certfp_bind_mod = @import("../certfp_bind.zig");
const key_transparency_store = @import("../key_transparency_store.zig");
const ObservationOrigin = @import("contracts.zig").ObservationOrigin;

test "KEYTRANS log records certfp and passkey binding changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-key-transparency.wal");
    defer store.deinit();
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachCertfpBinds(&binds);
    services.attachKeyTransparencyLog(&kt);

    const fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };
    try services.bindCertfp("Alice", fp);
    try services.webauthnBind("Alice", "credAAA", &cose, 5, "phone", 1_700_000_000);
    try services.webauthnDelete("Alice", "credAAA");
    try services.deleteCertfp("Alice", fp);

    try std.testing.expectEqual(@as(usize, 4), kt.len());
    const root = kt.root();
    const webauthn_bind = key_transparency.Event{
        .account = "alice",
        .kind = .webauthn,
        .action = .bind,
        .key_id = "credAAA",
        .key_hash = key_transparency.materialHash(&cose),
        .timestamp_ms = 1_700_000_000_000,
    };
    var proof = try kt.proof(1);
    defer proof.deinit(std.testing.allocator);
    try std.testing.expect(key_transparency.verifyInclusion(root, webauthn_bind, proof, 1, kt.len()));

    var snapshot = try services.keyTransparencyProof(std.testing.allocator, 1);
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshot.position);
    try std.testing.expectEqual(@as(usize, 4), snapshot.size);
    try std.testing.expectEqualSlices(u8, &root, &snapshot.root);
    try std.testing.expect(snapshot.path.len != 0);
    try std.testing.expectError(error.IndexOutOfRange, services.keyTransparencyProof(std.testing.allocator, 99));
}

test "KEYTRANS log records external E2EE device and identity changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-key-transparency-external.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);

    try services.recordExternalKeyTransparencyEvent("Alice", .e2ee_device, .bind, "phone", "mls-x25519:device-public-key", 10);
    try services.recordExternalKeyTransparencyEvent("ALICE", .identity, .delete, "primary", "identity-public-key", 20);

    try std.testing.expectEqual(@as(usize, 2), kt.len());
    const root = kt.root();
    const identity_delete = key_transparency.Event{
        .account = "alice",
        .kind = .identity,
        .action = .delete,
        .key_id = "primary",
        .key_hash = key_transparency.materialHash("identity-public-key"),
        .timestamp_ms = 20,
    };
    var proof = try kt.proof(1);
    defer proof.deinit(std.testing.allocator);
    try std.testing.expect(key_transparency.verifyInclusion(root, identity_delete, proof, 1, kt.len()));
}

test "KEYTRANS store restores events across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-kt-restart.wal");
        defer store.deinit();
        var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
        defer kt.deinit();
        var services = Services.init(&store, null);
        services.attachKeyTransparencyLog(&kt);
        try services.recordExternalKeyTransparencyEvent("Alice", .e2ee_device, .bind, "phone", "v1", 10);
        try services.recordExternalKeyTransparencyEvent("Alice", .e2ee_device, .delete, "phone", "v1", 20);
        try std.testing.expectEqual(@as(usize, 2), kt.len());
    }

    var store = try openTestStore(tmp, "services-kt-restart.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try std.testing.expectEqual(@as(usize, 2), kt.len());

    const ev = try services.keyTransparencyEvent(0);
    try std.testing.expectEqualStrings("alice", ev.event.account());
    try std.testing.expectEqual(key_transparency.CredentialKind.e2ee_device, ev.event.kind);
    try std.testing.expectEqual(key_transparency.Action.bind, ev.event.action);
    try std.testing.expectEqualStrings("phone", ev.event.keyId());
    try std.testing.expectEqualSlices(u8, &key_transparency.materialHash("v1"), &ev.event.key_hash);
    try std.testing.expectEqualSlices(u8, &key_transparency.eventDigest(ev.event.asEvent()), &ev.event.leaf);

    const device = try services.keyTransparencyDevice("ALICE", "phone");
    try std.testing.expectEqual(key_transparency.Action.delete, device.observation);
    try std.testing.expectEqual(@as(usize, 1), device.position);
    try std.testing.expectError(error.NotFound, services.keyTransparencyDevice("alice", "missing"));

    const cmp = try services.keyTransparencyConsistency(1);
    try std.testing.expectEqual(key_transparency.PrefixStatus.match, cmp.prefix);
    try std.testing.expectEqual(@as(usize, 1), cmp.old_size);
    try std.testing.expectEqual(@as(usize, 2), cmp.size);
}

test "KEYTRANS add then delete lookup and unknown device" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-device.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);

    try std.testing.expectError(error.NotFound, services.keyTransparencyDevice("alice", "phone"));
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 1);
    const bound = try services.keyTransparencyDevice("alice", "phone");
    try std.testing.expectEqual(key_transparency.Action.bind, bound.observation);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .delete, "phone", "pub", 2);
    const deleted = try services.keyTransparencyDevice("alice", "phone");
    try std.testing.expectEqual(key_transparency.Action.delete, deleted.observation);
}

test "KEYTRANS unusable store fails required E2EE records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-unusable.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 1);

    var ev_key: [key_transparency_store.event_key_len]u8 = undefined;
    try store.family(.props).put(key_transparency_store.eventKey(0, &ev_key), "junk");

    var kt2 = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt2.deinit();
    var services2 = Services.init(&store, null);
    services2.attachKeyTransparencyLog(&kt2);
    try std.testing.expect(kt2.unusable);
    try std.testing.expectError(error.Unavailable, services2.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "tablet", "pub", 2));
    try std.testing.expectEqual(@as(usize, 0), kt2.len());
}

test "KEYTRANS consistency missing checkpoint is UNKNOWN_CHECKPOINT" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-unknown-ckpt.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    _ = try kt.append(.{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = key_transparency.materialHash("pub"),
        .timestamp_ms = 1,
    });
    try std.testing.expectError(error.UnknownCheckpoint, services.keyTransparencyConsistency(1));
    const empty = try services.keyTransparencyConsistency(0);
    try std.testing.expectEqual(key_transparency.PrefixStatus.match, empty.prefix);
}

test "KEYTRANS consistency corrupt checkpoint is CORRUPT" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-corrupt-ckpt.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 1);

    var ckpt_key: [key_transparency_store.checkpoint_key_len]u8 = undefined;
    try store.family(.props).put(key_transparency_store.checkpointKey(1, &ckpt_key), "junk");
    try std.testing.expectError(error.Corrupt, services.keyTransparencyConsistency(1));
}

test "KEYTRANS observe is best-effort when log is unusable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-observe-best-effort.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 1);
    var ev_key: [key_transparency_store.event_key_len]u8 = undefined;
    try store.family(.props).put(key_transparency_store.eventKey(0, &ev_key), "junk");

    var kt2 = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt2.deinit();
    var services2 = Services.init(&store, null);
    services2.attachKeyTransparencyLog(&kt2);
    try std.testing.expect(kt2.unusable);
    services2.observeKeyTransparencyEvent("alice", .e2ee_device, .bind, "tablet", "pub", 2);
    try std.testing.expectEqual(@as(usize, 0), kt2.len());
    try std.testing.expect(kt2.unusable);
}

test "KEYTRANS replay of the same observational event does not grow the log" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-replay.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 77);
    try services.recordExternalKeyTransparencyEvent("alice", .e2ee_device, .bind, "phone", "pub", 77);
    try std.testing.expectEqual(@as(usize, 1), kt.len());
}

test "KEYTRANS accepted facts with origin use exact identity for bind and delete" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-fact-id.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);

    const origin_a = Services.ObservationOrigin{ .hlc = 50, .origin_node = 1, .origin_pubkey = "pk1" };
    const origin_b = Services.ObservationOrigin{ .hlc = 50, .origin_node = 2, .origin_pubkey = "pk2" };
    services.observeKeyTransparencyFact("Alice", .e2ee_device, .bind, "phone", "mat", 50, origin_a);
    services.observeKeyTransparencyFact("Alice", .e2ee_device, .bind, "phone", "mat", 50, origin_a);
    try std.testing.expectEqual(@as(usize, 1), kt.len());
    services.observeKeyTransparencyFact("Alice", .e2ee_device, .bind, "phone", "mat", 50, origin_b);
    try std.testing.expectEqual(@as(usize, 2), kt.len());
    services.observeKeyTransparencyFact("Alice", .e2ee_device, .delete, "phone", "", 50, origin_a);
    try std.testing.expectEqual(@as(usize, 3), kt.len());
    services.observeKeyTransparencyFact("Alice", .e2ee_device, .delete, "phone", "", 50, origin_a);
    try std.testing.expectEqual(@as(usize, 3), kt.len());

    const expected_bind = key_transparency.factObservationHash(.{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .hlc = 50,
        .origin_node = 1,
        .origin_pubkey = "pk1",
    }, "mat");
    try std.testing.expectEqualSlices(u8, &expected_bind, &(try kt.eventAt(0)).key_hash);
    const expected_del = key_transparency.factObservationHash(.{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .delete,
        .key_id = "phone",
        .hlc = 50,
        .origin_node = 1,
        .origin_pubkey = "pk1",
    }, "");
    try std.testing.expectEqualSlices(u8, &expected_del, &(try kt.eventAt(2)).key_hash);
}

test "KEYTRANS cold restart keeps different-origin facts distinct" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const wal_name = "services-kt-origin-restart.wal";
    {
        var store = try openTestStore(tmp, wal_name);
        defer store.deinit();
        var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
        defer kt.deinit();
        var services = Services.init(&store, null);
        services.attachKeyTransparencyLog(&kt);
        services.observeKeyTransparencyFact("alice", .e2ee_device, .bind, "phone", "mat", 9, .{
            .hlc = 9,
            .origin_node = 1,
            .origin_pubkey = "a",
        });
        try std.testing.expectEqual(@as(usize, 1), kt.len());
    }
    var store = try openTestStore(tmp, wal_name);
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    try std.testing.expectEqual(@as(usize, 1), kt.len());
    services.observeKeyTransparencyFact("alice", .e2ee_device, .bind, "phone", "mat", 9, .{
        .hlc = 9,
        .origin_node = 2,
        .origin_pubkey = "b",
    });
    try std.testing.expectEqual(@as(usize, 2), kt.len());
    services.observeKeyTransparencyFact("alice", .e2ee_device, .bind, "phone", "mat", 9, .{
        .hlc = 9,
        .origin_node = 1,
        .origin_pubkey = "a",
    });
    try std.testing.expectEqual(@as(usize, 2), kt.len());
}

test "KEYTRANS local certfp records still hash material only" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-certfp-material.wal");
    defer store.deinit();
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachCertfpBinds(&binds);
    services.attachKeyTransparencyLog(&kt);
    const fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try services.bindCertfp("alice", fp);
    try std.testing.expectEqual(@as(usize, 1), kt.len());
    try std.testing.expectEqualSlices(u8, &key_transparency.materialHash(fp), &(try kt.eventAt(0)).key_hash);
}

test "KEYTRANS observe without origin keeps material hash for bind" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-kt-no-origin.wal");
    defer store.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachKeyTransparencyLog(&kt);
    services.observeKeyTransparencyEvent("alice", .identity, .bind, "primary", "pub", 3);
    try std.testing.expectEqualSlices(u8, &key_transparency.materialHash("pub"), &(try kt.eventAt(0)).key_hash);
}
