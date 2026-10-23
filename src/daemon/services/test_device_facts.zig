// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device facts regression tests.

const std = @import("std");
const store_mod = @import("../store.zig");
const durable_credential_props = @import("../durable_credential_props.zig");
const key_transparency = @import("../key_transparency.zig");
const OroStore = @import("records.zig").OroStore;
const Config = @import("records.zig").Config;
const canonicalAccount = @import("records.zig").canonicalAccount;
const DurableDeviceFactPreadmission = @import("contracts.zig").DurableDeviceFactPreadmission;
const DurableDeviceFactRestart = @import("contracts.zig").DurableDeviceFactRestart;
const DurableDeviceFactKeyTransparency = @import("contracts.zig").DurableDeviceFactKeyTransparency;
const openTestStore = @import("test_support.zig").openTestStore;
const durableServicesEvent = @import("test_support.zig").durableServicesEvent;
const durableServicesEventWithOwner = @import("test_support.zig").durableServicesEventWithOwner;
const freeDurableServicesEvent = @import("test_support.zig").freeDurableServicesEvent;
const Services = @import("core.zig").Services;

test "DPROP Services canonical account uses service account policy" {
    const canonical = try canonicalAccount("Alice.EXAMPLE-1");
    try std.testing.expectEqualStrings("alice.example-1", canonical.asSlice());
    try std.testing.expectError(error.InvalidName, canonicalAccount("bad account"));
}

test "DPROP Services durable commit survives OroStore reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const event = try durableServicesEvent(0x81, "alice", "e2ee.device.phone", 51, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    const config = durable_credential_props.Config{ .local_origin_node = event.origin_node };

    {
        var store = try openTestStore(tmp, "services-dprop-reopen.wal");
        defer store.deinit();
        var state = try durable_credential_props.State.init(std.testing.allocator, config);
        defer state.deinit();
        var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
        defer kt.deinit();
        var services = Services.init(&store, null);
        services.attachDurableCredentialProps(&state);
        services.attachKeyTransparencyLog(&kt);

        const committed = services.commitLocalDurableDeviceFact(event);
        switch (committed) {
            .committed => |result| try std.testing.expectEqual(Services.DurableDeviceFactKeyTransparency.recorded, result.key_transparency),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(@as(usize, 1), state.count());
        try std.testing.expectEqualStrings(state.snapshot(), store.family(.props).get(durable_credential_props.store_key) orelse return error.TestUnexpectedResult);
    }

    {
        var store = try openTestStore(tmp, "services-dprop-reopen.wal");
        defer store.deinit();
        const image = store.family(.props).get(durable_credential_props.store_key) orelse return error.TestUnexpectedResult;
        var restored = try durable_credential_props.decode(std.testing.allocator, config, image);
        defer restored.deinit();
        try std.testing.expectEqual(@as(usize, 1), restored.count());
        try std.testing.expectEqual(@as(u64, 51), restored.maxHlc());
        try std.testing.expectEqualStrings("mls-x25519:abcd+/=", restored.get("alice", "e2ee.device.phone").?.value);
    }
}

test "DPROP Services precommit rejection is inert and reservations clean up" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-dprop-preadmit.wal");
    defer store.deinit();
    const event = try durableServicesEvent(0x82, "alice", "e2ee.device.phone", 61, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    const mismatched_owner = try durableServicesEventWithOwner(0x82, "alice", "mallory", "e2ee.device.phone", 60, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(mismatched_owner);
    var state = try durable_credential_props.State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    defer state.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachDurableCredentialProps(&state);
    services.attachKeyTransparencyLog(&kt);

    const owner_rejected = services.commitLocalDurableDeviceFact(mismatched_owner);
    try std.testing.expectEqual(Services.DurableDeviceFactPreadmission.invalid_fact, owner_rejected.preadmission);
    try std.testing.expectEqual(@as(usize, 0), state.count());
    try std.testing.expectEqual(@as(usize, 0), kt.len());
    try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) == null);

    var invalid = event;
    invalid.key = "STATUS";
    const rejected = services.commitLocalDurableDeviceFact(invalid);
    try std.testing.expectEqual(Services.DurableDeviceFactPreadmission.invalid_fact, rejected.preadmission);
    try std.testing.expectEqual(@as(usize, 0), state.count());
    try std.testing.expectEqual(@as(usize, 0), kt.len());
    try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) == null);

    const committed = services.commitLocalDurableDeviceFact(event);
    try std.testing.expect(committed == .committed);
    try std.testing.expectEqual(Services.DurableDeviceFactKeyTransparency.recorded, committed.committed.key_transparency);
    try std.testing.expectEqual(@as(usize, 1), state.count());
    try std.testing.expect(services.commitLocalDurableDeviceFact(event) == .replay);
    try std.testing.expectEqual(@as(usize, 1), state.count());
}

test "DPROP Services ambiguous prepared write requires reopen without publishing state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const event = try durableServicesEvent(0x83, "alice", "e2ee.device.phone", 71, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    const config = durable_credential_props.Config{ .local_origin_node = event.origin_node };

    {
        var store = try openTestStore(tmp, "services-dprop-ambiguous.wal");
        defer store.deinit();
        var state = try durable_credential_props.State.init(std.testing.allocator, config);
        defer state.deinit();
        var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
        defer kt.deinit();
        var services = Services.init(&store, null);
        services.attachDurableCredentialProps(&state);
        services.attachKeyTransparencyLog(&kt);
        store.setPreparedIoFault(.{ .sync = true });

        const outcome = services.commitLocalDurableDeviceFact(event);
        try std.testing.expectEqual(Services.DurableDeviceFactRestart.ambiguous_store, outcome.restart_required);
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(@as(usize, 0), state.count());
        try std.testing.expectEqual(@as(usize, 0), kt.len());
        try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) == null);
        const second = services.commitLocalDurableDeviceFact(event);
        try std.testing.expectEqual(Services.DurableDeviceFactRestart.fatal_store, second.restart_required);
        try std.testing.expectEqual(@as(usize, 0), state.count());
        try std.testing.expectEqual(@as(usize, 0), kt.len());
    }

    {
        var store = try openTestStore(tmp, "services-dprop-ambiguous.wal");
        defer store.deinit();
        const image = store.family(.props).get(durable_credential_props.store_key) orelse return error.TestUnexpectedResult;
        var restored = try durable_credential_props.decode(std.testing.allocator, config, image);
        defer restored.deinit();
        try std.testing.expectEqual(@as(usize, 1), restored.count());
        try std.testing.expectEqualStrings("alice", restored.factAt(0).?.entity);
    }
}

test "DPROP Services failed and torn prepared writes reopen absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const event = try durableServicesEvent(0x85, "alice", "e2ee.device.phone", 91, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    const config = durable_credential_props.Config{ .local_origin_node = event.origin_node };
    const cases = [_]struct {
        wal_name: []const u8,
        fault: store_mod.PreparedIoFault,
    }{
        .{ .wal_name = "services-dprop-write-failed.wal", .fault = .{ .write = .failed } },
        .{ .wal_name = "services-dprop-write-short.wal", .fault = .{ .write = .short } },
    };

    for (cases) |case| {
        {
            var store = try openTestStore(tmp, case.wal_name);
            defer store.deinit();
            var state = try durable_credential_props.State.init(std.testing.allocator, config);
            defer state.deinit();
            var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
            defer kt.deinit();
            var services = Services.init(&store, null);
            services.attachDurableCredentialProps(&state);
            services.attachKeyTransparencyLog(&kt);
            store.setPreparedIoFault(case.fault);

            const outcome = services.commitLocalDurableDeviceFact(event);
            try std.testing.expectEqual(Services.DurableDeviceFactRestart.ambiguous_store, outcome.restart_required);
            try std.testing.expect(store.preparedWritesPoisoned());
            try std.testing.expectEqual(@as(usize, 0), state.count());
            try std.testing.expectEqual(@as(usize, 0), kt.len());
            try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) == null);
            const second = services.commitLocalDurableDeviceFact(event);
            try std.testing.expectEqual(Services.DurableDeviceFactRestart.fatal_store, second.restart_required);
        }

        var reopened = try openTestStore(tmp, case.wal_name);
        defer reopened.deinit();
        try std.testing.expect(reopened.family(.props).get(durable_credential_props.store_key) == null);
    }
}

test "DPROP Services failed prepared overwrite preserves old snapshot on reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const old_event = try durableServicesEvent(0x87, "alice", "e2ee.device.phone", 110, true, "mls-x25519:old+/=");
    defer freeDurableServicesEvent(old_event);
    const new_event = try durableServicesEvent(0x87, "alice", "e2ee.device.phone", 111, true, "mls-x25519:new+/=");
    defer freeDurableServicesEvent(new_event);
    const config = durable_credential_props.Config{ .local_origin_node = old_event.origin_node };

    {
        var store = try openTestStore(tmp, "services-dprop-write-failed-old.wal");
        defer store.deinit();
        var state = try durable_credential_props.State.init(std.testing.allocator, config);
        defer state.deinit();
        var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
        defer kt.deinit();
        var services = Services.init(&store, null);
        services.attachDurableCredentialProps(&state);
        services.attachKeyTransparencyLog(&kt);
        try std.testing.expect(services.commitLocalDurableDeviceFact(old_event) == .committed);
        try std.testing.expectEqual(@as(usize, 1), kt.len());

        store.setPreparedIoFault(.{ .write = .failed });
        const outcome = services.commitLocalDurableDeviceFact(new_event);
        try std.testing.expectEqual(Services.DurableDeviceFactRestart.ambiguous_store, outcome.restart_required);
        try std.testing.expectEqualStrings("mls-x25519:old+/=", state.get("alice", "e2ee.device.phone").?.value);
        try std.testing.expectEqual(@as(usize, 1), kt.len());
    }

    var reopened = try openTestStore(tmp, "services-dprop-write-failed-old.wal");
    defer reopened.deinit();
    const image = reopened.family(.props).get(durable_credential_props.store_key) orelse return error.TestUnexpectedResult;
    var restored = try durable_credential_props.decode(std.testing.allocator, config, image);
    defer restored.deinit();
    try std.testing.expectEqualStrings("mls-x25519:old+/=", restored.get("alice", "e2ee.device.phone").?.value);
}

test "DPROP Services undersized store rejection is inert and unpoisoned" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "services-dprop-too-small.wal", .{ .max_record_bytes = 16 });
    defer store.deinit();
    const event = try durableServicesEvent(0x86, "alice", "e2ee.device.phone", 101, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    var state = try durable_credential_props.State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    defer state.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachDurableCredentialProps(&state);
    services.attachKeyTransparencyLog(&kt);

    const outcome = services.commitLocalDurableDeviceFact(event);
    try std.testing.expectEqual(Services.DurableDeviceFactPreadmission.capacity, outcome.preadmission);
    try std.testing.expect(!store.preparedWritesPoisoned());
    try std.testing.expectEqual(@as(usize, 0), state.count());
    try std.testing.expectEqual(@as(usize, 0), kt.len());
    try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) == null);
}

test "DPROP Services key transparency failure cannot roll back durable fact" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-dprop-kt-failure.wal");
    defer store.deinit();
    const event = try durableServicesEvent(0x84, "alice", "e2ee.device.phone", 81, true, "mls-x25519:abcd+/=");
    defer freeDurableServicesEvent(event);
    var state = try durable_credential_props.State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    defer state.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachDurableCredentialProps(&state);
    services.attachKeyTransparencyLog(&kt);
    kt.unusable = true;

    const outcome = services.commitLocalDurableDeviceFact(event);
    try std.testing.expectEqual(Services.DurableDeviceFactKeyTransparency.unavailable, outcome.committed.key_transparency);
    try std.testing.expectEqual(@as(usize, 1), state.count());
    try std.testing.expect(store.family(.props).get(durable_credential_props.store_key) != null);
    try std.testing.expectEqual(@as(usize, 0), kt.len());
}
