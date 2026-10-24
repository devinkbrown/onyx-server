// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auth atomic regression tests.

const std = @import("std");
const store_mod = @import("../store.zig");
const OroStore = @import("records.zig").OroStore;
const ScramStore = @import("records.zig").ScramStore;
const account_max = @import("records.zig").account_max;
const record_max = @import("records.zig").record_max;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const Internal = @import("core.zig").Internal;
const scram_store_mod = @import("../scram_store.zig");
const sasl = @import("../../proto/sasl.zig");
const sasl_scram512 = @import("../../proto/sasl_scram512_server.zig");
const ServiceError = @import("records.zig").ServiceError;
const SessionTokenIssue = @import("records.zig").SessionTokenIssue;
const certfp_key_max = @import("records.zig").certfp_key_max;
const certfpKey = @import("records.zig").certfpKey;
const WebauthnCredential = @import("contracts.zig").WebauthnCredential;
const AuthAtomicTestOperation = @import("test_support.zig").AuthAtomicTestOperation;
const auth_atomic_old_secret = @import("test_support.zig").auth_atomic_old_secret;
const auth_atomic_new_secret = @import("test_support.zig").auth_atomic_new_secret;
const auth_atomic_old_password = @import("test_support.zig").auth_atomic_old_password;
const auth_atomic_new_password = @import("test_support.zig").auth_atomic_new_password;
const authAtomicTestApply = @import("test_support.zig").authAtomicTestApply;
const authAtomicTestExpectSecret = @import("test_support.zig").authAtomicTestExpectSecret;
const authAtomicTestExpectApplied = @import("test_support.zig").authAtomicTestExpectApplied;

test "TOTP Services atomic policy revocation issuance and reset allocation failures retry and reopen" {
    for (std.meta.tags(AuthAtomicTestOperation)) |operation| {
        var failed: usize = 0;
        var failure_index: usize = 0;
        while (failure_index < 128) : (failure_index += 1) {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
            var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "auth-atomic-oom.wal");
            defer store.deinit();
            var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
            var scratch: [record_max]u8 = undefined;
            _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
            const old_secret: ?[]const u8 = if (operation == .enable) null else auth_atomic_old_secret;
            if (old_secret) |secret| try services.totpSecretPut("alice", secret);
            if (operation == .reset) try store.family(.props).put("scram:alice", "stale credential mirror");
            const old = try services.issueSessionToken("alice", 1000);
            const seq_before = store.next_seq;
            const offset_before = store.wal_offset;
            const change_count_before = store.changeCount();
            const before = try tmp.dir.readFileAlloc(std.testing.io, "auth-atomic-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(before);
            failing.fail_index = failing.alloc_index + failure_index;

            const replacement = authAtomicTestApply(&services, operation) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expect(services.authenticationAvailable());
                try authAtomicTestExpectSecret(&services, old_secret);
                var out: [account_max]u8 = undefined;
                try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &out) != null);
                _ = try services.identifyAccount("alice", auth_atomic_old_password);
                try std.testing.expectEqual(seq_before, store.next_seq);
                try std.testing.expectEqual(offset_before, store.wal_offset);
                try std.testing.expectEqual(change_count_before, store.changeCount());
                const after = try tmp.dir.readFileAlloc(std.testing.io, "auth-atomic-oom.wal", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(after);
                try std.testing.expectEqualSlices(u8, before, after);
                {
                    var reopened = try openTestStore(tmp, "auth-atomic-oom.wal");
                    defer reopened.deinit();
                    var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                    try authAtomicTestExpectSecret(&cold, old_secret);
                    try std.testing.expect(cold.validateSessionToken("alice", old.tokenSlice(), 1002, &out) != null);
                    _ = try cold.identifyAccount("alice", auth_atomic_old_password);
                }
                const retried = try authAtomicTestApply(&services, operation);
                try authAtomicTestExpectApplied(&services, operation, old, retried);
                {
                    var reopened = try openTestStore(tmp, "auth-atomic-oom.wal");
                    defer reopened.deinit();
                    var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                    try authAtomicTestExpectApplied(&cold, operation, old, retried);
                }
                failed += 1;
                continue;
            };
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(!failing.has_induced_failure);
            try authAtomicTestExpectApplied(&services, operation, old, replacement);
            try std.testing.expect(failed > 0);
            std.debug.print("TOTP atomic {s}: {d} induced allocation failures, retries, and cold reopens\n", .{ @tagName(operation), failed });
            break;
        } else return error.FailureSweepDidNotComplete;
    }
}

test "TOTP Services atomic policy write and sync ambiguity deny every auth until reopen" {
    const cases = [_]struct { fault: store_mod.PreparedIoFault, committed: bool }{
        .{ .fault = .{ .write = .failed }, .committed = false },
        .{ .fault = .{ .write = .short }, .committed = false },
        .{ .fault = .{ .sync = true }, .committed = true },
    };
    for (std.meta.tags(AuthAtomicTestOperation)) |operation| {
        for (cases) |case| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var old: SessionTokenIssue = undefined;
            const old_secret: ?[]const u8 = if (operation == .enable) null else auth_atomic_old_secret;
            {
                var store = try openTestStore(tmp, "auth-atomic-io.wal");
                defer store.deinit();
                var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
                var scratch: [record_max]u8 = undefined;
                _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
                if (old_secret) |secret| try services.totpSecretPut("alice", secret);
                old = try services.issueSessionToken("alice", 1000);
                const fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
                var fingerprint_key: [certfp_key_max]u8 = undefined;
                try store.family(.props).put(certfpKey(&fingerprint_key, fingerprint).?, "alice");
                _ = try services.recognizeAdd("alice", "*!*@example.test");
                try services.recoveryCodesReplace("alice", &.{"RECOVERYXX"});
                const cose = [_]u8{ 0xA5, 0x01, 0x02, 0x03 };
                try services.webauthnBind("alice", "credAAA", &cose, 1, "factor", 1);
                var credential: Services.WebauthnCredential = undefined;
                try services.webauthnLookup("credAAA", &credential);
                var scram_record_buf: [ScramStore.serialized_max]u8 = undefined;
                const scram_record = ScramStore.serializeFullRecord(.{
                    .salt = "old-scram-salt16",
                    .iterations = 1,
                    .stored_key = @splat(1),
                    .server_key = @splat(2),
                }, &scram_record_buf).?;
                try store.family(.props).put("scram:alice", scram_record);
                const loader = services.scramLoader();
                var backfill_destination = ScramStore.init(std.testing.allocator);
                defer backfill_destination.deinit();
                try std.testing.expect(loader.loadFn(loader.ptr, "alice", &backfill_destination));
                const seq_before = store.next_seq;
                const offset_before = store.wal_offset;
                const count_before = store.changeCount();
                store.setPreparedIoFault(case.fault);
                try std.testing.expectError(error.IoAmbiguous, authAtomicTestApply(&services, operation));
                try std.testing.expect(!services.authenticationAvailable());
                try std.testing.expect(services.accountAuthBlocked("alice"));
                try std.testing.expect(services.accountAuthBlocked("unknown"));
                try std.testing.expectError(error.StorePoisoned, services.identifyAccount("alice", auth_atomic_old_password));
                try std.testing.expectError(error.StorePoisoned, services.ghostAccount("alice", auth_atomic_old_password, "alice"));
                try std.testing.expect(services.accountForCertfp(fingerprint) == null);
                try std.testing.expect(!services.recognizeMatches("alice", "alice!user@example.test"));
                try std.testing.expectError(error.StorePoisoned, services.recoveryCodeConsume("alice", "RECOVERYXX"));
                try std.testing.expectError(error.StorePoisoned, services.webauthnLookup("credAAA", &credential));
                try std.testing.expect(!loader.loadFn(loader.ptr, "alice", &backfill_destination));
                var out: [account_max]u8 = undefined;
                try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &out) == null);
                try std.testing.expectError(error.StorePoisoned, services.issueSessionToken("alice", 1002));
                try std.testing.expectError(error.StorePoisoned, services.revokeSessionTokens("alice"));
                try std.testing.expectError(error.StorePoisoned, services.totpPolicyCommit("alice", auth_atomic_new_secret));
                try authAtomicTestExpectSecret(&services, old_secret);
                try std.testing.expectEqual(seq_before, store.next_seq);
                try std.testing.expectEqual(offset_before, store.wal_offset);
                try std.testing.expectEqual(count_before, store.changeCount());
            }
            var reopened = try openTestStore(tmp, "auth-atomic-io.wal");
            defer reopened.deinit();
            var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
            var out: [account_max]u8 = undefined;
            try std.testing.expect(cold.authenticationAvailable());
            if (case.committed) {
                try authAtomicTestExpectApplied(&cold, operation, old, null);
            } else {
                try authAtomicTestExpectSecret(&cold, old_secret);
                try std.testing.expect(cold.validateSessionToken("alice", old.tokenSlice(), 1002, &out) != null);
                _ = try cold.identifyAccount("alice", auth_atomic_old_password);
                const retried = try authAtomicTestApply(&cold, operation);
                try authAtomicTestExpectApplied(&cold, operation, old, retried);
            }
        }
    }
}

test "TOTP Services atomic admission rejection preserves policy and token authority" {
    const rejection_kinds = enum { record_limit, wal_limit, sequence_limit, read_only };
    for (std.meta.tags(rejection_kinds)) |rejection| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "auth-atomic-admission.wal");
        defer store.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
        try services.totpSecretPut("alice", auth_atomic_old_secret);
        const old = try services.issueSessionToken("alice", 1000);
        const cfg_before = store.cfg;
        const seq_before = store.next_seq;
        const offset_before = store.wal_offset;
        const feed_before = store.changeCount();
        const before = try tmp.dir.readFileAlloc(std.testing.io, "auth-atomic-admission.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        const expected: ServiceError = switch (rejection) {
            .record_limit => expected: {
                store.cfg.max_record_bytes = 1;
                break :expected error.RecordTooLarge;
            },
            .wal_limit => expected: {
                store.cfg.max_wal_bytes = 1;
                break :expected error.RecordTooLarge;
            },
            .sequence_limit => expected: {
                store.next_seq = std.math.maxInt(u64);
                break :expected error.SequenceExhausted;
            },
            .read_only => expected: {
                store.staged_read_only = true;
                break :expected error.ReadOnlyStore;
            },
        };
        try std.testing.expectError(expected, services.totpPolicyCommit("alice", auth_atomic_new_secret));
        store.cfg = cfg_before;
        store.next_seq = seq_before;
        store.staged_read_only = false;
        try std.testing.expect(services.authenticationAvailable());
        try authAtomicTestExpectSecret(&services, auth_atomic_old_secret);
        var out: [account_max]u8 = undefined;
        try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &out) != null);
        try std.testing.expectEqual(offset_before, store.wal_offset);
        try std.testing.expectEqual(feed_before, store.changeCount());
        const after = try tmp.dir.readFileAlloc(std.testing.io, "auth-atomic-admission.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        try services.totpPolicyCommit("alice", auth_atomic_new_secret);
        try authAtomicTestExpectApplied(&services, .replace, old, null);
    }
}

test "TOTP Services forced reset reserves SCRAM cache before durable mutation and reopens exact tuple" {
    for ([_]bool{ true, false }) |fail_cache| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "auth-reset-scram.wal");
        defer store.deinit();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var scram = ScramStore.init(failing.allocator());
        defer scram.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
        try scram.storeWithSalt("alice", auth_atomic_old_password, "old-scram-salt16", 1);
        services.attachScramStore(&scram);
        Internal.persistScram(&services, &scram, "alice");
        const old_record = scram.lookup("alice").?;
        const old_512 = scram.lookup512("alice").?;
        const old_token = try services.issueSessionToken("alice", 1000);
        const before = try tmp.dir.readFileAlloc(std.testing.io, "auth-reset-scram.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        const cfg_before = store.cfg;
        if (fail_cache) {
            failing.fail_index = failing.alloc_index;
            try std.testing.expectError(error.OutOfMemory, services.setAccountPasswordForced("alice", auth_atomic_new_password, &scratch));
            failing.fail_index = std.math.maxInt(usize);
        } else {
            store.cfg.max_record_bytes = 1;
            try std.testing.expectError(error.RecordTooLarge, services.setAccountPasswordForced("alice", auth_atomic_new_password, &scratch));
            store.cfg = cfg_before;
        }
        const unchanged = scram.lookup("alice").?;
        const unchanged_512 = scram.lookup512("alice").?;
        try std.testing.expectEqualSlices(u8, &old_record.stored_key, &unchanged.stored_key);
        try std.testing.expectEqualSlices(u8, &old_record.server_key, &unchanged.server_key);
        try std.testing.expectEqualSlices(u8, &old_512.stored_key, &unchanged_512.stored_key);
        try std.testing.expectEqualSlices(u8, &old_512.server_key, &unchanged_512.server_key);
        _ = try services.identifyAccount("alice", auth_atomic_old_password);
        var out: [account_max]u8 = undefined;
        try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) != null);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "auth-reset-scram.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);

        try services.setAccountPasswordForced("alice", auth_atomic_new_password, &scratch);
        const current = scram.lookup("alice").?;
        const current_512 = scram.lookup512("alice").?;
        try std.testing.expect(!std.mem.eql(u8, &old_record.stored_key, &current.stored_key));
        try std.testing.expect(!std.mem.eql(u8, &old_512.stored_key, &current_512.stored_key));
        var expected_256 = try sasl.deriveScramKeys(auth_atomic_new_password, current.salt, current.iterations);
        defer expected_256.wipe();
        var expected_512 = try sasl_scram512.deriveScramKeys(auth_atomic_new_password, current_512.salt, current_512.iterations);
        defer expected_512.wipe();
        try std.testing.expectEqualSlices(u8, &expected_256.stored_key, &current.stored_key);
        try std.testing.expectEqualSlices(u8, &expected_512.stored_key, &current_512.stored_key);
        try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
        _ = try services.identifyAccount("alice", auth_atomic_new_password);
        try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) == null);
        var reopened = try openTestStore(tmp, "auth-reset-scram.wal");
        defer reopened.deinit();
        var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
        var cold_scram = ScramStore.init(std.testing.allocator);
        defer cold_scram.deinit();
        cold_scram.setLoader(cold.scramLoader());
        const restored = cold_scram.resolve("alice").?;
        const restored_512 = cold_scram.resolve512("alice").?;
        try std.testing.expectEqualSlices(u8, current.salt, restored.salt);
        try std.testing.expectEqual(current.iterations, restored.iterations);
        try std.testing.expectEqualSlices(u8, &current.stored_key, &restored.stored_key);
        try std.testing.expectEqualSlices(u8, &current.server_key, &restored.server_key);
        try std.testing.expectEqualSlices(u8, &current_512.stored_key, &restored_512.stored_key);
        try std.testing.expectEqualSlices(u8, &current_512.server_key, &restored_512.server_key);
        _ = try cold.identifyAccount("alice", auth_atomic_new_password);
        try std.testing.expect(cold.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) == null);
    }
}

test "ordinary password change keeps PLAIN SCRAM and tokens atomic across allocation failure" {
    var failed: usize = 0;
    var failure_index: usize = 0;
    while (failure_index < 128) : (failure_index += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "password-change-oom.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        services.attachScramStore(&scram);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
        try scram.storeWithSalt("alice", auth_atomic_old_password, "old-scram-salt16", 1);
        Internal.persistScram(&services, &scram, "alice");
        const old_token = try services.issueSessionToken("alice", 1000);
        const old_scram = scram.lookup("alice").?;
        const before = try tmp.dir.readFileAlloc(std.testing.io, "password-change-oom.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        failing.fail_index = failing.alloc_index + failure_index;

        services.changeAccountPassword("alice", auth_atomic_old_password, auth_atomic_new_password, &scratch) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            failing.fail_index = std.math.maxInt(usize);
            _ = try services.identifyAccount("alice", auth_atomic_old_password);
            try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_new_password));
            try std.testing.expectEqualSlices(u8, &old_scram.stored_key, &scram.lookup("alice").?.stored_key);
            var token_account: [account_max]u8 = undefined;
            try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) != null);
            const after = try tmp.dir.readFileAlloc(std.testing.io, "password-change-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            try services.changeAccountPassword("alice", auth_atomic_old_password, auth_atomic_new_password, &scratch);
            _ = try services.identifyAccount("alice", auth_atomic_new_password);
            try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
            try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) == null);
            {
                var reopened = try openTestStore(tmp, "password-change-oom.wal");
                defer reopened.deinit();
                var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                var cold_scram = ScramStore.init(std.testing.allocator);
                defer cold_scram.deinit();
                cold_scram.setLoader(cold.scramLoader());
                cold.attachScramStore(&cold_scram);
                _ = try cold.identifyAccount("alice", auth_atomic_new_password);
                try std.testing.expectError(error.AuthFailed, cold.identifyAccount("alice", auth_atomic_old_password));
                try std.testing.expect(cold.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) == null);
            }
            failed += 1;
            continue;
        };
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(failed > 0);
        std.debug.print("ordinary password change atomic: {d} induced allocation failures, retries, and cold reopen\n", .{failed});
        break;
    } else return error.FailureSweepDidNotComplete;
}

test "DROP atomically revokes credentials before same-name re-registration" {
    const fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03 };
    var failed: usize = 0;
    var failure_index: usize = 0;
    while (failure_index < 128) : (failure_index += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "drop-credentials.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var binds = @import("../certfp_bind.zig").CertfpBindStore.init(std.testing.allocator);
        defer binds.deinit();
        var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
        services.attachScramStore(&scram);
        services.attachCertfpBinds(&binds);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
        try scram.storeWithSalt("alice", auth_atomic_old_password, "old-scram-salt16", 1);
        Internal.persistScram(&services, &scram, "alice");
        try services.bindCertfp("alice", fingerprint);
        try services.webauthnBind("alice", "credDROP", &cose, 1, "old", 1);
        // Model rows left by older best-effort index writes: the direct
        // credentials still name alice, while both account indexes are absent.
        var certfp_list_key_buf: [@import("records.zig").certfp_account_key_max]u8 = undefined;
        try store.family(.props).delete(@import("records.zig").certfpAccountKey(&certfp_list_key_buf, "alice").?);
        var webauthn_list_key_buf: [@import("../webauthn_creds.zig").account_list_key_max]u8 = undefined;
        try store.family(.props).delete(@import("../webauthn_creds.zig").accountListKey(&webauthn_list_key_buf, "alice").?);
        const old_token = try services.issueSessionToken("alice", 1000);
        failing.fail_index = failing.alloc_index + failure_index;

        const dropped = services.dropAccount("alice", auth_atomic_old_password) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            failing.fail_index = std.math.maxInt(usize);
            _ = try services.identifyAccount("alice", auth_atomic_old_password);
            try std.testing.expectEqualStrings("alice", services.accountForCertfp(fingerprint).?);
            var credential: Services.WebauthnCredential = .{};
            try services.webauthnLookup("credDROP", &credential);
            try std.testing.expect(scram.resolve("alice") != null);
            var token_account: [account_max]u8 = undefined;
            try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) != null);

            _ = try services.dropAccount("alice", auth_atomic_old_password);
            try std.testing.expect(services.accountForCertfp(fingerprint) == null);
            try std.testing.expect(scram.resolve("alice") == null);
            try std.testing.expectError(error.NotFound, services.webauthnLookup("credDROP", &credential));
            try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) == null);
            _ = try services.registerAccount("alice", auth_atomic_new_password, &scratch);
            try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
            _ = try services.identifyAccount("alice", auth_atomic_new_password);
            {
                var reopened = try openTestStore(tmp, "drop-credentials.wal");
                defer reopened.deinit();
                var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
                var cold_scram = ScramStore.init(std.testing.allocator);
                defer cold_scram.deinit();
                cold_scram.setLoader(cold.scramLoader());
                cold.attachScramStore(&cold_scram);
                var token_out: [account_max]u8 = undefined;
                try std.testing.expect(cold.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_out) == null);
                try std.testing.expect(cold_scram.resolve("alice") == null);
                try std.testing.expectError(error.NotFound, cold.webauthnLookup("credDROP", &credential));
                _ = try cold.identifyAccount("alice", auth_atomic_new_password);
            }
            failed += 1;
            continue;
        };
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqualStrings("alice", dropped.dropped_account.name.asSlice());
        try std.testing.expect(services.accountForCertfp(fingerprint) == null);
        try std.testing.expect(scram.resolve("alice") == null);
        var credential: Services.WebauthnCredential = .{};
        try std.testing.expectError(error.NotFound, services.webauthnLookup("credDROP", &credential));
        var token_account: [account_max]u8 = undefined;
        try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &token_account) == null);
        _ = try services.registerAccount("alice", auth_atomic_new_password, &scratch);
        try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
        _ = try services.identifyAccount("alice", auth_atomic_new_password);
        try std.testing.expect(failed > 0);
        std.debug.print("DROP credential atomicity: {d} induced allocation failures, retries, and cold re-registration\n", .{failed});
        break;
    } else return error.FailureSweepDidNotComplete;
}

test "TOTP Services forced reset ambiguity preserves live SCRAM and replays one complete credential policy" {
    const cases = [_]struct { fault: store_mod.PreparedIoFault, committed: bool }{
        .{ .fault = .{ .write = .failed }, .committed = false },
        .{ .fault = .{ .write = .short }, .committed = false },
        .{ .fault = .{ .sync = true }, .committed = true },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var old_token: SessionTokenIssue = undefined;
        var old_key: [scram_store_mod.digest_len]u8 = undefined;
        {
            var store = try openTestStore(tmp, "auth-reset-scram-io.wal");
            defer store.deinit();
            var scram = ScramStore.init(std.testing.allocator);
            defer scram.deinit();
            var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
            var scratch: [record_max]u8 = undefined;
            _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
            try scram.storeWithSalt("alice", auth_atomic_old_password, "old-scram-salt16", 1);
            services.attachScramStore(&scram);
            Internal.persistScram(&services, &scram, "alice");
            old_key = scram.lookup("alice").?.stored_key;
            old_token = try services.issueSessionToken("alice", 1000);
            store.setPreparedIoFault(case.fault);
            try std.testing.expectError(error.IoAmbiguous, services.setAccountPasswordForced("alice", auth_atomic_new_password, &scratch));
            try std.testing.expect(!services.authenticationAvailable());
            try std.testing.expect(services.accountAuthBlocked("alice"));
            try std.testing.expectEqualSlices(u8, &old_key, &scram.lookup("alice").?.stored_key);
            try std.testing.expectError(error.StorePoisoned, services.identifyAccount("alice", auth_atomic_old_password));
        }
        var reopened = try openTestStore(tmp, "auth-reset-scram-io.wal");
        defer reopened.deinit();
        var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
        var cold_scram = ScramStore.init(std.testing.allocator);
        defer cold_scram.deinit();
        cold_scram.setLoader(cold.scramLoader());
        const restored = cold_scram.resolve("alice").?;
        const restored_512 = cold_scram.resolve512("alice").?;
        const accepted_password = if (case.committed) auth_atomic_new_password else auth_atomic_old_password;
        var keys256 = try sasl.deriveScramKeys(accepted_password, restored.salt, restored.iterations);
        defer keys256.wipe();
        var keys512 = try sasl_scram512.deriveScramKeys(accepted_password, restored_512.salt, restored_512.iterations);
        defer keys512.wipe();
        try std.testing.expectEqualSlices(u8, &keys256.stored_key, &restored.stored_key);
        try std.testing.expectEqualSlices(u8, &keys512.stored_key, &restored_512.stored_key);
        try std.testing.expect(cold.authenticationAvailable());
        _ = try cold.identifyAccount("alice", accepted_password);
        var out: [account_max]u8 = undefined;
        try std.testing.expectEqual(!case.committed, cold.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) != null);
        try std.testing.expectEqual(!case.committed, std.mem.eql(u8, &old_key, &restored.stored_key));
    }
}

test "TOTP Services SCRAM backfill holds durable borrow through cache publication and serializes reset" {
    const PausingAllocator = struct {
        entered: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),

        fn allocate(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!self.entered.swap(true, .acq_rel)) {
                while (!self.release.load(.acquire)) std.Thread.yield() catch {};
            }
            return std.testing.allocator.rawAlloc(len, alignment, ra);
        }

        fn resize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
            return std.testing.allocator.rawResize(memory, alignment, len, ra);
        }

        fn remap(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
            return std.testing.allocator.rawRemap(memory, alignment, len, ra);
        }

        fn free(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
            std.testing.allocator.rawFree(memory, alignment, ra);
        }

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = allocate, .resize = resize, .remap = remap, .free = free } };
        }
    };
    const Reader = struct {
        scram: *ScramStore,
        loaded: bool = false,

        fn run(self: *@This()) void {
            self.loaded = self.scram.resolve("alice") != null;
        }
    };
    const Reset = struct {
        services: *Services,
        completed: bool = false,

        fn run(self: *@This()) void {
            var scratch: [record_max]u8 = undefined;
            self.services.setAccountPasswordForced("alice", auth_atomic_new_password, &scratch) catch return;
            self.completed = true;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "auth-backfill-reset.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccount("alice", auth_atomic_old_password, &scratch);
    var fixture_scram = ScramStore.init(std.testing.allocator);
    defer fixture_scram.deinit();
    try fixture_scram.storeWithSalt("alice", auth_atomic_old_password, "old-scram-salt16", 1);
    Internal.persistScram(&services, &fixture_scram, "alice");
    const old_token = try services.issueSessionToken("alice", 1000);
    var pausing: PausingAllocator = .{};
    var destination = ScramStore.init(pausing.allocator());
    defer destination.deinit();
    destination.setLoader(services.scramLoader());
    services.attachScramStore(&destination);
    var reader_context = Reader{ .scram = &destination };
    var reader = try std.Thread.spawn(.{}, Reader.run, .{&reader_context});
    var reader_joined = false;
    defer if (!reader_joined) {
        pausing.release.store(true, .release);
        reader.join();
    };
    while (!pausing.entered.load(.acquire)) std.Thread.yield() catch {};
    const shared_lock_held = !services.lock.tryLockExclusive();
    if (!shared_lock_held) services.lock.unlockExclusive();
    var reset_context = Reset{ .services = &services };
    var reset = try std.Thread.spawn(.{}, Reset.run, .{&reset_context});
    if (shared_lock_held) {
        // The pending exclusive writer is observable without sleep or a
        // scheduling guess. It cannot pass the loader's durable borrow cut.
        while (services.lock.writers_waiting.load(.acquire) == 0) std.Thread.yield() catch {};
    }
    pausing.release.store(true, .release);
    reader.join();
    reader_joined = true;
    reset.join();
    try std.testing.expect(shared_lock_held);
    try std.testing.expect(reader_context.loaded);
    try std.testing.expect(reset_context.completed);
    const current = destination.lookup("alice").?;
    const current_512 = destination.lookup512("alice").?;
    var expected_256 = try sasl.deriveScramKeys(auth_atomic_new_password, current.salt, current.iterations);
    defer expected_256.wipe();
    var expected_512 = try sasl_scram512.deriveScramKeys(auth_atomic_new_password, current_512.salt, current_512.iterations);
    defer expected_512.wipe();
    try std.testing.expectEqualSlices(u8, &expected_256.stored_key, &current.stored_key);
    try std.testing.expectEqualSlices(u8, &expected_512.stored_key, &current_512.stored_key);
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
    _ = try services.identifyAccount("alice", auth_atomic_new_password);
    var out: [account_max]u8 = undefined;
    try std.testing.expect(services.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) == null);

    var reopened = try openTestStore(tmp, "auth-backfill-reset.wal");
    defer reopened.deinit();
    var cold = Services.initWithConfig(&reopened, null, .{ .pbkdf2_rounds = 1 });
    var cold_scram = ScramStore.init(std.testing.allocator);
    defer cold_scram.deinit();
    cold_scram.setLoader(cold.scramLoader());
    const restored = cold_scram.resolve("alice").?;
    const restored_512 = cold_scram.resolve512("alice").?;
    try std.testing.expectEqualSlices(u8, current.salt, restored.salt);
    try std.testing.expectEqualSlices(u8, &current.stored_key, &restored.stored_key);
    try std.testing.expectEqualSlices(u8, &current_512.stored_key, &restored_512.stored_key);
    _ = try cold.identifyAccount("alice", auth_atomic_new_password);
    try std.testing.expect(cold.validateSessionToken("alice", old_token.tokenSlice(), 1002, &out) == null);
}
