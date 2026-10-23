// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Accounts regression tests.

const std = @import("std");
const ScramStore = @import("records.zig").ScramStore;
const account_max = @import("records.zig").account_max;
const record_max = @import("records.zig").record_max;
const Config = @import("records.zig").Config;
const account_flag_secure = @import("records.zig").account_flag_secure;
const account_flag_passkey_only = @import("records.zig").account_flag_passkey_only;
const account_flag_oper_stepup = @import("records.zig").account_flag_oper_stepup;
const successor_hold_ms = @import("records.zig").successor_hold_ms;
const login_audit_cap = @import("records.zig").login_audit_cap;
const LoginMechanism = @import("records.zig").LoginMechanism;
const LoginTls = @import("records.zig").LoginTls;
const LoginAuditEntry = @import("records.zig").LoginAuditEntry;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const certfp_key_max = @import("records.zig").certfp_key_max;
const certfpKey = @import("records.zig").certfpKey;
const ServicesMtCtx = @import("test_support.zig").ServicesMtCtx;
const account_verify = @import("../account_verify.zig");
const EmailVerifyResult = @import("records.zig").EmailVerifyResult;
const toml = @import("../../proto/toml.zig");
const default_pbkdf2_rounds = @import("records.zig").default_pbkdf2_rounds;
const default_password_min_len = @import("records.zig").default_password_min_len;
const default_password_max_len = @import("records.zig").default_password_max_len;
const account_flag_suspended = @import("records.zig").account_flag_suspended;
const account_flag_noexpire = @import("records.zig").account_flag_noexpire;

test "register and identify account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-account.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    const registered = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    try std.testing.expectEqualStrings("alice", registered.registered_account.name.asSlice());

    const identified = try services.identifyAccount("ALICE", "correct horse battery staple");
    try std.testing.expectEqualStrings("alice", identified.identified.name.asSlice());
}

test "services passkey-only successor hold and login audit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-passkey-successor.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 1 });
    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();
    services.attachScramStore(&scram);
    var scratch: [record_max]u8 = undefined;
    const password = "correct horse battery staple";
    _ = try services.registerAccount("Alice", password, &scratch);
    _ = try services.registerAccount("Bob", password, &scratch);
    try std.testing.expect(scram.resolve("alice") != null);

    services.clock_override_ms.store(1_000, .release);
    var rows: [login_audit_cap]LoginAuditEntry = undefined;
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        services.clock_override_ms.store(1_000 + @as(u64, @intCast(i)), .release);
        const identified = try services.identifyAccountWithAudit("alice", password, .{
            .at_ms = services.clock_override_ms.load(.acquire),
            .tls = .unknown,
        });
        try std.testing.expectEqualStrings("alice", identified.identified.name.asSlice());
    }
    const unchecked = try services.copyLoginAudit("alice", &rows);
    try std.testing.expectEqual(login_audit_cap, unchecked.len);
    try std.testing.expectEqual(@as(u64, 1_001), unchecked[0].at_ms);
    _ = try services.identifyAccount("alice", password);
    const still = try services.copyLoginAudit("alice", &rows);
    try std.testing.expectEqual(@as(u64, 1_001), still[0].at_ms);
    try std.testing.expectEqual(@as(u64, 1_008), still[still.len - 1].at_ms);
    const got = try services.copyLoginAudit("alice", &rows);
    try std.testing.expectEqual(login_audit_cap, got.len);
    try std.testing.expectEqual(@as(u64, 1_001), got[0].at_ms);
    try std.testing.expectEqual(@as(u64, 1_008), got[got.len - 1].at_ms);
    try std.testing.expectEqual(LoginMechanism.password, got[0].mechanism);
    try std.testing.expectEqual(LoginTls.unknown, got[0].tls);

    var prefix: [8]u8 = @splat(0);
    @memcpy(prefix[0..4], "abcd");
    try services.appendLoginAudit("alice", .{
        .at_ms = 9_000,
        .mechanism = .passkey,
        .tls = .tls,
        .certfp_prefix = prefix,
        .certfp_len = 4,
    });
    const audited = try services.copyLoginAudit("ALICE", &rows);
    try std.testing.expectEqual(login_audit_cap, audited.len);
    try std.testing.expectEqual(@as(u64, 1_002), audited[0].at_ms);
    try std.testing.expectEqual(LoginMechanism.passkey, audited[audited.len - 1].mechanism);
    try std.testing.expectEqual(LoginTls.tls, audited[audited.len - 1].tls);
    try std.testing.expectEqual(@as(u8, 4), audited[audited.len - 1].certfp_len);
    try std.testing.expectEqualStrings("abcd", audited[audited.len - 1].certfp_prefix[0..4]);

    services.clock_override_ms.store(5_000, .release);
    var out: [account_max]u8 = undefined;
    try std.testing.expect(services.channelSuccessorGet("#Room", &out) == null);
    try services.channelSuccessorSet("#Room", "Alice");
    try std.testing.expect(services.channelSuccessorGet("#room", &out) == null);
    services.clock_override_ms.store(5_000 + successor_hold_ms - 1, .release);
    try std.testing.expect(services.channelSuccessorGet("#room", &out) == null);
    services.clock_override_ms.store(5_000 + successor_hold_ms, .release);
    try std.testing.expectEqualStrings("alice", services.channelSuccessorGet("#room", &out).?);

    const replace_at: u64 = 5_000 + successor_hold_ms;
    try services.channelSuccessorSet("#room", "Bob");
    try std.testing.expectEqualStrings("alice", services.channelSuccessorGet("#room", &out).?);
    try services.channelSuccessorSet("#room", "alice");
    services.clock_override_ms.store(replace_at + successor_hold_ms, .release);
    try std.testing.expectEqualStrings("alice", services.channelSuccessorGet("#room", &out).?);

    const second = services.clock_override_ms.load(.acquire);
    try services.channelSuccessorSet("#room", "bob");
    services.clock_override_ms.store(second + successor_hold_ms - 1, .release);
    try services.channelSuccessorClear("#room");
    try std.testing.expectEqualStrings("alice", services.channelSuccessorGet("#room", &out).?);
    services.clock_override_ms.store(second + successor_hold_ms, .release);
    try std.testing.expectEqualStrings("alice", services.channelSuccessorGet("#room", &out).?);

    const third = services.clock_override_ms.load(.acquire);
    try services.channelSuccessorSet("#room", "Bob");
    services.clock_override_ms.store(third + successor_hold_ms, .release);
    try std.testing.expectEqualStrings("bob", services.channelSuccessorGet("#room", &out).?);
    try services.channelSuccessorSet("#room", "bob");
    try std.testing.expectEqualStrings("bob", services.channelSuccessorGet("#room", &out).?);
    const fourth = services.clock_override_ms.load(.acquire);
    try services.channelSuccessorSet("#room", "Alice");
    services.clock_override_ms.store(fourth + 1, .release);
    try std.testing.expectEqualStrings("bob", services.channelSuccessorGet("#room", &out).?);
    try services.channelSuccessorClear("#room");
    try std.testing.expectEqualStrings("bob", services.channelSuccessorGet("#room", &out).?);
    try services.channelSuccessorClear("#room");
    try std.testing.expect(services.channelSuccessorGet("#room", &out) == null);

    try std.testing.expectError(error.Forbidden, services.enablePasskeyOnly("alice", &scratch));
    try services.webauthnBind("alice", "abc", "k", 0, "", 1);
    try services.webauthnBind("alice", "def", "k", 0, "lap", 1);
    const issued = try services.issueSessionToken("alice", 1_000);
    var token_account: [account_max]u8 = undefined;
    try std.testing.expect(services.validateSessionToken("alice", issued.tokenSlice(), 1_001, &token_account) != null);
    try services.enablePasskeyOnly("alice", &scratch);
    try std.testing.expect(services.operStepUpRequired("alice"));
    try std.testing.expect(services.validateSessionToken("alice", issued.tokenSlice(), 1_001, &token_account) == null);
    try std.testing.expectError(error.AuthFailed, services.issueSessionToken("alice", 1_002));
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", password));
    try std.testing.expectError(error.AuthFailed, services.dropAccount("alice", password));
    try std.testing.expectError(error.AuthFailed, services.changeAccountPassword("alice", password, "another correct horse battery", &scratch));
    try std.testing.expectError(error.AuthFailed, services.ghostAccount("alice", password, "Other"));
    try std.testing.expectError(error.AuthFailed, services.setAccount("alice", password, .{ .flags = 0 }, &scratch));
    try std.testing.expect(scram.resolve("alice") == null);
    try services.webauthnDelete("alice", "abc");
    try std.testing.expectError(error.Forbidden, services.webauthnDelete("alice", "def"));

    const flagged = try services.setAccount("bob", password, .{ .flags = account_flag_passkey_only | account_flag_oper_stepup | account_flag_secure }, &scratch);
    try std.testing.expect((flagged.set_account.flags & account_flag_passkey_only) == 0);
    try std.testing.expect((flagged.set_account.flags & account_flag_oper_stepup) == 0);
    try std.testing.expect((flagged.set_account.flags & account_flag_secure) != 0);

    try services.setAccountPasswordForced("alice", password, &scratch);
    const restored = try services.identifyAccount("alice", password);
    try std.testing.expectEqualStrings("alice", restored.identified.name.asSlice());
    try std.testing.expect(scram.resolve("alice") != null);
    try services.webauthnDelete("alice", "def");
    const info = try services.accountInfo("alice");
    try std.testing.expect((info.account_info.flags & account_flag_passkey_only) == 0);
    try std.testing.expect((info.account_info.flags & account_flag_oper_stepup) != 0);
    const kept = try services.setAccount("alice", password, .{ .flags = 0 }, &scratch);
    try std.testing.expect((kept.set_account.flags & account_flag_oper_stepup) != 0);
    try services.notePasskeyAuthentication("alice", &scratch);
    const cleared = try services.accountInfo("alice");
    try std.testing.expect((cleared.account_info.flags & account_flag_oper_stepup) == 0);
    try services.setAccountPasswordForced("bob", password, &scratch);
    const bob_info = try services.accountInfo("bob");
    try std.testing.expect((bob_info.account_info.flags & account_flag_oper_stepup) == 0);
    try std.testing.expect(!services.operStepUpRequired("bob"));
}

test "Services concurrent account writers and readers preserve account records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-concurrent.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{ .pbkdf2_rounds = 16 });
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccount("seed", "correct horse battery staple", &scratch);

    const writers = 4;
    const readers = 4;
    const iters = 16;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]ServicesMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .services = &services, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ServicesMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ServicesMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    var name_buf: [account_max]u8 = undefined;
    for (0..writers) |w| {
        for (0..iters) |i| {
            const name = ServicesMtCtx.accountName(&name_buf, w, i);
            const info = try services.accountInfo(name);
            try std.testing.expectEqualStrings("thread@example.test", info.account_info.email.asSlice());
        }
    }
}

test "account email verification persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-email-verify.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccountWithEmail("Alice", "correct horse battery staple", "alice@example.test", false, &scratch);
        var info = try services.accountInfo("alice");
        try std.testing.expectEqualStrings("alice@example.test", info.account_info.email.asSlice());
        try std.testing.expect(!info.account_info.email_verified);

        try services.setAccountEmailPending("alice", "alice@example.test", "abc123", 10, &scratch);
    }
    {
        var store = try openTestStore(tmp, "services-email-verify.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        try std.testing.expectEqual(EmailVerifyResult.bad_token, try services.confirmAccountEmail("ALICE", "wrong", 11, &scratch));
        var info = try services.accountInfo("alice");
        try std.testing.expect(!info.account_info.email_verified);

        try std.testing.expectEqual(EmailVerifyResult.verified, try services.confirmAccountEmail("ALICE", "abc123", 12, &scratch));
        info = try services.accountInfo("alice");
        try std.testing.expectEqualStrings("alice@example.test", info.account_info.email.asSlice());
        try std.testing.expect(info.account_info.email_verified);
        try std.testing.expectEqual(EmailVerifyResult.no_pending, try services.confirmAccountEmail("ALICE", "abc123", 13, &scratch));
    }
}

test "DST GAP-D7 a failed pending-address write issues no verification token" {
    std.debug.print("GAP-D7 branch=a failed pending-address write issues no verification token; live mail stays off\n", .{});
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "gap-d7-verify.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccountWithEmail("alice", "correct horse battery staple", "alice@example.test", false, &scratch);
    var verifies = account_verify.VerifyStore.init(std.testing.allocator, .{ .token_bytes = 16 });
    defer verifies.deinit();
    var random: [16]u8 = undefined;
    @memset(&random, 0xab);

    store.cfg.max_record_bytes = 8;
    try std.testing.expectError(error.RecordTooLarge, services.beginEmailVerification(&verifies, "alice", "other@example.test", &random, 10, &scratch));
    try std.testing.expect(!verifies.isPending("alice"));
    try std.testing.expectEqual(EmailVerifyResult.no_pending, try services.confirmAccountEmail("alice", "abcd", 11, &scratch));
    var info = try services.accountInfo("alice");
    try std.testing.expectEqualStrings("alice@example.test", info.account_info.email.asSlice());

    store.cfg.max_record_bytes = 16 * 1024 * 1024;
    const token = try services.beginEmailVerification(&verifies, "alice", "other@example.test", &random, 12, &scratch);
    try std.testing.expect(verifies.isPending("alice"));
    try std.testing.expectEqual(EmailVerifyResult.verified, try services.confirmAccountEmail("alice", token, 13, &scratch));
    info = try services.accountInfo("alice");
    try std.testing.expectEqualStrings("other@example.test", info.account_info.email.asSlice());
    try std.testing.expect(info.account_info.email_verified);
}

test "accountAuthBlocked gates the SASL success chokepoint on suspend and forbid" {
    // The shared fail-closed predicate consulted at SASL success so that SCRAM /
    // OAUTHBEARER (whose proof/token verification never consults account status)
    // cannot bind a SUSPENDED or FORBIDDEN account. Mirrors the FORBID lockout
    // test above, but targets the status accessor the chokepoint reuses.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-authblocked.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    // A healthy registered account is not blocked.
    try std.testing.expect(!services.accountAuthBlocked("alice"));
    // An account that does not exist is not blocked (guest/unknown authcid).
    try std.testing.expect(!services.accountAuthBlocked("nobody"));

    // SUSPEND blocks; UNSUSPEND restores.
    _ = try services.setAccountSuspended("alice", true, &scratch);
    try std.testing.expect(services.accountAuthBlocked("alice"));
    _ = try services.setAccountSuspended("alice", false, &scratch);
    try std.testing.expect(!services.accountAuthBlocked("alice"));

    // FORBID blocks; UNFORBID restores.
    _ = try services.setAccountForbidden("alice", true, &scratch);
    try std.testing.expect(services.accountAuthBlocked("alice"));
    _ = try services.setAccountForbidden("alice", false, &scratch);
    try std.testing.expect(!services.accountAuthBlocked("alice"));

    // A FORBID reservation on a never-registered name still blocks (the loser of
    // a nick forbid must not slip through a credential path either).
    _ = try services.setAccountForbidden("ghostname", true, &scratch);
    try std.testing.expect(services.accountAuthBlocked("ghostname"));
}

test "GAP-P0b accountIsRegistered requires a real account record" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-oauth-known.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    try std.testing.expect(!services.accountIsRegistered("Alice"));
    try std.testing.expect(!services.accountIsRegistered("bad/name"));
    _ = try services.setAccountForbidden("reserved", true, &scratch);
    try std.testing.expect(!services.accountIsRegistered("reserved"));
    _ = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    try std.testing.expect(services.accountIsRegistered("alice"));
    try std.testing.expect(services.accountIsRegistered("ALICE"));
}

test "setAccount refuses password-holder lifecycle flag changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-accountset-lifecycle-denied.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = account_flag_suspended }, &scratch));
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = account_flag_noexpire }, &scratch));

    const display_pref: u32 = 1 << 8;
    const changed = try services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref }, &scratch);
    try std.testing.expectEqual(display_pref, changed.set_account.flags);

    var admin = try services.setAccountNoExpire("alice", true, &scratch);
    try std.testing.expect(admin.noexpire());
    try std.testing.expectError(error.Forbidden, services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref }, &scratch));

    const with_pref = try services.setAccount("alice", "correct horse battery staple", .{ .flags = display_pref | account_flag_noexpire }, &scratch);
    try std.testing.expectEqual(display_pref | account_flag_noexpire, with_pref.set_account.flags);
    admin = try services.adminAccountInfo("alice");
    try std.testing.expect(admin.noexpire());
}

test "ghostAccount authenticates account separately from target nick" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-ghost-nick.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    const ghosted = try services.ghostAccount("alice", "correct horse battery staple", "AwayNick");
    try std.testing.expectEqualStrings("alice", ghosted.ghosted.account.asSlice());
    try std.testing.expectEqualStrings("AwayNick", ghosted.ghosted.nick.asSlice());
    try std.testing.expectError(error.NotFound, services.ghostAccount("AwayNick", "correct horse battery staple", "AwayNick"));
}

test "scram credentials persist across store reopen via loader" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-scram.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var services = Services.init(&store, null);
        services.attachScramStore(&scram);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        try std.testing.expect(scram.lookup("alice") != null);
    }
    {
        // Reopen with a COLD in-memory SCRAM store + the durable loader.
        var store = try openTestStore(tmp, "services-scram.wal");
        defer store.deinit();
        var scram = ScramStore.init(std.testing.allocator);
        defer scram.deinit();
        var services = Services.init(&store, null);
        services.attachScramStore(&scram);
        scram.setLoader(services.scramLoader());
        try std.testing.expect(scram.lookup("alice") == null); // cold cache
        try std.testing.expect(scram.resolve("alice") != null); // backfilled from disk
        try std.testing.expect(scram.resolve("nobody") == null);
    }
}

test "setAccount on a missing account runs the dummy hash reject path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-setaccount-missing.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    // A missing account must take the same rejection path (dummy PBKDF2) as a
    // present account with the wrong password so ACCOUNTSET is not a timing
    // oracle. Structurally we assert both reach the credential-failure surface
    // rather than a fast NotFound short-circuit: a MISSING account with a
    // policy-passing password returns NotFound (after the dummy hash), and a
    // PRESENT account with a wrong password returns AuthFailed.
    try std.testing.expectError(error.NotFound, services.setAccount("ghost", "correct horse battery staple", .{ .email = "ghost@example.test" }, &scratch));

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.AuthFailed, services.setAccount("alice", "wrong horse battery staple", .{ .email = "alice@example.test" }, &scratch));

    // A password that fails the length/char policy short-circuits identically
    // on both the missing and present paths (validatePassword precedes any
    // hashing in both rejectMissingAccount and verifyPassword).
    try std.testing.expectError(error.InvalidPassword, services.setAccount("ghost", "x", .{ .email = "ghost@example.test" }, &scratch));
}

test "Config default preserves historical account policy" {
    const cfg = Config{};
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
    try std.testing.expectEqual(@as(u32, 100_000), cfg.pbkdf2_rounds);
    try std.testing.expectEqual(default_password_min_len, cfg.password_min_len);
    try std.testing.expectEqual(default_password_max_len, cfg.password_max_len);
}

test "Config.applyToml overlays account password policy" {
    var doc = try toml.parse(std.testing.allocator, "[accounts]\npbkdf2_rounds = 250000\npassword_min_len = 12\npassword_max_len = 1024\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(u32, 250_000), cfg.pbkdf2_rounds);
    try std.testing.expectEqual(@as(usize, 12), cfg.password_min_len);
    try std.testing.expectEqual(@as(usize, 1024), cfg.password_max_len);
}

test "Config.applyToml leaves defaults when keys absent" {
    var doc = try toml.parse(std.testing.allocator, "[server]\nname = \"x\"\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
    try std.testing.expectEqual(default_password_min_len, cfg.password_min_len);
    try std.testing.expectEqual(default_password_max_len, cfg.password_max_len);
}

test "Config.applyToml ignores out-of-range rounds" {
    var doc = try toml.parse(std.testing.allocator, "[accounts]\npbkdf2_rounds = 0\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
}

test "registerAccount mirrors SCRAM credentials when a store is attached" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-scram-mirror.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [record_max]u8 = undefined;

    // Registration provisions both the PLAIN record and the SCRAM mirror.
    _ = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    const record = scram.lookup("alice");
    try std.testing.expect(record != null);
    try std.testing.expect(record.?.salt.len != 0);
    // The PLAIN path still verifies against the persistent account record.
    _ = try services.identifyAccount("alice", "correct horse battery staple");
}

test "registerAccount without a SCRAM store leaves SCRAM unprovisioned" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-scram-absent.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    // No store attached: registration succeeds with historical behaviour intact.
    const registered = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectEqualStrings("alice", registered.registered_account.name.asSlice());
    try std.testing.expect(services.scram == null);
}

test "initWithConfig threads custom account policy into hashing and password validation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-cfg-rounds.wal");
    defer store.deinit();
    var services = Services.initWithConfig(&store, null, .{
        .pbkdf2_rounds = 4096,
        .password_min_len = 12,
        .password_max_len = 32,
    });
    var scratch: [record_max]u8 = undefined;

    try std.testing.expectError(error.InvalidPassword, services.registerAccount("too_short", "short", &scratch));
    try std.testing.expectError(error.InvalidPassword, services.registerAccount("too_long", "this password is longer than twenty four bytes", &scratch));
    _ = try services.registerAccount("Bob", "correct horse battery staple", &scratch);
    const identified = try services.identifyAccount("bob", "correct horse battery staple");
    try std.testing.expectEqualStrings("bob", identified.identified.name.asSlice());
}

test "wrong password is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-wrong-pass.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "wrong horse battery staple"));
}

test "missing identify collapses to auth failed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-missing-identify.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    try std.testing.expectError(error.AuthFailed, services.identifyAccount("missing", "correct horse battery staple"));
}

test "corrupt account record is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-corrupt-account.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    try store.family(.accounts).put("alice", "A1|alice|not-a-salt|not-a-hash|0|");
    try std.testing.expectError(error.InvalidRecord, services.identifyAccount("alice", "correct horse battery staple"));
}

test "account persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.setAccount("alice", "correct horse battery staple", .{ .email = "alice@example.test" }, &scratch);
    }
    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        const result = try services.accountInfo("ALICE");
        try std.testing.expectEqualStrings("alice@example.test", result.account_info.email.asSlice());
        _ = try services.identifyAccount("alice", "correct horse battery staple");
    }
}

test "account lifecycle flags round-trip and persist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-account-lifecycle.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        var info = try services.setAccountSuspended("alice", true, &scratch);
        try std.testing.expect(info.suspended());
        try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "correct horse battery staple"));

        info = try services.setAccountSuspended("alice", false, &scratch);
        try std.testing.expect(!info.suspended());
        _ = try services.identifyAccount("alice", "correct horse battery staple");

        info = try services.setAccountForbidden("alice", true, &scratch);
        try std.testing.expect(info.forbidden());
        info = try services.setAccountNoExpire("alice", true, &scratch);
        try std.testing.expect(info.noexpire());

        const reserved = try services.setAccountForbidden("Reserved", true, &scratch);
        try std.testing.expect(!reserved.registered);
        try std.testing.expect(reserved.forbidden());
        try std.testing.expectError(error.Forbidden, services.registerAccount("reserved", "correct horse battery staple", &scratch));
    }
    {
        var store = try openTestStore(tmp, "services-account-lifecycle.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const info = try services.adminAccountInfo("ALICE");
        try std.testing.expect(info.registered);
        try std.testing.expect(info.forbidden());
        try std.testing.expect(info.noexpire());
        try std.testing.expect(!info.suspended());

        const reserved = try services.adminAccountInfo("reserved");
        try std.testing.expect(!reserved.registered);
        try std.testing.expect(reserved.forbidden());
    }
}

test "forbidden account is locked out of every login path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-forbidden-login.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    // Bind a certfp to alice through the durable props mirror; certfpOwnerUnlocked
    // falls back to it when the in-memory cache is cold, so this exercises the
    // SASL EXTERNAL lookup without a live CertfpBindStore.
    const fp = "aa:bb:cc:dd";
    var kb: [certfp_key_max]u8 = undefined;
    const k = certfpKey(&kb, fp).?;
    try store.family(.props).put(k, "alice");
    try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);

    // An admin FORBID on a registered account must lock it out of EVERY login
    // path, exactly as the session-token paths (issue/validate) already do.
    const info = try services.setAccountForbidden("alice", true, &scratch);
    try std.testing.expect(info.forbidden());

    // Password / SASL PLAIN both route through identifyAccount.
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "correct horse battery staple"));
    // A minted session token must also refuse to issue for a forbidden account.
    try std.testing.expectError(error.AuthFailed, services.issueSessionToken("alice", 1000));
    // Client-cert (SASL EXTERNAL).
    try std.testing.expect(services.accountForCertfp(fp) == null);

    // UNFORBID restores authentication on both credential paths.
    _ = try services.setAccountForbidden("alice", false, &scratch);
    _ = try services.identifyAccount("alice", "correct horse battery staple");
    try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);
}
