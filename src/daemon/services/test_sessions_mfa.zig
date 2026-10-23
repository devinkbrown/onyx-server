// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sessions mfa regression tests.

const std = @import("std");
const account_max = @import("records.zig").account_max;
const record_max = @import("records.zig").record_max;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const hash_len = @import("records.zig").hash_len;
const session_token_prefix = @import("records.zig").session_token_prefix;
const session_token_key_max = @import("records.zig").session_token_key_max;
const session_token_account_key_max = @import("records.zig").session_token_account_key_max;
const sessionTokenKey = @import("records.zig").sessionTokenKey;
const sessionTokenAccountKey = @import("records.zig").sessionTokenAccountKey;
const totp_secret_max = @import("contracts.zig").totp_secret_max;

test "recovery codes: generate, consume, remaining, clear" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-recovery.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    try std.testing.expectEqual(@as(usize, 0), services.recoveryCodesRemaining("alice"));
    const codes = [_][]const u8{ "ABCDEFGHJK", "MN01234567", "PQRSTVWXYZ" };
    try services.recoveryCodesReplace("alice", &codes);
    try std.testing.expectEqual(@as(usize, 3), services.recoveryCodesRemaining("ALICE"));

    try services.recoveryCodeConsume("alice", "MN01234567");
    try std.testing.expectEqual(@as(usize, 2), services.recoveryCodesRemaining("alice"));
    // Already spent
    try std.testing.expectError(error.AuthFailed, services.recoveryCodeConsume("alice", "MN01234567"));
    try services.recoveryCodeConsume("alice", "ABCDEFGHJK");
    try services.recoveryCodeConsume("alice", "PQRSTVWXYZ");
    try std.testing.expectEqual(@as(usize, 0), services.recoveryCodesRemaining("alice"));

    try services.recoveryCodesReplace("alice", &codes);
    try services.recoveryCodesClear("alice");
    try std.testing.expectEqual(@as(usize, 0), services.recoveryCodesRemaining("alice"));
}

test "session tokens issue, validate by hash, and expire" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-session-token.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    const issued = try services.issueSessionToken("alice", 1000);
    try std.testing.expectEqualStrings("alice", issued.account.asSlice());
    try std.testing.expect(std.mem.startsWith(u8, issued.tokenSlice(), session_token_prefix));

    var account_out: [account_max]u8 = undefined;
    const account = services.validateSessionToken("ALICE", issued.tokenSlice(), 1001, &account_out) orelse return error.ExpectedValidToken;
    try std.testing.expectEqualStrings("alice", account);
    try std.testing.expect(services.validateSessionToken("bob", issued.tokenSlice(), 1001, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", "sst_ffffffffffffffffffffffffffffffff", 1001, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", issued.tokenSlice(), issued.expires_unix, &account_out) == null);
}

test "session token validation refuses orphan records after rotation and revocation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-session-token-orphan.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    const old = try services.issueSessionToken("alice", 1000);
    var digest: [hash_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(old.tokenSlice(), &digest, .{});
    const old_hash = std.fmt.bytesToHex(digest, .lower);
    var old_key_buf: [session_token_key_max]u8 = undefined;
    const old_key = sessionTokenKey(&old_key_buf, &old_hash) orelse return error.BufferTooSmall;
    const old_record = try std.testing.allocator.dupe(u8, store.family(.props).get(old_key).?);
    defer std.testing.allocator.free(old_record);
    const current = try services.issueSessionToken("alice", 1001);
    // Recreate exactly the row a failed physical deletion would leave behind.
    try store.family(.props).put(old_key, old_record);
    var account_out: [account_max]u8 = undefined;
    try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", current.tokenSlice(), 1002, &account_out) != null);
    var account_key_buf: [session_token_account_key_max]u8 = undefined;
    const account_key = sessionTokenAccountKey(&account_key_buf, "alice") orelse return error.BufferTooSmall;
    try store.family(.props).delete(account_key);
    try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &account_out) == null);
    try std.testing.expect(services.validateSessionToken("alice", current.tokenSlice(), 1002, &account_out) == null);
    try store.family(.props).put(account_key, "malformed");
    try std.testing.expect(services.validateSessionToken("alice", current.tokenSlice(), 1002, &account_out) == null);
}

test "account TOTP secret: put/get/delete persist across reopen; case-insensitive" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const secret_b32 = "MZXW6YTBOI======";

    {
        var store = try openTestStore(tmp, "services-accttotp.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(!services.totpEnrolled("kain"));
        try services.totpSecretPut("kain", secret_b32);
        try std.testing.expect(services.totpEnrolled("KAIN")); // case-insensitive key
    }
    {
        var store = try openTestStore(tmp, "services-accttotp.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        // Secret survives a cold reopen and is readable by the verifier.
        var buf: [Services.totp_secret_max]u8 = undefined;
        try std.testing.expectEqualStrings(secret_b32, services.totpSecretGet("kain", &buf).?);
        // Disable removes it.
        try services.totpSecretDelete("KAIN");
        try std.testing.expect(!services.totpEnrolled("kain"));
        try std.testing.expect(services.totpSecretGet("kain", &buf) == null);
    }
}
