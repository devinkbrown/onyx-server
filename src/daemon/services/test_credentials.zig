// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credentials regression tests.

const std = @import("std");
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const WebauthnCredential = @import("contracts.zig").WebauthnCredential;
const certfp_bind_mod = @import("../certfp_bind.zig");
const webauthn_creds = @import("../webauthn_creds.zig");
const WebauthnListEntry = @import("contracts.zig").WebauthnListEntry;

test "certfp binding persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fp = &@as([64]u8, @splat('a')); // 64-hex placeholder fingerprint

    {
        var store = try openTestStore(tmp, "services-certfp.wal");
        defer store.deinit();
        var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
        defer binds.deinit();
        var services = Services.init(&store, null);
        services.attachCertfpBinds(&binds);
        try services.bindCertfp("alice", fp);
        try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);
    }
    {
        // Reopen with a COLD in-memory cache: the binding must come from the
        // durable store via the lazy fallback.
        var store = try openTestStore(tmp, "services-certfp.wal");
        defer store.deinit();
        var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
        defer binds.deinit();
        var services = Services.init(&store, null);
        services.attachCertfpBinds(&binds);
        try std.testing.expectEqualStrings("alice", services.accountForCertfp(fp).?);
        // An unknown fingerprint still returns null.
        try std.testing.expect(services.accountForCertfp(&@as([64]u8, @splat('b'))) == null);
    }
}

test "certfp list and delete enforce account ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fp_alice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const fp_bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    var store = try openTestStore(tmp, "services-certfp-list.wal");
    defer store.deinit();
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    var services = Services.init(&store, null);
    services.attachCertfpBinds(&binds);

    try services.bindCertfp("alice", fp_alice);
    try services.bindCertfp("bob", fp_bob);

    var listed_buf: [4][]const u8 = undefined;
    var listed = try services.listCertfps("alice", listed_buf[0..]);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings(fp_alice, listed[0]);

    try std.testing.expectError(error.Forbidden, services.deleteCertfp("alice", fp_bob));
    try services.deleteCertfp("alice", fp_alice);
    listed = try services.listCertfps("alice", listed_buf[0..]);
    try std.testing.expectEqual(@as(usize, 0), listed.len);
    try std.testing.expect(services.accountForCertfp(fp_alice) == null);
}

test "webauthn bind/lookup/list/delete round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-webauthn.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 }; // arbitrary COSE-ish bytes
    try services.webauthnBind("alice", "credAAA", &cose, 5, "phone", 1_700_000_000);

    // Lookup by id copies out account + COSE key + counter + label.
    var cred: Services.WebauthnCredential = .{};
    try services.webauthnLookup("credAAA", &cred);
    try std.testing.expectEqualStrings("alice", cred.account());
    try std.testing.expectEqual(@as(u32, 5), cred.sign_count);
    try std.testing.expectEqualSlices(u8, &cose, cred.coseKey());
    try std.testing.expectEqualStrings("phone", cred.label());

    // Duplicate id is rejected.
    try std.testing.expectError(error.AlreadyExists, services.webauthnBind("alice", "credAAA", &cose, 1, "dup", 1));

    // A second credential lists both.
    try services.webauthnBind("alice", "credBBB", &cose, 0, "laptop", 1_700_000_100);
    var entries: [8]Services.WebauthnListEntry = undefined;
    const listed = try services.webauthnList("alice", entries[0..]);
    try std.testing.expectEqual(@as(usize, 2), listed.len);

    // Update the counter (monotonic caller-enforced) and read it back.
    try services.webauthnUpdateSignCount("credAAA", 9);
    try services.webauthnLookup("credAAA", &cred);
    try std.testing.expectEqual(@as(u32, 9), cred.sign_count);

    // Delete by label; the other credential survives.
    try services.webauthnDelete("alice", "laptop");
    try std.testing.expectError(error.NotFound, services.webauthnLookup("credBBB", &cred));
    const after = try services.webauthnList("alice", entries[0..]);
    try std.testing.expectEqual(@as(usize, 1), after.len);
    try std.testing.expectEqualStrings("credAAA", after[0].credId());

    // Delete by id.
    try services.webauthnDelete("alice", "credAAA");
    try std.testing.expectError(error.NotFound, services.webauthnLookup("credAAA", &cred));
    const empty = try services.webauthnList("alice", entries[0..]);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "webauthn rename relabels, preserves fields, and enforces ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-webauthn-rename.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };
    try services.webauthnBind("alice", "credAAA", &cose, 5, "phone", 1_700_000_000);

    // Rename preserves sign_count, created_unix, and the COSE key verbatim.
    try services.webauthnRename("alice", "credAAA", "work-laptop");
    var cred: Services.WebauthnCredential = .{};
    try services.webauthnLookup("credAAA", &cred);
    try std.testing.expectEqualStrings("work-laptop", cred.label());
    try std.testing.expectEqual(@as(u32, 5), cred.sign_count);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), cred.created_unix);
    try std.testing.expectEqualSlices(u8, &cose, cred.coseKey());

    // An unbound id is NotFound; a foreign owner is Forbidden (no relabel).
    try std.testing.expectError(error.NotFound, services.webauthnRename("alice", "credZZZ", "ghost"));
    try services.webauthnBind("bob", "credBBB", &cose, 0, "bob-key", 1_700_000_100);
    try std.testing.expectError(error.Forbidden, services.webauthnRename("alice", "credBBB", "steal"));
    try services.webauthnLookup("credBBB", &cred);
    try std.testing.expectEqualStrings("bob-key", cred.label());
}

// FIX 2 premise: AUTH-FINISH logs in via `finishLogin(cred.account())`, not the
// client-echoed AUTH argument. This proves cred.account() is the CANONICAL,
// lowercased stored owner even when the credential was bound (and later named at
// AUTH time) with a different case, and that the case-insensitive binding gate
// still admits the case-variant client argument.
test "WEBAUTHN AUTH-FINISH: cred.account() is the canonical lowercased owner, not the client case-variant" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-webauthn-canonical.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };
    // Bind with a mixed-case account; the store lowercases it at bind time.
    try services.webauthnBind("MixedCase", "credCANON", &cose, 1, "phone", 1_700_000_000);

    var cred: Services.WebauthnCredential = .{};
    try services.webauthnLookup("credCANON", &cred);
    // The value finishLogin now receives is the canonical lowercase owner.
    try std.testing.expectEqualStrings("mixedcase", cred.account());

    // A different-CASE AUTH argument still passes the eqlIgnoreCase binding gate,
    // so login proceeds — but as the canonical owner, never the client string.
    const client_auth_arg = "MIXEDCASE";
    try std.testing.expect(std.ascii.eqlIgnoreCase(cred.account(), client_auth_arg));
    try std.testing.expect(!std.mem.eql(u8, cred.account(), client_auth_arg));

    // A genuinely different account fails the binding gate (credential mismatch).
    try std.testing.expect(!std.ascii.eqlIgnoreCase(cred.account(), "eve"));
}

test "webauthn credential persists across a store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cose = [_]u8{ 0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06 };

    {
        var store = try openTestStore(tmp, "services-webauthn-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.webauthnBind("bob", "credPERSIST", &cose, 3, "yubikey", 1_700_000_200);
    }

    // Reopen from the WAL: the credential must be recoverable.
    var store = try openTestStore(tmp, "services-webauthn-persist.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var cred: Services.WebauthnCredential = .{};
    try services.webauthnLookup("credPERSIST", &cred);
    try std.testing.expectEqualStrings("bob", cred.account());
    try std.testing.expectEqual(@as(u32, 3), cred.sign_count);
    try std.testing.expectEqualSlices(u8, &cose, cred.coseKey());
    try std.testing.expectEqualStrings("yubikey", cred.label());

    var entries: [4]Services.WebauthnListEntry = undefined;
    const listed = try services.webauthnList("bob", entries[0..]);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("credPERSIST", listed[0].credId());
}

test "webauthn delete enforces account ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-webauthn-own.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };

    try services.webauthnBind("alice", "credA", &cose, 0, "", 1);
    try services.webauthnBind("bob", "credB", &cose, 0, "", 1);

    // alice cannot delete bob's credential id (not in her list → NotFound).
    try std.testing.expectError(error.NotFound, services.webauthnDelete("alice", "credB"));
    // bob's credential is intact.
    var cred: Services.WebauthnCredential = .{};
    try services.webauthnLookup("credB", &cred);
    try std.testing.expectEqualStrings("bob", cred.account());
}

test "webauthn bind fail-closed on malformed id / oversized key" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-webauthn-bad.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    const cose = [_]u8{ 0xa5, 0x01 };

    try std.testing.expectError(error.InvalidValue, services.webauthnBind("alice", "bad/id", &cose, 0, "", 1)); // '/' not url-safe
    try std.testing.expectError(error.InvalidValue, services.webauthnBind("alice", "", &cose, 0, "", 1)); // empty id
    var big: [webauthn_creds.max_cose_key_bytes + 1]u8 = @splat(0);
    try std.testing.expectError(error.InvalidValue, services.webauthnBind("alice", "credX", &big, 0, "", 1)); // oversized key
    var lbl: [webauthn_creds.max_label_bytes + 1]u8 = @splat('x');
    try std.testing.expectError(error.InvalidValue, services.webauthnBind("alice", "credY", &cose, 0, &lbl, 1)); // oversized label
}
