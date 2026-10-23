// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mfa.

const std = @import("std");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const account_max = @import("records.zig").account_max;
const ServiceError = @import("records.zig").ServiceError;
const session_token_account_key_max = @import("records.zig").session_token_account_key_max;
const sessionTokenAccountKey = @import("records.zig").sessionTokenAccountKey;
const accountKey = @import("records.zig").accountKey;
const totp_secret_max = @import("contracts.zig").totp_secret_max;
const totp_prefix = @import("contracts.zig").totp_prefix;
const totp_key_max = @import("contracts.zig").totp_key_max;
const recovery_code_count = @import("contracts.zig").recovery_code_count;
const recovery_digest_len = @import("contracts.zig").recovery_digest_len;
const rcd_prefix = @import("contracts.zig").rcd_prefix;
const rcd_key_max = @import("contracts.zig").rcd_key_max;
const rcd_blob_max = @import("contracts.zig").rcd_blob_max;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,

    pub fn totpKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < totp_prefix.len + account.len) return null;
        @memcpy(buf[0..totp_prefix.len], totp_prefix);
        for (account, 0..) |c, i| buf[totp_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. totp_prefix.len + account.len];
    }

    /// Persist the active TOTP policy and revoke every SASL token minted under
    /// its predecessor in one synced record. All allocations precede that cut;
    /// preparation failures leave the old policy and token authority unchanged.
    /// Ambiguous writes poison authentication until cold WAL replay resolves
    /// which complete policy crossed the durability boundary.
    pub fn totpPolicyCommit(self: Context, account: []const u8, secret_b32: ?[]const u8) ServiceError!void {
        if (secret_b32) |secret| {
            if (secret.len == 0 or secret.len > totp_secret_max) return error.InvalidValue;
        }
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        const canonical = try accountKey(account);
        var totp_key_buf: [totp_key_max]u8 = undefined;
        const totp_key = totpKey(&totp_key_buf, canonical.asSlice()) orelse return error.BufferTooSmall;
        var token_account_key_buf: [session_token_account_key_max]u8 = undefined;
        const token_account_key = sessionTokenAccountKey(&token_account_key_buf, canonical.asSlice()) orelse return error.BufferTooSmall;
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .props, .kind = if (secret_b32 == null) .delete else .put, .key = totp_key, .value = secret_b32 },
            .{ .family = .props, .kind = .delete, .key = token_account_key },
        });
        defer prepared.abort();
        try prepared.commit();
    }

    /// Persist the active secret and atomically invalidate prior SASL tokens.
    pub fn totpSecretPut(self: Context, account: []const u8, secret_b32: []const u8) ServiceError!void {
        try self.totpPolicyCommit(account, secret_b32);
    }

    /// Copy the account's persisted TOTP secret into `out`, or null when none is
    /// stored (or it does not fit `out`). The returned slice aliases `out`.
    pub fn totpSecretGet(self: Context, account: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return null;
        const v = self.store.*.family(.props).get(k) orelse return null;
        if (v.len == 0 or v.len > out.len) return null;
        @memcpy(out[0..v.len], v);
        return out[0..v.len];
    }

    /// Remove the account's persisted TOTP secret (disable 2FA). Idempotent.
    pub fn totpSecretDelete(self: Context, account: []const u8) ServiceError!void {
        try self.totpPolicyCommit(account, null);
    }

    /// True when the account has a persisted (active) TOTP secret.
    pub fn totpEnrolled(self: Context, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return false;
        return self.store.*.family(.props).get(k) != null;
    }

    pub fn rcdKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < rcd_prefix.len + account.len) return null;
        @memcpy(buf[0..rcd_prefix.len], rcd_prefix);
        for (account, 0..) |c, i| buf[rcd_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. rcd_prefix.len + account.len];
    }

    pub fn hashRecoveryCode(out: *[recovery_digest_len]u8, account: []const u8, code: []const u8) void {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("onyx-recovery-v1|");
        // Domain-separate by account so a leaked digest cannot be replayed across accounts.
        var acc_l: [account_max]u8 = undefined;
        const n = @min(account.len, account_max);
        for (account[0..n], 0..) |c, i| acc_l[i] = std.ascii.toLower(c);
        h.update(acc_l[0..n]);
        h.update("|");
        h.update(code);
        h.final(out);
    }

    /// How many unused recovery codes remain (0 if none stored).
    pub fn recoveryCodesRemaining(self: Context, account: []const u8) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return 0;
        const v = self.store.*.family(.props).get(k) orelse return 0;
        if (v.len % recovery_digest_len != 0) return 0;
        return v.len / recovery_digest_len;
    }

    /// Replace all recovery codes for `account` with `codes` (plaintext). Stores only digests.
    pub fn recoveryCodesReplace(self: Context, account: []const u8, codes: []const []const u8) ServiceError!void {
        if (codes.len == 0 or codes.len > recovery_code_count) return error.InvalidRecord;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return error.NotFound;
        var blob: [rcd_blob_max]u8 = undefined;
        var offset: usize = 0;
        for (codes) |code| {
            if (code.len == 0 or code.len > 64) return error.InvalidRecord;
            var dig: [recovery_digest_len]u8 = undefined;
            hashRecoveryCode(&dig, account, code);
            @memcpy(blob[offset .. offset + recovery_digest_len], &dig);
            offset += recovery_digest_len;
        }
        try self.store.*.family(.props).put(k, blob[0..offset]);
    }

    /// Delete all recovery codes for `account` (idempotent).
    pub fn recoveryCodesClear(self: Context, account: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return;
        try self.store.*.family(.props).delete(k);
    }

    /// Consume one matching recovery code (constant-time scan). On success the
    /// digest is removed from the blob. Returns AuthFailed when none match.
    pub fn recoveryCodeConsume(self: Context, account: []const u8, code: []const u8) ServiceError!void {
        if (code.len == 0 or code.len > 64) return error.AuthFailed;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return error.NotFound;
        const v = self.store.*.family(.props).get(k) orelse return error.AuthFailed;
        if (v.len == 0 or v.len % recovery_digest_len != 0) return error.AuthFailed;
        var want: [recovery_digest_len]u8 = undefined;
        hashRecoveryCode(&want, account, code);
        var match_i: ?usize = null;
        var i: usize = 0;
        while (i < v.len) : (i += recovery_digest_len) {
            var dig: [recovery_digest_len]u8 = undefined;
            @memcpy(&dig, v[i .. i + recovery_digest_len]);
            if (std.crypto.timing_safe.eql([recovery_digest_len]u8, dig, want)) {
                // Prefer first match; keep scanning for constant-ish work.
                if (match_i == null) match_i = i;
            }
        }
        const hit = match_i orelse return error.AuthFailed;
        // Rewrite blob without the consumed digest.
        var new_blob: [rcd_blob_max]u8 = undefined;
        var w: usize = 0;
        i = 0;
        while (i < v.len) : (i += recovery_digest_len) {
            if (i == hit) continue;
            @memcpy(new_blob[w .. w + recovery_digest_len], v[i .. i + recovery_digest_len]);
            w += recovery_digest_len;
        }
        if (w == 0) {
            try self.store.*.family(.props).delete(k);
        } else {
            try self.store.*.family(.props).put(k, new_blob[0..w]);
        }
    }
};
