// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sessions.

const std = @import("std");
const store_mod = @import("../store.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const hash_len = @import("records.zig").hash_len;
const hash_hex_len = @import("records.zig").hash_hex_len;
const session_token_prefix = @import("records.zig").session_token_prefix;
const session_token_random_len = @import("records.zig").session_token_random_len;
const session_token_len = @import("records.zig").session_token_len;
const default_session_token_ttl_seconds = @import("records.zig").default_session_token_ttl_seconds;
const ServiceError = @import("records.zig").ServiceError;
const account_flag_suspended = @import("records.zig").account_flag_suspended;
const account_flag_forbidden = @import("records.zig").account_flag_forbidden;
const account_flag_passkey_only = @import("records.zig").account_flag_passkey_only;
const SessionTokenIssue = @import("records.zig").SessionTokenIssue;
const session_token_key_max = @import("records.zig").session_token_key_max;
const session_token_account_key_max = @import("records.zig").session_token_account_key_max;
const session_token_value_max = @import("records.zig").session_token_value_max;
const secureZero = @import("records.zig").secureZero;
const sessionTokenKey = @import("records.zig").sessionTokenKey;
const sessionTokenAccountKey = @import("records.zig").sessionTokenAccountKey;
const encodeSessionTokenRecord = @import("records.zig").encodeSessionTokenRecord;
const decodeSessionTokenRecord = @import("records.zig").decodeSessionTokenRecord;
const validSessionTokenText = @import("records.zig").validSessionTokenText;
const accountKey = @import("records.zig").accountKey;
const decodeAccount = @import("records.zig").decodeAccount;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,

    /// Issue a durable SASL SESSION-TOKEN for an already-authenticated services
    /// account. The raw token is returned once to the caller; only SHA-256(token)
    /// and expiry metadata are stored.
    pub fn issueSessionToken(self: Context, account: []const u8, now_unix: i64) ServiceError!SessionTokenIssue {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        const key = try accountKey(account);
        const value = self.store.*.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        const record = try decodeAccount(value);
        if ((record.flags & account_flag_suspended) != 0 or (record.flags & account_flag_forbidden) != 0) return error.AuthFailed;
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;

        var token: [session_token_len]u8 = undefined;
        defer secureZero(&token);
        @memcpy(token[0..session_token_prefix.len], session_token_prefix);
        var random: [session_token_random_len]u8 = undefined;
        self.store.*.io.randomSecure(&random) catch return error.RandomUnavailable;
        var random_hex = std.fmt.bytesToHex(random, .lower);
        @memcpy(token[session_token_prefix.len..], &random_hex);
        secureZero(random[0..]);
        secureZero(random_hex[0..]);

        var digest: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token, &digest, .{});
        defer secureZero(digest[0..]);
        var hash_hex = std.fmt.bytesToHex(digest, .lower);
        defer secureZero(hash_hex[0..]);

        var acct_key_buf: [session_token_account_key_max]u8 = undefined;
        const acct_key = sessionTokenAccountKey(&acct_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const expires_unix = std.math.add(i64, now_unix, default_session_token_ttl_seconds) catch return error.InvalidValue;
        var value_buf: [session_token_value_max]u8 = undefined;
        const encoded = try encodeSessionTokenRecord(record.name.asSlice(), expires_unix, hash_hex[0..], &value_buf);
        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return error.BufferTooSmall;
        var mutations: [3]store_mod.BatchMutation = undefined;
        mutations[0] = .{ .family = .props, .kind = .put, .key = token_key, .value = encoded };
        mutations[1] = .{ .family = .props, .kind = .put, .key = acct_key, .value = hash_hex[0..] };
        var mutation_count: usize = 2;
        var old_token_key_buf: [session_token_key_max]u8 = undefined;
        if (self.store.*.family(.props).get(acct_key)) |old_hash| {
            if (old_hash.len == hash_hex_len and !std.mem.eql(u8, old_hash, &hash_hex)) {
                const old_token_key = sessionTokenKey(&old_token_key_buf, old_hash) orelse return error.BufferTooSmall;
                mutations[2] = .{ .family = .props, .kind = .delete, .key = old_token_key };
                mutation_count = 3;
            }
        }
        var prepared = try self.store.*.prepareBatch(mutations[0..mutation_count]);
        defer prepared.abort();
        try prepared.commit();

        return .{
            .account = record.name,
            .token = token,
            .expires_unix = expires_unix,
        };
    }

    /// Validate SASL SESSION-TOKEN credentials. `authcid` must be the account
    /// name bound to the token, and `account_out` receives the canonical account
    /// on success. Returns null for malformed, expired, missing, suspended, or
    /// mismatched tokens.
    pub fn validateSessionToken(
        self: Context,
        authcid: []const u8,
        token: []const u8,
        now_unix: i64,
        account_out: []u8,
    ) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return null;

        const key = accountKey(authcid) catch return null;
        if (!validSessionTokenText(token)) return null;

        var digest: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        defer secureZero(digest[0..]);
        var hash_hex = std.fmt.bytesToHex(digest, .lower);
        defer secureZero(hash_hex[0..]);

        // A leftover token record after rotation or revocation is not authority.
        // Require the account's current binding before accepting its credential.
        var acct_key_buf: [session_token_account_key_max]u8 = undefined;
        const acct_key = sessionTokenAccountKey(&acct_key_buf, key.asSlice()) orelse return null;
        const current_hash = self.store.*.family(.props).get(acct_key) orelse return null;
        if (current_hash.len != hash_hex_len) return null;
        var bound_hash: [hash_hex_len]u8 = undefined;
        @memcpy(&bound_hash, current_hash);
        defer secureZero(bound_hash[0..]);
        if (!std.crypto.timing_safe.eql([hash_hex_len]u8, bound_hash, hash_hex)) return null;

        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return null;
        const encoded = self.store.*.family(.props).get(token_key) orelse return null;
        const record = decodeSessionTokenRecord(encoded) catch return null;
        if (record.expires_unix <= now_unix) return null;
        if (!std.mem.eql(u8, record.account.asSlice(), key.asSlice())) return null;

        var stored_hash: [hash_hex_len]u8 = undefined;
        if (record.hash.len != stored_hash.len) return null;
        @memcpy(&stored_hash, record.hash);
        defer secureZero(stored_hash[0..]);
        const hash_ok = std.crypto.timing_safe.eql([hash_hex_len]u8, stored_hash, hash_hex);
        if (!hash_ok) return null;

        const acct_value = self.store.*.family(.accounts).get(key.asSlice()) orelse return null;
        const acct_record = decodeAccount(acct_value) catch return null;
        if ((acct_record.flags & account_flag_suspended) != 0 or (acct_record.flags & account_flag_forbidden) != 0) return null;
        if ((acct_record.flags & account_flag_passkey_only) != 0) return null;
        if (acct_record.name.asSlice().len > account_out.len) return null;
        @memcpy(account_out[0..acct_record.name.asSlice().len], acct_record.name.asSlice());
        return account_out[0..acct_record.name.asSlice().len];
    }

    /// Revoke any active SASL session token for `account`. A session token is a
    /// password-equivalent re-entry credential, so it must not outlive a change
    /// to the account's second factor — call this when TOTP is enabled or
    /// disabled so a token minted under the old policy cannot bypass the new one.
    /// The account binding is the sole authority; orphan hash rows cannot
    /// authenticate. Revocation is synced, fallible, and idempotent.
    pub fn revokeSessionTokens(self: Context, account: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        const key = try accountKey(account);
        var acct_key_buf: [session_token_account_key_max]u8 = undefined;
        const acct_key = sessionTokenAccountKey(&acct_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(acct_key) == null) return;
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .props, .kind = .delete, .key = acct_key },
        });
        defer prepared.abort();
        try prepared.commit();
    }
};
