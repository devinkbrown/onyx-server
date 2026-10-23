// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credentials.

const std = @import("std");
const certfp_bind_mod = @import("../certfp_bind.zig");
const webauthn_creds = @import("../webauthn_creds.zig");
const key_transparency = @import("../key_transparency.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const ServiceError = @import("records.zig").ServiceError;
const account_flag_passkey_only = @import("records.zig").account_flag_passkey_only;
const account_flag_oper_stepup = @import("records.zig").account_flag_oper_stepup;
const account_flags_sticky = @import("records.zig").account_flags_sticky;
const AccountRecord = @import("records.zig").AccountRecord;
const certfp_key_max = @import("records.zig").certfp_key_max;
const certfp_account_key_max = @import("records.zig").certfp_account_key_max;
const certfp_list_value_max = @import("records.zig").certfp_list_value_max;
const session_token_account_key_max = @import("records.zig").session_token_account_key_max;
const certfpKey = @import("records.zig").certfpKey;
const certfpAccountKey = @import("records.zig").certfpAccountKey;
const sessionTokenAccountKey = @import("records.zig").sessionTokenAccountKey;
const accountKey = @import("records.zig").accountKey;
const encodeAccount = @import("records.zig").encodeAccount;
const WebauthnCredential = @import("contracts.zig").WebauthnCredential;
const WebauthnListEntry = @import("contracts.zig").WebauthnListEntry;
const key_transparency_domain = @import("key_transparency.zig");
const persistence_domain = @import("persistence.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    certfp_binds: *const ?*certfp_bind_mod.CertfpBindStore,
    key_transparency: *const ?*key_transparency.KeyTransparencyLog,

    /// Bind a TLS certfp to an account (the CERTADD command). Caller has verified
    /// the account is the caller's own logged-in account.
    pub fn bindCertfp(self: Context, account: []const u8, fingerprint: []const u8) certfp_bind_mod.CertfpBindError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const binds = self.certfp_binds.* orelse return error.InvalidFingerprint;
        try binds.bind(account, fingerprint);
        // Mirror the binding into the durable store, keyed by fingerprint, so it
        // survives a restart. In-memory is authoritative for this session; the
        // store is a best-effort durable mirror (a WAL hiccup must not fail the
        // already-applied in-memory bind).
        var kb: [certfp_key_max]u8 = undefined;
        if (certfpKey(&kb, fingerprint)) |k| {
            self.store.*.family(.props).put(k, account) catch {};
        }
        self.addCertfpListEntry(account, fingerprint) catch {};
        self.recordKeyTransparency(account, .certfp, .bind, fingerprint, fingerprint, 0);
    }

    /// List certfps bound to `account` by CERTADD. Output slices borrow durable
    /// store memory and remain valid until the next mutation.
    pub fn listCertfps(self: Context, account: []const u8, out: [][]const u8) ServiceError![]const []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const value = self.store.*.family(.props).get(list_key) orelse return out[0..0];
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, value, '\n');
        while (it.next()) |fp| {
            if (fp.len == 0) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = fp;
            count += 1;
        }
        return out[0..count];
    }

    /// Remove a certfp from `account`. Returns NotFound when the fingerprint is
    /// unbound, and Forbidden when another account owns it.
    pub fn deleteCertfp(self: Context, account: []const u8, fingerprint: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(account);
        const owner = try self.certfpOwnerUnlocked(fingerprint);
        if (!std.ascii.eqlIgnoreCase(owner, key.asSlice())) return error.Forbidden;

        if (self.certfp_binds.*) |binds| _ = binds.unbind(fingerprint);
        var fp_key_buf: [certfp_key_max]u8 = undefined;
        if (certfpKey(&fp_key_buf, fingerprint)) |fp_key| self.store.*.family(.props).delete(fp_key) catch {};
        try self.removeCertfpListEntry(key.asSlice(), fingerprint);
        self.recordKeyTransparency(key.asSlice(), .certfp, .delete, fingerprint, fingerprint, 0);
    }

    /// Bind a passkey credential to `account`. `cose_key` is the raw COSE_Key
    /// CBOR public key extracted from the registration authData. Fail-closed:
    /// rejects a malformed/oversized id or key, a duplicate id (already bound to
    /// any account), and enforces the per-account credential cap. Writes are
    /// ordered so a failure leaves no half-bound state (record rolled back if the
    /// list update fails).
    pub fn webauthnBind(
        self: Context,
        account: []const u8,
        cred_id_b64: []const u8,
        cose_key: []const u8,
        sign_count: u32,
        label: []const u8,
        now_unix: i64,
    ) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.InvalidValue;
        if (cose_key.len == 0 or cose_key.len > webauthn_creds.max_cose_key_bytes) return error.InvalidValue;
        if (!webauthn_creds.validLabel(label)) return error.InvalidValue;
        const key = try accountKey(account); // validates + lowercases

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(cred_key) != null) return error.AlreadyExists;

        // Encode label + cose key to base64url (delimiter-safe record fields).
        var label_b64_buf: [webauthn_creds.max_cose_key_bytes]u8 = undefined;
        const label_b64 = std.base64.url_safe_no_pad.Encoder.encode(label_b64_buf[0..std.base64.url_safe_no_pad.Encoder.calcSize(label.len)], label);
        var cose_b64_buf: [webauthn_creds.max_cose_key_bytes * 2]u8 = undefined;
        const cose_b64 = std.base64.url_safe_no_pad.Encoder.encode(cose_b64_buf[0..std.base64.url_safe_no_pad.Encoder.calcSize(cose_key.len)], cose_key);

        var rec_buf: [webauthn_creds.record_value_max]u8 = undefined;
        const record = webauthn_creds.encodeRecord(key.asSlice(), sign_count, now_unix, label_b64, cose_b64, &rec_buf) catch
            return error.BufferTooSmall;

        // Compute the new account list first so a cap/overflow failure aborts
        // BEFORE the record is written (no orphaned record).
        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const existing = self.store.*.family(.props).get(list_key) orelse "";
        var new_list_buf: [webauthn_creds.account_list_value_max]u8 = undefined;
        const new_list = (webauthn_creds.listAppend(existing, cred_id_b64, &new_list_buf) catch |e| switch (e) {
            error.ListFull => return error.AlreadyExists,
            else => return error.BufferTooSmall,
        }) orelse return error.AlreadyExists; // already present under this account

        // Record first, then list; roll the record back if the list write fails.
        try self.store.*.family(.props).put(cred_key, record);
        self.store.*.family(.props).put(list_key, new_list) catch |e| {
            self.store.*.family(.props).delete(cred_key) catch {};
            return e;
        };
        self.recordKeyTransparency(key.asSlice(), .webauthn, .bind, cred_id_b64, cose_key, now_unix * 1000);
    }

    /// Look up a credential by id, copying its account, COSE key, counter, and
    /// label out under the lock. Returns `NotFound` when unbound.
    pub fn webauthnLookup(self: Context, cred_id_b64: []const u8, out: *WebauthnCredential) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.NotFound;

        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.*.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;

        if (rec.account.len > out.account_buf.len) return error.InvalidRecord;
        @memcpy(out.account_buf[0..rec.account.len], rec.account);
        out.account_len = rec.account.len;
        out.sign_count = rec.sign_count;
        out.created_unix = rec.created_unix;
        const cose = rec.decodeCoseKey(&out.cose_key_buf) catch return error.InvalidRecord;
        out.cose_key_len = cose.len;
        const lbl = rec.decodeLabel(&out.label_buf) catch return error.InvalidRecord;
        out.label_len = lbl.len;
    }

    /// Persist a new (monotonically greater) signature counter for a credential.
    /// Caller has already enforced the monotonic check; this only rewrites the
    /// record. A missing record is `NotFound`.
    pub fn webauthnUpdateSignCount(self: Context, cred_id_b64: []const u8, new_count: u32) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.NotFound;

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.*.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;
        // Re-encode with the new counter, preserving every other field verbatim.
        var rec_buf: [webauthn_creds.record_value_max]u8 = undefined;
        const record = webauthn_creds.encodeRecord(rec.account, new_count, rec.created_unix, rec.label_b64, rec.cose_key_b64, &rec_buf) catch
            return error.BufferTooSmall;
        try self.store.*.family(.props).put(cred_key, record);
    }

    /// Update the user label of a passkey the caller owns, identified by
    /// credential id. Fail-closed: `NotFound` when the id is unbound, `Forbidden`
    /// when it resolves to a different account, `InvalidValue` on a malformed id
    /// or an over-long label. Every other record field is preserved verbatim.
    pub fn webauthnRename(self: Context, account: []const u8, cred_id_b64: []const u8, label: []const u8) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.InvalidValue;
        if (!webauthn_creds.validLabel(label)) return error.InvalidValue;
        const key = try accountKey(account); // validates + lowercases

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.*.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;
        if (!std.ascii.eqlIgnoreCase(rec.account, key.asSlice())) return error.Forbidden;

        // Encode the new label (base64url, delimiter-safe) and re-encode the
        // record, preserving every other field. `encodeRecord` copies rec's
        // borrowed fields into `rec_buf` BEFORE the put, so the borrow into the
        // store value never dangles across the write (matches webauthnUpdateSignCount).
        var label_b64_buf: [webauthn_creds.max_label_b64]u8 = undefined;
        const label_b64 = std.base64.url_safe_no_pad.Encoder.encode(label_b64_buf[0..std.base64.url_safe_no_pad.Encoder.calcSize(label.len)], label);
        var rec_buf: [webauthn_creds.record_value_max]u8 = undefined;
        const record = webauthn_creds.encodeRecord(rec.account, rec.sign_count, rec.created_unix, label_b64, rec.cose_key_b64, &rec_buf) catch
            return error.BufferTooSmall;
        try self.store.*.family(.props).put(cred_key, record);
    }

    /// List the passkeys bound to `account` into `out`, returning the populated
    /// prefix. Silently skips any list entry whose record is missing/corrupt.
    pub fn webauthnList(self: Context, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        const key = try accountKey(account);

        self.lock.lockShared();
        defer self.lock.unlockShared();

        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const list = self.store.*.family(.props).get(list_key) orelse return out[0..0];

        var ids_buf: [webauthn_creds.max_creds_per_account][]const u8 = undefined;
        const ids = webauthn_creds.listIds(list, &ids_buf);
        var n: usize = 0;
        for (ids) |id| {
            if (n >= out.len) break;
            if (id.len > out[n].cred_id_buf.len) continue;
            var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
            const cred_key = webauthn_creds.credKey(&cred_key_buf, id) orelse continue;
            const value = self.store.*.family(.props).get(cred_key) orelse continue;
            const rec = webauthn_creds.decodeRecord(value) catch continue;
            @memcpy(out[n].cred_id_buf[0..id.len], id);
            out[n].cred_id_len = id.len;
            const lbl = rec.decodeLabel(&out[n].label_buf) catch out[n].label_buf[0..0];
            out[n].label_len = lbl.len;
            out[n].sign_count = rec.sign_count;
            out[n].created_unix = rec.created_unix;
            n += 1;
        }
        return out[0..n];
    }

    /// The credential ids bound to `account`, copied into `out` (each entry's
    /// `credId()` is valid after the lock releases). Used to build the AUTH
    /// challenge's allow-list.
    pub fn webauthnCredIds(self: Context, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        return self.webauthnList(account, out);
    }

    /// Delete a credential from `account`, identified by its credential id OR its
    /// label. Verifies ownership. `NotFound` when no matching credential exists;
    /// `Forbidden` when the id resolves to a different account.
    pub fn webauthnDelete(self: Context, account: []const u8, id_or_label: []const u8) ServiceError!void {
        const key = try accountKey(account);

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        // Resolve the target credential id: try a direct id match, else scan the
        // account's list for a label match.
        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const list = self.store.*.family(.props).get(list_key) orelse return error.NotFound;

        var target_buf: [webauthn_creds.max_cred_id_b64]u8 = undefined;
        var target_len: usize = 0;
        var ids_buf: [webauthn_creds.max_creds_per_account][]const u8 = undefined;
        const ids = webauthn_creds.listIds(list, &ids_buf);
        for (ids) |id| {
            if (std.mem.eql(u8, id, id_or_label)) {
                @memcpy(target_buf[0..id.len], id);
                target_len = id.len;
                break;
            }
        }
        if (target_len == 0) {
            // Label match: decode each record's label and compare.
            for (ids) |id| {
                var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
                const cred_key = webauthn_creds.credKey(&cred_key_buf, id) orelse continue;
                const value = self.store.*.family(.props).get(cred_key) orelse continue;
                const rec = webauthn_creds.decodeRecord(value) catch continue;
                var lbl_buf: [webauthn_creds.max_label_bytes]u8 = undefined;
                const lbl = rec.decodeLabel(&lbl_buf) catch continue;
                if (lbl.len != 0 and std.mem.eql(u8, lbl, id_or_label)) {
                    @memcpy(target_buf[0..id.len], id);
                    target_len = id.len;
                    break;
                }
            }
        }
        if (target_len == 0) return error.NotFound;
        const target = target_buf[0..target_len];

        // Ownership: the record must belong to this account.
        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, target) orelse return error.NotFound;
        const value = self.store.*.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;
        if (!std.ascii.eqlIgnoreCase(rec.account, key.asSlice())) return error.Forbidden;
        var cose_key_buf: [webauthn_creds.max_cose_key_bytes]u8 = undefined;
        const cose_key = rec.decodeCoseKey(&cose_key_buf) catch return error.InvalidRecord;

        // A passkey-only account must keep one credential. Removing the last
        // one would leave no way in except the recovery-code password reset.
        if (ids.len <= 1) {
            const owner = self.loadAccount(key.asSlice()) catch null;
            if (owner) |record| {
                if ((record.flags & account_flag_passkey_only) != 0) return error.Forbidden;
            }
        }

        // Remove from the list, then delete the record.
        var new_list_buf: [webauthn_creds.account_list_value_max]u8 = undefined;
        const new_list = (webauthn_creds.listRemove(list, target, &new_list_buf) catch return error.BufferTooSmall) orelse
            return error.NotFound;
        if (new_list.len == 0) {
            self.store.*.family(.props).delete(list_key) catch {};
        } else {
            try self.store.*.family(.props).put(list_key, new_list);
        }
        self.store.*.family(.props).delete(cred_key) catch {};
        self.recordKeyTransparency(key.asSlice(), .webauthn, .delete, target, cose_key, 0);
    }

    /// Refuse password-derived mechanisms for `account`. Requires at least one
    /// bound passkey, so a typo in a flags field cannot lock the account out.
    /// Not reachable from ACCOUNTSET. A later ceremony calls this only after
    /// the passkey has already verified. Also arms the operator step-up latch
    /// and revokes SASL session tokens in the same durable cut: a token minted
    /// before the lock is a password-equivalent re-entry credential.
    pub fn enablePasskeyOnly(self: Context, account: []const u8, scratch: []u8) ServiceError!void {
        const key = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        if (!self.passkeysBoundUnlocked(key.asSlice())) return error.Forbidden;
        var record = try self.loadAccount(key.asSlice());
        record.flags |= account_flag_passkey_only | account_flag_oper_stepup;
        const encoded = try encodeAccount(record, scratch);
        var account_token_key_buf: [session_token_account_key_max]u8 = undefined;
        const account_token_key = sessionTokenAccountKey(&account_token_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .accounts, .kind = .put, .key = record.name.asSlice(), .value = encoded },
            .{ .family = .props, .kind = .delete, .key = account_token_key },
        });
        defer prepared.abort();
        try prepared.commit();
    }

    /// True when this account must not become a network operator on a password,
    /// SCRAM, recovery-code, or session-token session. A missing account is not
    /// latched, so an unknown name keeps the caller's ordinary not-found path.
    pub fn operStepUpRequired(self: Context, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const record = self.loadAccount(account) catch return false;
        return (record.flags & account_flags_sticky) != 0;
    }

    /// A verified passkey login retires the operator latch once password login
    /// is already allowed again. While the account is still passkey-only the
    /// latch stays, so the later recovery replacement re-arms it from that bit.
    /// A no-op when the latch is already clear.
    pub fn notePasskeyAuthentication(self: Context, account: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        var record = try self.loadAccount(account);
        if ((record.flags & account_flag_oper_stepup) == 0) return;
        if ((record.flags & account_flag_passkey_only) != 0) return;
        record.flags &= ~account_flag_oper_stepup;
        try self.saveAccount(record, scratch);
    }

    pub fn passkeysBoundUnlocked(self: Context, account: []const u8) bool {
        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, account) orelse return false;
        const list = self.store.*.family(.props).get(list_key) orelse return false;
        var ids_buf: [webauthn_creds.max_creds_per_account][]const u8 = undefined;
        const ids = webauthn_creds.listIds(list, &ids_buf);
        for (ids) |id| {
            var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
            const cred_key = webauthn_creds.credKey(&cred_key_buf, id) orelse continue;
            if (self.store.*.family(.props).get(cred_key) != null) return true;
        }
        return false;
    }

    /// The account a certfp is bound to, if any (SASL EXTERNAL verification).
    /// Falls back to the durable store when the in-memory cache is cold (e.g.
    /// immediately after a restart, before any CERTADD has repopulated it).
    pub fn accountForCertfp(self: Context, fingerprint: []const u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return null;

        return self.accountForCertfpUnlocked(fingerprint) catch null;
    }

    pub fn accountForCertfpUnlocked(self: Context, fingerprint: []const u8) ServiceError![]const u8 {
        const acct = try self.certfpOwnerUnlocked(fingerprint);
        if (try self.accountSuspendedUnlocked(acct)) return error.AuthFailed;
        // SASL EXTERNAL must honor an admin FORBID too — otherwise a certfp bound
        // before the forbid keeps logging the account in.
        if (self.accountForbiddenUnlocked(acct)) return error.AuthFailed;
        return acct;
    }

    pub fn certfpOwnerUnlocked(self: Context, fingerprint: []const u8) ServiceError![]const u8 {
        if (self.certfp_binds.*) |binds| {
            if (binds.accountForFingerprint(fingerprint)) |acct| return acct;
        }
        var kb: [certfp_key_max]u8 = undefined;
        const k = certfpKey(&kb, fingerprint) orelse return error.NotFound;
        return self.store.*.family(.props).get(k) orelse error.NotFound;
    }

    pub fn addCertfpListEntry(self: Context, account: []const u8, fingerprint: []const u8) ServiceError!void {
        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const existing = self.store.*.family(.props).get(list_key) orelse "";

        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |fp| {
            if (std.ascii.eqlIgnoreCase(fp, fingerprint)) return;
        }

        var out: [certfp_list_value_max]u8 = undefined;
        if (existing.len == 0) {
            const value = std.fmt.bufPrint(&out, "{s}", .{fingerprint}) catch return error.BufferTooSmall;
            try self.store.*.family(.props).put(list_key, value);
            return;
        }
        const value = std.fmt.bufPrint(&out, "{s}\n{s}", .{ existing, fingerprint }) catch return error.BufferTooSmall;
        try self.store.*.family(.props).put(list_key, value);
    }

    pub fn removeCertfpListEntry(self: Context, account: []const u8, fingerprint: []const u8) ServiceError!void {
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, account) orelse return error.BufferTooSmall;
        const existing = self.store.*.family(.props).get(list_key) orelse return error.NotFound;

        var out: [certfp_list_value_max]u8 = undefined;
        var len: usize = 0;
        var removed = false;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |fp| {
            if (fp.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(fp, fingerprint)) {
                removed = true;
                continue;
            }
            if (len != 0) {
                if (len >= out.len) return error.BufferTooSmall;
                out[len] = '\n';
                len += 1;
            }
            if (len + fp.len > out.len) return error.BufferTooSmall;
            @memcpy(out[len..][0..fp.len], fp);
            len += fp.len;
        }
        if (!removed) return error.NotFound;
        if (len == 0) {
            try self.store.*.family(.props).delete(list_key);
        } else {
            try self.store.*.family(.props).put(list_key, out[0..len]);
        }
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn accountForbiddenUnlocked(self: Context, account: []const u8) bool {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).accountForbiddenUnlocked(account);
    }

    pub fn accountSuspendedUnlocked(self: Context, account: []const u8) ServiceError!bool {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).accountSuspendedUnlocked(account);
    }

    pub fn loadAccount(self: Context, name: []const u8) ServiceError!AccountRecord {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).loadAccount(name);
    }

    pub fn recordKeyTransparency(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        return (key_transparency_domain.Context{ .store = self.store, .lock = self.lock, .key_transparency = self.key_transparency }).recordKeyTransparency(account, kind, action, key_id, material, timestamp_ms);
    }

    pub fn saveAccount(self: Context, record: AccountRecord, scratch: []u8) ServiceError!void {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).saveAccount(record, scratch);
    }
};
