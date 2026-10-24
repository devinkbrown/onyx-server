// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Accounts.

const std = @import("std");
const scram_store_mod = @import("../scram_store.zig");
const sasl = @import("../../proto/sasl.zig");
const sasl_scram512 = @import("../../proto/sasl_scram512_server.zig");
const account_verify = @import("../account_verify.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const svc_enforce = @import("../svc_enforce.zig");
const OroStore = @import("records.zig").OroStore;
const ScramStore = @import("records.zig").ScramStore;
const account_max = @import("records.zig").account_max;
const salt_len = @import("records.zig").salt_len;
const hash_len = @import("records.zig").hash_len;
const Config = @import("records.zig").Config;
const ServiceError = @import("records.zig").ServiceError;
const AccountSetField = @import("records.zig").AccountSetField;
const account_flag_suspended = @import("records.zig").account_flag_suspended;
const account_flag_forbidden = @import("records.zig").account_flag_forbidden;
const account_flag_noexpire = @import("records.zig").account_flag_noexpire;
const account_flag_enforce_off = @import("records.zig").account_flag_enforce_off;
const account_flag_secure = @import("records.zig").account_flag_secure;
const account_flag_passkey_only = @import("records.zig").account_flag_passkey_only;
const account_flag_oper_stepup = @import("records.zig").account_flag_oper_stepup;
const account_flags_privileged = @import("records.zig").account_flags_privileged;
const account_flags_sticky = @import("records.zig").account_flags_sticky;
const login_audit_cap = @import("records.zig").login_audit_cap;
const login_audit_prefix = @import("records.zig").login_audit_prefix;
const login_audit_record_len = @import("records.zig").login_audit_record_len;
const login_audit_key_max = @import("records.zig").login_audit_key_max;
const login_audit_blob_max = @import("records.zig").login_audit_blob_max;
const LoginMechanism = @import("records.zig").LoginMechanism;
const LoginTls = @import("records.zig").LoginTls;
const LoginAuditEntry = @import("records.zig").LoginAuditEntry;
const AccountAdminInfo = @import("records.zig").AccountAdminInfo;
const EmailVerifyResult = @import("records.zig").EmailVerifyResult;
const CommandResult = @import("records.zig").CommandResult;
const AccountRecord = @import("records.zig").AccountRecord;
const validatePasswordPolicy = @import("records.zig").validatePasswordPolicy;
const validateEmail = @import("records.zig").validateEmail;
const validateNick = @import("records.zig").validateNick;
const forbidden_account_key_max = @import("records.zig").forbidden_account_key_max;
const verify_key_max = @import("records.zig").verify_key_max;
const verify_value_max = @import("records.zig").verify_value_max;
const default_verify_ttl_ms = @import("records.zig").default_verify_ttl_ms;
const session_token_account_key_max = @import("records.zig").session_token_account_key_max;
const secureZero = @import("records.zig").secureZero;
const forbiddenAccountKey = @import("records.zig").forbiddenAccountKey;
const verifyKey = @import("records.zig").verifyKey;
const scram_key_max = @import("records.zig").scram_key_max;
const scramKey = @import("records.zig").scramKey;
const sessionTokenAccountKey = @import("records.zig").sessionTokenAccountKey;
const accountKey = @import("records.zig").accountKey;
const setFlag = @import("records.zig").setFlag;
const hashPassword = @import("records.zig").hashPassword;
const verifyPassword = @import("records.zig").verifyPassword;
const rejectMissingAccount = @import("records.zig").rejectMissingAccount;
const encodeAccount = @import("records.zig").encodeAccount;
const decodeAccount = @import("records.zig").decodeAccount;
const encodeVerify = @import("records.zig").encodeVerify;
const decodeVerify = @import("records.zig").decodeVerify;
const tokenMatches = @import("records.zig").tokenMatches;
const clock_domain = @import("clock.zig");
const persistence_domain = @import("persistence.zig");
const certfp_bind_mod = @import("../certfp_bind.zig");
const webauthn_creds = @import("../webauthn_creds.zig");
const contracts = @import("contracts.zig");
const store_mod = @import("../store.zig");
const max_batch_mutations = @import("../store/contracts.zig").max_batch_mutations;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    cfg: *const Config,
    scram: *const ?*ScramStore,
    certfp_binds: *const ?*certfp_bind_mod.CertfpBindStore,
    clock_override_ms: *const std.atomic.Value(u64),

    /// False when the account has refused password-derived mechanisms.
    /// A missing account returns true so the caller keeps its ordinary
    /// unknown-account behavior.
    pub fn passwordMechanismsAllowed(self: Context, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const record = self.loadAccount(account) catch return true;
        return (record.flags & account_flag_passkey_only) == 0;
    }

    pub fn validateNewPassword(self: Context, password: []const u8) ServiceError!void {
        try validatePasswordPolicy(password, self.cfg.password_min_len, self.cfg.password_max_len);
    }

    pub fn setAccountEmailPending(
        self: Context,
        name: []const u8,
        email: []const u8,
        token: []const u8,
        issued_ms: u64,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        record.email = try validateEmail(email);
        record.email_verified = false;
        try self.saveAccount(record, scratch);

        var key_buf: [verify_key_max]u8 = undefined;
        const key = verifyKey(&key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var value_buf: [verify_value_max]u8 = undefined;
        const value = try encodeVerify(record.name.asSlice(), record.email.asSlice(), token, issued_ms, &value_buf);
        try self.store.*.family(.props).put(key, value);
    }

    /// Write the pending address and verify token, then mirror the token into
    /// RAM. A failed address write returns before `issue`, so no token exists.
    pub fn beginEmailVerification(
        self: Context,
        verifies: *account_verify.VerifyStore,
        name: []const u8,
        email: []const u8,
        random_bytes: []const u8,
        issued_ms: u64,
        scratch: []u8,
    ) (ServiceError || account_verify.Error)![]const u8 {
        var hex_buf: [128]u8 = undefined;
        const token = account_verify.formatToken(random_bytes, &hex_buf) catch return error.BufferTooSmall;
        try self.setAccountEmailPending(name, email, token, issued_ms, scratch);
        return verifies.issue(name, email, random_bytes, issued_ms);
    }

    pub fn confirmAccountEmail(
        self: Context,
        name: []const u8,
        token: []const u8,
        now_ms: u64,
        scratch: []u8,
    ) ServiceError!EmailVerifyResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        var verify_key_buf: [verify_key_max]u8 = undefined;
        const verify_key_text = verifyKey(&verify_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const encoded = self.store.*.family(.props).get(verify_key_text) orelse return .no_pending;
        const pending = try decodeVerify(encoded);
        if (!std.ascii.eqlIgnoreCase(pending.account, key.asSlice())) return .no_pending;
        if (now_ms >= pending.issued_ms and now_ms - pending.issued_ms >= default_verify_ttl_ms) {
            try self.store.*.family(.props).delete(verify_key_text);
            return .expired;
        }
        if (!tokenMatches(pending.token, token)) return .bad_token;

        var record = try self.loadAccount(key.asSlice());
        record.email = try validateEmail(pending.email);
        record.email_verified = true;
        try self.saveAccount(record, scratch);
        try self.store.*.family(.props).delete(verify_key_text);
        return .verified;
    }

    pub fn loginAuditKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < login_audit_prefix.len + account.len) return null;
        @memcpy(buf[0..login_audit_prefix.len], login_audit_prefix);
        @memcpy(buf[login_audit_prefix.len..][0..account.len], account);
        return buf[0 .. login_audit_prefix.len + account.len];
    }

    pub fn loginMechanismFromByte(byte: u8) ?LoginMechanism {
        return switch (byte) {
            @backingInt(LoginMechanism.password) => .password,
            @backingInt(LoginMechanism.scram) => .scram,
            @backingInt(LoginMechanism.external) => .external,
            @backingInt(LoginMechanism.passkey) => .passkey,
            @backingInt(LoginMechanism.recovery) => .recovery,
            @backingInt(LoginMechanism.oauth) => .oauth,
            @backingInt(LoginMechanism.token) => .token,
            else => null,
        };
    }

    pub fn loginTlsFromByte(byte: u8) ?LoginTls {
        return switch (byte) {
            @backingInt(LoginTls.unknown) => .unknown,
            @backingInt(LoginTls.clear) => .clear,
            @backingInt(LoginTls.tls) => .tls,
            else => null,
        };
    }

    pub fn decodeLoginAuditRecord(raw: []const u8) ?LoginAuditEntry {
        if (raw.len != login_audit_record_len) return null;
        const mechanism = loginMechanismFromByte(raw[8]) orelse return null;
        const tls = loginTlsFromByte(raw[9]) orelse return null;
        var prefix: [8]u8 = @splat(0);
        @memcpy(&prefix, raw[11..19]);
        return .{
            .at_ms = std.mem.readInt(u64, raw[0..8], .little),
            .mechanism = mechanism,
            .tls = tls,
            .certfp_prefix = prefix,
            .certfp_len = @min(raw[10], 8),
        };
    }

    /// Append one successful login. The ring keeps `login_audit_cap` records and
    /// drops the oldest. A failure here must not fail the login that recorded it.
    /// `tls = unknown` is the honest value when the caller cannot see the socket.
    pub fn appendLoginAudit(self: Context, account: []const u8, entry: LoginAuditEntry) ServiceError!void {
        const key_name = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var key_buf: [login_audit_key_max]u8 = undefined;
        const key = loginAuditKey(&key_buf, key_name.asSlice()) orelse return error.BufferTooSmall;
        var blob: [login_audit_blob_max]u8 = undefined;
        var n: usize = 0;
        if (self.store.*.family(.props).get(key)) |existing| {
            const whole = (existing.len / login_audit_record_len) * login_audit_record_len;
            const records = whole / login_audit_record_len;
            const keep = if (records >= login_audit_cap) login_audit_cap - 1 else records;
            const drop = records - keep;
            const src = existing[drop * login_audit_record_len .. whole];
            @memcpy(blob[0..src.len], src);
            n = src.len;
        }
        var stamped = entry;
        if (stamped.at_ms == 0) stamped.at_ms = self.servicesNowMs();
        var rec: [login_audit_record_len]u8 = undefined;
        std.mem.writeInt(u64, rec[0..8], stamped.at_ms, .little);
        rec[8] = @backingInt(stamped.mechanism);
        rec[9] = @backingInt(stamped.tls);
        rec[10] = @min(stamped.certfp_len, 8);
        @memcpy(rec[11..19], &stamped.certfp_prefix);
        @memcpy(blob[n..][0..login_audit_record_len], &rec);
        n += login_audit_record_len;
        try self.store.*.family(.props).put(key, blob[0..n]);
    }

    /// Copy the account's login ring into `out`, oldest first and newest last.
    /// When `out` is shorter than the ring, the newest entries are kept.
    pub fn copyLoginAudit(self: Context, account: []const u8, out: []LoginAuditEntry) ServiceError![]const LoginAuditEntry {
        const key_name = try accountKey(account);
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var key_buf: [login_audit_key_max]u8 = undefined;
        const key = loginAuditKey(&key_buf, key_name.asSlice()) orelse return error.BufferTooSmall;
        const blob = self.store.*.family(.props).get(key) orelse return out[0..0];
        var decoded: [login_audit_cap]LoginAuditEntry = undefined;
        var count: usize = 0;
        var off: usize = 0;
        while (off + login_audit_record_len <= blob.len and count < login_audit_cap) : (off += login_audit_record_len) {
            if (decodeLoginAuditRecord(blob[off..][0..login_audit_record_len])) |row| {
                decoded[count] = row;
                count += 1;
            }
        }
        if (out.len == 0 or count == 0) return out[0..0];
        const start = if (count > out.len) count - out.len else 0;
        const kept = count - start;
        for (0..kept) |i| out[i] = decoded[start + i];
        return out[0..kept];
    }

    pub fn identifyAccount(self: Context, name: []const u8, password: []const u8) ServiceError!CommandResult {
        return self.identifyAccountChecked(name, password);
    }

    /// Password login that records one audit row. Password checks that are not
    /// logins stay on `identifyAccount` and write nothing. `mechanism` is forced
    /// to password. `at_ms == 0` is stamped from the services clock.
    pub fn identifyAccountWithAudit(self: Context, name: []const u8, password: []const u8, entry: LoginAuditEntry) ServiceError!CommandResult {
        const result = try self.identifyAccountChecked(name, password);
        switch (result) {
            .identified => |id| {
                var stamped = entry;
                stamped.mechanism = .password;
                self.appendLoginAudit(id.name.asSlice(), stamped) catch {};
            },
            else => {},
        }
        return result;
    }

    pub fn identifyAccountChecked(self: Context, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        const key = try accountKey(name);
        const value = self.store.*.family(.accounts).get(key.asSlice()) orelse {
            try rejectMissingAccount(password, self.cfg.pbkdf2_rounds);
            return error.AuthFailed;
        };
        const record = try decodeAccount(value);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        // A suspended OR admin-forbidden account cannot authenticate: FORBID must
        // lock the owner out of every credential path, matching issueSessionToken
        // and validateSessionToken which already reject both flags.
        if ((record.flags & (account_flag_suspended | account_flag_forbidden)) != 0) return error.AuthFailed;
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;
        return .{ .identified = .{ .name = record.name } };
    }

    pub fn dropAccount(self: Context, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;
        if (self.certfp_binds.*) |binds| {
            const bind_count = binds.accountBindingCount(record.name.asSlice(), 4096) orelse return error.TableWorkExceeded;
            if (bind_count > 16) return error.TableWorkExceeded;
        }

        var mutations: [max_batch_mutations]store_mod.BatchMutation = undefined;
        var mutation_count: usize = 0;
        try appendDropDelete(&mutations, &mutation_count, .accounts, record.name.asSlice());

        var audit_key_buf: [login_audit_key_max]u8 = undefined;
        if (loginAuditKey(&audit_key_buf, record.name.asSlice())) |audit_key| {
            if (self.store.*.family(.props).get(audit_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, audit_key);
        }
        var verify_key_buf: [verify_key_max]u8 = undefined;
        if (verifyKey(&verify_key_buf, record.name.asSlice())) |verify_key| {
            if (self.store.*.family(.props).get(verify_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, verify_key);
        }
        var scram_key_buf: [scram_key_max]u8 = undefined;
        const scram_key = scramKey(&scram_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(scram_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, scram_key);
        var totp_key_buf: [contracts.totp_key_max]u8 = undefined;
        const totp_key = @import("mfa.zig").Context.totpKey(&totp_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(totp_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, totp_key);
        var recovery_key_buf: [contracts.rcd_key_max]u8 = undefined;
        const recovery_key = std.fmt.bufPrint(&recovery_key_buf, "{s}{s}", .{ contracts.rcd_prefix, record.name.asSlice() }) catch return error.BufferTooSmall;
        if (self.store.*.family(.props).get(recovery_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, recovery_key);

        var token_index_buf: [session_token_account_key_max]u8 = undefined;
        const token_index = sessionTokenAccountKey(&token_index_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(token_index) != null) try appendDropDelete(&mutations, &mutation_count, .props, token_index);

        var certfp_list_key_buf: [@import("records.zig").certfp_account_key_max]u8 = undefined;
        const certfp_list_key = @import("records.zig").certfpAccountKey(&certfp_list_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(certfp_list_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, certfp_list_key);

        var webauthn_list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const webauthn_list_key = webauthn_creds.accountListKey(&webauthn_list_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        if (self.store.*.family(.props).get(webauthn_list_key) != null) try appendDropDelete(&mutations, &mutation_count, .props, webauthn_list_key);

        // Account-scoped indexes can be missing after older best-effort writes.
        // Scan the bounded in-memory props map for credential rows whose own
        // value names this account, so re-registration cannot inherit them.
        const props = &self.store.*.maps[@backingInt(store_mod.Family.props)].map;
        var props_it = props.iterator();
        var scanned: usize = 0;
        while (props_it.next()) |entry| {
            scanned += 1;
            if (scanned > 4096) return error.TableWorkExceeded;
            const row_key = entry.key_ptr.*;
            const row_value = entry.value_ptr.*;
            if (std.mem.startsWith(u8, row_key, "certfp:")) {
                if (std.ascii.eqlIgnoreCase(row_value, record.name.asSlice())) try appendDropDelete(&mutations, &mutation_count, .props, row_key);
            } else if (std.mem.startsWith(u8, row_key, "webauthn:")) {
                const credential = webauthn_creds.decodeRecord(row_value) catch continue;
                if (std.ascii.eqlIgnoreCase(credential.account, record.name.asSlice())) try appendDropDelete(&mutations, &mutation_count, .props, row_key);
            } else if (std.mem.startsWith(u8, row_key, "sessiontok:")) {
                const token = @import("records.zig").decodeSessionTokenRecord(row_value) catch continue;
                if (std.ascii.eqlIgnoreCase(token.account.asSlice(), record.name.asSlice())) try appendDropDelete(&mutations, &mutation_count, .props, row_key);
            }
        }

        var prepared = try self.store.*.prepareBatch(mutations[0..mutation_count]);
        defer prepared.abort();
        try prepared.commit();
        if (self.certfp_binds.*) |binds| _ = binds.unbindAccount(record.name.asSlice());
        if (self.scram.*) |scram| _ = scram.remove(record.name.asSlice());
        return .{ .dropped_account = .{ .name = record.name } };
    }

    /// Change an account's password after verifying the presented current one.
    /// Errors: AuthFailed (wrong current password), InvalidPassword (new fails the
    /// length policy or equals the current one). On success the new salt/hash are
    /// persisted and the SCRAM mirror (if any) is re-derived so SCRAM logins track
    /// the new password. All other account fields are preserved.
    pub fn changeAccountPassword(
        self: Context,
        name: []const u8,
        old_password: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        try verifyPassword(record, old_password, self.cfg.pbkdf2_rounds);
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;
        try self.validateNewPassword(new_password);
        // A change must actually change the password.
        if (std.mem.eql(u8, old_password, new_password)) return error.InvalidPassword;
        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        var salt: [salt_len]u8 = undefined;
        self.store.*.io.randomSecure(&salt) catch self.store.*.io.random(&salt);
        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, new_password, &salt, self.cfg.pbkdf2_rounds);
        record.salt = salt;
        record.hash = hash;

        const encoded = try encodeAccount(record, scratch);
        var token_key_buf: [session_token_account_key_max]u8 = undefined;
        const token_key = sessionTokenAccountKey(&token_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var scram_key_buf: [scram_key_max]u8 = undefined;
        const scram_key = scramKey(&scram_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var scram_value_buf: [ScramStore.serialized_max]u8 = undefined;
        defer secureZero(&scram_value_buf);
        var scram_value: ?[]const u8 = null;
        var prepared_import: ?ScramStore.PreparedImport = null;
        defer if (prepared_import) |*prepared| prepared.abort();
        if (self.scram.*) |scram| {
            var keys256 = sasl.deriveScramKeys(new_password, &salt, scram_store_mod.default_iterations) catch return error.InvalidRecord;
            defer keys256.wipe();
            var keys512 = sasl_scram512.deriveScramKeys(new_password, &salt, scram_store_mod.default_iterations) catch return error.InvalidRecord;
            defer keys512.wipe();
            var full = ScramStore.FullRecord{
                .salt = &salt,
                .iterations = scram_store_mod.default_iterations,
                .stored_key = keys256.stored_key,
                .server_key = keys256.server_key,
                .has_512 = true,
                .stored_key_512 = keys512.stored_key,
                .server_key_512 = keys512.server_key,
            };
            defer {
                secureZero(&full.stored_key);
                secureZero(&full.server_key);
                secureZero(&full.stored_key_512);
                secureZero(&full.server_key_512);
            }
            scram_value = ScramStore.serializeFullRecord(full, &scram_value_buf) orelse return error.InvalidRecord;
            prepared_import = scram.prepareImportFullRecord(record.name.asSlice(), full) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidRecord,
            };
        }
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .accounts, .kind = .put, .key = record.name.asSlice(), .value = encoded },
            .{ .family = .props, .kind = if (scram_value == null) .delete else .put, .key = scram_key, .value = scram_value },
            .{ .family = .props, .kind = .delete, .key = token_key },
        });
        defer prepared.abort();
        try prepared.commit();
        if (prepared_import) |*candidate| candidate.commit();
    }

    /// Set an account's password WITHOUT verifying the current one — for an
    /// authenticated RECOVERY flow where the requester has already proven their
    /// identity by a non-knowledge factor (e.g. a connection authenticated by a
    /// client certificate bound to the account). Authorization is the CALLER's
    /// responsibility. The password, durable SCRAM mirror, and SASL token
    /// revocation commit together; the prepared SCRAM cache then publishes
    /// without allocation. Never expose it on a path that has not independently
    /// verified the requester.
    pub fn setAccountPasswordForced(
        self: Context,
        name: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        var record = try self.loadAccount(name);
        try self.validateNewPassword(new_password);

        var salt: [salt_len]u8 = undefined;
        self.store.*.io.randomSecure(&salt) catch self.store.*.io.random(&salt);
        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, new_password, &salt, self.cfg.pbkdf2_rounds);
        record.salt = salt;
        record.hash = hash;
        // Recovery replacement is the break-glass path back to a password.
        // It clears the passkey-only refusal. An account that was locked, or
        // that was already waiting on a passkey before operator elevation,
        // keeps the operator latch so this password is not an operator credential.
        const step_up = (record.flags & account_flags_sticky) != 0;
        record.flags &= ~account_flag_passkey_only;
        if (step_up) record.flags |= account_flag_oper_stepup;

        const encoded = try encodeAccount(record, scratch);
        var account_token_key_buf: [session_token_account_key_max]u8 = undefined;
        const account_token_key = sessionTokenAccountKey(&account_token_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var scram_key_buf: [scram_key_max]u8 = undefined;
        const scram_key = scramKey(&scram_key_buf, record.name.asSlice()) orelse return error.BufferTooSmall;
        var scram_value_buf: [ScramStore.serialized_max]u8 = undefined;
        defer secureZero(&scram_value_buf);
        var scram_value: ?[]const u8 = null;
        var prepared_import: ?ScramStore.PreparedImport = null;
        defer if (prepared_import) |*prepared| prepared.abort();
        if (self.scram.*) |scram| {
            var keys256 = sasl.deriveScramKeys(new_password, &salt, scram_store_mod.default_iterations) catch return error.InvalidRecord;
            defer keys256.wipe();
            var keys512 = sasl_scram512.deriveScramKeys(new_password, &salt, scram_store_mod.default_iterations) catch return error.InvalidRecord;
            defer keys512.wipe();
            var full = ScramStore.FullRecord{
                .salt = &salt,
                .iterations = scram_store_mod.default_iterations,
                .stored_key = keys256.stored_key,
                .server_key = keys256.server_key,
                .has_512 = true,
                .stored_key_512 = keys512.stored_key,
                .server_key_512 = keys512.server_key,
            };
            defer {
                secureZero(&full.stored_key);
                secureZero(&full.server_key);
                secureZero(&full.stored_key_512);
                secureZero(&full.server_key_512);
            }
            scram_value = ScramStore.serializeFullRecord(full, &scram_value_buf) orelse return error.InvalidRecord;
            prepared_import = scram.prepareImportFullRecord(record.name.asSlice(), full) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidRecord,
            };
        }
        var prepared = try self.store.*.prepareBatch(&.{
            .{ .family = .accounts, .kind = .put, .key = record.name.asSlice(), .value = encoded },
            .{ .family = .props, .kind = if (scram_value == null) .delete else .put, .key = scram_key, .value = scram_value },
            .{ .family = .props, .kind = .delete, .key = account_token_key },
        });
        defer prepared.abort();
        try prepared.commit();
        if (prepared_import) |*candidate| candidate.commit();
    }

    pub fn ghostAccount(self: Context, name: []const u8, password: []const u8, nick: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        if (self.store.*.preparedWritesPoisoned()) return error.StorePoisoned;

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;
        const clean_nick = try validateNick(nick);
        return .{ .ghosted = .{ .account = record.name, .nick = clean_nick } };
    }

    pub fn setAccount(
        self: Context,
        name: []const u8,
        password: []const u8,
        field: AccountSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = self.loadAccount(name) catch |err| switch (err) {
            // A missing account must cost the same as a present account with a
            // wrong password so ACCOUNTSET cannot be used as a timing oracle to
            // enumerate registered accounts (handleAccountSet has no login
            // throttle and returns the identical ERR_PASSWDMISMATCH). Run the
            // dummy PBKDF2, matching identifyAccount, before returning NotFound.
            error.NotFound => {
                try rejectMissingAccount(password, self.cfg.pbkdf2_rounds);
                return error.NotFound;
            },
            else => return err,
        };
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        if ((record.flags & account_flag_passkey_only) != 0) return error.AuthFailed;
        switch (field) {
            .email => |email| {
                record.email = try validateEmail(email);
                record.email_verified = false;
            },
            .flags => |flags| {
                const preserved = record.flags & account_flags_privileged;
                if ((flags & account_flags_privileged) != preserved) return error.Forbidden;
                const sticky = record.flags & account_flags_sticky;
                record.flags = preserved | sticky | (flags & ~(account_flags_privileged | account_flags_sticky));
            },
            // SECURE on/off. ENFORCE on/off is stored inverted (`enforce_off`) so
            // the default-0 record keeps today's always-on enforcement.
            .secure => |on| setFlag(&record.flags, account_flag_secure, on),
            .enforce => |on| setFlag(&record.flags, account_flag_enforce_off, !on),
        }
        const encoded = try encodeAccount(record, scratch);
        try self.store.*.family(.accounts).put(record.name.asSlice(), encoded);
        return .{ .set_account = record.info() };
    }

    pub fn accountInfo(self: Context, name: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadAccount(name);
        return .{ .account_info = record.info() };
    }

    /// Server-side (no password) read of an account's nick-protection settings,
    /// for the registration sweep. An unknown account yields the protective
    /// default (ENFORCE on, SECURE off). ENFORCETIME is the configured grace,
    /// supplied by the caller as `enforce_seconds` since it is not per-account.
    pub fn accountSecurity(self: Context, name: []const u8, enforce_seconds: u32) svc_enforce.AccountSecurity {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = accountKey(name) catch return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const value = self.store.*.family(.accounts).get(key.asSlice()) orelse
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const record = decodeAccount(value) catch
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        return .{
            .secure = (record.flags & account_flag_secure) != 0,
            .enforce = (record.flags & account_flag_enforce_off) == 0,
            .enforce_seconds = enforce_seconds,
        };
    }

    pub fn setAccountSuspended(self: Context, name: []const u8, suspended: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        setFlag(&record.flags, account_flag_suspended, suspended);
        try self.saveAccount(record, scratch);
        return record.adminInfo();
    }

    pub fn setAccountNoExpire(self: Context, name: []const u8, noexpire: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        setFlag(&record.flags, account_flag_noexpire, noexpire);
        try self.saveAccount(record, scratch);
        return record.adminInfo();
    }

    /// Reserve or unreserve an account name. Registered accounts record the
    /// forbidden bit in their account record; unregistered names use a durable
    /// props-family reservation so REGISTER can reject the name later.
    pub fn setAccountForbidden(self: Context, name: []const u8, forbidden: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;

        if (self.store.*.family(.accounts).get(key.asSlice())) |value| {
            var record = try decodeAccount(value);
            setFlag(&record.flags, account_flag_forbidden, forbidden);
            try self.saveAccount(record, scratch);
            if (forbidden) {
                try self.store.*.family(.props).put(reservation_key, "1");
            } else {
                try self.store.*.family(.props).delete(reservation_key);
            }
            return record.adminInfo();
        }

        if (forbidden) {
            try self.store.*.family(.props).put(reservation_key, "1");
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        if (self.store.*.family(.props).get(reservation_key) == null) return error.NotFound;
        try self.store.*.family(.props).delete(reservation_key);
        return .{ .name = key, .registered = false };
    }

    pub fn adminAccountInfo(self: Context, name: []const u8) ServiceError!AccountAdminInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(name);
        if (self.store.*.family(.accounts).get(key.asSlice())) |value| {
            return (try decodeAccount(value)).adminInfo();
        }
        if (self.accountForbiddenUnlocked(key.asSlice())) {
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        return error.NotFound;
    }

    /// Fail-closed authentication gate: whether `account` must be denied every
    /// credential path because it is SUSPENDED or FORBIDDEN, or because the
    /// store crossed an ambiguous durable authentication boundary. This is the shared
    /// chokepoint the SASL success path consults so SCRAM / OAUTHBEARER — whose
    /// proof/token verification never consults account status — cannot bind a
    /// locked account. Fail-closed: an account whose status cannot be decoded
    /// reads as blocked. An unknown/unregistered name that carries no forbid
    /// reservation is not blocked (guests and unknown authcids pass).
    pub fn accountAuthBlocked(self: Context, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.store.*.preparedWritesPoisoned()) return true;
        // A decode failure on the suspend check is treated as blocked.
        const suspended = self.accountSuspendedUnlocked(account) catch return true;
        if (suspended) return true;
        return self.accountForbiddenUnlocked(account);
    }

    pub fn accountIsRegistered(self: Context, account: []const u8) bool {
        const key = accountKey(account) catch return false;
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.store.*.family(.accounts).get(key.asSlice()) != null;
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

    /// Mirror an account's derived SCRAM tuple into the durable store, keyed by
    /// account. Serializes BOTH the SHA-256 and (when provisioned) SHA-512
    /// material in a single backward-compatible record so a SCRAM-SHA-256 OR
    /// SCRAM-SHA-512 login resolves after a restart. Best-effort; the in-memory
    /// SCRAM store is authoritative live.
    pub fn persistScram(self: Context, scram: *ScramStore, account: []const u8) void {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).persistScram(scram, account);
    }

    pub fn saveAccount(self: Context, record: AccountRecord, scratch: []u8) ServiceError!void {
        return (persistence_domain.Context{ .store = self.store, .lock = self.lock }).saveAccount(record, scratch);
    }

    pub fn servicesNowMs(self: Context) u64 {
        return (clock_domain.Context{ .store = self.store, .clock_override_ms = self.clock_override_ms }).servicesNowMs();
    }
};

fn appendDropDelete(
    mutations: *[max_batch_mutations]store_mod.BatchMutation,
    count: *usize,
    family: store_mod.Family,
    key: []const u8,
) ServiceError!void {
    if (count.* >= mutations.len) return error.TableWorkExceeded;
    mutations[count.*] = .{ .family = family, .kind = .delete, .key = key };
    count.* += 1;
}
