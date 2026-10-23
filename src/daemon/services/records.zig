// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Records.

const std = @import("std");
const store_mod = @import("../store.zig");
const toml = @import("../../proto/toml.zig");
const scram_store_mod = @import("../scram_store.zig");

pub const OroStore = store_mod.OroStore;

pub const ScramStore = scram_store_mod.ScramStore;

pub const account_max = 32;

pub const channel_max = 64;

pub const nick_max = 64;

pub const email_max = 96;

pub const mlock_max = 128;

pub const mask_max = 160;

pub const reason_max = 128;

pub const key_max = 256;

pub const record_max = 768;

pub const salt_len = 16;

pub const hash_len = 32;

pub const salt_hex_len = salt_len * 2;

pub const hash_hex_len = hash_len * 2;

pub const generation_len = 16;

pub const generation_hex_len = generation_len * 2;

pub const default_pbkdf2_rounds: u32 = 100_000;

pub const default_password_min_len: usize = 8;

pub const default_password_max_len: usize = 512;

pub const password_policy_min_len_max: usize = 64;

pub const password_policy_max_len_min: usize = 64;

pub const password_policy_max_len: usize = 4096;

/// Runtime-tunable account/credential policy. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[accounts]` TOML section
/// via `Config.applyToml` before constructing `Services`.
pub const Config = struct {
    /// PBKDF2-HMAC-SHA256 iteration count for account password hashing.
    pbkdf2_rounds: u32 = default_pbkdf2_rounds,
    /// Minimum length for newly registered or changed account passwords.
    password_min_len: usize = default_password_min_len,
    /// Maximum length for newly registered or changed account passwords.
    password_max_len: usize = default_password_max_len,

    /// Overlay `[accounts]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("accounts.pbkdf2_rounds")) |v| {
            if (v >= 1 and v <= std.math.maxInt(u32)) cfg.pbkdf2_rounds = @intCast(v);
        }
        var min_len = cfg.password_min_len;
        var max_len = cfg.password_max_len;
        if (doc.getUint("accounts.password_min_len")) |v| {
            if (v >= 1 and v <= password_policy_min_len_max) min_len = @intCast(v);
        }
        if (doc.getUint("accounts.password_max_len")) |v| {
            if (v >= password_policy_max_len_min and v <= password_policy_max_len) max_len = @intCast(v);
        }
        if (min_len <= max_len) {
            cfg.password_min_len = min_len;
            cfg.password_max_len = max_len;
        }
    }
};

pub const account_version = "A1";

pub const account_version_v2 = "A2";

pub const channel_version = "C1";

pub const channel_version_v2 = "C2";

pub const access_version = "X1";

pub const akick_version = "K1";

pub const verify_version = "V1";

pub const ward_version = "W1";

pub const saccess_version = "S1";

pub const access_prefix = "chanaccess:";

pub const akick_prefix = "chanakick:";

pub const verify_prefix = "acctverify:";

pub const ward_prefix = "ward:";

pub const saccess_prefix = "saccess:";

pub const missing_account_salt: [salt_len]u8 = .{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x2d,
    0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
};

pub const session_token_prefix = "sst_";

pub const session_token_random_len: usize = 16;

pub const session_token_len: usize = session_token_prefix.len + session_token_random_len * 2;

pub const default_session_token_ttl_seconds: i64 = 30 * 24 * 60 * 60;

pub const channel_access_family = store_mod.Family.props;

pub const StorePutError = @typeInfo(@typeInfo(@TypeOf(OroStore.put)).@"fn".return_type.?).error_union.error_set;

pub const StoreDeleteError = @typeInfo(@typeInfo(@TypeOf(OroStore.delete)).@"fn".return_type.?).error_union.error_set;

pub const Pbkdf2Error = @typeInfo(@typeInfo(@TypeOf(std.crypto.pwhash.pbkdf2)).@"fn".return_type.?).error_union.error_set;

pub const ServiceError = StorePutError || StoreDeleteError || Pbkdf2Error || error{
    NotFound,
    AuthFailed,
    Forbidden,
    AlreadyExists,
    InvalidName,
    InvalidChannel,
    InvalidRecord,
    InvalidPassword,
    InvalidValue,
    RandomUnavailable,
    BufferTooSmall,
};

comptime {
    if (@typeInfo(ServiceError).error_set.error_names == null) @compileError("ServiceError must remain concrete");
}

/// Optional integration hook for the daemon's UNDERTOW state.
pub const StateHook = struct {
    ptr: *anyopaque,
    create_channel: *const fn (ctx: *anyopaque, channel: []const u8) ServiceError!void,
    /// Optional: invoked when a channel registration is dropped, so the live
    /// world can clear the +r REGISTERED flag and let the channel become
    /// ephemeral again. Null hooks simply skip this notification.
    drop_channel: ?*const fn (ctx: *anyopaque, channel: []const u8) ServiceError!void = null,

    pub fn createChannel(self: StateHook, channel: []const u8) ServiceError!void {
        try self.create_channel(self.ptr, channel);
    }

    pub fn dropChannel(self: StateHook, channel: []const u8) ServiceError!void {
        if (self.drop_channel) |cb| try cb(self.ptr, channel);
    }
};

pub fn InlineText(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = @splat(0),
        len: u16 = 0,

        pub fn init(input: []const u8) error{StringTooLong}!@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = @intCast(input.len);
            return out;
        }

        pub fn empty() @This() {
            return .{};
        }

        pub fn asSlice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const AccountName = InlineText(account_max);

pub const ChannelName = InlineText(channel_max);

pub const NickName = InlineText(nick_max);

pub const Email = InlineText(email_max);

pub const Mlock = InlineText(mlock_max);

pub const Mask = InlineText(mask_max);

pub const Reason = InlineText(reason_max);

pub const AccessLevel = enum(u8) {
    voice = 10,
    op = 25,
    admin = 50,
    founder = 100,

    pub fn allows(self: AccessLevel, needed: AccessLevel) bool {
        return @backingInt(self) >= @backingInt(needed);
    }
};

pub const AccountSetField = union(enum) { email: []const u8, flags: u32, secure: bool, enforce: bool };

pub const ChannelSetField = union(enum) { flags: u32, mlock: []const u8 };

pub const AccessAction = enum { query, grant, revoke };

pub const AkickAction = enum { add, remove, query };

pub const AccountRef = struct { name: AccountName };

pub const ChannelRef = struct { name: ChannelName };

// ── Registered-channel boolean settings (CHANNEL SET) ───────────────────────
// Stored in the channel record's `flags` so they survive recreation. A fresh
// record has flags 0 (all off), which preserves the prior "unset" behavior.
/// TOPICLOCK: only channel ops / those with channel ACCESS may change the topic
/// (a registration-backed +t that holds even after the channel empties).
pub const channel_flag_topiclock: u32 = 1 << 0;

/// GUARD: keep the registered channel "open" — services hold it so its modes and
/// topic persist while empty (surfaced to the daemon to recreate/secure it).
pub const channel_flag_guard: u32 = 1 << 1;

/// PRIVATE: hide the channel from public listings (LIST / NAMES enumeration).
pub const channel_flag_private: u32 = 1 << 2;

pub const account_flag_suspended: u32 = 1 << 0;

pub const account_flag_forbidden: u32 = 1 << 1;

pub const account_flag_noexpire: u32 = 1 << 2;

/// Owner-settable nick-protection flags (NOT privileged). Stored so the bit
/// layout stays backward-compatible: a fresh/old account record has these 0,
/// which means "ENFORCE on, SECURE off" — exactly today's always-on behavior.
/// `enforce_off` is inverted (set = the owner opted OUT of auto-enforcement on
/// their registered nick) so default protection is preserved without a DB
/// format change. `secure` = recognize the account only via identify.
pub const account_flag_enforce_off: u32 = 1 << 3;

pub const account_flag_secure: u32 = 1 << 4;

/// Password, SCRAM, and the other password-derived mechanisms are refused.
/// Passkey login and a recovery-code password replacement stay available.
/// The generic ACCOUNTSET flags field cannot set or clear this bit.
pub const account_flag_passkey_only: u32 = 1 << 5;

/// Operator elevation stays closed to password, SCRAM, recovery, and session
/// tokens until a later passkey authentication. LOCK sets this with
/// `passkey_only`. Recovery clears `passkey_only` and leaves this set, so the
/// restored password is not an operator credential. A passkey sign-in clears
/// it only after `passkey_only` is already clear. ACCOUNTSET cannot touch it.
pub const account_flag_oper_stepup: u32 = 1 << 6;

pub const account_flags_privileged: u32 = account_flag_suspended | account_flag_forbidden | account_flag_noexpire;

pub const account_flags_sticky: u32 = account_flag_passkey_only | account_flag_oper_stepup;

/// How long a SUCCESSOR SET waits before it replaces the armed successor.
/// CLEAR during the wait cancels the replacement. A drop during the wait
/// still hands the channel to the already-armed successor.
pub const successor_hold_ms: u64 = 10 * 60 * 1000;

pub const login_audit_cap: usize = 8;

pub const login_audit_prefix = "lga\x00";

pub const login_audit_record_len: usize = 19;

pub const login_audit_key_max: usize = login_audit_prefix.len + account_max;

pub const login_audit_blob_max: usize = login_audit_cap * login_audit_record_len;

pub const LoginMechanism = enum(u8) {
    password = 1,
    scram = 2,
    external = 3,
    passkey = 4,
    recovery = 5,
    oauth = 6,
    token = 7,

    pub fn label(self: LoginMechanism) []const u8 {
        return switch (self) {
            .password => "password",
            .scram => "scram",
            .external => "external",
            .passkey => "passkey",
            .recovery => "recovery",
            .oauth => "oauth",
            .token => "token",
        };
    }
};

pub const LoginTls = enum(u8) {
    unknown = 0,
    clear = 1,
    tls = 2,

    pub fn label(self: LoginTls) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .clear => "clear",
            .tls => "tls",
        };
    }
};

pub const LoginAuditEntry = struct {
    at_ms: u64 = 0,
    mechanism: LoginMechanism = .password,
    tls: LoginTls = .unknown,
    certfp_prefix: [8]u8 = @splat(0),
    certfp_len: u8 = 0,
};

pub const AccountInfo = struct {
    name: AccountName,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,
};

pub const AccountAdminInfo = struct {
    name: AccountName,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,
    registered: bool = false,

    pub fn suspended(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_suspended) != 0;
    }

    pub fn forbidden(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_forbidden) != 0;
    }

    pub fn noexpire(self: AccountAdminInfo) bool {
        return (self.flags & account_flag_noexpire) != 0;
    }
};

pub const ChannelInfo = struct {
    name: ChannelName,
    founder: AccountName,
    flags: u32 = 0,
    mlock: Mlock = Mlock.empty(),
};

pub const GhostInfo = struct {
    account: AccountName,
    nick: NickName,
};

pub const SessionTokenIssue = struct {
    account: AccountName,
    token: [session_token_len]u8,
    expires_unix: i64,

    pub fn tokenSlice(self: *const SessionTokenIssue) []const u8 {
        return self.token[0..];
    }
};

pub const AccessInfo = struct {
    channel: ChannelName,
    account: AccountName,
    level: AccessLevel,
};

pub const AkickInfo = struct {
    channel: ChannelName,
    mask: Mask,
    setter: AccountName,
    reason: Reason = Reason.empty(),
};

pub const EmailVerifyResult = enum {
    verified,
    expired,
    no_pending,
    bad_token,
};

pub const ReplayWard = struct {
    match: []const u8,
    pattern: []const u8,
    scope: []const u8,
    action: []const u8,
    reason: []const u8,
    setter: []const u8,
    created_ms: i64,
    expires_ms: i64,
};

/// Server-level IRCX ACCESS (SACCESS) entry as carried across the persistence
/// boundary. Fields borrow from caller-owned buffers / decoded WAL values.
pub const ReplaySaccess = struct {
    /// Entry-type token: DENY / GAG / GRANT / NOCHANNEL / NONICK.
    entry_type: []const u8,
    mask: []const u8,
    duration: u64 = 0,
    reason: []const u8 = "",
};

pub const LiveReplaySummary = struct {
    channels: usize = 0,
    mlocks: usize = 0,
    akicks: usize = 0,
    wards: usize = 0,
    saccesses: usize = 0,
};

pub const LiveReplaySink = struct {
    ptr: *anyopaque,
    channel: *const fn (ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void,
    akick: ?*const fn (ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, setter: []const u8) ServiceError!void = null,
    ward: ?*const fn (ctx: *anyopaque, ward: ReplayWard) ServiceError!void = null,
    saccess: ?*const fn (ctx: *anyopaque, entry: ReplaySaccess) ServiceError!void = null,
};

pub const CommandResult = union(enum) {
    registered_account: AccountRef,
    identified: AccountRef,
    dropped_account: AccountRef,
    ghosted: GhostInfo,
    set_account: AccountInfo,
    account_info: AccountInfo,
    registered_channel: ChannelInfo,
    dropped_channel: ChannelRef,
    channel_info: ChannelInfo,
    access: AccessInfo,
    access_revoked: AccessInfo,
    akick: AkickInfo,
    akick_removed: AkickInfo,
    set_channel: ChannelInfo,
};

pub const AccountRecord = struct {
    name: AccountName,
    salt: [salt_len]u8,
    hash: [hash_len]u8,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,

    pub fn info(self: AccountRecord) AccountInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags };
    }

    pub fn adminInfo(self: AccountRecord) AccountAdminInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags, .registered = true };
    }
};

pub const ChannelRecord = struct {
    name: ChannelName,
    founder: AccountName,
    generation: [generation_len]u8,
    flags: u32 = 0,
    mlock: Mlock = Mlock.empty(),

    pub fn info(self: ChannelRecord) ChannelInfo {
        return .{ .name = self.name, .founder = self.founder, .flags = self.flags, .mlock = self.mlock };
    }
};

pub const AccessRecord = struct {
    channel: ChannelName,
    account: AccountName,
    generation: [generation_len]u8,
    level: AccessLevel,

    pub fn info(self: AccessRecord) AccessInfo {
        return .{ .channel = self.channel, .account = self.account, .level = self.level };
    }
};

pub const AkickRecord = struct {
    channel: ChannelName,
    mask: Mask,
    generation: [generation_len]u8,
    setter: AccountName,
    reason: Reason = Reason.empty(),

    pub fn info(self: AkickRecord) AkickInfo {
        return .{ .channel = self.channel, .mask = self.mask, .setter = self.setter, .reason = self.reason };
    }
};

pub const DirectoryFamily = struct {
    family: store_mod.Family,
    prefix: ?[]const u8,
};

pub const directory_families = [_]DirectoryFamily{
    .{ .family = .accounts, .prefix = null },
    .{ .family = .chanregs, .prefix = null },
    .{ .family = .props, .prefix = access_prefix },
    .{ .family = .props, .prefix = akick_prefix },
};

pub fn directoryKeyIncluded(key: []const u8, prefix: ?[]const u8) bool {
    if (prefix) |wanted| return std.mem.startsWith(u8, key, wanted);
    return true;
}

pub fn directoryConflicts(left: *OroStore, right: *OroStore) bool {
    for (directory_families) |spec| {
        var it = left.maps[@backingInt(spec.family)].map.iterator();
        while (it.next()) |entry| {
            if (!directoryKeyIncluded(entry.key_ptr.*, spec.prefix)) continue;
            const other = right.get(spec.family, entry.key_ptr.*) orelse continue;
            if (!std.mem.eql(u8, other, entry.value_ptr.*)) return true;
        }
    }
    return false;
}

pub fn copyMissingDirectory(dst: *OroStore, src: *OroStore) !usize {
    var copied: usize = 0;
    for (directory_families) |spec| {
        var it = src.maps[@backingInt(spec.family)].map.iterator();
        while (it.next()) |entry| {
            if (!directoryKeyIncluded(entry.key_ptr.*, spec.prefix)) continue;
            if (dst.get(spec.family, entry.key_ptr.*) != null) continue;
            try dst.put(spec.family, entry.key_ptr.*, entry.value_ptr.*);
            copied += 1;
        }
    }
    return copied;
}

pub fn validatePassword(password: []const u8) ServiceError!void {
    try validatePasswordPolicy(password, default_password_min_len, default_password_max_len);
}

pub fn validatePasswordPolicy(password: []const u8, min_len: usize, max_len: usize) ServiceError!void {
    if (password.len < min_len or password.len > max_len) return error.InvalidPassword;
    for (password) |byte| if (byte == 0 or byte == '\n' or byte == '\r') return error.InvalidPassword;
}

pub fn validateEmail(input: []const u8) ServiceError!Email {
    if (input.len == 0) return Email.empty();
    if (input.len > email_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Email.init(input) catch error.InvalidValue;
}

pub fn validateMlock(input: []const u8) ServiceError!Mlock {
    if (input.len == 0) return Mlock.empty();
    if (input.len > mlock_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mlock.init(input) catch error.InvalidValue;
}

pub fn validateReason(input: []const u8) ServiceError!Reason {
    if (input.len > reason_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Reason.init(input) catch error.InvalidValue;
}

pub fn validateNick(input: []const u8) ServiceError!NickName {
    if (input.len == 0 or input.len > nick_max or hasCtlOrSep(input)) return error.InvalidName;
    for (input) |byte| if (byte == ' ' or byte == ',') return error.InvalidName;
    return NickName.init(input) catch error.InvalidName;
}

pub fn validateMask(input: []const u8) ServiceError!Mask {
    if (input.len == 0 or input.len > mask_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mask.init(input) catch error.InvalidValue;
}

/// Durable-store key prefix for certfp→account bindings (props family). The
/// prefix keeps these out of the channel-access keyspace that shares `.props`.
pub const certfp_key_prefix = "certfp:";

pub const certfp_key_max = certfp_key_prefix.len + 128;

pub const certfp_account_key_prefix = "certfps:";

pub const certfp_account_key_max = certfp_account_key_prefix.len + account_max;

pub const certfp_list_value_max = 16 * 64 + 15;

pub const forbidden_account_key_prefix = "acctforbid:";

pub const forbidden_account_key_max = forbidden_account_key_prefix.len + account_max;

pub const verify_key_max = verify_prefix.len + account_max;

pub const verify_value_max = verify_version.len + 1 + account_max + 1 + email_max + 1 + 128 + 1 + 20;

pub const default_verify_ttl_ms: u64 = 15 * 60 * 1000;

pub const ward_key_max = ward_prefix.len + 16 + 1 + 256;

pub const ward_value_max = ward_version.len + 1 + 16 + 1 + 256 + 1 + 16 + 1 + 16 + 1 + 20 + 1 + 20 + 1 + 64 + 1 + 512;

// SACCESS persistence sizing. Entry-type token <= 9 ("NOCHANNEL"); mask is the
// IRCX access mask (DEFAULT_MAX_MASK_BYTES = 128); reason <= 256; duration is a
// u64 (<= 20 digits). Generous bounds keep this restart-safe under any config.
pub const saccess_type_max = 16;

pub const saccess_mask_max = 256;

pub const saccess_reason_max = 512;

pub const saccess_key_max = saccess_prefix.len + saccess_type_max + 1 + saccess_mask_max;

pub const saccess_value_max = saccess_version.len + 1 + saccess_type_max + 1 + saccess_mask_max + 1 + 20 + 1 + saccess_reason_max;

pub const session_token_version = "T1";

pub const session_token_key_prefix = "sessiontok:";

pub const session_token_account_key_prefix = "sessiontokacct:";

pub const session_token_key_max = session_token_key_prefix.len + hash_hex_len;

pub const session_token_account_key_max = session_token_account_key_prefix.len + account_max;

pub const session_token_value_max = session_token_version.len + 1 + account_max + 1 + 20 + 1 + hash_hex_len;

pub const SessionTokenRecord = struct {
    account: AccountName,
    expires_unix: i64,
    hash: []const u8,
};

pub fn secureZero(buf: []u8) void {
    for (buf) |*byte| {
        const vp: *volatile u8 = @ptrCast(byte);
        vp.* = 0;
    }
}

/// Build the props-family key for a certfp binding, or null if it would not fit.
pub fn certfpKey(buf: []u8, fingerprint: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_key_prefix ++ "{s}", .{fingerprint}) catch null;
}

pub fn certfpAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_account_key_prefix ++ "{s}", .{account}) catch null;
}

pub fn forbiddenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, forbidden_account_key_prefix ++ "{s}", .{account}) catch null;
}

pub fn verifyKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, verify_prefix ++ "{s}", .{account}) catch null;
}

/// Durable-store key prefix for persisted SCRAM credential tuples (props family).
pub const scram_key_prefix = "scram:";

pub const scram_key_max = scram_key_prefix.len + account_max;

/// Build the props-family key for an account's SCRAM tuple, or null if too long.
pub fn scramKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, scram_key_prefix ++ "{s}", .{account}) catch null;
}

pub fn sessionTokenKey(buf: []u8, hash_hex: []const u8) ?[]const u8 {
    if (hash_hex.len != hash_hex_len) return null;
    return std.fmt.bufPrint(buf, session_token_key_prefix ++ "{s}", .{hash_hex}) catch null;
}

pub fn sessionTokenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, session_token_account_key_prefix ++ "{s}", .{account}) catch null;
}

pub fn encodeSessionTokenRecord(account: []const u8, expires_unix: i64, hash_hex: []const u8, scratch: []u8) ServiceError![]const u8 {
    if (hash_hex.len != hash_hex_len) return error.InvalidRecord;
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{d}|{s}",
        .{ session_token_version, account, expires_unix, hash_hex },
    ) catch error.BufferTooSmall;
}

pub fn decodeSessionTokenRecord(value: []const u8) ServiceError!SessionTokenRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    if (!std.mem.eql(u8, version, session_token_version)) return error.InvalidRecord;
    const account = try accountKey(it.next() orelse return error.InvalidRecord);
    const expires_unix = std.fmt.parseInt(i64, it.next() orelse return error.InvalidRecord, 10) catch return error.InvalidRecord;
    const hash_hex = it.next() orelse return error.InvalidRecord;
    if (it.next() != null) return error.InvalidRecord;
    if (hash_hex.len != hash_hex_len) return error.InvalidRecord;
    for (hash_hex) |ch| if (!std.ascii.isHex(ch)) return error.InvalidRecord;
    return .{ .account = account, .expires_unix = expires_unix, .hash = hash_hex };
}

pub fn validSessionTokenText(token: []const u8) bool {
    if (token.len != session_token_len) return false;
    if (!std.mem.eql(u8, token[0..session_token_prefix.len], session_token_prefix)) return false;
    for (token[session_token_prefix.len..]) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

pub fn accountKey(input: []const u8) ServiceError!AccountName {
    if (input.len == 0 or input.len > account_max) return error.InvalidName;
    var out = AccountName{};
    for (input, 0..) |byte, idx| {
        if (!isAccountChar(byte)) return error.InvalidName;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

/// Canonicalize an account exactly as account storage, SCRAM provisioning, and
/// service authentication do. Daemon admission paths use this instead of
/// growing a second, subtly different account-name policy.
pub fn canonicalAccount(input: []const u8) ServiceError!AccountName {
    return accountKey(input);
}

pub fn channelKey(input: []const u8) ServiceError!ChannelName {
    if (input.len < 2 or input.len > channel_max or input[0] != '#') return error.InvalidChannel;
    var out = ChannelName{};
    for (input, 0..) |byte, idx| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return error.InvalidChannel;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

pub fn isAccountChar(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

pub fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

pub fn setFlag(flags: *u32, bit: u32, enabled: bool) void {
    if (enabled) {
        flags.* |= bit;
    } else {
        flags.* &= ~bit;
    }
}

pub fn hasCtlOrSep(input: []const u8) bool {
    for (input) |byte| if (byte < 0x20 or byte == 0x7f or byte == '|') return true;
    return false;
}

pub fn hashPassword(out: *[hash_len]u8, password: []const u8, salt: *const [salt_len]u8, rounds: u32) ServiceError!void {
    try std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
}

pub fn verifyPassword(record: AccountRecord, password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &record.salt, rounds);
    if (!std.crypto.timing_safe.eql([hash_len]u8, candidate, record.hash)) return error.AuthFailed;
}

pub fn rejectMissingAccount(password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &missing_account_salt, rounds);
}

pub fn encodeAccount(record: AccountRecord, scratch: []u8) ServiceError![]const u8 {
    var salt_hex = std.fmt.bytesToHex(record.salt, .lower);
    var hash_hex = std.fmt.bytesToHex(record.hash, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}|{}",
        .{ account_version_v2, record.name.asSlice(), &salt_hex, &hash_hex, record.flags, record.email.asSlice(), record.email_verified },
    ) catch error.BufferTooSmall;
}

pub fn decodeAccount(value: []const u8) ServiceError!AccountRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    const is_v1 = std.mem.eql(u8, version, account_version);
    const is_v2 = std.mem.eql(u8, version, account_version_v2);
    if (!is_v1 and !is_v2) return error.InvalidRecord;
    const name = try accountKey(it.next() orelse return error.InvalidRecord);
    const salt_hex = it.next() orelse return error.InvalidRecord;
    const hash_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    const email_text = it.next() orelse "";
    const verified_text = if (is_v2) it.next() orelse return error.InvalidRecord else "false";
    if (it.next() != null) return error.InvalidRecord;
    if (salt_hex.len != salt_hex_len or hash_hex.len != hash_hex_len) return error.InvalidRecord;

    var record = AccountRecord{
        .name = name,
        .salt = undefined,
        .hash = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
        .email = try validateEmail(email_text),
        .email_verified = std.mem.eql(u8, verified_text, "true"),
    };
    _ = std.fmt.hexToBytes(&record.salt, salt_hex) catch return error.InvalidRecord;
    _ = std.fmt.hexToBytes(&record.hash, hash_hex) catch return error.InvalidRecord;
    return record;
}

pub fn encodeChannel(record: ChannelRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}",
        .{ channel_version_v2, record.name.asSlice(), record.founder.asSlice(), &gen_hex, record.flags, record.mlock.asSlice() },
    ) catch error.BufferTooSmall;
}

pub fn decodeChannel(value: []const u8) ServiceError!ChannelRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.InvalidRecord;
    const is_v1 = std.mem.eql(u8, version, channel_version);
    const is_v2 = std.mem.eql(u8, version, channel_version_v2);
    if (!is_v1 and !is_v2) return error.InvalidRecord;
    const name = try channelKey(it.next() orelse return error.InvalidRecord);
    const founder = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    const mlock_text = if (is_v2) it.next() orelse return error.InvalidRecord else "";
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = ChannelRecord{
        .name = name,
        .founder = founder,
        .generation = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
        .mlock = try validateMlock(mlock_text),
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

pub fn encodeAccess(record: AccessRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}",
        .{ access_version, record.channel.asSlice(), record.account.asSlice(), &gen_hex, @backingInt(record.level) },
    ) catch error.BufferTooSmall;
}

pub fn decodeAccess(value: []const u8) ServiceError!AccessRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, access_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const account = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const level_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AccessRecord{
        .channel = channel,
        .account = account,
        .generation = undefined,
        .level = levelFromInt(std.fmt.parseInt(u8, level_text, 10) catch return error.InvalidRecord) orelse return error.InvalidRecord,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

pub fn encodeAkick(record: AkickRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{s}|{s}",
        .{ akick_version, record.channel.asSlice(), record.mask.asSlice(), &gen_hex, record.setter.asSlice(), record.reason.asSlice() },
    ) catch error.BufferTooSmall;
}

pub fn decodeAkick(value: []const u8) ServiceError!AkickRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, akick_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const mask = try validateMask(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const setter = try accountKey(it.next() orelse return error.InvalidRecord);
    const reason = try validateReason(it.next() orelse "");
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AkickRecord{
        .channel = channel,
        .mask = mask,
        .generation = undefined,
        .setter = setter,
        .reason = reason,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

pub const PendingVerify = struct {
    account: []const u8,
    email: []const u8,
    token: []const u8,
    issued_ms: u64,
};

pub fn encodeVerify(account: []const u8, email: []const u8, token: []const u8, issued_ms: u64, out: []u8) ServiceError![]const u8 {
    if (hasCtlOrSep(token) or token.len == 0 or token.len > 128) return error.InvalidValue;
    return std.fmt.bufPrint(out, "{s}|{s}|{s}|{s}|{d}", .{ verify_version, account, email, token, issued_ms }) catch error.BufferTooSmall;
}

pub fn decodeVerify(value: []const u8) ServiceError!PendingVerify {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, verify_version)) return error.InvalidRecord;
    const account = it.next() orelse return error.InvalidRecord;
    const email = it.next() orelse return error.InvalidRecord;
    const token = it.next() orelse return error.InvalidRecord;
    const issued_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null) return error.InvalidRecord;
    _ = try accountKey(account);
    _ = try validateEmail(email);
    if (hasCtlOrSep(token) or token.len == 0 or token.len > 128) return error.InvalidRecord;
    return .{
        .account = account,
        .email = email,
        .token = token,
        .issued_ms = std.fmt.parseInt(u64, issued_text, 10) catch return error.InvalidRecord,
    };
}

pub fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    return std.crypto.timing_safe.compare(u8, expected, actual, .big) == .eq;
}

pub fn validateWardField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len == 0 or value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

pub fn validateWardOptionalField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

pub fn wardKey(match: []const u8, pattern: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(match, 16);
    try validateWardField(pattern, 256);
    if (ward_prefix.len + match.len + 1 + pattern.len > @min(out.len, ward_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, ward_prefix ++ "{s}:{s}", .{ match, pattern }) catch error.BufferTooSmall;
}

pub fn encodeWard(ward: ReplayWard, out: []u8) ServiceError![]const u8 {
    try validateWardField(ward.match, 16);
    try validateWardField(ward.pattern, 256);
    try validateWardField(ward.scope, 16);
    try validateWardField(ward.action, 16);
    try validateWardOptionalField(ward.setter, 64);
    try validateWardOptionalField(ward.reason, 512);
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{s}|{s}|{s}|{d}|{d}|{s}|{s}",
        .{
            ward_version,
            ward.match,
            ward.pattern,
            ward.scope,
            ward.action,
            ward.created_ms,
            ward.expires_ms,
            ward.setter,
            ward.reason,
        },
    ) catch error.BufferTooSmall;
}

pub fn decodeWard(value: []const u8) ServiceError!ReplayWard {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, ward_version)) return error.InvalidRecord;
    const match = it.next() orelse return error.InvalidRecord;
    const pattern = it.next() orelse return error.InvalidRecord;
    const scope = it.next() orelse return error.InvalidRecord;
    const action = it.next() orelse return error.InvalidRecord;
    const created = it.next() orelse return error.InvalidRecord;
    const expires = it.next() orelse return error.InvalidRecord;
    const setter = it.next() orelse "";
    const reason = it.next() orelse "";
    if (it.next() != null) return error.InvalidRecord;
    try validateWardField(match, 16);
    try validateWardField(pattern, 256);
    try validateWardField(scope, 16);
    try validateWardField(action, 16);
    try validateWardOptionalField(setter, 64);
    try validateWardOptionalField(reason, 512);
    return .{
        .match = match,
        .pattern = pattern,
        .scope = scope,
        .action = action,
        .created_ms = std.fmt.parseInt(i64, created, 10) catch return error.InvalidRecord,
        .expires_ms = std.fmt.parseInt(i64, expires, 10) catch return error.InvalidRecord,
        .setter = setter,
        .reason = reason,
    };
}

pub fn saccessKey(entry_type: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry_type, saccess_type_max);
    try validateWardField(mask, saccess_mask_max);
    if (saccess_prefix.len + entry_type.len + 1 + mask.len > @min(out.len, saccess_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, saccess_prefix ++ "{s}:{s}", .{ entry_type, mask }) catch error.BufferTooSmall;
}

pub fn encodeSaccess(entry: ReplaySaccess, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry.entry_type, saccess_type_max);
    try validateWardField(entry.mask, saccess_mask_max);
    try validateWardOptionalField(entry.reason, saccess_reason_max);
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{s}|{d}|{s}",
        .{ saccess_version, entry.entry_type, entry.mask, entry.duration, entry.reason },
    ) catch error.BufferTooSmall;
}

pub fn decodeSaccess(value: []const u8) ServiceError!ReplaySaccess {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, saccess_version)) return error.InvalidRecord;
    const entry_type = it.next() orelse return error.InvalidRecord;
    const mask = it.next() orelse return error.InvalidRecord;
    const duration = it.next() orelse return error.InvalidRecord;
    const reason = it.next() orelse "";
    if (it.next() != null) return error.InvalidRecord;
    try validateWardField(entry_type, saccess_type_max);
    try validateWardField(mask, saccess_mask_max);
    try validateWardOptionalField(reason, saccess_reason_max);
    return .{
        .entry_type = entry_type,
        .mask = mask,
        .duration = std.fmt.parseInt(u64, duration, 10) catch return error.InvalidRecord,
        .reason = reason,
    };
}

pub fn levelFromInt(value: u8) ?AccessLevel {
    return switch (value) {
        @backingInt(AccessLevel.voice) => .voice,
        @backingInt(AccessLevel.op) => .op,
        @backingInt(AccessLevel.admin) => .admin,
        @backingInt(AccessLevel.founder) => .founder,
        else => null,
    };
}

pub fn accessKey(channel: []const u8, account: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(access_prefix, channel, account, out);
}

pub fn akickKey(channel: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(akick_prefix, channel, mask, out);
}

pub fn prefixedKey(prefix: []const u8, channel: []const u8, tail: []const u8, out: []u8) ServiceError![]const u8 {
    if (prefix.len + channel.len + 1 + tail.len > out.len) return error.BufferTooSmall;
    var len: usize = 0;
    @memcpy(out[len..][0..prefix.len], prefix);
    len += prefix.len;
    @memcpy(out[len..][0..channel.len], channel);
    len += channel.len;
    out[len] = ':';
    len += 1;
    @memcpy(out[len..][0..tail.len], tail);
    len += tail.len;
    return out[0..len];
}

pub fn sameBytes(comptime len: usize, a: *const [len]u8, b: *const [len]u8) bool {
    return std.crypto.timing_safe.eql([len]u8, a.*, b.*);
}
