// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process IRC services over OroStore with typed results and no IRC I/O.
const std = @import("std");

const store_mod = @import("store.zig");
const toml = @import("../proto/toml.zig");
const scram_store_mod = @import("scram_store.zig");
const sasl = @import("../proto/sasl.zig");
const certfp_bind_mod = @import("certfp_bind.zig");
const webauthn_creds = @import("webauthn_creds.zig");
const key_transparency = @import("key_transparency.zig");
const mmr = @import("../substrate/merkle_mountain_range.zig");
const rwlock = @import("../substrate/rwlock.zig");
const svc_enforce = @import("svc_enforce.zig");
const svc_acclist = @import("svc_acclist.zig");
const svc_chanbadwords = @import("svc_chanbadwords.zig");

pub const OroStore = store_mod.OroStore;
pub const ScramStore = scram_store_mod.ScramStore;

const account_max = 32;
const channel_max = 64;
const nick_max = 64;
const email_max = 96;
const mlock_max = 128;
const mask_max = 160;
const reason_max = 128;
const key_max = 256;
const record_max = 768;
const salt_len = 16;
const hash_len = 32;
const salt_hex_len = salt_len * 2;
const hash_hex_len = hash_len * 2;
const generation_len = 16;
const generation_hex_len = generation_len * 2;
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

const account_version = "A1";
const account_version_v2 = "A2";
const channel_version = "C1";
const channel_version_v2 = "C2";
const access_version = "X1";
const akick_version = "K1";
const verify_version = "V1";
const ward_version = "W1";
const saccess_version = "S1";
const access_prefix = "chanaccess:";
const akick_prefix = "chanakick:";
const verify_prefix = "acctverify:";
const ward_prefix = "ward:";
const saccess_prefix = "saccess:";
const missing_account_salt: [salt_len]u8 = .{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x2d,
    0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
};
pub const session_token_prefix = "sst_";
pub const session_token_random_len: usize = 16;
pub const session_token_len: usize = session_token_prefix.len + session_token_random_len * 2;
pub const default_session_token_ttl_seconds: i64 = 30 * 24 * 60 * 60;

pub const channel_access_family = store_mod.Family.props;

const StorePutError = @typeInfo(@typeInfo(@TypeOf(OroStore.put)).@"fn".return_type.?).error_union.error_set;
const StoreDeleteError = @typeInfo(@typeInfo(@TypeOf(OroStore.delete)).@"fn".return_type.?).error_union.error_set;
const Pbkdf2Error = @typeInfo(@typeInfo(@TypeOf(std.crypto.pwhash.pbkdf2)).@"fn".return_type.?).error_union.error_set;

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
        return @intFromEnum(self) >= @intFromEnum(needed);
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
pub const account_flags_privileged: u32 = account_flag_suspended | account_flag_forbidden | account_flag_noexpire;

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

const AccountRecord = struct {
    name: AccountName,
    salt: [salt_len]u8,
    hash: [hash_len]u8,
    email: Email = Email.empty(),
    email_verified: bool = false,
    flags: u32 = 0,

    fn info(self: AccountRecord) AccountInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags };
    }

    fn adminInfo(self: AccountRecord) AccountAdminInfo {
        return .{ .name = self.name, .email = self.email, .email_verified = self.email_verified, .flags = self.flags, .registered = true };
    }
};

const ChannelRecord = struct {
    name: ChannelName,
    founder: AccountName,
    generation: [generation_len]u8,
    flags: u32 = 0,
    mlock: Mlock = Mlock.empty(),

    fn info(self: ChannelRecord) ChannelInfo {
        return .{ .name = self.name, .founder = self.founder, .flags = self.flags, .mlock = self.mlock };
    }
};

const AccessRecord = struct {
    channel: ChannelName,
    account: AccountName,
    generation: [generation_len]u8,
    level: AccessLevel,

    fn info(self: AccessRecord) AccessInfo {
        return .{ .channel = self.channel, .account = self.account, .level = self.level };
    }
};

const AkickRecord = struct {
    channel: ChannelName,
    mask: Mask,
    generation: [generation_len]u8,
    setter: AccountName,
    reason: Reason = Reason.empty(),

    fn info(self: AkickRecord) AkickInfo {
        return .{ .channel = self.channel, .mask = self.mask, .setter = self.setter, .reason = self.reason };
    }
};

pub const Services = struct {
    store: *OroStore,
    state: ?StateHook = null,
    cfg: Config = .{},
    /// Optional SCRAM-SHA-256 credential mirror. When set, account registration
    /// additionally derives and stores `{salt, iters, StoredKey, ServerKey}` so
    /// the daemon can advertise and complete SCRAM-SHA-256. PLAIN remains the
    /// source of truth in the persistent account record; this is an in-memory
    /// companion (see scram_store.zig). Null leaves SCRAM unprovisioned, exactly
    /// matching the historical PLAIN-only behaviour.
    scram: ?*ScramStore = null,
    /// Optional account ⇄ TLS certfp bindings, backing SASL EXTERNAL (CERTADD).
    /// In-memory companion (see certfp_bind.zig); null = EXTERNAL has nothing to
    /// match and fails closed.
    certfp_binds: ?*certfp_bind_mod.CertfpBindStore = null,
    /// Optional append-only key-transparency log for account credential changes.
    /// The log must outlive `self`; append failures are non-fatal until the log is
    /// exposed as a client/operator contract.
    key_transparency: ?*key_transparency.KeyTransparencyLog = null,
    lock: rwlock.RwLock = .{},

    pub fn init(store: *OroStore, state: ?StateHook) Services {
        return .{ .store = store, .state = state };
    }

    pub fn initWithConfig(store: *OroStore, state: ?StateHook, cfg: Config) Services {
        return .{ .store = store, .state = state, .cfg = cfg };
    }

    /// Attach a SCRAM credential mirror. Accounts registered after this call
    /// gain SCRAM-SHA-256 material; the store must outlive `self`.
    pub fn attachScramStore(self: *Services, scram: *ScramStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.scram = scram;
    }

    /// Attach the account ⇄ certfp binding store (for SASL EXTERNAL / CERTADD).
    /// The store must outlive `self`.
    pub fn attachCertfpBinds(self: *Services, binds: *certfp_bind_mod.CertfpBindStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.certfp_binds = binds;
    }

    /// Attach the account credential transparency log. Credential mutations
    /// append canonical events under the services lock.
    pub fn attachKeyTransparencyLog(self: *Services, log: *key_transparency.KeyTransparencyLog) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.key_transparency = log;
    }

    pub const KeyTransparencyStatus = struct {
        enabled: bool,
        entries: usize = 0,
        root: key_transparency.Hash = @splat(0),
    };

    pub const KeyTransparencyProofStep = struct {
        side: mmr.Side,
        hash: key_transparency.Hash,
    };

    pub const KeyTransparencyProofSnapshot = struct {
        position: usize,
        size: usize,
        root: key_transparency.Hash,
        path: []KeyTransparencyProofStep,
        peaks: []key_transparency.Hash,

        pub fn deinit(self: *KeyTransparencyProofSnapshot, allocator: std.mem.Allocator) void {
            allocator.free(self.path);
            allocator.free(self.peaks);
            self.* = undefined;
        }
    };

    /// Return the current credential transparency root/size for status surfaces.
    pub fn keyTransparencyStatus(self: *Services) KeyTransparencyStatus {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency orelse return .{ .enabled = false };
        return .{
            .enabled = true,
            .entries = log.len(),
            .root = log.root(),
        };
    }

    /// Copy an inclusion proof for `position` into caller-owned memory. The
    /// returned snapshot is stable after the services lock releases.
    pub fn keyTransparencyProof(self: *Services, allocator: std.mem.Allocator, position: usize) (std.mem.Allocator.Error || error{ Disabled, IndexOutOfRange })!KeyTransparencyProofSnapshot {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const log = self.key_transparency orelse return error.Disabled;
        var proof = log.proof(position) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.IndexOutOfRange => return error.IndexOutOfRange,
        };
        defer proof.deinit(log.tree.allocator);

        const path = try allocator.alloc(KeyTransparencyProofStep, proof.path.len);
        errdefer allocator.free(path);
        for (proof.path, 0..) |step, i| {
            path[i] = .{ .side = step.side, .hash = step.hash };
        }

        const peaks = try allocator.alloc(key_transparency.Hash, proof.peaks.len);
        errdefer allocator.free(peaks);
        @memcpy(peaks, proof.peaks);

        return .{
            .position = position,
            .size = log.len(),
            .root = log.root(),
            .path = path,
            .peaks = peaks,
        };
    }

    /// Force the backing OroStore into a compact snapshot for external backup.
    /// The caller may copy `store.snapshot_path` after this returns. Serialized with
    /// normal services mutations so the snapshot represents a whole store state.
    pub fn compactStoreForBackup(self: *Services) !void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        try self.store.snapshotAndTruncate();
    }

    fn validateNewPassword(self: *const Services, password: []const u8) ServiceError!void {
        try validatePasswordPolicy(password, self.cfg.password_min_len, self.cfg.password_max_len);
    }

    /// Bind a TLS certfp to an account (the CERTADD command). Caller has verified
    /// the account is the caller's own logged-in account.
    pub fn bindCertfp(self: *Services, account: []const u8, fingerprint: []const u8) certfp_bind_mod.CertfpBindError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const binds = self.certfp_binds orelse return error.InvalidFingerprint;
        try binds.bind(account, fingerprint);
        // Mirror the binding into the durable store, keyed by fingerprint, so it
        // survives a restart. In-memory is authoritative for this session; the
        // store is a best-effort durable mirror (a WAL hiccup must not fail the
        // already-applied in-memory bind).
        var kb: [certfp_key_max]u8 = undefined;
        if (certfpKey(&kb, fingerprint)) |k| {
            self.store.family(.props).put(k, account) catch {};
        }
        self.addCertfpListEntry(account, fingerprint) catch {};
        self.recordKeyTransparency(account, .certfp, .bind, fingerprint, fingerprint, 0);
    }

    /// List certfps bound to `account` by CERTADD. Output slices borrow durable
    /// store memory and remain valid until the next mutation.
    pub fn listCertfps(self: *Services, account: []const u8, out: [][]const u8) ServiceError![]const []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const value = self.store.family(.props).get(list_key) orelse return out[0..0];
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
    pub fn deleteCertfp(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(account);
        const owner = try self.certfpOwnerUnlocked(fingerprint);
        if (!std.ascii.eqlIgnoreCase(owner, key.asSlice())) return error.Forbidden;

        if (self.certfp_binds) |binds| _ = binds.unbind(fingerprint);
        var fp_key_buf: [certfp_key_max]u8 = undefined;
        if (certfpKey(&fp_key_buf, fingerprint)) |fp_key| self.store.family(.props).delete(fp_key) catch {};
        try self.removeCertfpListEntry(key.asSlice(), fingerprint);
        self.recordKeyTransparency(key.asSlice(), .certfp, .delete, fingerprint, fingerprint, 0);
    }

    // -- WebAuthn (passkey) credentials --------------------------------------
    //
    // Durable credential storage mirroring the certfp pattern: each credential
    // is a `.props` record keyed by its (unique) credential id, plus a per-
    // account newline-separated list of credential ids for LIST/allow-list.
    // All record encode/decode + validation lives in `webauthn_creds.zig`; these
    // methods only serialize store access under the Services lock and copy every
    // borrowed value out before releasing it. The durable store IS authoritative
    // (no in-memory companion): verification is stateless and the single-use
    // challenge lives in per-connection state.

    /// A credential looked up by id, with all bytes copied out (valid after the
    /// lock is released). `cose_key` holds the raw COSE_Key CBOR public key.
    pub const WebauthnCredential = struct {
        account_buf: [account_max]u8 = undefined,
        account_len: usize = 0,
        sign_count: u32 = 0,
        created_unix: i64 = 0,
        cose_key_buf: [webauthn_creds.max_cose_key_bytes]u8 = undefined,
        cose_key_len: usize = 0,
        label_buf: [webauthn_creds.max_label_bytes]u8 = undefined,
        label_len: usize = 0,

        pub fn account(self: *const WebauthnCredential) []const u8 {
            return self.account_buf[0..self.account_len];
        }
        pub fn coseKey(self: *const WebauthnCredential) []const u8 {
            return self.cose_key_buf[0..self.cose_key_len];
        }
        pub fn label(self: *const WebauthnCredential) []const u8 {
            return self.label_buf[0..self.label_len];
        }
    };

    /// A LIST entry, with credential id + label copied out.
    pub const WebauthnListEntry = struct {
        cred_id_buf: [webauthn_creds.max_cred_id_b64]u8 = undefined,
        cred_id_len: usize = 0,
        label_buf: [webauthn_creds.max_label_bytes]u8 = undefined,
        label_len: usize = 0,
        sign_count: u32 = 0,
        created_unix: i64 = 0,

        pub fn credId(self: *const WebauthnListEntry) []const u8 {
            return self.cred_id_buf[0..self.cred_id_len];
        }
        pub fn label(self: *const WebauthnListEntry) []const u8 {
            return self.label_buf[0..self.label_len];
        }
    };

    /// Bind a passkey credential to `account`. `cose_key` is the raw COSE_Key
    /// CBOR public key extracted from the registration authData. Fail-closed:
    /// rejects a malformed/oversized id or key, a duplicate id (already bound to
    /// any account), and enforces the per-account credential cap. Writes are
    /// ordered so a failure leaves no half-bound state (record rolled back if the
    /// list update fails).
    pub fn webauthnBind(
        self: *Services,
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
        if (self.store.family(.props).get(cred_key) != null) return error.AlreadyExists;

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
        const existing = self.store.family(.props).get(list_key) orelse "";
        var new_list_buf: [webauthn_creds.account_list_value_max]u8 = undefined;
        const new_list = (webauthn_creds.listAppend(existing, cred_id_b64, &new_list_buf) catch |e| switch (e) {
            error.ListFull => return error.AlreadyExists,
            else => return error.BufferTooSmall,
        }) orelse return error.AlreadyExists; // already present under this account

        // Record first, then list; roll the record back if the list write fails.
        try self.store.family(.props).put(cred_key, record);
        self.store.family(.props).put(list_key, new_list) catch |e| {
            self.store.family(.props).delete(cred_key) catch {};
            return e;
        };
        self.recordKeyTransparency(key.asSlice(), .webauthn, .bind, cred_id_b64, cose_key, now_unix * 1000);
    }

    /// Look up a credential by id, copying its account, COSE key, counter, and
    /// label out under the lock. Returns `NotFound` when unbound.
    pub fn webauthnLookup(self: *Services, cred_id_b64: []const u8, out: *WebauthnCredential) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.NotFound;

        self.lock.lockShared();
        defer self.lock.unlockShared();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.family(.props).get(cred_key) orelse return error.NotFound;
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
    pub fn webauthnUpdateSignCount(self: *Services, cred_id_b64: []const u8, new_count: u32) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.NotFound;

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;
        // Re-encode with the new counter, preserving every other field verbatim.
        var rec_buf: [webauthn_creds.record_value_max]u8 = undefined;
        const record = webauthn_creds.encodeRecord(rec.account, new_count, rec.created_unix, rec.label_b64, rec.cose_key_b64, &rec_buf) catch
            return error.BufferTooSmall;
        try self.store.family(.props).put(cred_key, record);
    }

    /// Update the user label of a passkey the caller owns, identified by
    /// credential id. Fail-closed: `NotFound` when the id is unbound, `Forbidden`
    /// when it resolves to a different account, `InvalidValue` on a malformed id
    /// or an over-long label. Every other record field is preserved verbatim.
    pub fn webauthnRename(self: *Services, account: []const u8, cred_id_b64: []const u8, label: []const u8) ServiceError!void {
        if (!webauthn_creds.validCredIdB64(cred_id_b64)) return error.InvalidValue;
        if (!webauthn_creds.validLabel(label)) return error.InvalidValue;
        const key = try accountKey(account); // validates + lowercases

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
        const cred_key = webauthn_creds.credKey(&cred_key_buf, cred_id_b64) orelse return error.NotFound;
        const value = self.store.family(.props).get(cred_key) orelse return error.NotFound;
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
        try self.store.family(.props).put(cred_key, record);
    }

    /// List the passkeys bound to `account` into `out`, returning the populated
    /// prefix. Silently skips any list entry whose record is missing/corrupt.
    pub fn webauthnList(self: *Services, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        const key = try accountKey(account);

        self.lock.lockShared();
        defer self.lock.unlockShared();

        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const list = self.store.family(.props).get(list_key) orelse return out[0..0];

        var ids_buf: [webauthn_creds.max_creds_per_account][]const u8 = undefined;
        const ids = webauthn_creds.listIds(list, &ids_buf);
        var n: usize = 0;
        for (ids) |id| {
            if (n >= out.len) break;
            if (id.len > out[n].cred_id_buf.len) continue;
            var cred_key_buf: [webauthn_creds.cred_key_max]u8 = undefined;
            const cred_key = webauthn_creds.credKey(&cred_key_buf, id) orelse continue;
            const value = self.store.family(.props).get(cred_key) orelse continue;
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
    pub fn webauthnCredIds(self: *Services, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        return self.webauthnList(account, out);
    }

    /// Delete a credential from `account`, identified by its credential id OR its
    /// label. Verifies ownership. `NotFound` when no matching credential exists;
    /// `Forbidden` when the id resolves to a different account.
    pub fn webauthnDelete(self: *Services, account: []const u8, id_or_label: []const u8) ServiceError!void {
        const key = try accountKey(account);

        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        // Resolve the target credential id: try a direct id match, else scan the
        // account's list for a label match.
        var list_key_buf: [webauthn_creds.account_list_key_max]u8 = undefined;
        const list_key = webauthn_creds.accountListKey(&list_key_buf, key.asSlice()) orelse return error.BufferTooSmall;
        const list = self.store.family(.props).get(list_key) orelse return error.NotFound;

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
                const value = self.store.family(.props).get(cred_key) orelse continue;
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
        const value = self.store.family(.props).get(cred_key) orelse return error.NotFound;
        const rec = webauthn_creds.decodeRecord(value) catch return error.InvalidRecord;
        if (!std.ascii.eqlIgnoreCase(rec.account, key.asSlice())) return error.Forbidden;
        var cose_key_buf: [webauthn_creds.max_cose_key_bytes]u8 = undefined;
        const cose_key = rec.decodeCoseKey(&cose_key_buf) catch return error.InvalidRecord;

        // Remove from the list, then delete the record.
        var new_list_buf: [webauthn_creds.account_list_value_max]u8 = undefined;
        const new_list = (webauthn_creds.listRemove(list, target, &new_list_buf) catch return error.BufferTooSmall) orelse
            return error.NotFound;
        if (new_list.len == 0) {
            self.store.family(.props).delete(list_key) catch {};
        } else {
            try self.store.family(.props).put(list_key, new_list);
        }
        self.store.family(.props).delete(cred_key) catch {};
        self.recordKeyTransparency(key.asSlice(), .webauthn, .delete, target, cose_key, 0);
    }

    /// Mirror an account's derived SCRAM tuple into the durable store, keyed by
    /// account. Serializes BOTH the SHA-256 and (when provisioned) SHA-512
    /// material in a single backward-compatible record so a SCRAM-SHA-256 OR
    /// SCRAM-SHA-512 login resolves after a restart. Best-effort; the in-memory
    /// SCRAM store is authoritative live.
    fn persistScram(self: *Services, scram: *ScramStore, account: []const u8) void {
        const rec256 = scram.lookup(account) orelse return;
        var full = ScramStore.FullRecord{
            .salt = rec256.salt,
            .iterations = rec256.iterations,
            .stored_key = rec256.stored_key,
            .server_key = rec256.server_key,
        };
        if (scram.lookup512(account)) |rec512| {
            full.has_512 = true;
            full.stored_key_512 = rec512.stored_key;
            full.server_key_512 = rec512.server_key;
        }
        var vbuf: [ScramStore.serialized_max]u8 = undefined;
        const value = ScramStore.serializeFullRecord(full, &vbuf) orelse return;
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return;
        self.store.family(.props).put(key, value) catch {};
    }

    /// A backfill loader for the SCRAM store that reads this services' durable
    /// mirror, so a SCRAM login resolves after a restart. The returned record's
    /// salt borrows store memory and is copied by the SCRAM store before caching.
    /// Carries SHA-512 material when the durable record includes it.
    pub fn scramLoader(self: *Services) ScramStore.Loader {
        return .{ .ptr = self, .loadFn = scramLoadThunk };
    }

    fn scramLoadThunk(ptr: *anyopaque, account: []const u8) ?ScramStore.FullRecord {
        const self: *Services = @ptrCast(@alignCast(ptr));
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return null;
        const bytes = self.store.family(.props).get(key) orelse return null;
        return ScramStore.deserializeFullRecord(bytes);
    }

    /// The account a certfp is bound to, if any (SASL EXTERNAL verification).
    /// Falls back to the durable store when the in-memory cache is cold (e.g.
    /// immediately after a restart, before any CERTADD has repopulated it).
    pub fn accountForCertfp(self: *const Services, fingerprint: []const u8) ?[]const u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        return @constCast(self).accountForCertfpUnlocked(fingerprint) catch null;
    }

    /// Issue a durable SASL SESSION-TOKEN for an already-authenticated services
    /// account. The raw token is returned once to the caller; only SHA-256(token)
    /// and expiry metadata are stored.
    pub fn issueSessionToken(self: *Services, account: []const u8, now_unix: i64) ServiceError!SessionTokenIssue {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(account);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        const record = try decodeAccount(value);
        if ((record.flags & account_flag_suspended) != 0 or (record.flags & account_flag_forbidden) != 0) return error.AuthFailed;

        var token: [session_token_len]u8 = undefined;
        @memcpy(token[0..session_token_prefix.len], session_token_prefix);
        var random: [session_token_random_len]u8 = undefined;
        self.store.io.randomSecure(&random) catch return error.RandomUnavailable;
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
        if (self.store.family(.props).get(acct_key)) |old_hash| {
            var old_token_key_buf: [session_token_key_max]u8 = undefined;
            if (old_hash.len == hash_hex_len) {
                if (sessionTokenKey(&old_token_key_buf, old_hash)) |old_token_key| {
                    self.store.family(.props).delete(old_token_key) catch {};
                }
            }
        }

        const expires_unix = now_unix + default_session_token_ttl_seconds;
        var value_buf: [session_token_value_max]u8 = undefined;
        const encoded = try encodeSessionTokenRecord(record.name.asSlice(), expires_unix, hash_hex[0..], &value_buf);
        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return error.BufferTooSmall;
        try self.store.family(.props).put(token_key, encoded);
        try self.store.family(.props).put(acct_key, hash_hex[0..]);

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
        self: *Services,
        authcid: []const u8,
        token: []const u8,
        now_unix: i64,
        account_out: []u8,
    ) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = accountKey(authcid) catch return null;
        if (!validSessionTokenText(token)) return null;

        var digest: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        defer secureZero(digest[0..]);
        var hash_hex = std.fmt.bytesToHex(digest, .lower);
        defer secureZero(hash_hex[0..]);

        var token_key_buf: [session_token_key_max]u8 = undefined;
        const token_key = sessionTokenKey(&token_key_buf, hash_hex[0..]) orelse return null;
        const encoded = self.store.family(.props).get(token_key) orelse return null;
        const record = decodeSessionTokenRecord(encoded) catch return null;
        if (record.expires_unix <= now_unix) return null;
        if (!std.mem.eql(u8, record.account.asSlice(), key.asSlice())) return null;

        var stored_hash: [hash_hex_len]u8 = undefined;
        if (record.hash.len != stored_hash.len) return null;
        @memcpy(&stored_hash, record.hash);
        defer secureZero(stored_hash[0..]);
        const hash_ok = std.crypto.timing_safe.eql([hash_hex_len]u8, stored_hash, hash_hex);
        if (!hash_ok) return null;

        const acct_value = self.store.family(.accounts).get(key.asSlice()) orelse return null;
        const acct_record = decodeAccount(acct_value) catch return null;
        if ((acct_record.flags & account_flag_suspended) != 0 or (acct_record.flags & account_flag_forbidden) != 0) return null;
        if (acct_record.name.asSlice().len > account_out.len) return null;
        @memcpy(account_out[0..acct_record.name.asSlice().len], acct_record.name.asSlice());
        return account_out[0..acct_record.name.asSlice().len];
    }

    /// Revoke any active SASL session token for `account`. A session token is a
    /// password-equivalent re-entry credential, so it must not outlive a change
    /// to the account's second factor — call this when TOTP is enabled or
    /// disabled so a token minted under the old policy cannot bypass the new one.
    /// Best-effort and idempotent.
    pub fn revokeSessionTokens(self: *Services, account: []const u8) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const key = accountKey(account) catch return;
        var acct_key_buf: [session_token_account_key_max]u8 = undefined;
        const acct_key = sessionTokenAccountKey(&acct_key_buf, key.asSlice()) orelse return;
        const old_hash = self.store.family(.props).get(acct_key) orelse return;
        if (old_hash.len == hash_hex_len) {
            var token_key_buf: [session_token_key_max]u8 = undefined;
            if (sessionTokenKey(&token_key_buf, old_hash)) |tk| self.store.family(.props).delete(tk) catch {};
        }
        self.store.family(.props).delete(acct_key) catch {};
    }

    fn accountForCertfpUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        const acct = try self.certfpOwnerUnlocked(fingerprint);
        if (try self.accountSuspendedUnlocked(acct)) return error.AuthFailed;
        // SASL EXTERNAL must honor an admin FORBID too — otherwise a certfp bound
        // before the forbid keeps logging the account in.
        if (self.accountForbiddenUnlocked(acct)) return error.AuthFailed;
        return acct;
    }

    fn certfpOwnerUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        if (self.certfp_binds) |binds| {
            if (binds.accountForFingerprint(fingerprint)) |acct| return acct;
        }
        var kb: [certfp_key_max]u8 = undefined;
        const k = certfpKey(&kb, fingerprint) orelse return error.NotFound;
        return self.store.family(.props).get(k) orelse error.NotFound;
    }

    pub fn registerAccount(self: *Services, name: []const u8, password: []const u8, scratch: []u8) ServiceError!CommandResult {
        return self.registerAccountWithEmail(name, password, null, false, scratch);
    }

    pub fn registerAccountWithEmail(
        self: *Services,
        name: []const u8,
        password: []const u8,
        email: ?[]const u8,
        email_verified: bool,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        if (self.accountForbiddenUnlocked(key.asSlice())) return error.Forbidden;
        if (self.store.family(.accounts).get(key.asSlice()) != null) return error.AlreadyExists;
        try self.validateNewPassword(password);

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);

        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, password, &salt, self.cfg.pbkdf2_rounds);

        const record = AccountRecord{
            .name = AccountName.init(key.asSlice()) catch return error.InvalidName,
            .salt = salt,
            .hash = hash,
            .email = if (email) |value| try validateEmail(value) else Email.empty(),
            .email_verified = email_verified and email != null,
        };
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(key.asSlice(), encoded);

        // Mirror the credential into the SCRAM store, if attached, so a
        // SCRAM-SHA-256 exchange can later verify this account. The canonical
        // (lowercased) name is used so SCRAM lookups match the account key. The
        // PLAIN record above is already persisted and authoritative; a SCRAM
        // mirror failure must not roll that back, so failures map to
        // error.InvalidRecord rather than leaving a half-registered account.
        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), password) catch return error.InvalidRecord;
            // Persist the derived SCRAM tuple so a SCRAM-SHA-256 login still works
            // after a restart (the in-memory store is otherwise re-seeded only on
            // a fresh register/identify). Best-effort: a mirror failure must not
            // roll back the already-persisted PLAIN account record.
            self.persistScram(scram, record.name.asSlice());
        }
        return .{ .registered_account = .{ .name = record.name } };
    }

    pub fn setAccountEmailPending(
        self: *Services,
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
        try self.store.family(.props).put(key, value);
    }

    pub fn confirmAccountEmail(
        self: *Services,
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
        const encoded = self.store.family(.props).get(verify_key_text) orelse return .no_pending;
        const pending = try decodeVerify(encoded);
        if (!std.ascii.eqlIgnoreCase(pending.account, key.asSlice())) return .no_pending;
        if (now_ms >= pending.issued_ms and now_ms - pending.issued_ms >= default_verify_ttl_ms) {
            try self.store.family(.props).delete(verify_key_text);
            return .expired;
        }
        if (!tokenMatches(pending.token, token)) return .bad_token;

        var record = try self.loadAccount(key.asSlice());
        record.email = try validateEmail(pending.email);
        record.email_verified = true;
        try self.saveAccount(record, scratch);
        try self.store.family(.props).delete(verify_key_text);
        return .verified;
    }

    pub fn identifyAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(name);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse {
            try rejectMissingAccount(password, self.cfg.pbkdf2_rounds);
            return error.AuthFailed;
        };
        const record = try decodeAccount(value);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        // A suspended OR admin-forbidden account cannot authenticate: FORBID must
        // lock the owner out of every credential path, matching issueSessionToken
        // and validateSessionToken which already reject both flags.
        if ((record.flags & (account_flag_suspended | account_flag_forbidden)) != 0) return error.AuthFailed;
        return .{ .identified = .{ .name = record.name } };
    }

    pub fn dropAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        try self.store.family(.accounts).delete(record.name.asSlice());
        return .{ .dropped_account = .{ .name = record.name } };
    }

    /// Change an account's password after verifying the presented current one.
    /// Errors: AuthFailed (wrong current password), InvalidPassword (new fails the
    /// length policy or equals the current one). On success the new salt/hash are
    /// persisted and the SCRAM mirror (if any) is re-derived so SCRAM logins track
    /// the new password. All other account fields are preserved.
    pub fn changeAccountPassword(
        self: *Services,
        name: []const u8,
        old_password: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        try verifyPassword(record, old_password, self.cfg.pbkdf2_rounds);
        try self.validateNewPassword(new_password);
        // A change must actually change the password.
        if (std.mem.eql(u8, old_password, new_password)) return error.InvalidPassword;

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);
        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, new_password, &salt, self.cfg.pbkdf2_rounds);
        record.salt = salt;
        record.hash = hash;

        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);

        // Re-derive the SCRAM credential so a SCRAM-SHA-256 login uses the new
        // password; a mirror failure must not roll back the persisted change.
        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), new_password) catch return error.InvalidRecord;
            self.persistScram(scram, record.name.asSlice());
        }
    }

    /// Set an account's password WITHOUT verifying the current one — for an
    /// authenticated RECOVERY flow where the requester has already proven their
    /// identity by a non-knowledge factor (e.g. a connection authenticated by a
    /// client certificate bound to the account). Authorization is the CALLER's
    /// responsibility; this only validates + stores the new password and
    /// re-derives the SCRAM credential. Never expose it on a path that has not
    /// independently verified the requester.
    pub fn setAccountPasswordForced(
        self: *Services,
        name: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        try self.validateNewPassword(new_password);

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);
        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, new_password, &salt, self.cfg.pbkdf2_rounds);
        record.salt = salt;
        record.hash = hash;

        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);

        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), new_password) catch return error.InvalidRecord;
            self.persistScram(scram, record.name.asSlice());
        }
    }

    pub fn ghostAccount(self: *Services, name: []const u8, password: []const u8, nick: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadAccount(name);
        try verifyPassword(record, password, self.cfg.pbkdf2_rounds);
        const clean_nick = try validateNick(nick);
        return .{ .ghosted = .{ .account = record.name, .nick = clean_nick } };
    }

    pub fn setAccount(
        self: *Services,
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
        switch (field) {
            .email => |email| {
                record.email = try validateEmail(email);
                record.email_verified = false;
            },
            .flags => |flags| {
                const preserved = record.flags & account_flags_privileged;
                if ((flags & account_flags_privileged) != preserved) return error.Forbidden;
                record.flags = preserved | (flags & ~account_flags_privileged);
            },
            // SECURE on/off. ENFORCE on/off is stored inverted (`enforce_off`) so
            // the default-0 record keeps today's always-on enforcement.
            .secure => |on| setFlag(&record.flags, account_flag_secure, on),
            .enforce => |on| setFlag(&record.flags, account_flag_enforce_off, !on),
        }
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);
        return .{ .set_account = record.info() };
    }

    pub fn accountInfo(self: *Services, name: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadAccount(name);
        return .{ .account_info = record.info() };
    }

    /// Server-side (no password) read of an account's nick-protection settings,
    /// for the registration sweep. An unknown account yields the protective
    /// default (ENFORCE on, SECURE off). ENFORCETIME is the configured grace,
    /// supplied by the caller as `enforce_seconds` since it is not per-account.
    pub fn accountSecurity(self: *Services, name: []const u8, enforce_seconds: u32) svc_enforce.AccountSecurity {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = accountKey(name) catch return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const value = self.store.family(.accounts).get(key.asSlice()) orelse
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        const record = decodeAccount(value) catch
            return .{ .enforce = true, .enforce_seconds = enforce_seconds };
        return .{
            .secure = (record.flags & account_flag_secure) != 0,
            .enforce = (record.flags & account_flag_enforce_off) == 0,
            .enforce_seconds = enforce_seconds,
        };
    }

    pub fn setAccountSuspended(self: *Services, name: []const u8, suspended: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadAccount(name);
        setFlag(&record.flags, account_flag_suspended, suspended);
        try self.saveAccount(record, scratch);
        return record.adminInfo();
    }

    pub fn setAccountNoExpire(self: *Services, name: []const u8, noexpire: bool, scratch: []u8) ServiceError!AccountAdminInfo {
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
    pub fn setAccountForbidden(self: *Services, name: []const u8, forbidden: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try accountKey(name);
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;

        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            var record = try decodeAccount(value);
            setFlag(&record.flags, account_flag_forbidden, forbidden);
            try self.saveAccount(record, scratch);
            if (forbidden) {
                try self.store.family(.props).put(reservation_key, "1");
            } else {
                try self.store.family(.props).delete(reservation_key);
            }
            return record.adminInfo();
        }

        if (forbidden) {
            try self.store.family(.props).put(reservation_key, "1");
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        if (self.store.family(.props).get(reservation_key) == null) return error.NotFound;
        try self.store.family(.props).delete(reservation_key);
        return .{ .name = key, .registered = false };
    }

    pub fn adminAccountInfo(self: *Services, name: []const u8) ServiceError!AccountAdminInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const key = try accountKey(name);
        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            return (try decodeAccount(value)).adminInfo();
        }
        if (self.accountForbiddenUnlocked(key.asSlice())) {
            return .{ .name = key, .flags = account_flag_forbidden, .registered = false };
        }
        return error.NotFound;
    }

    pub fn registerChannel(self: *Services, channel: []const u8, founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const channel_key = try channelKey(channel);
        if (self.store.family(.chanregs).get(channel_key.asSlice()) != null) return error.AlreadyExists;
        const founder_key = try accountKey(founder);
        if (self.store.family(.accounts).get(founder_key.asSlice()) == null) return error.NotFound;

        var generation: [generation_len]u8 = undefined;
        self.store.io.randomSecure(&generation) catch self.store.io.random(&generation);

        const record = ChannelRecord{
            .name = ChannelName.init(channel_key.asSlice()) catch return error.InvalidChannel,
            .founder = AccountName.init(founder_key.asSlice()) catch return error.InvalidName,
            .generation = generation,
        };
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);

        if (self.state) |hook| try hook.createChannel(record.name.asSlice());

        return .{ .registered_channel = record.info() };
    }

    pub fn dropChannel(self: *Services, channel: []const u8, actor: []const u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .founder);
        try self.store.family(.chanregs).delete(record.name.asSlice());
        if (self.state) |hook| try hook.dropChannel(record.name.asSlice());
        return .{ .dropped_channel = .{ .name = record.name } };
    }

    /// Transfer founder ownership of a registered channel. Only the CURRENT founder
    /// may transfer; the new founder must be a registered account. The new founder
    /// also receives an explicit FOUNDER access grant.
    pub fn transferChannel(self: *Services, channel: []const u8, actor: []const u8, new_founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        const actor_key = try accountKey(actor);
        if (!std.ascii.eqlIgnoreCase(record.founder.asSlice(), actor_key.asSlice())) return error.Forbidden;
        const nf_key = try accountKey(new_founder);
        if (self.store.family(.accounts).get(nf_key.asSlice()) == null) return error.NotFound;

        record.founder = nf_key;
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);
        return .{ .registered_channel = record.info() };
    }

    pub fn channelAccess(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
            .grant, .revoke => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAccessUnlocked(channel, actor, target, action, level, scratch);
            },
        }
    }

    pub fn channelAccessList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AccessInfo,
    ) ServiceError![]AccessInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(access_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const access = try decodeAccess(entry.value_ptr.*);
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = access.info();
            count += 1;
        }
        return out[0..count];
    }

    fn channelAccessUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        // Authorize BEFORE probing target-account existence. All three actions
        // require .admin, so hoisting the gate above the `.accounts` lookup
        // closes a registration-enumeration oracle: without it a non-admin
        // actor distinguished a registered target (Forbidden) from an
        // unregistered one (NotFound) on a channel they do not administer.
        try self.requireAccess(record, actor, .admin);
        const target_key = try accountKey(target);
        if (self.store.family(.accounts).get(target_key.asSlice()) == null) return error.NotFound;

        switch (action) {
            .query => {
                const access = try self.loadAccess(record, target_key.asSlice());
                return .{ .access = access.info() };
            },
            .grant => {
                if (level == .founder) try self.requireAccess(record, actor, .founder);
                const access = try self.putAccess(record, AccountName.init(target_key.asSlice()) catch return error.InvalidName, level, scratch);
                return .{ .access = access.info() };
            },
            .revoke => {
                try self.requireAccess(record, actor, .admin);
                if (std.mem.eql(u8, target_key.asSlice(), record.founder.asSlice())) return error.Forbidden;
                const existing = try self.loadAccess(record, target_key.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try accessKey(record.name.asSlice(), target_key.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .access_revoked = existing.info() };
            },
        }
    }

    pub fn channelAkick(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        switch (action) {
            .query => {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
            .add, .remove => {
                self.lock.lockExclusive();
                defer self.lock.unlockExclusive();
                return self.channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
            },
        }
    }

    pub fn channelAkickList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AkickInfo,
    ) ServiceError![]AkickInfo {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        var prefix_buf: [key_max]u8 = undefined;
        const prefix = try prefixedKey(akick_prefix, record.name.asSlice(), "", &prefix_buf);
        var count: usize = 0;
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            const akick = try decodeAkick(entry.value_ptr.*);
            if (!sameBytes(generation_len, &akick.generation, &record.generation)) continue;
            if (count >= out.len) return error.BufferTooSmall;
            out[count] = akick.info();
            count += 1;
        }
        return out[0..count];
    }

    fn channelAkickUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const clean_mask = try validateMask(mask);
        switch (action) {
            .query => {
                // An AKICK mask + its reason text is moderation state: gate the
                // query with the same .admin requirement as the list-all sibling
                // (channelAkickList) so an actor with no access to the channel
                // cannot read back the ban list mask/reason.
                try self.requireAccess(record, actor, .admin);
                const akick = try self.loadAkick(record, clean_mask.asSlice());
                return .{ .akick = akick.info() };
            },
            .add => {
                try self.requireAccess(record, actor, .admin);
                const actor_key = try accountKey(actor);
                const akick = AkickRecord{
                    .channel = record.name,
                    .mask = clean_mask,
                    .generation = record.generation,
                    .setter = AccountName.init(actor_key.asSlice()) catch return error.InvalidName,
                    .reason = try validateReason(reason),
                };
                const encoded = try encodeAkick(akick, scratch);
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.put(channel_access_family, key, encoded);
                return .{ .akick = akick.info() };
            },
            .remove => {
                try self.requireAccess(record, actor, .admin);
                const existing = try self.loadAkick(record, clean_mask.asSlice());
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .akick_removed = existing.info() };
            },
        }
    }

    pub fn setChannel(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        field: ChannelSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        switch (field) {
            .flags => |flags| record.flags = flags,
            .mlock => |spec| record.mlock = try validateMlock(spec),
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        return .{ .set_channel = record.info() };
    }

    /// Set or clear a single registered-channel boolean flag bit (TOPICLOCK /
    /// GUARD / PRIVATE) while preserving the others. Requires founder-or-admin
    /// ACCESS on the channel. Persists the record so the flag survives recreation.
    pub fn setChannelFlag(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        flag: u32,
        on: bool,
        scratch: []u8,
    ) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        if (on) {
            record.flags |= flag;
        } else {
            record.flags &= ~flag;
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
    }

    /// True when `flag` is set on `channel`'s registration record. False for an
    /// unregistered channel (read-only, no lock contention on the live path).
    pub fn channelFlagSet(self: *Services, channel: []const u8, flag: u32) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const record = self.loadChannel(channel) catch return false;
        return (record.flags & flag) != 0;
    }

    pub fn channelInfo(self: *Services, channel: []const u8) ServiceError!CommandResult {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        return .{ .channel_info = record.info() };
    }

    pub fn channelAccessLevelFor(self: *Services, channel: []const u8, account: []const u8) ServiceError!?AccessLevel {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        const record = try self.loadChannel(channel);
        const key = try accountKey(account);
        if (std.mem.eql(u8, key.asSlice(), record.founder.asSlice())) return .founder;
        const access = self.loadAccess(record, key.asSlice()) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return access.level;
    }

    pub fn persistWard(self: *Services, ward: ReplayWard, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(ward.match, ward.pattern, scratch);
        var value_buf: [ward_value_max]u8 = undefined;
        const value = try encodeWard(ward, &value_buf);
        try self.store.family(.bans).put(key, value);
    }

    pub fn deleteWard(self: *Services, match: []const u8, pattern: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try wardKey(match, pattern, scratch);
        try self.store.family(.bans).delete(key);
    }

    /// Persist (add or replace) one server-level IRCX ACCESS / SACCESS entry so
    /// it survives restart and hot-rebuild. Mirrors `persistWard`: keyed by
    /// `saccess:<type>:<mask>` in the durable `bans` family. Idempotent — a
    /// re-add of the same type+mask overwrites the prior value.
    pub fn persistSaccess(self: *Services, entry: ReplaySaccess, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry.entry_type, entry.mask, scratch);
        var value_buf: [saccess_value_max]u8 = undefined;
        const value = try encodeSaccess(entry, &value_buf);
        try self.store.family(.bans).put(key, value);
    }

    /// Remove one persisted SACCESS entry by type+mask. Restart-safe: a delete
    /// that mutated the live store is durably reflected.
    pub fn deleteSaccess(self: *Services, entry_type: []const u8, mask: []const u8, scratch: []u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const key = try saccessKey(entry_type, mask, scratch);
        try self.store.family(.bans).delete(key);
    }

    /// Remove all persisted SACCESS entries (optionally one type). Mirrors the
    /// live `ServerAccessStore.clear` so a CLEAR is durable across restart.
    ///
    /// Keys are snapshotted into a caller-owned buffer BEFORE any delete: the
    /// store frees the map-owned key on delete, so deleting straight from a
    /// borrowed iterator key would be a use-after-free (the WAL/changefeed
    /// re-reads the key after the map entry is freed).
    pub fn clearSaccess(self: *Services, entry_type: ?[]const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var key_store: [256][saccess_key_max]u8 = undefined;
        var key_lens: [256]usize = undefined;
        var keys_len: usize = 0;
        {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                const key = entry.key_ptr.*;
                if (!std.mem.startsWith(u8, key, saccess_prefix)) continue;
                if (entry_type) |want| {
                    const decoded = decodeSaccess(entry.value_ptr.*) catch continue;
                    if (!std.ascii.eqlIgnoreCase(decoded.entry_type, want)) continue;
                }
                if (keys_len >= key_store.len or key.len > saccess_key_max) continue;
                @memcpy(key_store[keys_len][0..key.len], key);
                key_lens[keys_len] = key.len;
                keys_len += 1;
            }
        }
        for (0..keys_len) |idx| {
            self.store.family(.bans).delete(key_store[idx][0..key_lens[idx]]) catch {};
        }
    }

    // ── Account recognition masks (svc_acclist feature; RECOGNIZE command) ───────
    // Per-account hostmask list. Stored as ONE newline-joined value in the `.props`
    // family — durable, restart-safe, and isolated from account/channel records
    // (so it can never corrupt them). Matching uses `svc_acclist.globMatch`.
    const recognize_prefix = "rcg\x00";
    const recognize_max_masks: usize = svc_acclist.default_max_masks;
    const recognize_mask_max: usize = 128;
    const recognize_key_max: usize = recognize_prefix.len + account_max;
    const recognize_value_max: usize = recognize_max_masks * (recognize_mask_max + 1);

    pub const RecognizeAdd = enum { added, already_present, list_full, invalid_mask };

    fn recognizeKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < recognize_prefix.len + account.len) return null;
        @memcpy(buf[0..recognize_prefix.len], recognize_prefix);
        for (account, 0..) |c, i| buf[recognize_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. recognize_prefix.len + account.len];
    }

    fn validRecognizeMask(mask: []const u8) bool {
        if (mask.len == 0 or mask.len > recognize_mask_max) return false;
        for (mask) |c| {
            if (c < 0x20 or c == '\n' or c == 0) return false;
        }
        return true;
    }

    /// True if `hostmask` (nick!user@host) matches any recognition mask owned by
    /// `account`. Reads the durable mirror, so it is correct immediately after a
    /// restart with no in-memory warm-up.
    pub fn recognizeMatches(self: *Services, account: []const u8, hostmask: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const blob = self.store.family(.props).get(key) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |mask| {
            if (mask.len != 0 and svc_acclist.globMatch(mask, hostmask)) return true;
        }
        return false;
    }

    /// Copy the newline-joined recognition mask blob for `account` into `out`,
    /// returning the populated slice ("" when none). Used by RECOGNIZE LIST.
    pub fn recognizeBlob(self: *Services, account: []const u8, out: []u8) []const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return out[0..0];
        const blob = self.store.family(.props).get(key) orelse return out[0..0];
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Add `mask` to `account`'s recognition list (durable). Idempotent; bounded
    /// by `recognize_max_masks`.
    pub fn recognizeAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!RecognizeAdd {
        if (!validRecognizeMask(mask)) return .invalid_mask;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return .invalid_mask;
        const existing = self.store.family(.props).get(key) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return .already_present;
            count += 1;
        }
        if (count >= recognize_max_masks) return .list_full;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        if (existing.len != 0) {
            w.writeAll(existing) catch return .list_full;
            w.writeAll("\n") catch return .list_full;
        }
        w.writeAll(mask) catch return .list_full;
        try self.store.family(.props).put(key, w.buffered());
        return .added;
    }

    /// Remove `mask` from `account`'s recognition list (durable). Returns whether
    /// a mask was actually removed.
    pub fn recognizeDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [recognize_key_max]u8 = undefined;
        const key = recognizeKey(&kb, account) orelse return false;
        const existing = self.store.family(.props).get(key) orelse return false;
        var vbuf: [recognize_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vbuf);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(m) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.family(.props).delete(key);
        } else {
            try self.store.family(.props).put(key, w.buffered());
        }
        return true;
    }

    // ── Durable account-scoped IRCv3 METADATA (web-client profiles) ─────────────
    // The live metadata store (server.metadata) is in-memory; these helpers mirror
    // a logged-in user's OWN metadata into the durable `.props` family keyed by
    // ACCOUNT, so a profile (avatar/display-name/…) survives a cold restart and is
    // restored into the live store on next login. Value = "<vis-token>\x00<value>".
    // Isolated key namespace ("mda\x00…") — never touches account/channel records.
    const metadata_prefix = "mda\x00";
    const metadata_key_max = 64;
    const metadata_value_max = 512;
    const metadata_full_key_max = metadata_prefix.len + account_max + 1 + metadata_key_max;

    fn metadataAccountPrefix(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < metadata_prefix.len + account.len + 1) return null;
        @memcpy(buf[0..metadata_prefix.len], metadata_prefix);
        for (account, 0..) |c, i| buf[metadata_prefix.len + i] = std.ascii.toLower(c);
        buf[metadata_prefix.len + account.len] = 0;
        return buf[0 .. metadata_prefix.len + account.len + 1];
    }

    fn metadataKey(buf: []u8, account: []const u8, key: []const u8) ?[]const u8 {
        if (key.len == 0 or key.len > metadata_key_max) return null;
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return null;
        if (buf.len < prefix.len + key.len) return null;
        @memcpy(buf[0..prefix.len], prefix);
        @memcpy(buf[prefix.len .. prefix.len + key.len], key);
        return buf[0 .. prefix.len + key.len];
    }

    pub fn metadataPut(self: *Services, account: []const u8, key: []const u8, value: []const u8, vis_token: []const u8) ServiceError!void {
        if (value.len > metadata_value_max or vis_token.len == 0 or vis_token.len > 16) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        var vb: [metadata_value_max + 24]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        w.writeAll(vis_token) catch return;
        w.writeAll("\x00") catch return;
        w.writeAll(value) catch return;
        try self.store.family(.props).put(k, w.buffered());
    }

    pub fn metadataDelete(self: *Services, account: []const u8, key: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [metadata_full_key_max]u8 = undefined;
        const k = metadataKey(&kb, account, key) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// Invoke `cb(ctx, key, value, vis_token)` for every durable metadata entry
    /// owned by `account`. Used to restore a user's profile metadata at login.
    pub fn metadataForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, []const u8, []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var pb: [metadata_full_key_max]u8 = undefined;
        const prefix = metadataAccountPrefix(&pb, account) orelse return;
        var it = self.store.maps[@intFromEnum(store_mod.Family.props)].map.iterator();
        while (it.next()) |entry| {
            const k = entry.key_ptr.*;
            if (!std.mem.startsWith(u8, k, prefix)) continue;
            const blob = entry.value_ptr.*;
            const sep = std.mem.indexOfScalar(u8, blob, 0) orelse continue;
            cb(ctx, k[prefix.len..], blob[sep + 1 ..], blob[0..sep]);
        }
    }

    // ── Durable account-scoped SILENCE (ignore list survives reconnect/restart) ──
    // One newline-joined blob per account in `.props` ("sil\x00<account>"). The live
    // per-nick `server.silence` store is restored from this at login.
    const silence_prefix = "sil\x00";
    const silence_max_masks: usize = 64;
    const silence_mask_max: usize = 128;
    const silence_key_max: usize = silence_prefix.len + account_max;
    const silence_value_max: usize = silence_max_masks * (silence_mask_max + 1);

    fn silenceKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < silence_prefix.len + account.len) return null;
        @memcpy(buf[0..silence_prefix.len], silence_prefix);
        for (account, 0..) |c, i| buf[silence_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. silence_prefix.len + account.len];
    }

    pub fn silencePersistAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        if (mask.len == 0 or mask.len > silence_mask_max) return;
        for (mask) |c| if (c < 0x20 or c == '\n' or c == 0) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) return;
            count += 1;
        }
        if (count >= silence_max_masks) return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return;
            w.writeAll("\n") catch return;
        }
        w.writeAll(mask) catch return;
        try self.store.family(.props).put(k, w.buffered());
    }

    pub fn silencePersistDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const existing = self.store.family(.props).get(k) orelse return;
        var vb: [silence_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |m| {
            if (m.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(m, mask)) continue;
            if (remaining != 0) w.writeAll("\n") catch return;
            w.writeAll(m) catch return;
            remaining += 1;
        }
        if (remaining == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, w.buffered());
        }
    }

    /// Invoke `cb(ctx, mask)` for each persisted SILENCE mask owned by `account`.
    pub fn silenceForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [silence_key_max]u8 = undefined;
        const k = silenceKey(&kb, account) orelse return;
        const blob = self.store.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |m| {
            if (m.len != 0) cb(ctx, m);
        }
    }

    // ── Durable Web Push subscriptions (per-account blob) ───────────────────────
    // One serialized subscription list per account in `.props` ("wps\x00<account>").
    // The blob format is owned by daemon/webpush.zig (encodeList/decodeList);
    // services just stores it. Same private-namespace rule as TOTP: never
    // reachable through the METADATA command surface.
    const webpush_prefix = "wps\x00";
    const webpush_key_max = webpush_prefix.len + account_max;
    /// 3 subscriptions × (512-byte endpoint + b64url keys + separators), rounded up.
    pub const webpush_value_max: usize = 4096;

    fn webpushKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < webpush_prefix.len + account.len) return null;
        @memcpy(buf[0..webpush_prefix.len], webpush_prefix);
        for (account, 0..) |c, i| buf[webpush_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. webpush_prefix.len + account.len];
    }

    /// Copy of the account's stored subscription blob (caller frees), or null.
    pub fn webpushGetAlloc(self: *Services, allocator: std.mem.Allocator, account: []const u8) ?[]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, account) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        return allocator.dupe(u8, blob) catch null;
    }

    /// Replace the account's subscription blob; empty blob deletes the record.
    pub fn webpushPut(self: *Services, account: []const u8, blob: []const u8) ServiceError!void {
        if (blob.len > webpush_value_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [webpush_key_max]u8 = undefined;
        const k = webpushKey(&kb, account) orelse return;
        if (blob.len == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, blob);
        }
    }

    // ── Durable account-scoped TOTP secret (2FA enrollment survives restart) ────
    // The base32 shared secret for an account's ACTIVE TOTP enrollment, stored in
    // the private `.props` family under "tot\x00<account>". This namespace is
    // NEVER exposed via the IRCv3 METADATA command (which reads only the "mda\x00"
    // prefix), so the secret is not client-readable — it is server-side state used
    // solely to verify a login second factor. Only a confirmed enrollment is
    // persisted; a pending (unconfirmed) secret lives only in the in-memory store.
    pub const totp_secret_max: usize = 64; // base32 of up to ~40 raw bytes
    const totp_prefix = "tot\x00";
    const totp_key_max: usize = totp_prefix.len + account_max;

    fn totpKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < totp_prefix.len + account.len) return null;
        @memcpy(buf[0..totp_prefix.len], totp_prefix);
        for (account, 0..) |c, i| buf[totp_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. totp_prefix.len + account.len];
    }

    /// Persist `secret_b32` as the account's active TOTP secret (overwrites any
    /// prior). No-op on an empty / over-long secret.
    pub fn totpSecretPut(self: *Services, account: []const u8, secret_b32: []const u8) ServiceError!void {
        if (secret_b32.len == 0 or secret_b32.len > totp_secret_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return;
        try self.store.family(.props).put(k, secret_b32);
    }

    /// Copy the account's persisted TOTP secret into `out`, or null when none is
    /// stored (or it does not fit `out`). The returned slice aliases `out`.
    pub fn totpSecretGet(self: *Services, account: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return null;
        const v = self.store.family(.props).get(k) orelse return null;
        if (v.len == 0 or v.len > out.len) return null;
        @memcpy(out[0..v.len], v);
        return out[0..v.len];
    }

    /// Remove the account's persisted TOTP secret (disable 2FA). Idempotent.
    pub fn totpSecretDelete(self: *Services, account: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// True when the account has a persisted (active) TOTP secret.
    pub fn totpEnrolled(self: *Services, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [totp_key_max]u8 = undefined;
        const k = totpKey(&kb, account) orelse return false;
        return self.store.family(.props).get(k) != null;
    }

    // ── Account recovery codes (Era 2 B8) ───────────────────────────────────
    // Single-use offline login codes. Stored hashed under props key
    // "rcd\x00<account>" (never client-readable via METADATA). Format of value:
    // concatenation of remaining 32-byte SHA-256 digests (count = value.len/32).
    pub const recovery_code_count: usize = 10;
    pub const recovery_code_raw_len: usize = 10; // printable alnum body (no dashes)
    pub const recovery_digest_len: usize = 32;
    const rcd_prefix = "rcd\x00";
    const rcd_key_max: usize = rcd_prefix.len + account_max;
    const rcd_blob_max: usize = recovery_code_count * recovery_digest_len;

    fn rcdKey(buf: []u8, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > account_max) return null;
        if (buf.len < rcd_prefix.len + account.len) return null;
        @memcpy(buf[0..rcd_prefix.len], rcd_prefix);
        for (account, 0..) |c, i| buf[rcd_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. rcd_prefix.len + account.len];
    }

    fn hashRecoveryCode(out: *[recovery_digest_len]u8, account: []const u8, code: []const u8) void {
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
    pub fn recoveryCodesRemaining(self: *Services, account: []const u8) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return 0;
        const v = self.store.family(.props).get(k) orelse return 0;
        if (v.len % recovery_digest_len != 0) return 0;
        return v.len / recovery_digest_len;
    }

    /// Replace all recovery codes for `account` with `codes` (plaintext). Stores only digests.
    pub fn recoveryCodesReplace(self: *Services, account: []const u8, codes: []const []const u8) ServiceError!void {
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
        try self.store.family(.props).put(k, blob[0..offset]);
    }

    /// Delete all recovery codes for `account` (idempotent).
    pub fn recoveryCodesClear(self: *Services, account: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// Consume one matching recovery code (constant-time scan). On success the
    /// digest is removed from the blob. Returns AuthFailed when none match.
    pub fn recoveryCodeConsume(self: *Services, account: []const u8, code: []const u8) ServiceError!void {
        if (code.len == 0 or code.len > 64) return error.AuthFailed;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [rcd_key_max]u8 = undefined;
        const k = rcdKey(&kb, account) orelse return error.NotFound;
        const v = self.store.family(.props).get(k) orelse return error.AuthFailed;
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
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, new_blob[0..w]);
        }
    }

    /// Invoke `cb(ctx, channel, level)` for every channel where `account` holds a
    /// live access grant — the durable reverse of `channelAccessList`, backing
    /// LISTCHANS. Stale grants (channel dropped, or dropped+re-registered) are
    /// skipped by re-checking the channel's current generation.
    pub fn channelsForAccount(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, AccessLevel) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
        while (it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, access_prefix)) continue;
            const access = decodeAccess(entry.value_ptr.*) catch continue;
            if (!std.ascii.eqlIgnoreCase(access.account.asSlice(), account)) continue;
            const record = self.loadChannel(access.channel.asSlice()) catch continue;
            if (!sameBytes(generation_len, &access.generation, &record.generation)) continue;
            cb(ctx, access.channel.asSlice(), access.level);
        }
    }

    // ── Durable per-channel bad-word filter (svc_chanbadwords; CHANBADWORDS) ─────
    // One newline-joined pattern blob per channel in `.props` ("cbw\x00<channel>"),
    // channel-op managed. A non-op/non-oper channel message containing any pattern
    // (case-insensitive substring, via svc_chanbadwords.containsIgnoreCase) is
    // blocked. Read straight from the store, so it is correct across restarts.
    const chanbadword_prefix = "cbw\x00";
    const chanbadword_max: usize = 64;
    const chanbadword_pattern_max: usize = 128;
    const chanbadword_key_max: usize = chanbadword_prefix.len + channel_max;
    const chanbadword_value_max: usize = chanbadword_max * (chanbadword_pattern_max + 1);

    fn chanBadwordKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < chanbadword_prefix.len + channel.len) return null;
        @memcpy(buf[0..chanbadword_prefix.len], chanbadword_prefix);
        for (channel, 0..) |c, i| buf[chanbadword_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. chanbadword_prefix.len + channel.len];
    }

    pub fn chanBadwordAdd(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        if (pattern.len == 0 or pattern.len > chanbadword_pattern_max) return false;
        for (pattern) |c| if (c < 0x20 or c == '\n' or c == 0) return false;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.family(.props).get(k) orelse "";
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) return false;
            count += 1;
        }
        if (count >= chanbadword_max) return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        if (existing.len != 0) {
            w.writeAll(existing) catch return false;
            w.writeAll("\n") catch return false;
        }
        w.writeAll(pattern) catch return false;
        try self.store.family(.props).put(k, w.buffered());
        return true;
    }

    pub fn chanBadwordDel(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const existing = self.store.family(.props).get(k) orelse return false;
        var vb: [chanbadword_value_max]u8 = undefined;
        var w = std.Io.Writer.fixed(&vb);
        var found = false;
        var remaining: usize = 0;
        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(p, pattern)) {
                found = true;
                continue;
            }
            if (remaining != 0) w.writeAll("\n") catch return found;
            w.writeAll(p) catch return found;
            remaining += 1;
        }
        if (!found) return false;
        if (remaining == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, w.buffered());
        }
        return true;
    }

    pub fn chanBadwordForEach(self: *Services, channel: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return;
        const blob = self.store.family(.props).get(k) orelse return;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| if (p.len != 0) cb(ctx, p);
    }

    /// True if `text` contains any of `channel`'s bad-word patterns. Read directly
    /// from the durable store (correct across restarts, no warm-up).
    pub fn chanBadwordMatches(self: *Services, channel: []const u8, text: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [chanbadword_key_max]u8 = undefined;
        const k = chanBadwordKey(&kb, channel) orelse return false;
        const blob = self.store.family(.props).get(k) orelse return false;
        var it = std.mem.splitScalar(u8, blob, '\n');
        while (it.next()) |p| {
            if (p.len != 0 and svc_chanbadwords.containsIgnoreCase(text, p)) return true;
        }
        return false;
    }

    // ── Durable KEEPTOPIC (registered-channel topic survives recreation) ────────
    // "ktp\x00<channel>" in `.props`: presence = enabled. The value is one of:
    //   • empty            — enabled but nothing saved yet.
    //   • legacy text      — a raw topic written by an older build (no metadata).
    //   • versioned blob   — [sentinel=0x01][ver=0x01][set_at i64 LE]
    //                        [setter_len u16 LE][setter][text]
    // Every new save writes a versioned blob, so a topic round-trips exactly
    // whatever its bytes (including a leading 0x01). The SOH (0x01) sentinel only
    // discriminates a LEGACY (pre-metadata) value from a versioned one. Decode is
    // fail-closed and fully bounds-checked: a sentinel-led value whose metadata is
    // malformed falls back to the legacy whole-value-is-text interpretation rather
    // than crashing or reading OOB. The sole residual ambiguity is an old legacy
    // value that both begins with 0x01 and happens to form a self-consistent
    // header — it decodes to a wrong setter/set-time (never a crash) for that one
    // pre-existing value; new saves are immune.
    const keeptopic_prefix = "ktp\x00";
    const keeptopic_key_max: usize = keeptopic_prefix.len + channel_max;
    const keeptopic_text_max: usize = 512; // topic TEXT cap (unchanged behaviour)
    const keeptopic_setter_max: usize = 256; // setter (nick!user@host) cap
    const keeptopic_meta_sentinel: u8 = 0x01;
    const keeptopic_meta_version: u8 = 1;
    // sentinel(1) + version(1) + set_at(8) + setter_len(2)
    const keeptopic_meta_header: usize = 12;
    const keeptopic_value_max: usize = keeptopic_meta_header + keeptopic_setter_max + keeptopic_text_max;

    /// Restored KEEPTOPIC state. `text`/`setter` slice into the caller's out
    /// buffers. `setter == null` signals a legacy/metadata-absent value: the
    /// caller restores the topic text and falls back to serverName()/now for the
    /// setter and set-time. `set_at` is meaningful only when `setter != null`.
    pub const KeepTopicRestore = struct {
        text: []const u8,
        setter: ?[]const u8,
        set_at: i64,
    };

    fn keepTopicKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < keeptopic_prefix.len + channel.len) return null;
        @memcpy(buf[0..keeptopic_prefix.len], keeptopic_prefix);
        for (channel, 0..) |c, i| buf[keeptopic_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. keeptopic_prefix.len + channel.len];
    }

    pub fn chanKeepTopicEnable(self: *Services, channel: []const u8, on: bool) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (on) {
            if (self.store.family(.props).get(k) == null) try self.store.family(.props).put(k, "");
        } else {
            try self.store.family(.props).delete(k);
        }
    }

    /// Persist `topic` with the `setter` that set it and `set_at` (Unix seconds)
    /// for `channel` — only when KEEPTOPIC is enabled (key present). Oversize text
    /// (> keeptopic_text_max) is not persisted (unchanged behaviour); the setter
    /// is truncated to keeptopic_setter_max.
    pub fn chanKeepTopicSave(
        self: *Services,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
    ) ServiceError!void {
        if (topic.len > keeptopic_text_max) return;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return;
        if (self.store.family(.props).get(k) == null) return; // not enabled

        // An empty topic clears the remembered value: store the empty marker so
        // recreation restores nothing, matching the pre-metadata behaviour (a
        // metadata blob is never empty, so `get` returns null for this).
        if (topic.len == 0) {
            try self.store.family(.props).put(k, "");
            return;
        }

        const setter_clamped = setter[0..@min(setter.len, keeptopic_setter_max)];
        var blob: [keeptopic_value_max]u8 = undefined;
        blob[0] = keeptopic_meta_sentinel;
        blob[1] = keeptopic_meta_version;
        std.mem.writeInt(i64, blob[2..10], set_at, .little);
        std.mem.writeInt(u16, blob[10..12], @intCast(setter_clamped.len), .little);
        @memcpy(blob[keeptopic_meta_header .. keeptopic_meta_header + setter_clamped.len], setter_clamped);
        const text_off = keeptopic_meta_header + setter_clamped.len;
        @memcpy(blob[text_off .. text_off + topic.len], topic);
        try self.store.family(.props).put(k, blob[0 .. text_off + topic.len]);
    }

    /// Return the saved topic for `channel` when KEEPTOPIC is enabled and a
    /// non-empty value is stored; else null. `text`/`setter` slice into `text_out`
    /// / `setter_out`. A legacy (pre-metadata) value returns `setter == null`, so
    /// the caller falls back to serverName()/now — see KeepTopicRestore.
    pub fn chanKeepTopicGet(
        self: *Services,
        channel: []const u8,
        text_out: []u8,
        setter_out: []u8,
    ) ?KeepTopicRestore {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [keeptopic_key_max]u8 = undefined;
        const k = keepTopicKey(&kb, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;

        // Versioned blob: decode fail-closed — malformed metadata falls through to
        // the legacy whole-value-is-text interpretation below. A decoded but empty
        // topic restores nothing (mirrors the empty-value case above).
        if (blob[0] == keeptopic_meta_sentinel) {
            if (decodeKeepTopicMeta(blob, text_out, setter_out)) |r| {
                return if (r.text.len == 0) null else r;
            }
        }

        // Legacy value (or malformed metadata): the whole value is the topic text,
        // with no setter/set_at — signal metadata absent.
        const n = @min(blob.len, text_out.len);
        @memcpy(text_out[0..n], blob[0..n]);
        return .{ .text = text_out[0..n], .setter = null, .set_at = 0 };
    }

    /// Decode a sentinel-led KEEPTOPIC value. Every field is bounds-checked; any
    /// malformation (short header, unknown version, setter length past the end)
    /// returns null so the caller falls back to the legacy text-only path.
    fn decodeKeepTopicMeta(blob: []const u8, text_out: []u8, setter_out: []u8) ?KeepTopicRestore {
        if (blob.len < keeptopic_meta_header) return null;
        if (blob[1] != keeptopic_meta_version) return null;
        const set_at = std.mem.readInt(i64, blob[2..10], .little);
        const setter_len: usize = std.mem.readInt(u16, blob[10..12], .little);
        const setter_end = keeptopic_meta_header + setter_len;
        if (setter_end > blob.len) return null; // truncated setter
        const setter = blob[keeptopic_meta_header..setter_end];
        const text = blob[setter_end..];
        const sn = @min(setter.len, setter_out.len);
        @memcpy(setter_out[0..sn], setter[0..sn]);
        const tn = @min(text.len, text_out.len);
        @memcpy(text_out[0..tn], text[0..tn]);
        return .{ .text = text_out[0..tn], .setter = setter_out[0..sn], .set_at = set_at };
    }

    // ── Durable registered-channel founder successor (svc_successor; SUCCESSOR) ──
    // One successor account per channel in `.props` ("suc\x00<channel>"). When the
    // founder's account is dropped, the channel is handed to its successor.
    const successor_prefix = "suc\x00";
    const successor_key_max: usize = successor_prefix.len + channel_max;

    fn successorKey(buf: []u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < successor_prefix.len + channel.len) return null;
        @memcpy(buf[0..successor_prefix.len], successor_prefix);
        for (channel, 0..) |c, i| buf[successor_prefix.len + i] = std.ascii.toLower(c);
        return buf[0 .. successor_prefix.len + channel.len];
    }

    /// Set `account` (normalized) as `channel`'s configured successor.
    pub fn channelSuccessorSet(self: *Services, channel: []const u8, account: []const u8) ServiceError!void {
        const acc = try accountKey(account);
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return error.InvalidChannel;
        try self.store.family(.props).put(k, acc.asSlice());
    }

    /// Remove `channel`'s configured successor. No-op when unset.
    pub fn channelSuccessorClear(self: *Services, channel: []const u8) ServiceError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return;
        try self.store.family(.props).delete(k);
    }

    /// Copy `channel`'s configured successor account into `out`, or null if unset.
    pub fn channelSuccessorGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [successor_key_max]u8 = undefined;
        const k = successorKey(&kb, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    // ── Durable registered-channel metadata (CHANNEL SET DESC / URL) ────────────
    // Free-text channel metadata in `.props` keyed by "<tag>\x00<channel>". DESC
    // is a human description; URL is a homepage link. Empty value clears the key.
    const meta_value_max: usize = 400;

    fn metaKey(buf: []u8, tag: []const u8, channel: []const u8) ?[]const u8 {
        if (channel.len == 0 or channel.len > channel_max) return null;
        if (buf.len < tag.len + channel.len) return null;
        @memcpy(buf[0..tag.len], tag);
        for (channel, 0..) |c, i| buf[tag.len + i] = std.ascii.toLower(c);
        return buf[0 .. tag.len + channel.len];
    }

    fn chanMetaSet(self: *Services, tag: []const u8, channel: []const u8, value: []const u8) ServiceError!void {
        if (value.len > meta_value_max) return error.InvalidChannel;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return error.InvalidChannel;
        if (value.len == 0) {
            try self.store.family(.props).delete(k);
        } else {
            try self.store.family(.props).put(k, value);
        }
    }

    fn chanMetaGet(self: *Services, tag: []const u8, channel: []const u8, out: []u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        var kb: [16 + channel_max]u8 = undefined;
        const k = metaKey(&kb, tag, channel) orelse return null;
        const blob = self.store.family(.props).get(k) orelse return null;
        if (blob.len == 0) return null;
        const n = @min(blob.len, out.len);
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    /// Set (or clear, when empty) `channel`'s human description (CHANNEL SET DESC).
    pub fn chanDescSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("desc\x00", channel, value);
    }

    /// Copy `channel`'s description into `out`, or null if unset.
    pub fn chanDescGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("desc\x00", channel, out);
    }

    /// Set (or clear, when empty) `channel`'s homepage URL (CHANNEL SET URL).
    pub fn chanUrlSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.chanMetaSet("url\x00", channel, value);
    }

    /// Copy `channel`'s URL into `out`, or null if unset.
    pub fn chanUrlGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.chanMetaGet("url\x00", channel, out);
    }

    pub fn replayLiveState(self: *Services, sink: LiveReplaySink) ServiceError!LiveReplaySummary {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        var summary = LiveReplaySummary{};
        {
            var it = self.store.maps[@intFromEnum(store_mod.Family.chanregs)].map.iterator();
            while (it.next()) |entry| {
                const record = decodeChannel(entry.value_ptr.*) catch continue;
                try sink.channel(sink.ptr, record.name.asSlice(), record.mlock.asSlice());
                summary.channels += 1;
                if (record.mlock.asSlice().len != 0) summary.mlocks += 1;
            }
        }
        if (sink.akick) |on_akick| {
            var it = self.store.maps[@intFromEnum(channel_access_family)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, akick_prefix)) continue;
                const akick = decodeAkick(entry.value_ptr.*) catch continue;
                const channel = self.loadChannel(akick.channel.asSlice()) catch continue;
                if (!sameBytes(generation_len, &akick.generation, &channel.generation)) continue;
                try on_akick(sink.ptr, akick.channel.asSlice(), akick.mask.asSlice(), akick.reason.asSlice(), akick.setter.asSlice());
                summary.akicks += 1;
            }
        }
        if (sink.ward) |on_ward| {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, ward_prefix)) continue;
                const ward = decodeWard(entry.value_ptr.*) catch continue;
                try on_ward(sink.ptr, ward);
                summary.wards += 1;
            }
        }
        if (sink.saccess) |on_saccess| {
            var it = self.store.maps[@intFromEnum(store_mod.Family.bans)].map.iterator();
            while (it.next()) |entry| {
                if (!std.mem.startsWith(u8, entry.key_ptr.*, saccess_prefix)) continue;
                const sa = decodeSaccess(entry.value_ptr.*) catch continue;
                try on_saccess(sink.ptr, sa);
                summary.saccesses += 1;
            }
        }
        return summary;
    }

    fn addCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        const key = try accountKey(account);
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, key.asSlice()) orelse return error.BufferTooSmall;
        const existing = self.store.family(.props).get(list_key) orelse "";

        var it = std.mem.splitScalar(u8, existing, '\n');
        while (it.next()) |fp| {
            if (std.ascii.eqlIgnoreCase(fp, fingerprint)) return;
        }

        var out: [certfp_list_value_max]u8 = undefined;
        if (existing.len == 0) {
            const value = std.fmt.bufPrint(&out, "{s}", .{fingerprint}) catch return error.BufferTooSmall;
            try self.store.family(.props).put(list_key, value);
            return;
        }
        const value = std.fmt.bufPrint(&out, "{s}\n{s}", .{ existing, fingerprint }) catch return error.BufferTooSmall;
        try self.store.family(.props).put(list_key, value);
    }

    fn removeCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        var kb: [certfp_account_key_max]u8 = undefined;
        const list_key = certfpAccountKey(&kb, account) orelse return error.BufferTooSmall;
        const existing = self.store.family(.props).get(list_key) orelse return error.NotFound;

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
            try self.store.family(.props).delete(list_key);
        } else {
            try self.store.family(.props).put(list_key, out[0..len]);
        }
    }

    fn recordKeyTransparency(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        const log = self.key_transparency orelse return;
        _ = log.append(.{
            .account = account,
            .kind = kind,
            .action = action,
            .key_id = key_id,
            .key_hash = key_transparency.materialHash(material),
            .timestamp_ms = timestamp_ms,
        }) catch {};
    }

    /// Fail-closed authentication gate: whether `account` must be denied every
    /// credential path because it is SUSPENDED or FORBIDDEN. This is the shared
    /// chokepoint the SASL success path consults so SCRAM / OAUTHBEARER — whose
    /// proof/token verification never consults account status — cannot bind a
    /// locked account. Fail-closed: an account whose status cannot be decoded
    /// reads as blocked. An unknown/unregistered name that carries no forbid
    /// reservation is not blocked (guests and unknown authcids pass).
    pub fn accountAuthBlocked(self: *Services, account: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        // A decode failure on the suspend check is treated as blocked.
        const suspended = self.accountSuspendedUnlocked(account) catch return true;
        if (suspended) return true;
        return self.accountForbiddenUnlocked(account);
    }

    fn accountSuspendedUnlocked(self: *Services, account: []const u8) ServiceError!bool {
        const key = try accountKey(account);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return false;
        const record = try decodeAccount(value);
        return (record.flags & account_flag_suspended) != 0;
    }

    fn accountForbiddenUnlocked(self: *Services, account: []const u8) bool {
        const key = accountKey(account) catch return false;
        if (self.store.family(.accounts).get(key.asSlice())) |value| {
            const record = decodeAccount(value) catch return false;
            if ((record.flags & account_flag_forbidden) != 0) return true;
        }
        var kb: [forbidden_account_key_max]u8 = undefined;
        const reservation_key = forbiddenAccountKey(&kb, key.asSlice()) orelse return false;
        return self.store.family(.props).get(reservation_key) != null;
    }

    fn loadAccount(self: *Services, name: []const u8) ServiceError!AccountRecord {
        const key = try accountKey(name);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        return decodeAccount(value);
    }

    fn saveAccount(self: *Services, record: AccountRecord, scratch: []u8) ServiceError!void {
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);
    }

    fn loadChannel(self: *Services, channel: []const u8) ServiceError!ChannelRecord {
        const key = try channelKey(channel);
        const value = self.store.family(.chanregs).get(key.asSlice()) orelse return error.NotFound;
        return decodeChannel(value);
    }

    /// Whether `channel` has a durable registration (a `.chanregs` record).
    /// Used to decide a channel still "exists" for stats even when momentarily
    /// empty; a malformed name is simply not registered.
    pub fn channelIsRegistered(self: *Services, channel: []const u8) bool {
        const key = channelKey(channel) catch return false;
        return self.store.family(.chanregs).get(key.asSlice()) != null;
    }

    fn putAccess(
        self: *Services,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        const record = AccessRecord{
            .channel = channel.name,
            .account = account,
            .generation = channel.generation,
            .level = level,
        };
        const encoded = try encodeAccess(record, scratch);
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account.asSlice(), &key_buf);
        try self.store.put(channel_access_family, key, encoded);
        return record;
    }

    fn loadAccess(self: *Services, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAccess(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn loadAkick(self: *Services, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try akickKey(channel.name.asSlice(), mask, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAkick(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn requireAccess(self: *Services, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        const actor_key = try accountKey(actor);
        if (std.mem.eql(u8, actor_key.asSlice(), channel.founder.asSlice())) return;
        const access = self.loadAccess(channel, actor_key.asSlice()) catch |err| switch (err) {
            error.NotFound => return error.Forbidden,
            else => return err,
        };
        if (!access.level.allows(needed)) return error.Forbidden;
    }
};

fn validatePassword(password: []const u8) ServiceError!void {
    try validatePasswordPolicy(password, default_password_min_len, default_password_max_len);
}

fn validatePasswordPolicy(password: []const u8, min_len: usize, max_len: usize) ServiceError!void {
    if (password.len < min_len or password.len > max_len) return error.InvalidPassword;
    for (password) |byte| if (byte == 0 or byte == '\n' or byte == '\r') return error.InvalidPassword;
}

fn validateEmail(input: []const u8) ServiceError!Email {
    if (input.len == 0) return Email.empty();
    if (input.len > email_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Email.init(input) catch error.InvalidValue;
}

fn validateMlock(input: []const u8) ServiceError!Mlock {
    if (input.len == 0) return Mlock.empty();
    if (input.len > mlock_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mlock.init(input) catch error.InvalidValue;
}

fn validateReason(input: []const u8) ServiceError!Reason {
    if (input.len > reason_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Reason.init(input) catch error.InvalidValue;
}

fn validateNick(input: []const u8) ServiceError!NickName {
    if (input.len == 0 or input.len > nick_max or hasCtlOrSep(input)) return error.InvalidName;
    for (input) |byte| if (byte == ' ' or byte == ',') return error.InvalidName;
    return NickName.init(input) catch error.InvalidName;
}

fn validateMask(input: []const u8) ServiceError!Mask {
    if (input.len == 0 or input.len > mask_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mask.init(input) catch error.InvalidValue;
}

/// Durable-store key prefix for certfp→account bindings (props family). The
/// prefix keeps these out of the channel-access keyspace that shares `.props`.
const certfp_key_prefix = "certfp:";
const certfp_key_max = certfp_key_prefix.len + 128;
const certfp_account_key_prefix = "certfps:";
const certfp_account_key_max = certfp_account_key_prefix.len + account_max;
const certfp_list_value_max = 16 * 64 + 15;
const forbidden_account_key_prefix = "acctforbid:";
const forbidden_account_key_max = forbidden_account_key_prefix.len + account_max;
const verify_key_max = verify_prefix.len + account_max;
const verify_value_max = verify_version.len + 1 + account_max + 1 + email_max + 1 + 128 + 1 + 20;
const default_verify_ttl_ms: u64 = 15 * 60 * 1000;
const ward_key_max = ward_prefix.len + 16 + 1 + 256;
const ward_value_max = ward_version.len + 1 + 16 + 1 + 256 + 1 + 16 + 1 + 16 + 1 + 20 + 1 + 20 + 1 + 64 + 1 + 512;

// SACCESS persistence sizing. Entry-type token <= 9 ("NOCHANNEL"); mask is the
// IRCX access mask (DEFAULT_MAX_MASK_BYTES = 128); reason <= 256; duration is a
// u64 (<= 20 digits). Generous bounds keep this restart-safe under any config.
const saccess_type_max = 16;
const saccess_mask_max = 256;
const saccess_reason_max = 512;
const saccess_key_max = saccess_prefix.len + saccess_type_max + 1 + saccess_mask_max;
const saccess_value_max = saccess_version.len + 1 + saccess_type_max + 1 + saccess_mask_max + 1 + 20 + 1 + saccess_reason_max;
const session_token_version = "T1";
const session_token_key_prefix = "sessiontok:";
const session_token_account_key_prefix = "sessiontokacct:";
const session_token_key_max = session_token_key_prefix.len + hash_hex_len;
const session_token_account_key_max = session_token_account_key_prefix.len + account_max;
const session_token_value_max = session_token_version.len + 1 + account_max + 1 + 20 + 1 + hash_hex_len;

const SessionTokenRecord = struct {
    account: AccountName,
    expires_unix: i64,
    hash: []const u8,
};

fn secureZero(buf: []u8) void {
    for (buf) |*byte| {
        const vp: *volatile u8 = @ptrCast(byte);
        vp.* = 0;
    }
}

/// Build the props-family key for a certfp binding, or null if it would not fit.
fn certfpKey(buf: []u8, fingerprint: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_key_prefix ++ "{s}", .{fingerprint}) catch null;
}

fn certfpAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, certfp_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn forbiddenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, forbidden_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn verifyKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, verify_prefix ++ "{s}", .{account}) catch null;
}

/// Durable-store key prefix for persisted SCRAM credential tuples (props family).
const scram_key_prefix = "scram:";
const scram_key_max = scram_key_prefix.len + account_max;

/// Build the props-family key for an account's SCRAM tuple, or null if too long.
fn scramKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, scram_key_prefix ++ "{s}", .{account}) catch null;
}

fn sessionTokenKey(buf: []u8, hash_hex: []const u8) ?[]const u8 {
    if (hash_hex.len != hash_hex_len) return null;
    return std.fmt.bufPrint(buf, session_token_key_prefix ++ "{s}", .{hash_hex}) catch null;
}

fn sessionTokenAccountKey(buf: []u8, account: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, session_token_account_key_prefix ++ "{s}", .{account}) catch null;
}

fn encodeSessionTokenRecord(account: []const u8, expires_unix: i64, hash_hex: []const u8, scratch: []u8) ServiceError![]const u8 {
    if (hash_hex.len != hash_hex_len) return error.InvalidRecord;
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{d}|{s}",
        .{ session_token_version, account, expires_unix, hash_hex },
    ) catch error.BufferTooSmall;
}

fn decodeSessionTokenRecord(value: []const u8) ServiceError!SessionTokenRecord {
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

fn validSessionTokenText(token: []const u8) bool {
    if (token.len != session_token_len) return false;
    if (!std.mem.eql(u8, token[0..session_token_prefix.len], session_token_prefix)) return false;
    for (token[session_token_prefix.len..]) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn accountKey(input: []const u8) ServiceError!AccountName {
    if (input.len == 0 or input.len > account_max) return error.InvalidName;
    var out = AccountName{};
    for (input, 0..) |byte, idx| {
        if (!isAccountChar(byte)) return error.InvalidName;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn channelKey(input: []const u8) ServiceError!ChannelName {
    if (input.len < 2 or input.len > channel_max or input[0] != '#') return error.InvalidChannel;
    var out = ChannelName{};
    for (input, 0..) |byte, idx| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return error.InvalidChannel;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn isAccountChar(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn setFlag(flags: *u32, bit: u32, enabled: bool) void {
    if (enabled) {
        flags.* |= bit;
    } else {
        flags.* &= ~bit;
    }
}

fn hasCtlOrSep(input: []const u8) bool {
    for (input) |byte| if (byte < 0x20 or byte == 0x7f or byte == '|') return true;
    return false;
}

fn hashPassword(out: *[hash_len]u8, password: []const u8, salt: *const [salt_len]u8, rounds: u32) ServiceError!void {
    try std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
}

fn verifyPassword(record: AccountRecord, password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &record.salt, rounds);
    if (!std.crypto.timing_safe.eql([hash_len]u8, candidate, record.hash)) return error.AuthFailed;
}

fn rejectMissingAccount(password: []const u8, rounds: u32) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &missing_account_salt, rounds);
}

fn encodeAccount(record: AccountRecord, scratch: []u8) ServiceError![]const u8 {
    var salt_hex = std.fmt.bytesToHex(record.salt, .lower);
    var hash_hex = std.fmt.bytesToHex(record.hash, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}|{}",
        .{ account_version_v2, record.name.asSlice(), &salt_hex, &hash_hex, record.flags, record.email.asSlice(), record.email_verified },
    ) catch error.BufferTooSmall;
}

fn decodeAccount(value: []const u8) ServiceError!AccountRecord {
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

fn encodeChannel(record: ChannelRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}",
        .{ channel_version_v2, record.name.asSlice(), record.founder.asSlice(), &gen_hex, record.flags, record.mlock.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeChannel(value: []const u8) ServiceError!ChannelRecord {
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

fn encodeAccess(record: AccessRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}",
        .{ access_version, record.channel.asSlice(), record.account.asSlice(), &gen_hex, @intFromEnum(record.level) },
    ) catch error.BufferTooSmall;
}

fn decodeAccess(value: []const u8) ServiceError!AccessRecord {
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

fn encodeAkick(record: AkickRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{s}|{s}",
        .{ akick_version, record.channel.asSlice(), record.mask.asSlice(), &gen_hex, record.setter.asSlice(), record.reason.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeAkick(value: []const u8) ServiceError!AkickRecord {
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

const PendingVerify = struct {
    account: []const u8,
    email: []const u8,
    token: []const u8,
    issued_ms: u64,
};

fn encodeVerify(account: []const u8, email: []const u8, token: []const u8, issued_ms: u64, out: []u8) ServiceError![]const u8 {
    if (hasCtlOrSep(token) or token.len == 0 or token.len > 128) return error.InvalidValue;
    return std.fmt.bufPrint(out, "{s}|{s}|{s}|{s}|{d}", .{ verify_version, account, email, token, issued_ms }) catch error.BufferTooSmall;
}

fn decodeVerify(value: []const u8) ServiceError!PendingVerify {
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

fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    return std.crypto.timing_safe.compare(u8, expected, actual, .big) == .eq;
}

fn validateWardField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len == 0 or value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

fn validateWardOptionalField(value: []const u8, max_len: usize) ServiceError!void {
    if (value.len > max_len) return error.InvalidValue;
    if (hasCtlOrSep(value)) return error.InvalidValue;
}

fn wardKey(match: []const u8, pattern: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(match, 16);
    try validateWardField(pattern, 256);
    if (ward_prefix.len + match.len + 1 + pattern.len > @min(out.len, ward_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, ward_prefix ++ "{s}:{s}", .{ match, pattern }) catch error.BufferTooSmall;
}

fn encodeWard(ward: ReplayWard, out: []u8) ServiceError![]const u8 {
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

fn decodeWard(value: []const u8) ServiceError!ReplayWard {
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

fn saccessKey(entry_type: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry_type, saccess_type_max);
    try validateWardField(mask, saccess_mask_max);
    if (saccess_prefix.len + entry_type.len + 1 + mask.len > @min(out.len, saccess_key_max)) return error.BufferTooSmall;
    return std.fmt.bufPrint(out, saccess_prefix ++ "{s}:{s}", .{ entry_type, mask }) catch error.BufferTooSmall;
}

fn encodeSaccess(entry: ReplaySaccess, out: []u8) ServiceError![]const u8 {
    try validateWardField(entry.entry_type, saccess_type_max);
    try validateWardField(entry.mask, saccess_mask_max);
    try validateWardOptionalField(entry.reason, saccess_reason_max);
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{s}|{d}|{s}",
        .{ saccess_version, entry.entry_type, entry.mask, entry.duration, entry.reason },
    ) catch error.BufferTooSmall;
}

fn decodeSaccess(value: []const u8) ServiceError!ReplaySaccess {
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

fn levelFromInt(value: u8) ?AccessLevel {
    return switch (value) {
        @intFromEnum(AccessLevel.voice) => .voice,
        @intFromEnum(AccessLevel.op) => .op,
        @intFromEnum(AccessLevel.admin) => .admin,
        @intFromEnum(AccessLevel.founder) => .founder,
        else => null,
    };
}

fn accessKey(channel: []const u8, account: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(access_prefix, channel, account, out);
}

fn akickKey(channel: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(akick_prefix, channel, mask, out);
}

fn prefixedKey(prefix: []const u8, channel: []const u8, tail: []const u8, out: []u8) ServiceError![]const u8 {
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

fn sameBytes(comptime len: usize, a: *const [len]u8, b: *const [len]u8) bool {
    return std.crypto.timing_safe.eql([len]u8, a.*, b.*);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

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

test "channel SET flags and DESC/URL persist and round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-set.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("admin", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#room", "admin", &scratch);

    // Flags start clear, set independently, and persist without clobbering siblings.
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, true, &scratch);
    try services.setChannelFlag("#room", "admin", channel_flag_private, true, &scratch);
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_guard));

    // Clearing one leaves the other intact.
    try services.setChannelFlag("#room", "admin", channel_flag_topiclock, false, &scratch);
    try std.testing.expect(!services.channelFlagSet("#room", channel_flag_topiclock));
    try std.testing.expect(services.channelFlagSet("#room", channel_flag_private));

    // DESC / URL round-trip and clear on empty.
    var out: [512]u8 = undefined;
    try std.testing.expect(services.chanDescGet("#room", &out) == null);
    try services.chanDescSet("#room", "Our room");
    try std.testing.expectEqualStrings("Our room", services.chanDescGet("#room", &out).?);
    try services.chanUrlSet("#room", "https://example.test");
    try std.testing.expectEqualStrings("https://example.test", services.chanUrlGet("#room", &out).?);
    try services.chanDescSet("#room", "");
    try std.testing.expect(services.chanDescGet("#room", &out) == null);

    // A non-founder/non-admin actor cannot set flags.
    _ = try services.registerAccount("mallory", "another correct horse battery", &scratch);
    try std.testing.expectError(error.Forbidden, services.setChannelFlag("#room", "mallory", channel_flag_guard, true, &scratch));
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

test "recognize masks: add/match/list/delete and persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "*!*@*.example.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.added, try services.recognizeAdd("kain", "kain!*@host"));
        // case-insensitive account + mask dedupe
        try std.testing.expectEqual(Services.RecognizeAdd.already_present, try services.recognizeAdd("KAIN", "*!*@*.EXAMPLE.net"));
        try std.testing.expectEqual(Services.RecognizeAdd.invalid_mask, try services.recognizeAdd("kain", ""));

        try std.testing.expect(services.recognizeMatches("kain", "kain!user@gw.example.net"));
        try std.testing.expect(!services.recognizeMatches("kain", "kain!user@other.org"));
        try std.testing.expect(!services.recognizeMatches("nobody", "kain!user@gw.example.net"));

        try std.testing.expect(try services.recognizeDel("kain", "kain!*@host"));
        try std.testing.expect(!try services.recognizeDel("kain", "kain!*@host"));
    }
    {
        // reopen: the remaining mask survived durably; the deleted one did not.
        var store = try openTestStore(tmp, "services-recognize.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(services.recognizeMatches("kain", "anyone!x@host.example.net"));
        var lb: [512]u8 = undefined;
        const blob = services.recognizeBlob("kain", &lb);
        try std.testing.expect(std.mem.indexOf(u8, blob, "*!*@*.example.net") != null);
        try std.testing.expect(std.mem.indexOf(u8, blob, "kain!*@host") == null);
    }
}

test "account metadata: put/delete persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.metadataPut("kain", "avatar", "https://x/a.png", "*");
        try services.metadataPut("kain", "display-name", "Kain", "*");
        try services.metadataDelete("kain", "avatar"); // remove one
    }
    {
        var store = try openTestStore(tmp, "services-acctmeta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        var count: usize = 0;
        var ok_display = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.metadataForEach("KAIN", Ctx{ .count = &count, .ok = &ok_display }, struct {
            fn cb(c: Ctx, key: []const u8, value: []const u8, vis: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, key, "display-name") and std.mem.eql(u8, value, "Kain") and std.mem.eql(u8, vis, "*")) c.ok.* = true;
            }
        }.cb);
        // avatar was deleted; only display-name survives, with value + visibility intact.
        try std.testing.expectEqual(@as(usize, 1), count);
        try std.testing.expect(ok_display);
    }
}

test "account silence: add/remove persist; restore via forEach across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.silencePersistAdd("kain", "*!*@spam.example");
        try services.silencePersistAdd("kain", "troll!*@*");
        try services.silencePersistAdd("KAIN", "*!*@SPAM.example"); // case-insensitive dup: no-op
        try services.silencePersistDel("kain", "troll!*@*");
    }
    {
        var store = try openTestStore(tmp, "services-acctsilence.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var count: usize = 0;
        var ok = false;
        const Ctx = struct { count: *usize, ok: *bool };
        services.silenceForEach("kain", Ctx{ .count = &count, .ok = &ok }, struct {
            fn cb(c: Ctx, mask: []const u8) void {
                c.count.* += 1;
                if (std.mem.eql(u8, mask, "*!*@spam.example")) c.ok.* = true;
            }
        }.cb);
        try std.testing.expectEqual(@as(usize, 1), count); // troll removed; one survives
        try std.testing.expect(ok);
    }
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

test "channelsForAccount: durable reverse access lookup (LISTCHANS)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-listchans.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);
    _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);

    var count: usize = 0;
    var found_op = false;
    const Ctx = struct { count: *usize, found: *bool };
    services.channelsForAccount("BOB", Ctx{ .count = &count, .found = &found_op }, struct {
        fn cb(c: Ctx, channel: []const u8, level: AccessLevel) void {
            c.count.* += 1;
            if (std.ascii.eqlIgnoreCase(channel, "#onyx") and level == .op) c.found.* = true;
        }
    }.cb);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(found_op);
}

test "channel bad-words: add/match/remove persist across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(try services.chanBadwordAdd("#chan", "spam"));
        try std.testing.expect(try services.chanBadwordAdd("#chan", "scam"));
        try std.testing.expect(!try services.chanBadwordAdd("#CHAN", "SPAM")); // case-insensitive dup
        try std.testing.expect(services.chanBadwordMatches("#chan", "buy this SpAm now"));
        try std.testing.expect(!services.chanBadwordMatches("#chan", "a clean message"));
        try std.testing.expect(try services.chanBadwordDel("#chan", "spam"));
    }
    {
        var store = try openTestStore(tmp, "services-chanbadwords.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try std.testing.expect(!services.chanBadwordMatches("#chan", "buy this spam now")); // removed
        try std.testing.expect(services.chanBadwordMatches("#chan", "a scam here")); // survived
    }
}

test "keeptopic: enable/save/get persist across reopen; save is a no-op when off" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [128]u8 = undefined;
        var s: [128]u8 = undefined;
        // off by default; save does nothing while off
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
        try services.chanKeepTopicSave("#chan", "ignored", "nick!u@h", 100);
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
        // enable then save
        try services.chanKeepTopicEnable("#chan", true);
        try services.chanKeepTopicSave("#chan", "the topic", "nick!u@h", 100);
        const got = services.chanKeepTopicGet("#CHAN", &t, &s) orelse return error.TestUnexpectedResult; // case-insensitive
        try std.testing.expectEqualStrings("the topic", got.text);
    }
    {
        var store = try openTestStore(tmp, "services-keeptopic.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [128]u8 = undefined;
        var s: [128]u8 = undefined;
        const got = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("the topic", got.text); // survived reopen
        try std.testing.expectEqualStrings("nick!u@h", got.setter.?);
        try std.testing.expectEqual(@as(i64, 100), got.set_at);
        try services.chanKeepTopicEnable("#chan", false);
        try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null); // disabled -> gone
    }
}

test "keeptopic: setter and set-time round-trip exactly, and survive reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-keeptopic-meta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        try services.chanKeepTopicEnable("#chan", true);
        try services.chanKeepTopicSave("#chan", "hello world", "alice!a@host.example", 1_700_000_000);
        var t: [512]u8 = undefined;
        var s: [256]u8 = undefined;
        const r = services.chanKeepTopicGet("#CHAN", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("hello world", r.text);
        try std.testing.expectEqualStrings("alice!a@host.example", r.setter.?);
        try std.testing.expectEqual(@as(i64, 1_700_000_000), r.set_at);
    }
    {
        var store = try openTestStore(tmp, "services-keeptopic-meta.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var t: [512]u8 = undefined;
        var s: [256]u8 = undefined;
        const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("hello world", r.text); // survived reopen
        try std.testing.expectEqualStrings("alice!a@host.example", r.setter.?);
        try std.testing.expectEqual(@as(i64, 1_700_000_000), r.set_at);
    }
}

test "keeptopic: legacy raw-text blob decodes as text-only with metadata absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-legacy.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    // Write a legacy value directly (raw topic bytes, no sentinel/metadata) under
    // the exact ktp key, as an older build would have stored it.
    var kb: [Services.keeptopic_key_max]u8 = undefined;
    const key = Services.keepTopicKey(&kb, "#chan").?;
    try store.family(.props).put(key, "an old topic set before metadata");

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("an old topic set before metadata", r.text);
    try std.testing.expect(r.setter == null); // metadata absent -> caller uses serverName()/now
}

test "keeptopic: malformed metadata fails closed to text-only, no crash" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-malformed.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var kb: [Services.keeptopic_key_max]u8 = undefined;
    const key = Services.keepTopicKey(&kb, "#chan").?;
    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;

    // Case 1: sentinel + version present but the fixed header is truncated (< 12).
    const short_header = [_]u8{ 0x01, 0x01, 0x00, 0x00 };
    try store.family(.props).put(key, &short_header);
    const r1 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r1.setter == null); // fell back to legacy text-only
    try std.testing.expectEqualSlices(u8, &short_header, r1.text);

    // Case 2: full 12-byte header but setter_len points past the end of the value.
    var bad_setter_len: [12]u8 = @splat(0);
    bad_setter_len[0] = 0x01; // sentinel
    bad_setter_len[1] = 0x01; // version
    // set_at bytes [2..10] left 0; setter_len (u16 LE at [10..12]) = 100, but no
    // setter bytes follow -> setter_end (112) > blob.len (12).
    std.mem.writeInt(u16, bad_setter_len[10..12], 100, .little);
    try store.family(.props).put(key, &bad_setter_len);
    const r2 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r2.setter == null); // fell back to legacy text-only
    try std.testing.expectEqualSlices(u8, &bad_setter_len, r2.text);

    // Case 3: unknown version -> fail closed to text-only.
    var bad_version: [12]u8 = @splat(0);
    bad_version[0] = 0x01; // sentinel
    bad_version[1] = 0xFF; // unknown version
    try store.family(.props).put(key, &bad_version);
    const r3 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r3.setter == null);
    try std.testing.expectEqualSlices(u8, &bad_version, r3.text);
}

test "keeptopic: setter truncated to cap; oversize text not persisted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-caps.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;

    // A setter over the 256-byte cap is truncated to the cap.
    var long_setter: [400]u8 = undefined;
    @memset(&long_setter, 'x');
    try services.chanKeepTopicSave("#chan", "topic", &long_setter, 42);
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("topic", r.text);
    try std.testing.expectEqual(@as(usize, 256), r.setter.?.len); // truncated to keeptopic_setter_max
    try std.testing.expectEqual(@as(i64, 42), r.set_at);

    // A topic over the 512-byte text cap is a no-op (unchanged behaviour): the
    // prior saved value stays intact.
    var long_text: [600]u8 = undefined;
    @memset(&long_text, 't');
    try services.chanKeepTopicSave("#chan", &long_text, "bob!b@h", 43);
    const r2 = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("topic", r2.text); // oversize text rejected, prior value kept
    try std.testing.expectEqual(@as(i64, 42), r2.set_at);
}

test "keeptopic: a legacy value beginning with the sentinel fails closed to text-only" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-legacy-sentinel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    // A pre-metadata topic that legitimately begins with SOH (0x01) but is NOT a
    // valid versioned blob (byte[1] is not the format version) must fall back to
    // legacy text — bounds-checked, no crash, whole value returned as text with
    // metadata absent so the caller uses serverName()/now.
    var kb: [Services.keeptopic_key_max]u8 = undefined;
    const key = Services.keepTopicKey(&kb, "#chan").?;
    const legacy = "\x01ACTION waves at the channel from before metadata existed";
    try store.family(.props).put(key, legacy);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expect(r.setter == null);
    try std.testing.expectEqualStrings(legacy, r.text);
}

test "keeptopic: saving an empty topic clears an enabled channel's remembered value" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-keeptopic-clear.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try services.chanKeepTopicEnable("#chan", true);

    var t: [512]u8 = undefined;
    var s: [256]u8 = undefined;
    // Remember a topic, then clear it with an empty save.
    try services.chanKeepTopicSave("#chan", "remembered", "alice!a@h", 500);
    _ = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try services.chanKeepTopicSave("#chan", "", "alice!a@h", 600);
    // Cleared: recreation restores nothing, but KEEPTOPIC stays enabled.
    try std.testing.expect(services.chanKeepTopicGet("#chan", &t, &s) == null);
    // Still enabled -> a fresh save is remembered again.
    try services.chanKeepTopicSave("#chan", "again", "bob!b@h", 700);
    const r = services.chanKeepTopicGet("#chan", &t, &s) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("again", r.text);
    try std.testing.expectEqualStrings("bob!b@h", r.setter.?);
    try std.testing.expectEqual(@as(i64, 700), r.set_at);
}

test "channel transfer: only the founder may hand ownership to a registered account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-chantransfer.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another good passphrase here", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.transferChannel("#onyx", "bob", "bob", &scratch)); // not founder
    try std.testing.expectError(error.NotFound, services.transferChannel("#onyx", "alice", "carol", &scratch)); // unknown target
    const res = try services.transferChannel("#onyx", "alice", "bob", &scratch);
    try std.testing.expectEqualStrings("bob", res.registered_channel.founder.asSlice());
    // ownership moved: alice can no longer transfer
    try std.testing.expectError(error.Forbidden, services.transferChannel("#onyx", "alice", "alice", &scratch));
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

test "key transparency log records certfp and passkey binding changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-key-transparency.wal");
    defer store.deinit();
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    var kt = key_transparency.KeyTransparencyLog.init(std.testing.allocator);
    defer kt.deinit();
    var services = Services.init(&store, null);
    services.attachCertfpBinds(&binds);
    services.attachKeyTransparencyLog(&kt);

    const fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const cose = [_]u8{ 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };
    try services.bindCertfp("Alice", fp);
    try services.webauthnBind("Alice", "credAAA", &cose, 5, "phone", 1_700_000_000);
    try services.webauthnDelete("Alice", "credAAA");
    try services.deleteCertfp("Alice", fp);

    try std.testing.expectEqual(@as(usize, 4), kt.len());
    const root = kt.root();
    const webauthn_bind = key_transparency.Event{
        .account = "alice",
        .kind = .webauthn,
        .action = .bind,
        .key_id = "credAAA",
        .key_hash = key_transparency.materialHash(&cose),
        .timestamp_ms = 1_700_000_000_000,
    };
    var proof = try kt.proof(1);
    defer proof.deinit(std.testing.allocator);
    try std.testing.expect(key_transparency.verifyInclusion(root, webauthn_bind, proof, 1, kt.len()));

    var snapshot = try services.keyTransparencyProof(std.testing.allocator, 1);
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshot.position);
    try std.testing.expectEqual(@as(usize, 4), snapshot.size);
    try std.testing.expectEqualSlices(u8, &root, &snapshot.root);
    try std.testing.expect(snapshot.path.len != 0);
    try std.testing.expectError(error.IndexOutOfRange, services.keyTransparencyProof(std.testing.allocator, 99));
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

test "channel register and access grant" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    const registered = try services.registerChannel("#Onyx", "alice", &scratch);
    try std.testing.expectEqualStrings("#onyx", registered.registered_channel.name.asSlice());
    try std.testing.expectEqualStrings("alice", registered.registered_channel.founder.asSlice());

    const granted = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
    try std.testing.expectEqual(AccessLevel.op, granted.access.level);

    // The founder (admin+) may read back another account's access level.
    const queried = try services.channelAccess("#onyx", "alice", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, queried.access.level);
    // But an actor lacking .admin (op-level bob) may NOT probe access state.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "bob", .query, .voice, &scratch));
}

test "channel mlock access akick and ward replay from durable services" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
        _ = try services.registerChannel("#Onyx", "alice", &scratch);
        _ = try services.setChannel("#onyx", "alice", .{ .mlock = "+nt-k" }, &scratch);
        _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
        _ = try services.channelAkick("#onyx", "alice", "Bad!*@*", .add, "go away", &scratch);
        try services.persistWard(.{
            .match = "mask",
            .pattern = "Bad!*@*",
            .scope = "node",
            .action = "expel",
            .reason = "spam",
            .setter = "alice",
            .created_ms = 111,
            .expires_ms = 222,
        }, &scratch);
    }

    {
        var store = try openTestStore(tmp, "services-live-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const info = try services.channelInfo("#onyx");
        try std.testing.expectEqualStrings("+nt-k", info.channel_info.mlock.asSlice());
        try std.testing.expectEqual(AccessLevel.op, (try services.channelAccessLevelFor("#onyx", "bob")).?);

        const ReplayRecorder = struct {
            channel: [channel_max]u8 = @splat(0),
            channel_len: usize = 0,
            mlock: [mlock_max]u8 = @splat(0),
            mlock_len: usize = 0,
            akick_channel: [channel_max]u8 = @splat(0),
            akick_channel_len: usize = 0,
            akick_mask: [mask_max]u8 = @splat(0),
            akick_mask_len: usize = 0,
            akick_reason: [reason_max]u8 = @splat(0),
            akick_reason_len: usize = 0,
            ward_match: [16]u8 = @splat(0),
            ward_match_len: usize = 0,
            ward_pattern: [mask_max]u8 = @splat(0),
            ward_pattern_len: usize = 0,
            ward_reason: [reason_max]u8 = @splat(0),
            ward_reason_len: usize = 0,

            fn copyInto(dst: []u8, len: *usize, value: []const u8) ServiceError!void {
                if (value.len > dst.len) return error.BufferTooSmall;
                @memcpy(dst[0..value.len], value);
                len.* = value.len;
            }

            fn onChannel(ctx: *anyopaque, channel: []const u8, mlock: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.channel, &self.channel_len, channel);
                try copyInto(&self.mlock, &self.mlock_len, mlock);
            }

            fn onAkick(ctx: *anyopaque, channel: []const u8, mask: []const u8, reason: []const u8, _: []const u8) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.akick_channel, &self.akick_channel_len, channel);
                try copyInto(&self.akick_mask, &self.akick_mask_len, mask);
                try copyInto(&self.akick_reason, &self.akick_reason_len, reason);
            }

            fn onWard(ctx: *anyopaque, ward: ReplayWard) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                try copyInto(&self.ward_match, &self.ward_match_len, ward.match);
                try copyInto(&self.ward_pattern, &self.ward_pattern_len, ward.pattern);
                try copyInto(&self.ward_reason, &self.ward_reason_len, ward.reason);
            }
        };
        var recorder = ReplayRecorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = ReplayRecorder.onChannel,
            .akick = ReplayRecorder.onAkick,
            .ward = ReplayRecorder.onWard,
        });
        try std.testing.expectEqual(@as(usize, 1), summary.channels);
        try std.testing.expectEqual(@as(usize, 1), summary.mlocks);
        try std.testing.expectEqual(@as(usize, 1), summary.akicks);
        try std.testing.expectEqual(@as(usize, 1), summary.wards);
        try std.testing.expectEqualStrings("#onyx", recorder.channel[0..recorder.channel_len]);
        try std.testing.expectEqualStrings("+nt-k", recorder.mlock[0..recorder.mlock_len]);
        try std.testing.expectEqualStrings("#onyx", recorder.akick_channel[0..recorder.akick_channel_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.akick_mask[0..recorder.akick_mask_len]);
        try std.testing.expectEqualStrings("go away", recorder.akick_reason[0..recorder.akick_reason_len]);
        try std.testing.expectEqualStrings("mask", recorder.ward_match[0..recorder.ward_match_len]);
        try std.testing.expectEqualStrings("Bad!*@*", recorder.ward_pattern[0..recorder.ward_pattern_len]);
        try std.testing.expectEqualStrings("spam", recorder.ward_reason[0..recorder.ward_reason_len]);
    }
}

test "SACCESS entries persist across a WAL reopen and replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;

        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "bad!*@*", .duration = 60, .reason = "abuse" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GRANT", .mask = "trusted!*@*" }, &scratch);
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*" }, &scratch);
        // A deleted entry must not survive the reopen.
        try services.persistSaccess(.{ .entry_type = "DENY", .mask = "temp!*@*" }, &scratch);
        try services.deleteSaccess("DENY", "temp!*@*", &scratch);
        // A re-add of the same type+mask is idempotent (overwrite, not duplicate).
        try services.persistSaccess(.{ .entry_type = "GAG", .mask = "noisy!*@*", .reason = "updated" }, &scratch);
    }

    {
        // Reopen the WAL — this is the actual "restart": state comes only from disk.
        var store = try openTestStore(tmp, "services-saccess-replay.wal");
        defer store.deinit();
        var services = Services.init(&store, null);

        const Recorder = struct {
            count: usize = 0,
            deny_mask: [256]u8 = @splat(0),
            deny_mask_len: usize = 0,
            deny_duration: u64 = 0,
            deny_reason: [512]u8 = @splat(0),
            deny_reason_len: usize = 0,
            saw_grant: bool = false,
            saw_gag: bool = false,
            gag_reason: [512]u8 = @splat(0),
            gag_reason_len: usize = 0,
            saw_temp: bool = false,

            fn onChannel(_: *anyopaque, _: []const u8, _: []const u8) ServiceError!void {}

            fn onSaccess(ctx: *anyopaque, entry: ReplaySaccess) ServiceError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                self.count += 1;
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "bad!*@*")) {
                    @memcpy(self.deny_mask[0..entry.mask.len], entry.mask);
                    self.deny_mask_len = entry.mask.len;
                    self.deny_duration = entry.duration;
                    @memcpy(self.deny_reason[0..entry.reason.len], entry.reason);
                    self.deny_reason_len = entry.reason.len;
                }
                if (std.mem.eql(u8, entry.entry_type, "DENY") and std.mem.eql(u8, entry.mask, "temp!*@*")) self.saw_temp = true;
                if (std.mem.eql(u8, entry.entry_type, "GRANT")) self.saw_grant = true;
                if (std.mem.eql(u8, entry.entry_type, "GAG")) {
                    self.saw_gag = true;
                    @memcpy(self.gag_reason[0..entry.reason.len], entry.reason);
                    self.gag_reason_len = entry.reason.len;
                }
            }
        };
        var recorder = Recorder{};
        const summary = try services.replayLiveState(.{
            .ptr = &recorder,
            .channel = Recorder.onChannel,
            .saccess = Recorder.onSaccess,
        });

        // 3 survivors: DENY bad, GRANT trusted, GAG noisy (temp DENY was deleted,
        // and the duplicate GAG add overwrote rather than added).
        try std.testing.expectEqual(@as(usize, 3), summary.saccesses);
        try std.testing.expectEqual(@as(usize, 3), recorder.count);
        try std.testing.expectEqualStrings("bad!*@*", recorder.deny_mask[0..recorder.deny_mask_len]);
        try std.testing.expectEqual(@as(u64, 60), recorder.deny_duration);
        try std.testing.expectEqualStrings("abuse", recorder.deny_reason[0..recorder.deny_reason_len]);
        try std.testing.expect(recorder.saw_grant);
        try std.testing.expect(recorder.saw_gag);
        try std.testing.expectEqualStrings("updated", recorder.gag_reason[0..recorder.gag_reason_len]);
        try std.testing.expect(!recorder.saw_temp);
    }
}

test "SACCESS codec round-trips and rejects malformed records" {
    var key_buf: [saccess_key_max]u8 = undefined;
    const key = try saccessKey("DENY", "bad!*@*", &key_buf);
    try std.testing.expectEqualStrings("saccess:DENY:bad!*@*", key);

    var val_buf: [saccess_value_max]u8 = undefined;
    const encoded = try encodeSaccess(.{ .entry_type = "GAG", .mask = "x!*@*", .duration = 7, .reason = "hush" }, &val_buf);
    const decoded = try decodeSaccess(encoded);
    try std.testing.expectEqualStrings("GAG", decoded.entry_type);
    try std.testing.expectEqualStrings("x!*@*", decoded.mask);
    try std.testing.expectEqual(@as(u64, 7), decoded.duration);
    try std.testing.expectEqualStrings("hush", decoded.reason);

    // A pipe in a field would corrupt the delimiter; encode rejects it.
    try std.testing.expectError(error.InvalidValue, encodeSaccess(.{ .entry_type = "DENY", .mask = "a|b", .duration = 0, .reason = "" }, &val_buf));
    // Wrong version / truncated record is rejected on decode.
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S9|DENY|m|0|"));
    try std.testing.expectError(error.InvalidRecord, decodeSaccess("S1|DENY"));
}

test "non-admin channel mutations are forbidden" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-forbidden.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerAccount("carol", "carol correct battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "carol", .grant, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "carol", .revoke, .op, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "*!*@bad.test", .add, "bad", &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "*!*@bad.test", .remove, "", &scratch));
}

test "channel access and akick query require admin" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-query-gate.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerAccount("mallory", "a third correct battery staple", &scratch);
    _ = try services.registerChannel("#Onyx", "alice", &scratch);
    _ = try services.channelAccess("#onyx", "alice", "bob", .grant, .op, &scratch);
    _ = try services.channelAkick("#onyx", "alice", "Bad!*@*", .add, "go away", &scratch);

    // mallory has NO access to #onyx: both query paths must be Forbidden and
    // must not leak the access level or the akick mask/reason.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "mallory", "bob", .query, .voice, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "mallory", "Bad!*@*", .query, "", &scratch));

    // bob holds op (below .admin): still Forbidden on either query.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "bob", "bob", .query, .voice, &scratch));
    try std.testing.expectError(error.Forbidden, services.channelAkick("#onyx", "bob", "Bad!*@*", .query, "", &scratch));

    // A non-admin querying an UNREGISTERED target must get Forbidden, NOT
    // NotFound: the .admin gate is hoisted above the target-account existence
    // probe so the reply cannot distinguish a registered from an unregistered
    // account (a registration-enumeration oracle). Pre-hoist this returned
    // error.NotFound.
    try std.testing.expectError(error.Forbidden, services.channelAccess("#onyx", "mallory", "no_such_account", .query, .voice, &scratch));

    // The founder (admin+) may still read both back.
    const acc = try services.channelAccess("#onyx", "alice", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, acc.access.level);
    const ak = try services.channelAkick("#onyx", "alice", "Bad!*@*", .query, "", &scratch);
    try std.testing.expectEqualStrings("go away", ak.akick.reason.asSlice());
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
    try std.testing.expectError(error.NotFound, services.setAccount(
        "ghost",
        "correct horse battery staple",
        .{ .email = "ghost@example.test" },
        &scratch,
    ));

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.AuthFailed, services.setAccount(
        "alice",
        "wrong horse battery staple",
        .{ .email = "alice@example.test" },
        &scratch,
    ));

    // A password that fails the length/char policy short-circuits identically
    // on both the missing and present paths (validatePassword precedes any
    // hashing in both rejectMissingAccount and verifyPassword).
    try std.testing.expectError(error.InvalidPassword, services.setAccount(
        "ghost",
        "x",
        .{ .email = "ghost@example.test" },
        &scratch,
    ));
}

test "missing access and akick removals return not found" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel-missing-remove.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);

    try std.testing.expectError(error.NotFound, services.channelAccess("#onyx", "alice", "bob", .revoke, .op, &scratch));
    try std.testing.expectError(error.NotFound, services.channelAkick("#onyx", "alice", "*!*@missing.test", .remove, "", &scratch));
}

test "drop account and channel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-drop.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#onyx", "alice", &scratch);
    _ = try services.dropChannel("#onyx", "alice");
    try std.testing.expectError(error.NotFound, services.channelInfo("#onyx"));

    _ = try services.dropAccount("alice", "correct horse battery staple");
    try std.testing.expectError(error.NotFound, services.accountInfo("alice"));
}

test "state hook fires on channel register and drop" {
    const Recorder = struct {
        created: [64]u8 = undefined,
        created_len: usize = 0,
        dropped: [64]u8 = undefined,
        dropped_len: usize = 0,

        fn onCreate(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.created[0..channel.len], channel);
            self.created_len = channel.len;
        }
        fn onDrop(ctx: *anyopaque, channel: []const u8) ServiceError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.dropped[0..channel.len], channel);
            self.dropped_len = channel.len;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-hook.wal");
    defer store.deinit();

    var rec = Recorder{};
    var services = Services.init(&store, .{
        .ptr = &rec,
        .create_channel = Recorder.onCreate,
        .drop_channel = Recorder.onDrop,
    });
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#Onyx", "alice", &scratch);
    // The canonical (lowercased) channel name is bridged to the live world.
    try std.testing.expectEqualStrings("#onyx", rec.created[0..rec.created_len]);
    try std.testing.expectEqual(@as(usize, 0), rec.dropped_len);

    _ = try services.dropChannel("#onyx", "alice");
    try std.testing.expectEqualStrings("#onyx", rec.dropped[0..rec.dropped_len]);
}

test "Config default preserves historical account policy" {
    const cfg = Config{};
    try std.testing.expectEqual(default_pbkdf2_rounds, cfg.pbkdf2_rounds);
    try std.testing.expectEqual(@as(u32, 100_000), cfg.pbkdf2_rounds);
    try std.testing.expectEqual(default_password_min_len, cfg.password_min_len);
    try std.testing.expectEqual(default_password_max_len, cfg.password_max_len);
}

test "Config.applyToml overlays account password policy" {
    var doc = try toml.parse(
        std.testing.allocator,
        "[accounts]\npbkdf2_rounds = 250000\npassword_min_len = 12\npassword_max_len = 1024\n",
    );
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

const ServicesMtCtx = struct {
    services: *Services,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn accountName(out: *[account_max]u8, writer_id: usize, i: usize) []const u8 {
        return std.fmt.bufPrint(out, "svc{d}_{d}", .{ writer_id, i }) catch unreachable;
    }

    fn writer(ctx: *ServicesMtCtx) void {
        var scratch: [record_max]u8 = undefined;
        var name_buf: [account_max]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const name = accountName(&name_buf, ctx.writer_id, i);
            _ = ctx.services.registerAccount(name, "correct horse battery staple", &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            _ = ctx.services.setAccount(name, "correct horse battery staple", .{ .email = "thread@example.test" }, &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }

    fn reader(ctx: *ServicesMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            _ = ctx.services.identifyAccount("seed", "correct horse battery staple") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            const info = ctx.services.accountInfo("seed") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, info.account_info.name.asSlice(), "seed")) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            _ = ctx.services.ghostAccount("seed", "correct horse battery staple", "SeedNick") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }
};

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
