// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SASL mechanism state machines.
//!
//! This module owns the protocol exchange only: callers provide credential
//! callbacks and emit the returned `Decision` as IRC numerics/AUTHENTICATE
//! payloads at the daemon boundary.
const std = @import("std");

const Sha256 = struct {
    pub const digest_len = std.crypto.hash.sha2.Sha256.digest_length;

    pub fn hash(msg: []const u8) [digest_len]u8 {
        var out: [digest_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &out, .{});
        return out;
    }
};

const HmacSha256 = struct {
    const Impl = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);

    pub fn create(key: []const u8, msg: []const u8) [Sha256.digest_len]u8 {
        var out: [Sha256.digest_len]u8 = undefined;
        Impl.create(&out, msg, key);
        return out;
    }
};

pub const MAX_AUTHENTICATE_PAYLOAD: usize = 512;
pub const MAX_SCRAM_MESSAGE: usize = 512;
pub const MAX_SCRAM_USERNAME: usize = 128;
pub const MAX_SCRAM_NONCE: usize = 128;
pub const MAX_SCRAM_SALT: usize = 128;

/// SASL mechanisms implemented by Onyx Server M0.
pub const Mechanism = enum {
    plain,
    external,
    scram_sha_256,
    scram_sha_512,
    scram_sha_512_plus,
    session_token,
    oauthbearer,
    anonymous,

    pub fn parse(mechanism_name: []const u8) ?Mechanism {
        if (std.ascii.eqlIgnoreCase(mechanism_name, "PLAIN")) return .plain;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "EXTERNAL")) return .external;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "SCRAM-SHA-512")) return .scram_sha_512;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "SCRAM-SHA-512-PLUS")) return .scram_sha_512_plus;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "SESSION-TOKEN")) return .session_token;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "OAUTHBEARER")) return .oauthbearer;
        if (std.ascii.eqlIgnoreCase(mechanism_name, "ANONYMOUS")) return .anonymous;
        return null;
    }

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .external => "EXTERNAL",
            .scram_sha_256 => "SCRAM-SHA-256",
            .scram_sha_512 => "SCRAM-SHA-512",
            .scram_sha_512_plus => "SCRAM-SHA-512-PLUS",
            .session_token => "SESSION-TOKEN",
            .oauthbearer => "OAUTHBEARER",
            .anonymous => "ANONYMOUS",
        };
    }
};

/// SASL-related numerics returned at the protocol boundary.
pub const Numeric = enum(u16) {
    RPL_LOGGEDIN = 900,
    RPL_SASLSUCCESS = 903,
    ERR_SASLFAIL = 904,
    ERR_SASLTOOLONG = 905,
    ERR_SASLABORTED = 906,
    RPL_SASLMECHS = 908,
};

pub const SaslError = error{
    InvalidMechanism,
    InvalidMessage,
    OutputTooSmall,
};

pub const PlainCredentials = struct {
    authzid: []const u8,
    authcid: []const u8,
    password: []const u8,
};

pub const AuthIdentity = struct {
    authcid: []const u8,
    authzid: ?[]const u8 = null,
};

pub const Success = struct {
    identity: AuthIdentity,
    logged_in: Numeric = .RPL_LOGGEDIN,
    complete: Numeric = .RPL_SASLSUCCESS,
    final_data: ?[]const u8 = null,
};

/// Dispatcher output. `continue_` and `success.final_data` are AUTHENTICATE
/// payloads already base64 encoded, except the literal "+" empty challenge.
pub const Decision = union(enum) {
    continue_: []const u8,
    success: Success,
    failure: Numeric,
    mechanisms: []const u8,
};

pub const PlainChecker = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, creds: PlainCredentials) bool,

    pub fn verify(self: PlainChecker, creds: PlainCredentials) bool {
        return self.verifyFn(self.ptr, creds);
    }
};

pub const ExternalChecker = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, certfp: []const u8, authzid: []const u8) bool,

    pub fn verify(self: ExternalChecker, certfp: []const u8, authzid: []const u8) bool {
        return self.verifyFn(self.ptr, certfp, authzid);
    }
};

/// Injected predicate: does `account` have active TOTP two-factor auth? Backed
/// by the daemon's persisted enrollment store. Used to refuse a knowledge-factor
/// SASL success (PLAIN/SCRAM) that carries no second factor.
pub const TotpGate = struct {
    ptr: *anyopaque,
    activeFn: *const fn (ptr: *anyopaque, account: []const u8) bool,

    pub fn active(self: TotpGate, account: []const u8) bool {
        return self.activeFn(self.ptr, account);
    }
};

/// Injected predicate: is `account` SUSPENDED or FORBIDDEN and therefore barred
/// from every credential path? Backed by the daemon's services account store.
/// Consulted at SASL success so a mechanism whose verification never checks
/// account status (a SCRAM proof verifies from stored key material alone; an
/// OAUTHBEARER token from the IdP) still cannot bind a locked account. The
/// backing implementation is fail-closed: an undecodable status reads as blocked.
pub const AccountStatusGate = struct {
    ptr: *anyopaque,
    blockedFn: *const fn (ptr: *anyopaque, account: []const u8) bool,

    pub fn blocked(self: AccountStatusGate, account: []const u8) bool {
        return self.blockedFn(self.ptr, account);
    }
};

/// Injected predicate: does the canonical account have a registered services
/// record? A reservation without an account record is not registered.
pub const AccountKnownGate = struct {
    ptr: *anyopaque,
    knownFn: *const fn (ptr: *anyopaque, account: []const u8) bool,

    pub fn known(self: AccountKnownGate, account: []const u8) bool {
        return self.knownFn(self.ptr, account);
    }
};

/// Whether `mechanism` authenticates purely by a knowledge factor (a password or
/// password-derived secret) and therefore requires a TOTP second factor when the
/// account has 2FA. EXTERNAL (client cert) and OAUTHBEARER (external IdP) are
/// other/possession factors; SESSION-TOKEN is a prior-auth continuation (scoped
/// by token revocation on a 2FA change); ANONYMOUS is a guest (no account).
pub fn mechanismIsKnowledgeFactor(mechanism: Mechanism) bool {
    return switch (mechanism) {
        .plain, .scram_sha_256, .scram_sha_512, .scram_sha_512_plus => true,
        .external, .oauthbearer, .session_token, .anonymous => false,
    };
}

pub const ScramRecord = struct {
    salt: []const u8,
    iterations: u32,
    stored_key: [Sha256.digest_len]u8,
    server_key: [Sha256.digest_len]u8,
};

pub const ScramLookup = struct {
    ptr: *anyopaque,
    lookupFn: *const fn (ptr: *anyopaque, username: []const u8) ?ScramRecord,

    pub fn lookup(self: ScramLookup, username: []const u8) ?ScramRecord {
        return self.lookupFn(self.ptr, username);
    }
};

pub const Callbacks = struct {
    plain: ?PlainChecker = null,
    external: ?ExternalChecker = null,
    scram: ?ScramLookup = null,
};

pub const Dispatcher = struct {
    callbacks: Callbacks,
    tls_certfp: ?[]const u8 = null,
    server_nonce: []const u8,
    state: State = .idle,
    authcid_buf: [MAX_SCRAM_USERNAME]u8 = undefined,
    authcid_len: usize = 0,

    const State = union(enum) {
        idle,
        plain,
        external,
        scram: ScramState,
    };

    pub fn init(callbacks: Callbacks, server_nonce: []const u8) Dispatcher {
        return .{ .callbacks = callbacks, .server_nonce = server_nonce };
    }

    pub fn listMechanisms(self: *const Dispatcher, out: []u8) SaslError!Decision {
        var n: usize = 0;
        inline for (.{ Mechanism.plain, Mechanism.external, Mechanism.scram_sha_256 }) |mech| {
            if (!self.enabled(mech)) continue;
            const prefix: usize = if (n == 0) 0 else 1;
            if (n + prefix + mech.name().len > out.len) return error.OutputTooSmall;
            if (prefix == 1) {
                out[n] = ' ';
                n += 1;
            }
            @memcpy(out[n..][0..mech.name().len], mech.name());
            n += mech.name().len;
        }
        return .{ .mechanisms = out[0..n] };
    }

    pub fn start(self: *Dispatcher, mech: Mechanism) Decision {
        if (!self.enabled(mech)) return .{ .failure = .ERR_SASLFAIL };
        self.state = switch (mech) {
            .plain => .plain,
            .external => .external,
            .scram_sha_256 => .{ .scram = ScramState.init() },
            .scram_sha_512,
            .scram_sha_512_plus,
            .session_token,
            .oauthbearer,
            .anonymous,
            => return .{ .failure = .ERR_SASLFAIL },
        };
        return .{ .continue_ = "+" };
    }

    pub fn abort(self: *Dispatcher) Decision {
        self.state = .idle;
        return .{ .failure = .ERR_SASLABORTED };
    }

    pub fn receive(
        self: *Dispatcher,
        payload_b64: []const u8,
        decode_buf: []u8,
        out: []u8,
    ) SaslError!Decision {
        if (std.mem.eql(u8, payload_b64, "*")) return self.abort();
        const raw = decodeBase64(payload_b64, decode_buf) catch return .{ .failure = .ERR_SASLTOOLONG };

        switch (self.state) {
            .idle => return .{ .failure = .ERR_SASLFAIL },
            .plain => return self.stepPlain(raw),
            .external => return self.stepExternal(raw),
            .scram => |*scram| return self.stepScram(scram, raw, out),
        }
    }

    fn enabled(self: *const Dispatcher, mech: Mechanism) bool {
        return switch (mech) {
            .plain => self.callbacks.plain != null,
            .external => self.callbacks.external != null and self.tls_certfp != null,
            .scram_sha_256 => self.callbacks.scram != null and self.server_nonce.len != 0,
            .scram_sha_512,
            .scram_sha_512_plus,
            .session_token,
            .oauthbearer,
            .anonymous,
            => false,
        };
    }

    fn stepPlain(self: *Dispatcher, raw: []const u8) Decision {
        const creds = parsePlain(raw) catch {
            self.state = .idle;
            return .{ .failure = .ERR_SASLFAIL };
        };
        const checker = self.callbacks.plain orelse return .{ .failure = .ERR_SASLFAIL };
        self.state = .idle;
        if (!checker.verify(creds)) return .{ .failure = .ERR_SASLFAIL };
        return .{ .success = .{ .identity = .{ .authcid = creds.authcid, .authzid = nonEmpty(creds.authzid) } } };
    }

    fn stepExternal(self: *Dispatcher, raw: []const u8) Decision {
        const certfp = self.tls_certfp orelse {
            self.state = .idle;
            return .{ .failure = .ERR_SASLFAIL };
        };
        const checker = self.callbacks.external orelse {
            self.state = .idle;
            return .{ .failure = .ERR_SASLFAIL };
        };
        self.state = .idle;
        if (!checker.verify(certfp, raw)) return .{ .failure = .ERR_SASLFAIL };
        return .{ .success = .{ .identity = .{ .authcid = certfp, .authzid = nonEmpty(raw) } } };
    }

    fn stepScram(self: *Dispatcher, scram: *ScramState, raw: []const u8, out: []u8) SaslError!Decision {
        const lookup = self.callbacks.scram orelse return .{ .failure = .ERR_SASLFAIL };
        switch (scram.step) {
            .client_first => {
                const challenge = scram.clientFirst(raw, lookup, self.server_nonce, out) catch |err| {
                    self.state = .idle;
                    return if (err == error.OutputTooSmall) err else .{ .failure = .ERR_SASLFAIL };
                };
                return .{ .continue_ = challenge };
            },
            .client_final => {
                const final_data = scram.clientFinal(raw, out) catch |err| {
                    self.state = .idle;
                    return if (err == error.OutputTooSmall) err else .{ .failure = .ERR_SASLFAIL };
                };
                const authcid = self.copyAuthcid(scram.username()) orelse {
                    self.state = .idle;
                    return .{ .failure = .ERR_SASLFAIL };
                };
                self.state = .idle;
                return .{ .success = .{ .identity = .{ .authcid = authcid }, .final_data = final_data } };
            },
        }
    }

    fn copyAuthcid(self: *Dispatcher, authcid: []const u8) ?[]const u8 {
        if (authcid.len == 0 or authcid.len > self.authcid_buf.len) return null;
        @memcpy(self.authcid_buf[0..authcid.len], authcid);
        self.authcid_len = authcid.len;
        return self.authcid_buf[0..self.authcid_len];
    }
};

pub fn parsePlain(raw: []const u8) SaslError!PlainCredentials {
    const first = std.mem.indexOfScalar(u8, raw, 0) orelse return error.InvalidMessage;
    const rest = raw[first + 1 ..];
    const second_rel = std.mem.indexOfScalar(u8, rest, 0) orelse return error.InvalidMessage;
    const second = first + 1 + second_rel;
    if (std.mem.indexOfScalar(u8, raw[second + 1 ..], 0) != null) return error.InvalidMessage;
    if (second == first + 1) return error.InvalidMessage;
    return .{
        .authzid = raw[0..first],
        .authcid = raw[first + 1 .. second],
        .password = raw[second + 1 ..],
    };
}

pub const ScramKeys = struct {
    salted_password: [Sha256.digest_len]u8,
    client_key: [Sha256.digest_len]u8,
    stored_key: [Sha256.digest_len]u8,
    server_key: [Sha256.digest_len]u8,

    pub fn wipe(self: *ScramKeys) void {
        secureZero(&self.salted_password);
        secureZero(&self.client_key);
        secureZero(&self.stored_key);
        secureZero(&self.server_key);
    }
};

pub fn deriveScramKeys(password: []const u8, salt: []const u8, iterations: u32) SaslError!ScramKeys {
    var salted: [Sha256.digest_len]u8 = undefined;
    try hi(password, salt, iterations, &salted);
    const client_key = HmacSha256.create(&salted, "Client Key");
    const stored_key = Sha256.hash(&client_key);
    const server_key = HmacSha256.create(&salted, "Server Key");
    return .{
        .salted_password = salted,
        .client_key = client_key,
        .stored_key = stored_key,
        .server_key = server_key,
    };
}

pub fn recordFromPassword(password: []const u8, salt: []const u8, iterations: u32) SaslError!ScramRecord {
    var keys = try deriveScramKeys(password, salt, iterations);
    defer keys.wipe();
    return .{
        .salt = salt,
        .iterations = iterations,
        .stored_key = keys.stored_key,
        .server_key = keys.server_key,
    };
}

fn hi(password: []const u8, salt: []const u8, iterations: u32, out: *[Sha256.digest_len]u8) SaslError!void {
    if (iterations == 0) return error.InvalidMessage;
    var block_salt: [MAX_SCRAM_SALT + 4]u8 = undefined;
    if (salt.len > MAX_SCRAM_SALT) return error.InvalidMessage;
    @memcpy(block_salt[0..salt.len], salt);
    std.mem.writeInt(u32, block_salt[salt.len..][0..4], 1, .big);

    var u = HmacSha256.create(password, block_salt[0 .. salt.len + 4]);
    @memcpy(out, &u);
    var round: u32 = 1;
    while (round < iterations) : (round += 1) {
        u = HmacSha256.create(password, &u);
        for (out, u) |*dst, b| dst.* ^= b;
    }
    secureZero(&u);
    secureZero(&block_salt);
}

const ScramStep = enum {
    client_first,
    client_final,
};

const ScramState = struct {
    step: ScramStep = .client_first,
    gs2_header_buf: [32]u8 = undefined,
    gs2_header_len: usize = 0,
    client_first_bare_buf: [MAX_SCRAM_MESSAGE]u8 = undefined,
    client_first_bare_len: usize = 0,
    server_first_buf: [MAX_SCRAM_MESSAGE]u8 = undefined,
    server_first_len: usize = 0,
    username_buf: [MAX_SCRAM_USERNAME]u8 = undefined,
    username_len: usize = 0,
    nonce_buf: [MAX_SCRAM_NONCE]u8 = undefined,
    nonce_len: usize = 0,
    stored_key: [Sha256.digest_len]u8 = undefined,
    server_key: [Sha256.digest_len]u8 = undefined,

    fn init() ScramState {
        return .{};
    }

    fn username(self: *const ScramState) []const u8 {
        return self.username_buf[0..self.username_len];
    }

    fn clientFirst(
        self: *ScramState,
        raw: []const u8,
        lookup: ScramLookup,
        server_nonce: []const u8,
        out: []u8,
    ) SaslError![]const u8 {
        const header_len = gs2HeaderLen(raw) orelse return error.InvalidMessage;
        if (header_len > self.gs2_header_buf.len) return error.InvalidMessage;
        const bare = raw[header_len..];
        if (bare.len > self.client_first_bare_buf.len) return error.InvalidMessage;
        @memcpy(self.gs2_header_buf[0..header_len], raw[0..header_len]);
        self.gs2_header_len = header_len;
        @memcpy(self.client_first_bare_buf[0..bare.len], bare);
        self.client_first_bare_len = bare.len;

        const parsed = try parseClientFirstBare(bare, &self.username_buf);
        self.username_len = parsed.username_len;
        if (parsed.nonce.len + server_nonce.len > self.nonce_buf.len) return error.InvalidMessage;
        @memcpy(self.nonce_buf[0..parsed.nonce.len], parsed.nonce);
        @memcpy(self.nonce_buf[parsed.nonce.len..][0..server_nonce.len], server_nonce);
        self.nonce_len = parsed.nonce.len + server_nonce.len;

        const record = lookup.lookup(self.username()) orelse return error.InvalidMessage;
        if (record.iterations == 0 or record.salt.len > MAX_SCRAM_SALT) return error.InvalidMessage;
        self.stored_key = record.stored_key;
        self.server_key = record.server_key;

        var salt_b64_buf: [std.base64.standard.Encoder.calcSize(MAX_SCRAM_SALT)]u8 = undefined;
        const salt_b64 = std.base64.standard.Encoder.encode(&salt_b64_buf, record.salt);
        const server_first = std.fmt.bufPrint(
            &self.server_first_buf,
            "r={s},s={s},i={d}",
            .{ self.nonce_buf[0..self.nonce_len], salt_b64, record.iterations },
        ) catch return error.InvalidMessage;
        self.server_first_len = server_first.len;
        self.step = .client_final;
        return encodeBase64(server_first, out);
    }

    fn clientFinal(self: *ScramState, raw: []const u8, out: []u8) SaslError![]const u8 {
        const proof_index = std.mem.indexOf(u8, raw, ",p=") orelse return error.InvalidMessage;
        const without_proof = raw[0..proof_index];
        const parsed = try parseClientFinal(raw);
        if (!std.mem.eql(u8, parsed.nonce, self.nonce_buf[0..self.nonce_len])) return error.InvalidMessage;

        var cb_buf: [32]u8 = undefined;
        const cb = decodeBase64(parsed.channel_binding, &cb_buf) catch return error.InvalidMessage;
        if (!std.mem.eql(u8, cb, self.gs2_header_buf[0..self.gs2_header_len])) return error.InvalidMessage;

        var proof: [Sha256.digest_len]u8 = undefined;
        const proof_decoded = decodeBase64(parsed.proof, &proof) catch return error.InvalidMessage;
        if (proof_decoded.len != proof.len) return error.InvalidMessage;

        var auth_message_buf: [MAX_SCRAM_MESSAGE * 3]u8 = undefined;
        const auth_message = std.fmt.bufPrint(
            &auth_message_buf,
            "{s},{s},{s}",
            .{
                self.client_first_bare_buf[0..self.client_first_bare_len],
                self.server_first_buf[0..self.server_first_len],
                without_proof,
            },
        ) catch return error.InvalidMessage;

        const client_sig = HmacSha256.create(&self.stored_key, auth_message);
        var client_key: [Sha256.digest_len]u8 = undefined;
        for (&client_key, proof, client_sig) |*dst, proof_byte, sig_byte| {
            dst.* = proof_byte ^ sig_byte;
        }
        const stored_check = Sha256.hash(&client_key);
        const ok = ctEql(&stored_check, &self.stored_key);
        secureZero(&client_key);
        secureZero(&proof);
        if (!ok) return error.InvalidMessage;

        const server_sig = HmacSha256.create(&self.server_key, auth_message);
        var verifier_b64_buf: [std.base64.standard.Encoder.calcSize(Sha256.digest_len)]u8 = undefined;
        const verifier_b64 = std.base64.standard.Encoder.encode(&verifier_b64_buf, &server_sig);
        var final_buf: [2 + verifier_b64_buf.len]u8 = undefined;
        const final = std.fmt.bufPrint(&final_buf, "v={s}", .{verifier_b64}) catch return error.InvalidMessage;
        return encodeBase64(final, out);
    }
};

fn gs2HeaderLen(raw: []const u8) ?usize {
    if (std.mem.startsWith(u8, raw, "n,,")) return 3;
    if (std.mem.startsWith(u8, raw, "y,,")) return 3;
    if (std.mem.startsWith(u8, raw, "n,a=")) {
        const comma = std.mem.indexOfScalarPos(u8, raw, 4, ',') orelse return null;
        if (comma + 1 >= raw.len or raw[comma + 1] != ',') return null;
        return comma + 2;
    }
    return null;
}

const ClientFirstParsed = struct {
    username_len: usize,
    nonce: []const u8,
};

fn parseClientFirstBare(raw: []const u8, username_buf: []u8) SaslError!ClientFirstParsed {
    var username_len: ?usize = null;
    var nonce: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        if (attr.len < 3 or attr[1] != '=') return error.InvalidMessage;
        switch (attr[0]) {
            'n' => username_len = try decodeSaslName(attr[2..], username_buf),
            'r' => nonce = attr[2..],
            'm' => return error.InvalidMessage,
            else => {},
        }
    }
    const n = username_len orelse return error.InvalidMessage;
    const r = nonce orelse return error.InvalidMessage;
    if (n == 0 or r.len == 0) return error.InvalidMessage;
    return .{ .username_len = n, .nonce = r };
}

const ClientFinalParsed = struct {
    channel_binding: []const u8,
    nonce: []const u8,
    proof: []const u8,
};

fn parseClientFinal(raw: []const u8) SaslError!ClientFinalParsed {
    var cb: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var proof: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |attr| {
        if (attr.len < 3 or attr[1] != '=') return error.InvalidMessage;
        switch (attr[0]) {
            'c' => cb = attr[2..],
            'r' => nonce = attr[2..],
            'p' => proof = attr[2..],
            else => {},
        }
    }
    return .{
        .channel_binding = cb orelse return error.InvalidMessage,
        .nonce = nonce orelse return error.InvalidMessage,
        .proof = proof orelse return error.InvalidMessage,
    };
}

fn decodeSaslName(raw: []const u8, out: []u8) SaslError!usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        if (n == out.len) return error.InvalidMessage;
        if (raw[i] != '=') {
            out[n] = raw[i];
            n += 1;
            i += 1;
            continue;
        }
        if (i + 2 >= raw.len) return error.InvalidMessage;
        if (raw[i + 1] == '2' and raw[i + 2] == 'C') {
            out[n] = ',';
        } else if (raw[i + 1] == '3' and raw[i + 2] == 'D') {
            out[n] = '=';
        } else {
            return error.InvalidMessage;
        }
        n += 1;
        i += 3;
    }
    return n;
}

fn decodeBase64(src: []const u8, out: []u8) ![]const u8 {
    if (std.mem.eql(u8, src, "+")) return out[0..0];
    const padded_size = std.base64.standard.Decoder.calcSizeForSlice(src) catch null;
    if (padded_size) |size| {
        if (size > out.len) return error.NoSpaceLeft;
        try std.base64.standard.Decoder.decode(out[0..size], src);
        return out[0..size];
    }
    const size = try std.base64.standard_no_pad.Decoder.calcSizeForSlice(src);
    if (size > out.len) return error.NoSpaceLeft;
    try std.base64.standard_no_pad.Decoder.decode(out[0..size], src);
    return out[0..size];
}

fn encodeBase64(src: []const u8, out: []u8) SaslError![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(src.len);
    if (size > out.len) return error.OutputTooSmall;
    return std.base64.standard.Encoder.encode(out[0..size], src);
}

fn nonEmpty(value: []const u8) ?[]const u8 {
    return if (value.len == 0) null else value;
}

fn ctEql(a: []const u8, b: []const u8) bool {
    var diff: u8 = @intCast(a.len ^ b.len);
    const n = @min(a.len, b.len);
    for (a[0..n], b[0..n]) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn b64(comptime text: []const u8) [std.base64.standard.Encoder.calcSize(text.len)]u8 {
    var out: [std.base64.standard.Encoder.calcSize(text.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, text);
    return out;
}

test "mechanismIsKnowledgeFactor classifies every SASL mechanism" {
    // Knowledge factors (need a TOTP second factor when 2FA is active).
    try std.testing.expect(mechanismIsKnowledgeFactor(.plain));
    try std.testing.expect(mechanismIsKnowledgeFactor(.scram_sha_256));
    try std.testing.expect(mechanismIsKnowledgeFactor(.scram_sha_512));
    try std.testing.expect(mechanismIsKnowledgeFactor(.scram_sha_512_plus));
    // Other/possession/continuation factors (not gated by TOTP).
    try std.testing.expect(!mechanismIsKnowledgeFactor(.external));
    try std.testing.expect(!mechanismIsKnowledgeFactor(.oauthbearer));
    try std.testing.expect(!mechanismIsKnowledgeFactor(.session_token));
    try std.testing.expect(!mechanismIsKnowledgeFactor(.anonymous));
}

test "PLAIN parses credentials and dispatcher accepts or rejects" {
    const raw = "authz\x00kain\x00correct";
    const creds = try parsePlain(raw);
    try std.testing.expectEqualStrings("authz", creds.authzid);
    try std.testing.expectEqualStrings("kain", creds.authcid);
    try std.testing.expectEqualStrings("correct", creds.password);

    const Db = struct {
        accept: bool,

        fn verify(ptr: *anyopaque, plain: PlainCredentials) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.accept and
                std.mem.eql(u8, plain.authcid, "kain") and
                std.mem.eql(u8, plain.password, "correct");
        }
    };

    var db = Db{ .accept = true };
    var d = Dispatcher.init(.{ .plain = .{ .ptr = &db, .verifyFn = Db.verify } }, "nonce");
    try std.testing.expectEqualStrings("+", d.start(.plain).continue_);
    var decode_buf: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    const encoded = b64(raw);
    const ok = try d.receive(&encoded, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.RPL_SASLSUCCESS, ok.success.complete);
    try std.testing.expectEqualStrings("kain", ok.success.identity.authcid);

    db.accept = false;
    _ = d.start(.plain);
    const rejected = try d.receive(&encoded, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.ERR_SASLFAIL, rejected.failure);
}

test "EXTERNAL accepts and rejects certfp identity" {
    const Db = struct {
        fn verify(_: *anyopaque, certfp: []const u8, authzid: []const u8) bool {
            return std.mem.eql(u8, certfp, "ABCD") and std.mem.eql(u8, authzid, "kain");
        }
    };
    var token: u8 = 0;
    var d = Dispatcher.init(.{ .external = .{ .ptr = &token, .verifyFn = Db.verify } }, "nonce");
    d.tls_certfp = "ABCD";
    try std.testing.expectEqualStrings("+", d.start(.external).continue_);
    var decode_buf: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const authzid = b64("kain");
    const ok = try d.receive(&authzid, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.RPL_SASLSUCCESS, ok.success.complete);
    try std.testing.expectEqualStrings("ABCD", ok.success.identity.authcid);

    _ = d.start(.external);
    const bad = b64("other");
    const rejected = try d.receive(&bad, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.ERR_SASLFAIL, rejected.failure);
}

test "SCRAM-SHA-256 full handshake accepts correct proof and rejects wrong proof" {
    const Db = struct {
        record: ScramRecord,

        fn lookup(ptr: *anyopaque, username: []const u8) ?ScramRecord {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.record;
        }
    };

    const salt = "saltSALTsalt";
    const iterations: u32 = 4096;
    const password = "pencil";
    var db = Db{ .record = try recordFromPassword(password, salt, iterations) };
    var d = Dispatcher.init(.{ .scram = .{ .ptr = &db, .lookupFn = Db.lookup } }, "SERVERNONCE");

    var decode_buf: [MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    var out: [MAX_AUTHENTICATE_PAYLOAD]u8 = undefined;
    try std.testing.expectEqualStrings("+", d.start(.scram_sha_256).continue_);

    const client_first = b64("n,,n=user,r=CLIENTNONCE");
    const first = try d.receive(&client_first, &decode_buf, &out);
    const server_first_b64 = first.continue_;
    var server_first_raw: [MAX_SCRAM_MESSAGE]u8 = undefined;
    const server_first = try decodeBase64(server_first_b64, &server_first_raw);
    try std.testing.expectEqualStrings("r=CLIENTNONCESERVERNONCE,s=c2FsdFNBTFRzYWx0,i=4096", server_first);

    const client_final = try makeClientFinal(
        password,
        salt,
        iterations,
        "n=user,r=CLIENTNONCE",
        server_first,
        "n,,",
        "CLIENTNONCESERVERNONCE",
        false,
        &out,
    );
    const ok = try d.receive(client_final, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.RPL_SASLSUCCESS, ok.success.complete);
    try std.testing.expect(ok.success.final_data != null);

    _ = d.start(.scram_sha_256);
    _ = try d.receive(&client_first, &decode_buf, &out);
    const bad_final = try makeClientFinal(
        password,
        salt,
        iterations,
        "n=user,r=CLIENTNONCE",
        server_first,
        "n,,",
        "CLIENTNONCESERVERNONCE",
        true,
        &out,
    );
    const rejected = try d.receive(bad_final, &decode_buf, &out);
    try std.testing.expectEqual(Numeric.ERR_SASLFAIL, rejected.failure);
}

fn makeClientFinal(
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    client_first_bare: []const u8,
    server_first: []const u8,
    gs2_header: []const u8,
    nonce: []const u8,
    corrupt: bool,
    out: []u8,
) SaslError![]const u8 {
    var keys = try deriveScramKeys(password, salt, iterations);
    defer keys.wipe();
    var cb_buf: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
    const cb = std.base64.standard.Encoder.encode(&cb_buf, gs2_header);
    var without_proof_buf: [MAX_SCRAM_MESSAGE]u8 = undefined;
    const without_proof = std.fmt.bufPrint(&without_proof_buf, "c={s},r={s}", .{ cb, nonce }) catch return error.InvalidMessage;
    var auth_message_buf: [MAX_SCRAM_MESSAGE * 3]u8 = undefined;
    const auth_message = std.fmt.bufPrint(&auth_message_buf, "{s},{s},{s}", .{ client_first_bare, server_first, without_proof }) catch return error.InvalidMessage;
    const sig = HmacSha256.create(&keys.stored_key, auth_message);
    var proof = keys.client_key;
    for (&proof, sig) |*p, s| p.* ^= s;
    if (corrupt) proof[0] ^= 0x01;
    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(Sha256.digest_len)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &proof);
    var final_buf: [MAX_SCRAM_MESSAGE]u8 = undefined;
    const final = std.fmt.bufPrint(&final_buf, "{s},p={s}", .{ without_proof, proof_b64 }) catch return error.InvalidMessage;
    return encodeBase64(final, out);
}

test {
    std.testing.refAllDecls(@This());
}
