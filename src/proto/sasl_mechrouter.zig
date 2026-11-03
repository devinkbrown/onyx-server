// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SASL mechanism router.
//!
//! This module is protocol-only. It consumes AUTHENTICATE base64 chunks and
//! dispatches to the selected responder without doing I/O or daemon work.
const std = @import("std");

const sasl = @import("sasl.zig");
const scram256 = @import("sasl_scram_server.zig");
const scram512 = @import("sasl_scram512_server.zig");
const oauthbearer = @import("sasl_oauthbearer.zig");
const anonymous = @import("sasl_anonymous.zig");

pub const SUPPORTED_MECHANISMS = "PLAIN EXTERNAL SCRAM-SHA-256 SCRAM-SHA-256-PLUS SCRAM-SHA-512 SCRAM-SHA-512-PLUS SESSION-TOKEN OAUTHBEARER ANONYMOUS";
pub const MAX_AUTHENTICATE_CHUNK: usize = 400;
pub const MAX_RAW_MESSAGE: usize = sasl.MAX_SCRAM_MESSAGE;
pub const MAX_B64_MESSAGE: usize = std.base64.standard.Encoder.calcSize(MAX_RAW_MESSAGE);
pub const MAX_ACCOUNT: usize = sasl.MAX_SCRAM_USERNAME;

pub const Mechanism = enum {
    plain,
    external,
    scram_sha_256,
    scram_sha_256_plus,
    scram_sha_512,
    scram_sha_512_plus,
    session_token,
    oauthbearer,
    anonymous,

    pub fn parse(name_text: []const u8) ?Mechanism {
        if (std.ascii.eqlIgnoreCase(name_text, "PLAIN")) return .plain;
        if (std.ascii.eqlIgnoreCase(name_text, "EXTERNAL")) return .external;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-256-PLUS")) return .scram_sha_256_plus;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-512")) return .scram_sha_512;
        if (std.ascii.eqlIgnoreCase(name_text, "SCRAM-SHA-512-PLUS")) return .scram_sha_512_plus;
        if (std.ascii.eqlIgnoreCase(name_text, "SESSION-TOKEN")) return .session_token;
        if (std.ascii.eqlIgnoreCase(name_text, "OAUTHBEARER")) return .oauthbearer;
        if (std.ascii.eqlIgnoreCase(name_text, "ANONYMOUS")) return .anonymous;
        return null;
    }

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .external => "EXTERNAL",
            .scram_sha_256 => "SCRAM-SHA-256",
            .scram_sha_256_plus => "SCRAM-SHA-256-PLUS",
            .scram_sha_512 => "SCRAM-SHA-512",
            .scram_sha_512_plus => "SCRAM-SHA-512-PLUS",
            .session_token => "SESSION-TOKEN",
            .oauthbearer => "OAUTHBEARER",
            .anonymous => "ANONYMOUS",
        };
    }
};

pub const Failure = enum {
    unknown_mechanism,
    unavailable,
    invalid_state,
    invalid_message,
    invalid_credentials,
    too_long,
    output_too_small,
    aborted,
};

pub const Success = struct {
    account: []const u8,
    final_data: ?[]const u8 = null,
    guest: bool = false,
    issue_session_token: bool = true,
    /// Fingerprint of the exact durable SCRAM verifier this exchange proved
    /// against (SCRAM mechanisms only). The session-binding layer re-checks
    /// it against the account service before login so a mid-exchange
    /// credential rotation cannot bind a different verifier.
    scram_credential: ?sasl.ScramCredentialFingerprint = null,
};

pub const Outcome = union(enum) {
    /// AUTHENTICATE payload for the caller to send. The literal "+" means an
    /// empty challenge; an empty slice means the router is awaiting more input
    /// chunks before producing an outbound payload.
    continue_: []const u8,
    success: Success,
    fail: Failure,
};

pub const PlainLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8,

    pub fn verify(self: PlainLookup, creds: sasl.PlainCredentials) ?[]const u8 {
        return self.verifyFn(self.ptr, creds);
    }
};

pub const ExternalLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8,

    pub fn verify(self: ExternalLookup, certfp: []const u8, authzid: []const u8) ?[]const u8 {
        return self.verifyFn(self.ptr, certfp, authzid);
    }
};

pub const Scram256Lookup = struct {
    ptr: *anyopaque,
    lookupFn: *const fn (ptr: *anyopaque, username: []const u8) ?scram256.Credential,

    pub fn lookup(self: Scram256Lookup, username: []const u8) ?scram256.Credential {
        return self.lookupFn(self.ptr, username);
    }
};

pub const Scram512Lookup = struct {
    ptr: *anyopaque,
    lookupFn: *const fn (ptr: *anyopaque, username: []const u8) ?scram512.Credential,

    pub fn lookup(self: Scram512Lookup, username: []const u8) ?scram512.Credential {
        return self.lookupFn(self.ptr, username);
    }
};

pub const SessionTokenCredentials = struct {
    authcid: []const u8,
    token: []const u8,
};

pub const SessionTokenLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, creds: SessionTokenCredentials, account_out: []u8) ?[]const u8,

    pub fn verify(self: SessionTokenLookup, creds: SessionTokenCredentials, account_out: []u8) ?[]const u8 {
        return self.verifyFn(self.ptr, creds, account_out);
    }
};

pub const OAuthBearerLookup = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (ptr: *anyopaque, token: []const u8, authzid: ?[]const u8, account_out: []u8) ?[]const u8,

    pub fn verify(self: OAuthBearerLookup, token: []const u8, authzid: ?[]const u8, account_out: []u8) ?[]const u8 {
        return self.verifyFn(self.ptr, token, authzid, account_out);
    }
};

pub const Callbacks = struct {
    plain: ?PlainLookup = null,
    external: ?ExternalLookup = null,
    scram256: ?Scram256Lookup = null,
    scram512: ?Scram512Lookup = null,
    session_token: ?SessionTokenLookup = null,
    oauthbearer: ?OAuthBearerLookup = null,
    anonymous: bool = false,
};

pub const Router = struct {
    callbacks: Callbacks,
    server_nonce: []const u8,
    raw_message_limit: usize = MAX_RAW_MESSAGE,
    tls_certfp: ?[]const u8 = null,
    tls_exporter: ?[scram512.tls_exporter_len]u8 = null,
    state: State = .idle,
    pending_b64: [MAX_B64_MESSAGE]u8 = undefined,
    pending_len: usize = 0,
    decode_buf: [MAX_RAW_MESSAGE]u8 = undefined,
    account_buf: [MAX_ACCOUNT]u8 = undefined,
    account_len: usize = 0,
    /// Fingerprint of the verifier fetched at SCRAM client-first, carried to
    /// the success outcome at client-final. Cleared on every exchange reset.
    pending_scram_fingerprint: ?sasl.ScramCredentialFingerprint = null,

    const State = union(enum) {
        idle,
        plain,
        external,
        session_token,
        oauthbearer,
        anonymous,
        scram256: scram256.Server,
        scram512: scram512.Server,
    };

    pub fn init(callbacks: Callbacks, server_nonce: []const u8) Router {
        return initWithLimit(callbacks, server_nonce, MAX_RAW_MESSAGE);
    }

    pub fn initWithLimit(callbacks: Callbacks, server_nonce: []const u8, raw_message_limit: usize) Router {
        return .{
            .callbacks = callbacks,
            .server_nonce = server_nonce,
            .raw_message_limit = @min(raw_message_limit, MAX_RAW_MESSAGE),
        };
    }

    pub fn mechanismList() []const u8 {
        return SUPPORTED_MECHANISMS;
    }

    pub fn start(self: *Router, mechanism_name: []const u8) Outcome {
        const mechanism = Mechanism.parse(mechanism_name) orelse {
            self.resetExchange();
            return .{ .fail = .unknown_mechanism };
        };
        if (!self.enabled(mechanism)) {
            self.resetExchange();
            return .{ .fail = .unavailable };
        }
        self.pending_len = 0;
        self.account_len = 0;
        self.state = switch (mechanism) {
            .plain => .plain,
            .external => .external,
            .session_token => .session_token,
            .oauthbearer => .oauthbearer,
            .anonymous => .anonymous,
            .scram_sha_256 => .{ .scram256 = scram256.Server.init() },
            .scram_sha_256_plus => .{ .scram256 = scram256.Server.initTlsExporter(self.tls_exporter.?) },
            .scram_sha_512 => .{ .scram512 = scram512.Server.init() },
            .scram_sha_512_plus => .{ .scram512 = scram512.Server.initTlsExporter(self.tls_exporter.?) },
        };
        return .{ .continue_ = "+" };
    }

    pub fn abort(self: *Router) Outcome {
        self.resetExchange();
        return .{ .fail = .aborted };
    }

    pub fn receive(self: *Router, client_chunk_b64: []const u8, out: []u8) Outcome {
        if (std.mem.eql(u8, client_chunk_b64, "*")) return self.abort();
        if (client_chunk_b64.len > MAX_AUTHENTICATE_CHUNK) return self.failReset(.too_long);
        if (self.pending_len + client_chunk_b64.len > self.pending_b64.len) return self.failReset(.too_long);

        @memcpy(self.pending_b64[self.pending_len..][0..client_chunk_b64.len], client_chunk_b64);
        self.pending_len += client_chunk_b64.len;
        if (client_chunk_b64.len == MAX_AUTHENTICATE_CHUNK) return .{ .continue_ = "" };

        const pending = self.pending_b64[0..self.pending_len];
        if ((decodedBase64Len(pending) catch return self.failReset(.invalid_message)) > self.raw_message_limit) {
            return self.failReset(.too_long);
        }
        const raw = decodeBase64(pending, &self.decode_buf) catch return self.failReset(.invalid_message);
        self.pending_len = 0;

        return switch (self.state) {
            .idle => self.failReset(.invalid_state),
            .plain => self.stepPlain(raw),
            .external => self.stepExternal(raw),
            .session_token => self.stepSessionToken(raw),
            .oauthbearer => self.stepOAuthBearer(raw),
            .anonymous => self.stepAnonymous(raw),
            .scram256 => |*server| self.stepScram256(server, raw, out),
            .scram512 => |*server| self.stepScram512(server, raw, out),
        };
    }

    fn enabled(self: *const Router, mechanism: Mechanism) bool {
        return switch (mechanism) {
            .plain => self.callbacks.plain != null,
            .external => self.callbacks.external != null and self.tls_certfp != null,
            .scram_sha_256 => self.callbacks.scram256 != null and self.server_nonce.len != 0,
            .scram_sha_256_plus => self.callbacks.scram256 != null and self.server_nonce.len != 0 and self.tls_exporter != null,
            .scram_sha_512 => self.callbacks.scram512 != null and self.server_nonce.len != 0,
            .scram_sha_512_plus => self.callbacks.scram512 != null and self.server_nonce.len != 0 and self.tls_exporter != null,
            .session_token => self.callbacks.session_token != null,
            .oauthbearer => self.callbacks.oauthbearer != null,
            .anonymous => self.callbacks.anonymous,
        };
    }

    fn stepPlain(self: *Router, raw: []const u8) Outcome {
        const checker = self.callbacks.plain orelse return self.failReset(.unavailable);
        const creds = sasl.parsePlain(raw) catch return self.failReset(.invalid_message);
        const account = checker.verify(creds) orelse return self.failReset(.invalid_credentials);
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied } };
    }

    fn stepExternal(self: *Router, raw: []const u8) Outcome {
        const certfp = self.tls_certfp orelse return self.failReset(.unavailable);
        const checker = self.callbacks.external orelse return self.failReset(.unavailable);
        const account = checker.verify(certfp, raw) orelse return self.failReset(.invalid_credentials);
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied } };
    }

    fn stepSessionToken(self: *Router, raw: []const u8) Outcome {
        const checker = self.callbacks.session_token orelse return self.failReset(.unavailable);
        const sep = std.mem.indexOfScalar(u8, raw, 0) orelse return self.failReset(.invalid_message);
        if (sep == 0 or sep + 1 >= raw.len) return self.failReset(.invalid_message);
        const token = raw[sep + 1 ..];
        if (std.mem.indexOfScalar(u8, token, 0) != null) return self.failReset(.invalid_message);
        var account_tmp: [MAX_ACCOUNT]u8 = undefined;
        const account = checker.verify(.{ .authcid = raw[0..sep], .token = token }, &account_tmp) orelse {
            return self.failReset(.invalid_credentials);
        };
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied, .issue_session_token = false } };
    }

    fn stepOAuthBearer(self: *Router, raw: []const u8) Outcome {
        const checker = self.callbacks.oauthbearer orelse return self.failReset(.unavailable);
        const parsed = oauthbearer.ClientFirst.parse(raw) catch return self.failReset(.invalid_message);
        var account_tmp: [MAX_ACCOUNT]u8 = undefined;
        const account = checker.verify(parsed.token, parsed.authzid, &account_tmp) orelse {
            return self.failReset(.invalid_credentials);
        };
        const copied = self.copyAccount(account) orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied } };
    }

    fn stepAnonymous(self: *Router, raw: []const u8) Outcome {
        switch (anonymous.step(raw, .{ .enabled = self.callbacks.anonymous })) {
            .guest => {},
            .fail => return self.failReset(.invalid_credentials),
        }
        const copied = self.copyAccount("guest") orelse return self.failReset(.invalid_message);
        self.state = .idle;
        return .{ .success = .{ .account = copied, .guest = true, .issue_session_token = false } };
    }

    fn stepScram256(self: *Router, server: *scram256.Server, raw: []const u8, out: []u8) Outcome {
        switch (server.step) {
            .client_first => {
                var username_buf: [scram256.MAX_USERNAME]u8 = undefined;
                const parsed = scram256.parseClientFirst(raw, &username_buf) catch return self.failReset(.invalid_message);
                const lookup = self.callbacks.scram256 orelse return self.failReset(.unavailable);
                const credential = lookup.lookup(parsed.username) orelse return self.failReset(.invalid_credentials);
                self.pending_scram_fingerprint = sasl.fingerprintScramCredential(.sha256, credential.salt, credential.iterations, &credential.stored_key, &credential.server_key) orelse return self.failReset(.invalid_credentials);
                var raw_out: [scram256.MAX_MESSAGE]u8 = undefined;
                const first = server.receiveClientFirst(raw, credential, self.server_nonce, &raw_out) catch {
                    return self.failReset(.invalid_message);
                };
                const encoded = encodeBase64(first.server_first, out) catch return self.failReset(.output_too_small);
                return .{ .continue_ = encoded };
            },
            .client_final => {
                var raw_out: [scram256.MAX_MESSAGE]u8 = undefined;
                const final = server.receiveClientFinal(raw, &raw_out) catch return self.failReset(.invalid_credentials);
                const account = self.copyAccount(server.username()) orelse return self.failReset(.invalid_message);
                const encoded = encodeBase64(final.server_final, out) catch return self.failReset(.output_too_small);
                self.state = .idle;
                const fingerprint = self.pending_scram_fingerprint;
                self.pending_scram_fingerprint = null;
                return .{ .success = .{ .account = account, .final_data = encoded, .scram_credential = fingerprint } };
            },
            .complete => return self.failReset(.invalid_state),
        }
    }

    fn stepScram512(self: *Router, server: *scram512.Server, raw: []const u8, out: []u8) Outcome {
        switch (server.step) {
            .client_first => {
                var username_buf: [scram512.MAX_USERNAME]u8 = undefined;
                const parsed = scram512.parseClientFirst(raw, &username_buf) catch return self.failReset(.invalid_message);
                const lookup = self.callbacks.scram512 orelse return self.failReset(.unavailable);
                const credential = lookup.lookup(parsed.username) orelse return self.failReset(.invalid_credentials);
                self.pending_scram_fingerprint = sasl.fingerprintScramCredential(.sha512, credential.salt, credential.iterations, &credential.stored_key, &credential.server_key) orelse return self.failReset(.invalid_credentials);
                var raw_out: [scram512.MAX_MESSAGE]u8 = undefined;
                const first = server.receiveClientFirst(raw, credential, self.server_nonce, &raw_out) catch {
                    return self.failReset(.invalid_message);
                };
                const encoded = encodeBase64(first.server_first, out) catch return self.failReset(.output_too_small);
                return .{ .continue_ = encoded };
            },
            .client_final => {
                var raw_out: [scram512.MAX_MESSAGE]u8 = undefined;
                const final = server.receiveClientFinal(raw, &raw_out) catch return self.failReset(.invalid_credentials);
                const account = self.copyAccount(server.username()) orelse return self.failReset(.invalid_message);
                const encoded = encodeBase64(final.server_final, out) catch return self.failReset(.output_too_small);
                self.state = .idle;
                const fingerprint = self.pending_scram_fingerprint;
                self.pending_scram_fingerprint = null;
                return .{ .success = .{ .account = account, .final_data = encoded, .scram_credential = fingerprint } };
            },
            .complete => return self.failReset(.invalid_state),
        }
    }

    fn copyAccount(self: *Router, account: []const u8) ?[]const u8 {
        if (account.len == 0 or account.len > self.account_buf.len) return null;
        @memcpy(self.account_buf[0..account.len], account);
        self.account_len = account.len;
        return self.account_buf[0..self.account_len];
    }

    fn failReset(self: *Router, failure: Failure) Outcome {
        self.resetExchange();
        return .{ .fail = failure };
    }

    fn resetExchange(self: *Router) void {
        self.state = .idle;
        self.pending_len = 0;
        self.account_len = 0;
        self.pending_scram_fingerprint = null;
    }
};

fn decodeBase64(src: []const u8, out: []u8) ![]const u8 {
    if (std.mem.eql(u8, src, "+")) return out[0..0];
    if (std.base64.standard.Decoder.calcSizeForSlice(src)) |size| {
        if (size > out.len) return error.NoSpaceLeft;
        try std.base64.standard.Decoder.decode(out[0..size], src);
        return out[0..size];
    } else |_| {}
    const size = try std.base64.standard_no_pad.Decoder.calcSizeForSlice(src);
    if (size > out.len) return error.NoSpaceLeft;
    try std.base64.standard_no_pad.Decoder.decode(out[0..size], src);
    return out[0..size];
}

fn decodedBase64Len(src: []const u8) !usize {
    if (std.mem.eql(u8, src, "+")) return 0;
    if (std.base64.standard.Decoder.calcSizeForSlice(src)) |size| {
        return size;
    } else |_| {}
    return std.base64.standard_no_pad.Decoder.calcSizeForSlice(src);
}

fn encodeBase64(src: []const u8, out: []u8) ![]const u8 {
    const size = std.base64.standard.Encoder.calcSize(src.len);
    if (size > out.len) return error.NoSpaceLeft;
    return std.base64.standard.Encoder.encode(out[0..size], src);
}

fn secureZero(buf: []u8) void {
    for (buf) |*byte| {
        const vp: *volatile u8 = @ptrCast(byte);
        vp.* = 0;
    }
}

fn hmacSha256(key: []const u8, msg: []const u8) [scram256.digest_len]u8 {
    var out: [scram256.digest_len]u8 = undefined;
    std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).create(&out, msg, key);
    return out;
}

fn b64(comptime text: []const u8) [std.base64.standard.Encoder.calcSize(text.len)]u8 {
    var out: [std.base64.standard.Encoder.calcSize(text.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, text);
    return out;
}

test "PLAIN accepts and rejects through router" {
    const Db = struct {
        accept: bool,

        fn verify(ptr: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.accept) return null;
            if (!std.mem.eql(u8, creds.authcid, "kain")) return null;
            if (!std.mem.eql(u8, creds.password, "correct")) return null;
            return "kain";
        }
    };

    var db = Db{ .accept = true };
    var router = Router.init(.{ .plain = .{ .ptr = &db, .verifyFn = Db.verify } }, "serverNonce");
    try std.testing.expectEqualStrings("+", router.start("PLAIN").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const good = b64("authz\x00kain\x00correct");
    const accepted = router.receive(&good, &out);
    try std.testing.expectEqualStrings("kain", accepted.success.account);

    db.accept = false;
    try std.testing.expectEqualStrings("+", router.start("plain").continue_);
    const rejected = router.receive(&good, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "router enforces configured decoded message limit" {
    const Db = struct {
        fn verify(_: *anyopaque, _: sasl.PlainCredentials) ?[]const u8 {
            return "kain";
        }
    };

    var token: u8 = 0;
    var router = Router.initWithLimit(.{ .plain = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce", 8);
    try std.testing.expectEqualStrings("+", router.start("PLAIN").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const too_large = b64("authz\x00kain\x00correct");
    const rejected = router.receive(&too_large, &out);
    try std.testing.expectEqual(Failure.too_long, rejected.fail);

    router = Router.initWithLimit(.{ .plain = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce", 64);
    try std.testing.expectEqualStrings("+", router.start("PLAIN").continue_);
    const accepted = router.receive(&too_large, &out);
    try std.testing.expectEqualStrings("kain", accepted.success.account);
}

test "SCRAM-SHA-256 round trip accepts and rejects tampered proof through router" {
    const allocator = std.testing.allocator;
    const salt = try allocator.dupe(u8, "known-scram-sha-256-salt");
    defer allocator.free(salt);

    var keys = try sasl.deriveScramKeys("pencil", salt, 4096);
    defer keys.wipe();

    const Db = struct {
        credential: scram256.Credential,

        fn lookup(ptr: *anyopaque, username: []const u8) ?scram256.Credential {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, username, "user")) return null;
            return self.credential;
        }
    };
    var db = Db{
        .credential = .{
            .salt = salt,
            .iterations = 4096,
            .stored_key = keys.stored_key,
            .server_key = keys.server_key,
        },
    };
    var router = Router.init(.{ .scram256 = .{ .ptr = &db, .lookupFn = Db.lookup } }, "serverNonce256");
    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-256").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const client_first = b64("n,,n=user,r=clientNonce256");
    const first_out = router.receive(&client_first, &out);
    const server_first_b64 = first_out.continue_;
    var server_first_raw_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_first = try decodeBase64(server_first_b64, &server_first_raw_buf);
    const parsed_first = try scram256.parseServerFirst(server_first);
    try std.testing.expectEqualStrings("clientNonce256serverNonce256", parsed_first.nonce);

    const client_final_without_proof = try std.fmt.allocPrint(
        allocator,
        "c=biws,r={s}",
        .{parsed_first.nonce},
    );
    defer allocator.free(client_final_without_proof);
    const auth_message = try std.fmt.allocPrint(
        allocator,
        "n=user,r=clientNonce256,{s},{s}",
        .{ server_first, client_final_without_proof },
    );
    defer allocator.free(auth_message);

    var client_sig = hmacSha256(&keys.stored_key, auth_message);
    defer secureZero(&client_sig);
    var client_proof: [scram256.digest_len]u8 = undefined;
    defer secureZero(&client_proof);
    for (&client_proof, keys.client_key, client_sig) |*dst, key_byte, sig_byte| {
        dst.* = key_byte ^ sig_byte;
    }

    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(scram256.digest_len)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &client_proof);
    const client_final = try std.fmt.allocPrint(
        allocator,
        "{s},p={s}",
        .{ client_final_without_proof, proof_b64 },
    );
    defer allocator.free(client_final);

    const client_final_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(client_final.len));
    defer allocator.free(client_final_b64);
    _ = std.base64.standard.Encoder.encode(client_final_b64, client_final);
    const accepted = router.receive(client_final_b64, &out);
    try std.testing.expectEqualStrings("user", accepted.success.account);
    const final_data = accepted.success.final_data orelse return error.MissingFinalData;
    var server_final_raw_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_final = try decodeBase64(final_data, &server_final_raw_buf);
    _ = try scram256.parseServerFinal(server_final);

    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-256").continue_);
    _ = router.receive(&client_first, &out);
    client_proof[0] ^= 1;
    const bad_proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &client_proof);
    const bad_final = try std.fmt.allocPrint(
        allocator,
        "{s},p={s}",
        .{ client_final_without_proof, bad_proof_b64 },
    );
    defer allocator.free(bad_final);
    const bad_final_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bad_final.len));
    defer allocator.free(bad_final_b64);
    _ = std.base64.standard.Encoder.encode(bad_final_b64, bad_final);
    const rejected = router.receive(bad_final_b64, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "EXTERNAL accepts through router" {
    const Db = struct {
        fn verify(_: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8 {
            if (!std.mem.eql(u8, certfp, "ABCD")) return null;
            if (!std.mem.eql(u8, authzid, "kain")) return null;
            return "kain";
        }
    };
    var token: u8 = 0;
    var router = Router.init(.{ .external = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce");
    router.tls_certfp = "ABCD";
    try std.testing.expectEqualStrings("+", router.start("EXTERNAL").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const authzid = b64("kain");
    const accepted = router.receive(&authzid, &out);
    try std.testing.expectEqualStrings("kain", accepted.success.account);
}

test "SESSION-TOKEN accepts and rejects through router callback" {
    const Db = struct {
        fn verify(_: *anyopaque, creds: SessionTokenCredentials, account_out: []u8) ?[]const u8 {
            if (!std.mem.eql(u8, creds.authcid, "alice")) return null;
            if (!std.mem.eql(u8, creds.token, "sst_0123456789abcdef0123456789abcdef")) return null;
            @memcpy(account_out[0.."alice".len], "alice");
            return account_out[0.."alice".len];
        }
    };
    var token: u8 = 0;
    var router = Router.init(.{ .session_token = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce");
    try std.testing.expectEqualStrings("+", router.start("SESSION-TOKEN").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const good = b64("alice\x00sst_0123456789abcdef0123456789abcdef");
    const accepted = router.receive(&good, &out);
    try std.testing.expectEqualStrings("alice", accepted.success.account);
    try std.testing.expect(!accepted.success.issue_session_token);

    try std.testing.expectEqualStrings("+", router.start("SESSION-TOKEN").continue_);
    const bad = b64("alice\x00sst_ffffffffffffffffffffffffffffffff");
    const rejected = router.receive(&bad, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "OAUTHBEARER accepts and rejects through router callback" {
    const Db = struct {
        fn verify(_: *anyopaque, token: []const u8, authzid: ?[]const u8, account_out: []u8) ?[]const u8 {
            if (!std.mem.eql(u8, token, "good.jwt")) return null;
            if (authzid) |zid| {
                if (!std.mem.eql(u8, zid, "alice")) return null;
            }
            @memcpy(account_out[0.."alice".len], "alice");
            return account_out[0.."alice".len];
        }
    };
    var token: u8 = 0;
    var router = Router.init(.{ .oauthbearer = .{ .ptr = &token, .verifyFn = Db.verify } }, "serverNonce");
    try std.testing.expectEqualStrings("+", router.start("OAUTHBEARER").continue_);

    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const good = b64("n,a=alice,\x01auth=Bearer good.jwt\x01\x01");
    const accepted = router.receive(&good, &out);
    try std.testing.expectEqualStrings("alice", accepted.success.account);

    try std.testing.expectEqualStrings("+", router.start("OAUTHBEARER").continue_);
    const bad = b64("n,,\x01auth=Bearer bad.jwt\x01\x01");
    const rejected = router.receive(&bad, &out);
    try std.testing.expectEqual(Failure.invalid_credentials, rejected.fail);
}

test "ANONYMOUS is default gated and succeeds as guest when enabled" {
    var router = Router.init(.{}, "serverNonce");
    try std.testing.expectEqual(Failure.unavailable, router.start("ANONYMOUS").fail);

    router = Router.init(.{ .anonymous = true }, "serverNonce");
    try std.testing.expectEqualStrings("+", router.start("ANONYMOUS").continue_);
    var out: [MAX_B64_MESSAGE]u8 = undefined;
    const accepted = router.receive("+", &out);
    try std.testing.expectEqualStrings("guest", accepted.success.account);
    try std.testing.expect(accepted.success.guest);
    try std.testing.expect(!accepted.success.issue_session_token);
}

test "SCRAM PLUS mechanisms require tls exporter through router" {
    const Db = struct {
        fn lookup256(_: *anyopaque, _: []const u8) ?scram256.Credential {
            return null;
        }

        fn lookup512(_: *anyopaque, _: []const u8) ?scram512.Credential {
            return null;
        }
    };

    var token: u8 = 0;
    var router = Router.init(.{
        .scram256 = .{ .ptr = &token, .lookupFn = Db.lookup256 },
        .scram512 = .{ .ptr = &token, .lookupFn = Db.lookup512 },
    }, "serverNonce");
    try std.testing.expectEqual(Failure.unavailable, router.start("SCRAM-SHA-256-PLUS").fail);
    try std.testing.expectEqual(Failure.unavailable, router.start("SCRAM-SHA-512-PLUS").fail);

    router.tls_exporter = @as([scram512.tls_exporter_len]u8, @splat(0x42));
    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-256-PLUS").continue_);
    try std.testing.expectEqualStrings("+", router.start("SCRAM-SHA-512-PLUS").continue_);
}

test "unknown mechanism rejects" {
    var router = Router.init(.{}, "serverNonce");
    const rejected = router.start("NOT-A-MECH");
    try std.testing.expectEqual(Failure.unknown_mechanism, rejected.fail);
}

test "mechanism list string advertises supported mechanisms" {
    try std.testing.expectEqualStrings(
        "PLAIN EXTERNAL SCRAM-SHA-256 SCRAM-SHA-256-PLUS SCRAM-SHA-512 SCRAM-SHA-512-PLUS SESSION-TOKEN OAUTHBEARER ANONYMOUS",
        Router.mechanismList(),
    );
    try std.testing.expectEqualStrings(SUPPORTED_MECHANISMS, Router.mechanismList());
}

// ---------------------------------------------------------------------------
// Exploit corpus (P3 / CWE-287,294,306,384): the SASL router is the auth state
// machine a hostile client drives via AUTHENTICATE. Every case asserts it FAILS
// CLOSED — no account is ever granted on malformed / out-of-order / oversized /
// replayed input, the exchange resets on failure, and no path panics. Runs in
// the full `zig build test` AND under `zig build test-exploit`.

/// A PLAIN checker that accepts ONLY kain/correct — any other credential (empty,
/// garbage, wrong password) returns null so the router must fail closed.
const ExploitPlainDb = struct {
    fn verify(_: *anyopaque, creds: sasl.PlainCredentials) ?[]const u8 {
        if (!std.mem.eql(u8, creds.authcid, "kain")) return null;
        if (!std.mem.eql(u8, creds.password, "correct")) return null;
        return "kain";
    }
};

fn exploitPlainRouter(token: *u8) Router {
    return Router.init(.{ .plain = .{ .ptr = token, .verifyFn = ExploitPlainDb.verify } }, "serverNonce");
}

test "exploit: SASL router grants nothing on out-of-order / malformed / oversized input" {
    var token: u8 = 0;
    var out: [MAX_B64_MESSAGE]u8 = undefined;

    // AUTHENTICATE payload BEFORE any mechanism start: idle state must refuse,
    // never fall through into a mechanism step.
    {
        var router = exploitPlainRouter(&token);
        const r = router.receive(&b64("authz\x00kain\x00correct"), &out);
        try std.testing.expectEqual(Failure.invalid_state, r.fail);
    }

    // Oversized chunk (> MAX_AUTHENTICATE_CHUNK): refused as too_long, no decode.
    {
        var router = exploitPlainRouter(&token);
        _ = router.start("PLAIN");
        var big: [MAX_AUTHENTICATE_CHUNK + 1]u8 = undefined;
        @memset(&big, 'A');
        const r = router.receive(&big, &out);
        try std.testing.expectEqual(Failure.too_long, r.fail);
    }

    // Non-base64 garbage: invalid_message (decode fails fail-closed).
    {
        var router = exploitPlainRouter(&token);
        _ = router.start("PLAIN");
        const r = router.receive("!!!!not base64!!!!", &out);
        try std.testing.expectEqual(Failure.invalid_message, r.fail);
    }

    // Empty and structurally-wrong PLAIN blobs: never a grant.
    {
        const bad = [_][]const u8{
            "", // empty message
            "garbage-no-nul", // no NUL separators
            "authz\x00kainonly", // missing password field
            "authz\x00wrong\x00correct", // wrong authcid
            "authz\x00kain\x00wrong", // wrong password
        };
        for (bad) |raw| {
            var router = exploitPlainRouter(&token);
            _ = router.start("PLAIN");
            const enc = std.base64.standard.Encoder;
            var eb: [512]u8 = undefined;
            const encoded = enc.encode(eb[0..enc.calcSize(raw.len)], raw);
            const r = router.receive(encoded, &out);
            // Either invalid_message (parse) or invalid_credentials (verify) — but
            // NEVER a success. Assert the outcome is a fail, not a grant.
            try std.testing.expect(r == .fail);
        }
    }
}

test "exploit: SASL abort resets the exchange (no lingering authenticated state)" {
    var token: u8 = 0;
    var out: [MAX_B64_MESSAGE]u8 = undefined;
    var router = exploitPlainRouter(&token);

    try std.testing.expectEqualStrings("+", router.start("PLAIN").continue_);
    // Client aborts mid-exchange.
    try std.testing.expectEqual(Failure.aborted, router.receive("*", &out).fail);
    // A follow-up payload after abort hits idle: refused, never resumed.
    try std.testing.expectEqual(Failure.invalid_state, router.receive(&b64("authz\x00kain\x00correct"), &out).fail);
}

test "exploit: SASL success cannot be replayed for a second grant" {
    var token: u8 = 0;
    var out: [MAX_B64_MESSAGE]u8 = undefined;
    var router = exploitPlainRouter(&token);

    _ = router.start("PLAIN");
    const good = b64("authz\x00kain\x00correct");
    try std.testing.expectEqualStrings("kain", router.receive(&good, &out).success.account);
    // Replaying the exact accepted chunk WITHOUT a fresh start must not re-grant:
    // the router returned to idle, so the replay is refused fail-closed.
    try std.testing.expectEqual(Failure.invalid_state, router.receive(&good, &out).fail);
}

test "exploit: SASL EXTERNAL is unavailable without a bound certfp (no spoof)" {
    // EXTERNAL binds to the TLS-presented certfp only. With no certfp bound (a
    // plaintext or unverified conn), the mechanism must not even start — a client
    // cannot assert an identity by naming an authzid.
    var ext_token: u8 = 0;
    var router = Router.init(.{ .external = .{
        .ptr = &ext_token,
        .verifyFn = struct {
            fn verify(_: *anyopaque, _: []const u8, _: []const u8) ?[]const u8 {
                return "should-never-be-called";
            }
        }.verify,
    } }, "serverNonce");
    // tls_certfp is null → enabled(external) is false → start fails unavailable.
    try std.testing.expectEqual(Failure.unavailable, router.start("EXTERNAL").fail);
}

test {
    std.testing.refAllDecls(@This());
}
