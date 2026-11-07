// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ACME (RFC 8555) certificate-issuance orchestration state machine.
//!
//! Conductor for a Let's Encrypt issuance flow answering http-01 (RFC 8555
//! §8.3), dns-01 (RFC 8555 §8.4) or tls-alpn-01 (RFC 8737) challenges. Owns no
//! sockets, clock, or RNG: every interaction is injected. The caller calls
//! `step` repeatedly; each call advances the machine by one round-trip (or one
//! local decision) and returns a `Progress` plus zero-or-more `Effect`s the
//! caller must act on (provision a challenge response, write the issued
//! certificate).
//!
//! Flow (RFC 8555 §7): directory -> newNonce -> newAccount -> newOrder(domains)
//! -> per authorization: GET authz, pick the configured challenge type, emit
//! the provisioning effect, [caller provisions], POST challenge (RFC 8555
//! §7.5.1: only once the response is in place), poll until valid -> finalize
//! with CSR -> poll order -> download.
//!
//! Injection: `Transport` (ctx + `get`/`postJws` fn pointers returning
//! `HttpResponse`); `Signer` (ctx + `sign(signing_input) -> signature`). The
//! machine builds the JWS header/signing-input and frames the flattened JWS; it
//! never touches a private key. The Replay-Nonce on each response is threaded
//! into the next signed request, with `badNonce` recovery.
//!
//! Pure, 64-bit, allocator-clean (no leaks under std.testing.allocator).

const std = @import("std");
const Allocator = std.mem.Allocator;

const directory = @import("../proto/acme_directory.zig");
const order_mod = @import("../proto/acme_order.zig");
const account_mod = @import("../proto/acme_account.zig");
const jws = @import("../proto/acme_jws.zig");
const jwk = @import("../proto/acme_jwk.zig");
const challenge = @import("../proto/acme_challenge.zig");
const csr = @import("../proto/csr.zig");
const problem = @import("../proto/acme_problem.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("acme_client requires a 64-bit target");
}

/// Upper bound on how many times a single signed request is retried after a
/// `badNonce` rejection before the machine gives up. RFC 8555 only ever expects
/// one retry, but we allow a small margin.
const max_nonce_retries: u8 = 3;

/// Challenge types this client can answer (RFC 8555 §8.3/§8.4, RFC 8737 §3).
pub const ChallengeType = enum {
    http_01,
    dns_01,
    tls_alpn_01,

    /// The `type` string the CA uses in a challenge object.
    pub fn wireName(self: ChallengeType) []const u8 {
        return switch (self) {
            .http_01 => "http-01",
            .dns_01 => "dns-01",
            .tls_alpn_01 => "tls-alpn-01",
        };
    }

    /// Parse the operator / wire spelling (`http-01`, `dns-01`, `tls-alpn-01`).
    pub fn fromString(text: []const u8) ?ChallengeType {
        for ([_]ChallengeType{ .http_01, .dns_01, .tls_alpn_01 }) |t| {
            if (std.mem.eql(u8, text, t.wireName())) return t;
        }
        return null;
    }
};

/// JOSE `alg` for the account key. ES256 (ECDSA P-256 + SHA-256) is the
/// algorithm Let's Encrypt accepts; it rejects EdDSA on accounts.
const jose_alg = "ES256";

// ---------------------------------------------------------------------------
// Injected I/O surfaces
// ---------------------------------------------------------------------------

/// A single HTTP response from the transport. Slices are borrowed for the
/// duration of one `step`; the machine copies anything it must retain. `nonce`
/// is the `Replay-Nonce` header, `location` the `Location` header (account kid /
/// order URL), each null when absent.
pub const HttpResponse = struct {
    status: u16,
    body: []const u8,
    nonce: ?[]const u8 = null,
    location: ?[]const u8 = null,
};

/// Injected HTTP transport. `get` does a plain GET; `postJws` POSTs a flattened
/// JWS body. Implementations populate `nonce`/`location` from headers.
pub const Transport = struct {
    ctx: *anyopaque,
    getFn: *const fn (ctx: *anyopaque, url: []const u8) anyerror!HttpResponse,
    postJwsFn: *const fn (ctx: *anyopaque, url: []const u8, jws_body: []const u8) anyerror!HttpResponse,

    fn get(self: Transport, url: []const u8) anyerror!HttpResponse {
        return self.getFn(self.ctx, url);
    }

    fn postJws(self: Transport, url: []const u8, body: []const u8) anyerror!HttpResponse {
        return self.postJwsFn(self.ctx, url, body);
    }
};

/// Injected signer for ES256 (ECDSA P-256 + SHA-256), the JWS algorithm Let's
/// Encrypt accepts for accounts. `sign` receives the JWS signing input and writes
/// the raw fixed-width signature (r‖s, 64 bytes) into `out`. The same key is
/// reused for the certificate CSR (acme_client converts r‖s to DER there).
pub const Signer = struct {
    ctx: *anyopaque,
    /// Affine P-256 public-key coordinates (the `x`/`y` JWK members).
    public_key_x: [32]u8,
    public_key_y: [32]u8,
    signFn: *const fn (ctx: *anyopaque, signing_input: []const u8, out: []u8) anyerror![]const u8,

    fn sign(self: Signer, signing_input: []const u8, out: []u8) anyerror![]const u8 {
        return self.signFn(self.ctx, signing_input, out);
    }
};

// ---------------------------------------------------------------------------
// Configuration & effects
// ---------------------------------------------------------------------------

/// Static inputs for an issuance run. All slices are borrowed and must outlive
/// the `Acme` instance.
pub const Config = struct {
    /// Absolute URL of the ACME directory resource.
    directory_url: []const u8,
    /// Domains to include in the order (first is the CSR common name).
    domains: []const []const u8,
    /// Contact URIs (e.g. "mailto:admin@example.com").
    contacts: []const []const u8 = &.{},
    /// Whether to set `termsOfServiceAgreed`.
    tos_agreed: bool = true,
    /// Account key — signs the JWS of every ACME request.
    signer: Signer,
    /// Certificate key — signs the CSR and becomes the issued cert's key. MUST be
    /// a distinct key from `signer`; Let's Encrypt rejects a CSR whose public key
    /// equals the account key. The first `step` fails with
    /// `error.AccountKeyReuse` if they are equal.
    cert_signer: Signer,
    /// Which challenge type to answer for every authorization.
    challenge: ChallengeType = .http_01,
};

/// Effects the caller MUST act on when returned from `step`.
pub const Effect = union(enum) {
    /// Provision the http-01 challenge: serve `key_authorization` (as the body)
    /// at `/.well-known/acme-challenge/<token>` until issuance completes.
    serve_http01: struct { token: []const u8, key_authorization: []const u8 },
    /// Provision the dns-01 challenge (RFC 8555 §8.4): publish a TXT record
    /// at `fqdn` (`_acme-challenge.<domain>`) whose value is `txt_value`
    /// (base64url(SHA-256(keyAuth))), and wait for it to propagate, before the
    /// next `step` (which tells the CA to validate).
    provision_dns01: struct { fqdn: []const u8, txt_value: []const u8 },
    /// Provision the tls-alpn-01 challenge (RFC 8737 §3): answer TLS
    /// handshakes for `domain` that offer only ALPN `acme-tls/1` with a
    /// certificate carrying the critical acmeIdentifier extension over
    /// SHA-256(`key_authorization`), before the next `step`.
    provision_tls_alpn01: struct { domain: []const u8, key_authorization: []const u8 },
    /// The issued certificate chain (PEM). Persist it.
    write_cert: struct { pem: []const u8 },
};

/// Result of one `step` call. `effects` borrows storage owned by the `Acme`
/// instance; it is valid until the next `step` call.
pub const Progress = struct {
    state: State,
    done: bool,
    effects: []const Effect,
};

/// Issuance lifecycle. Exhaustively switched everywhere.
pub const State = enum {
    start, // fetch directory
    account, // ensure nonce, create account
    order, // create order
    authorizing, // fetch the next authorization, emit the provisioning effect
    responding, // caller provisioned; POST the challenge (RFC 8555 §7.5.1)
    polling_authz, // challenge POSTed; poll authz until valid
    finalizing, // finalize order with CSR
    polling_order, // poll order until it carries a certificate URL
    downloading, // download the certificate
    done, // terminal success
    failed, // terminal failure
};

pub const Error = error{
    Terminal, // stepped after a terminal state
    MissingNonce, // signed request needs a nonce we do not have
    UnexpectedStatus, // unexpected HTTP status / problem document
    MissingAccountUrl, // newAccount lacked a Location header
    MissingOrderUrl, // newOrder lacked a Location header
    NoChallenge, // authz offered no challenge of the configured type
    UnexpectedIdentifier, // authz identifier is not one we ordered
    InvalidToken, // challenge token is not RFC 8555 §8.1 base64url
    AccountKeyReuse, // account key == certificate key
    OrderFailed, // order reached a terminal non-valid state
    AuthzFailed, // authz reached a terminal non-valid state
    TooManyNonceRetries, // badNonce retried past the limit
} || Allocator.Error;

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

pub const Acme = struct {
    allocator: Allocator,
    config: Config,
    state: State = .start,

    /// Owned copies threaded between steps.
    dir: ?directory.Directory = null,
    nonce: ?[]u8 = null,
    account_url: ?[]u8 = null,
    order_url: ?[]u8 = null,
    finalize_url: ?[]u8 = null,
    cert_url: ?[]u8 = null,

    /// Authorization URLs remaining to process (owned).
    authz_urls: [][]u8 = &.{},
    authz_index: usize = 0,
    /// URL of the authz being answered (owned), used to poll it.
    current_authz_url: ?[]u8 = null,
    /// URL of the challenge to POST once the caller has provisioned (owned).
    current_challenge_url: ?[]u8 = null,

    /// Effect scratch storage, valid until the next step.
    effect_buf: [2]Effect = undefined,
    /// Backing storage for effect string fields.
    token_buf: [256]u8 = undefined,
    keyauth_buf: [512]u8 = undefined,
    name_buf: [challenge.dns01_label.len + challenge.max_dns_name_len]u8 = undefined,
    txt_buf: [64]u8 = undefined,
    pem_buf: ?[]u8 = null,

    /// badNonce retry counter for the in-flight signed request.
    nonce_retries: u8 = 0,

    pub fn init(allocator: Allocator, config: Config) Acme {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Acme) void {
        if (self.dir) |*d| d.deinit(self.allocator);
        if (self.nonce) |n| self.allocator.free(n);
        if (self.account_url) |u| self.allocator.free(u);
        if (self.order_url) |u| self.allocator.free(u);
        if (self.finalize_url) |u| self.allocator.free(u);
        if (self.cert_url) |u| self.allocator.free(u);
        if (self.current_authz_url) |u| self.allocator.free(u);
        if (self.current_challenge_url) |u| self.allocator.free(u);
        for (self.authz_urls) |u| self.allocator.free(u);
        self.allocator.free(self.authz_urls);
        if (self.pem_buf) |p| self.allocator.free(p);
        self.* = undefined;
    }

    /// Advance the machine by one round-trip. Returns the new `Progress`.
    pub fn step(self: *Acme, transport: Transport) Error!Progress {
        return switch (self.state) {
            .start => self.stepStart(transport),
            .account => self.stepAccount(transport),
            .order => self.stepOrder(transport),
            .authorizing => self.stepAuthorizing(transport),
            .responding => self.stepResponding(transport),
            .polling_authz => self.stepPollAuthz(transport),
            .finalizing => self.stepFinalize(transport),
            .polling_order => self.stepPollOrder(transport),
            .downloading => self.stepDownload(transport),
            .done, .failed => error.Terminal,
        };
    }

    // --- helpers -----------------------------------------------------------

    fn noEffects(self: *Acme) Progress {
        return .{ .state = self.state, .done = self.state == .done, .effects = self.effect_buf[0..0] };
    }

    fn fail(self: *Acme, err: Error) Error {
        self.state = .failed;
        return err;
    }

    /// Replace the stored nonce with a copy of `new`, freeing the old one.
    fn setNonce(self: *Acme, new: ?[]const u8) Allocator.Error!void {
        const incoming = new orelse return;
        const copy = try self.allocator.dupe(u8, incoming);
        if (self.nonce) |old| self.allocator.free(old);
        self.nonce = copy;
    }

    fn takeNonce(self: *Acme) Error![]const u8 {
        return self.nonce orelse self.fail(error.MissingNonce);
    }

    /// Build and POST a signed JWS, retrying on `badNonce`. `jwk_header` picks
    /// the JWK protected header (newAccount) vs. the KID header.
    fn postSigned(
        self: *Acme,
        transport: Transport,
        url: []const u8,
        payload: []const u8,
        jwk_header: bool,
    ) Error!HttpResponse {
        while (true) {
            const nonce = try self.takeNonce();

            var hdr_buf: [1024]u8 = undefined;
            const protected = if (jwk_header) blk: {
                var jwk_buf: [jwk.ec_json_max_len]u8 = undefined;
                const jwk_json = jwk.jwkEc(self.config.signer.public_key_x, self.config.signer.public_key_y, &jwk_buf) catch
                    return self.fail(error.OutOfMemory);
                break :blk jws.protectedHeaderJwk(jose_alg, nonce, url, jwk_json, &hdr_buf) catch
                    return self.fail(error.OutOfMemory);
            } else blk: {
                const kid = self.account_url orelse return self.fail(error.MissingAccountUrl);
                break :blk jws.protectedHeaderKid(jose_alg, nonce, url, kid, &hdr_buf) catch
                    return self.fail(error.OutOfMemory);
            };

            var si_buf: [2048]u8 = undefined;
            const signing_input = jws.signingInput(protected, payload, &si_buf) catch
                return self.fail(error.OutOfMemory);

            var sig_buf: [64]u8 = undefined;
            const signature = self.config.signer.sign(signing_input, &sig_buf) catch
                return self.fail(error.OutOfMemory);

            var body_buf: [4096]u8 = undefined;
            const body = jws.flattened(protected, payload, signature, &body_buf) catch
                return self.fail(error.OutOfMemory);

            const resp = transport.postJws(url, body) catch return self.fail(error.UnexpectedStatus);
            try self.setNonce(resp.nonce);

            if (isProblemStatus(resp.status)) {
                const prob = problem.parse(self.allocator, resp.body) catch
                    return self.fail(error.UnexpectedStatus);
                if (prob.kind == .bad_nonce and self.nonce_retries < max_nonce_retries) {
                    self.nonce_retries += 1;
                    continue;
                }
                return self.fail(error.UnexpectedStatus);
            }

            self.nonce_retries = 0;
            return resp;
        }
    }

    // --- per-state handlers ------------------------------------------------

    fn stepStart(self: *Acme, transport: Transport) Error!Progress {
        // Account key and certificate key MUST differ (RFC 8555 §11.1: the
        // account key is not to be reused for other purposes; Let's Encrypt
        // rejects such a CSR with badCSR).
        if (std.mem.eql(u8, &self.config.signer.public_key_x, &self.config.cert_signer.public_key_x) and
            std.mem.eql(u8, &self.config.signer.public_key_y, &self.config.cert_signer.public_key_y))
        {
            return self.fail(error.AccountKeyReuse);
        }
        const resp = transport.get(self.config.directory_url) catch return self.fail(error.UnexpectedStatus);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);
        try self.setNonce(resp.nonce);

        const dir = directory.parse(self.allocator, resp.body) catch
            return self.fail(error.UnexpectedStatus);
        self.dir = dir;

        if (self.nonce == null) {
            const nresp = transport.get(dir.new_nonce) catch return self.fail(error.UnexpectedStatus);
            try self.setNonce(nresp.nonce);
        }

        self.state = .account;
        return self.noEffects();
    }

    fn stepAccount(self: *Acme, transport: Transport) Error!Progress {
        const dir = self.dir.?;

        var payload_buf: [1024]u8 = undefined;
        const payload = account_mod.buildNewAccount(&payload_buf, self.config.contacts, self.config.tos_agreed) catch
            return self.fail(error.OutOfMemory);

        const resp = try self.postSigned(transport, dir.new_account, payload, true);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        const loc = resp.location orelse return self.fail(error.MissingAccountUrl);
        self.account_url = try self.allocator.dupe(u8, loc);

        self.state = .order;
        return self.noEffects();
    }

    fn stepOrder(self: *Acme, transport: Transport) Error!Progress {
        const dir = self.dir.?;

        var payload_buf: [2048]u8 = undefined;
        const payload = order_mod.buildNewOrder(&payload_buf, self.config.domains) catch
            return self.fail(error.OutOfMemory);

        const resp = try self.postSigned(transport, dir.new_order, payload, false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        const loc = resp.location orelse return self.fail(error.MissingOrderUrl);
        self.order_url = try self.allocator.dupe(u8, loc);

        var parsed = order_mod.parseOrder(self.allocator, resp.body) catch
            return self.fail(error.UnexpectedStatus);
        defer parsed.deinit();

        self.finalize_url = try self.allocator.dupe(u8, parsed.finalize);

        var urls = try self.allocator.alloc([]u8, parsed.authorizations.len);
        errdefer self.allocator.free(urls);
        var filled: usize = 0;
        errdefer for (urls[0..filled]) |u| self.allocator.free(u);
        for (parsed.authorizations, 0..) |a, i| {
            urls[i] = try self.allocator.dupe(u8, a);
            filled += 1;
        }
        self.authz_urls = urls;
        self.authz_index = 0;

        self.state = .authorizing;
        return self.noEffects();
    }

    fn stepAuthorizing(self: *Acme, transport: Transport) Error!Progress {
        if (self.authz_index >= self.authz_urls.len) {
            self.state = .finalizing;
            return self.noEffects();
        }

        const authz_url = self.authz_urls[self.authz_index];
        const resp = try self.postSigned(transport, authz_url, "", false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        var authz = order_mod.parseAuthorization(self.allocator, resp.body) catch
            return self.fail(error.UnexpectedStatus);
        defer authz.deinit();

        if (authz.status == .valid) {
            self.authz_index += 1;
            return self.noEffects();
        }
        if (authz.status == .invalid or authz.status == .deactivated or
            authz.status == .expired or authz.status == .revoked)
        {
            return self.fail(error.AuthzFailed);
        }

        // Only answer for an identifier we actually ordered (RFC 8555 §7.1.4:
        // a wildcard order's authz carries the base domain).
        if (!std.mem.eql(u8, authz.identifier.type, "dns") or
            !self.orderedIdentifier(authz.identifier.value))
        {
            return self.fail(error.UnexpectedIdentifier);
        }

        const chal = order_mod.findChallenge(authz, self.config.challenge.wireName()) orelse
            return self.fail(error.NoChallenge);
        if (!challenge.validateToken(chal.token)) return self.fail(error.InvalidToken);

        var thumb_buf: [jwk.thumbprint_b64_len]u8 = undefined;
        var thumb_digest: [32]u8 = undefined;
        jwk.thumbprintEc(self.config.signer.public_key_x, self.config.signer.public_key_y, &thumb_digest);
        const thumb = std.base64.url_safe_no_pad.Encoder.encode(&thumb_buf, &thumb_digest);

        const key_auth = challenge.keyAuthorization(chal.token, thumb, &self.keyauth_buf) catch
            return self.fail(error.OutOfMemory);

        switch (self.config.challenge) {
            .http_01 => {
                if (chal.token.len > self.token_buf.len) return self.fail(error.OutOfMemory);
                @memcpy(self.token_buf[0..chal.token.len], chal.token);
                const token = self.token_buf[0..chal.token.len];
                self.effect_buf[0] = .{ .serve_http01 = .{ .token = token, .key_authorization = key_auth } };
            },
            .dns_01 => {
                const fqdn = challenge.dns01RecordName(authz.identifier.value, &self.name_buf) catch
                    return self.fail(error.UnexpectedIdentifier);
                const txt = challenge.dns01TxtValue(key_auth, &self.txt_buf) catch
                    return self.fail(error.OutOfMemory);
                self.effect_buf[0] = .{ .provision_dns01 = .{ .fqdn = fqdn, .txt_value = txt } };
            },
            .tls_alpn_01 => {
                const v = authz.identifier.value;
                if (v.len > self.name_buf.len) return self.fail(error.UnexpectedIdentifier);
                @memcpy(self.name_buf[0..v.len], v);
                self.effect_buf[0] = .{ .provision_tls_alpn01 = .{ .domain = self.name_buf[0..v.len], .key_authorization = key_auth } };
            },
        }

        const authz_copy = try self.allocator.dupe(u8, authz_url);
        errdefer self.allocator.free(authz_copy);
        const chal_copy = try self.allocator.dupe(u8, chal.url);
        if (self.current_authz_url) |old| self.allocator.free(old);
        self.current_authz_url = authz_copy;
        if (self.current_challenge_url) |old| self.allocator.free(old);
        self.current_challenge_url = chal_copy;

        // The CA is told to validate only on the NEXT step, after the caller
        // has acted on the provisioning effect (RFC 8555 §7.5.1: the client
        // responds to the challenge once it has provisioned the response).
        self.state = .responding;
        return .{ .state = self.state, .done = false, .effects = self.effect_buf[0..1] };
    }

    fn stepResponding(self: *Acme, transport: Transport) Error!Progress {
        const chal_url = self.current_challenge_url orelse return self.fail(error.AuthzFailed);
        const trig = try self.postSigned(transport, chal_url, "{}", false);
        if (!isOk(trig.status)) return self.fail(error.UnexpectedStatus);
        self.state = .polling_authz;
        return self.noEffects();
    }

    /// Whether `value` (an authz identifier) is one of the ordered domains,
    /// compared case-insensitively; a configured `*.base` matches `base`.
    fn orderedIdentifier(self: *const Acme, value: []const u8) bool {
        for (self.config.domains) |d| {
            if (std.ascii.eqlIgnoreCase(d, value)) return true;
            if (std.mem.startsWith(u8, d, "*.") and std.ascii.eqlIgnoreCase(d[2..], value)) return true;
        }
        return false;
    }

    fn stepPollAuthz(self: *Acme, transport: Transport) Error!Progress {
        const authz_url = self.current_authz_url orelse return self.fail(error.AuthzFailed);
        const resp = try self.postSigned(transport, authz_url, "", false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        var authz = order_mod.parseAuthorization(self.allocator, resp.body) catch
            return self.fail(error.UnexpectedStatus);
        defer authz.deinit();

        switch (authz.status) {
            .valid => {
                self.authz_index += 1;
                self.state = .authorizing;
                return self.noEffects();
            },
            .pending, .processing => {
                return self.noEffects();
            },
            .invalid, .deactivated, .expired, .revoked, .ready => return self.fail(error.AuthzFailed),
        }
    }

    fn stepFinalize(self: *Acme, transport: Transport) Error!Progress {
        const finalize_url = self.finalize_url orelse return self.fail(error.OrderFailed);

        var cri_buf: [4096]u8 = undefined;
        const cri = csr.certificationRequestInfo(&cri_buf, .{
            .common_name = self.config.domains[0],
            .dns_names = self.config.domains,
            .spki_der = &ecP256Spki(self.config.cert_signer.public_key_x, self.config.cert_signer.public_key_y),
        }) catch return self.fail(error.OutOfMemory);

        // The cert key (distinct from the account key) signs the CRI. It yields a
        // fixed-width ES256 (r‖s) signature; a PKCS#10 CSR carries the DER-encoded
        // ECDSA signature, so transcode r‖s -> DER.
        var sig_buf: [64]u8 = undefined;
        const raw_sig = self.config.cert_signer.sign(cri, &sig_buf) catch
            return self.fail(error.OutOfMemory);
        if (raw_sig.len != 64) return self.fail(error.UnexpectedStatus);
        var fixed: [64]u8 = undefined;
        @memcpy(&fixed, raw_sig[0..64]);
        var der_sig_buf: [80]u8 = undefined;
        const der_sig = ecdsa_p256.signatureToDer(ecdsa_p256.Signature.fromBytes(fixed), &der_sig_buf) catch
            return self.fail(error.OutOfMemory);

        var csr_buf: [4096]u8 = undefined;
        const csr_der = csr.assemble(&csr_buf, cri, &ecdsa_sha256_sig_alg, der_sig) catch
            return self.fail(error.OutOfMemory);

        var payload_buf: [8192]u8 = undefined;
        const payload = order_mod.buildFinalize(&payload_buf, csr_der) catch
            return self.fail(error.OutOfMemory);

        const resp = try self.postSigned(transport, finalize_url, payload, false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        self.state = .polling_order;
        return self.noEffects();
    }

    fn stepPollOrder(self: *Acme, transport: Transport) Error!Progress {
        const order_url = self.order_url orelse return self.fail(error.OrderFailed);
        const resp = try self.postSigned(transport, order_url, "", false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        var parsed = order_mod.parseOrder(self.allocator, resp.body) catch
            return self.fail(error.UnexpectedStatus);
        defer parsed.deinit();

        switch (parsed.status) {
            .valid => {
                const cert = parsed.certificate orelse return self.fail(error.OrderFailed);
                self.cert_url = try self.allocator.dupe(u8, cert);
                self.state = .downloading;
                return self.noEffects();
            },
            .processing, .ready, .pending => return self.noEffects(),
            .invalid, .deactivated, .expired, .revoked => return self.fail(error.OrderFailed),
        }
    }

    fn stepDownload(self: *Acme, transport: Transport) Error!Progress {
        const cert_url = self.cert_url orelse return self.fail(error.OrderFailed);
        const resp = try self.postSigned(transport, cert_url, "", false);
        if (!isOk(resp.status)) return self.fail(error.UnexpectedStatus);

        const pem = try self.allocator.dupe(u8, resp.body);
        if (self.pem_buf) |old| self.allocator.free(old);
        self.pem_buf = pem;

        self.effect_buf[0] = .{ .write_cert = .{ .pem = pem } };
        self.state = .done;
        return .{ .state = .done, .done = true, .effects = self.effect_buf[0..1] };
    }
};

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

fn isOk(status: u16) bool {
    return status >= 200 and status < 300;
}

fn isProblemStatus(status: u16) bool {
    return status >= 400;
}

/// DER SubjectPublicKeyInfo for an uncompressed P-256 public key (91 bytes):
/// SEQUENCE { SEQUENCE { ecPublicKey, prime256v1 }, BIT STRING (0x04‖x‖y) }.
fn ecP256Spki(x: [32]u8, y: [32]u8) [91]u8 {
    var out: [91]u8 = .{
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04,
    } ++ @as([64]u8, @splat(0));
    @memcpy(out[27..59], &x);
    @memcpy(out[59..91], &y);
    return out;
}

/// DER AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2), no params.
const ecdsa_sha256_sig_alg = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };

// ===========================================================================
// Tests (AAA) — driven by an in-memory mock transport replaying a full flow.
// ===========================================================================

const testing = std.testing;

/// Canned response keyed by url. The mock returns the next unconsumed entry for
/// a url, so a repeated url (e.g. an authz poll) yields different bodies in turn.
const Canned = struct {
    url: []const u8,
    status: u16 = 200,
    body: []const u8,
    nonce: ?[]const u8 = "nonce-default",
    location: ?[]const u8 = null,
    used: bool = false,
};

const MockTransport = struct {
    entries: []Canned,
    sign_calls: *usize,

    fn next(self: *MockTransport, url: []const u8) HttpResponse {
        for (self.entries) |*e| {
            if (!e.used and std.mem.eql(u8, e.url, url)) {
                e.used = true;
                return .{ .status = e.status, .body = e.body, .nonce = e.nonce, .location = e.location };
            }
        }
        // Fall back to the last matching (re-poll) entry if all consumed.
        var last: ?*Canned = null;
        for (self.entries) |*e| {
            if (std.mem.eql(u8, e.url, url)) last = e;
        }
        if (last) |e| return .{ .status = e.status, .body = e.body, .nonce = e.nonce, .location = e.location };
        return .{ .status = 404, .body = "{}", .nonce = "nonce-default" };
    }

    fn getThunk(ctx: *anyopaque, url: []const u8) anyerror!HttpResponse {
        const self: *MockTransport = @ptrCast(@alignCast(ctx));
        return self.next(url);
    }

    fn postThunk(ctx: *anyopaque, url: []const u8, _: []const u8) anyerror!HttpResponse {
        const self: *MockTransport = @ptrCast(@alignCast(ctx));
        return self.next(url);
    }

    fn transport(self: *MockTransport) Transport {
        return .{ .ctx = self, .getFn = getThunk, .postJwsFn = postThunk };
    }
};

/// Deterministic test signer: 64 zero bytes (signatures are not verified here).
fn testSign(ctx: *anyopaque, signing_input: []const u8, out: []u8) anyerror![]const u8 {
    _ = signing_input;
    const calls: *usize = @ptrCast(@alignCast(ctx));
    calls.* += 1;
    @memset(out[0..64], 0x42); // non-zero r‖s so DER transcoding is well-formed
    return out[0..64];
}

fn makeSigner(calls: *usize) Signer {
    return .{
        .ctx = calls,
        .public_key_x = @as([32]u8, @splat(7)),
        .public_key_y = @as([32]u8, @splat(9)),
        .signFn = testSign,
    };
}

/// A certificate-key signer whose public key differs from `makeSigner`'s.
fn makeCertSigner(calls: *usize) Signer {
    var s = makeSigner(calls);
    s.public_key_x = @as([32]u8, @splat(3));
    s.public_key_y = @as([32]u8, @splat(5));
    return s;
}

/// Run the machine to a terminal state, collecting emitted effect tags.
fn driveToEnd(acme: *Acme, t: Transport, saw_serve: *bool, saw_cert: *bool) !State {
    var guard: usize = 0;
    while (acme.state != .done and acme.state != .failed) : (guard += 1) {
        if (guard > 64) return error.TestExpectedEqual;
        const prog = try acme.step(t);
        for (prog.effects) |eff| switch (eff) {
            .serve_http01, .provision_dns01, .provision_tls_alpn01 => saw_serve.* = true,
            .write_cert => saw_cert.* = true,
        };
    }
    return acme.state;
}

test "full http-01 issuance flow drives machine to done and emits effects" {
    // Arrange — canned Let's Encrypt-style responses.
    const dir_json =
        \\{"newNonce":"https://ca/nonce","newAccount":"https://ca/acct",
        \\"newOrder":"https://ca/order","revokeCert":"https://ca/revoke",
        \\"keyChange":"https://ca/keychange"}
    ;
    const order_json =
        \\{"status":"pending","identifiers":[{"type":"dns","value":"example.com"}],
        \\"authorizations":["https://ca/authz/1"],"finalize":"https://ca/finalize/1"}
    ;
    const authz_pending =
        \\{"status":"pending","identifier":{"type":"dns","value":"example.com"},
        \\"challenges":[{"type":"http-01","url":"https://ca/chal/1","token":"tok123","status":"pending"}]}
    ;
    const authz_valid =
        \\{"status":"valid","identifier":{"type":"dns","value":"example.com"},
        \\"challenges":[{"type":"http-01","url":"https://ca/chal/1","token":"tok123","status":"valid"}]}
    ;
    const order_processing =
        \\{"status":"processing","identifiers":[{"type":"dns","value":"example.com"}],
        \\"authorizations":["https://ca/authz/1"],"finalize":"https://ca/finalize/1"}
    ;
    const order_valid =
        \\{"status":"valid","identifiers":[{"type":"dns","value":"example.com"}],
        \\"authorizations":["https://ca/authz/1"],"finalize":"https://ca/finalize/1",
        \\"certificate":"https://ca/cert/1"}
    ;
    const cert_pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = dir_json, .nonce = "n0" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{\"status\":\"valid\"}", .nonce = "n1", .location = "https://ca/acct/9" },
        .{ .url = "https://ca/order", .status = 201, .body = order_json, .nonce = "n2", .location = "https://ca/order/1" },
        // GET (POST-as-GET) authz before triggering.
        .{ .url = "https://ca/authz/1", .body = authz_pending, .nonce = "n3" },
        // trigger challenge POST.
        .{ .url = "https://ca/chal/1", .body = authz_pending, .nonce = "n4" },
        // poll authz -> valid.
        .{ .url = "https://ca/authz/1", .body = authz_valid, .nonce = "n5" },
        // finalize.
        .{ .url = "https://ca/finalize/1", .body = order_processing, .nonce = "n6" },
        // poll order -> processing then valid.
        .{ .url = "https://ca/order/1", .body = order_processing, .nonce = "n7" },
        .{ .url = "https://ca/order/1", .body = order_valid, .nonce = "n8" },
        // download cert.
        .{ .url = "https://ca/cert/1", .body = cert_pem, .nonce = "n9" },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };

    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .contacts = &.{"mailto:admin@example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
    });
    defer acme.deinit();

    // Act
    var saw_serve = false;
    var saw_cert = false;
    const final = try driveToEnd(&acme, mock.transport(), &saw_serve, &saw_cert);

    // Assert
    try testing.expectEqual(State.done, final);
    try testing.expect(saw_serve);
    try testing.expect(saw_cert);
    try testing.expect(acme.pem_buf != null);
    try testing.expectEqualStrings(cert_pem, acme.pem_buf.?);
    try testing.expect(sign_calls > 0);
}

test "badNonce on newAccount is retried with the fresh nonce then succeeds" {
    // Arrange — first newAccount POST returns badNonce (carrying a new nonce);
    // the retry succeeds. We only drive far enough to observe recovery.
    const dir_json =
        \\{"newNonce":"https://ca/nonce","newAccount":"https://ca/acct",
        \\"newOrder":"https://ca/order","revokeCert":"https://ca/revoke",
        \\"keyChange":"https://ca/keychange"}
    ;
    const bad_nonce_problem =
        \\{"type":"urn:ietf:params:acme:error:badNonce","detail":"bad nonce"}
    ;

    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = dir_json, .nonce = "n0" },
        // First acct POST -> 400 badNonce, hands back a fresh nonce.
        .{ .url = "https://ca/acct", .status = 400, .body = bad_nonce_problem, .nonce = "fresh-nonce" },
        // Retry acct POST -> 201 created.
        .{ .url = "https://ca/acct", .status = 201, .body = "{\"status\":\"valid\"}", .nonce = "n2", .location = "https://ca/acct/9" },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };

    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
    });
    defer acme.deinit();

    // Act — step through start then account.
    _ = try acme.step(mock.transport()); // start -> account
    const prog = try acme.step(mock.transport()); // account (retries internally) -> order

    // Assert — recovered past the badNonce and advanced to order.
    try testing.expectEqual(State.order, prog.state);
    try testing.expect(acme.account_url != null);
    try testing.expectEqualStrings("https://ca/acct/9", acme.account_url.?);
    // signer was called twice for the account request (original + retry).
    try testing.expect(sign_calls >= 2);
}

test "stepping a terminal machine returns error.Terminal" {
    // Arrange
    var sign_calls: usize = 0;
    var entries = [_]Canned{.{ .url = "x", .body = "{}" }};
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "x",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
    });
    defer acme.deinit();
    acme.state = .done;

    // Act / Assert
    try testing.expectError(error.Terminal, acme.step(mock.transport()));
}

const test_dir_json =
    \\{"newNonce":"https://ca/nonce","newAccount":"https://ca/acct",
    \\"newOrder":"https://ca/order","revokeCert":"https://ca/revoke",
    \\"keyChange":"https://ca/keychange"}
;
const test_order_json =
    \\{"status":"pending","identifiers":[{"type":"dns","value":"example.com"}],
    \\"authorizations":["https://ca/authz/1"],"finalize":"https://ca/finalize/1"}
;
const test_authz_pending_all =
    \\{"status":"pending","identifier":{"type":"dns","value":"example.com"},
    \\"challenges":[{"type":"http-01","url":"https://ca/chal/h","token":"tokH","status":"pending"},
    \\{"type":"dns-01","url":"https://ca/chal/d","token":"tokD","status":"pending"},
    \\{"type":"tls-alpn-01","url":"https://ca/chal/t","token":"tokT","status":"pending"}]}
;

/// Drive start -> account -> order -> authorizing and return the progress of
/// the authorizing step (the provisioning effect).
fn driveToProvision(acme: *Acme, t: Transport) !Progress {
    _ = try acme.step(t); // start
    _ = try acme.step(t); // account
    _ = try acme.step(t); // order
    return acme.step(t); // authorizing -> effect
}

test "dns-01 emits _acme-challenge TXT effect before the challenge POST" {
    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = test_dir_json, .nonce = "n0" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{}", .location = "https://ca/acct/1" },
        .{ .url = "https://ca/order", .status = 201, .body = test_order_json, .location = "https://ca/order/1" },
        .{ .url = "https://ca/authz/1", .body = test_authz_pending_all },
        .{ .url = "https://ca/chal/d", .body = "{}" },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
        .challenge = .dns_01,
    });
    defer acme.deinit();

    const prog = try driveToProvision(&acme, mock.transport());
    try testing.expectEqual(State.responding, prog.state);
    try testing.expectEqual(@as(usize, 1), prog.effects.len);
    const eff = prog.effects[0].provision_dns01;
    try testing.expectEqualStrings("_acme-challenge.example.com", eff.fqdn);

    // Expected TXT = base64url(SHA-256("tokD." ++ thumbprint(account key))).
    var thumb_digest: [32]u8 = undefined;
    jwk.thumbprintEc(@as([32]u8, @splat(7)), @as([32]u8, @splat(9)), &thumb_digest);
    var thumb_buf: [jwk.thumbprint_b64_len]u8 = undefined;
    const thumb = std.base64.url_safe_no_pad.Encoder.encode(&thumb_buf, &thumb_digest);
    var ka_buf: [128]u8 = undefined;
    const ka = try challenge.keyAuthorization("tokD", thumb, &ka_buf);
    var txt_buf: [64]u8 = undefined;
    try testing.expectEqualStrings(try challenge.dns01TxtValue(ka, &txt_buf), eff.txt_value);

    // The CA has NOT been told to validate yet (RFC 8555 §7.5.1 ordering).
    try testing.expect(!entries[4].used);
    const next = try acme.step(mock.transport());
    try testing.expectEqual(State.polling_authz, next.state);
    try testing.expect(entries[4].used);
}

test "tls-alpn-01 emits domain + key authorization effect for the identifier" {
    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = test_dir_json, .nonce = "n0" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{}", .location = "https://ca/acct/1" },
        .{ .url = "https://ca/order", .status = 201, .body = test_order_json, .location = "https://ca/order/1" },
        .{ .url = "https://ca/authz/1", .body = test_authz_pending_all },
        .{ .url = "https://ca/chal/t", .body = "{}" },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"EXAMPLE.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
        .challenge = .tls_alpn_01,
    });
    defer acme.deinit();

    const prog = try driveToProvision(&acme, mock.transport());
    const eff = prog.effects[0].provision_tls_alpn01;
    try testing.expectEqualStrings("example.com", eff.domain);
    try testing.expect(std.mem.startsWith(u8, eff.key_authorization, "tokT."));
    try testing.expect(!entries[4].used);
    _ = try acme.step(mock.transport());
    try testing.expect(entries[4].used);
}

test "authz without the configured challenge type fails closed" {
    const authz_http_only =
        \\{"status":"pending","identifier":{"type":"dns","value":"example.com"},
        \\"challenges":[{"type":"http-01","url":"https://ca/chal/h","token":"tokH","status":"pending"}]}
    ;
    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = test_dir_json, .nonce = "n0" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{}", .location = "https://ca/acct/1" },
        .{ .url = "https://ca/order", .status = 201, .body = test_order_json, .location = "https://ca/order/1" },
        .{ .url = "https://ca/authz/1", .body = authz_http_only },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
        .challenge = .dns_01,
    });
    defer acme.deinit();
    try testing.expectError(error.NoChallenge, driveToProvision(&acme, mock.transport()));
    try testing.expectEqual(State.failed, acme.state);
}

test "authz for an identifier we did not order fails closed; wildcard base matches" {
    const authz_other =
        \\{"status":"pending","identifier":{"type":"dns","value":"evil.example"},
        \\"challenges":[{"type":"dns-01","url":"https://ca/chal/d","token":"tokD","status":"pending"}]}
    ;
    var entries = [_]Canned{
        .{ .url = "https://ca/directory", .body = test_dir_json, .nonce = "n0" },
        .{ .url = "https://ca/acct", .status = 201, .body = "{}", .location = "https://ca/acct/1" },
        .{ .url = "https://ca/order", .status = 201, .body = test_order_json, .location = "https://ca/order/1" },
        .{ .url = "https://ca/authz/1", .body = authz_other },
    };
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
        .challenge = .dns_01,
    });
    defer acme.deinit();
    try testing.expectError(error.UnexpectedIdentifier, driveToProvision(&acme, mock.transport()));

    // RFC 8555 §7.1.4: a "*.example.com" order's authz names "example.com".
    var wild = Acme.init(testing.allocator, .{
        .directory_url = "x",
        .domains = &.{"*.example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeCertSigner(&sign_calls),
    });
    defer wild.deinit();
    try testing.expect(wild.orderedIdentifier("example.com"));
    try testing.expect(wild.orderedIdentifier("Example.COM"));
    try testing.expect(!wild.orderedIdentifier("sub.example.com"));
}

test "account key equal to certificate key is refused before any request" {
    var entries = [_]Canned{.{ .url = "https://ca/directory", .body = test_dir_json }};
    var sign_calls: usize = 0;
    var mock = MockTransport{ .entries = &entries, .sign_calls = &sign_calls };
    var acme = Acme.init(testing.allocator, .{
        .directory_url = "https://ca/directory",
        .domains = &.{"example.com"},
        .signer = makeSigner(&sign_calls),
        .cert_signer = makeSigner(&sign_calls),
    });
    defer acme.deinit();
    try testing.expectError(error.AccountKeyReuse, acme.step(mock.transport()));
    try testing.expect(!entries[0].used);
}

test "ChallengeType round-trips its wire names" {
    try testing.expectEqual(ChallengeType.http_01, ChallengeType.fromString("http-01").?);
    try testing.expectEqual(ChallengeType.dns_01, ChallengeType.fromString("dns-01").?);
    try testing.expectEqual(ChallengeType.tls_alpn_01, ChallengeType.fromString("tls-alpn-01").?);
    try testing.expect(ChallengeType.fromString("tls-sni-01") == null);
    try testing.expect(ChallengeType.fromString("HTTP-01") == null);
}
