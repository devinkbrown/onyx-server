// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bridge: expose the in-process account `Services` as a SASL PLAIN verifier.
//!
//! The dispatch SASL handler (`dispatch.zig`) takes an injected
//! `sasl.PlainChecker`; this adapts the account store to that interface so the
//! live server can authenticate PLAIN credentials against registered accounts.
//! Verification delegates to `Services.identifyAccount`, which runs PBKDF2 + a
//! constant-time hash compare and a dummy PBKDF2 on missing accounts (no
//! username-enumeration timing oracle — see services.zig).
const std = @import("std");
const sasl = @import("../proto/sasl.zig");
const mechrouter = @import("../proto/sasl_mechrouter.zig");
const services_mod = @import("services.zig");
const scram_store_mod = @import("scram_store.zig");
const platform = @import("../substrate/platform.zig");
const Services = services_mod.Services;
const ScramStore = scram_store_mod.ScramStore;

/// Adapter holding a `*Services`. Hand `checker()` to `ClientSession.sasl_plain`
/// (typically via `server.Config.sasl_checker`) so AUTHENTICATE PLAIN verifies
/// against the account store.
///
/// LIFETIME: each connection copies the returned fat pointer, so this
/// `ServicesPlainChecker` (and the `Services` + `OroStore` it points at) MUST
/// outlive every connection — own it in the same scope as the `Server`, never a
/// stack temporary.
pub const ServicesPlainChecker = struct {
    services: *Services,

    pub fn checker(self: *ServicesPlainChecker) sasl.PlainChecker {
        return .{ .ptr = self, .verifyFn = verify };
    }

    fn verify(ptr: *anyopaque, creds: sasl.PlainCredentials) bool {
        const self: *ServicesPlainChecker = @ptrCast(@alignCast(ptr));
        // Defense-in-depth: refuse empty credentials at the adapter boundary so
        // the guarantee is local here, not an emergent property of the account
        // password policy downstream.
        if (creds.authcid.len == 0 or creds.password.len == 0) return false;
        // Identity assumption (logging in as an account other than authcid) is
        // not supported: a non-empty authzid must equal authcid.
        if (creds.authzid.len != 0 and !std.mem.eql(u8, creds.authzid, creds.authcid)) return false;
        const result = self.services.identifyAccount(creds.authcid, creds.password) catch return false;
        return switch (result) {
            .identified => true,
            else => false,
        };
    }
};

/// Adapter exposing a `*ScramStore` as the mechrouter's SCRAM-SHA-256
/// credential source. Hand `lookup()` to `mechrouter.Callbacks.scram256` so the
/// router can fetch each account's `{salt, iters, StoredKey, ServerKey}` and run
/// the challenge/response. Unlike PLAIN, SCRAM never sees the cleartext password
/// at verification time — the proof is checked against the stored keys by
/// `sasl_scram_server` in constant time.
///
/// LIFETIME: the returned fat pointer borrows the `*ScramStore`, which must
/// outlive every connection (own it alongside the `Server`, never a stack
/// temporary). This is the SCRAM analogue of `ServicesPlainChecker`.
pub const ServicesScramLookup = struct {
    scram: *ScramStore,

    /// Build the mechrouter SCRAM-SHA-256 lookup callback. Equivalent to
    /// `ScramStore.scram256Lookup`, surfaced here so daemon wiring can source
    /// every SASL adapter from a single bridge module.
    pub fn lookup(self: *ServicesScramLookup) mechrouter.Scram256Lookup {
        return self.scram.scram256Lookup();
    }
};

/// Adapter exposing a `*ScramStore` as the mechrouter's SCRAM-SHA-512 credential
/// source. The SHA-512 sibling of `ServicesScramLookup`: hand `lookup()` to
/// `mechrouter.Callbacks.scram512` so the router can fetch each account's
/// SHA-512 `{salt, iters, StoredKey, ServerKey}`. The lookup returns null for
/// accounts that were never provisioned with SHA-512 material (e.g. records
/// loaded from a pre-SHA-512 durable mirror), so SCRAM-SHA-512 is offered only
/// where it can actually complete.
///
/// LIFETIME: identical to `ServicesScramLookup` — the returned fat pointer
/// borrows the `*ScramStore`, which must outlive every connection.
pub const ServicesScram512Lookup = struct {
    scram: *ScramStore,

    /// Build the mechrouter SCRAM-SHA-512 lookup callback. Equivalent to
    /// `ScramStore.scram512Lookup`.
    pub fn lookup(self: *ServicesScram512Lookup) mechrouter.Scram512Lookup {
        return self.scram.scram512Lookup();
    }
};

/// Adapter exposing a `*Services` as the mechrouter's SASL EXTERNAL verifier:
/// the presented client-cert fingerprint is matched to a bound account
/// (CERTADD). Hand `lookup()` to `mechrouter.Callbacks.external`. No secret is
/// exchanged — possession of the cert's private key was already proven by the
/// TLS CertificateVerify; this only maps the fingerprint to an account.
///
/// LIFETIME: the returned fat pointer borrows `*Services`, which must outlive
/// every connection (own it alongside the `Server`).
pub const ServicesExternalLookup = struct {
    services: *Services,

    pub fn lookup(self: *ServicesExternalLookup) mechrouter.ExternalLookup {
        return .{ .ptr = self, .verifyFn = verify };
    }

    fn verify(ptr: *anyopaque, certfp: []const u8, authzid: []const u8) ?[]const u8 {
        const self: *ServicesExternalLookup = @ptrCast(@alignCast(ptr));
        const account = self.services.accountForCertfp(certfp) orelse return null;
        // Identity assumption is unsupported: a non-empty authzid must name the
        // same account the certificate is bound to (case-insensitive).
        if (authzid.len != 0 and !std.ascii.eqlIgnoreCase(authzid, account)) return null;
        return account;
    }
};

/// Adapter exposing durable services SESSION-TOKEN validation to the SASL
/// mechanism router. Tokens are checked by SHA-256(token) against the services
/// props family; only the canonical account is returned.
pub const ServicesSessionTokenLookup = struct {
    services: *Services,

    pub fn lookup(self: *ServicesSessionTokenLookup) mechrouter.SessionTokenLookup {
        return .{ .ptr = self, .verifyFn = verify };
    }

    fn verify(ptr: *anyopaque, creds: mechrouter.SessionTokenCredentials, account_out: []u8) ?[]const u8 {
        const self: *ServicesSessionTokenLookup = @ptrCast(@alignCast(ptr));
        const now_ms = platform.realtimeMillisChecked() orelse return null;
        if (now_ms <= 0) return null;
        return self.services.validateSessionToken(creds.authcid, creds.token, @divTrunc(now_ms, 1000), account_out);
    }
};

test "services-backed PLAIN checker verifies registered accounts" {
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge.wal");
    defer store.deinit();

    var services = Services.init(&store, null);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesPlainChecker{ .services = &services };
    const chk = bridge.checker();

    // Correct credentials authenticate.
    try std.testing.expect(chk.verify(.{ .authzid = "", .authcid = "alice", .password = "correct horse battery staple" }));
    // Wrong password is rejected.
    try std.testing.expect(!chk.verify(.{ .authzid = "", .authcid = "alice", .password = "wrong" }));
    // Unknown account is rejected (and runs a dummy PBKDF2 internally).
    try std.testing.expect(!chk.verify(.{ .authzid = "", .authcid = "nobody", .password = "whatever" }));
    // Identity assumption (authzid != authcid) is refused.
    try std.testing.expect(!chk.verify(.{ .authzid = "bob", .authcid = "alice", .password = "correct horse battery staple" }));
}

test "services-backed EXTERNAL verifier maps a bound certfp to its account" {
    const OroStore = services_mod.OroStore;
    const certfp_bind_mod = @import("certfp_bind.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "extbridge.wal");
    defer store.deinit();

    var services = Services.init(&store, null);
    var binds = certfp_bind_mod.CertfpBindStore.init(std.testing.allocator);
    defer binds.deinit();
    services.attachCertfpBinds(&binds);

    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try services.bindCertfp("alice", fp);

    var bridge = ServicesExternalLookup{ .services = &services };
    const ext = bridge.lookup();

    // The bound fingerprint resolves to its account.
    try std.testing.expectEqualStrings("alice", ext.verify(fp, "").?);
    // A matching authzid is allowed (case-insensitive).
    try std.testing.expectEqualStrings("alice", ext.verify(fp, "ALICE").?);
    // An unbound fingerprint and a mismatched authzid both fail.
    try std.testing.expect(ext.verify("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "") == null);
    try std.testing.expect(ext.verify(fp, "bob") == null);
}

const scram256 = @import("../proto/sasl_scram_server.zig");
const scram_client = @import("../crypto/sasl_scram_client.zig");

/// Run a full SCRAM-SHA-256 exchange against a credential sourced from the
/// bridge. The server side is `sasl_scram_server.Server`; the client side is the
/// in-repo `sasl_scram_client`. Returns true if the server accepts the proof and
/// the client verifies the returned server signature, false on a proof mismatch.
fn runScramExchange(
    allocator: std.mem.Allocator,
    credential: scram256.Credential,
    username: []const u8,
    password: []const u8,
) !bool {
    const client_nonce = "fixedClientNonceForBridgeTest";
    const server_nonce = "fixedServerNonceForBridgeTest";

    var first = try scram_client.clientFirst(allocator, username, client_nonce);
    defer first.deinit();

    var server = scram256.Server.init();
    var server_first_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_first = try server.receiveClientFirst(
        first.message,
        credential,
        server_nonce,
        &server_first_buf,
    );

    var final = try scram_client.clientFinal(allocator, &first.state, server_first.server_first, password);
    defer final.deinit(allocator);

    var server_final_buf: [scram256.MAX_MESSAGE]u8 = undefined;
    const server_final = server.receiveClientFinal(final.message, &server_final_buf) catch |err| switch (err) {
        error.ProofMismatch => return false,
        else => return err,
    };
    // The client also authenticates the server: a successful exchange must carry
    // a verifiable server signature.
    try final.verifyServerFinal(server_final.server_final);
    return true;
}

test "registered account completes a SCRAM-SHA-256 exchange via the bridge lookup" {
    // Arrange: register an account through Services with a SCRAM mirror attached.
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge-scram.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesScramLookup{ .scram = &scram };
    const lookup = bridge.lookup();

    // Act: source the credential through the bridge and run a real exchange.
    const credential = lookup.lookup("alice") orelse return error.MissingCredential;
    const ok = try runScramExchange(
        std.testing.allocator,
        credential,
        "alice",
        "correct horse battery staple",
    );

    // Assert
    try std.testing.expect(ok);
}

test "SCRAM-SHA-256 exchange rejects the wrong password for a registered account" {
    // Arrange
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge-scram-bad.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesScramLookup{ .scram = &scram };
    const lookup = bridge.lookup();
    const credential = lookup.lookup("alice") orelse return error.MissingCredential;

    // Act: a client that knows the wrong password produces a bad proof.
    const ok = try runScramExchange(
        std.testing.allocator,
        credential,
        "alice",
        "wrong password value here",
    );

    // Assert
    try std.testing.expect(!ok);
}

test "SASL SCRAM proof stays valid but the account gate blocks a suspended or forbidden account" {
    // Regression for the SCRAM flag-gate bypass: the SCRAM proof verifies purely
    // from the stored key material, so a SUSPENDED or FORBIDDEN account still
    // produces a valid proof. The SASL success chokepoint must refuse the login
    // by consulting `accountAuthBlocked` — this test proves the proof/gate split.
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge-scram-gate.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesScramLookup{ .scram = &scram };
    const lookup = bridge.lookup();
    const credential = lookup.lookup("alice") orelse return error.MissingCredential;

    // Baseline: correct proof verifies AND the account is not blocked -> login.
    try std.testing.expect(try runScramExchange(std.testing.allocator, credential, "alice", "correct horse battery staple"));
    try std.testing.expect(!services.accountAuthBlocked("alice"));

    // SUSPEND: the SCRAM proof is STILL valid (the material is unchanged), but the
    // gate must now block the success -> login denied.
    _ = try services.setAccountSuspended("alice", true, &scratch);
    const cred_suspended = bridge.lookup().lookup("alice") orelse return error.MissingCredential;
    try std.testing.expect(try runScramExchange(std.testing.allocator, cred_suspended, "alice", "correct horse battery staple"));
    try std.testing.expect(services.accountAuthBlocked("alice"));

    // UNSUSPEND: gate clears -> login allowed again.
    _ = try services.setAccountSuspended("alice", false, &scratch);
    try std.testing.expect(!services.accountAuthBlocked("alice"));

    // FORBID: proof still valid, gate blocks.
    _ = try services.setAccountForbidden("alice", true, &scratch);
    const cred_forbidden = bridge.lookup().lookup("alice") orelse return error.MissingCredential;
    try std.testing.expect(try runScramExchange(std.testing.allocator, cred_forbidden, "alice", "correct horse battery staple"));
    try std.testing.expect(services.accountAuthBlocked("alice"));

    // UNFORBID: login allowed again.
    _ = try services.setAccountForbidden("alice", false, &scratch);
    try std.testing.expect(!services.accountAuthBlocked("alice"));
}

test "bridge lookup returns null for an unregistered account" {
    // Arrange
    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();
    var bridge = ServicesScramLookup{ .scram = &scram };

    // Act
    const lookup = bridge.lookup();

    // Assert
    try std.testing.expect(lookup.lookup("nobody") == null);
}

const scram512 = @import("../proto/sasl_scram512_server.zig");

/// Run a full SCRAM-SHA-512 exchange against a credential sourced from the
/// bridge. The server side is `sasl_scram512_server.Server`; the client side is
/// built inline (there is no in-repo SHA-512 SCRAM client). Returns true if the
/// server accepts the proof and the returned server signature verifies, false on
/// a proof mismatch. Mirrors `runScramExchange` for the SHA-512 mechanism.
fn runScram512Exchange(
    allocator: std.mem.Allocator,
    credential: scram512.Credential,
    username: []const u8,
    password: []const u8,
) !bool {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const HmacSha512 = std.crypto.auth.hmac.Hmac(Sha512);
    const dl = scram512.digest_len;

    const client_nonce = "fixedClientNonce512ForBridgeTest";
    const server_nonce = "fixedServerNonce512ForBridgeTest";

    const client_first = try std.fmt.allocPrint(allocator, "n,,n={s},r={s}", .{ username, client_nonce });
    defer allocator.free(client_first);

    var server = scram512.Server.init();
    var server_first_buf: [scram512.MAX_MESSAGE]u8 = undefined;
    const first = try server.receiveClientFirst(client_first, credential, server_nonce, &server_first_buf);

    const without_proof = try std.fmt.allocPrint(allocator, "c=biws,r={s}", .{first.combined_nonce});
    defer allocator.free(without_proof);
    const auth_message = try std.fmt.allocPrint(
        allocator,
        "n={s},r={s},{s},{s}",
        .{ username, client_nonce, first.server_first, without_proof },
    );
    defer allocator.free(auth_message);

    // Client-side proof from the password + advertised salt/iterations.
    var salted: [dl]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, password, credential.salt, credential.iterations, HmacSha512);
    var client_key: [dl]u8 = undefined;
    HmacSha512.create(&client_key, "Client Key", &salted);
    var stored_key: [dl]u8 = undefined;
    Sha512.hash(&client_key, &stored_key, .{});
    var client_sig: [dl]u8 = undefined;
    HmacSha512.create(&client_sig, auth_message, &stored_key);
    var proof: [dl]u8 = undefined;
    for (&proof, client_key, client_sig) |*dst, ck, cs| dst.* = ck ^ cs;

    var proof_b64_buf: [std.base64.standard.Encoder.calcSize(dl)]u8 = undefined;
    const proof_b64 = std.base64.standard.Encoder.encode(&proof_b64_buf, &proof);
    const client_final = try std.fmt.allocPrint(allocator, "{s},p={s}", .{ without_proof, proof_b64 });
    defer allocator.free(client_final);

    var server_final_buf: [scram512.MAX_MESSAGE]u8 = undefined;
    const server_final = server.receiveClientFinal(client_final, &server_final_buf) catch |err| switch (err) {
        error.ProofMismatch => return false,
        else => return err,
    };
    // The client authenticates the server too: verify v=ServerSignature.
    var server_sig: [dl]u8 = undefined;
    HmacSha512.create(&server_sig, auth_message, &credential.server_key);
    var verifier_b64_buf: [std.base64.standard.Encoder.calcSize(dl)]u8 = undefined;
    const verifier_b64 = std.base64.standard.Encoder.encode(&verifier_b64_buf, &server_sig);
    const expected = try std.fmt.allocPrint(allocator, "v={s}", .{verifier_b64});
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, server_final.server_final);
    return true;
}

test "registered account completes a SCRAM-SHA-512 exchange via the bridge lookup" {
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge-scram512.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesScram512Lookup{ .scram = &scram };
    const lookup = bridge.lookup();

    const credential = lookup.lookup("alice") orelse return error.MissingCredential;
    const ok = try runScram512Exchange(
        std.testing.allocator,
        credential,
        "alice",
        "correct horse battery staple",
    );
    try std.testing.expect(ok);
}

test "SCRAM-SHA-512 exchange rejects the wrong password for a registered account" {
    const OroStore = services_mod.OroStore;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "sasl-bridge-scram512-bad.wal");
    defer store.deinit();

    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();

    var services = Services.init(&store, null);
    services.attachScramStore(&scram);
    var scratch: [768]u8 = undefined;
    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);

    var bridge = ServicesScram512Lookup{ .scram = &scram };
    const lookup = bridge.lookup();
    const credential = lookup.lookup("alice") orelse return error.MissingCredential;

    const ok = try runScram512Exchange(
        std.testing.allocator,
        credential,
        "alice",
        "wrong password value here",
    );
    try std.testing.expect(!ok);
}

test "SCRAM-SHA-512 bridge lookup returns null for an unregistered account" {
    var scram = ScramStore.init(std.testing.allocator);
    defer scram.deinit();
    var bridge = ServicesScram512Lookup{ .scram = &scram };
    const lookup = bridge.lookup();
    try std.testing.expect(lookup.lookup("nobody") == null);
}

test {
    std.testing.refAllDecls(@This());
}
