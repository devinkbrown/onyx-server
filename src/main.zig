// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx Server entry point (M1: Ringlane TCP server).
const std = @import("std");
const builtin = @import("builtin");
const onyx_server = @import("onyx_server");
const delegated_credential_cli = @import("daemon/delegated_credential_cli.zig");
const windows_config_proof = onyx_server.daemon.helix.native_windows_config_proof;
const windows_process = onyx_server.daemon.helix.native_windows_process;
const windows_bootstrap = onyx_server.daemon.helix.native_windows_bootstrap;
const windows_driver = onyx_server.daemon.helix.native_windows_driver;
const windows_runtime = onyx_server.daemon.helix.native_windows_runtime;
const windows_tls_material = onyx_server.daemon.helix.native_windows_tls_material;
const native_service = onyx_server.daemon.native_service;
const service_helper = onyx_server.daemon.native_service_helper;

/// Own the original PEM decode container as well as every DER allocation.
/// Companion workers borrow items until their stop/join completes; main keeps
/// this owner in the enclosing scope and destroys it after those workers.
const OwnedTrustAnchors = struct {
    allocator: std.mem.Allocator,
    anchors: std.ArrayList([]u8),

    fn load(allocator: std.mem.Allocator, text: []const u8) !OwnedTrustAnchors {
        return .{ .allocator = allocator, .anchors = try onyx_server.daemon.acme_cli.loadTrustAnchors(allocator, text) };
    }

    fn items(self: *const OwnedTrustAnchors) []const []const u8 {
        return self.anchors.items;
    }

    fn deinit(self: *OwnedTrustAnchors) void {
        for (self.anchors.items) |der| self.allocator.free(der);
        self.anchors.deinit(self.allocator);
        self.anchors = .empty;
    }
};

/// Windows Helix must serve from the same MMDB bytes preflight parsed and
/// committed to the effective config digest. The database borrows `bytes`;
/// only this owner (or Server after transfer) may free them.
const WindowsGeoDatabase = struct {
    bytes: []u8,
    database: onyx_server.substrate.geoip.Database,

    fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !WindowsGeoDatabase {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(256 << 20));
        errdefer allocator.free(bytes);
        return .{ .bytes = bytes, .database = try onyx_server.substrate.geoip.Database.init(bytes) };
    }

    fn deinit(self: *WindowsGeoDatabase, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const WindowsGeoOwned = struct {
    city: ?WindowsGeoDatabase = null,
    asn: ?WindowsGeoDatabase = null,

    fn deinit(self: *WindowsGeoOwned, allocator: std.mem.Allocator) void {
        if (self.city) |*owner| owner.deinit(allocator);
        if (self.asn) |*owner| owner.deinit(allocator);
        self.* = .{};
    }

    fn cityBytes(self: *const WindowsGeoOwned) ?[]const u8 {
        return if (self.city) |owner| owner.bytes else null;
    }

    fn asnBytes(self: *const WindowsGeoOwned) ?[]const u8 {
        return if (self.asn) |owner| owner.bytes else null;
    }
};

const anchor_ownership_test_pem =
    "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n" ++
    "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";

fn testTrustAnchorAllocationPath(allocator: std.mem.Allocator, disabled_after_load: bool) !void {
    var owner = try OwnedTrustAnchors.load(allocator, anchor_ownership_test_pem);
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 2), owner.items().len);
    // A late disabled branch owns the successfully decoded bundle too.
    if (disabled_after_load) return;
    // Exercise OOM after both DER allocations and the original list exist.
    const consumer = try allocator.create(u8);
    defer allocator.destroy(consumer);
    consumer.* = owner.items()[1][4];
    try std.testing.expectEqual(@as(u8, 1), consumer.*);
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 3, 2, 1, 0 }, owner.items()[0]);
}

test "managed anchors: late disabled and consumer allocation failures free DER and the original container" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testTrustAnchorAllocationPath, .{true});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testTrustAnchorAllocationPath, .{false});
}

test "managed anchors: empty and malformed bundles remain allocation-free" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var empty = try OwnedTrustAnchors.load(failing.allocator(), "no certificate blocks");
    defer empty.deinit();
    var malformed = try OwnedTrustAnchors.load(failing.allocator(), "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n");
    defer malformed.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.items().len);
    try std.testing.expectEqual(@as(usize, 0), malformed.items().len);
    try std.testing.expect(!failing.has_induced_failure);
}

const TrustAnchorBorrowFixture = if (builtin.is_test) struct {
    io: std.Io,
    anchors: []const []const u8,
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    observed: bool = false,

    fn run(self: *@This()) void {
        self.entered.set(self.io);
        self.release.waitUncancelable(self.io);
        self.observed = self.anchors.len == 2 and
            std.mem.eql(u8, self.anchors[0], &.{ 0x30, 3, 2, 1, 0 }) and
            std.mem.eql(u8, self.anchors[1], &.{ 0x30, 3, 2, 1, 1 });
    }
} else void;

test "managed anchors: real borrowed reader joins before its owner frees DER" {
    var tracked = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var owner = try OwnedTrustAnchors.load(tracked.allocator(), anchor_ownership_test_pem);
    defer owner.deinit();
    var borrow: TrustAnchorBorrowFixture = .{ .io = std.testing.io, .anchors = owner.items() };
    const thread = try std.Thread.spawn(.{}, TrustAnchorBorrowFixture.run, .{&borrow});
    var joined = false;
    defer if (!joined) {
        borrow.release.set(borrow.io);
        thread.join();
    };
    borrow.entered.waitUncancelable(borrow.io);
    try std.testing.expect(tracked.allocated_bytes > tracked.freed_bytes);
    borrow.release.set(borrow.io);
    thread.join();
    joined = true;
    try std.testing.expect(borrow.observed);
    owner.deinit();
    try std.testing.expectEqual(tracked.allocated_bytes, tracked.freed_bytes);
}

/// Commit the actual loaded source and each resolved value, rather than reopening
/// a config after the root launcher has accepted its preflight. Framing keeps
/// different names/value partitions distinct without retaining secret text.
const ManagedConfigCommitment = struct {
    hash: std.crypto.hash.sha2.Sha256,
    fn init() ManagedConfigCommitment {
        var result: ManagedConfigCommitment = .{ .hash = .init(.{}) };
        result.hash.update("onyx/native-service/config-v2\x00");
        result.record(0, "build", onyx_server.version_full);
        return result;
    }
    fn record(self: *ManagedConfigCommitment, kind: u8, name: []const u8, value: []const u8) void {
        self.hash.update(&.{kind});
        var lengths: [16]u8 = undefined;
        std.mem.writeInt(u64, lengths[0..8], name.len, .little);
        std.mem.writeInt(u64, lengths[8..16], value.len, .little);
        self.hash.update(&lengths);
        self.hash.update(name);
        self.hash.update(value);
    }
    fn finish(self: *ManagedConfigCommitment) native_service.Digest {
        var result: native_service.Digest = undefined;
        self.hash.final(&result);
        return result;
    }
};

fn parseWindowsCandidateNumber(comptime T: type, text: []const u8) error{InvalidWindowsCandidate}!T {
    if (text.len == 0 or (text.len > 1 and text[0] == '0')) return error.InvalidWindowsCandidate;
    for (text) |digit| if (digit < '0' or digit > '9') return error.InvalidWindowsCandidate;
    const value = std.fmt.parseInt(T, text, 10) catch return error.InvalidWindowsCandidate;
    if (value == 0) return error.InvalidWindowsCandidate;
    return value;
}

test "Windows Helix candidate numeric arguments are canonical decimal" {
    try std.testing.expectEqual(@as(usize, 123), try parseWindowsCandidateNumber(usize, "123"));
    try std.testing.expectError(error.InvalidWindowsCandidate, parseWindowsCandidateNumber(usize, "0"));
    try std.testing.expectError(error.InvalidWindowsCandidate, parseWindowsCandidateNumber(usize, "01"));
    try std.testing.expectError(error.InvalidWindowsCandidate, parseWindowsCandidateNumber(usize, "+1"));
    try std.testing.expectError(error.InvalidWindowsCandidate, parseWindowsCandidateNumber(usize, "1x"));
    try std.testing.expectError(error.InvalidWindowsCandidate, parseWindowsCandidateNumber(u32, "4294967296"));
}

const WindowsInheritedRows = struct {
    allocator: std.mem.Allocator,
    listeners: []onyx_server.daemon.server.ListenerDescriptor,
    state_fds: []i32,

    fn init(allocator: std.mem.Allocator, rows: []const windows_bootstrap.ReceivedRow) !WindowsInheritedRows {
        var listener_count: usize = 0;
        for (rows) |row| switch (row.role) {
            .client, .s2s_state => {},
            .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => listener_count += 1,
        };
        const listeners = try allocator.alloc(onyx_server.daemon.server.ListenerDescriptor, listener_count);
        errdefer allocator.free(listeners);
        const state_fds = try allocator.alloc(i32, rows.len - listener_count);
        errdefer allocator.free(state_fds);
        var li: usize = 0;
        var si: usize = 0;
        for (rows) |row| switch (row.role) {
            .client, .s2s_state => {
                state_fds[si] = row.canonical;
                si += 1;
            },
            .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => {
                if (row.shard > std.math.maxInt(u12)) return error.InvalidWindowsCandidate;
                listeners[li] = .{
                    .fd = row.canonical,
                    .shard = @intCast(row.shard),
                    .family = std.enums.fromInt(onyx_server.daemon.server.ListenerFamily, row.family) orelse return error.InvalidWindowsCandidate,
                    .kind = switch (row.role) {
                        .plain_listener => .plain,
                        .tls_listener => .tls,
                        .websocket_listener => .ws,
                        .s2s_listener => .s2s,
                        else => unreachable,
                    },
                };
                li += 1;
            },
        };
        if (li == 0 or li != listeners.len or si != state_fds.len) return error.InvalidWindowsCandidate;
        return .{ .allocator = allocator, .listeners = listeners, .state_fds = state_fds };
    }

    fn deinit(self: *WindowsInheritedRows) void {
        self.allocator.free(self.listeners);
        self.allocator.free(self.state_fds);
    }
};

const WindowsCandidateBarrier = struct {
    child: *windows_process.Incoming,
    transfer: *windows_bootstrap.Incoming,
    deadline: i64,

    fn asServerBarrier(self: *WindowsCandidateBarrier) onyx_server.daemon.server.NativeAdoptBarrier {
        return .{
            .ctx = self,
            .readyAndAwaitCommit = readyAndAwaitCommit,
            .claimInertListenerSocket = claimSocket,
            .claimInertStateSocket = claimSocket,
        };
    }

    fn claimSocket(ctx: *anyopaque, canonical: i32) anyerror!void {
        const self: *WindowsCandidateBarrier = @ptrCast(@alignCast(ctx));
        try self.transfer.claimStagedForServer(canonical);
    }

    // Server.adoptInheritedSessions invokes this barrier only after its strict
    // capsule decode, relation checks, and physical connection join. The
    // driver additionally requires every imported socket to be claimed.
    fn verifyServerStage(ctx: ?*anyopaque, transfer: *windows_bootstrap.Incoming) anyerror!void {
        const self: *WindowsCandidateBarrier = @ptrCast(@alignCast(ctx orelse return error.InvalidWindowsCandidate));
        if (self.transfer != transfer) return error.InvalidWindowsCandidate;
    }

    fn readyAndAwaitCommit(ctx: *anyopaque) anyerror!void {
        const self: *WindowsCandidateBarrier = @ptrCast(@alignCast(ctx));
        const ticket = windows_driver.childAnswerReady(self.child, self.transfer, .{
            .context = self,
            .run = verifyServerStage,
        }, self.deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix READY validation failed ({s})\n", .{@errorName(err)});
            windows_driver.candidateAbortNow();
        };
        windows_driver.childAwaitCommit(self.child, self.transfer, ticket, self.deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix COMMIT release failed ({s})\n", .{@errorName(err)});
            windows_driver.candidateAbortNow();
        };
    }
};

fn recordWindowsTlsMaterial(proof: *windows_config_proof.EffectiveBuilder, loaded: *const onyx_server.daemon.tls_certs.Loaded) !void {
    try proof.record(.tls, "key-kind", &.{@intFromEnum(loaded.key_kind)});
    try proof.recordCount(.tls, "certificate-count", loaded.cert_chain.len);
    for (loaded.cert_chain) |der| try proof.record(.tls, "certificate-der", der);
    switch (loaded.key_kind) {
        .ed25519 => {
            const key = loaded.signing_key orelse return error.InvalidWindowsTlsMaterial;
            var secret = key.secret_key.toBytes();
            defer std.crypto.secureZero(u8, &secret);
            try proof.record(.tls, "ed25519-private", &secret);
        },
        .ecdsa_p256 => {
            const key = loaded.ecdsa_p256_signing_key orelse return error.InvalidWindowsTlsMaterial;
            var secret = key.secret_key.toBytes();
            defer std.crypto.secureZero(u8, &secret);
            try proof.record(.tls, "p256-private", &secret);
        },
        .rsa => try proof.record(.tls, "rsa-private-der", loaded.rsa_key_storage orelse return error.InvalidWindowsTlsMaterial),
    }
}

/// Static inputs stay byte-identical across an ACME renewal. The actual
/// serving default/TLS 1.2 generations are carried by mandatory HXTM and
/// checked under the authenticated World cut before READY.
fn windowsStaticEffectiveConfigDigest(
    source_digest: windows_config_proof.Digest,
    tls_default_present: bool,
    tls_sni: []const onyx_server.daemon.tls_certs.Loaded,
    ech: []const onyx_server.crypto.tls_server.EchKey,
    vapid: ?*const onyx_server.daemon.webpush.Vapid,
    oauth_jwks: ?[]const u8,
    node: ?*const onyx_server.daemon.node_identity.NodeIdentity,
    cloak: ?onyx_server.proto.cloak.SecretKey,
    previous_cloak: ?onyx_server.proto.cloak.SecretKey,
    geo_city: ?[]const u8,
    geo_asn: ?[]const u8,
) !windows_config_proof.Digest {
    var proof = windows_config_proof.EffectiveBuilder.init(source_digest);
    defer proof.deinit();
    try proof.recordCount(.tls, "default-present", @intFromBool(tls_default_present));
    try proof.recordCount(.tls, "sni-count", tls_sni.len);
    for (tls_sni, 0..) |*loaded, index| {
        try proof.recordCount(.tls, "sni-index", index);
        try recordWindowsTlsMaterial(&proof, loaded);
    }
    try proof.recordCount(.ech, "ech-count", ech.len);
    for (ech) |key| {
        try proof.record(.ech, "config-list", key.config);
        try proof.record(.ech, "recipient-private", &key.private_key);
    }
    try proof.recordCount(.vapid, "present", @intFromBool(vapid != null));
    if (vapid) |key| {
        var secret = key.key_pair.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &secret);
        try proof.record(.vapid, "p256-private", &secret);
        const public = key.key_pair.public_key.toUncompressedSec1();
        try proof.record(.vapid, "p256-public", &public);
    }
    try proof.recordCount(.oauth, "jwks-present", @intFromBool(oauth_jwks != null));
    if (oauth_jwks) |bytes| try proof.record(.oauth, "jwks", bytes);
    try proof.recordCount(.node, "present", @intFromBool(node != null));
    if (node) |identity| {
        try proof.record(.node, "realm", &identity.realm);
        try proof.record(.node, "node-id", &identity.node_id);
        try proof.record(.node, "sign-public", &identity.sign_kp.public_key);
        try proof.record(.node, "kem-public", &identity.kem_kp.public_key);
    }
    try proof.recordCount(.cloak, "present", @intFromBool(cloak != null));
    if (cloak) |key| try proof.record(.cloak, "current", &key.bytes);
    try proof.recordCount(.cloak, "previous-present", @intFromBool(previous_cloak != null));
    if (previous_cloak) |key| try proof.record(.cloak, "previous", &key.bytes);
    try windows_config_proof.recordGeoipMaterial(&proof, geo_city, geo_asn);
    return proof.finish();
}

test "Windows static Helix proof binds TLS presence and SNI material" {
    const source: windows_config_proof.Digest = @splat(0x37);
    const base = try windowsStaticEffectiveConfigDigest(source, true, &.{}, &.{}, null, null, null, null, null, null, null);
    const absent = try windowsStaticEffectiveConfigDigest(source, false, &.{}, &.{}, null, null, null, null, null, null, null);
    try std.testing.expect(!std.crypto.timing_safe.eql(windows_config_proof.Digest, base, absent));

    const key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x52));
    const chain = [_][]const u8{"sni-leaf"};
    const sni = [_]onyx_server.daemon.tls_certs.Loaded{.{
        .cert_chain = @constCast(&chain),
        .key_kind = .ed25519,
        .signing_key = key,
    }};
    const with_sni = try windowsStaticEffectiveConfigDigest(source, true, &sni, &.{}, null, null, null, null, null, null, null);
    try std.testing.expect(!std.crypto.timing_safe.eql(windows_config_proof.Digest, base, with_sni));
}

/// Shared context for the config-string resolver. Both `env:NAME` and
/// `@file:path` indirection run through a single `?*anyopaque` ctx, so it
/// carries everything either lookup needs: the process environment map and an
/// `Io` handle for reading `@file:` payloads off disk.
const ResolverCtx = struct {
    environ_map: *std.process.Environ.Map,
    io: std.Io,
    path_allocator: std.mem.Allocator,
    file_paths: std.ArrayList([]u8) = .empty,
    record_paths: bool = true,
    managed_commitment: ?*ManagedConfigCommitment = null,
    windows_helix_proof: ?*windows_config_proof.Builder = null,

    fn deinit(self: *ResolverCtx) void {
        for (self.file_paths.items) |path| self.path_allocator.free(path);
        self.file_paths.deinit(self.path_allocator);
    }
};

/// `env:NAME` resolver for the config parser — reads the process environment map
/// (Zig 0.16 delivers the environment via `std.process.Init.environ_map`, which
/// we thread through the resolver `ctx`). Returns an owned dupe of the value.
fn envLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.EnvironmentVariableNotFound));
    const value = rc.environ_map.get(name) orelse return error.EnvironmentVariableNotFound;
    if (rc.managed_commitment) |commitment| commitment.record(2, name, value);
    if (rc.windows_helix_proof) |proof| try proof.recordEnvironment(name, value);
    return allocator.dupe(u8, value);
}

/// `@file:path` resolver for the config parser — loads the file's contents
/// (relative to the daemon cwd) as the string value, so secrets and large text
/// blobs (e.g. `[motd] text = "@file:etc/motd.example.txt"`) can live on disk.
fn fileLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.FileNotFound));
    if (comptime builtin.os.tag == .openbsd) {
        if (rc.record_paths) {
            const owned = try rc.path_allocator.dupe(u8, path);
            errdefer rc.path_allocator.free(owned);
            try rc.file_paths.append(rc.path_allocator, owned);
        }
    }
    const value = try std.Io.Dir.cwd().readFileAlloc(rc.io, path, allocator, .limited(1 << 20));
    errdefer allocator.free(value);
    if (rc.managed_commitment) |commitment| commitment.record(3, path, value);
    if (rc.windows_helix_proof) |proof| try proof.recordFile(path, value);
    return value;
}

fn validateTlsChain(chain: []const []const u8) anyerror!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    const now_unix: i64 = @divTrunc(onyx_server.substrate.platform.realtimeMillis(), 1000);
    // The daemon's OWN chain: validate the leaf only (a CA-issued server chain
    // ships leaf + intermediates, never a self-signed root, and its intermediate
    // may use a key type the server does not sign with). See validateServerChainAt.
    try onyx_server.crypto.x509_verify.validateServerChainAt(chain, now_unix);
}

/// Check native Windows companion inputs during --check-config and before the
/// live server binds.
fn validateWindowsCompanionInputs(allocator: std.mem.Allocator, io: std.Io, cfg: onyx_server.daemon.config_format.Config, geo_out: ?*WindowsGeoOwned) !void {
    if (comptime builtin.os.tag != .windows) return;
    try onyx_server.daemon.config_boot.validateWindowsStatsOutputDirs(io, cfg.stats);
    if (cfg.node.secret_key) |secret| {
        var identity = try onyx_server.daemon.node_identity.fromConfig(secret, cfg.mesh.realm);
        defer identity.deinit();
    }
    if (cfg.tls.enabled) {
        var loaded = try onyx_server.daemon.tls_certs.loadOrBootstrap(allocator, io, .{
            .enabled = true,
            .cert_path = cfg.tls.cert_path,
            .key_path = cfg.tls.key_path,
            .dns_name = cfg.tls.dns_name,
        });
        defer loaded.deinit(allocator);
        try validateTlsChain(loaded.cert_chain);
        try validateTlsIdentity(loaded.cert_chain, loaded.signing_key, loaded.ecdsa_p256_signing_key, loaded.rsa_signing_key);

        var sni_loaded: std.ArrayList(onyx_server.daemon.tls_certs.Loaded) = .empty;
        defer {
            for (sni_loaded.items) |*entry| entry.deinit(allocator);
            sni_loaded.deinit(allocator);
        }
        const sni_certs = try onyx_server.daemon.tls_sni_load.buildSniCerts(
            allocator,
            io,
            cfg.tls.sni,
            cfg.tls.dns_name,
            &sni_loaded,
            validateTlsChain,
            onyx_server.daemon.tls_sni_load.default_loader,
        );
        defer allocator.free(sni_certs);
        for (sni_certs) |cert| try validateTlsIdentity(cert.cert_chain, cert.signing_key, cert.ecdsa_p256_signing_key, cert.rsa_signing_key);

        if (cfg.tls.ech_keys.len != 0) {
            var ech = try loadTlsEchKeys(allocator, io, cfg.tls.ech_keys);
            defer ech.deinit(allocator);
            var probe = try onyx_server.crypto.tls_server.Server.init(allocator, .{
                .cert_chain = loaded.cert_chain,
                .signing_key = loaded.signing_key,
                .ecdsa_p256_signing_key = loaded.ecdsa_p256_signing_key,
                .rsa_signing_key = loaded.rsa_signing_key,
                .sni_certs = sni_certs,
                .ech_keys = ech.keys,
            });
            probe.deinit();
        }
    }
    if (cfg.sts.enabled) {
        if (!cfg.tls.enabled) return error.StsTlsListenerRequired;
        var value_buf: [onyx_server.proto.sts.MAX_VALUE_LEN]u8 = undefined;
        _ = try onyx_server.proto.sts_policy.writeCapValue(.{
            .duration_seconds = cfg.sts.duration,
            .port = cfg.sts.port,
            .preload = cfg.sts.preload,
        }, .combined, &value_buf);
    }
    if (cfg.sasl.enabled and cfg.sasl.oauth_hmac_key == null) {
        if (cfg.sasl.oauth_jwks_file) |path| {
            const jwks = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
            defer allocator.free(jwks);
            var key = try onyx_server.daemon.oauth_jwt.OwnedKey.fromJwks(allocator, jwks);
            defer key.deinit();
        } else if (cfg.sasl.oauth_pubkey) |pubkey| {
            var key = try onyx_server.daemon.oauth_jwt.OwnedKey.fromPubkey(allocator, pubkey);
            defer key.deinit();
        }
    }
    if (cfg.wasm.plugin_dir) |path| {
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        dir.close(io);
    }
    if (cfg.acme.enabled) {
        try onyx_server.daemon.os_runtime.requirePrivateDirectoryWindows(io, std.Io.Dir.cwd(), cfg.tls.key_path orelse return error.AcmeKeyPathRequired);
    }
    if (cfg.acme.enabled or cfg.ocsp.enabled or cfg.webpush.enabled) {
        const bundle = try std.Io.Dir.cwd().readFileAlloc(io, cfg.acme.ca_bundle_path, allocator, .limited(@intCast(cfg.acme.ca_bundle_max_bytes)));
        defer allocator.free(bundle);
        var anchors = try OwnedTrustAnchors.load(allocator, bundle);
        defer anchors.deinit();
        if (anchors.items().len == 0) return error.NoTrustAnchors;
    }
    if (cfg.mail.enabled) if (cfg.mail.trust_store_path) |path| {
        const bundle = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
        defer allocator.free(bundle);
        var anchors = try OwnedTrustAnchors.load(allocator, bundle);
        defer anchors.deinit();
        if (anchors.items().len == 0) return error.NoTrustAnchors;
    };
    if (cfg.geo.enabled) if (cfg.geo.news_cache_dir) |path| {
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        dir.close(io);
    };
    var geo: WindowsGeoOwned = .{};
    defer geo.deinit(allocator);
    if (cfg.geoip.database.len != 0)
        geo.city = try WindowsGeoDatabase.load(allocator, io, cfg.geoip.database);
    if (cfg.geoip.asn_database.len != 0)
        geo.asn = try WindowsGeoDatabase.load(allocator, io, cfg.geoip.asn_database);
    if (geo_out) |out| {
        if (out.city != null or out.asn != null) return error.InvalidWindowsGeoOwner;
        out.* = geo;
        geo = .{};
    }
}

/// Preflight uses the same parsed boot projection without creating the node
/// keyfile, opening a WAL, binding a socket, or reparsing resolved config data.
fn validateManagedBootPlan(allocator: std.mem.Allocator, io: std.Io, loaded: *const onyx_server.daemon.config_boot.Loaded, config_path: []const u8) !void {
    const boot = onyx_server.daemon.config_boot;
    if (boot.portableTransportError(builtin.os.tag, loaded.parsed)) |reason| {
        std.debug.print("onyx-server: unsupported on {s}: {s}\n", .{ @tagName(builtin.os.tag), reason });
        return error.UnsupportedManagedTransport;
    }
    if (loaded.parsed.meshCloakSecretMissing()) return error.MissingMeshCloakSecret;
    if (boot.configCheckError(loaded.io, loaded.tls.ktls) != null) return error.InvalidManagedIoPolicy;
    if (boot.unsecuredMeshPeerError(loaded.parsed.mesh.connect.len, loaded.parsed.mesh.require_secured) != null) return error.UnsecuredManagedMesh;
    if (loaded.parsed.node.secret_key) |secret| {
        var identity = try onyx_server.daemon.node_identity.fromConfig(secret, loaded.parsed.mesh.realm);
        defer identity.deinit();
    }
    if (loaded.parsed.mesh.relay_v2_activation_epoch != 0 and loaded.parsed.node.secret_key == null) {
        const key_path = try onyx_server.daemon.node_keyfile.derivePath(allocator, config_path);
        defer allocator.free(key_path);
        try onyx_server.daemon.node_keyfile.validateExistingPublicKey(allocator, io, std.Io.Dir.cwd(), key_path, loaded.parsed.mesh.realm, loaded.parsed.node.public_key orelse return error.MissingNodePublicKey);
    }
    if (loaded.ocg2.enabled) {
        if (!boot.ocg2RuntimeModeSupported(loaded.ocg2.mode)) return error.UnsupportedManagedOcg2Mode;
        var identity = if (loaded.parsed.node.secret_key) |secret|
            try onyx_server.daemon.node_identity.fromConfig(secret, loaded.parsed.mesh.realm)
        else identity_blk: {
            const key_path = try onyx_server.daemon.node_keyfile.derivePath(allocator, config_path);
            defer allocator.free(key_path);
            var seed = try onyx_server.daemon.node_keyfile.loadExisting(allocator, io, std.Io.Dir.cwd(), key_path);
            defer std.crypto.secureZero(u8, &seed);
            break :identity_blk try onyx_server.daemon.node_identity.fromSeed(seed, loaded.parsed.mesh.realm);
        };
        defer identity.deinit();
        _ = try boot.validateOcg2LocalIdentity(loaded.ocg2, &identity);
    }
}

test "managed boot: config commitment frames actual source and resolved values" {
    var first = ManagedConfigCommitment.init();
    first.record(1, "/etc/onyx-server.toml", "key = env:KEY");
    first.record(2, "KEY", "abc");
    var equal = ManagedConfigCommitment.init();
    equal.record(1, "/etc/onyx-server.toml", "key = env:KEY");
    equal.record(2, "KEY", "abc");
    try std.testing.expectEqualSlices(u8, &first.finish(), &equal.finish());
    var changed = ManagedConfigCommitment.init();
    changed.record(1, "/etc/onyx-server.toml", "key = env:KEY");
    changed.record(2, "KEY", "abd");
    try std.testing.expect(!std.mem.eql(u8, &first.finish(), &changed.finish()));
    var split = ManagedConfigCommitment.init();
    split.record(1, "a", "bc");
    var joined = ManagedConfigCommitment.init();
    joined.record(1, "ab", "c");
    try std.testing.expect(!std.mem.eql(u8, &split.finish(), &joined.finish()));
}

test "managed boot: leaf identity refuses another same-family signing key" {
    const ed = std.crypto.sign.Ed25519;
    const pair = try ed.KeyPair.generateDeterministic(@splat(0x31));
    const other = try ed.KeyPair.generateDeterministic(@splat(0x32));
    var der: [4096]u8 = undefined;
    const leaf = try onyx_server.proto.x509_selfsign.buildSelfSigned(&der, .{ .common_name = "managed.test", .not_before = 1700000000, .not_after = 1900000000, .serial = &.{1}, .key_pair = pair });
    try validateTlsIdentity(&.{leaf}, pair, null, null);
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{leaf}, other, null, null));
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{leaf}, null, null, null));
    const ec = onyx_server.crypto.ecdsa_p256.KeyPair.generate(std.testing.io);
    const ec_other = onyx_server.crypto.ecdsa_p256.KeyPair.generate(std.testing.io);
    const ec_leaf = try onyx_server.proto.x509_selfsign.buildSelfSignedEcdsaP256(&der, .{ .common_name = "managed.test", .not_before = 1700000000, .not_after = 1900000000, .serial = &.{2}, .key_pair = ec });
    try validateTlsIdentity(&.{ec_leaf}, null, ec, null);
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{ec_leaf}, null, ec_other, null));
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{ec_leaf}, pair, ec, null));
}

test "managed boot: parsed preflight refuses mesh policy without creating state" {
    var loaded = try onyx_server.daemon.config_boot.loadFromText(std.testing.allocator, "[node]\nid=1\n[listen]\nirc=6680\ns2s=0\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(std.testing.allocator);
    try validateManagedBootPlan(std.testing.allocator, std.testing.io, &loaded, "/not-created/onyx-server.toml");
    loaded.parsed.listen.s2s = 7000;
    const mesh_error = if (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)
        error.MissingMeshCloakSecret
    else
        error.UnsupportedManagedTransport;
    try std.testing.expectError(mesh_error, validateManagedBootPlan(std.testing.allocator, std.testing.io, &loaded, "/not-created/onyx-server.toml"));
    loaded.parsed.listen.s2s = 0;
    loaded.tls.ktls = .txrx;
    try std.testing.expectError(error.InvalidManagedIoPolicy, validateManagedBootPlan(std.testing.allocator, std.testing.io, &loaded, "/not-created/onyx-server.toml"));
}

test "managed boot: configured invalid node key refuses before cold mutation" {
    var loaded = try onyx_server.daemon.config_boot.loadFromText(std.testing.allocator, "[node]\nid=1\nsecret_key=\"bad\"\n[listen]\nirc=6680\ns2s=0\n", .{ .port = 6680 }, .{});
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectError(error.BadSeed, validateManagedBootPlan(std.testing.allocator, std.testing.io, &loaded, "/not-created/onyx-server.toml"));
}

/// Key family equality alone cannot prove a configured private key belongs to
/// the loaded leaf. Compare the parsed public material before granting launch.
fn validateTlsIdentity(
    chain: []const []const u8,
    signing_key: ?std.crypto.sign.Ed25519.KeyPair,
    ecdsa_key: ?onyx_server.crypto.ecdsa_p256.KeyPair,
    rsa_key: ?onyx_server.crypto.rsa_sign.PrivateKey,
) !void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    const leaf = try onyx_server.crypto.x509.parse(chain[0]);
    const key = try onyx_server.crypto.x509.extractPublicKey(leaf.spki_der);
    switch (key) {
        .ed25519 => |public| {
            const private = signing_key orelse return error.TlsKeyMismatch;
            if (ecdsa_key != null or rsa_key != null or !std.mem.eql(u8, public, &private.public_key.toBytes())) return error.TlsKeyMismatch;
        },
        .ecdsa_p256 => |public| {
            const private = ecdsa_key orelse return error.TlsKeyMismatch;
            if (signing_key != null or rsa_key != null or !std.mem.eql(u8, public, &private.public_key.toUncompressedSec1())) return error.TlsKeyMismatch;
        },
        .rsa => |public| {
            const private = rsa_key orelse return error.TlsKeyMismatch;
            if (signing_key != null or ecdsa_key != null or !std.mem.eql(u8, public.modulus, private.n) or !std.mem.eql(u8, public.exponent, private.e)) return error.TlsKeyMismatch;
        },
    }
}

const LoadedEchKeys = struct {
    configs: [][]u8 = &.{},
    keys: []onyx_server.crypto.tls_server.EchKey = &.{},

    fn deinit(self: *LoadedEchKeys, allocator: std.mem.Allocator) void {
        for (self.keys) |*key| std.crypto.secureZero(u8, &key.private_key);
        allocator.free(self.keys);
        for (self.configs) |bytes| allocator.free(bytes);
        allocator.free(self.configs);
        self.* = .{};
    }
};

fn loadTlsEchKeys(
    allocator: std.mem.Allocator,
    io: std.Io,
    defs: []const onyx_server.daemon.config_format.Config.EchKeyDef,
) !LoadedEchKeys {
    var configs: std.ArrayList([]u8) = .empty;
    errdefer {
        for (configs.items) |bytes| allocator.free(bytes);
        configs.deinit(allocator);
    }
    var keys: std.ArrayList(onyx_server.crypto.tls_server.EchKey) = .empty;
    errdefer {
        for (keys.items) |*key| std.crypto.secureZero(u8, &key.private_key);
        keys.deinit(allocator);
    }

    for (defs) |def| {
        const config = try std.Io.Dir.cwd().readFileAlloc(io, def.config_path, allocator, .limited(64 * 1024));
        var config_unlisted = true;
        errdefer if (config_unlisted) allocator.free(config);
        try configs.append(allocator, config);
        config_unlisted = false;
        try keys.append(allocator, .{ .config = config, .private_key = def.private_key });
    }

    const key_slice = try keys.toOwnedSlice(allocator);
    errdefer {
        for (key_slice) |*key| std.crypto.secureZero(u8, &key.private_key);
        allocator.free(key_slice);
    }
    const config_slice = try configs.toOwnedSlice(allocator);
    return .{
        .configs = config_slice,
        .keys = key_slice,
    };
}

/// Services → live-world bridge: a channel registration marks the live channel
/// REGISTERED (+r), materializing it if empty so the reservation persists.
fn svcCreateChannel(ctx: *anyopaque, channel: []const u8) onyx_server.daemon.services.ServiceError!void {
    const srv: *onyx_server.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, true);
}

/// Services → live-world bridge: dropping a registration clears +r so the
/// channel reverts to ephemeral and is reclaimed once empty.
fn svcDropChannel(ctx: *anyopaque, channel: []const u8) onyx_server.daemon.services.ServiceError!void {
    const srv: *onyx_server.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, false);
}

fn daemonPanic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .windows or builtin.os.tag == .openbsd)
        onyx_server.daemon.server.flushFlightRecorderOnPanic(msg);
    std.debug.defaultPanic(msg, first_trace_addr);
}

pub const panic = std.debug.FullPanic(daemonPanic);

fn installOpenBsdSandbox(
    allocator: std.mem.Allocator,
    io: std.Io,
    runtime: onyx_server.daemon.server.Config,
    parsed: ?*const onyx_server.daemon.config_format.Config,
    resolver_ctx: *ResolverCtx,
    managed_context: ?*const native_service.Context,
) !void {
    var plan = onyx_server.daemon.openbsd_sandbox.Plan{ .allocator = allocator, .io = io };
    defer plan.deinit();
    try plan.addDirectory("/etc", "r");
    try plan.addDirectory("/usr", "rx");
    try plan.addDirectory("/tmp", "rwc");
    try plan.addDirectory("/dev", "r");
    if (managed_context != null) try plan.addNativeServiceNamespace();
    try plan.addExecutable(runtime.exe_path orelse return error.MissingExecutablePath);
    if (runtime.config_path) |path| try plan.addFile(path, true);
    for (resolver_ctx.file_paths.items) |path| try plan.addFile(path, false);
    if (parsed) |cfg| {
        if (cfg.sasl.account_db) |path| try plan.addFile(path, true);
        if (cfg.sasl.oauth_jwks_file) |path| try plan.addFile(path, false);
        if (cfg.webhook.store_path) |path| try plan.addFile(path, true);
        if (cfg.oper.grants_path) |path| try plan.addFile(path, true);
        if (cfg.oper.event_history_path) |path| try plan.addFile(path, true);
        if (cfg.trace.file) |path| try plan.addFile(path, true);
        if (cfg.weather.source) |path| try plan.addFile(path, false);
        if (cfg.news.source) |path| try plan.addFile(path, false);
        if (cfg.geo.news_cache_dir) |path| try plan.addDirectory(path, "r");
        if (cfg.wasm.plugin_dir) |path| try plan.addDirectory(path, "r");
        try plan.addDirectory(cfg.stats.dir, "rwc");
        try plan.addDirectory(cfg.stats.channel_dir, "rwc");
        try plan.addDirectory(cfg.backup.dir, "rwc");
        if (cfg.tls.cert_path) |path| try plan.addFile(path, cfg.acme.enabled);
        if (cfg.tls.key_path) |path| try plan.addFile(path, cfg.acme.enabled);
        for (cfg.tls.sni) |cert| {
            try plan.addFile(cert.cert_path, false);
            try plan.addFile(cert.key_path, false);
        }
        for (cfg.tls.ech_keys) |key| try plan.addFile(key.config_path, false);
        try plan.addFile(cfg.geoip.database, false);
        try plan.addFile(cfg.geoip.asn_database, false);
        if (cfg.mail.trust_store_path) |path| try plan.addFile(path, false);
        if (cfg.acme.enabled or cfg.ocsp.enabled or cfg.webpush.enabled)
            try plan.addFile(cfg.acme.ca_bundle_path, false);
        if (cfg.webpush.enabled) try plan.addFile(cfg.webpush.vapid_key_path, true);
    }
    try plan.install();
    resolver_ctx.record_paths = false;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Resolver context for `env:`/`@file:` config indirection. Lives on `main`'s
    // frame for the whole process, so the resolver stored on the live config
    // (used by REHASH) never dangles.
    var resolver_ctx = ResolverCtx{ .environ_map = init.environ_map, .io = init.io, .path_allocator = allocator };
    defer resolver_ctx.deinit();

    // Default config (6680; 6667/6697 belong to the local eshmaki server). A
    // config file path may be passed as argv[1]: present values override the
    // defaults; a missing/invalid file keeps defaults (boot never fails on it).
    var srv_cfg = onyx_server.daemon.server.Config{ .port = 6680 };
    var native_incoming: ?onyx_server.daemon.helix.native_bootstrap.Incoming = null;
    defer if (native_incoming) |*incoming| incoming.deinit();
    var windows_child: ?windows_process.Incoming = null;
    defer if (windows_child) |*child| child.deinit();
    var windows_transfer: ?windows_bootstrap.Incoming = null;
    defer if (windows_transfer) |*transfer| transfer.deinit();
    // A WebTransport candidate borrows the source's authenticated serving
    // certificate before READY. Keep this detached copy until its UDP owner
    // has joined and been destroyed on process exit.
    var windows_wt_tls_material: ?windows_tls_material.Owned = null;
    defer if (windows_wt_tls_material) |*material| material.deinit();
    var windows_wt_active_body: ?onyx_server.daemon.helix.native_windows_active_webtransport_snapshot.Body = null;
    defer if (windows_wt_active_body) |*body| body.deinit(allocator);
    var windows_active_media_graph: ?onyx_server.daemon.helix.media_graph_checkpoint.Snapshot = null;
    defer if (windows_active_media_graph) |*body| body.deinit();
    var windows_active_media_native: ?onyx_server.daemon.native_media_transport.PhysicalSnapshot = null;
    defer if (windows_active_media_native) |*body| body.deinit();
    var windows_active_media_webrtc: ?onyx_server.daemon.media_plane.PhysicalSnapshot = null;
    defer if (windows_active_media_webrtc) |*body| body.deinit();
    var windows_deadline: i64 = 0;
    var windows_rows: ?WindowsInheritedRows = null;
    defer if (windows_rows) |*rows| rows.deinit();
    var windows_barrier: ?WindowsCandidateBarrier = null;
    var windows_source_digest_boot: ?windows_config_proof.Digest = null;
    var windows_geo: WindowsGeoOwned = .{};
    defer windows_geo.deinit(allocator);
    var windows_runtime_driver = windows_runtime.Driver{ .allocator = allocator };
    // Outer lifetime custody survives Server and every companion cleanup. The
    // Prelude admits only a root-created channel; it cannot publish readiness.
    var managed_prelude: ?*service_helper.ManagedPrelude = null;
    defer if (comptime builtin.os.tag == .openbsd) {
        if (managed_prelude) |prelude| prelude.deinit();
    };
    var managed_spec: ?service_helper.ServiceSpec = null;
    var managed_incoming: ?native_service.Incoming = null;
    defer if (managed_incoming) |*incoming| incoming.deinit();
    var managed_commitment = ManagedConfigCommitment.init();
    var managed_config_digest: ?native_service.Digest = null;
    var native_driver = onyx_server.daemon.helix.native_bootstrap.Driver{ .allocator = allocator, .config_path = null, .environ = init.minimal.environ };
    var native_executable: ?[:0]u8 = null;
    defer if (native_executable) |path| allocator.free(path);
    var held: ?onyx_server.daemon.config_boot.Loaded = null;
    defer if (held) |*h| h.deinit(allocator);
    // Backing storage for the inherited per-shard listener fds (multi-shard
    // Helix handoff). Lives on main's frame so the slice stored on the config
    // stays valid for the whole boot.
    var inherited_listeners: [onyx_server.daemon.helix.live.max_inherited_listeners]i32 = undefined;
    // Authoritative version-independent manifest of every client/S2S fd carried
    // in the state arena. This must outlive config parsing and server adoption.
    var inherited_state_fds: [onyx_server.daemon.helix.live.max_inherited_state_fds]i32 = undefined;
    if (comptime builtin.os.tag != .linux) {
        _ = &inherited_listeners;
        _ = &inherited_state_fds;
    }

    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit(); // no-op on POSIX, frees the arg buffer on Windows/WASI
    // argv[0] is the launch path. UPGRADE re-execs THIS path (not /proc/self/exe,
    // which would re-run the old in-memory image), so a swapped-in new binary is
    // what actually boots across a hot upgrade.
    if (args.next()) |exe| srv_cfg.exe_path = exe;
    if (comptime builtin.os.tag == .openbsd or builtin.os.tag == .windows) {
        if (comptime builtin.os.tag == .openbsd) try onyx_server.daemon.os_runtime.raiseOpenBsdFdAllowance();
        native_executable = try std.process.executablePathAlloc(init.io, allocator);
        srv_cfg.exe_path = native_executable.?;
    }
    var config_path_arg: ?[]const u8 = null;
    const first_arg = args.next();
    if (first_arg == null or !std.mem.eql(u8, first_arg.?, "doctor")) {
        std.debug.print(
            \\
            \\  Onyx Server {s}
            \\  Zig-native mesh IRC daemon — Undertow + Mooring mesh
            \\
            \\
        , .{onyx_server.version_full});
    }
    if (first_arg) |first| {
        // Private, side-effect-free Helix compatibility handshake. The running
        // predecessor executes the exact already-open target image with this
        // flag and refuses a hot handoff unless the complete token matches.
        // This branch must stay ahead of all config, socket, and daemon setup.
        if (std.mem.eql(u8, first, service_helper.activation_arg)) {
            if (comptime builtin.os.tag == .openbsd) {
                if (!std.mem.eql(u8, args.next() orelse return error.InvalidManagedActivation, service_helper.managed_arg)) return error.InvalidManagedActivation;
                const fd_text = args.next() orelse return error.InvalidManagedActivation;
                if (!std.mem.eql(u8, fd_text, "3") or args.next() != null) return error.InvalidManagedActivation;
                managed_prelude = service_helper.receiveManaged(allocator, init.io, 3, try std.math.add(i64, onyx_server.substrate.platform.monotonicMillis(), 30_000)) catch |err| {
                    onyx_server.daemon.os_runtime.close(3);
                    return err;
                };
                managed_spec = managed_prelude.?.spec();
                if (!std.mem.eql(u8, srv_cfg.exe_path orelse return error.MissingExecutablePath, managed_spec.?.executable.bytes())) return error.ManagedExecutableMismatch;
                config_path_arg = managed_spec.?.config.bytes();
            } else return error.Unsupported;
        } else if (std.mem.eql(u8, first, onyx_server.daemon.helix.native_process.candidate_arg)) {
            if (comptime builtin.os.tag == .openbsd) {
                const fd = try std.fmt.parseInt(i32, args.next() orelse return error.InvalidNativeCandidate, 10);
                const parent_pid = try std.fmt.parseInt(i32, args.next() orelse return error.InvalidNativeCandidate, 10);
                const generation = try std.fmt.parseInt(u64, args.next() orelse return error.InvalidNativeCandidate, 10);
                const id_text = args.next() orelse return error.InvalidNativeCandidate;
                var identity: onyx_server.daemon.helix.native_exchange.Identity = .{ .generation = generation, .upgrade_id = undefined };
                if (id_text.len != 32) return error.InvalidNativeCandidate;
                _ = try std.fmt.hexToBytes(&identity.upgrade_id, id_text);
                native_incoming = try onyx_server.daemon.helix.native_bootstrap.Incoming.receive(allocator, fd, parent_pid, identity);
                if (args.next()) |path| if (path.len != 0) {
                    config_path_arg = path;
                };
            } else return error.InvalidNativeCandidate;
        } else if (std.mem.eql(u8, first, windows_process.candidate_arg)) {
            if (comptime builtin.os.tag == .windows) {
                const read_handle = try parseWindowsCandidateNumber(usize, args.next() orelse return error.InvalidWindowsCandidate);
                const write_handle = try parseWindowsCandidateNumber(usize, args.next() orelse return error.InvalidWindowsCandidate);
                const parent_process = try parseWindowsCandidateNumber(usize, args.next() orelse return error.InvalidWindowsCandidate);
                const parent_pid = try parseWindowsCandidateNumber(u32, args.next() orelse return error.InvalidWindowsCandidate);
                const path = args.next() orelse return error.InvalidWindowsCandidate;
                if (path.len == 0 or path.len > windows_config_proof.max_path_bytes or
                    std.mem.indexOfAny(u8, path, "\x00\r\n") != null or args.next() != null)
                    return error.InvalidWindowsCandidate;
                var handles = windows_process.CandidateHandles{
                    .read_handle = read_handle,
                    .write_handle = write_handle,
                    .parent_process = parent_process,
                };
                defer handles.deinit();
                windows_deadline = try std.math.add(i64, onyx_server.substrate.platform.monotonicMillis(), 30_000);
                windows_child = try windows_process.accept(&handles, parent_pid, windows_deadline);
                windows_transfer = windows_bootstrap.receive(allocator, &windows_child.?.endpoint, windows_deadline) catch |err| {
                    // Return a bounded authenticated diagnostic before the
                    // inert candidate exits; the predecessor remains live.
                    windows_child.?.endpoint.send(.abort, @errorName(err), windows_deadline) catch {};
                    windows_driver.candidateAbortNow();
                };
                const zero_digest: windows_config_proof.Digest = @splat(0);
                if (std.crypto.timing_safe.eql(windows_config_proof.Digest, windows_transfer.?.source_digest, zero_digest))
                    windows_driver.candidateAbortNow();
                config_path_arg = path;
            } else return error.InvalidWindowsCandidate;
        } else if (std.mem.eql(u8, first, onyx_server.daemon.helix.live.upgrade_capability_arg)) {
            // Advertise the current contract plus the exact predecessor token.
            // The latter lets a deployed HSSN v3 writer upgrade into this v4
            // reader; current predecessors still require the current token and
            // therefore reject rollback to a v3-only image.
            std.debug.print("{s}\n", .{
                onyx_server.daemon.helix.live.upgrade_capability_advertisement,
            });
            return;
        } else
        // `onyx-server --supervisor` is the Helix in-process-upgrade successor mode:
        // a fresh image execve'd by an UPGRADE handoff. If the handoff env fds are
        // present we resume from them (listener + client fds + sessions + live TLS
        // state + mesh re-dial hints); otherwise it boots normally.
        if (std.mem.eql(u8, first, "--supervisor")) {
            if (comptime builtin.os.tag == .linux) {
                if (onyx_server.daemon.helix.live.resumeFromEnv()) |r| {
                    if (r.listen_fd) |lfd| {
                        // Adopt the inherited listening socket so the port stays
                        // bound across the upgrade (no connection-refused window).
                        srv_cfg.inherited_listener_fd = lfd;
                        std.debug.print("onyx-server: Helix resume — adopting listen fd {d}\n", .{lfd});
                    } else {
                        std.debug.print("onyx-server: Helix resume (no listen fd; binding fresh)\n", .{});
                    }
                    // Multi-shard predecessor: the full shard-ordered listener
                    // list (entry 0 duplicates the singular fd above). Each
                    // successor shard adopts its own; leftovers are closed at
                    // server init. Copy into main's frame — the config slice
                    // must outlive server init.
                    if (r.listen_fd_count > 1) {
                        inherited_listeners = r.listen_fds;
                        srv_cfg.inherited_listener_fds = inherited_listeners[0..r.listen_fd_count];
                        std.debug.print("onyx-server: Helix resume — adopting {d} per-shard listen fds\n", .{r.listen_fd_count});
                    }
                    // Hand the inherited state arena to the server, which reads it
                    // after boot and re-attaches the carried-over client connections.
                    if (r.arena_fd) |afd| srv_cfg.resume_arena_fd = afd;
                    srv_cfg.inherited_state_fd_manifest_present = r.state_fd_manifest_present;
                    srv_cfg.inherited_state_fd_manifest_valid = r.state_fd_manifest_valid;
                    if (r.state_fd_count != 0) {
                        inherited_state_fds = r.state_fds;
                        srv_cfg.inherited_state_fds = inherited_state_fds[0..r.state_fd_count];
                        std.debug.print("onyx-server: Helix resume — tracking {d} carried state fds\n", .{r.state_fd_count});
                    }
                } else {
                    std.debug.print("onyx-server: --supervisor with no Helix handoff env; normal boot\n", .{});
                }
            } else {
                std.debug.print("onyx-server: --supervisor is Linux-only\n", .{});
            }
            // The successor carries its config path as the arg after --supervisor,
            // so it boots with the SAME config (ports/certs/opers/cloak) as the
            // predecessor — not the built-in defaults.
            config_path_arg = args.next();
        } else
        // GAP-O4 read-only doctor exits before daemon setup or any listener bind.
        if (std.mem.eql(u8, first, "doctor")) {
            const path = args.next() orelse {
                std.debug.print("usage: onyx-server doctor <config> [metrics-url]\n", .{});
                std.process.exit(2);
            };
            const metrics_url = args.next();
            if (args.next() != null) {
                std.debug.print("usage: onyx-server doctor <config> [metrics-url]\n", .{});
                std.process.exit(2);
            }
            const resolver = onyx_server.daemon.config_format.Resolver{
                .ctx = @ptrCast(&resolver_ctx),
                .env = envLookup,
                .file = fileLookup,
            };
            const config_text = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20)) catch |err| {
                std.debug.print("doctor: cannot read {s}: {s}\n", .{ path, @errorName(err) });
                std.process.exit(1);
            };
            defer allocator.free(config_text);
            var loaded = onyx_server.daemon.config_boot.loadFromText(allocator, config_text, srv_cfg, resolver) catch |err| {
                std.debug.print("doctor: cannot load {s}: {s}\n", .{ path, @errorName(err) });
                std.process.exit(1);
            };
            defer loaded.deinit(allocator);
            const result = try onyx_server.daemon.doctor.report(allocator, init.io, &loaded, metrics_url, null, onyx_server.daemon.doctor.fetchMetrics);
            defer result.deinit(allocator);
            std.debug.print("{s}", .{result.lines});
            if (result.failed) std.process.exit(1);
            return;
        } else
        // `onyx-server --check-config <path> [--against <running.toml>]` parses a
        // config and reports OK/ERROR WITHOUT booting (no ports bound, no mesh
        // dialed) — safe pre-deploy validation. Exits 0 on success, 1 on any
        // read/parse error. `--against` compares configured listeners with the
        // file the running daemon booted, and refuses an add, removal, or port
        // move before the operator sends SIGUSR2.
        if (std.mem.eql(u8, first, "--check-config")) {
            const path = args.next() orelse {
                std.debug.print("usage: onyx-server --check-config <path> [--against <running.toml>]\n", .{});
                std.process.exit(2);
            };
            const against_path: ?[]const u8 = if (args.next()) |extra| blk: {
                if (!std.mem.eql(u8, extra, "--against")) {
                    std.debug.print("usage: onyx-server --check-config <path> [--against <running.toml>]\n", .{});
                    std.process.exit(2);
                }
                break :blk args.next() orelse {
                    std.debug.print("usage: onyx-server --check-config <path> [--against <running.toml>]\n", .{});
                    std.process.exit(2);
                };
            } else null;
            const resolver = onyx_server.daemon.config_format.Resolver{
                .ctx = @ptrCast(&resolver_ctx),
                .env = envLookup,
                .file = fileLookup,
            };
            if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
                defer allocator.free(text);
                if (onyx_server.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                    var l = loaded;
                    defer l.deinit(allocator);
                    if (onyx_server.daemon.config_boot.portableTransportError(builtin.os.tag, l.parsed)) |why| {
                        std.debug.print("config ERROR in {s}: {s}\n", .{ path, why });
                        std.process.exit(1);
                    }
                    if (comptime builtin.os.tag == .windows) {
                        if (l.config.sasl_enabled) if (l.parsed.sasl.account_db) |db| {
                            onyx_server.daemon.os_runtime.requirePrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), db) catch |err| {
                                std.debug.print("config ERROR in {s}: account store directory for {s}: {s}\n", .{ path, db, @errorName(err) });
                                std.process.exit(1);
                            };
                        };
                        if (l.parsed.backup.dir.len != 0) {
                            const backup_dir = onyx_server.daemon.os_runtime.openPrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), l.parsed.backup.dir) catch |err| {
                                std.debug.print("config ERROR in {s}: backup directory for {s}: {s}\n", .{ path, l.parsed.backup.dir, @errorName(err) });
                                std.process.exit(1);
                            };
                            backup_dir.close(init.io);
                        }
                        if (l.parsed.webpush.enabled) {
                            onyx_server.daemon.os_runtime.requirePrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), l.parsed.webpush.vapid_key_path) catch |err| {
                                std.debug.print("config ERROR in {s}: VAPID key directory for {s}: {s}\n", .{ path, l.parsed.webpush.vapid_key_path, @errorName(err) });
                                std.process.exit(1);
                            };
                        }
                        validateWindowsCompanionInputs(allocator, init.io, l.parsed, null) catch |err| {
                            std.debug.print("config ERROR in {s}: Windows companion preflight: {s}\n", .{ path, @errorName(err) });
                            std.process.exit(1);
                        };
                    }
                    // A meshed node with no shared [cloak] secret is a
                    // misconfiguration, not merely a style nit: per-boot random
                    // cloak keys differ per node and change on restart, so
                    // host/subnet WARD bans neither federate nor persist. Fail
                    // validation loudly so it is caught before deploy.
                    if (l.parsed.meshCloakSecretMissing()) {
                        std.debug.print("config ERROR in {s}: meshed node ([mesh] connect or [listen] s2s set) has no shared [cloak] secret; per-boot cloak keys break host/subnet ban federation and persistence — set the SAME [cloak] secret on every mesh node\n", .{path});
                        std.process.exit(1);
                    }
                    // A public-key-only activation plan relies on the persisted
                    // node seed used by normal boot. Validate that exact existing
                    // identity without generating or changing the keyfile, so a
                    // pre-deploy check cannot pass and then fail at restart.
                    if (l.parsed.mesh.relay_v2_activation_epoch != 0 and
                        l.parsed.node.secret_key == null)
                    {
                        const key_path = onyx_server.daemon.node_keyfile.derivePath(allocator, path) catch |err| {
                            std.debug.print("config ERROR in {s}: cannot derive node keyfile path: {s}\n", .{ path, @errorName(err) });
                            std.process.exit(1);
                        };
                        defer allocator.free(key_path);
                        onyx_server.daemon.node_keyfile.validateExistingPublicKey(
                            allocator,
                            init.io,
                            std.Io.Dir.cwd(),
                            key_path,
                            l.parsed.mesh.realm,
                            l.parsed.node.public_key orelse unreachable,
                        ) catch |err| {
                            std.debug.print("config ERROR in {s}: activation node identity in {s}: {s}\n", .{ path, key_path, @errorName(err) });
                            std.process.exit(1);
                        };
                    }
                    if (onyx_server.daemon.config_boot.configCheckError(l.io, l.tls.ktls)) |why| {
                        std.debug.print("config ERROR in {s}: {s}\n", .{ path, why });
                        std.process.exit(1);
                    }
                    if (onyx_server.daemon.config_boot.unsecuredMeshPeerError(
                        l.parsed.mesh.connect.len,
                        l.parsed.mesh.require_secured,
                    )) |why| {
                        std.debug.print("config ERROR in {s}: {s}\n", .{ path, why });
                        std.process.exit(1);
                    }
                    if (l.ocg2.enabled) {
                        if (!onyx_server.daemon.config_boot.ocg2RuntimeModeSupported(l.ocg2.mode)) {
                            std.debug.print(
                                "config ERROR in {s}: OCG2 {s} mode is reserved; this release exposes observation only\n",
                                .{ path, @tagName(l.ocg2.mode) },
                            );
                            std.process.exit(1);
                        }
                        var check_identity = if (l.parsed.node.secret_key) |secret|
                            onyx_server.daemon.node_identity.fromConfig(secret, l.parsed.mesh.realm) catch |err| {
                                std.debug.print("config ERROR in {s}: OCG2 local node secret: {s}\n", .{ path, @errorName(err) });
                                std.process.exit(1);
                            }
                        else identity_blk: {
                            const key_path = onyx_server.daemon.node_keyfile.derivePath(allocator, path) catch |err| {
                                std.debug.print("config ERROR in {s}: cannot derive OCG2 node keyfile path: {s}\n", .{ path, @errorName(err) });
                                std.process.exit(1);
                            };
                            defer allocator.free(key_path);
                            var seed = onyx_server.daemon.node_keyfile.loadExisting(
                                allocator,
                                init.io,
                                std.Io.Dir.cwd(),
                                key_path,
                            ) catch |err| {
                                std.debug.print("config ERROR in {s}: OCG2 requires existing node key {s}: {s}\n", .{ path, key_path, @errorName(err) });
                                std.process.exit(1);
                            };
                            defer std.crypto.secureZero(u8, &seed);
                            break :identity_blk onyx_server.daemon.node_identity.fromSeed(seed, l.parsed.mesh.realm) catch |err| {
                                std.debug.print("config ERROR in {s}: OCG2 node identity: {s}\n", .{ path, @errorName(err) });
                                std.process.exit(1);
                            };
                        };
                        defer check_identity.deinit();
                        const role = onyx_server.daemon.config_boot.validateOcg2LocalIdentity(
                            l.ocg2,
                            &check_identity,
                        ) catch |err| {
                            std.debug.print("config ERROR in {s}: OCG2 authority identity: {s}\n", .{ path, @errorName(err) });
                            std.process.exit(1);
                        };
                        std.debug.print("config OCG2: {s}\n", .{@tagName(role)});
                    }
                    if (against_path) |base_path| {
                        const base_text = std.Io.Dir.cwd().readFileAlloc(init.io, base_path, allocator, .limited(1 << 20)) catch |err| {
                            std.debug.print("config ERROR: cannot read {s}: {s}\n", .{ base_path, @errorName(err) });
                            std.process.exit(1);
                        };
                        defer allocator.free(base_text);
                        var base_loaded = onyx_server.daemon.config_boot.loadFromText(allocator, base_text, srv_cfg, resolver) catch |err| {
                            std.debug.print("config ERROR in {s}: {s}\n", .{ base_path, @errorName(err) });
                            std.process.exit(1);
                        };
                        defer base_loaded.deinit(allocator);
                        if (onyx_server.daemon.config_boot.listenerChangeError(
                            onyx_server.daemon.config_boot.listenerSetFromParsed(base_loaded.parsed),
                            onyx_server.daemon.config_boot.listenerSetFromParsed(l.parsed),
                        )) |why| {
                            std.debug.print("config ERROR in {s}: {s}\n", .{ path, why });
                            std.process.exit(1);
                        }
                    }
                    std.debug.print("config OK: {s}\n", .{path});
                    return;
                } else |err| {
                    std.debug.print("config ERROR in {s}: {s}\n", .{ path, @errorName(err) });
                    std.process.exit(1);
                }
            } else |err| {
                std.debug.print("config ERROR: cannot read {s}: {s}\n", .{ path, @errorName(err) });
                std.process.exit(1);
            }
        } else
        // GAP-D6 restore drill checks latest.json and reopens the account
        // snapshot in a scratch directory. It does not boot, bind, or send mail.
        if (std.mem.eql(u8, first, "--restore-drill")) {
            const backup_dir = args.next() orelse {
                std.debug.print("{s}\n", .{onyx_server.daemon.backup_set.drill_usage});
                std.process.exit(2);
            };
            const into_flag = args.next() orelse {
                std.debug.print("{s}\n", .{onyx_server.daemon.backup_set.drill_usage});
                std.process.exit(2);
            };
            if (!std.mem.eql(u8, into_flag, "--into")) {
                std.debug.print("{s}\n", .{onyx_server.daemon.backup_set.drill_usage});
                std.process.exit(2);
            }
            const scratch_dir = args.next() orelse {
                std.debug.print("{s}\n", .{onyx_server.daemon.backup_set.drill_usage});
                std.process.exit(2);
            };
            if (args.next() != null) {
                std.debug.print("{s}\n", .{onyx_server.daemon.backup_set.drill_usage});
                std.process.exit(2);
            }
            onyx_server.daemon.backup_set.restoreDrill(allocator, init.io, backup_dir, scratch_dir) catch |err| {
                std.debug.print("restore-drill failed: {s}\n", .{@errorName(err)});
                std.process.exit(1);
            };
            std.debug.print("restore-drill OK: {s} -> {s}/restored.wal\n", .{ backup_dir, scratch_dir });
            return;
        } else
        // `onyx-server acme-issue ...` runs an out-of-band ACME issuance and exits.
        // Run issuance through the platform's HTTP-01 and HTTPS transports.
        if (std.mem.eql(u8, first, "acme-issue")) {
            if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
                var rest: std.ArrayList([]const u8) = .empty;
                defer rest.deinit(allocator);
                while (args.next()) |a| try rest.append(allocator, a);
                const opts = onyx_server.daemon.acme_cli.parseArgs(rest.items) orelse {
                    onyx_server.daemon.acme_cli.usage();
                    return;
                };
                _ = onyx_server.daemon.acme_cli.runIssue(allocator, init.io, opts) catch |err| {
                    std.debug.print("acme-issue failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
                return;
            } else {
                std.debug.print("acme-issue is supported on Linux, OpenBSD, and Windows\n", .{});
                return;
            }
        } else
        // `onyx-server delegated-credential inspect|validate ...` inspects a raw RFC
        // 9345 DelegatedCredential and optionally validates it against the leaf
        // certificate that signed it. It never boots the daemon or binds ports.
        if (std.mem.eql(u8, first, "delegated-credential")) {
            var rest: std.ArrayList([]const u8) = .empty;
            defer rest.deinit(allocator);
            while (args.next()) |a| try rest.append(allocator, a);
            const opts = delegated_credential_cli.parseArgs(rest.items) catch |err| {
                std.debug.print("delegated-credential args error: {s}\n", .{@errorName(err)});
                delegated_credential_cli.usage();
                std.process.exit(2);
            } orelse {
                delegated_credential_cli.usage();
                std.process.exit(2);
            };
            if (!try delegated_credential_cli.run(allocator, init.io, opts)) {
                std.process.exit(1);
            }
            return;
        } else if (std.mem.eql(u8, first, "--version") or
            std.mem.eql(u8, first, "-v") or std.mem.eql(u8, first, "-V"))
        {
            // The version banner already printed above; exit WITHOUT booting.
            // (Previously `--version` fell through to the config-path branch,
            // failed to read a file named "--version", kept defaults, and booted
            // a stray daemon on port 6680.)
            return;
        } else if (std.mem.eql(u8, first, "--help") or std.mem.eql(u8, first, "-h")) {
            std.debug.print(
                \\usage: onyx-server [CONFIG_PATH]
                \\       onyx-server --check-config <path>
                \\       {s}
                \\       onyx-server doctor <config> [metrics-url]
                \\       onyx-server --version
                \\       onyx-server acme-issue ...
                \\       onyx-server delegated-credential inspect|validate ...
                \\
            , .{onyx_server.daemon.backup_set.drill_usage});
            return;
        } else if (first.len > 0 and first[0] == '-') {
            // An unrecognized dash-flag must NEVER be treated as a config path — a
            // real config path never starts with '-'. Treating it as one silently
            // boots the DEFAULT identity (wrong ports/certs/opers). Fail loudly.
            std.debug.print("onyx-server: unknown option '{s}' (try --help)\n", .{first});
            std.process.exit(2);
        } else {
            config_path_arg = first;
        }
    }

    // Load the config file — normal boot uses argv[1]; the UPGRADE successor uses
    // the path carried after --supervisor. One path for both so a hot-upgraded
    // process comes up on the real ports/certs/opers, not the defaults.
    if (config_path_arg) |path| {
        const resolver = onyx_server.daemon.config_format.Resolver{
            .ctx = @ptrCast(&resolver_ctx),
            .env = envLookup,
            .file = fileLookup,
        };
        // Read through the same normalized source path that enters the Windows
        // Helix proof. The resolver records the values actually used by parse.
        const windows_source_path: ?[:0]u8 = if (comptime builtin.os.tag == .windows)
            try std.Io.Dir.cwd().realPathFileAlloc(init.io, path, allocator)
        else
            null;
        defer if (windows_source_path) |canonical| allocator.free(canonical);
        const source_path = if (windows_source_path) |canonical| canonical else path;
        if (std.Io.Dir.cwd().readFileAlloc(init.io, source_path, allocator, .limited(1 << 20))) |text| {
            defer allocator.free(text); // string fields are duped by the parser
            var windows_source_proof: ?windows_config_proof.Builder = null;
            defer if (windows_source_proof) |*proof| proof.deinit();
            defer resolver_ctx.windows_helix_proof = null;
            if (comptime builtin.os.tag == .windows) {
                windows_source_proof = try windows_config_proof.Builder.initCanonical(windows_source_path.?, text);
                resolver_ctx.windows_helix_proof = &windows_source_proof.?;
            }
            if (managed_prelude != null) {
                managed_commitment.record(1, path, text);
                resolver_ctx.managed_commitment = &managed_commitment;
            }
            if (onyx_server.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                const windows_source_digest: ?windows_config_proof.Digest = if (comptime builtin.os.tag == .windows) blk: {
                    const proof = if (windows_source_proof) |*p| p else unreachable;
                    break :blk try proof.finish();
                } else null;
                resolver_ctx.windows_helix_proof = null;
                if (windows_transfer) |*transfer| {
                    // The static source proof is compared after read-only
                    // config material loads. HXTM carries the exact serving
                    // TLS generation separately; a provisional candidate
                    // bootstrap leaf cannot serve before its COMMIT swap.
                    if (loaded.parsed.node.secret_key == null or loaded.parsed.cloak.secret == null)
                        windows_driver.candidateAbortNow();
                    if (loaded.config.sasl_enabled and loaded.parsed.sasl.account_db != null) {
                        if (transfer.wal == null) windows_driver.candidateAbortNow();
                    } else if (transfer.wal != null) windows_driver.candidateAbortNow();
                }
                if (managed_prelude != null) {
                    managed_config_digest = managed_commitment.finish();
                    resolver_ctx.managed_commitment = null;
                }
                if (onyx_server.daemon.config_boot.portableTransportError(builtin.os.tag, loaded.parsed)) |why| {
                    std.debug.print("onyx-server: fatal config error in {s}: {s}\n", .{ path, why });
                    std.process.exit(1);
                }
                if (comptime builtin.os.tag == .windows) {
                    if (loaded.config.sasl_enabled) if (loaded.parsed.sasl.account_db) |db| {
                        onyx_server.daemon.os_runtime.requirePrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), db) catch |err| {
                            std.debug.print("onyx-server: fatal account store directory for {s}: {s}\n", .{ db, @errorName(err) });
                            std.process.exit(1);
                        };
                    };
                    if (loaded.parsed.backup.dir.len != 0) {
                        const backup_dir = onyx_server.daemon.os_runtime.openPrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), loaded.parsed.backup.dir) catch |err| {
                            std.debug.print("onyx-server: fatal backup directory for {s}: {s}\n", .{ loaded.parsed.backup.dir, @errorName(err) });
                            std.process.exit(1);
                        };
                        backup_dir.close(init.io);
                    }
                    if (loaded.parsed.webpush.enabled) {
                        onyx_server.daemon.os_runtime.requirePrivateDirectoryWindows(init.io, std.Io.Dir.cwd(), loaded.parsed.webpush.vapid_key_path) catch |err| {
                            std.debug.print("onyx-server: fatal VAPID key directory for {s}: {s}\n", .{ loaded.parsed.webpush.vapid_key_path, @errorName(err) });
                            std.process.exit(1);
                        };
                    }
                    validateWindowsCompanionInputs(allocator, init.io, loaded.parsed, &windows_geo) catch |err| {
                        std.debug.print("onyx-server: fatal Windows companion preflight: {s}\n", .{@errorName(err)});
                        std.process.exit(1);
                    };
                }
                if (onyx_server.daemon.config_boot.configCheckError(loaded.io, loaded.tls.ktls)) |why| {
                    std.debug.print("onyx-server: fatal config error in {s}: {s}\n", .{ path, why });
                    std.process.exit(1);
                }
                if (onyx_server.daemon.config_boot.unsecuredMeshPeerError(
                    loaded.parsed.mesh.connect.len,
                    loaded.parsed.mesh.require_secured,
                )) |why| {
                    std.debug.print("onyx-server: fatal config error in {s}: {s}\n", .{ path, why });
                    std.process.exit(1);
                }
                held = loaded;
                // Preserve the Helix handoff fields set above: `srv_cfg = loaded.config`
                // replaces the whole struct, and these are not config-file keys.
                const carried_exe = srv_cfg.exe_path;
                const carried_resume = srv_cfg.resume_arena_fd;
                const carried_listen = srv_cfg.inherited_listener_fd;
                const carried_listen_list = srv_cfg.inherited_listener_fds;
                const carried_state_fds = srv_cfg.inherited_state_fds;
                const carried_state_manifest_present = srv_cfg.inherited_state_fd_manifest_present;
                const carried_state_manifest_valid = srv_cfg.inherited_state_fd_manifest_valid;
                srv_cfg = loaded.config;
                windows_source_digest_boot = windows_source_digest;
                srv_cfg.exe_path = carried_exe;
                srv_cfg.resume_arena_fd = carried_resume;
                srv_cfg.inherited_listener_fd = carried_listen;
                srv_cfg.inherited_listener_fds = carried_listen_list;
                srv_cfg.inherited_state_fds = carried_state_fds;
                srv_cfg.inherited_state_fd_manifest_present = carried_state_manifest_present;
                srv_cfg.inherited_state_fd_manifest_valid = carried_state_manifest_valid;
                srv_cfg.num_shards = loaded.num_shards;
                srv_cfg.config_path = path;
                srv_cfg.config_resolver = resolver;
                // Windows pins every live companion to the effective config
                // proof and carries its process-owned state. A configured
                // native-media port has no socket when media is disabled.
                std.debug.print("onyx-server: loaded config from {s}\n", .{path});
            } else |err| {
                std.debug.print("onyx-server: fatal config error in {s} ({s})\n", .{ path, @errorName(err) });
                return err;
            }
        } else |err| {
            std.debug.print("onyx-server: fatal — cannot read explicit config {s} ({s})\n", .{ path, @errorName(err) });
            return err;
        }
    }

    if (comptime builtin.os.tag == .openbsd) {
        native_driver.config_path = srv_cfg.config_path;
        srv_cfg.native_upgrade_hooks = native_driver.hooks();
        if (native_incoming) |*incoming| {
            srv_cfg.native_listener_manifest = incoming.listeners;
            srv_cfg.native_arena_bytes = incoming.plaintext;
            srv_cfg.native_adopt_barrier = incoming.barrier();
            srv_cfg.inherited_state_fds = incoming.state_fds;
            srv_cfg.inherited_state_fd_manifest_present = true;
            srv_cfg.inherited_state_fd_manifest_valid = true;
        }
    }

    // Implicit-TLS client listener: when `[tls] enabled`, load the configured
    // cert/key (or mint a self-signed bootstrap leaf) and stand up the TLS
    // listener. The chain bytes + signing key live for the server's lifetime
    // (server.Config borrows them). No STARTTLS — this is a separate TLS port.
    var tls_loaded: ?onyx_server.daemon.tls_certs.Loaded = null;
    defer if (tls_loaded) |*t| t.deinit(allocator);
    var tls12_loaded: ?onyx_server.daemon.tls_certs.Tls12 = null;
    defer if (tls12_loaded) |*t| t.deinit(allocator);
    // [[tls.sni]] additional certs: each entry's on-disk cert+key is loaded with
    // the SAME loader as the default cert. The loaded material must outlive the
    // server (each `tls_server.SniCert` borrows its chain bytes and aliases any
    // RSA key storage), so the loads live on main's frame and free at process
    // exit — mirroring `tls_loaded`. `tls_sni_certs` is the selection list handed
    // to the listener; the array itself is freed here, its contents borrow above.
    var tls_sni_loaded: std.ArrayList(onyx_server.daemon.tls_certs.Loaded) = .empty;
    defer {
        for (tls_sni_loaded.items) |*s| s.deinit(allocator);
        tls_sni_loaded.deinit(allocator);
    }
    var tls_sni_certs: []onyx_server.crypto.tls_server.SniCert = &.{};
    defer if (tls_sni_certs.len != 0) allocator.free(tls_sni_certs);
    var tls_ech_loaded: ?LoadedEchKeys = null;
    defer if (tls_ech_loaded) |*e| e.deinit(allocator);
    if (held) |h| {
        if (h.tls.enabled) {
            const tls_options: onyx_server.daemon.tls_certs.Options = .{
                .enabled = true,
                .cert_path = h.tls.cert_path,
                .key_path = h.tls.key_path,
                .dns_name = h.tls.dns_name,
            };
            const loaded_tls = if (builtin.os.tag == .windows and srv_cfg.webtransport_port != 0)
                onyx_server.daemon.tls_certs.loadOrBootstrapWebTransport(allocator, init.io, tls_options)
            else
                onyx_server.daemon.tls_certs.loadOrBootstrap(allocator, init.io, tls_options);
            if (loaded_tls) |loaded| tls_material: {
                validateTlsChain(loaded.cert_chain) catch |err| {
                    var rejected = loaded;
                    rejected.deinit(allocator);
                    if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                    std.debug.print("onyx-server: TLS certificate validation failed ({s}); TLS disabled\n", .{@errorName(err)});
                    break :tls_material;
                };
                if (comptime builtin.os.tag == .windows) {
                    validateTlsIdentity(loaded.cert_chain, loaded.signing_key, loaded.ecdsa_p256_signing_key, loaded.rsa_signing_key) catch |err| {
                        var rejected = loaded;
                        rejected.deinit(allocator);
                        return err;
                    };
                }
                tls_loaded = loaded;
                // [[tls.sni]] additional SNI-selectable certificates: load each
                // entry's cert+key with the SAME loader as the default cert, retain
                // the material for the server's lifetime, and hand the listener the
                // selection list. A malformed/expired entry fails TLS bring-up
                // wholesale (fail-fast) — reached BEFORE any `srv_cfg.tls_*` field is
                // wired, so TLS stays fully disabled rather than half-configured,
                // consistent with the default cert's validation-failure path.
                if (h.tls.sni.len != 0) {
                    // The load loop lives in `daemon/tls_sni_load` so its four
                    // key-material error paths are unit-tested under
                    // `std.testing.allocator`. Ownership is unchanged: each entry
                    // is retained in `tls_sni_loaded` (freed at process exit by the
                    // defer above), the returned list is freed here, and on ANY
                    // error the helper frees its partial list + deinits the
                    // just-loaded entry, so we simply fail-fast into `break`.
                    const built = onyx_server.daemon.tls_sni_load.buildSniCerts(
                        allocator,
                        init.io,
                        h.tls.sni,
                        h.tls.dns_name,
                        &tls_sni_loaded,
                        validateTlsChain,
                        onyx_server.daemon.tls_sni_load.default_loader,
                    ) catch |err| {
                        if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                        std.debug.print("onyx-server: [[tls.sni]] certificate setup failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    tls_sni_certs = built;
                    if (comptime builtin.os.tag == .windows) for (tls_sni_certs) |cert|
                        try validateTlsIdentity(cert.cert_chain, cert.signing_key, cert.ecdsa_p256_signing_key, cert.rsa_signing_key);
                    std.debug.print("onyx-server: {d} SNI certificate(s) loaded\n", .{tls_sni_certs.len});
                }
                if (h.tls.ech_keys.len != 0) {
                    tls_ech_loaded = loadTlsEchKeys(allocator, init.io, h.tls.ech_keys) catch |err| {
                        if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                        std.debug.print("onyx-server: [[tls.ech_keys]] load failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    var probe = onyx_server.crypto.tls_server.Server.init(allocator, .{
                        .cert_chain = tls_loaded.?.cert_chain,
                        .signing_key = tls_loaded.?.signing_key,
                        .ecdsa_p256_signing_key = tls_loaded.?.ecdsa_p256_signing_key,
                        .rsa_signing_key = tls_loaded.?.rsa_signing_key,
                        .sni_certs = tls_sni_certs,
                        .ech_keys = tls_ech_loaded.?.keys,
                    }) catch |err| {
                        if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                        std.debug.print("onyx-server: [[tls.ech_keys]] validation failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    probe.deinit();
                    std.debug.print("onyx-server: {d} ECH key(s) loaded\n", .{tls_ech_loaded.?.keys.len});
                }
                srv_cfg.tls_port = h.tls.port;
                srv_cfg.tls_cert_chain = tls_loaded.?.cert_chain;
                srv_cfg.tls_signing_key = tls_loaded.?.signing_key;
                srv_cfg.tls_rsa_signing_key = tls_loaded.?.rsa_signing_key;
                srv_cfg.tls_ecdsa_signing_key = tls_loaded.?.ecdsa_p256_signing_key;
                srv_cfg.tls_sni_certs = tls_sni_certs;
                if (tls_ech_loaded) |e| srv_cfg.tls_ech_keys = e.keys;
                srv_cfg.tls_raw_public_key = h.tls.raw_public_key;
                srv_cfg.tls_request_client_cert = h.tls.request_client_cert;
                srv_cfg.tls_enable_resumption = h.tls.enable_resumption;
                srv_cfg.tls_early_data_max_size = h.tls.early_data_max_size;
                std.debug.print("onyx-server: TLS listener enabled on port {d}\n", .{h.tls.port});
                // kTLS offload (roadmap 3.1): activate kernel record crypto only
                // when the operator opted in via `[tls] ktls` AND the running
                // kernel offers the TLS ULP. `tx` offloads server→client encryption;
                // `txrx` additionally offloads client→server decryption.
                const ktls_capable = onyx_server.daemon.ktls.probeUlpSupport();
                const ktls_offload = onyx_server.daemon.config_boot.resolveKtlsOffload(h.tls.ktls, ktls_capable);
                srv_cfg.tls_ktls_tx = ktls_offload.tx;
                srv_cfg.tls_ktls_rx = ktls_offload.rx;
                if (ktls_offload.footgun) |msg| {
                    std.debug.print("onyx-server: {s}\n", .{msg});
                } else if (h.tls.ktls != .off) {
                    if (ktls_capable) {
                        std.debug.print("onyx-server: kTLS TX offload ACTIVE (tx) — TLS 1.3 record crypto runs in the kernel\n", .{});
                    } else {
                        std.debug.print("onyx-server: kTLS {s} requested but this kernel has no TLS ULP — TLS stays in userspace\n", .{@tagName(h.tls.ktls)});
                    }
                } else if (ktls_capable) {
                    std.debug.print("onyx-server: kTLS-capable kernel detected (TLS ULP present); set [tls] ktls=tx to offload server→client encryption\n", .{});
                } else {
                    std.debug.print("onyx-server: kTLS unavailable on this kernel (no TLS ULP); TLS stays in userspace\n", .{});
                }
                if (h.tls.enable_tls12) {
                    if (tls_loaded.?.key_kind == .ecdsa_p256) {
                        // The loaded ECDSA-P256 leaf serves the 1.2 leg natively.
                        srv_cfg.tls12_cert_chain = tls_loaded.?.cert_chain;
                        srv_cfg.tls12_signing_key = tls_loaded.?.ecdsa_p256_signing_key;
                        std.debug.print("onyx-server: hardened TLS 1.2 also accepted (ECDSA-P256 leaf)\n", .{});
                    } else if (tls_loaded.?.key_kind == .rsa) {
                        srv_cfg.tls12_cert_chain = tls_loaded.?.cert_chain;
                        std.debug.print("onyx-server: hardened TLS 1.2 also accepted (RSA leg)\n", .{});
                    } else {
                        if (onyx_server.daemon.tls_certs.bootstrapTls12(allocator, init.io, h.tls.dns_name)) |t12| {
                            tls12_loaded = t12;
                            srv_cfg.tls12_cert_chain = tls12_loaded.?.cert_chain;
                            srv_cfg.tls12_signing_key = tls12_loaded.?.key;
                            std.debug.print("onyx-server: hardened TLS 1.2 also accepted (ECDSA-P256 leg)\n", .{});
                        } else |err| {
                            if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                            std.debug.print("onyx-server: TLS 1.2 bootstrap failed ({s}); 1.3-only\n", .{@errorName(err)});
                        }
                    }
                }
            } else |err| {
                if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return err;
                std.debug.print("onyx-server: TLS cert error ({s}); TLS disabled\n", .{@errorName(err)});
            }
        }
    }
    // Native secure-WebSocket (wss) browser listener (`[listen] ws`): rides the
    // SAME cert chain + signing key loaded for the implicit-TLS listener above,
    // so the leg is genuine wss under the daemon's real certificate. Browsers
    // require wss on the production page, so a cert-less ws port is refused
    // unless the testing-only `[listen] ws_plain` flag is set.
    if (srv_cfg.ws_enabled) {
        if (srv_cfg.tls_cert_chain.len != 0) {
            std.debug.print("onyx-server: WebSocket (wss) listener enabled on port {d}\n", .{srv_cfg.ws_port});
        } else if (srv_cfg.ws_allow_plain) {
            std.debug.print("onyx-server: WebSocket listener on port {d} WITHOUT TLS ([listen] ws_plain testing mode)\n", .{srv_cfg.ws_port});
        } else {
            if (builtin.os.tag == .windows or managed_prelude != null or native_incoming != null) return error.ManagedWebSocketWithoutTls;
            srv_cfg.ws_enabled = false;
            std.debug.print("onyx-server: [listen] ws ignored — no TLS certificate loaded (enable [tls]; browsers require wss)\n", .{});
        }
    }

    if (comptime builtin.os.tag == .openbsd) {
        if (managed_prelude) |prelude| {
            const loaded = if (held) |*h| h else return error.MissingManagedConfig;
            try validateManagedBootPlan(allocator, init.io, loaded, srv_cfg.config_path.?);
            if (srv_cfg.tls_cert_chain.len != 0) {
                try validateTlsIdentity(srv_cfg.tls_cert_chain, srv_cfg.tls_signing_key, srv_cfg.tls_ecdsa_signing_key, srv_cfg.tls_rsa_signing_key);
                for (srv_cfg.tls_sni_certs) |cert| try validateTlsIdentity(cert.cert_chain, cert.signing_key, cert.ecdsa_p256_signing_key, cert.rsa_signing_key);
                if (srv_cfg.tls12_cert_chain.len != 0) try validateTlsIdentity(srv_cfg.tls12_cert_chain, null, srv_cfg.tls12_signing_key, if (srv_cfg.tls12_signing_key == null) srv_cfg.tls_rsa_signing_key else null);
                var probe = try onyx_server.crypto.tls_server.Server.init(allocator, .{
                    .cert_chain = srv_cfg.tls_cert_chain,
                    .signing_key = srv_cfg.tls_signing_key,
                    .ecdsa_p256_signing_key = srv_cfg.tls_ecdsa_signing_key,
                    .rsa_signing_key = srv_cfg.tls_rsa_signing_key,
                    .sni_certs = srv_cfg.tls_sni_certs,
                    .ech_keys = srv_cfg.tls_ech_keys,
                });
                probe.deinit();
            }
            const ports = onyx_server.daemon.config_boot.listenerSetFromParsed(loaded.parsed);
            try prelude.reportLoaded(.{ .config_commitment = managed_config_digest orelse return error.MissingManagedConfig, .listener_ports = .{ ports.irc, ports.tls, ports.ws, ports.webtransport, ports.s2s, ports.media, ports.native_media } });
            if (prelude.purpose() == .preflight) {
                try prelude.finishPreflight();
                return;
            }
            managed_incoming = try prelude.receiveBootstrap();
            try managed_incoming.?.state.context.validateExecutedContext(allocator, init.io);
        }
    }

    // The platform CSPRNG is always available to the server (session reclaim
    // tokens, etc.); PQ-secured S2S below is the only feature gated on a key.
    srv_cfg.crypto_io = init.io;

    // Install the configured network name before building ISUPPORT, so the
    // NETWORK= token and the welcome burst both reflect it. Write-once at boot.
    onyx_server.proto.protocol_inventory.setNetworkName(srv_cfg.network_name);
    onyx_server.proto.protocol_inventory.setServerName(srv_cfg.server_name);
    // Web Push VAPID key: loaded (or created) BEFORE ISUPPORT is built so the
    // 005 burst can advertise `VAPID=` — discovery is ISUPPORT, not a NOTE
    // round-trip. The delivery worker itself spawns later (needs `srv`).
    var webpush_vapid: ?onyx_server.daemon.webpush.Vapid = null;
    var webpush_pub_buf: [onyx_server.daemon.webpush.vapid_pub_b64_len]u8 = undefined;
    if (held) |h| {
        if (h.parsed.webpush.enabled and (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
            const loaded_vapid = if (comptime builtin.os.tag == .windows)
                if (windows_transfer != null)
                    onyx_server.daemon.webpush.Vapid.loadExistingPrivateWindows(init.io, std.Io.Dir.cwd(), h.parsed.webpush.vapid_key_path)
                else
                    onyx_server.daemon.webpush.Vapid.loadOrCreatePrivateWindows(init.io, std.Io.Dir.cwd(), h.parsed.webpush.vapid_key_path)
            else if (native_incoming != null)
                onyx_server.daemon.webpush.Vapid.loadExisting(init.io, allocator, std.Io.Dir.cwd(), h.parsed.webpush.vapid_key_path)
            else
                onyx_server.daemon.webpush.Vapid.loadOrCreate(init.io, allocator, std.Io.Dir.cwd(), h.parsed.webpush.vapid_key_path);
            if (loaded_vapid) |v| {
                webpush_vapid = v;
                srv_cfg.webpush_vapid_pub = v.publicB64(&webpush_pub_buf);
            } else |err| {
                if (comptime builtin.os.tag == .windows) return err;
                if (native_incoming != null) return err;
                std.debug.print("onyx-server: [webpush] VAPID key failed ({s}); web push disabled\n", .{@errorName(err)});
            }
        }
    }

    // Advertise config-driven length limits (TOPICLEN) in ISUPPORT. Built once
    // here, before any connection is served; retained until server teardown.
    const isupport_tokens = try onyx_server.daemon.server.buildIsupportTokens(allocator, srv_cfg);
    onyx_server.proto.protocol_inventory.setIsupportOverride(isupport_tokens);
    defer {
        onyx_server.proto.protocol_inventory.setIsupportOverride(null);
        onyx_server.daemon.server.freeIsupportTokens(allocator, isupport_tokens);
    }
    // NICKLEN is enforced in the pre-registration dispatch path, which reads the
    // runtime-limits holder rather than a config handle.
    onyx_server.proto.protocol_inventory.setRuntimeLimits(.{ .nicklen = srv_cfg.nicklen });

    // PQ-secured S2S is ON BY DEFAULT: an explicit `[node] secret_key` takes
    // precedence (and never touches the keyfile); otherwise the daemon loads — or
    // generates + persists (0600) — the seed from `onyx-server-node.key` next to the
    // config (CWD without one), so the secured Mooring mesh needs no manual key.
    // The identity outlives the server (it borrows a pointer); only a keyfile or
    // identity error leaves S2S plaintext.
    var node_id_holder: ?onyx_server.daemon.node_identity.NodeIdentity = null;
    defer if (node_id_holder) |*n| n.deinit();
    const mesh_realm: []const u8 = if (held) |h| h.parsed.mesh.realm else "local";
    // Apply [mesh].require_secured before the node-identity setup below, so the
    // policy holds even when secured S2S is NOT configured (the case it most
    // matters for — it then drops all S2S instead of falling back to plaintext).
    if (held) |h| srv_cfg.require_secured = h.parsed.mesh.require_secured;
    const dprop_requested = if (held) |h|
        srv_cfg.sasl_enabled and h.parsed.sasl.account_db != null
    else
        false;
    const ocg2_requested = if (held) |h| h.ocg2.enabled else false;
    const configured_key: ?[]const u8 = if (held) |h| h.parsed.node.secret_key else null;
    if (configured_key) |sk| {
        if (onyx_server.daemon.node_identity.fromConfig(sk, mesh_realm)) |ident| {
            node_id_holder = ident;
            std.debug.print("onyx-server: PQ-secured S2S enabled (node identity configured)\n", .{});
        } else |err| {
            if (builtin.os.tag == .windows or ocg2_requested or native_incoming != null) {
                std.debug.print("onyx-server: fatal — configured node identity is invalid ({s})\n", .{@errorName(err)});
                return err;
            }
            std.debug.print("onyx-server: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
        }
    } else auto: {
        if (windows_transfer != null) windows_driver.candidateAbortNow();
        const key_path = onyx_server.daemon.node_keyfile.derivePath(allocator, srv_cfg.config_path) catch |err| {
            if (builtin.os.tag == .windows or native_incoming != null) return err;
            break :auto;
        };
        defer allocator.free(key_path);
        // OCG2 never creates identity material implicitly. Its authority/receiver
        // role must be checkable against an already-provisioned private node seed;
        // ordinary non-OCG2 boots retain historical load-or-create behavior.
        const loaded_key = if (ocg2_requested or native_incoming != null)
            onyx_server.daemon.node_keyfile.LoadResult{
                .seed = onyx_server.daemon.node_keyfile.loadExisting(
                    allocator,
                    init.io,
                    std.Io.Dir.cwd(),
                    key_path,
                ) catch |err| {
                    std.debug.print("onyx-server: fatal — OCG2 requires existing node key {s} ({s})\n", .{ key_path, @errorName(err) });
                    return err;
                },
                .source = .loaded,
            }
        else
            onyx_server.daemon.node_keyfile.loadOrCreate(allocator, init.io, std.Io.Dir.cwd(), key_path) catch |err| {
                if (builtin.os.tag == .windows) return err;
                std.debug.print("onyx-server: node keyfile error in {s} ({s}); S2S stays plaintext\n", .{ key_path, @errorName(err) });
                break :auto;
            };
        if (onyx_server.daemon.node_identity.fromSeed(loaded_key.seed, mesh_realm)) |ident| {
            node_id_holder = ident;
            switch (loaded_key.source) {
                .loaded => std.debug.print("onyx-server: node identity loaded from {s}\n", .{key_path}),
                .generated => std.debug.print("onyx-server: node identity generated + persisted to {s}\n", .{key_path}),
            }
        } else |err| {
            if (builtin.os.tag == .windows or native_incoming != null) return err;
            std.debug.print("onyx-server: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
        }
    }
    if (node_id_holder != null) {
        srv_cfg.node_identity = &node_id_holder.?;
        if (held) |h| {
            if (h.parsed.mesh.mesh_pass) |mp| srv_cfg.mesh_pass = mp;
        }
    }
    if (comptime builtin.os.tag == .windows)
        srv_cfg.windows_helix_explicit_node_secret = configured_key != null and node_id_holder != null;
    if (dprop_requested and (srv_cfg.node_identity == null or srv_cfg.node_identity.?.shortId() == 0)) {
        std.debug.print("onyx-server: fatal — configured SASL account storage requires a non-zero DPROP1 node identity\n", .{});
        return error.DurableDeviceActivationFailed;
    }
    var ocg2_role: ?onyx_server.daemon.config_boot.Ocg2LocalRole = null;
    if (ocg2_requested) {
        if (!onyx_server.daemon.config_boot.ocg2RuntimeModeSupported(held.?.ocg2.mode)) {
            std.debug.print(
                "onyx-server: fatal — OCG2 {s} mode is configured but this release exposes observation only\n",
                .{@tagName(held.?.ocg2.mode)},
            );
            return error.Ocg2RuntimeModeUnavailable;
        }
        ocg2_role = onyx_server.daemon.config_boot.validateOcg2LocalIdentity(
            held.?.ocg2,
            srv_cfg.node_identity,
        ) catch |err| {
            std.debug.print("onyx-server: fatal — OCG2 local authority identity validation failed ({s})\n", .{@errorName(err)});
            return err;
        };
    }

    // The WebTransport (QUIC/HTTP3) listener is started AFTER the server is up
    // (it bridges to the daemon's bound IRC port via loopback TCP). See below,
    // after `srv.start()`.

    // SASL account backend: when `[sasl] account_db` is configured, open the
    // WAL-backed account store and verify SASL PLAIN credentials against it. The
    // store/services/checker live for the server's lifetime (the checker fat
    // pointer is copied into every connection).
    var account_store: ?onyx_server.daemon.services.OroStore = null;
    defer if (account_store) |*s| s.deinit();
    // The DPROP1 image is process-owned and outlives both Services and Server.
    // It remains absent unless an account OroStore and a non-zero persisted node
    // identity are both available; once selected, every load error is fatal.
    var durable_device_state: ?onyx_server.daemon.durable_credential_props.State = null;
    defer if (durable_device_state) |*state| state.deinit();
    // Process-owned OCG2 image. Services borrows it only after exact
    // marker/snapshot activation. Observe borrows Services and changes no
    // privileges. Project and mint borrow the projection runtime, which the
    // server applies to live sessions.
    var durable_oper_state: ?onyx_server.daemon.durable_oper_authority.State = null;
    defer if (durable_oper_state) |*state| state.deinit();
    // Runtime carries bounded 256-entry scratch inventories, so allocate it only
    // for an enabled OCG2 mode. Disabled deployments pay neither heap nor stack.
    var ocg2_observer: ?*onyx_server.daemon.ocg2_runtime.Runtime = null;
    defer if (ocg2_observer) |observer| onyx_server.daemon.ocg2_runtime.destroy(observer);
    var ocg2_projection: ?*onyx_server.daemon.ocg2_projection_runtime.Runtime = null;
    defer if (ocg2_projection) |runtime| runtime.deinit();
    var ocg2_audit_storage: ?onyx_server.daemon.audit_trail.AuditTrail = null;
    defer if (ocg2_audit_storage) |*audit| audit.deinit();
    var account_services: onyx_server.daemon.services.Services = undefined;
    var account_checker: onyx_server.daemon.sasl_bridge.ServicesPlainChecker = undefined;
    var external_bridge: onyx_server.daemon.sasl_bridge.ServicesExternalLookup = undefined;
    var session_token_bridge: onyx_server.daemon.sasl_bridge.ServicesSessionTokenLookup = undefined;
    var oauth_key: ?onyx_server.daemon.oauth_jwt.OwnedKey = null;
    defer if (oauth_key) |*key| key.deinit();
    var oauth_verifier: onyx_server.daemon.oauth_jwt.Verifier = undefined;
    var oauth_jwks_text: ?[]u8 = null;
    defer if (oauth_jwks_text) |bytes| allocator.free(bytes);
    // SCRAM-SHA-256 credential mirror: provisioned alongside each account so a
    // client can authenticate without sending its password. Must outlive the
    // server (the lookup fat-pointer captures &scram_store).
    var scram_store = onyx_server.daemon.scram_store.ScramStore.init(allocator);
    defer scram_store.deinit();
    // Account ⇄ TLS certfp bindings for SASL EXTERNAL (CERTADD); outlives server.
    var certfp_binds = onyx_server.daemon.certfp_bind.CertfpBindStore.init(allocator);
    defer certfp_binds.deinit();
    // Account credential transparency root; services append CERTFP/WebAuthn changes.
    var key_transparency_log = onyx_server.daemon.key_transparency.KeyTransparencyLog.init(allocator);
    defer key_transparency_log.deinit();
    if (held) |h| {
        if (!srv_cfg.sasl_enabled) {
            if (h.parsed.sasl.account_db != null) {
                std.debug.print("onyx-server: SASL account store configured but [sasl].enabled=false; SASL disabled\n", .{});
            }
        } else if (h.parsed.sasl.account_db) |db| {
            const opened = if (comptime builtin.os.tag == .windows)
                if (windows_transfer) |*transfer|
                    onyx_server.daemon.services.OroStore.openTransferredPrivateWindowsWithConfig(
                        allocator,
                        init.io,
                        std.Io.Dir.cwd(),
                        db,
                        h.parsed.storage,
                        if (transfer.wal) |*wal| wal else windows_driver.candidateAbortNow(),
                    )
                else
                    onyx_server.daemon.services.OroStore.openPrivateWindowsWithConfig(allocator, init.io, std.Io.Dir.cwd(), db, h.parsed.storage)
            else if (native_incoming != null)
                onyx_server.daemon.services.OroStore.openReadOnlyWithConfig(allocator, init.io, std.Io.Dir.cwd(), db, h.parsed.storage)
            else
                onyx_server.daemon.services.OroStore.openWithConfig(allocator, init.io, std.Io.Dir.cwd(), db, h.parsed.storage);
            if (opened) |store| {
                account_store = store;
                account_services = onyx_server.daemon.services.Services.initWithConfig(&account_store.?, null, .{
                    .pbkdf2_rounds = h.parsed.accounts.pbkdf2_rounds,
                    .password_min_len = @intCast(h.parsed.accounts.password_min_len),
                    .password_max_len = @intCast(h.parsed.accounts.password_max_len),
                });
                account_services.attachScramStore(&scram_store);
                account_services.attachCertfpBinds(&certfp_binds);
                account_services.attachKeyTransparencyLog(&key_transparency_log);
                if (dprop_requested) {
                    const identity = srv_cfg.node_identity orelse unreachable;
                    const local_origin = identity.shortId();
                    if (local_origin == 0) {
                        std.debug.print("onyx-server: fatal — DPROP1 authority requires a non-zero node identity\n", .{});
                        return error.DurableDeviceActivationFailed;
                    }
                    durable_device_state = onyx_server.daemon.durable_credential_props_boot.load(
                        allocator,
                        &account_store.?,
                        local_origin,
                    ) catch |err| {
                        std.debug.print("onyx-server: fatal — DPROP1 strict boot restore failed ({s})\n", .{@errorName(err)});
                        return err;
                    };
                    account_services.attachDurableCredentialProps(&durable_device_state.?);
                    srv_cfg.durable_device_boot = .{ .authoritative = .{
                        .state = &durable_device_state.?,
                        .local_origin_node = local_origin,
                    } };
                }
                if (ocg2_requested) {
                    const activation = onyx_server.daemon.config_boot.activateOcg2Store(
                        allocator,
                        &account_store.?,
                        h.ocg2,
                    ) catch |err| {
                        std.debug.print("onyx-server: fatal — OCG2 strict durable activation failed ({s})\n", .{@errorName(err)});
                        return err;
                    };
                    durable_oper_state = activation.state;
                    account_services.activateDurableOperAuthority(&durable_oper_state.?) catch |err| {
                        std.debug.print("onyx-server: fatal — OCG2 Services activation failed ({s})\n", .{@errorName(err)});
                        return err;
                    };
                    switch (h.ocg2.mode) {
                        .disabled => return error.Ocg2RuntimeActivationFailed,
                        .observe => {
                            const observer = try onyx_server.daemon.ocg2_runtime.createObserve(
                                allocator,
                                &account_services,
                            );
                            ocg2_observer = observer;
                            // Pair the wall sample with the immediately-following
                            // monotonic origin. Later timer ticks advance elapsed
                            // from this exact point, not from allocation/boot work.
                            const initial_realtime_ms: u64 = @intCast(@max(
                                @as(i64, 0),
                                onyx_server.substrate.platform.realtimeMillis(),
                            ));
                            const origin_ms: u64 = @intCast(@max(
                                @as(i64, 0),
                                onyx_server.substrate.platform.monotonicMillis(),
                            ));
                            const initial = observer.tick(initial_realtime_ms, 0);
                            switch (initial) {
                                .complete => |summary| std.debug.print(
                                    "onyx-server: OCG2 observe runtime primed ({s}; {s}; {d} durable record(s); no privilege consumer)\n",
                                    .{ @tagName(activation.source), @tagName(ocg2_role.?), summary.baseline_count },
                                ),
                                .retryable => |reason| {
                                    std.debug.print("onyx-server: fatal — OCG2 observe runtime could not establish its initial durable horizon ({s})\n", .{@tagName(reason)});
                                    return error.Ocg2RuntimeActivationFailed;
                                },
                                .failed => |reason| {
                                    std.debug.print("onyx-server: fatal — OCG2 observe runtime failed during initial inspection ({s})\n", .{@tagName(reason)});
                                    return error.Ocg2RuntimeActivationFailed;
                                },
                                .disabled => return error.Ocg2RuntimeActivationFailed,
                            }
                            srv_cfg.ocg2_runtime = observer;
                            srv_cfg.ocg2_runtime_monotonic_origin_ms = origin_ms;
                        },
                        .project, .mint => {
                            if (h.ocg2.mode == .mint and ocg2_role.? != .authority) {
                                std.debug.print("onyx-server: fatal — OCG2 mint is only available on the configured authority node\n", .{});
                                return error.Ocg2MintingRequiresAuthority;
                            }
                            const projection = try onyx_server.daemon.ocg2_projection_runtime.Runtime.initDefault(
                                allocator,
                                &account_services,
                            );
                            ocg2_projection = projection;
                            ocg2_audit_storage = onyx_server.daemon.audit_trail.AuditTrail.init(allocator);
                            const audit = &ocg2_audit_storage.?;
                            const initial_realtime_ms: u64 = @intCast(@max(
                                @as(i64, 0),
                                onyx_server.substrate.platform.realtimeMillis(),
                            ));
                            const origin_ms: u64 = @intCast(@max(
                                @as(i64, 0),
                                onyx_server.substrate.platform.monotonicMillis(),
                            ));
                            const primed = try onyx_server.daemon.ocg2_live_projection.projectOnce(
                                allocator,
                                projection,
                                &.{},
                                audit,
                                initial_realtime_ms,
                                0,
                            );
                            switch (primed) {
                                .committed, .unchanged => std.debug.print(
                                    "onyx-server: OCG2 {s} runtime primed ({s}; {s}; projects durable authority onto live sessions)\n",
                                    .{ @tagName(h.ocg2.mode), @tagName(activation.source), @tagName(ocg2_role.?) },
                                ),
                                else => {
                                    std.debug.print("onyx-server: fatal — OCG2 {s} runtime could not prime its durable image\n", .{@tagName(h.ocg2.mode)});
                                    return error.Ocg2RuntimeActivationFailed;
                                },
                            }
                            srv_cfg.ocg2_projection = projection;
                            srv_cfg.ocg2_projection_origin_ms = origin_ms;
                            srv_cfg.ocg2_audit = audit;
                        },
                    }
                }
                // Seed config-declared oper certfp bindings so SASL EXTERNAL works
                // certfp-only without a prior runtime CERTADD. Coexists with (never
                // wipes) runtime CERTADD binds; malformed entries warn-and-skip.
                const seeded = onyx_server.daemon.config_boot.seedOperCertfpBinds(&certfp_binds, h.parsed.opers);
                if (seeded != 0) std.debug.print("onyx-server: seeded {d} oper certfp binding(s) from config\n", .{seeded});
                // Backfill SCRAM credentials from the durable mirror on a miss,
                // so a SCRAM-SHA-256 login resolves after a restart.
                scram_store.setLoader(account_services.scramLoader());
                account_checker = .{ .services = &account_services };
                external_bridge = .{ .services = &account_services };
                session_token_bridge = .{ .services = &account_services };
                srv_cfg.sasl_checker = account_checker.checker();
                srv_cfg.sasl_scram256 = scram_store.scram256Lookup();
                srv_cfg.sasl_scram512 = scram_store.scram512Lookup();
                srv_cfg.sasl_external = external_bridge.lookup();
                srv_cfg.sasl_session_token = session_token_bridge.lookup();
                srv_cfg.account_services = &account_services;
                std.debug.print("onyx-server: SASL account store opened ({s}); PLAIN + SCRAM-SHA-256 + SCRAM-SHA-512 + EXTERNAL + SESSION-TOKEN live\n", .{db});
            } else |err| {
                if (builtin.os.tag == .windows or dprop_requested or ocg2_requested or native_incoming != null) {
                    std.debug.print("onyx-server: fatal — configured account store required for durable authority state could not open ({s})\n", .{@errorName(err)});
                    return err;
                }
                std.debug.print("onyx-server: account store error ({s}); SASL disabled\n", .{@errorName(err)});
            }
        }
    }
    if (held) |h| {
        if (srv_cfg.sasl_enabled) {
            const oauth_key_config: ?onyx_server.daemon.oauth_jwt.Key = if (h.parsed.sasl.oauth_hmac_key) |key|
                .{ .hs256 = key }
            else if (h.parsed.sasl.oauth_jwks_file) |path| jwks: {
                oauth_jwks_text = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20)) catch |err| {
                    if (builtin.os.tag == .windows or native_incoming != null) return err;
                    std.debug.print("onyx-server: OAuth JWKS read failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
                    break :jwks null;
                };
                oauth_key = onyx_server.daemon.oauth_jwt.OwnedKey.fromJwks(allocator, oauth_jwks_text.?) catch |err| {
                    if (builtin.os.tag == .windows or native_incoming != null) return err;
                    std.debug.print("onyx-server: OAuth JWKS parse failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
                    break :jwks null;
                };
                break :jwks oauth_key.?.key;
            } else if (h.parsed.sasl.oauth_pubkey) |pubkey| pubkey_blk: {
                oauth_key = onyx_server.daemon.oauth_jwt.OwnedKey.fromPubkey(allocator, pubkey) catch |err| {
                    if (builtin.os.tag == .windows or native_incoming != null) return err;
                    std.debug.print("onyx-server: OAuth public key parse failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
                    break :pubkey_blk null;
                };
                break :pubkey_blk oauth_key.?.key;
            } else null;

            if (oauth_key_config) |key| {
                oauth_verifier = .{
                    .key = key,
                    .issuer = h.parsed.sasl.oauth_issuer,
                    .audience = h.parsed.sasl.oauth_audience,
                    .account_claim = h.parsed.sasl.oauth_account_claim orelse "sub",
                };
                srv_cfg.sasl_oauthbearer = oauth_verifier.lookup();
                std.debug.print("onyx-server: SASL OAUTHBEARER live (local JWT verification)\n", .{});
            }
        }
    }

    // Hostname cloaking: derive the cloak key from `[cloak] secret`, or generate
    // a random per-boot key so a client's real IP is never shown to other users
    // by default.
    //
    // The secret is stretched through Argon2id (memory-hard) with a fixed
    // domain-separation salt, NOT a bare `SHA256(secret)`. The whole cloak
    // security model rests on key secrecy (the IPv4 input space is fully
    // enumerable), so a low-entropy operator passphrase must not be
    // offline-brute-forceable: SHA256 costs one hash per guess, Argon2id costs
    // ~64 MiB + t iterations per guess. Derivation is deterministic (fixed salt),
    // so cloaked hosts stay stable across restarts and identical mesh-wide.
    //
    // MIGRATION NOTE: this changes the derived key for any existing deployment
    // with a `[cloak] secret`, so every client's cloak reshuffles ONCE on the
    // first boot after this upgrade. Pre-upgrade host/subnet WARD bans on the
    // old SHA256-derived cloaks do NOT carry over — they were computed under a
    // key the daemon can no longer reproduce, so `previous_secret` grace applies
    // only to FUTURE rotations under this new Argon2id KDF, not to the SHA256→
    // Argon2id transition itself. That one-time invalidation is the accepted cost
    // of retiring the weak KDF. (Separately, `[cloak] anon_epoch_secs` defaults to
    // 24 h, so anonymous clients also switch from the hierarchical `.ip` cloak to
    // the opaque `.opq` epoch cloak on upgrade unless the operator sets it to 0.)
    var cloak_key_bytes: [onyx_server.proto.cloak.key_len]u8 = undefined;
    const cloak_kdf_params = onyx_server.crypto.argon2_kdf.default_params;
    const cloak_kdf_salt = onyx_server.crypto.argon2_kdf.cloak_key_salt;
    if (held) |h| {
        if (h.parsed.cloak.secret) |secret| {
            if (onyx_server.crypto.argon2_kdf.deriveKey(allocator, &cloak_key_bytes, secret, cloak_kdf_salt, cloak_kdf_params)) {
                srv_cfg.cloak_key = onyx_server.proto.cloak.SecretKey.init(cloak_key_bytes);
                if (comptime builtin.os.tag == .windows) srv_cfg.windows_helix_explicit_cloak_secret = true;
            } else |err| {
                if (windows_transfer != null) windows_driver.candidateAbortNow();
                // Only reachable under catastrophic conditions (OOM for the
                // 64 MiB scratch / thread-spawn failure). Leave cloak_key null so
                // the random per-boot fallback below still keeps privacy on, and
                // warn loudly (the mesh-federation caveat is printed there too).
                std.debug.print("onyx-server: cloak key derivation failed ({s}); falling back to a per-boot random key\n", .{@errorName(err)});
            }
        }
        // Previous cloak key (`[cloak] previous_secret`): kept live across a key
        // rotation so WARD host/mask bans written under the old key keep matching.
        // Derived through the same Argon2id path so old and new keys agree on KDF.
        if (h.parsed.cloak.previous_secret) |prev| {
            var prev_bytes: [onyx_server.proto.cloak.key_len]u8 = undefined;
            if (onyx_server.crypto.argon2_kdf.deriveKey(allocator, &prev_bytes, prev, cloak_kdf_salt, cloak_kdf_params)) {
                srv_cfg.cloak_prev_key = onyx_server.proto.cloak.SecretKey.init(prev_bytes);
            } else |err| {
                if (comptime builtin.os.tag == .windows) srv_cfg.windows_helix_explicit_cloak_secret = false;
                if (windows_transfer != null) windows_driver.candidateAbortNow();
                std.debug.print("onyx-server: previous cloak key derivation failed ({s}); rotation grace disabled this boot\n", .{@errorName(err)});
            }
            std.crypto.secureZero(u8, &prev_bytes);
        }
        // Network-identifying cloak suffix (`[cloak] suffix`); borrowed from
        // the held config, which outlives the server.
        if (h.parsed.cloak.suffix) |suffix| srv_cfg.cloak_suffix = suffix;
        // IP cloak granularity (`[cloak] mode`): "opaque" selects the single-token
        // max-privacy form; anything else (incl. null) keeps the hierarchical,
        // subnet-bannable default.
        if (h.parsed.cloak.mode) |mode| srv_cfg.cloak_opaque = std.mem.eql(u8, mode, "opaque");
        // Per-account cloak (`[cloak] account_cloak`): logged-in clients show
        // <account>.users.<suffix>.
        srv_cfg.cloak_account = h.parsed.cloak.account_cloak;
        // Anonymous-cloak rotation cadence (`[cloak] anon_epoch_secs`): non-zero
        // routes unauthenticated clients to the epoch-salted opaque cloak.
        srv_cfg.cloak_anon_epoch_secs = h.parsed.cloak.anon_epoch_secs;
    }
    if (srv_cfg.cloak_key == null) {
        if (windows_transfer != null) windows_driver.candidateAbortNow();
        init.io.random(&cloak_key_bytes);
        srv_cfg.cloak_key = onyx_server.proto.cloak.SecretKey.init(cloak_key_bytes);
        std.debug.print("onyx-server: cloak key generated (per-boot; set [cloak] secret to persist)\n", .{});
        // On a MESHED node a per-boot random cloak key is a federation hazard:
        // cloaked hosts differ per node and change on every restart, so
        // `*!*@<cloak>` and subnet WARD bans neither cross the mesh nor survive a
        // restart. Warn loudly so the operator sets one shared [cloak] secret.
        if (held) |h| {
            if (h.parsed.meshCloakSecretMissing())
                std.debug.print("onyx-server: WARNING — meshed node has NO shared [cloak] secret; per-boot cloak keys break host/subnet ban federation and persistence. Set the SAME [cloak] secret on every mesh node.\n", .{});
        }
    }
    // `srv_cfg.cloak_key` owns its own copy of the key; the local scratch buffer
    // has served both the Argon2id-derive and random-fallback consumers, so wipe
    // it — no live key material should linger on main's stack.
    std.crypto.secureZero(u8, &cloak_key_bytes);

    if (comptime builtin.os.tag == .windows) {
        if (windows_source_digest_boot) |source| {
            if ((srv_cfg.geoip_db_path.len != 0) != (windows_geo.city != null) or
                (srv_cfg.geoip_asn_db_path.len != 0) != (windows_geo.asn != null))
            {
                if (windows_transfer != null) windows_driver.candidateAbortNow();
                return error.InvalidWindowsGeoOwner;
            }
            const effective: ?windows_config_proof.Digest = windowsStaticEffectiveConfigDigest(
                source,
                tls_loaded != null,
                tls_sni_loaded.items,
                if (tls_ech_loaded) |loaded| loaded.keys else &.{},
                if (webpush_vapid) |*key| key else null,
                oauth_jwks_text,
                if (node_id_holder) |*identity| identity else null,
                srv_cfg.cloak_key,
                srv_cfg.cloak_prev_key,
                windows_geo.cityBytes(),
                windows_geo.asnBytes(),
            ) catch |err| blk: {
                if (windows_transfer != null) windows_driver.candidateAbortNow();
                std.debug.print("onyx-server: Windows Helix config proof unavailable ({s})\n", .{@errorName(err)});
                break :blk null;
            };
            srv_cfg.windows_helix_source_digest = effective;
            windows_runtime_driver.config_path = srv_cfg.config_path;
            windows_runtime_driver.source_digest = effective;
            if (windows_transfer == null and effective != null)
                srv_cfg.native_upgrade_hooks = windows_runtime_driver.hooks();
            if (windows_transfer) |*transfer| {
                const own = effective orelse windows_driver.candidateAbortNow();
                if (!std.crypto.timing_safe.eql(windows_config_proof.Digest, own, transfer.source_digest))
                    windows_driver.candidateAbortNow();
            }
        } else if (windows_transfer != null) windows_driver.candidateAbortNow();
    }

    // Background forward-confirmed reverse-DNS resolver: client IPs are resolved
    // off the accept path so hosts present a cloaked hostname rather than a
    // cloaked IP. Inert (no thread) when system DNS has no nameservers.
    var rdns_resolver: ?onyx_server.daemon.rdns.Resolver = if (comptime builtin.os.tag == .windows)
        try onyx_server.daemon.rdns.Resolver.initConfigured(
            allocator,
            init.io,
            onyx_server.proto.dns.systemResolverConfig(),
        )
    else
        onyx_server.daemon.rdns.Resolver.init(allocator) catch null;
    defer if (rdns_resolver) |*r| r.deinit();
    if (rdns_resolver) |*r| {
        if (native_incoming == null and windows_transfer == null) {
            r.start();
            if (comptime builtin.os.tag == .windows) {
                if (r.cfg.nameserver_count != 0 and r.thread == null) return error.RdnsWorkerUnavailable;
            }
        }
        srv_cfg.rdns = r;
    }

    // Connect-time DNS blocklist: built only when `[dnsbl]` is enabled with at
    // least one zone. Each client IP is checked off the accept path and a listed
    // IP is refused (or network-banned) at registration. Inert otherwise.
    var dnsbl_res: ?onyx_server.daemon.dnsbl_resolver.Resolver = null;
    defer if (dnsbl_res) |*r| r.deinit();
    if (held) |h| {
        if (comptime builtin.os.tag == .windows) {
            if (h.parsed.dnsbl.enabled and h.parsed.dnsbl.zones.len == 0) return error.DnsblNoZones;
        }
        if (h.parsed.dnsbl.enabled and h.parsed.dnsbl.zones.len != 0) {
            dnsbl_res = if (comptime builtin.os.tag == .windows)
                try onyx_server.daemon.dnsbl_resolver.Resolver.initConfigured(
                    allocator,
                    init.io,
                    onyx_server.proto.dns.systemResolverConfig(),
                    h.parsed.dnsbl.zones,
                )
            else
                onyx_server.daemon.dnsbl_resolver.Resolver.init(allocator, h.parsed.dnsbl.zones) catch |err| blk: {
                    if (native_incoming != null) return err;
                    break :blk null;
                };
            if (dnsbl_res) |*r| {
                if (comptime builtin.os.tag == .windows) {
                    if (windows_transfer != null and r.cfg.nameserver_count == 0) windows_driver.candidateAbortNow();
                }
                if (native_incoming == null and windows_transfer == null) {
                    if (comptime builtin.os.tag == .windows) try r.startChecked() else r.start();
                }
                srv_cfg.dnsbl = r;
                srv_cfg.dnsbl_ward = h.parsed.dnsbl.ward;
            }
        }
    }

    // Background SMTP submission sender: built only when `[mail]` is enabled with
    // a relay host + sender address. Delivers account email-verification codes
    // out-of-band. Inert otherwise (emails are recorded unverified).
    var mail_trust: ?[]u8 = null;
    defer if (mail_trust) |bytes| allocator.free(bytes);
    var mail_failure_path: ?[]u8 = null;
    defer if (mail_failure_path) |path| allocator.free(path);
    var mail_anchor_slot: [1][]const u8 = undefined;
    var mail_send: ?onyx_server.daemon.mail_sender.Sender = null;
    defer if (mail_send) |*m| m.deinit();
    if (held) |h| {
        const m = h.parsed.mail;
        if (m.enabled) {
            if (m.relay_host) |relay| if (m.from) |from| {
                if (comptime builtin.os.tag == .windows) {
                    const account_db = h.parsed.sasl.account_db orelse return error.MailAccountStoreRequired;
                    mail_failure_path = try std.fmt.allocPrint(allocator, "{s}/mail-failures.wal", .{std.fs.path.dirname(account_db) orelse "."});
                }
                var anchors: []const []const u8 = &.{};
                if (m.trust_store_path) |path| {
                    mail_trust = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20)) catch |err| blk: {
                        if (comptime builtin.os.tag == .windows) return err;
                        if (native_incoming != null) return err;
                        std.debug.print("mail: cannot read trust store {s}: {s}\n", .{ path, @errorName(err) });
                        break :blk null;
                    };
                    if (mail_trust) |bytes| if (bytes.len != 0) {
                        mail_anchor_slot[0] = bytes;
                        anchors = &mail_anchor_slot;
                    };
                }
                mail_send = onyx_server.daemon.mail_sender.Sender.init(allocator, .{
                    .relay_host = relay,
                    .relay_port = m.relay_port,
                    .starttls = m.starttls,
                    .insecure_skip_verify = m.insecure_skip_verify,
                    .trust_anchors = anchors,
                    .ehlo_domain = srv_cfg.server_name,
                    .from = from,
                    .user = m.user,
                    .pass = m.pass,
                    .failure_wal = if (comptime builtin.os.tag == .windows) mail_failure_path.? else "mail-failures.wal",
                    .failure_io = init.io,
                    .failure_dir = std.Io.Dir.cwd(),
                    .private_failure_windows = builtin.os.tag == .windows,
                }) catch |err| blk: {
                    if (comptime builtin.os.tag == .windows) return err;
                    if (native_incoming != null) return err;
                    break :blk null;
                };
                if (mail_send) |*s| {
                    if (comptime builtin.os.tag == .windows) {
                        // HXMA source capture and candidate parked restore both
                        // require the actual bound pause clock before start.
                        try s.prepareColdResources(init.io);
                    }
                    if (native_incoming == null and windows_transfer == null) {
                        if (comptime builtin.os.tag == .windows) try s.startChecked() else s.start();
                    }
                    srv_cfg.mail_sender = s;
                }
            };
        }
    }

    // IRCv3 STS: when an operator enables `[sts]` AND a TLS listener is live,
    // build the advertised wire value so each session's `sts` cap is offered.
    // STS without a live TLS port would strand clients, so require both.
    var sts_value_buf: [onyx_server.proto.sts.MAX_VALUE_LEN]u8 = undefined;
    if (held) |h| {
        if (h.sts.enabled) {
            if (srv_cfg.tls_cert_chain.len != 0) {
                const policy = onyx_server.proto.sts_policy.Policy{
                    .duration_seconds = h.sts.duration,
                    .port = h.sts.port,
                    .preload = h.sts.preload,
                };
                if (onyx_server.proto.sts_policy.writeCapValue(policy, .combined, &sts_value_buf)) |value| {
                    srv_cfg.sts_value = value;
                    std.debug.print("onyx-server: STS advertised ({s})\n", .{value});
                } else |err| {
                    if (comptime builtin.os.tag == .windows) return err;
                    std.debug.print("onyx-server: STS value error ({s}); STS disabled\n", .{@errorName(err)});
                }
            } else {
                if (comptime builtin.os.tag == .windows) return error.StsTlsListenerRequired;
                std.debug.print("onyx-server: [sts] enabled but no TLS listener; STS NOT advertised\n", .{});
            }
        }
    }

    // Sharded reactor pool across cores (SO_REUSEPORT clients; S2S pinned to
    // reactor 0). OPT-IN: default 1 (single in-line reactor). Set [limits]
    // num_shards > 1 to run that many reactor threads. Multi-reactor is correct
    // under the Phase-B coarse lock (`onCompletion` brackets every completion in
    // world.lockWrite, serializing all shared-state work; the per-reactor clients
    // table + send buffers are reactor-local) and is exercised by the
    // "multi-reactor (num_shards=4) survives concurrent clients" test. It stays
    // opt-in rather than CPU-defaulted because the live mesh deployment should
    // adopt it deliberately, and under the coarse lock the win is parallel I/O,
    // not parallel command processing.
    //
    // The earlier multi-reactor "flap" was THREE bugs, all fixed: (1) the
    // reciprocal-dial collision/redial loop; (2) accepted sockets not being
    // CLOEXEC, so every USR2 deploy stranded the mesh (d06b8f4); and (3) the one
    // that presented as a live "flap" — LUSERS/MAP counted peers + users from the
    // QUERYING shard's own connection set (S2S links live only on reactor 0, so a
    // LUSERS answered by shards 1..N under-reported, and a reconnecting probe
    // sampled that as 1<->2 oscillation). Fixed: servers come from a reactor-0
    // atomic, users from the shared world nick registry.

    if (comptime builtin.os.tag == .openbsd) {
        if (native_incoming != null) {
            resolver_ctx.record_paths = false;
            try onyx_server.daemon.kernel_other.pledgeInheritedRuntime();
        } else try installOpenBsdSandbox(allocator, init.io, srv_cfg, if (held) |*h| &h.parsed else null, &resolver_ctx, if (managed_incoming) |*incoming| &incoming.state.context else null);
    } else if (comptime builtin.os.tag == .linux or builtin.os.tag == .freebsd or builtin.os.tag == .windows) {
        onyx_server.daemon.server.installDaemonKernelSandbox(srv_cfg.config_path) catch |err| {
            std.debug.print("onyx-server: fatal — kernel sandbox: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    }

    if (windows_transfer) |*transfer| {
        windows_rows = WindowsInheritedRows.init(allocator, transfer.rows) catch windows_driver.candidateAbortNow();
        windows_barrier = .{ .child = &windows_child.?, .transfer = transfer, .deadline = windows_deadline };
        srv_cfg.native_listener_manifest = windows_rows.?.listeners;
        srv_cfg.inherited_state_fds = windows_rows.?.state_fds;
        srv_cfg.inherited_state_fd_manifest_present = true;
        srv_cfg.inherited_state_fd_manifest_valid = true;
        srv_cfg.native_arena_bytes = transfer.plaintext;
        srv_cfg.native_adopt_barrier = windows_barrier.?.asServerBarrier();
    }

    const Server = onyx_server.daemon.server.Server;
    // `init` copies LinuxServer onto the caller stack, which no longer fits
    // the default 8MB main thread. `initInPlace` fills this heap slot.
    const srv = allocator.create(Server) catch |err| {
        std.debug.print("onyx-server: fatal — cannot allocate server: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer allocator.destroy(srv);
    if (windows_transfer) |*transfer| transfer.stageInert() catch |err| {
        std.debug.print("onyx-server: Windows Helix socket staging failed ({s})\n", .{@errorName(err)});
        windows_driver.candidateAbortNow();
    };
    srv.initInPlace(allocator, srv_cfg) catch |err| {
        if (windows_transfer != null) {
            std.debug.print("onyx-server: Windows Helix inert server init failed ({s})\n", .{@errorName(err)});
            windows_driver.candidateAbortNow();
        }
        // The reactor requires io_uring on a 64-bit Linux kernel. If it is
        // unavailable (old kernel / restricted sandbox) the daemon cannot serve,
        // so fail loudly and exit non-zero rather than pretending to have started.
        std.debug.print("onyx-server: fatal — cannot start server: {s}\n", .{@errorName(err)});
        const reactor = switch (comptime builtin.os.tag) {
            .windows => "IOCP",
            .freebsd, .openbsd, .netbsd, .dragonfly => "kqueue",
            else => "io_uring on a 64-bit Linux kernel",
        };
        std.debug.print("onyx-server: the reactor requires {s}.\n", .{reactor});
        std.process.exit(1);
    };
    defer srv.deinit();
    // This owner borrows TLS material retained by main and, on Windows, is
    // published to Server for the source's exact paused Helix capture. Gate
    // workers must join before this defer closes the inherited UDP socket.
    var wt_listener: ?onyx_server.daemon.webtransport_listener.WebTransportListener = null;
    defer if (wt_listener) |*owner| {
        if (comptime builtin.os.tag == .windows) srv.setWindowsWebTransportOwner(null) catch @panic("Windows WebTransport owner could not detach");
        owner.deinit();
    };
    // Declare Web Push custody before the Windows Gate cleanup defer. A
    // Gate-owned worker must be joined and detached before shutdown frees its
    // queue, resolver, VAPID key, or trust anchors.
    const WebpushWorker = if ((builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) onyx_server.daemon.webpush.Worker else void;
    var webpush_trust_anchors: ?OwnedTrustAnchors = null;
    defer if (webpush_trust_anchors) |*owner| owner.deinit();
    var webpush_worker: ?*WebpushWorker = null;
    var webpush_resolver: ?*onyx_server.daemon.acme_runner.SystemResolver = null;
    defer if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
        if (webpush_worker) |w| {
            w.shutdown();
            if (srv.webpush_worker == w) srv.webpush_worker = null;
            allocator.destroy(w);
        }
        if (webpush_resolver) |r| allocator.destroy(r);
    };
    if (comptime builtin.os.tag == .windows) {
        // The proof above covered these exact retained buffers. Transfer their
        // ownership to Server before any inherited state is adopted or served;
        // a later disk change cannot alter GeoIP/ASN results in either image.
        if (windows_geo.city) |owner| {
            srv.geoip_bytes = owner.bytes;
            srv.geoip_db = owner.database;
            windows_geo.city = null;
        }
        if (windows_geo.asn) |owner| {
            srv.geoip_asn_bytes = owner.bytes;
            srv.geoip_asn_db = owner.database;
            windows_geo.asn = null;
        }
        srv.geoip_tried = true;
        srv.geoip_asn_tried = true;
        if (windows_transfer) |*transfer| {
            if ((transfer.metrics != null) != (srv_cfg.metrics_port != 0)) windows_driver.candidateAbortNow();
            if (transfer.metrics) |*metrics| {
                srv.metrics_server = onyx_server.daemon.metrics_http.MetricsServer.initTransferred(
                    &srv.metrics_snapshot,
                    &metrics.transfer,
                    &metrics.carry,
                    .{ .bind_addr = srv_cfg.metrics_bind_addr },
                    1024 * 1024,
                ) catch |err| {
                    std.debug.print("onyx-server: Windows Helix metrics import failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
                srv.metrics_server.?.prepareColdResources(init.io) catch windows_driver.candidateAbortNow();
            }
            if ((transfer.webhook != null) != srv_cfg.webhook_enabled) windows_driver.candidateAbortNow();
            if (transfer.webhook) |*webhook| {
                srv.stageWindowsInheritedWebhook(&webhook.transfer, &webhook.carry, init.io) catch |err| {
                    std.debug.print("onyx-server: Windows Helix webhook import failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (transfer.history) |*history| {
                // HXHH pins the source's entire TLS policy. Candidate boot
                // material must reproduce it exactly before the source can
                // retire; a history endpoint with other runtime-only material
                // is refused instead of silently changing its TLS identity.
                if (srv_cfg.tls_cert_chain.len == 0) windows_driver.candidateAbortNow();
                srv.stageWindowsInheritedHistory(&history.transfer, &history.carry, .{
                    .cert_chain = srv_cfg.tls_cert_chain,
                    .signing_key = srv_cfg.tls_signing_key,
                    .ecdsa_p256_signing_key = srv_cfg.tls_ecdsa_signing_key,
                    .rsa_signing_key = srv_cfg.tls_rsa_signing_key,
                    .sni_certs = srv_cfg.tls_sni_certs,
                    .ech_keys = srv_cfg.tls_ech_keys,
                    .enable_raw_public_key = srv_cfg.tls_raw_public_key,
                }, init.io) catch |err| {
                    std.debug.print("onyx-server: Windows Helix history HTTPS import failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
                if (!history.transfer.consumed) windows_driver.candidateAbortNow();
            }
            if ((transfer.history != null) != (srv.history_https != null)) windows_driver.candidateAbortNow();
            const active_media = transfer.media_graph_receiver != null;
            if (active_media and (transfer.webrtc_media_udp != null or transfer.native_media_udp != null))
                windows_driver.candidateAbortNow();
            if (!active_media and ((transfer.webrtc_media_udp != null) != srv_cfg.media_enabled or
                (transfer.native_media_udp != null) != srv_cfg.media_enabled))
                windows_driver.candidateAbortNow();
            if (active_media and !srv_cfg.media_enabled) windows_driver.candidateAbortNow();
            if (srv_cfg.media_enabled) {
                if (active_media) {
                    const max_wire_bytes = onyx_server.daemon.helix.native_windows_active_media_snapshot.max_wire_bytes;
                    const native_limits: onyx_server.daemon.helix.native_windows_active_media_snapshot.Limits = .{
                        .max_participants = @min(srv_cfg.media_max_participants, onyx_server.daemon.native_media_transport.max_call_participants),
                        .max_state_bytes = max_wire_bytes,
                    };
                    const webrtc_limits: onyx_server.daemon.media_plane.PhysicalSnapshot.Limits = .{
                        .max_rows = onyx_server.daemon.helix.media_graph_checkpoint.max_rows / 2,
                        .max_offered = onyx_server.daemon.helix.media_graph_checkpoint.max_rows / 2,
                        .max_bytes = max_wire_bytes,
                        .transport = .{ .max_endpoints = onyx_server.daemon.helix.media_graph_checkpoint.max_rows / 2, .max_groups = onyx_server.daemon.helix.media_graph_checkpoint.max_rows / 2, .max_bytes = max_wire_bytes },
                    };
                    windows_active_media_graph = (transfer.takeMediaGraph(allocator) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active media graph decode failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                    windows_active_media_native = (transfer.takeMediaNative(allocator, native_limits) catch |err| {
                        std.debug.print("onyx-server: Windows Helix native media decode failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                    windows_active_media_webrtc = (transfer.takeMediaWebrtc(allocator, webrtc_limits) catch |err| {
                        std.debug.print("onyx-server: Windows Helix WebRTC media decode failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                    var native_udp = (transfer.takeActiveNativeUdp(allocator) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active native UDP custody failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                    defer native_udp.deinit();
                    const webrtc_udp = (transfer.takeActiveWebrtcUdp(allocator, &windows_active_media_webrtc.?) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active WebRTC UDP custody failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                    srv.stageWindowsInheritedActiveMedia(
                        native_udp.transfer,
                        &native_udp.carry,
                        webrtc_udp.transfer,
                        &windows_active_media_webrtc.?,
                        webrtc_limits,
                        init.io,
                    ) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active media UDP import failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                    srv.setWindowsActiveMediaCandidate(.{
                        .graph = &windows_active_media_graph.?,
                        .native = &windows_active_media_native.?,
                        .webrtc = &windows_active_media_webrtc.?,
                        .native_limits = native_limits,
                        .webrtc_limits = webrtc_limits,
                    }) catch windows_driver.candidateAbortNow();
                } else {
                    const webrtc = if (transfer.webrtc_media_udp) |*owner| owner else windows_driver.candidateAbortNow();
                    const native = if (transfer.native_media_udp) |*owner| owner else windows_driver.candidateAbortNow();
                    srv.stageWindowsInheritedMedia(
                        &webrtc.transfer,
                        &webrtc.carry,
                        &native.transfer,
                        &native.carry,
                        init.io,
                    ) catch |err| {
                        std.debug.print("onyx-server: Windows Helix media UDP import failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                    srv.prepareWindowsInheritedMediaRouting() catch |err| {
                        std.debug.print("onyx-server: Windows Helix media routing preparation failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                }
            }
            const active_wt = transfer.active_webtransport_receiver != null;
            if ((transfer.webtransport_udp != null and active_wt) or
                ((transfer.webtransport_udp != null or active_wt) != (srv_cfg.webtransport_port != 0)))
                windows_driver.candidateAbortNow();
            if (transfer.webtransport_udp != null or active_wt) {
                // Both idle and established QUIC owners borrow the exact
                // serving certificate authenticated by the source arena.
                windows_wt_tls_material = windows_tls_material.preflightOwnedFromArena(
                    allocator,
                    transfer.plaintext,
                ) catch |err| {
                    std.debug.print("onyx-server: Windows Helix serving TLS preflight failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
                const source_tls = windows_wt_tls_material.?.default orelse windows_driver.candidateAbortNow();
                const signing_key: onyx_server.proto.quic_handshake.SigningKey =
                    if (source_tls.ecdsa_p256_signing_key) |key| .{ .ecdsa_p256 = key } else if (source_tls.signing_key) |key| .{ .ed25519 = key } else if (source_tls.rsa_signing_key) |key| .{ .rsa = key } else windows_driver.candidateAbortNow();
                const irc_port = srv.boundPort() catch windows_driver.candidateAbortNow();
                const wt_tls: onyx_server.daemon.webtransport_listener.TlsConfig = .{
                    .cert_chain = source_tls.cert_chain,
                    .signing_key = signing_key,
                };
                if (active_wt)
                    windows_wt_active_body = (transfer.takeActiveWebtransport(allocator, wt_tls) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active WebTransport custody failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    }) orelse windows_driver.candidateAbortNow();
                const wt_expected = onyx_server.daemon.webtransport_listener.WebTransportListener.init(allocator, wt_tls, irc_port);
                const carry: *const onyx_server.daemon.webtransport_listener.Snapshot =
                    if (windows_wt_active_body) |*body| &body.snapshot.base else if (transfer.webtransport_udp) |*owner| &owner.carry else windows_driver.candidateAbortNow();
                carry.validateConfiguration(wt_tls, .{
                    .irc_port = wt_expected.irc_port,
                    .send_proxy_header = wt_expected.send_proxy_header,
                    .echo_wt_datagrams = wt_expected.echo_wt_datagrams,
                    .max_connections = wt_expected.max_connections,
                    .retry_policy = wt_expected.retry_policy,
                    .retry_load_threshold = wt_expected.retry_load_threshold,
                    .reset_rate_per_s = wt_expected.reset_rate_per_s,
                    .reset_burst = wt_expected.reset_burst,
                }) catch windows_driver.candidateAbortNow();
                if (windows_wt_active_body) |*body| {
                    wt_listener = onyx_server.daemon.webtransport_listener.WebTransportListener.initTransferred(
                        allocator,
                        wt_tls,
                        &body.udp_transfer,
                        carry,
                    ) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active WebTransport UDP import failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                } else {
                    const webtransport = if (transfer.webtransport_udp) |*owner| owner else windows_driver.candidateAbortNow();
                    wt_listener = onyx_server.daemon.webtransport_listener.WebTransportListener.initTransferred(
                        allocator,
                        wt_tls,
                        &webtransport.transfer,
                        carry,
                    ) catch |err| {
                        std.debug.print("onyx-server: Windows Helix WebTransport import failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                }
                if (wt_listener.?.port != srv_cfg.webtransport_port or wt_listener.?.irc_port != irc_port)
                    windows_driver.candidateAbortNow();
                wt_listener.?.irc_host = srv_cfg.host;
                if (windows_wt_active_body) |*body| {
                    wt_listener.?.prepareActiveConnectionsWindows(&body.snapshot, body.bridges) catch |err| {
                        std.debug.print("onyx-server: Windows Helix active WebTransport restore failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                }
                wt_listener.?.prepareInheritedResources(init.io) catch |err| {
                    std.debug.print("onyx-server: Windows Helix WebTransport preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
                srv.setWindowsWebTransportOwner(&wt_listener.?) catch windows_driver.candidateAbortNow();
                if (windows_wt_active_body) |*body|
                    srv.setWindowsActiveWebTransportCandidate(&body.snapshot, body.accepted) catch windows_driver.candidateAbortNow();
            }
        }
    }
    // A Windows successor must own its complete reactor runtime before READY.
    // Otherwise COMMIT can retire the predecessor and a later allocation or
    // shard spawn failure can strand every inherited client.
    // These owners outlive Gate cleanup. A parked OCSP worker must be joined
    // and detached before its owner and retained trust anchors are freed.
    const AcmeRenewalService = if ((builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) onyx_server.daemon.acme_renewal.Service else void;
    var acme_renewal: ?*AcmeRenewalService = null;
    defer if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
        if (acme_renewal) |s| {
            s.stop();
            if (comptime builtin.os.tag == .windows) {
                if (srv.acme_worker == s) srv.acme_worker = null;
            }
            allocator.destroy(s);
        }
    };
    const OcspStapleService = if ((builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) onyx_server.daemon.ocsp_staple.Service else void;
    var ocsp_trust_anchors: ?OwnedTrustAnchors = null;
    defer if (ocsp_trust_anchors) |*owner| owner.deinit();
    var ocsp_staple: ?*OcspStapleService = null;
    defer if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
        if (ocsp_staple) |s| {
            s.stop();
            if (srv.ocsp_worker == s) srv.ocsp_worker = null;
            allocator.destroy(s);
        }
    };
    const gate_mod = onyx_server.daemon.reactor_pool.runtime_start_gate;
    var run = std.atomic.Value(bool).init(true);
    var windows_runtime_gate: ?gate_mod.Created = null;
    defer if (comptime builtin.os.tag == .windows) {
        if (windows_runtime_gate) |gate| {
            if (gate.view.inspect().phase == .preparing) {
                gate.control.cancelAllAndJoin();
            } else {
                srv.requestStop(&run);
                if (srv.metrics_server) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (srv.webhook_server) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (srv.history_https) |*owner| if (owner.runtime_worker.view != null) owner.requestStopAndWake();
                if (wt_listener) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (srv.native_media.runtime.view != null) srv.native_media.requestStopAndWake();
                if (srv.media_plane.runtime.view != null) srv.media_plane.requestStopAndWake();
                if (rdns_resolver) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (dnsbl_res) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (mail_send) |*owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (acme_renewal) |owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (ocsp_staple) |owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (webpush_worker) |owner| if (owner.runtime.view != null) owner.requestStopAndWake();
                if (srv.geo.runtime.view != null) srv.geo.requestStopAndWake();
                gate.control.joinAll();
            }
            if (srv.metrics_server) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows metrics cleanup without joined owner");
            if (srv.webhook_server) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows webhook cleanup without joined owner");
            if (srv.history_https) |*owner| if (owner.runtime_worker.view != null)
                owner.detachAfterJoined() catch @panic("Windows history HTTPS cleanup without joined owner");
            if (wt_listener) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows WebTransport cleanup without joined owner");
            if (srv.native_media.runtime.view != null)
                srv.native_media.detachAfterJoined() catch @panic("Windows native media cleanup without joined owner");
            if (srv.media_plane.runtime.view != null)
                srv.media_plane.detachAfterJoined() catch @panic("Windows media plane cleanup without joined owner");
            if (rdns_resolver) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows rDNS cleanup without joined owner");
            if (dnsbl_res) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows DNSBL cleanup without joined owner");
            if (mail_send) |*owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows mail cleanup without joined owner");
            if (acme_renewal) |owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows ACME cleanup without joined owner");
            if (ocsp_staple) |owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows OCSP cleanup without joined owner");
            if (webpush_worker) |owner| if (owner.runtime.view != null)
                owner.detachAfterJoined() catch @panic("Windows Web Push cleanup without joined owner");
            if (srv.geo.runtime.view != null)
                srv.geo.detachAfterJoined() catch @panic("Windows Geo cleanup without joined owner");
            srv.detachRuntimeAfterJoined() catch @panic("Windows runtime cleanup without joined shard owners");
            srv.pool.deinit();
            srv.pool = onyx_server.daemon.reactor_pool.ReactorPool(*Server).init(allocator);
            gate.control.destroyJoined();
        }
    };
    // Before COMMIT, ordinary cleanup could shutdown predecessor-owned sockets.
    // Once adoption succeeds, this process owns them and must never abort via
    // ExitProcess for an optional worker failure.
    var windows_commit_confirmed = false;
    errdefer if (windows_transfer != null and !windows_commit_confirmed) windows_driver.candidateAbortNow();

    if (comptime builtin.os.tag == .windows) {
        if (held) |h| {
            if (h.parsed.geo.enabled) {
                // Source pause and candidate HXGE restore need the same bound
                // clock before any thread can run. The successor's real worker
                // is prepared below under the shared Gate instead of here.
                try srv.geo.prepareColdResources(init.io);
                if (windows_transfer == null) try srv.geo.startChecked();
            }
        }
    }

    // `|*h|`: `setAcmeTlsReloadConfig` and the renewal worker both retain
    // `&h.parsed.tls` past this block, so it must point at `held`'s function-scope
    // payload rather than a block-local copy.
    if (held) |*h| {
        if (h.acme.enabled) {
            if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
                srv.setAcmeTlsReloadConfig(&h.parsed.tls);
                const svc = try allocator.create(AcmeRenewalService);
                svc.* = AcmeRenewalService.init(allocator, init.io, srv, h.parsed.acme, &h.parsed.tls);
                acme_renewal = svc;
                if (comptime builtin.os.tag == .windows) {
                    // Pause and parked-restore both require the bound clock.
                    try svc.prepareColdResources(init.io);
                    srv.acme_worker = svc;
                }
            } else {
                std.debug.print("onyx-server: [acme] renewal is unavailable on this platform\n", .{});
            }
        }
    }

    // ── OCSP staple fetcher ([ocsp] enabled + on-disk TLS cert) ─────────────
    // A background worker fetches, verifies, and caches an OCSP response for the
    // leaf and publishes it to the live TLS config; the leaf CertificateEntry
    // (1.3) / CertificateStatus (1.2) then carries it when a client offers
    // status_request. Needs a real cert file (self-signed bootstrap leaves have
    // no AIA responder URL, so the worker simply no-ops there).
    // Capture by pointer (`|*h|`): the worker thread holds `&h.parsed.tls` for its
    // whole lifetime, so it must target `held`'s function-scope payload, not a
    // block-local copy that dies at the end of this `if`.
    if (held) |*h| {
        if (h.parsed.ocsp.enabled and h.parsed.tls.enabled and h.parsed.tls.cert_path != null) {
            if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) {
                var trust_anchors: []const []const u8 = &.{};
                const bundle_text: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(init.io, h.parsed.acme.ca_bundle_path, allocator, .limited(@intCast(h.parsed.acme.ca_bundle_max_bytes))) catch |err| blk: {
                    if (comptime builtin.os.tag == .windows) return err;
                    if (native_incoming != null) return err;
                    std.debug.print("onyx-server: [ocsp] trust store {s} unreadable ({s}); HTTPS responder fetches fail closed\n", .{ h.parsed.acme.ca_bundle_path, @errorName(err) });
                    break :blk null;
                };
                if (bundle_text) |text| {
                    defer allocator.free(text);
                    if (OwnedTrustAnchors.load(allocator, text)) |anchors| {
                        ocsp_trust_anchors = anchors;
                        trust_anchors = ocsp_trust_anchors.?.items();
                        std.debug.print("onyx-server: [ocsp] using daemon trust store {s} ({d} anchors)\n", .{ h.parsed.acme.ca_bundle_path, trust_anchors.len });
                    } else |err| {
                        if (comptime builtin.os.tag == .windows) return err;
                        if (native_incoming != null) return err;
                        std.debug.print("onyx-server: [ocsp] trust store parse failed ({s}); HTTPS responder fetches fail closed\n", .{@errorName(err)});
                    }
                }
                const svc = try allocator.create(OcspStapleService);
                errdefer allocator.destroy(svc);
                svc.* = OcspStapleService.init(allocator, init.io, srv, &h.parsed.tls, .{
                    .check_interval_ms = h.parsed.ocsp.check_interval_ms,
                });
                svc.trust_anchors = trust_anchors;
                if (comptime builtin.os.tag == .windows) try svc.prepareColdResources(init.io);
                ocsp_staple = svc;
                if (comptime builtin.os.tag == .windows) srv.ocsp_worker = svc;
            } else {
                std.debug.print("onyx-server: [ocsp] staple fetching is unavailable on this platform\n", .{});
            }
        } else if (h.parsed.ocsp.enabled) {
            if (comptime builtin.os.tag == .windows) return error.OcspCertificateRequired;
            std.debug.print("onyx-server: [ocsp] enabled but requires [tls] with an on-disk cert_path; disabled\n", .{});
        }
    }

    // ── Web Push delivery worker ([webpush] enabled + account store) ────────
    // Offline DMs (memo) nudge the recipient's browser through their push
    // service — payloads are RFC 8291-encrypted end-to-end to the browser.
    if (held) |h| {
        if (h.parsed.webpush.enabled) {
            if (comptime (builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows)) webpush_blk: {
                if (srv_cfg.account_services == null) {
                    if (comptime builtin.os.tag == .windows) return error.WebpushAccountStoreRequired;
                    std.debug.print("onyx-server: [webpush] enabled but no account store; web push disabled\n", .{});
                    break :webpush_blk;
                }
                // Trust anchors + resolver live for the process lifetime.
                const bundle_text = std.Io.Dir.cwd().readFileAlloc(init.io, h.parsed.acme.ca_bundle_path, allocator, .limited(@intCast(h.parsed.acme.ca_bundle_max_bytes))) catch |err| {
                    if (comptime builtin.os.tag == .windows) return err;
                    if (native_incoming != null) return err;
                    std.debug.print("onyx-server: [webpush] CA bundle read failed ({s}); web push disabled\n", .{@errorName(err)});
                    break :webpush_blk;
                };
                defer allocator.free(bundle_text);
                webpush_trust_anchors = OwnedTrustAnchors.load(allocator, bundle_text) catch |err| {
                    if (comptime builtin.os.tag == .windows) return err;
                    if (native_incoming != null) return err;
                    std.debug.print("onyx-server: [webpush] trust anchors failed ({s}); web push disabled\n", .{@errorName(err)});
                    break :webpush_blk;
                };
                if (comptime builtin.os.tag == .windows) {
                    if (webpush_trust_anchors.?.items().len == 0) return error.WebpushNoTrustAnchors;
                }
                const vapid = webpush_vapid orelse {
                    if (comptime builtin.os.tag == .windows) return error.WebpushVapidUnavailable;
                    webpush_trust_anchors.?.deinit();
                    webpush_trust_anchors = null;
                    std.debug.print("onyx-server: [webpush] no VAPID key; web push disabled\n", .{});
                    break :webpush_blk;
                };
                const resolver = try allocator.create(onyx_server.daemon.acme_runner.SystemResolver);
                resolver.* = .{
                    .allocator = allocator,
                    .io = init.io,
                    .resolv_conf_max_bytes = @intCast(h.parsed.acme.resolv_conf_max_bytes),
                    .dns_port = h.parsed.acme.dns_port,
                };
                webpush_resolver = resolver;
                const w = try allocator.create(WebpushWorker);
                w.* = .{
                    .allocator = allocator,
                    .vapid = vapid.key_pair,
                    .subject = h.parsed.webpush.subject,
                    .resolver = resolver.resolver(),
                    .trust_anchors = webpush_trust_anchors.?.items(),
                };
                webpush_worker = w;
                if (comptime builtin.os.tag == .windows) {
                    // Source capture and candidate restore both require the
                    // bound pause clock and authenticated resolver identity.
                    // This happens while the worker is still cold, before the
                    // candidate can decode inherited Web Push state.
                    w.prepareColdResources(init.io, resolver) catch |err| {
                        if (windows_transfer != null) windows_driver.candidateAbortNow();
                        return err;
                    };
                    srv.webpush_worker = w;
                }
                std.debug.print("onyx-server: web push live ({d} trust anchors; VAPID {s})\n", .{ webpush_trust_anchors.?.items().len, srv_cfg.webpush_vapid_pub });
            } else {
                std.debug.print("onyx-server: [webpush] enabled but {s}\n", .{onyx_server.daemon.webpush.portable_disable_reason});
            }
        }
    }

    // Helix successor adoption must finish before start() launches any
    // off-reactor producer (webhook/media/metrics workers). Starting first left
    // a window in which a new-process webhook could acknowledge and enqueue an
    // event behind the still-unapplied inherited World/session boundary.
    if (comptime builtin.os.tag == .windows) {
        if (windows_transfer != null) {
            // The inherited listener must be observable before predecessor
            // retirement. All worker threads park under this one owned Gate.
            _ = srv.boundPort() catch windows_driver.candidateAbortNow();
            srv.prepareRuntimeResources(srv.config.crypto_io orelse init.io, &run) catch |err| {
                std.debug.print("onyx-server: Windows Helix reactor resource preparation failed ({s})\n", .{@errorName(err)});
                windows_driver.candidateAbortNow();
            };
            var specs: [onyx_server.daemon.shard.max_shards + 13]gate_mod.ParticipantSpec = undefined;
            var slots: [onyx_server.daemon.shard.max_shards]gate_mod.Slot = undefined;
            const worker_count = if (srv.reactors.len == 1) 0 else srv.reactors.len;
            for (specs[0..worker_count], 0..) |*spec, index|
                spec.* = .{ .kind = .reactor, .instance = @intCast(index), .owner_identity = srv };
            var gate_count = worker_count;
            if (rdns_resolver) |*owner| {
                if (owner.cfg.nameserver_count != 0) {
                    specs[gate_count] = .{ .kind = .rdns, .instance = 0, .owner_identity = owner };
                    gate_count += 1;
                }
            }
            if (dnsbl_res) |*owner| {
                if (owner.cfg.nameserver_count == 0) windows_driver.candidateAbortNow();
                specs[gate_count] = .{ .kind = .dnsbl, .instance = 0, .owner_identity = owner };
                gate_count += 1;
            }
            if (mail_send) |*owner| {
                specs[gate_count] = .{
                    .kind = .mail,
                    .instance = 0,
                    .owner_identity = owner,
                    .options = onyx_server.daemon.mail_sender.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (acme_renewal) |owner| {
                specs[gate_count] = .{
                    .kind = .acme,
                    .instance = 0,
                    .owner_identity = owner,
                    .options = onyx_server.daemon.acme_renewal.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (ocsp_staple) |owner| {
                specs[gate_count] = .{
                    .kind = .ocsp,
                    .instance = 0,
                    .owner_identity = owner,
                    .options = onyx_server.daemon.ocsp_staple.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (webpush_worker) |owner| {
                specs[gate_count] = .{
                    .kind = .webpush,
                    .instance = 0,
                    .owner_identity = owner,
                    .options = onyx_server.daemon.webpush.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (srv.metrics_server) |*owner| {
                specs[gate_count] = .{ .kind = .metrics, .instance = 0, .owner_identity = owner };
                gate_count += 1;
            }
            if (srv.webhook_server) |*owner| {
                specs[gate_count] = .{ .kind = .webhook, .instance = 0, .owner_identity = owner };
                gate_count += 1;
            }
            if (srv.history_https) |*owner| {
                specs[gate_count] = .{
                    .kind = .history,
                    .instance = @intFromBool(owner.v6),
                    .owner_identity = owner,
                    .options = onyx_server.daemon.history_http.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (srv_cfg.media_enabled) {
                if (srv.native_media.socket == null or srv.media_plane.socket == null)
                    windows_driver.candidateAbortNow();
                specs[gate_count] = .{
                    .kind = .native_media,
                    .instance = 0,
                    .owner_identity = &srv.native_media,
                    .options = onyx_server.daemon.native_media_transport.dormant_spawn_options,
                };
                gate_count += 1;
                specs[gate_count] = .{
                    .kind = .media_plane,
                    .instance = 0,
                    .owner_identity = &srv.media_plane,
                    .options = onyx_server.daemon.media_plane.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (wt_listener) |*owner| {
                specs[gate_count] = .{
                    .kind = .webtransport,
                    .instance = 0,
                    .owner_identity = owner,
                    .options = onyx_server.daemon.webtransport_listener.dormant_spawn_options,
                };
                gate_count += 1;
            }
            if (srv_cfg.geo_enabled) {
                specs[gate_count] = .{
                    .kind = .geo,
                    .instance = 0,
                    .owner_identity = srv.geo,
                    .options = onyx_server.daemon.geo_services.dormant_spawn_options,
                };
                gate_count += 1;
            }
            const gate = gate_mod.create(allocator, srv.config.crypto_io orelse init.io, specs[0..gate_count]) catch |err| {
                std.debug.print("onyx-server: Windows Helix reactor gate preparation failed ({s})\n", .{@errorName(err)});
                windows_driver.candidateAbortNow();
            };
            windows_runtime_gate = gate;
            for (slots[0..worker_count], 0..) |*slot, index|
                slot.* = gate.view.slot(.reactor, @intCast(index), srv) catch windows_driver.candidateAbortNow();
            srv.prepareRuntimeWorkers(gate.control, gate.view, slots[0..worker_count]) catch |err| {
                std.debug.print("onyx-server: Windows Helix reactor worker preparation failed ({s})\n", .{@errorName(err)});
                windows_driver.candidateAbortNow();
            };
            if (srv_cfg.media_enabled) {
                srv.native_media.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.native_media, 0, &srv.native_media) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix native media worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
                srv.media_plane.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.media_plane, 0, &srv.media_plane) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix media plane worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (rdns_resolver) |*owner| {
                if (owner.cfg.nameserver_count != 0) {
                    owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.rdns, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                        std.debug.print("onyx-server: Windows Helix rDNS worker preparation failed ({s})\n", .{@errorName(err)});
                        windows_driver.candidateAbortNow();
                    };
                }
            }
            if (dnsbl_res) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.dnsbl, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix DNSBL worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (mail_send) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.mail, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix mail worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (acme_renewal) |owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.acme, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix ACME worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (ocsp_staple) |owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.ocsp, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix OCSP worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (webpush_worker) |owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.webpush, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix Web Push worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (srv.metrics_server) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.metrics, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix metrics worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (srv.webhook_server) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.webhook, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix webhook worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (srv.history_https) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.history, @intFromBool(owner.v6), owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix history HTTPS worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (wt_listener) |*owner| {
                owner.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.webtransport, 0, owner) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix WebTransport worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            if (srv_cfg.geo_enabled) {
                srv.geo.prepareDormantWorker(gate.control, gate.view, gate.view.slot(.geo, 0, srv.geo) catch windows_driver.candidateAbortNow()) catch |err| {
                    std.debug.print("onyx-server: Windows Helix Geo worker preparation failed ({s})\n", .{@errorName(err)});
                    windows_driver.candidateAbortNow();
                };
            }
            gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(srv.config.crypto_io orelse init.io, .{ .clock = .awake, .raw = .fromMilliseconds(30_000) })) catch |err| {
                std.debug.print("onyx-server: Windows Helix reactor workers did not park ({s})\n", .{@errorName(err)});
                windows_driver.candidateAbortNow();
            };
            srv.requirePreparedRuntime() catch windows_driver.candidateAbortNow();
            if (srv.metrics_server) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (srv.webhook_server) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (srv.history_https) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (wt_listener) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (srv_cfg.media_enabled) {
                srv.native_media.requireParked() catch windows_driver.candidateAbortNow();
                srv.media_plane.requireParked() catch windows_driver.candidateAbortNow();
            }
            if (rdns_resolver) |*owner| if (owner.cfg.nameserver_count != 0)
                owner.requireParked() catch windows_driver.candidateAbortNow();
            if (dnsbl_res) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (mail_send) |*owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (acme_renewal) |owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (ocsp_staple) |owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (webpush_worker) |owner| owner.requireParked() catch windows_driver.candidateAbortNow();
            if (srv_cfg.geo_enabled) srv.geo.requireParked() catch windows_driver.candidateAbortNow();
        }
    }
    if (comptime builtin.os.tag == .openbsd) {
        srv.adoptInheritedSessions() catch |err| {
            std.debug.print("onyx-server: native Helix adoption failed ({s})\n", .{@errorName(err)});
            if (native_incoming != null) std.posix.system._exit(125);
            return err;
        };
    } else if (comptime builtin.os.tag == .linux) try srv.adoptInheritedSessions();
    if (comptime builtin.os.tag == .windows) {
        if (windows_transfer != null) {
            srv.adoptInheritedSessions() catch |err| {
                std.debug.print("onyx-server: Windows Helix adoption failed ({s})\n", .{@errorName(err)});
                windows_driver.candidateAbortNow();
            };
            std.debug.print("onyx-server: Windows Helix adoption committed; starting reactors\n", .{});
            windows_commit_confirmed = true;
            // A committed candidate becomes the next predecessor. Keep hooks
            // absent throughout inert staging and install them only after the
            // authenticated COMMIT and no-fail adoption edge have completed.
            srv.config.native_upgrade_hooks = windows_runtime_driver.hooks();
        }
    }

    if (native_incoming != null or windows_transfer != null) {
        if (rdns_resolver) |*r| {
            if (comptime builtin.os.tag == .windows) {
                // The native successor's actual worker is already Gate-owned.
                // Its release after COMMIT starts it without a late spawn.
                if (windows_transfer == null) r.start();
            } else r.start();
        }
        if (dnsbl_res) |*r| {
            if (comptime builtin.os.tag == .windows) {
                // The native successor's actual worker is already Gate-owned
                // and starts when COMMIT releases that Gate.
                if (windows_transfer == null) try r.startChecked();
            } else r.start();
        }
        if (mail_send) |*sender| {
            if (comptime builtin.os.tag == .windows) {
                // The successor's actual sender is Gate-owned and starts on
                // release after COMMIT; a late spawn would create a second one.
                if (windows_transfer == null)
                    sender.startChecked() catch |err| std.debug.print("onyx-server: [mail] worker start failed ({s}); delivery unavailable\n", .{@errorName(err)});
            } else sender.start();
        }
    }

    // Drive the SerpentRegistry module init→ready lifecycle now that the server
    // is at its final address (init() returns by value, so `self` is not stable
    // inside it). No-op until a module declares lifecycle fns.
    if (comptime builtin.os.tag == .windows) {
        srv.startCheckedWindows() catch |err| {
            if (windows_transfer != null)
                std.debug.print("onyx-server: Windows Helix post-COMMIT start failed ({s})\n", .{@errorName(err)});
            return err;
        };
    } else srv.start();

    // All fallible companion allocation/configuration is staged before READY.
    // Launch only after adoption has transferred ownership. A worker thread
    // failure must not tear down committed physical client attachments.
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows) {
        if (acme_renewal) |svc| {
            if (comptime builtin.os.tag == .windows) {
                // A successor's real worker is Gate-owned and starts on
                // release after COMMIT; cold boot still starts it here.
                if (windows_transfer == null) try svc.startChecked();
            } else svc.start();
        }
        if (ocsp_staple) |svc| {
            if (comptime builtin.os.tag == .windows) {
                // A Windows successor's real OCSP worker is already parked in
                // the Gate; COMMIT releases it without a second thread spawn.
                if (windows_transfer == null) try svc.startChecked();
            } else svc.start();
        }
    }
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd or builtin.os.tag == .windows) {
        if (webpush_worker) |w| {
            if (windows_transfer == null) {
                w.spawn() catch |err| {
                    if (native_incoming == null) return err;
                    std.debug.print("onyx-server: [webpush] worker start failed ({s}); delivery unavailable\n", .{@errorName(err)});
                };
                if (w.thread != null) srv.webpush_worker = w;
            }
            // A Windows successor already owns its real worker in the Gate;
            // releaseAll starts it after COMMIT without a second thread spawn.
        }
    }

    // Now that the server (and its live world) exists, attach the services state
    // hook so channel REGISTER/DROP reflects into the world's +r REGISTERED flag.
    if (account_store != null) {
        account_services.state = .{
            .ptr = srv,
            .create_channel = svcCreateChannel,
            .drop_channel = svcDropChannel,
        };
        // A Windows successor already adopted the exact live World and policy
        // checkpoints. Replaying persisted services rows after COMMIT could
        // resurrect a stale MLOCK, AKICK, WARD, or SACCESS authority.
        if (windows_transfer == null) srv.replayServicesLiveState(&account_services);
    }

    // OroWasm: load any *.wasm control-plane plugins from [wasm] plugin_dir.
    if (comptime builtin.os.tag == .windows) {
        // An explicitly configured plugin failure must be visible at boot.
        // An inherited image installed its exact module bytes and mutable
        // state before READY. Never reload a changed directory after COMMIT.
        const count = if (windows_transfer == null) try srv.loadWasmPluginsFallible() else srv.wasm.count();
        if (count != 0) std.debug.print("onyx-server: loaded {d} OroWasm plugin(s) from {s}\n", .{ count, srv_cfg.wasm_plugin_dir });
    } else {
        srv.loadWasmPlugins();
    }

    // SIGUSR2 → connection-preserving Helix UPGRADE: lets a shell-driven deploy
    // (`systemctl kill -s USR2 onyx-server`, after staging the new binary) hot-swap
    // the running image while keeping every live client session attached,
    // instead of dropping them with a hard `systemctl restart`.
    onyx_server.daemon.server.installUpgradeSignalHandler();

    // WebTransport (QUIC/HTTP3) listener: a real UDP endpoint built on the
    // from-scratch QUIC stack. It demuxes inbound QUIC datagrams to per-peer
    // connections, establishes a WebTransport session over Extended CONNECT, and
    // bridges each session to the daemon's IRC listener over a loopback TCP
    // proxy (the WT user is handled as an ordinary local IRC client — no reactor
    // changes). Requires the TLS cert chain + a signing key matching the leaf.
    if (srv_cfg.webtransport_port != 0 and wt_listener == null) wt: {
        if (srv_cfg.tls_cert_chain.len == 0) {
            if (comptime builtin.os.tag == .windows) return error.WebTransportCertificateRequired;
            std.debug.print("onyx-server: [listen] webtransport={d} ignored — no TLS certificate loaded (enable [tls]; QUIC needs a cert)\n", .{srv_cfg.webtransport_port});
            break :wt;
        }
        const signing_key: onyx_server.proto.quic_handshake.SigningKey =
            if (srv_cfg.tls_ecdsa_signing_key) |k| .{ .ecdsa_p256 = k } else if (srv_cfg.tls_signing_key) |k| .{ .ed25519 = k } else if (srv_cfg.tls_rsa_signing_key) |k| .{ .rsa = k } else {
                if (comptime builtin.os.tag == .windows) return error.WebTransportSigningKeyRequired;
                std.debug.print("onyx-server: [listen] webtransport={d} ignored — no usable TLS signing key\n", .{srv_cfg.webtransport_port});
                break :wt;
            };
        const irc_port = srv.boundPort() catch {
            if (comptime builtin.os.tag == .windows) return error.WebTransportIrcListenerRequired;
            std.debug.print("onyx-server: [listen] webtransport — IRC port not bound; WebTransport disabled\n", .{});
            break :wt;
        };
        wt_listener = onyx_server.daemon.webtransport_listener.WebTransportListener.init(
            allocator,
            .{ .cert_chain = srv_cfg.tls_cert_chain, .signing_key = signing_key },
            irc_port,
        );
        if (comptime builtin.os.tag == .windows) wt_listener.?.irc_host = srv_cfg.host;
        // Bind on all interfaces, dual-stack: the listener's socket is AF_INET6
        // with IPV6_V6ONLY=0, so `any_be` binds [::] and serves both IPv6 and
        // IPv4 (mapped) QUIC clients on one socket.
        const wt_start = if (comptime builtin.os.tag == .windows) blk: {
            wt_listener.?.prepareColdResources(init.io, .any, srv_cfg.webtransport_port) catch |err| {
                std.debug.print("onyx-server: WebTransport bind failed on UDP :{d} ({s})\n", .{ srv_cfg.webtransport_port, @errorName(err) });
                return err;
            };
            break :blk wt_listener.?.startPreparedLegacyWorker();
        } else wt_listener.?.start(onyx_server.daemon.webtransport_listener.any_be, srv_cfg.webtransport_port);
        wt_start catch |err| {
            std.debug.print("onyx-server: WebTransport bind failed on UDP :{d} ({s}); disabled\n", .{ srv_cfg.webtransport_port, @errorName(err) });
            wt_listener = null;
            if (comptime builtin.os.tag == .windows) return err;
            break :wt;
        };
        if (comptime builtin.os.tag == .windows) try srv.setWindowsWebTransportOwner(&wt_listener.?);
        std.debug.print("onyx-server: WebTransport listening on UDP :{d} (QUIC/HTTP3 → loopback IRC :{d})\n", .{ wt_listener.?.port, irc_port });
    }
    if (comptime builtin.os.tag == .windows) if (windows_transfer != null) if (wt_listener) |*owner|
        std.debug.print("onyx-server: WebTransport inherited UDP :{d} (QUIC/HTTP3 → loopback IRC :{d})\n", .{ owner.port, owner.irc_port });

    const reactor = switch (comptime builtin.os.tag) {
        .windows => "IOCP",
        .freebsd, .openbsd, .netbsd, .dragonfly => "kqueue",
        else => "Ringlane io_uring",
    };
    std.debug.print(
        "onyx-server: listening on {s}:{d} ({s})\n",
        .{ srv_cfg.host, try srv.boundPort(), reactor },
    );
    // Sharded multi-reactor run loop (one worker thread per shard, joined here).
    // runThreaded transparently runs a single in-line reactor when num_shards==1.
    if (comptime builtin.os.tag == .windows) {
        if (windows_runtime_gate) |gate| {
            srv.publishPreparedRuntime();
            gate.control.releaseAll();
            srv.runPreparedRuntime(gate.control, &run);
        } else srv.runThreaded(&run);
    } else srv.runThreaded(&run);
    if (srv.runtimeFailure()) |err| return err;
}

// Public test vector shared with x509_selfsign's RSA certificate controls.
test "managed boot: RSA leaf binds exact unsigned modulus and exponent" {
    const Decode = struct {
        fn bytes(comptime hex: []const u8) [hex.len / 2]u8 {
            var result: [hex.len / 2]u8 = undefined;
            _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
            return result;
        }
    };
    const rsa_n = Decode.bytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
    const rsa_e = Decode.bytes("010001");
    const rsa_d = Decode.bytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
    const private: onyx_server.crypto.rsa_sign.PrivateKey = .{ .n = &rsa_n, .e = &rsa_e, .d = &rsa_d };
    var der: [4096]u8 = undefined;
    const leaf = try onyx_server.proto.x509_selfsign.buildSelfSignedRsa(&der, .{ .common_name = "managed-rsa.test", .not_before = 1700000000, .not_after = 1900000000, .serial = &.{3}, .public_modulus = private.n, .public_exponent = private.e, .private_key = private });
    try validateTlsIdentity(&.{leaf}, null, null, private);
    var wrong = private;
    var different_modulus = rsa_n;
    different_modulus[10] ^= 1;
    wrong.n = &different_modulus;
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{leaf}, null, null, wrong));
    wrong = private;
    wrong.e = &.{ 1, 0, 3 };
    try std.testing.expectError(error.TlsKeyMismatch, validateTlsIdentity(&.{leaf}, null, null, wrong));
}
