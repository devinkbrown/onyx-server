// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Orochi entry point (M1: Ringlane TCP server).
const std = @import("std");
const builtin = @import("builtin");
const orochi = @import("orochi");
const delegated_credential_cli = @import("daemon/delegated_credential_cli.zig");

/// Shared context for the config-string resolver. Both `env:NAME` and
/// `@file:path` indirection run through a single `?*anyopaque` ctx, so it
/// carries everything either lookup needs: the process environment map and an
/// `Io` handle for reading `@file:` payloads off disk.
const ResolverCtx = struct {
    environ_map: *std.process.Environ.Map,
    io: std.Io,
};

/// `env:NAME` resolver for the config parser — reads the process environment map
/// (Zig 0.16 delivers the environment via `std.process.Init.environ_map`, which
/// we thread through the resolver `ctx`). Returns an owned dupe of the value.
fn envLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.EnvironmentVariableNotFound));
    const value = rc.environ_map.get(name) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}

/// `@file:path` resolver for the config parser — loads the file's contents
/// (relative to the daemon cwd) as the string value, so secrets and large text
/// blobs (e.g. `[motd] text = "@file:etc/motd.example.txt"`) can live on disk.
fn fileLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.FileNotFound));
    return std.Io.Dir.cwd().readFileAlloc(rc.io, path, allocator, .limited(1 << 20));
}

fn validateTlsChain(chain: []const []const u8) anyerror!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    const now_unix: i64 = @divTrunc(orochi.substrate.platform.realtimeMillis(), 1000);
    // The daemon's OWN chain: validate the leaf only (a CA-issued server chain
    // ships leaf + intermediates, never a self-signed root, and its intermediate
    // may use a key type the server does not sign with). See validateServerChainAt.
    try orochi.crypto.x509_verify.validateServerChainAt(chain, now_unix);
}

const LoadedEchKeys = struct {
    configs: [][]u8 = &.{},
    keys: []orochi.crypto.tls_server.EchKey = &.{},

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
    defs: []const orochi.daemon.config_format.Config.EchKeyDef,
) !LoadedEchKeys {
    var configs: std.ArrayList([]u8) = .empty;
    errdefer {
        for (configs.items) |bytes| allocator.free(bytes);
        configs.deinit(allocator);
    }
    var keys: std.ArrayList(orochi.crypto.tls_server.EchKey) = .empty;
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
fn svcCreateChannel(ctx: *anyopaque, channel: []const u8) orochi.daemon.services.ServiceError!void {
    const srv: *orochi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, true);
}

/// Services → live-world bridge: dropping a registration clears +r so the
/// channel reverts to ephemeral and is reclaimed once empty.
fn svcDropChannel(ctx: *anyopaque, channel: []const u8) orochi.daemon.services.ServiceError!void {
    const srv: *orochi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, false);
}

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        \\
        \\  Orochi {s}  (大蛇)
        \\  Zig-native mesh IRC daemon — Suimyaku + Tsumugi mesh
        \\
        \\
    , .{orochi.version_full});

    const allocator = init.gpa;

    // Resolver context for `env:`/`@file:` config indirection. Lives on `main`'s
    // frame for the whole process, so the resolver stored on the live config
    // (used by REHASH) never dangles.
    var resolver_ctx = ResolverCtx{ .environ_map = init.environ_map, .io = init.io };

    // Default config (6680; 6667/6697 belong to the local eshmaki server). A
    // config file path may be passed as argv[1]: present values override the
    // defaults; a missing/invalid file keeps defaults (boot never fails on it).
    var srv_cfg = orochi.daemon.server.Config{ .port = 6680 };
    var held: ?orochi.daemon.config_boot.Loaded = null;
    defer if (held) |*h| h.deinit(allocator);
    // Backing storage for the inherited per-shard listener fds (multi-shard
    // Helix handoff). Lives on main's frame so the slice stored on the config
    // stays valid for the whole boot.
    var inherited_listeners: [orochi.daemon.helix.live.max_inherited_listeners]i32 = undefined;
    if (comptime builtin.os.tag != .linux) _ = &inherited_listeners;

    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit(); // no-op on POSIX, frees the arg buffer on Windows/WASI
    // argv[0] is the launch path. UPGRADE re-execs THIS path (not /proc/self/exe,
    // which would re-run the old in-memory image), so a swapped-in new binary is
    // what actually boots across a hot upgrade.
    if (args.next()) |exe| srv_cfg.exe_path = exe;
    var config_path_arg: ?[]const u8 = null;
    if (args.next()) |first| {
        // `orochi --supervisor` is the Helix in-process-upgrade successor mode:
        // a fresh image execve'd by an UPGRADE handoff. If the handoff env fds are
        // present we resume from them (listener + client fds + sessions + live TLS
        // state + mesh re-dial hints); otherwise it boots normally.
        if (std.mem.eql(u8, first, "--supervisor")) {
            if (comptime builtin.os.tag == .linux) {
                if (orochi.daemon.helix.live.resumeFromEnv()) |r| {
                    if (r.listen_fd) |lfd| {
                        // Adopt the inherited listening socket so the port stays
                        // bound across the upgrade (no connection-refused window).
                        srv_cfg.inherited_listener_fd = lfd;
                        std.debug.print("orochi: Helix resume — adopting listen fd {d}\n", .{lfd});
                    } else {
                        std.debug.print("orochi: Helix resume (no listen fd; binding fresh)\n", .{});
                    }
                    // Multi-shard predecessor: the full shard-ordered listener
                    // list (entry 0 duplicates the singular fd above). Each
                    // successor shard adopts its own; leftovers are closed at
                    // server init. Copy into main's frame — the config slice
                    // must outlive server init.
                    if (r.listen_fd_count > 1) {
                        inherited_listeners = r.listen_fds;
                        srv_cfg.inherited_listener_fds = inherited_listeners[0..r.listen_fd_count];
                        std.debug.print("orochi: Helix resume — adopting {d} per-shard listen fds\n", .{r.listen_fd_count});
                    }
                    // Hand the inherited state arena to the server, which reads it
                    // after boot and re-attaches the carried-over client connections.
                    if (r.arena_fd) |afd| srv_cfg.resume_arena_fd = afd;
                } else {
                    std.debug.print("orochi: --supervisor with no Helix handoff env; normal boot\n", .{});
                }
            } else {
                std.debug.print("orochi: --supervisor is Linux-only\n", .{});
            }
            // The successor carries its config path as the arg after --supervisor,
            // so it boots with the SAME config (ports/certs/opers/cloak) as the
            // predecessor — not the built-in defaults.
            config_path_arg = args.next();
        } else
        // `orochi --check-config <path>` parses a config and reports OK/ERROR
        // WITHOUT booting (no ports bound, no mesh dialed) — safe pre-deploy
        // validation. Exits 0 on success, 1 on any read/parse error.
        if (std.mem.eql(u8, first, "--check-config")) {
            const path = args.next() orelse {
                std.debug.print("usage: orochi --check-config <path>\n", .{});
                std.process.exit(2);
            };
            const resolver = orochi.daemon.config_format.Resolver{
                .ctx = @ptrCast(&resolver_ctx),
                .env = envLookup,
                .file = fileLookup,
            };
            if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
                defer allocator.free(text);
                if (orochi.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                    var l = loaded;
                    defer l.deinit(allocator);
                    // A meshed node with no shared [cloak] secret is a
                    // misconfiguration, not merely a style nit: per-boot random
                    // cloak keys differ per node and change on restart, so
                    // host/subnet WARD bans neither federate nor persist. Fail
                    // validation loudly so it is caught before deploy.
                    if (l.parsed.meshCloakSecretMissing()) {
                        std.debug.print("config ERROR in {s}: meshed node ([mesh] connect or [listen] s2s set) has no shared [cloak] secret; per-boot cloak keys break host/subnet ban federation and persistence — set the SAME [cloak] secret on every mesh node\n", .{path});
                        std.process.exit(1);
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
        // `orochi acme-issue ...` runs an out-of-band ACME issuance and exits.
        // Linux-only (raw socket syscalls); comptime-gated so non-linux targets
        // never analyze the linux-specific ACME path.
        if (std.mem.eql(u8, first, "acme-issue")) {
            if (comptime builtin.os.tag == .linux) {
                var rest: std.ArrayList([]const u8) = .empty;
                defer rest.deinit(allocator);
                while (args.next()) |a| try rest.append(allocator, a);
                const opts = orochi.daemon.acme_cli.parseArgs(rest.items) orelse {
                    orochi.daemon.acme_cli.usage();
                    return;
                };
                _ = orochi.daemon.acme_cli.runIssue(allocator, init.io, opts) catch |err| {
                    std.debug.print("acme-issue failed: {s}\n", .{@errorName(err)});
                    return;
                };
                return;
            } else {
                std.debug.print("acme-issue is only supported on Linux\n", .{});
                return;
            }
        } else
        // `orochi delegated-credential inspect|validate ...` inspects a raw RFC
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
                \\usage: orochi [CONFIG_PATH]
                \\       orochi --check-config <path>
                \\       orochi --version
                \\       orochi acme-issue ...
                \\       orochi delegated-credential inspect|validate ...
                \\
            , .{});
            return;
        } else if (first.len > 0 and first[0] == '-') {
            // An unrecognized dash-flag must NEVER be treated as a config path — a
            // real config path never starts with '-'. Treating it as one silently
            // boots the DEFAULT identity (wrong ports/certs/opers). Fail loudly.
            std.debug.print("orochi: unknown option '{s}' (try --help)\n", .{first});
            std.process.exit(2);
        } else {
            config_path_arg = first;
        }
    }

    // Load the config file — normal boot uses argv[1]; the UPGRADE successor uses
    // the path carried after --supervisor. One path for both so a hot-upgraded
    // process comes up on the real ports/certs/opers, not the defaults.
    if (config_path_arg) |path| {
        const resolver = orochi.daemon.config_format.Resolver{
            .ctx = @ptrCast(&resolver_ctx),
            .env = envLookup,
            .file = fileLookup,
        };
        if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
            defer allocator.free(text); // string fields are duped by the parser
            if (orochi.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                held = loaded;
                // Preserve the Helix handoff fields set above: `srv_cfg = loaded.config`
                // replaces the whole struct, and these are not config-file keys.
                const carried_exe = srv_cfg.exe_path;
                const carried_resume = srv_cfg.resume_arena_fd;
                const carried_listen = srv_cfg.inherited_listener_fd;
                const carried_listen_list = srv_cfg.inherited_listener_fds;
                srv_cfg = loaded.config;
                srv_cfg.exe_path = carried_exe;
                srv_cfg.resume_arena_fd = carried_resume;
                srv_cfg.inherited_listener_fd = carried_listen;
                srv_cfg.inherited_listener_fds = carried_listen_list;
                srv_cfg.num_shards = loaded.num_shards;
                srv_cfg.config_path = path;
                srv_cfg.config_resolver = resolver;
                std.debug.print("orochi: loaded config from {s}\n", .{path});
            } else |err| {
                std.debug.print("orochi: config error in {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
        } else |err| {
            std.debug.print("orochi: cannot read config {s} ({s}); using defaults\n", .{ path, @errorName(err) });
        }
    }

    // The platform CSPRNG is always available to the server (session reclaim
    // tokens, etc.); PQ-secured S2S below is the only feature gated on a key.
    srv_cfg.crypto_io = init.io;

    // Install the configured network name before building ISUPPORT, so the
    // NETWORK= token and the welcome burst both reflect it. Write-once at boot.
    orochi.proto.protocol_inventory.setNetworkName(srv_cfg.network_name);
    orochi.proto.protocol_inventory.setServerName(srv_cfg.server_name);
    // Web Push VAPID key: loaded (or created) BEFORE ISUPPORT is built so the
    // 005 burst can advertise `VAPID=` — discovery is ISUPPORT, not a NOTE
    // round-trip. The delivery worker itself spawns later (needs `srv`).
    var webpush_vapid: ?orochi.daemon.webpush.Vapid = null;
    var webpush_pub_buf: [orochi.daemon.webpush.vapid_pub_b64_len]u8 = undefined;
    if (held) |h| {
        if (h.parsed.webpush.enabled and builtin.os.tag == .linux) {
            if (orochi.daemon.webpush.Vapid.loadOrCreate(init.io, allocator, std.Io.Dir.cwd(), h.parsed.webpush.vapid_key_path)) |v| {
                webpush_vapid = v;
                srv_cfg.webpush_vapid_pub = v.publicB64(&webpush_pub_buf);
            } else |err| {
                std.debug.print("orochi: [webpush] VAPID key failed ({s}); web push disabled\n", .{@errorName(err)});
            }
        }
    }

    // Advertise config-driven length limits (TOPICLEN) in ISUPPORT. Built once
    // here, before any connection is served; owned for the process lifetime.
    const isupport_tokens = try orochi.daemon.server.buildIsupportTokens(allocator, srv_cfg);
    orochi.proto.protocol_inventory.setIsupportOverride(isupport_tokens);
    // NICKLEN is enforced in the pre-registration dispatch path, which reads the
    // runtime-limits holder rather than a config handle.
    orochi.proto.protocol_inventory.setRuntimeLimits(.{ .nicklen = srv_cfg.nicklen });

    // PQ-secured S2S is ON BY DEFAULT: an explicit `[node] secret_key` takes
    // precedence (and never touches the keyfile); otherwise the daemon loads — or
    // generates + persists (0600) — the seed from `orochi-node.key` next to the
    // config (CWD without one), so the secured Tsumugi mesh needs no manual key.
    // The identity outlives the server (it borrows a pointer); only a keyfile or
    // identity error leaves S2S plaintext.
    var node_id_holder: ?orochi.daemon.node_identity.NodeIdentity = null;
    defer if (node_id_holder) |*n| n.deinit();
    const mesh_realm: []const u8 = if (held) |h| h.parsed.mesh.realm else "local";
    // Apply [mesh].require_secured before the node-identity setup below, so the
    // policy holds even when secured S2S is NOT configured (the case it most
    // matters for — it then drops all S2S instead of falling back to plaintext).
    if (held) |h| srv_cfg.require_secured = h.parsed.mesh.require_secured;
    const configured_key: ?[]const u8 = if (held) |h| h.parsed.node.secret_key else null;
    if (configured_key) |sk| {
        if (orochi.daemon.node_identity.fromConfig(sk, mesh_realm)) |ident| {
            node_id_holder = ident;
            std.debug.print("orochi: PQ-secured S2S enabled (node identity configured)\n", .{});
        } else |err| {
            std.debug.print("orochi: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
        }
    } else auto: {
        const key_path = orochi.daemon.node_keyfile.derivePath(allocator, srv_cfg.config_path) catch break :auto;
        defer allocator.free(key_path);
        const loaded_key = orochi.daemon.node_keyfile.loadOrCreate(allocator, init.io, std.Io.Dir.cwd(), key_path) catch |err| {
            std.debug.print("orochi: node keyfile error in {s} ({s}); S2S stays plaintext\n", .{ key_path, @errorName(err) });
            break :auto;
        };
        if (orochi.daemon.node_identity.fromSeed(loaded_key.seed, mesh_realm)) |ident| {
            node_id_holder = ident;
            switch (loaded_key.source) {
                .loaded => std.debug.print("orochi: node identity loaded from {s}\n", .{key_path}),
                .generated => std.debug.print("orochi: node identity generated + persisted to {s}\n", .{key_path}),
            }
        } else |err| {
            std.debug.print("orochi: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
        }
    }
    if (node_id_holder != null) {
        srv_cfg.node_identity = &node_id_holder.?;
        if (held) |h| {
            if (h.parsed.mesh.mesh_pass) |mp| srv_cfg.mesh_pass = mp;
        }
    }

    // The WebTransport (QUIC/HTTP3) listener is started AFTER the server is up
    // (it bridges to the daemon's bound IRC port via loopback TCP). See below,
    // after `srv.start()`.

    // SASL account backend: when `[sasl] account_db` is configured, open the
    // WAL-backed account store and verify SASL PLAIN credentials against it. The
    // store/services/checker live for the server's lifetime (the checker fat
    // pointer is copied into every connection).
    var account_store: ?orochi.daemon.services.OroStore = null;
    defer if (account_store) |*s| s.deinit();
    var account_services: orochi.daemon.services.Services = undefined;
    var account_checker: orochi.daemon.sasl_bridge.ServicesPlainChecker = undefined;
    var external_bridge: orochi.daemon.sasl_bridge.ServicesExternalLookup = undefined;
    var session_token_bridge: orochi.daemon.sasl_bridge.ServicesSessionTokenLookup = undefined;
    var oauth_key: ?orochi.daemon.oauth_jwt.OwnedKey = null;
    defer if (oauth_key) |*key| key.deinit();
    var oauth_verifier: orochi.daemon.oauth_jwt.Verifier = undefined;
    var oauth_jwks_text: ?[]u8 = null;
    defer if (oauth_jwks_text) |bytes| allocator.free(bytes);
    // SCRAM-SHA-256 credential mirror: provisioned alongside each account so a
    // client can authenticate without sending its password. Must outlive the
    // server (the lookup fat-pointer captures &scram_store).
    var scram_store = orochi.daemon.scram_store.ScramStore.init(allocator);
    defer scram_store.deinit();
    // Account ⇄ TLS certfp bindings for SASL EXTERNAL (CERTADD); outlives server.
    var certfp_binds = orochi.daemon.certfp_bind.CertfpBindStore.init(allocator);
    defer certfp_binds.deinit();
    // Account credential transparency root; services append CERTFP/WebAuthn changes.
    var key_transparency_log = orochi.daemon.key_transparency.KeyTransparencyLog.init(allocator);
    defer key_transparency_log.deinit();
    if (held) |h| {
        if (!srv_cfg.sasl_enabled) {
            if (h.parsed.sasl.account_db != null) {
                std.debug.print("orochi: SASL account store configured but [sasl].enabled=false; SASL disabled\n", .{});
            }
        } else if (h.parsed.sasl.account_db) |db| {
            if (orochi.daemon.services.OroStore.openWithConfig(allocator, init.io, std.Io.Dir.cwd(), db, h.parsed.storage)) |store| {
                account_store = store;
                account_services = orochi.daemon.services.Services.initWithConfig(&account_store.?, null, .{
                    .pbkdf2_rounds = h.parsed.accounts.pbkdf2_rounds,
                    .password_min_len = @intCast(h.parsed.accounts.password_min_len),
                    .password_max_len = @intCast(h.parsed.accounts.password_max_len),
                });
                account_services.attachScramStore(&scram_store);
                account_services.attachCertfpBinds(&certfp_binds);
                account_services.attachKeyTransparencyLog(&key_transparency_log);
                // Seed config-declared oper certfp bindings so SASL EXTERNAL works
                // certfp-only without a prior runtime CERTADD. Coexists with (never
                // wipes) runtime CERTADD binds; malformed entries warn-and-skip.
                const seeded = orochi.daemon.config_boot.seedOperCertfpBinds(&certfp_binds, h.parsed.opers);
                if (seeded != 0) std.debug.print("orochi: seeded {d} oper certfp binding(s) from config\n", .{seeded});
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
                std.debug.print("orochi: SASL account store opened ({s}); PLAIN + SCRAM-SHA-256 + SCRAM-SHA-512 + EXTERNAL + SESSION-TOKEN live\n", .{db});
            } else |err| {
                std.debug.print("orochi: account store error ({s}); SASL disabled\n", .{@errorName(err)});
            }
        }
    }
    if (held) |h| {
        if (srv_cfg.sasl_enabled) {
            const oauth_key_config: ?orochi.daemon.oauth_jwt.Key = if (h.parsed.sasl.oauth_hmac_key) |key|
                .{ .hs256 = key }
            else if (h.parsed.sasl.oauth_jwks_file) |path| jwks: {
                oauth_jwks_text = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20)) catch |err| {
                    std.debug.print("orochi: OAuth JWKS read failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
                    break :jwks null;
                };
                oauth_key = orochi.daemon.oauth_jwt.OwnedKey.fromJwks(allocator, oauth_jwks_text.?) catch |err| {
                    std.debug.print("orochi: OAuth JWKS parse failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
                    break :jwks null;
                };
                break :jwks oauth_key.?.key;
            } else if (h.parsed.sasl.oauth_pubkey) |pubkey| pubkey_blk: {
                oauth_key = orochi.daemon.oauth_jwt.OwnedKey.fromPubkey(allocator, pubkey) catch |err| {
                    std.debug.print("orochi: OAuth public key parse failed ({s}); OAUTHBEARER disabled\n", .{@errorName(err)});
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
                std.debug.print("orochi: SASL OAUTHBEARER live (local JWT verification)\n", .{});
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
    var cloak_key_bytes: [orochi.proto.cloak.key_len]u8 = undefined;
    const cloak_kdf_params = orochi.crypto.argon2_kdf.default_params;
    const cloak_kdf_salt = orochi.crypto.argon2_kdf.cloak_key_salt;
    if (held) |h| {
        if (h.parsed.cloak.secret) |secret| {
            if (orochi.crypto.argon2_kdf.deriveKey(allocator, &cloak_key_bytes, secret, cloak_kdf_salt, cloak_kdf_params)) {
                srv_cfg.cloak_key = orochi.proto.cloak.SecretKey.init(cloak_key_bytes);
            } else |err| {
                // Only reachable under catastrophic conditions (OOM for the
                // 64 MiB scratch / thread-spawn failure). Leave cloak_key null so
                // the random per-boot fallback below still keeps privacy on, and
                // warn loudly (the mesh-federation caveat is printed there too).
                std.debug.print("orochi: cloak key derivation failed ({s}); falling back to a per-boot random key\n", .{@errorName(err)});
            }
        }
        // Previous cloak key (`[cloak] previous_secret`): kept live across a key
        // rotation so WARD host/mask bans written under the old key keep matching.
        // Derived through the same Argon2id path so old and new keys agree on KDF.
        if (h.parsed.cloak.previous_secret) |prev| {
            var prev_bytes: [orochi.proto.cloak.key_len]u8 = undefined;
            if (orochi.crypto.argon2_kdf.deriveKey(allocator, &prev_bytes, prev, cloak_kdf_salt, cloak_kdf_params)) {
                srv_cfg.cloak_prev_key = orochi.proto.cloak.SecretKey.init(prev_bytes);
            } else |err| {
                std.debug.print("orochi: previous cloak key derivation failed ({s}); rotation grace disabled this boot\n", .{@errorName(err)});
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
        init.io.random(&cloak_key_bytes);
        srv_cfg.cloak_key = orochi.proto.cloak.SecretKey.init(cloak_key_bytes);
        std.debug.print("orochi: cloak key generated (per-boot; set [cloak] secret to persist)\n", .{});
        // On a MESHED node a per-boot random cloak key is a federation hazard:
        // cloaked hosts differ per node and change on every restart, so
        // `*!*@<cloak>` and subnet WARD bans neither cross the mesh nor survive a
        // restart. Warn loudly so the operator sets one shared [cloak] secret.
        if (held) |h| {
            if (h.parsed.meshCloakSecretMissing())
                std.debug.print("orochi: WARNING — meshed node has NO shared [cloak] secret; per-boot cloak keys break host/subnet ban federation and persistence. Set the SAME [cloak] secret on every mesh node.\n", .{});
        }
    }
    // `srv_cfg.cloak_key` owns its own copy of the key; the local scratch buffer
    // has served both the Argon2id-derive and random-fallback consumers, so wipe
    // it — no live key material should linger on main's stack.
    std.crypto.secureZero(u8, &cloak_key_bytes);

    // Background forward-confirmed reverse-DNS resolver: client IPs are resolved
    // off the accept path so hosts present a cloaked hostname rather than a
    // cloaked IP. Inert (no thread) when /etc/resolv.conf yields no nameservers.
    var rdns_resolver = orochi.daemon.rdns.Resolver.init(allocator) catch null;
    defer if (rdns_resolver) |*r| r.deinit();
    if (rdns_resolver) |*r| {
        r.start();
        srv_cfg.rdns = r;
    }

    // Connect-time DNS blocklist: built only when `[dnsbl]` is enabled with at
    // least one zone. Each client IP is checked off the accept path and a listed
    // IP is refused (or network-banned) at registration. Inert otherwise.
    var dnsbl_res: ?orochi.daemon.dnsbl_resolver.Resolver = null;
    defer if (dnsbl_res) |*r| r.deinit();
    if (held) |h| {
        if (h.parsed.dnsbl.enabled and h.parsed.dnsbl.zones.len != 0) {
            dnsbl_res = orochi.daemon.dnsbl_resolver.Resolver.init(allocator, h.parsed.dnsbl.zones) catch null;
            if (dnsbl_res) |*r| {
                r.start();
                srv_cfg.dnsbl = r;
                srv_cfg.dnsbl_ward = h.parsed.dnsbl.ward;
            }
        }
    }

    // Background SMTP submission sender: built only when `[mail]` is enabled with
    // a relay host + sender address. Delivers account email-verification codes
    // out-of-band. Inert otherwise (emails are recorded unverified).
    var mail_send: ?orochi.daemon.mail_sender.Sender = null;
    defer if (mail_send) |*m| m.deinit();
    if (held) |h| {
        const m = h.parsed.mail;
        if (m.enabled) {
            if (m.relay_host) |relay| if (m.from) |from| {
                mail_send = orochi.daemon.mail_sender.Sender.init(allocator, .{
                    .relay_host = relay,
                    .relay_port = m.relay_port,
                    .starttls = m.starttls,
                    .insecure_skip_verify = m.insecure_skip_verify,
                    .ehlo_domain = srv_cfg.server_name,
                    .from = from,
                    .user = m.user,
                    .pass = m.pass,
                }) catch null;
                if (mail_send) |*s| {
                    s.start();
                    srv_cfg.mail_sender = s;
                }
            };
        }
    }

    // Implicit-TLS client listener: when `[tls] enabled`, load the configured
    // cert/key (or mint a self-signed bootstrap leaf) and stand up the TLS
    // listener. The chain bytes + signing key live for the server's lifetime
    // (server.Config borrows them). No STARTTLS — this is a separate TLS port.
    var tls_loaded: ?orochi.daemon.tls_certs.Loaded = null;
    defer if (tls_loaded) |*t| t.deinit(allocator);
    var tls12_loaded: ?orochi.daemon.tls_certs.Tls12 = null;
    defer if (tls12_loaded) |*t| t.deinit(allocator);
    // [[tls.sni]] additional certs: each entry's on-disk cert+key is loaded with
    // the SAME loader as the default cert. The loaded material must outlive the
    // server (each `tls_server.SniCert` borrows its chain bytes and aliases any
    // RSA key storage), so the loads live on main's frame and free at process
    // exit — mirroring `tls_loaded`. `tls_sni_certs` is the selection list handed
    // to the listener; the array itself is freed here, its contents borrow above.
    var tls_sni_loaded: std.ArrayList(orochi.daemon.tls_certs.Loaded) = .empty;
    defer {
        for (tls_sni_loaded.items) |*s| s.deinit(allocator);
        tls_sni_loaded.deinit(allocator);
    }
    var tls_sni_certs: []orochi.crypto.tls_server.SniCert = &.{};
    defer if (tls_sni_certs.len != 0) allocator.free(tls_sni_certs);
    var tls_ech_loaded: ?LoadedEchKeys = null;
    defer if (tls_ech_loaded) |*e| e.deinit(allocator);
    if (held) |h| {
        if (h.tls.enabled) {
            if (orochi.daemon.tls_certs.loadOrBootstrap(allocator, init.io, .{
                .enabled = true,
                .cert_path = h.tls.cert_path,
                .key_path = h.tls.key_path,
                .dns_name = h.tls.dns_name,
            })) |loaded| tls_material: {
                validateTlsChain(loaded.cert_chain) catch |err| {
                    var rejected = loaded;
                    rejected.deinit(allocator);
                    std.debug.print("orochi: TLS certificate validation failed ({s}); TLS disabled\n", .{@errorName(err)});
                    break :tls_material;
                };
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
                    const built = orochi.daemon.tls_sni_load.buildSniCerts(
                        allocator,
                        init.io,
                        h.tls.sni,
                        h.tls.dns_name,
                        &tls_sni_loaded,
                        validateTlsChain,
                        orochi.daemon.tls_sni_load.default_loader,
                    ) catch |err| {
                        std.debug.print("orochi: [[tls.sni]] certificate setup failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    tls_sni_certs = built;
                    std.debug.print("orochi: {d} SNI certificate(s) loaded\n", .{tls_sni_certs.len});
                }
                if (h.tls.ech_keys.len != 0) {
                    tls_ech_loaded = loadTlsEchKeys(allocator, init.io, h.tls.ech_keys) catch |err| {
                        std.debug.print("orochi: [[tls.ech_keys]] load failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    var probe = orochi.crypto.tls_server.Server.init(allocator, .{
                        .cert_chain = tls_loaded.?.cert_chain,
                        .signing_key = tls_loaded.?.signing_key,
                        .ecdsa_p256_signing_key = tls_loaded.?.ecdsa_p256_signing_key,
                        .rsa_signing_key = tls_loaded.?.rsa_signing_key,
                        .sni_certs = tls_sni_certs,
                        .ech_keys = tls_ech_loaded.?.keys,
                    }) catch |err| {
                        std.debug.print("orochi: [[tls.ech_keys]] validation failed ({s}); TLS disabled\n", .{@errorName(err)});
                        break :tls_material;
                    };
                    probe.deinit();
                    std.debug.print("orochi: {d} ECH key(s) loaded\n", .{tls_ech_loaded.?.keys.len});
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
                std.debug.print("orochi: TLS listener enabled on port {d}\n", .{h.tls.port});
                // kTLS offload (roadmap 3.1): activate kernel record crypto only
                // when the operator opted in via `[tls] ktls` AND the running
                // kernel offers the TLS ULP. `tx` offloads server→client encryption;
                // `txrx` additionally offloads client→server decryption.
                const ktls_capable = orochi.daemon.ktls.probeUlpSupport();
                srv_cfg.tls_ktls_tx = (h.tls.ktls != .off and ktls_capable);
                srv_cfg.tls_ktls_rx = (h.tls.ktls == .txrx and ktls_capable);
                if (h.tls.ktls != .off) {
                    if (ktls_capable) {
                        const dirs = if (h.tls.ktls == .txrx) "TX+RX" else "TX";
                        std.debug.print("orochi: kTLS {s} offload ACTIVE ({s}) — TLS 1.3 record crypto runs in the kernel\n", .{ dirs, @tagName(h.tls.ktls) });
                    } else {
                        std.debug.print("orochi: kTLS {s} requested but this kernel has no TLS ULP — TLS stays in userspace\n", .{@tagName(h.tls.ktls)});
                    }
                } else if (ktls_capable) {
                    std.debug.print("orochi: kTLS-capable kernel detected (TLS ULP present); set [tls] ktls=tx to offload server→client encryption\n", .{});
                } else {
                    std.debug.print("orochi: kTLS unavailable on this kernel (no TLS ULP); TLS stays in userspace\n", .{});
                }
                if (h.tls.enable_tls12) {
                    if (tls_loaded.?.key_kind == .ecdsa_p256) {
                        // The loaded ECDSA-P256 leaf serves the 1.2 leg natively.
                        srv_cfg.tls12_cert_chain = tls_loaded.?.cert_chain;
                        srv_cfg.tls12_signing_key = tls_loaded.?.ecdsa_p256_signing_key;
                        std.debug.print("orochi: hardened TLS 1.2 also accepted (ECDSA-P256 leaf)\n", .{});
                    } else if (tls_loaded.?.key_kind == .rsa) {
                        srv_cfg.tls12_cert_chain = tls_loaded.?.cert_chain;
                        std.debug.print("orochi: hardened TLS 1.2 also accepted (RSA leg)\n", .{});
                    } else {
                        if (orochi.daemon.tls_certs.bootstrapTls12(allocator, init.io, h.tls.dns_name)) |t12| {
                            tls12_loaded = t12;
                            srv_cfg.tls12_cert_chain = tls12_loaded.?.cert_chain;
                            srv_cfg.tls12_signing_key = tls12_loaded.?.key;
                            std.debug.print("orochi: hardened TLS 1.2 also accepted (ECDSA-P256 leg)\n", .{});
                        } else |err| {
                            std.debug.print("orochi: TLS 1.2 bootstrap failed ({s}); 1.3-only\n", .{@errorName(err)});
                        }
                    }
                }
            } else |err| {
                std.debug.print("orochi: TLS cert error ({s}); TLS disabled\n", .{@errorName(err)});
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
            std.debug.print("orochi: WebSocket (wss) listener enabled on port {d}\n", .{srv_cfg.ws_port});
        } else if (srv_cfg.ws_allow_plain) {
            std.debug.print("orochi: WebSocket listener on port {d} WITHOUT TLS ([listen] ws_plain testing mode)\n", .{srv_cfg.ws_port});
        } else {
            srv_cfg.ws_enabled = false;
            std.debug.print("orochi: [listen] ws ignored — no TLS certificate loaded (enable [tls]; browsers require wss)\n", .{});
        }
    }

    // IRCv3 STS: when an operator enables `[sts]` AND a TLS listener is live,
    // build the advertised wire value so each session's `sts` cap is offered.
    // STS without a live TLS port would strand clients, so require both.
    var sts_value_buf: [orochi.proto.sts.MAX_VALUE_LEN]u8 = undefined;
    if (held) |h| {
        if (h.sts.enabled) {
            if (srv_cfg.tls_cert_chain.len != 0) {
                const policy = orochi.proto.sts_policy.Policy{
                    .duration_seconds = h.sts.duration,
                    .port = h.sts.port,
                    .preload = h.sts.preload,
                };
                if (orochi.proto.sts_policy.writeCapValue(policy, .combined, &sts_value_buf)) |value| {
                    srv_cfg.sts_value = value;
                    std.debug.print("orochi: STS advertised ({s})\n", .{value});
                } else |err| {
                    std.debug.print("orochi: STS value error ({s}); STS disabled\n", .{@errorName(err)});
                }
            } else {
                std.debug.print("orochi: [sts] enabled but no TLS listener; STS NOT advertised\n", .{});
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

    const Server = orochi.daemon.server.Server;
    var srv = Server.init(allocator, srv_cfg) catch |err| {
        // The reactor requires io_uring on a 64-bit Linux kernel. If it is
        // unavailable (old kernel / restricted sandbox) the daemon cannot serve,
        // so fail loudly and exit non-zero rather than pretending to have started.
        std.debug.print("orochi: fatal — cannot start server: {s}\n", .{@errorName(err)});
        std.debug.print("orochi: the reactor requires io_uring on a 64-bit Linux kernel.\n", .{});
        std.process.exit(1);
    };
    defer srv.deinit();

    // Drive the SerpentRegistry module init→ready lifecycle now that the server
    // is at its final address (init() returns by value, so `self` is not stable
    // inside it). No-op until a module declares lifecycle fns.
    srv.start();

    const AcmeRenewalService = if (builtin.os.tag == .linux) orochi.daemon.acme_renewal.Service else void;
    var acme_renewal: ?*AcmeRenewalService = null;
    defer if (comptime builtin.os.tag == .linux) {
        if (acme_renewal) |s| {
            s.stop();
            allocator.destroy(s);
        }
    };
    // `|*h|`: `setAcmeTlsReloadConfig` and the renewal worker both retain
    // `&h.parsed.tls` past this block, so it must point at `held`'s function-scope
    // payload rather than a block-local copy.
    if (held) |*h| {
        if (h.acme.enabled) {
            if (comptime builtin.os.tag == .linux) {
                srv.setAcmeTlsReloadConfig(&h.parsed.tls);
                const svc = try allocator.create(AcmeRenewalService);
                svc.* = AcmeRenewalService.init(allocator, init.io, &srv, h.parsed.acme, &h.parsed.tls);
                acme_renewal = svc;
                svc.start();
            } else {
                std.debug.print("orochi: [acme] enabled but in-daemon renewal is Linux-only; renewal disabled\n", .{});
            }
        }
    }

    // ── OCSP staple fetcher ([ocsp] enabled + on-disk TLS cert) ─────────────
    // A background worker fetches, verifies, and caches an OCSP response for the
    // leaf and publishes it to the live TLS config; the leaf CertificateEntry
    // (1.3) / CertificateStatus (1.2) then carries it when a client offers
    // status_request. Needs a real cert file (self-signed bootstrap leaves have
    // no AIA responder URL, so the worker simply no-ops there).
    const OcspStapleService = if (builtin.os.tag == .linux) orochi.daemon.ocsp_staple.Service else void;
    var ocsp_staple: ?*OcspStapleService = null;
    defer if (comptime builtin.os.tag == .linux) {
        if (ocsp_staple) |s| {
            s.stop();
            allocator.destroy(s);
        }
    };
    // Capture by pointer (`|*h|`): the worker thread holds `&h.parsed.tls` for its
    // whole lifetime, so it must target `held`'s function-scope payload, not a
    // block-local copy that dies at the end of this `if`.
    if (held) |*h| {
        if (h.parsed.ocsp.enabled and h.parsed.tls.enabled and h.parsed.tls.cert_path != null) {
            if (comptime builtin.os.tag == .linux) {
                const svc = try allocator.create(OcspStapleService);
                svc.* = OcspStapleService.init(allocator, init.io, &srv, &h.parsed.tls, .{
                    .check_interval_ms = h.parsed.ocsp.check_interval_ms,
                });
                ocsp_staple = svc;
                svc.start();
            } else {
                std.debug.print("orochi: [ocsp] enabled but staple fetching is Linux-only; disabled\n", .{});
            }
        } else if (h.parsed.ocsp.enabled) {
            std.debug.print("orochi: [ocsp] enabled but requires [tls] with an on-disk cert_path; disabled\n", .{});
        }
    }

    // ── Web Push delivery worker ([webpush] enabled + account store) ────────
    // Offline DMs (tegami) nudge the recipient's browser through their push
    // service — payloads are RFC 8291-encrypted end-to-end to the browser.
    const WebpushWorker = if (builtin.os.tag == .linux) orochi.daemon.webpush.Worker else void;
    var webpush_worker: ?*WebpushWorker = null;
    var webpush_resolver: ?*orochi.daemon.acme_runner.SystemResolver = null;
    defer if (comptime builtin.os.tag == .linux) {
        if (webpush_worker) |w| {
            w.shutdown();
            allocator.destroy(w);
        }
        if (webpush_resolver) |r| allocator.destroy(r);
    };
    if (held) |h| {
        if (h.parsed.webpush.enabled) {
            if (comptime builtin.os.tag == .linux) webpush_blk: {
                if (srv_cfg.account_services == null) {
                    std.debug.print("orochi: [webpush] enabled but no account store; web push disabled\n", .{});
                    break :webpush_blk;
                }
                // Trust anchors + resolver live for the process lifetime.
                const bundle_text = std.Io.Dir.cwd().readFileAlloc(init.io, h.parsed.acme.ca_bundle_path, allocator, .limited(@intCast(h.parsed.acme.ca_bundle_max_bytes))) catch |err| {
                    std.debug.print("orochi: [webpush] CA bundle read failed ({s}); web push disabled\n", .{@errorName(err)});
                    break :webpush_blk;
                };
                defer allocator.free(bundle_text);
                const anchors = orochi.daemon.acme_cli.loadTrustAnchors(allocator, bundle_text) catch |err| {
                    std.debug.print("orochi: [webpush] trust anchors failed ({s}); web push disabled\n", .{@errorName(err)});
                    break :webpush_blk;
                };
                const vapid = webpush_vapid orelse {
                    std.debug.print("orochi: [webpush] no VAPID key; web push disabled\n", .{});
                    break :webpush_blk;
                };
                const resolver = try allocator.create(orochi.daemon.acme_runner.SystemResolver);
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
                    .trust_anchors = anchors.items,
                };
                try w.spawn();
                webpush_worker = w;
                srv.webpush_worker = w;
                std.debug.print("orochi: web push live ({d} trust anchors; VAPID {s})\n", .{ anchors.items.len, srv_cfg.webpush_vapid_pub });
            } else {
                std.debug.print("orochi: [webpush] enabled but web push is Linux-only; disabled\n", .{});
            }
        }
    }

    // Now that the server (and its live world) exists, attach the services state
    // hook so channel REGISTER/DROP reflects into the world's +r REGISTERED flag.
    if (account_store != null) {
        account_services.state = .{
            .ptr = &srv,
            .create_channel = svcCreateChannel,
            .drop_channel = svcDropChannel,
        };
        srv.replayServicesLiveState(&account_services);
    }

    // OroWasm: load any *.wasm control-plane plugins from [wasm] plugin_dir.
    srv.loadWasmPlugins();

    // Helix UPGRADE successor: re-attach the carried-over client connections
    // (inherited socket fds + restored sessions) now that the ring exists.
    if (comptime builtin.os.tag == .linux) srv.adoptInheritedSessions();

    // SIGUSR2 → connection-preserving Helix UPGRADE: lets a shell-driven deploy
    // (`systemctl kill -s USR2 orochi`, after staging the new binary) hot-swap
    // the running image while keeping every live client session attached,
    // instead of dropping them with a hard `systemctl restart`.
    orochi.daemon.server.installUpgradeSignalHandler();

    // WebTransport (QUIC/HTTP3) listener: a real UDP endpoint built on the
    // from-scratch QUIC stack. It demuxes inbound QUIC datagrams to per-peer
    // connections, establishes a WebTransport session over Extended CONNECT, and
    // bridges each session to the daemon's IRC listener over a loopback TCP
    // proxy (the WT user is handled as an ordinary local IRC client — no reactor
    // changes). Requires the TLS cert chain + a signing key matching the leaf.
    var wt_listener: ?orochi.daemon.webtransport_listener.WebTransportListener = null;
    defer if (wt_listener) |*l| l.deinit();
    if (srv_cfg.webtransport_port != 0) wt: {
        if (srv_cfg.tls_cert_chain.len == 0) {
            std.debug.print("orochi: [listen] webtransport={d} ignored — no TLS certificate loaded (enable [tls]; QUIC needs a cert)\n", .{srv_cfg.webtransport_port});
            break :wt;
        }
        const signing_key: orochi.proto.quic_handshake.SigningKey =
            if (srv_cfg.tls_ecdsa_signing_key) |k| .{ .ecdsa_p256 = k } else if (srv_cfg.tls_signing_key) |k| .{ .ed25519 = k } else if (srv_cfg.tls_rsa_signing_key) |k| .{ .rsa = k } else {
                std.debug.print("orochi: [listen] webtransport={d} ignored — no usable TLS signing key\n", .{srv_cfg.webtransport_port});
                break :wt;
            };
        const irc_port = srv.boundPort() catch {
            std.debug.print("orochi: [listen] webtransport — IRC port not bound; WebTransport disabled\n", .{});
            break :wt;
        };
        wt_listener = orochi.daemon.webtransport_listener.WebTransportListener.init(
            allocator,
            .{ .cert_chain = srv_cfg.tls_cert_chain, .signing_key = signing_key },
            irc_port,
        );
        // Bind on all interfaces, dual-stack: the listener's socket is AF_INET6
        // with IPV6_V6ONLY=0, so `any_be` binds [::] and serves both IPv6 and
        // IPv4 (mapped) QUIC clients on one socket.
        wt_listener.?.start(orochi.daemon.webtransport_listener.any_be, srv_cfg.webtransport_port) catch |err| {
            std.debug.print("orochi: WebTransport bind failed on UDP :{d} ({s}); disabled\n", .{ srv_cfg.webtransport_port, @errorName(err) });
            wt_listener = null;
            break :wt;
        };
        std.debug.print("orochi: WebTransport listening on UDP :{d} (QUIC/HTTP3 → loopback IRC :{d})\n", .{ wt_listener.?.port, irc_port });
    }

    std.debug.print(
        "orochi: listening on 127.0.0.1:{d} (Ringlane io_uring) — PING + registration live\n",
        .{try srv.boundPort()},
    );
    // Sharded multi-reactor run loop (one worker thread per shard, joined here).
    // runThreaded transparently runs a single in-line reactor when num_shards==1.
    var run = std.atomic.Value(bool).init(true);
    srv.runThreaded(&run);
}
