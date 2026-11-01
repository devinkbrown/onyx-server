// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! New-install private material is staged together and published once. Canonical
//! daemon key and certificate routines own cryptographic formats and generation.
const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");
const workflow = @import("setup_workflow.zig");
const account = @import("setup_account.zig");
pub const names = [_][]const u8{ "onyx-server.toml", "onyx-server-node.key", "cloak.secret", "tls-cert.der", "tls-key.der", account.wal_name, account.snapshot_name };

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    stage_name: []u8,
    final_path: []u8,
    config: ?[]u8 = null,
    public_key: [64]u8 = undefined,
    certificate_expires_unix: i64 = 0,
    certificate_subject: [255]u8 = undefined,
    certificate_subject_len: usize = 0,
    committed: bool = false,
    account_bytes: [32]u8 = @splat(0),
    account_len: usize = 0,
    account_privileges: []const u8 = "none",
    account_snapshot: bool = false,

    pub fn accountName(self: *const Prepared) ?[]const u8 {
        return if (self.account_len == 0) null else self.account_bytes[0..self.account_len];
    }
    pub fn materialNames(self: *const Prepared) []const []const u8 {
        return names[0..if (self.account_len == 0) @as(usize, 5) else if (self.account_snapshot) @as(usize, 7) else @as(usize, 6)];
    }

    fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Prepared {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
        const basename = std.fs.path.basename(path);
        if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidBundlePath;
        const parent_path = try std.Io.Dir.cwd().realPathFileAlloc(io, std.fs.path.dirname(path) orelse ".", allocator);
        defer allocator.free(parent_path);
        const final_path = try std.fs.path.join(allocator, &.{ parent_path, basename });
        errdefer allocator.free(final_path);
        const parent = try std.Io.Dir.openDirAbsolute(io, parent_path, .{});
        errdefer parent.close(io);
        try workflow.requireDraftOwner(.{ .handle = parent.handle, .flags = .{ .nonblocking = false } }, std.os.linux.geteuid());
        if ((try parent.stat(io)).permissions.toMode() & 0o022 != 0) return error.InsecureBundleParent;
        var nonce: [16]u8 = undefined;
        try onyx.crypto.random.fillOsEntropy(&nonce);
        const stage_name = try std.fmt.allocPrint(allocator, ".onyx-setup-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
        errdefer allocator.free(stage_name);
        try parent.createDir(io, stage_name, .fromMode(0o700));
        errdefer parent.deleteDir(io, stage_name) catch {};
        const dir = try parent.openDir(io, stage_name, .{ .follow_symlinks = false });
        errdefer dir.close(io);
        try workflow.requireDraftOwner(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } }, std.os.linux.geteuid());
        if ((try dir.stat(io)).permissions.toMode() & 0o077 != 0) return error.InsecureBundleStage;
        return .{ .allocator = allocator, .parent = parent, .dir = dir, .stage_name = stage_name, .final_path = final_path };
    }

    pub fn deinit(self: *Prepared, io: std.Io) void {
        if (self.config) |text| self.allocator.free(text);
        if (!self.committed) {
            for (names) |name| self.dir.deleteFile(io, name) catch {};
            // Remove bounded unexpected entries from this private stage without
            // following symlinks; never recurse into an unknown directory.
            if (self.dir.openDir(io, ".", .{ .iterate = true })) |scan| {
                defer scan.close(io);
                var iterator = scan.iterate();
                var remaining: usize = 256;
                while (remaining != 0) : (remaining -= 1) {
                    const entry = iterator.next(io) catch break orelse break;
                    if (entry.kind == .directory) self.dir.deleteDir(io, entry.name) catch {} else self.dir.deleteFile(io, entry.name) catch {};
                }
            } else |_| {}
            const held = self.dir.stat(io) catch null;
            const named = self.parent.statFile(io, self.stage_name, .{ .follow_symlinks = false }) catch null;
            if (held != null and named != null and named.?.kind == .directory and held.?.inode == named.?.inode) self.parent.deleteDir(io, self.stage_name) catch {};
        }
        self.dir.close(io);
        self.parent.close(io);
        self.allocator.free(self.stage_name);
        self.allocator.free(self.final_path);
        self.* = undefined;
    }

    pub fn commit(self: *Prepared, io: std.Io) !void {
        if (self.committed) return error.AlreadyCommitted;
        try self.parent.renamePreserve(self.stage_name, self.parent, std.fs.path.basename(self.final_path), io);
        self.committed = true;
    }
};

/// Private custody record: never serialize or log these digests.
pub const Custody = struct {
    directory_inode: std.Io.File.INode,
    directory_mode: u32,
    file_count: usize,
    files: [names.len]File = @splat(.{}),
    const File = struct { inode: std.Io.File.INode = 0, size: u64 = 0, mode: u32 = 0, digest: [32]u8 = @splat(0) };
    pub fn wipe(self: *Custody) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Snapshot the exact held stage and its regular private files with bounded
/// streaming reads; any additional/replaced material is rejected.
pub fn captureCustody(bundle: *const Prepared, io: std.Io) !Custody {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    try workflow.requireDraftOwner(.{ .handle = bundle.dir.handle, .flags = .{ .nonblocking = false } }, std.os.linux.geteuid());
    const stage_stat = try bundle.dir.stat(io);
    const named = try bundle.parent.statFile(io, bundle.stage_name, .{ .follow_symlinks = false });
    if (stage_stat.kind != .directory or named.kind != .directory or stage_stat.inode != named.inode or stage_stat.permissions.toMode() & 0o7077 != 0) return error.BundleStageChanged;
    const scan = try bundle.parent.openDir(io, bundle.stage_name, .{ .iterate = true, .follow_symlinks = false });
    defer scan.close(io);
    if ((try scan.stat(io)).inode != stage_stat.inode) return error.BundleStageChanged;
    const expected = bundle.materialNames();
    var seen: [names.len]bool = @splat(false);
    var iter = scan.iterate();
    while (try iter.next(io)) |entry| {
        var found = false;
        for (expected, 0..) |name, i| {
            if (!std.mem.eql(u8, entry.name, name)) continue;
            if (seen[i]) return error.BundleStageChanged;
            seen[i] = true;
            found = true;
            break;
        }
        if (!found) return error.BundleStageChanged;
    }
    var custody: Custody = .{ .directory_inode = stage_stat.inode, .directory_mode = stage_stat.permissions.toMode() & 0o7777, .file_count = expected.len };
    errdefer custody.wipe();
    for (expected, 0..) |name, i| {
        if (!seen[i]) return error.BundleStageChanged;
        // O_PATH cannot block on a FIFO or device. Reopen only this held,
        // already-validated regular inode through procfs, never the name.
        const held = try bundle.dir.openFile(io, name, .{ .path_only = true, .follow_symlinks = false });
        defer held.close(io);
        try workflow.requireDraftOwner(held, std.os.linux.geteuid());
        const held_stat = try held.stat(io);
        if (held_stat.kind != .file or held_stat.nlink != 1 or held_stat.permissions.toMode() & 0o7177 != 0 or held_stat.size > 16 * 1024 * 1024) return error.BundleStageChanged;
        var fd_path_buf: [64]u8 = undefined;
        const fd_path = try std.fmt.bufPrint(&fd_path_buf, "/proc/self/fd/{d}", .{held.handle});
        const file = try std.Io.Dir.openFileAbsolute(io, fd_path, .{});
        defer file.close(io);
        try workflow.requireDraftOwner(file, std.os.linux.geteuid());
        const stat = try file.stat(io);
        if (stat.kind != .file or stat.inode != held_stat.inode or stat.nlink != 1 or stat.permissions.toMode() & 0o7177 != 0 or stat.size > 16 * 1024 * 1024) return error.BundleStageChanged;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [4096]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer);
        var total: u64 = 0;
        while (true) {
            const n = file.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            total += n;
            if (total > stat.size) return error.BundleStageChanged;
            hasher.update(buffer[0..n]);
        }
        if (total != stat.size) return error.BundleStageChanged;
        custody.files[i] = .{ .inode = stat.inode, .size = stat.size, .mode = stat.permissions.toMode() & 0o7777 };
        hasher.final(&custody.files[i].digest);
    }
    return custody;
}

pub fn verifyCustody(bundle: *const Prepared, io: std.Io, expected: *const Custody) !void {
    var observed = try captureCustody(bundle, io);
    defer observed.wipe();
    if (!std.meta.eql(expected.*, observed)) return error.BundleStageChanged;
}

const Resolver = struct {
    cloak_path: []const u8,
    cloak: []const u8,
    fn file(ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
        const self: *const Resolver = @ptrCast(@alignCast(ctx orelse return error.MissingResolver));
        if (!std.mem.eql(u8, path, self.cloak_path)) return error.UnexpectedSecretReference;
        return allocator.dupe(u8, self.cloak);
    }
};

pub fn prepare(allocator: std.mem.Allocator, io: std.Io, path: []const u8, profile: workflow.Profile, settings: workflow.Settings, base: onyx.daemon.server.Config, comptime validate: anytype) !Prepared {
    return prepareAuthenticated(allocator, io, path, profile, settings, base, null, null, validate);
}

pub fn prepareAuthenticated(allocator: std.mem.Allocator, io: std.Io, path: []const u8, profile: workflow.Profile, settings: workflow.Settings, base: onyx.daemon.server.Config, password: ?[]const u8, fault: ?onyx.daemon.store.PreparedIoFault, comptime validate: anytype) !Prepared {
    return prepareAuthenticatedWithAccountPolicy(allocator, io, path, profile, settings, base, password, fault, .production, validate);
}

/// Explicit allocation-sweep-only entry; absent from non-test builds. Neither
/// runtime CLI options nor ordinary prepareAuthenticated calls select it.
pub const AllocationFailureSweep = if (builtin.is_test) struct {
    pub fn prepareAuthenticated(allocator: std.mem.Allocator, io: std.Io, path: []const u8, profile: workflow.Profile, settings: workflow.Settings, base: onyx.daemon.server.Config, password: ?[]const u8, fault: ?onyx.daemon.store.PreparedIoFault, comptime validate: anytype) !Prepared {
        return prepareAuthenticatedWithAccountPolicy(allocator, io, path, profile, settings, base, password, fault, .allocation_failure_sweep, validate);
    }
} else struct {};

const AccountPolicy = enum { production, allocation_failure_sweep };

fn prepareAuthenticatedWithAccountPolicy(allocator: std.mem.Allocator, io: std.Io, path: []const u8, profile: workflow.Profile, settings: workflow.Settings, base: onyx.daemon.server.Config, password: ?[]const u8, fault: ?onyx.daemon.store.PreparedIoFault, comptime account_policy: AccountPolicy, comptime validate: anytype) !Prepared {
    if (comptime !builtin.is_test and account_policy != .production) @compileError("reduced bundle work is test-only");
    if (settings.bootstrap.enabled() and password == null) return error.BootstrapPasswordRequired;
    if (!settings.tls_enabled) return error.BundleRequiresTls;
    try settings.validate();
    var result = try Prepared.open(allocator, io, path);
    errdefer result.deinit(io);
    var node = try onyx.daemon.node_keyfile.loadOrCreate(allocator, io, result.dir, onyx.daemon.node_keyfile.default_basename);
    defer std.crypto.secureZero(u8, &node.seed);
    var identity = try onyx.daemon.node_identity.fromSeed(node.seed, "");
    defer identity.deinit();
    result.public_key = std.fmt.bytesToHex(identity.sign_kp.public_key, .lower);
    var cloak: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &cloak);
    try onyx.crypto.random.fillOsEntropy(&cloak);
    var cloak_hex = std.fmt.bytesToHex(cloak, .lower);
    defer std.crypto.secureZero(u8, &cloak_hex);
    try workflow.publish(io, result.dir, "cloak.secret", &cloak_hex);
    var tls = try onyx.daemon.tls_certs.loadOrBootstrap(allocator, io, .{ .enabled = true, .dns_name = settings.hostname });
    defer tls.deinit(allocator);
    try onyx.crypto.x509_verify.validateServerChainAt(tls.cert_chain, std.Io.Clock.real.now(io).toSeconds());
    const certificate = try onyx.proto.x509.parseCertificate(tls.cert_chain[0]);
    result.certificate_expires_unix = certificate.not_after;
    if (certificate.subject_common_name.len > result.certificate_subject.len) return error.InvalidBundleCertificate;
    result.certificate_subject_len = certificate.subject_common_name.len;
    @memcpy(result.certificate_subject[0..result.certificate_subject_len], certificate.subject_common_name);
    var tls_seed = tls.signing_key.?.secret_key.seed();
    defer std.crypto.secureZero(u8, &tls_seed);
    var key_buffer: [onyx.proto.ed25519_pkcs8.der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_buffer);
    const key_der = try onyx.proto.ed25519_pkcs8.encode(&key_buffer, tls_seed);
    try workflow.publish(io, result.dir, "tls-key.der", key_der);
    try workflow.publish(io, result.dir, "tls-cert.der", tls.cert_chain[0]);
    const staged_cert = try std.fs.path.join(allocator, &.{ std.fs.path.dirname(result.final_path).?, result.stage_name, "tls-cert.der" });
    defer allocator.free(staged_cert);
    const staged_key = try std.fs.path.join(allocator, &.{ std.fs.path.dirname(result.final_path).?, result.stage_name, "tls-key.der" });
    defer allocator.free(staged_key);
    var reloaded_tls = try onyx.daemon.tls_certs.loadOrBootstrap(allocator, io, .{ .cert_path = staged_cert, .key_path = staged_key });
    defer reloaded_tls.deinit(allocator);
    try onyx.crypto.x509_verify.validateServerChainAt(reloaded_tls.cert_chain, std.Io.Clock.real.now(io).toSeconds());
    if (!std.crypto.timing_safe.eql([32]u8, tls.signing_key.?.public_key.toBytes(), reloaded_tls.signing_key.?.public_key.toBytes())) return error.TlsKeyMismatch;
    var persisted_seed = try onyx.daemon.node_keyfile.loadExisting(allocator, io, result.dir, onyx.daemon.node_keyfile.default_basename);
    defer std.crypto.secureZero(u8, &persisted_seed);
    if (!std.crypto.timing_safe.eql([32]u8, node.seed, persisted_seed)) return error.NodeIdentityMismatch;
    result.config = try workflow.configuredCandidate(allocator, profile, settings, result.final_path);
    if (settings.bootstrap.enabled()) {
        try workflow.publish(io, result.dir, account.wal_name, "");
        if (comptime account_policy == .production) {
            try account.provision(allocator, io, result.dir, settings.bootstrap, password.?, fault);
        } else {
            try account.AllocationFailureSweep.provision(allocator, io, result.dir, settings.bootstrap, password.?, fault);
        }
        const canonical = try settings.bootstrap.canonical();
        result.account_len = canonical.asSlice().len;
        @memcpy(result.account_bytes[0..result.account_len], canonical.asSlice());
        result.account_privileges = settings.bootstrap.privileges;
        result.account_snapshot = if (result.dir.statFile(io, account.snapshot_name, .{ .follow_symlinks = false })) |_| true else |err| switch (err) {
            error.FileNotFound => false,
            else => return err,
        };
        const extended = try account.appendConfig(allocator, result.config.?, result.final_path, settings.bootstrap);
        allocator.free(result.config.?);
        result.config = extended;
    }
    const cloak_path = try std.fs.path.join(allocator, &.{ result.final_path, "cloak.secret" });
    defer allocator.free(cloak_path);
    var resolver = Resolver{ .cloak_path = cloak_path, .cloak = &cloak_hex };
    var loaded = try onyx.daemon.config_boot.loadFromTextQuiet(allocator, result.config.?, base, .{ .ctx = &resolver, .file = Resolver.file });
    defer loaded.deinit(allocator);
    defer if (loaded.parsed.cloak.secret) |secret| std.crypto.secureZero(u8, @constCast(secret));
    if (validate(&loaded) != null) return error.InvalidBundleConfiguration;
    if (settings.bootstrap.enabled()) {
        const permissions = try settings.bootstrap.permissions();
        if (permissions.count() != 0) {
            const registry = loaded.config.oper_registry orelse return error.BootstrapOperatorMissing;
            const binding = registry.lookup(result.accountName().?) orelse return error.BootstrapOperatorMissing;
            if (binding.privileges.toBits() != permissions.toBits()) return error.BootstrapOperatorMismatch;
        } else if (loaded.config.oper_registry != null) return error.UnexpectedBootstrapOperator;
    }
    try workflow.publish(io, result.dir, "onyx-server.toml", result.config.?);
    return result;
}
