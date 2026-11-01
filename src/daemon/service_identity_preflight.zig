// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only identity preparation for a managed service. No file is created,
//! changed, or opened for writing. The caller must carry the returned identity
//! into startup: a later independent config/key reload would reopen the race.
const std = @import("std");
const builtin = @import("builtin");
const boot = @import("config_boot.zig");
const format = @import("config_format.zig");
const server = @import("server.zig");
const keyfile = @import("node_keyfile.zig");
const identity = @import("node_identity.zig");
const toml = @import("../proto/toml.zig");
const live = @import("helix/live.zig");

// Reject in-place resizing/remapping so every abandoned buffer passes through
// secureFree. This also leaves each allocation visible to failure injection.
const WipingAllocator = struct {
    parent: std.mem.Allocator,
    fn allocator(self: *WipingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(len, alignment, ra);
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, bytes);
        self.parent.rawFree(bytes, alignment, ra);
    }
};
const key_file_limit = 4096;
pub const Source = enum { configured, existing_keyfile };
pub const Prepared = struct {
    source: Source,
    node: identity.NodeIdentity,
    pub fn deinit(self: *Prepared) void {
        self.node.deinit();
        self.* = undefined;
    }
};

/// Owns the parsed config and its matching validated identity as one snapshot.
/// Keep this owner alive until every consumer of `loaded` and `identity` ends.
/// `takeIdentity` transfers ownership exactly once; the caller must deinit it.
pub const PreparedBoot = struct {
    wiping: WipingAllocator,
    loaded: boot.Loaded,
    identity: ?Prepared,
    env_bindings: live.ConfigEnvCollector,
    pub fn takeIdentity(self: *PreparedBoot) ?Prepared {
        const value = self.identity orelse return null;
        self.identity = null;
        return value;
    }
    pub fn deinit(self: *PreparedBoot) void {
        if (self.identity) |*value| value.deinit();
        self.loaded.deinit(self.wiping.allocator());
        self.env_bindings.deinit();
        const parent = self.wiping.parent;
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        parent.destroy(self);
    }
};

fn requirePrivate(fd: std.posix.fd_t) !void {
    const linux = std.os.linux;
    var info: linux.Statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .NLINK = true }, &info))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.PrivateCustodyUnavailable,
    };
    if (!info.mask.TYPE or !info.mask.MODE or !info.mask.UID or !info.mask.NLINK or
        info.uid != linux.geteuid() or info.mode & std.posix.S.IFMT != std.posix.S.IFREG or
        (info.mode & 0o7777 != 0o600 and info.mode & 0o7777 != 0o400) or info.nlink != 1) return error.InsecurePrivateFile;
}

// A root-owned sticky parent (e.g. /tmp) may be world-writable: sticky
// semantics prevent an untrusted user from replacing the next trusted-owned
// entry. Every opened child directory and final file is checked independently.
pub fn trustedDirectory(uid: u32, mode: u16, effective_uid: u32) bool {
    if (uid != 0 and uid != effective_uid) return false;
    if (mode & 0o022 == 0) return true;
    return uid == 0 and mode & 0o1000 != 0;
}
fn requireTrustedDirectory(fd: std.posix.fd_t) !void {
    const linux = std.os.linux;
    var info: linux.Statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true }, &info))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.PrivateCustodyUnavailable,
    };
    if (!info.mask.TYPE or !info.mask.MODE or !info.mask.UID or
        info.mode & std.posix.S.IFMT != std.posix.S.IFDIR or
        !trustedDirectory(info.uid, info.mode, linux.geteuid())) return error.InsecurePrivateDirectory;
}

// Traverse every ancestor without following symlinks and reopen only the held
// regular file through procfs. Input is bounded and wiped on every exit path.
fn readPrivate(a: std.mem.Allocator, io: std.Io, cwd: std.Io.Dir, path: []const u8, limit: usize) ![]u8 {
    if (path.len == 0 or path.len > 4096 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.InvalidPath;
    var dir = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false })
    else
        try cwd.openDir(io, ".", .{ .follow_symlinks = false });
    defer dir.close(io);
    try requireTrustedDirectory(dir.handle);
    var parts = std.mem.tokenizeScalar(u8, std.fs.path.dirname(path) orelse ".", '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        const next = try dir.openDir(io, part, .{ .follow_symlinks = false });
        dir.close(io);
        dir = next;
        try requireTrustedDirectory(dir.handle);
    }
    const held = try dir.openFile(io, base, .{ .path_only = true, .follow_symlinks = false });
    defer held.close(io);
    try requirePrivate(held.handle);
    var fd_buf: [64]u8 = undefined;
    const fd_path = try std.fmt.bufPrint(&fd_buf, "/proc/self/fd/{d}", .{held.handle});
    const file = try std.Io.Dir.openFileAbsolute(io, fd_path, .{});
    defer file.close(io);
    try requirePrivate(file.handle);
    if ((try file.stat(io)).inode != (try held.stat(io)).inode) return error.InsecurePrivateFile;
    const bytes = try a.alloc(u8, limit + 1);
    defer a.free(bytes);
    var len: usize = 0;
    while (len < bytes.len) {
        const n = file.readStreaming(io, &.{bytes[len..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        len += n;
    }
    if (len > limit) return error.LimitExceeded;
    return a.dupe(u8, bytes[0..len]);
}

const Resolve = struct {
    io: std.Io,
    cwd: std.Io.Dir,
    upstream: format.Resolver,
    secret_file: ?[]const u8,
    owner: *PreparedBoot,
    fn env(ctx: ?*anyopaque, a: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
        const self: *Resolve = @ptrCast(@alignCast(ctx.?));
        const lookup = self.upstream.env orelse return error.EnvironmentVariableNotFound;
        const value = try lookup(self.upstream.ctx, a, name);
        errdefer a.free(value);
        try self.owner.env_bindings.record(name, value);
        return value;
    }
    fn file(ctx: ?*anyopaque, a: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
        const self: *Resolve = @ptrCast(@alignCast(ctx.?));
        if (self.secret_file) |secret_path| if (std.mem.eql(u8, secret_path, path)) {
            const bytes = try readPrivate(a, self.io, self.cwd, path, 1 << 20);
            return bytes;
        };
        const lookup = self.upstream.file orelse return error.FileNotFound;
        return lookup(self.upstream.ctx, a, path);
    }
};

/// `upstream` is the daemon's ordinary resolver, using the same process env
/// and cwd. Key-bearing files are checked as uid-owned 0400 or 0600 regular files.
/// All parser allocations are wiped on free, including partial parses and resolver copies.
pub fn loadPreparedBoot(allocator: std.mem.Allocator, io: std.Io, cwd: std.Io.Dir, config_path: []const u8, base: server.Config, upstream: format.Resolver) !*PreparedBoot {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const owner = try allocator.create(PreparedBoot);
    errdefer {
        std.crypto.secureZero(u8, std.mem.asBytes(owner));
        allocator.destroy(owner);
    }
    owner.wiping = .{ .parent = allocator };
    owner.env_bindings = live.ConfigEnvCollector.init(owner.wiping.allocator());
    errdefer owner.env_bindings.deinit();
    const a = owner.wiping.allocator();
    const text = try readPrivate(a, io, cwd, config_path, format.max_config_bytes);
    defer a.free(text);
    var doc = try toml.parse(a, text);
    defer doc.deinit(a);
    if (doc.get("node.secret_key")) |value| if (value.* != .string) return error.InvalidNodeSecretType;
    if (doc.get("node.public_key")) |value| if (value.* != .string) return error.InvalidNodePublicType;
    const configured = doc.getString("node.secret_key");
    const secret_file = if (configured) |raw| if (std.mem.startsWith(u8, raw, "@file:")) raw[6..] else null else null;
    var resolve = Resolve{ .io = io, .cwd = cwd, .upstream = upstream, .secret_file = secret_file, .owner = owner };
    var loaded = try boot.loadFromTextQuiet(a, text, base, .{ .ctx = &resolve, .env = Resolve.env, .file = Resolve.file });
    errdefer loaded.deinit(a);
    var prepared: Prepared = if (loaded.parsed.node.secret_key) |secret| .{
        .source = .configured,
        .node = try identity.fromConfig(secret, loaded.parsed.mesh.realm),
    } else blk: {
        const path = try keyfile.derivePath(a, config_path);
        defer a.free(path);
        const encoded = try readPrivate(a, io, cwd, path, key_file_limit);
        defer a.free(encoded);
        var seed = try keyfile.parseSeedHex(encoded);
        defer std.crypto.secureZero(u8, &seed);
        break :blk .{ .source = .existing_keyfile, .node = try identity.fromSeed(seed, loaded.parsed.mesh.realm) };
    };
    errdefer prepared.deinit();
    if (loaded.parsed.node.public_key) |public| {
        var expected: [32]u8 = undefined;
        if (public.len == expected.len * 2) {
            _ = std.fmt.hexToBytes(&expected, public) catch return error.BadPublicKey;
        } else {
            const size = std.base64.standard.Decoder.calcSizeForSlice(public) catch return error.BadPublicKey;
            if (size != expected.len) return error.BadPublicKey;
            std.base64.standard.Decoder.decode(&expected, public) catch return error.BadPublicKey;
        }
        if (!std.crypto.timing_safe.eql([32]u8, expected, prepared.node.sign_kp.public_key)) return error.PublicKeyMismatch;
    }
    owner.loaded = loaded;
    owner.identity = prepared;
    return owner;
}

/// Compatibility convenience: the returned identity owns its own resources;
/// this deliberately discards the parsed configuration snapshot.
pub fn prepare(allocator: std.mem.Allocator, io: std.Io, cwd: std.Io.Dir, config_path: []const u8, base: server.Config, upstream: format.Resolver) !Prepared {
    const owner = try loadPreparedBoot(allocator, io, cwd, config_path, base, upstream);
    defer owner.deinit();
    return owner.takeIdentity() orelse unreachable;
}

/// Exactly one non-option config path; rejects trailing arguments.
pub fn strictPath(path: ?[]const u8, extra: ?[]const u8) ![]const u8 {
    const value = path orelse return error.InvalidServiceArguments;
    if (value.len == 0 or value[0] == '-' or extra != null) return error.InvalidServiceArguments;
    return value;
}

pub const SupervisorPath = struct { path: ?[]const u8, strict: bool };
/// Helix appends the strict flag after its carried config path.
pub fn supervisorPath(path: ?[]const u8, flag: ?[]const u8, extra: ?[]const u8) !SupervisorPath {
    if (path) |value| if (std.mem.eql(u8, value, live.strict_existing_identity_arg))
        return error.InvalidServiceArguments;
    if (flag) |value| {
        if (!std.mem.eql(u8, value, live.strict_existing_identity_arg)) return error.InvalidServiceArguments;
        return .{ .path = try strictPath(path, extra), .strict = true };
    }
    if (extra != null) return error.InvalidServiceArguments;
    return .{ .path = path, .strict = false };
}

test "service identity: bounded environment custody deduplicates and rejects conflict" {
    var owner: PreparedBoot = undefined;
    owner.wiping = .{ .parent = std.testing.allocator };
    owner.env_bindings = live.ConfigEnvCollector.init(owner.wiping.allocator());
    defer owner.env_bindings.deinit();
    try owner.env_bindings.record("KEY", "one");
    try owner.env_bindings.record("KEY", "one");
    try std.testing.expectEqual(@as(usize, 1), owner.env_bindings.view().len);
    try std.testing.expectError(error.ConflictingConfigEnvironment, owner.env_bindings.record("KEY", "two"));
    try std.testing.expectEqual(@as(usize, 1), owner.env_bindings.view().len);
    try std.testing.expectError(error.InvalidBootPolicy, owner.env_bindings.record("LISTEN_FDS", "3"));
    try std.testing.expectEqual(@as(usize, 1), owner.env_bindings.view().len);
    for (0..63) |i| {
        var name: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&name, "REF{d}", .{i});
        try owner.env_bindings.record(text, "v");
    }
    try std.testing.expectEqual(@as(usize, 64), owner.env_bindings.view().len);
    try std.testing.expectError(error.InvalidBootPolicy, owner.env_bindings.record("EXTRA", "v"));
    try std.testing.expectEqual(@as(usize, 64), owner.env_bindings.view().len);
    var total_owner: PreparedBoot = undefined;
    total_owner.wiping = .{ .parent = std.testing.allocator };
    total_owner.env_bindings = live.ConfigEnvCollector.init(total_owner.wiping.allocator());
    defer total_owner.env_bindings.deinit();
    const large: [4096]u8 = @splat('v');
    const overlong: [4097]u8 = @splat('v');
    try std.testing.expectError(error.InvalidBootPolicy, total_owner.env_bindings.record("TOO_LONG", &overlong));
    for (0..7) |i| {
        var name: [16]u8 = undefined;
        try total_owner.env_bindings.record(try std.fmt.bufPrint(&name, "L{d}", .{i}), &large);
    }
    try std.testing.expectError(error.InvalidBootPolicy, total_owner.env_bindings.record("L7", &large));
    try std.testing.expectEqual(@as(usize, 7), total_owner.env_bindings.view().len);
}
