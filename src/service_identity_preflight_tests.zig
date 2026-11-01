// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
const std = @import("std");
const builtin = @import("builtin");
const service = @import("daemon/service_identity_preflight.zig");
const node_identity = @import("daemon/node_identity.zig");
const io = std.testing.io;
const seed = "4242424242424242424242424242424242424242424242424242424242424242";

fn write(dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const opened_file = try dir.createFile(io, name, .{ .permissions = .fromMode(0o600) });
    defer opened_file.close(io);
    try opened_file.writeStreamingAll(io, bytes);
}
fn env(_: ?*anyopaque, a: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (!std.mem.eql(u8, name, "NODE_TEST_SECRET")) return error.EnvironmentVariableNotFound;
    return a.dupe(u8, seed);
}
fn file(_: ?*anyopaque, a: std.mem.Allocator, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1 << 20));
}
fn prepare(a: std.mem.Allocator, path: []const u8) !service.Prepared {
    return service.prepare(a, io, std.Io.Dir.cwd(), path, .{ .port = 6680 }, .{ .env = env, .file = file });
}
fn expectSeed(result: *const service.Prepared) !void {
    var expected = try node_identity.fromConfig(seed, "local");
    defer expected.deinit();
    try std.testing.expectEqualSlices(u8, &expected.node_id, &result.node.node_id);
}
// Config's existing resolver maps allocation errors to ParseError, so assert
// fail-closed at every induced cut instead of requiring one particular error.
fn exerciseAllocationCuts(path: []const u8) !void {
    var cut: usize = 0;
    while (cut < 8192) : (cut += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = cut });
        if (prepare(failing.allocator(), path)) |value| {
            var result = value;
            defer result.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try expectSeed(&result);
            try std.testing.expect(cut != 0);
            return;
        } else |err| {
            if (!failing.has_induced_failure) return err;
        }
    }
    return error.AllocationSweepDidNotComplete;
}

test "service identity: inline, environment, referenced file and existing seed are read only" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const config_path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(config_path);
    const secret_path = try std.fs.path.join(a, &.{ root, "reference.key" });
    defer a.free(secret_path);
    try write(tmp.dir, "reference.key", seed);
    const inline_config = "[node]\nid=1\nsecret_key=\"" ++ seed ++ "\"\n[listen]\nirc=6680\ns2s=0\n";
    try write(tmp.dir, "onyx.toml", inline_config);
    var inline_result = try prepare(a, config_path);
    defer inline_result.deinit();
    try tmp.dir.setFilePermissions(io, "onyx.toml", .fromMode(0o400), .{});
    var readonly_inline = try prepare(a, config_path);
    defer readonly_inline.deinit();
    try expectSeed(&readonly_inline);
    try tmp.dir.setFilePermissions(io, "onyx.toml", .fromMode(0o600), .{});
    try std.testing.expectEqual(service.Source.configured, inline_result.source);
    try expectSeed(&inline_result);
    try exerciseAllocationCuts(config_path);
    // No adjacent seed is required or produced by inline configuration.
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "onyx-server-node.key", .{}));
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"env:NODE_TEST_SECRET\"\n[listen]\nirc=6680\ns2s=0\n");
    var env_result = try prepare(a, config_path);
    defer env_result.deinit();
    try expectSeed(&env_result);
    try exerciseAllocationCuts(config_path);
    const ref_config = try std.fmt.allocPrint(a, "[node]\nid=1\nsecret_key=\"@file:{s}\"\n[listen]\nirc=6680\ns2s=0\n", .{secret_path});
    defer a.free(ref_config);
    try write(tmp.dir, "onyx.toml", ref_config);
    try tmp.dir.setFilePermissions(io, "reference.key", .fromMode(0o400), .{});
    var ref_result = try prepare(a, config_path);
    defer ref_result.deinit();
    try expectSeed(&ref_result);
    try exerciseAllocationCuts(config_path);
    const unchanged_reference = try tmp.dir.readFileAlloc(io, "reference.key", a, .limited(4096));
    defer a.free(unchanged_reference);
    try std.testing.expectEqualStrings(seed, unchanged_reference);
    try tmp.dir.setFilePermissions(io, "reference.key", .fromMode(0o600), .{});
    const file_config = "[node]\nid=1\n[listen]\nirc=6680\ns2s=0\n";
    try write(tmp.dir, "onyx.toml", file_config);
    try write(tmp.dir, "onyx-server-node.key", seed ++ "\n");
    try tmp.dir.setFilePermissions(io, "onyx-server-node.key", .fromMode(0o400), .{});
    try tmp.dir.setFilePermissions(io, "onyx.toml", .fromMode(0o400), .{});
    var file_result = try prepare(a, config_path);
    defer file_result.deinit();
    try std.testing.expectEqual(service.Source.existing_keyfile, file_result.source);
    try expectSeed(&file_result);
    const unchanged_seed = try tmp.dir.readFileAlloc(io, "onyx-server-node.key", a, .limited(4096));
    defer a.free(unchanged_seed);
    try std.testing.expectEqualStrings(seed ++ "\n", unchanged_seed);
    const unchanged_config = try tmp.dir.readFileAlloc(io, "onyx.toml", a, .limited(4096));
    defer a.free(unchanged_config);
    try std.testing.expectEqualStrings(file_config, unchanged_config);
    try exerciseAllocationCuts(config_path);
}

test "service identity: missing malformed permissive and symlink inputs fail closed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const config_path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(config_path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\n[listen]\nirc=6680\ns2s=0\n");
    try std.testing.expectError(error.FileNotFound, prepare(a, config_path));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "onyx-server-node.key", .{}));
    try write(tmp.dir, "onyx-server-node.key", "bad\n");
    try std.testing.expectError(error.BadSeed, prepare(a, config_path));
    try write(tmp.dir, "onyx-server-node.key", seed);
    try tmp.dir.setFilePermissions(io, "onyx-server-node.key", .fromMode(0o000), .{});
    try std.testing.expectError(error.InsecurePrivateFile, prepare(a, config_path));
    try tmp.dir.setFilePermissions(io, "onyx-server-node.key", .fromMode(0o644), .{});
    try std.testing.expectError(error.InsecurePrivateFile, prepare(a, config_path));
    try tmp.dir.setFilePermissions(io, "onyx-server-node.key", .fromMode(0o600), .{});
    try tmp.dir.setFilePermissions(io, "onyx.toml", .fromMode(0o644), .{});
    try std.testing.expectError(error.InsecurePrivateFile, prepare(a, config_path));
    try tmp.dir.setFilePermissions(io, "onyx.toml", .fromMode(0o600), .{});
    try tmp.dir.deleteFile(io, "onyx-server-node.key");
    try write(tmp.dir, "seed-target", seed);
    try tmp.dir.symLink(io, "seed-target", "onyx-server-node.key", .{});
    if (prepare(a, config_path)) |value| {
        var bad = value;
        bad.deinit();
        return error.SymlinkAccepted;
    } else |_| {}
    try tmp.dir.deleteFile(io, "onyx-server-node.key");
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"bad\"\n[listen]\nirc=6680\ns2s=0\n");
    try std.testing.expectError(error.BadSeed, prepare(a, config_path));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "onyx-server-node.key", .{}));
}

test "service identity: hardlinked and private-reference violations refuse" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const config_path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(config_path);
    const secret_path = try std.fs.path.join(a, &.{ root, "reference.key" });
    defer a.free(secret_path);
    const text = try std.fmt.allocPrint(a, "[node]\nid=1\nsecret_key=\"@file:{s}\"\n[listen]\nirc=6680\ns2s=0\n", .{secret_path});
    defer a.free(text);
    try write(tmp.dir, "onyx.toml", text);
    try write(tmp.dir, "reference.key", seed);
    try tmp.dir.setFilePermissions(io, "reference.key", .fromMode(0o644), .{});
    if (prepare(a, config_path)) |value| {
        var bad = value;
        bad.deinit();
        return error.PermissiveReferenceAccepted;
    } else |_| {}
    try tmp.dir.setFilePermissions(io, "reference.key", .fromMode(0o600), .{});
    const linux = std.os.linux;
    const rc = linux.linkat(tmp.dir.handle, "reference.key", tmp.dir.handle, "reference-hardlink", 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    if (prepare(a, config_path)) |value| {
        var bad = value;
        bad.deinit();
        return error.HardlinkedReferenceAccepted;
    } else |_| {}
    try tmp.dir.deleteFile(io, "reference-hardlink");
    try tmp.dir.deleteFile(io, "reference.key");
    try tmp.dir.symLink(io, "onyx.toml", "reference.key", .{});
    if (prepare(a, config_path)) |value| {
        var bad = value;
        bad.deinit();
        return error.SymlinkReferenceAccepted;
    } else |_| {}
    try tmp.dir.deleteFile(io, "reference.key");
    try tmp.dir.symLink(io, "onyx.toml", "config-link", .{});
    const linked_config = try std.fs.path.join(a, &.{ root, "config-link" });
    defer a.free(linked_config);
    if (prepare(a, linked_config)) |value| {
        var bad = value;
        bad.deinit();
        return error.SymlinkConfigAccepted;
    } else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "onyx-server-node.key", .{}));
}

const WipeProbe = struct {
    parent: std.mem.Allocator,
    frees: usize = 0,
    all_zero: bool = true,
    fn allocator(self: *WipeProbe) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipeProbe = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(len, alignment, ra);
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *WipeProbe = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        for (bytes) |byte| if (byte != 0) {
            self.all_zero = false;
        };
        self.parent.rawFree(bytes, alignment, ra);
    }
};

test "service identity: all preflight buffers are wiped before release" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const config_path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(config_path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"" ++ seed ++ "\"\n[listen]\nirc=6680\ns2s=0\n");
    var probe = WipeProbe{ .parent = a };
    var result = try prepare(probe.allocator(), config_path);
    result.deinit();
    try std.testing.expect(probe.frees > 0);
    try std.testing.expect(probe.all_zero);
}

test "service identity: trusted parent ownership, writable and sticky rules" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const uid = std.os.linux.geteuid();
    const other: u32 = if (uid == 12345) 12346 else 12345;
    try std.testing.expect(service.trustedDirectory(0, 0o755, uid));
    try std.testing.expect(service.trustedDirectory(0, 0o750, uid));
    try std.testing.expect(service.trustedDirectory(uid, 0o700, uid));
    try std.testing.expect(service.trustedDirectory(0, 0o1777, uid));
    try std.testing.expect(!service.trustedDirectory(other, 0o700, uid));
    try std.testing.expect(!service.trustedDirectory(other, 0o1777, uid));
    try std.testing.expect(!service.trustedDirectory(0, 0o777, uid));
    if (uid != 0) try std.testing.expect(!service.trustedDirectory(uid, 0o1777, uid));
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"" ++ seed ++ "\"\n[listen]\nirc=6680\ns2s=0\n");
    var good = try prepare(a, path);
    good.deinit();
    try tmp.dir.setPermissions(io, .fromMode(0o770));
    try std.testing.expectError(error.InsecurePrivateDirectory, prepare(a, path));
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    var restored = try prepare(a, path);
    restored.deinit();
}

test "service identity: present nonstring secret or public key cannot fall back" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx-server-node.key", seed ++ "\n");
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=123\n[listen]\nirc=6680\ns2s=0\n");
    try std.testing.expectError(error.InvalidNodeSecretType, prepare(a, path));
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\npublic_key=123\n[listen]\nirc=6680\ns2s=0\n");
    try std.testing.expectError(error.InvalidNodePublicType, prepare(a, path));
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"" ++ seed ++ "\"\npublic_key=123\n[listen]\nirc=6680\ns2s=0\n");
    try std.testing.expectError(error.InvalidNodePublicType, prepare(a, path));
    const original = try tmp.dir.readFileAlloc(io, "onyx-server-node.key", a, .limited(4096));
    defer a.free(original);
    try std.testing.expectEqualStrings(seed ++ "\n", original);
}

test "service identity: configured public key binds both identity sources" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx-server-node.key", seed ++ "\n");
    var expected = try node_identity.fromConfig(seed, "local");
    defer expected.deinit();
    const pubhex = std.fmt.bytesToHex(expected.sign_kp.public_key, .lower);
    var b64_buffer: [44]u8 = undefined;
    const pub64 = std.base64.standard.Encoder.encode(&b64_buffer, &expected.sign_kp.public_key);
    const badhex: [64]u8 = @splat('0');
    for ([_]bool{ false, true }) |inline_secret| {
        const secret_line: []const u8 = if (inline_secret) "secret_key=\"" ++ seed ++ "\"\n" else "";
        for ([_][]const u8{ &pubhex, pub64 }) |key| {
            const config = try std.fmt.allocPrint(a, "[node]\nid=1\n{s}public_key=\"{s}\"\n[listen]\nirc=6680\ns2s=0\n", .{ secret_line, key });
            defer a.free(config);
            try write(tmp.dir, "onyx.toml", config);
            var result = try prepare(a, path);
            defer result.deinit();
            try std.testing.expectEqual(if (inline_secret) service.Source.configured else service.Source.existing_keyfile, result.source);
            try expectSeed(&result);
        }
        const mismatch = try std.fmt.allocPrint(a, "[node]\nid=1\n{s}public_key=\"{s}\"\n[listen]\nirc=6680\ns2s=0\n", .{ secret_line, &badhex });
        defer a.free(mismatch);
        try write(tmp.dir, "onyx.toml", mismatch);
        try std.testing.expectError(error.PublicKeyMismatch, prepare(a, path));
        const malformed = try std.fmt.allocPrint(a, "[node]\nid=1\n{s}public_key=\"bad\"\n[listen]\nirc=6680\ns2s=0\n", .{secret_line});
        defer a.free(malformed);
        try write(tmp.dir, "onyx.toml", malformed);
        try std.testing.expectError(error.BadPublicKey, prepare(a, path));
    }
    const original = try tmp.dir.readFileAlloc(io, "onyx-server-node.key", a, .limited(4096));
    defer a.free(original);
    try std.testing.expectEqualStrings(seed ++ "\n", original);
}

fn loadOwner(a: std.mem.Allocator, path: []const u8) !*service.PreparedBoot {
    return service.loadPreparedBoot(a, io, std.Io.Dir.cwd(), path, .{ .port = 6680 }, .{ .env = env, .file = file });
}
fn ownerAllocationCuts(path: []const u8) !void {
    var cut: usize = 0;
    while (cut < 8192) : (cut += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = cut });
        if (loadOwner(failing.allocator(), path)) |owner| {
            defer owner.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expect(cut != 0);
            try std.testing.expectEqualStrings("realm-original", owner.loaded.parsed.mesh.realm);
            return;
        } else |err| {
            if (!failing.has_induced_failure) return err;
        }
    }
    return error.AllocationSweepDidNotComplete;
}

test "service identity: retained boot snapshot survives config and key replacement" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    const first_config = "[node]\nid=1\n[mesh]\nrealm=\"realm-original\"\n[listen]\nirc=6680\ns2s=0\n";
    try write(tmp.dir, "onyx.toml", first_config);
    try write(tmp.dir, "onyx-server-node.key", seed ++ "\n");
    try ownerAllocationCuts(path);
    const owner = try loadOwner(a, path);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const node_id = owner.identity.?.node.node_id;
    const realm = owner.identity.?.node.realm;
    try std.testing.expectEqual(service.Source.existing_keyfile, owner.identity.?.source);
    try tmp.dir.deleteFile(io, "onyx.toml");
    try tmp.dir.deleteFile(io, "onyx-server-node.key");
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"bad\"\n[mesh]\nrealm=\"different\"\n[listen]\nirc=6680\ns2s=0\n");
    try write(tmp.dir, "onyx-server-node.key", "invalid\n");
    try std.testing.expectEqualStrings("realm-original", owner.loaded.parsed.mesh.realm);
    try std.testing.expectEqualStrings("realm-original", owner.loaded.config.mesh_realm);
    try std.testing.expectEqualSlices(u8, &node_id, &owner.identity.?.node.node_id);
    try std.testing.expectEqualSlices(u8, &realm, &owner.identity.?.node.realm);
    var taken = owner.takeIdentity() orelse return error.MissingPreparedIdentity;
    defer taken.deinit();
    try std.testing.expect(owner.takeIdentity() == null);
    owner.deinit();
    owner_alive = false;
    try std.testing.expectEqualSlices(u8, &node_id, &taken.node.node_id);
    try std.testing.expectEqualSlices(u8, &realm, &taken.node.realm);
}

test "service identity: retained inline owner wipes all released allocations" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"env:NODE_TEST_SECRET\"\n[mesh]\nrealm=\"realm-original\"\n[listen]\nirc=6680\ns2s=0\n");
    try ownerAllocationCuts(path);
    var probe = WipeProbe{ .parent = a };
    const owner = try loadOwner(probe.allocator(), path);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const node_id = owner.identity.?.node.node_id;
    try tmp.dir.deleteFile(io, "onyx.toml");
    try std.testing.expectEqualStrings(seed, owner.loaded.parsed.node.secret_key.?);
    try std.testing.expectEqualStrings("realm-original", owner.loaded.parsed.mesh.realm);
    try std.testing.expectEqualSlices(u8, &node_id, &owner.identity.?.node.node_id);
    owner.deinit();
    owner_alive = false;
    try std.testing.expect(probe.frees > 0);
    try std.testing.expect(probe.all_zero);
}

test "service identity: strict path grammar refuses missing and extra operands" {
    try std.testing.expectEqualStrings("/etc/onyx-server/onyx-server.toml", try service.strictPath("/etc/onyx-server/onyx-server.toml", null));
    try std.testing.expectError(error.InvalidServiceArguments, service.strictPath(null, null));
    try std.testing.expectError(error.InvalidServiceArguments, service.strictPath("", null));
    try std.testing.expectError(error.InvalidServiceArguments, service.strictPath("--supervisor", null));
    try std.testing.expectError(error.InvalidServiceArguments, service.strictPath("config.toml", "extra"));
    try std.testing.expectError(error.InvalidServiceArguments, service.supervisorPath("--strict-existing-identity", null, null));
    const ordinary = try service.supervisorPath("config.toml", null, null);
    try std.testing.expect(!ordinary.strict);
    try std.testing.expectEqualStrings("config.toml", ordinary.path.?);
    const successor = try service.supervisorPath("config.toml", "--strict-existing-identity", null);
    try std.testing.expect(successor.strict);
    try std.testing.expectEqualStrings("config.toml", successor.path.?);
    try std.testing.expectError(error.InvalidServiceArguments, service.supervisorPath(null, "--strict-existing-identity", null));
    try std.testing.expectError(error.InvalidServiceArguments, service.supervisorPath("config.toml", "--wrong", null));
    try std.testing.expectError(error.InvalidServiceArguments, service.supervisorPath("config.toml", "--strict-existing-identity", "extra"));
}

const CaptureResolver = struct {
    calls: usize = 0,
    change: bool = false,
    fn lookup(ctx: ?*anyopaque, a: std.mem.Allocator, name: []const u8) ![]const u8 {
        const self: *CaptureResolver = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        if (std.mem.eql(u8, name, "NODE_TEST_SECRET")) {
            if (self.change and self.calls > 1) return a.dupe(u8, "changed");
            return a.dupe(u8, seed);
        }
        if (std.mem.eql(u8, name, "NET_NAME")) return a.dupe(u8, "private-net");
        return error.EnvironmentVariableNotFound;
    }
};

test "service identity: one resolution pass retains exact unique environment values" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"env:NODE_TEST_SECRET\"\n[network]\nname=\"env:NET_NAME\"\n[admin]\nemail=\"env:NODE_TEST_SECRET\"\n[listen]\nirc=6680\ns2s=0\n");
    var resolver = CaptureResolver{};
    const owner = try service.loadPreparedBoot(a, io, std.Io.Dir.cwd(), path, .{ .port = 6680 }, .{ .ctx = &resolver, .env = CaptureResolver.lookup, .file = file });
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 3), resolver.calls);
    try std.testing.expectEqual(@as(usize, 2), owner.env_bindings.view().len);
    try std.testing.expectEqualStrings("NODE_TEST_SECRET", owner.env_bindings.view()[0].name);
    try std.testing.expectEqualStrings(seed, owner.env_bindings.view()[0].value);
    try std.testing.expectEqualStrings("NET_NAME", owner.env_bindings.view()[1].name);
    try std.testing.expectEqualStrings("private-net", owner.env_bindings.view()[1].value);
    try std.testing.expectEqualStrings("private-net", owner.loaded.parsed.network.name);
    try tmp.dir.deleteFile(io, "onyx.toml");
    try std.testing.expectEqualStrings(seed, owner.env_bindings.view()[0].value);
}

test "service identity: changed duplicate environment resolution fails closed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const path = try std.fs.path.join(a, &.{ root, "onyx.toml" });
    defer a.free(path);
    try write(tmp.dir, "onyx.toml", "[node]\nid=1\nsecret_key=\"env:NODE_TEST_SECRET\"\n[admin]\nemail=\"env:NODE_TEST_SECRET\"\n[listen]\nirc=6680\ns2s=0\n");
    var resolver = CaptureResolver{ .change = true };
    if (service.loadPreparedBoot(a, io, std.Io.Dir.cwd(), path, .{ .port = 6680 }, .{ .ctx = &resolver, .env = CaptureResolver.lookup, .file = file })) |owner| {
        owner.deinit();
        return error.ConflictingEnvironmentAccepted;
    } else |_| {}
    try std.testing.expectEqual(@as(usize, 2), resolver.calls);
}
