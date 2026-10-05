// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persisted node identity seed: secured S2S on by default.
//!
//! When the operator configures no `[node] secret_key`, the daemon still turns
//! the PQ-secured Mooring mesh on: it loads the 32-byte Ed25519 seed from a
//! keyfile next to the config (`onyx-server-node.key`), generating a fresh random
//! seed and persisting it (owner-only) on first boot. An explicitly
//! configured `secret_key` always wins and never touches the keyfile.
//!
//! The keyfile body is the same format as the config value: 64 lowercase hex
//! chars (one line). A corrupt keyfile is an error, never silently replaced —
//! regenerating would change the node's mesh identity behind the operator's
//! back and orphan every TOFU pin peers hold for it.
const std = @import("std");
const builtin = @import("builtin");
const node_identity = @import("node_identity.zig");
const os_runtime = @import("os_runtime.zig");

pub const seed_len = 32;
pub const hex_len = seed_len * 2;

/// Keyfile basename, placed next to the config file (or in the CWD when the
/// daemon boots without a config path).
pub const default_basename = "onyx-server-node.key";

/// Largest keyfile we will read: the hex seed plus generous whitespace slack.
const max_keyfile_bytes = 4096;

/// Owner-only on platforms with POSIX modes. Windows uses a protected DACL.
const key_permissions: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

pub const ParseError = error{BadSeed};

pub const Source = enum { loaded, generated };

pub const LoadResult = struct {
    seed: [seed_len]u8,
    source: Source,
};

pub const IdentityValidationError = error{
    BadPublicKey,
    PublicKeyMismatch,
};

/// Derive the keyfile path: alongside the config file when one was used,
/// otherwise `onyx-server-node.key` relative to the CWD. Caller owns the slice.
pub fn derivePath(allocator: std.mem.Allocator, config_path: ?[]const u8) ![]u8 {
    if (config_path) |cp| {
        if (std.fs.path.dirname(cp)) |dir_name| {
            return std.fs.path.join(allocator, &.{ dir_name, default_basename });
        }
    }
    return allocator.dupe(u8, default_basename);
}

/// Parse a keyfile body: exactly 64 hex chars, surrounding whitespace tolerated.
pub fn parseSeedHex(text: []const u8) ParseError![seed_len]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len != hex_len) return error.BadSeed;
    var seed: [seed_len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&seed, trimmed) catch return error.BadSeed;
    if (decoded.len != seed_len) return error.BadSeed;
    return seed;
}

/// Load the seed from `path` under `dir`, or generate a fresh random seed and
/// persist it with owner-only access. A corrupt keyfile is an error so a node
/// never silently changes identity; the operator must remove or fix the file.
pub fn loadOrCreate(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
) !LoadResult {
    if (readSeed(allocator, io, dir, path, .remediate)) |seed| {
        return .{ .seed = seed, .source = .loaded };
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    var seed: [seed_len]u8 = undefined;
    io.random(&seed);
    writeSeed(io, dir, path, seed) catch |err| switch (err) {
        // Lost a create race against a concurrent boot: trust whoever won.
        error.PathAlreadyExists => return .{
            .seed = try readSeed(allocator, io, dir, path, .remediate),
            .source = .loaded,
        },
        else => return err,
    };
    return .{ .seed = seed, .source = .generated };
}

/// Read an already-provisioned keyfile without creating or mutating anything.
/// Deployment preflight uses this path so `--check-config` cannot report an
/// activation plan as safe when normal boot would load a different identity.
/// Windows preflight rejects a permissive ACL without changing it.
pub fn loadExisting(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
) ![seed_len]u8 {
    return readSeed(allocator, io, dir, path, .verify_only);
}

/// Prove that an explicit activation public key belongs to the persisted seed.
/// This is deliberately side-effect free: a missing key is an error rather than
/// an invitation to generate a new identity during config validation.
pub fn validateExistingPublicKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    realm: []const u8,
    configured_public_key: []const u8,
) !void {
    var seed = try loadExisting(allocator, io, dir, path);
    defer std.crypto.secureZero(u8, &seed);
    var identity = try node_identity.fromSeed(seed, realm);
    defer identity.deinit();

    var expected: [32]u8 = undefined;
    if (configured_public_key.len == expected.len * 2) {
        _ = std.fmt.hexToBytes(&expected, configured_public_key) catch
            return error.BadPublicKey;
    } else {
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(configured_public_key) catch
            return error.BadPublicKey;
        if (decoded_len != expected.len) return error.BadPublicKey;
        std.base64.standard.Decoder.decode(&expected, configured_public_key) catch
            return error.BadPublicKey;
    }
    if (!std.crypto.timing_safe.eql([32]u8, expected, identity.sign_kp.public_key))
        return error.PublicKeyMismatch;
}

const ReadPolicy = enum { verify_only, remediate };

fn readSeed(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, policy: ReadPolicy) ![seed_len]u8 {
    const text = if (comptime builtin.os.tag == .windows) blk: {
        var file = try openWindowsSeedForRead(dir, path, policy);
        defer file.close(io);
        var reader = file.reader(io, &.{});
        break :blk reader.interface.allocRemaining(allocator, .limited(max_keyfile_bytes)) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            error.OutOfMemory, error.StreamTooLong => |e| return e,
        };
    } else try dir.readFileAlloc(io, path, allocator, .limited(max_keyfile_bytes));
    defer {
        std.crypto.secureZero(u8, text);
        allocator.free(text);
    }
    return parseSeedHex(text);
}

fn openWindowsSeedForRead(dir: std.Io.Dir, path: []const u8, policy: ReadPolicy) !std.Io.File {
    if (policy == .verify_only) return os_runtime.openExistingPrivateWindows(dir, path, .verify_only);
    // A concurrent first boot may still hold its exclusive newly created
    // file while finishing the seed write. Wait briefly for that handoff;
    // persistent readers or writers still fail closed without any read.
    var busy_retries: u8 = 0;
    while (true) {
        return os_runtime.openExistingPrivateWindows(dir, path, .remediate) catch |err| {
            if (err != error.FileBusy or busy_retries == 20) return err;
            busy_retries += 1;
            os_runtime.sleepMillis(10);
            continue;
        };
    }
}

fn writeSeed(io: std.Io, dir: std.Io.Dir, path: []const u8, seed: [seed_len]u8) !void {
    var line: [hex_len + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &line);
    const charset = "0123456789abcdef";
    for (seed, 0..) |byte, i| {
        line[i * 2] = charset[byte >> 4];
        line[i * 2 + 1] = charset[byte & 0xf];
    }
    line[hex_len] = '\n';

    // The native Windows create attaches a protected DACL atomically. Both
    // paths create exclusively so a concurrent boot cannot clobber its seed.
    var file = if (comptime builtin.os.tag == .windows)
        try os_runtime.createPrivateExclusiveWindows(dir, path)
    else
        try dir.createFile(io, path, .{ .exclusive = true, .permissions = key_permissions });
    defer file.close(io);
    try file.writeStreamingAll(io, &line);
    try file.sync(io);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseSeedHex accepts a hex seed with surrounding whitespace" {
    const seed = try parseSeedHex(&repeatBytes("42", seed_len) ++ "\n");
    try testing.expectEqual(@as([seed_len]u8, @splat(0x42)), seed);

    const padded = try parseSeedHex("  \t" ++ &repeatBytes("ab", seed_len) ++ "\r\n");
    try testing.expectEqual(@as([seed_len]u8, @splat(0xab)), padded);
}

test "parseSeedHex rejects wrong lengths and non-hex input" {
    try testing.expectError(error.BadSeed, parseSeedHex(""));
    try testing.expectError(error.BadSeed, parseSeedHex("abcd")); // too short
    try testing.expectError(error.BadSeed, parseSeedHex(&repeatBytes("42", seed_len) ++ "ff")); // too long
    try testing.expectError(error.BadSeed, parseSeedHex(&repeatBytes("zz", seed_len))); // non-hex
}

test "derivePath places the keyfile next to the config, or in the CWD" {
    const beside = try derivePath(testing.allocator, "/etc/onyx/onyx-server.toml");
    defer testing.allocator.free(beside);
    try testing.expectEqualStrings("/etc/onyx", std.fs.path.dirname(beside).?);
    try testing.expectEqualStrings(default_basename, std.fs.path.basename(beside));

    const bare = try derivePath(testing.allocator, "onyx_server.toml"); // no dir component
    defer testing.allocator.free(bare);
    try testing.expectEqualStrings(default_basename, bare);

    const none = try derivePath(testing.allocator, null);
    defer testing.allocator.free(none);
    try testing.expectEqualStrings(default_basename, none);
}

test "loadOrCreate generates once, persists 0600, and reloads the same seed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const first = try loadOrCreate(testing.allocator, testing.io, tmp.dir, "onyx-server-node.key");
    try testing.expectEqual(Source.generated, first.source);

    // The persisted body is exactly the hex line and parses back to the seed.
    const text = try tmp.dir.readFileAlloc(testing.io, "onyx-server-node.key", testing.allocator, .limited(max_keyfile_bytes));
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(usize, hex_len + 1), text.len);
    try testing.expectEqual(first.seed, try parseSeedHex(text));

    // Owner-only: no group/other permission bits on POSIX targets.
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        var file = try tmp.dir.openFile(testing.io, "onyx-server-node.key", .{ .mode = .read_only, .allow_directory = false });
        defer file.close(testing.io);
        const stat = try file.stat(testing.io);
        try testing.expectEqual(@as(@TypeOf(stat.permissions.toMode()), 0), stat.permissions.toMode() & 0o077);
    }

    // Second boot loads the same identity instead of generating a new one.
    const second = try loadOrCreate(testing.allocator, testing.io, tmp.dir, "onyx-server-node.key");
    try testing.expectEqual(Source.loaded, second.source);
    try testing.expectEqual(first.seed, second.seed);
}

test "loadOrCreate refuses to clobber a corrupt keyfile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "onyx-server-node.key", .data = "not a seed\n" });
    try testing.expectError(error.BadSeed, loadOrCreate(testing.allocator, testing.io, tmp.dir, "onyx-server-node.key"));

    // The corrupt file is left untouched for the operator to inspect.
    const text = try tmp.dir.readFileAlloc(testing.io, "onyx-server-node.key", testing.allocator, .limited(max_keyfile_bytes));
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("not a seed\n", text);
}

test "Windows node keyfile create collision leaves the persisted identity untouched" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const winner: [seed_len]u8 = @splat(0x42);
    try writeSeed(testing.io, tmp.dir, default_basename, winner);
    try testing.expectError(error.PathAlreadyExists, writeSeed(testing.io, tmp.dir, default_basename, @splat(0xa5)));

    const loaded = try loadOrCreate(testing.allocator, testing.io, tmp.dir, default_basename);
    try testing.expectEqual(Source.loaded, loaded.source);
    try testing.expectEqual(winner, loaded.seed);
    const text = try tmp.dir.readFileAlloc(testing.io, default_basename, testing.allocator, .limited(max_keyfile_bytes));
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(usize, hex_len + 1), text.len);
    try testing.expectEqual(winner, try parseSeedHex(text));
}

test "activation preflight binds public key to an existing persisted seed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const seed = @as([seed_len]u8, @splat(0x42));
    var identity = try node_identity.fromSeed(seed, "activation-test");
    defer identity.deinit();
    const public_hex = std.fmt.bytesToHex(identity.sign_kp.public_key, .lower);

    try testing.expectError(
        error.FileNotFound,
        validateExistingPublicKey(
            testing.allocator,
            testing.io,
            tmp.dir,
            default_basename,
            "activation-test",
            &public_hex,
        ),
    );

    try writeSeed(testing.io, tmp.dir, default_basename, seed);

    try validateExistingPublicKey(
        testing.allocator,
        testing.io,
        tmp.dir,
        default_basename,
        "activation-test",
        &public_hex,
    );
    const wrong_public = std.fmt.bytesToHex(@as([32]u8, @splat(0xaa)), .lower);
    try testing.expectError(
        error.PublicKeyMismatch,
        validateExistingPublicKey(
            testing.allocator,
            testing.io,
            tmp.dir,
            default_basename,
            "activation-test",
            &wrong_public,
        ),
    );
}

fn repeatBytes(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var b: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(b[i * s.len ..][0..s.len], s);
    return b;
}
