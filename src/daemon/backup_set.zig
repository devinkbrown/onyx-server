// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backup-set manifest and restore drill.
//! One OroStore snapshot contains every column family. Search, webhook TSVs,
//! the event-history file, and mail are deliberately absent. Mail is not
//! created here.

const std = @import("std");
const builtin = @import("builtin");
const os_runtime = @import("os_runtime.zig");
const store_mod = @import("store.zig");

pub const max_backup_file_bytes: usize = 512 << 20;
pub const drill_usage = "onyx-server --restore-drill <backup-dir> --into <scratch-dir>";
pub const chanstats_name = "chanstats";

pub const included_families = [_][]const u8{
    "accounts",
    "nicks",
    "chanregs",
    "bans",
    "memos",
    "vhosts",
    "props",
    "history",
};

pub const excluded_families = [_][]const u8{
    "search",
    "webhooks",
    "event_history",
    "mail",
};

comptime {
    const tags = std.enums.values(store_mod.Family);
    if (tags.len != included_families.len) @compileError("OroStore.Family and the backup included list differ in length");
    for (tags, 0..) |family, index| {
        if (!std.mem.eql(u8, @tagName(family), included_families[index])) {
            @compileError("OroStore.Family tag drifted from the backup included list");
        }
    }
}

pub const Artifact = struct {
    kind: []const u8,
    name: []const u8,
    source: []const u8,
};

pub const Verified = struct {
    accounts_name: []u8,

    pub fn deinit(self: Verified, allocator: std.mem.Allocator) void {
        allocator.free(self.accounts_name);
    }
};

pub const DrillError = error{
    InvalidManifest,
    MissingFamily,
    MissingFile,
    EmptySnapshot,
    UnexpectedFamily,
    NoSpaceLeft,
};

pub fn writeManifest(buf: []u8, generated_unix: i64, files: []const Artifact, chanstats_included: bool) DrillError![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    writeAll(&w, "{\"generated_at\":") catch return error.NoSpaceLeft;
    w.print("{d}", .{generated_unix}) catch return error.NoSpaceLeft;
    writeAll(&w, ",\"files\":[") catch return error.NoSpaceLeft;
    for (files, 0..) |file, index| {
        if (index != 0) w.writeByte(',') catch return error.NoSpaceLeft;
        writeAll(&w, "{\"kind\":") catch return error.NoSpaceLeft;
        writeJsonString(&w, file.kind) catch return error.NoSpaceLeft;
        writeAll(&w, ",\"name\":") catch return error.NoSpaceLeft;
        writeJsonString(&w, file.name) catch return error.NoSpaceLeft;
        writeAll(&w, ",\"source\":") catch return error.NoSpaceLeft;
        writeJsonString(&w, file.source) catch return error.NoSpaceLeft;
        w.writeByte('}') catch return error.NoSpaceLeft;
    }
    writeAll(&w, "],\"included\":[") catch return error.NoSpaceLeft;
    for (included_families, 0..) |name, index| {
        if (index != 0) w.writeByte(',') catch return error.NoSpaceLeft;
        writeJsonString(&w, name) catch return error.NoSpaceLeft;
    }
    if (chanstats_included) {
        w.writeByte(',') catch return error.NoSpaceLeft;
        writeJsonString(&w, chanstats_name) catch return error.NoSpaceLeft;
    }
    writeAll(&w, "],\"excluded\":[") catch return error.NoSpaceLeft;
    for (excluded_families, 0..) |name, index| {
        if (index != 0) w.writeByte(',') catch return error.NoSpaceLeft;
        writeJsonString(&w, name) catch return error.NoSpaceLeft;
    }
    if (!chanstats_included) {
        w.writeByte(',') catch return error.NoSpaceLeft;
        writeJsonString(&w, chanstats_name) catch return error.NoSpaceLeft;
    }
    writeAll(&w, "]}") catch return error.NoSpaceLeft;
    return w.buffered();
}

pub fn verify(allocator: std.mem.Allocator, text: []const u8) !Verified {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return error.InvalidManifest;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidManifest;
    const root = parsed.value.object;
    const generated = root.get("generated_at") orelse return error.InvalidManifest;
    if (generated != .integer) return error.InvalidManifest;

    const included = root.get("included") orelse return error.MissingFamily;
    const excluded = root.get("excluded") orelse return error.MissingFamily;
    const chanstats_in = try consumeList(included, &included_families, chanstats_name);
    const chanstats_out = try consumeList(excluded, &excluded_families, chanstats_name);
    if (chanstats_in == chanstats_out) return error.MissingFamily;

    const files_value = root.get("files") orelse return error.MissingFile;
    if (files_value != .array) return error.InvalidManifest;
    var accounts_name: []const u8 = "";
    var accounts_seen = false;
    var chanstats_file = false;
    for (files_value.array.items) |item| {
        if (item != .object) return error.InvalidManifest;
        const kind = jsonString(item.object, "kind") orelse return error.InvalidManifest;
        const name = jsonString(item.object, "name") orelse return error.InvalidManifest;
        if (!singleSegment(name)) return error.InvalidManifest;
        if (std.mem.eql(u8, kind, "accounts")) {
            if (accounts_seen) return error.InvalidManifest;
            accounts_seen = true;
            accounts_name = name;
        } else if (std.mem.eql(u8, kind, chanstats_name)) {
            if (chanstats_file) return error.InvalidManifest;
            chanstats_file = true;
        } else return error.UnexpectedFamily;
    }
    if (!accounts_seen) return error.MissingFile;
    if (chanstats_file != chanstats_in) return error.MissingFile;
    return .{ .accounts_name = try allocator.dupe(u8, accounts_name) };
}

/// Keep one validated directory HANDLE for the whole backup set so every
/// snapshot and the final manifest go to the same directory object even if a
/// path is renamed while publication is in progress. The caller must create
/// the directory with its private ACL before any other handle can access it.
pub const PrivateWriterWindows = struct {
    io: std.Io,
    dir: std.Io.Dir,

    pub fn open(io: std.Io, dir_path: []const u8) !PrivateWriterWindows {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        return .{ .io = io, .dir = try os_runtime.openPrivateDirectoryWindows(io, std.Io.Dir.cwd(), dir_path) };
    }

    pub fn deinit(self: *PrivateWriterWindows) void {
        self.dir.close(self.io);
        self.* = undefined;
    }

    /// A new temp file is checked before bytes are written, reacquired
    /// exclusively, and assigned a protected DACL before sync and replace.
    pub fn writeFile(self: *PrivateWriterWindows, name: []const u8, data: []const u8) !void {
        try writePrivateFileAtomicInDirWindows(self.io, self.dir, name, data, true);
    }

    /// Snapshot names must never replace an older artifact that a published
    /// manifest may still reference. A collision fails this backup attempt.
    pub fn writeNewFile(self: *PrivateWriterWindows, name: []const u8, data: []const u8) !void {
        try writePrivateFileAtomicInDirWindows(self.io, self.dir, name, data, false);
    }
};

pub fn writePrivateFileAtomicWindows(io: std.Io, dir_path: []const u8, name: []const u8, data: []const u8) !void {
    var writer = try PrivateWriterWindows.open(io, dir_path);
    defer writer.deinit();
    try writer.writeFile(name, data);
}

fn writePrivateFileAtomicInDirWindows(io: std.Io, private_dir: std.Io.Dir, name: []const u8, data: []const u8, replace: bool) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (!singleSegment(name)) return error.InvalidPath;
    if (replace) {
        const existing: ?std.Io.File = os_runtime.openExistingPrivateWindows(private_dir, name, .verify_only) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |file| file.close(io);
    }
    var atomic = try private_dir.createFileAtomic(io, name, .{ .replace = replace });
    defer atomic.deinit(io);
    if (!atomic.file_exists or !atomic.file_open) return error.Unsupported;
    // A broad inherited DACL is rejected before secret bytes exist. Closing
    // and reacquiring the temporary file also rejects a retained reader.
    try os_runtime.requireInheritedPrivateFileWindows(atomic.file);
    atomic.file.close(io);
    atomic.file_open = false;
    const temp_name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file = try os_runtime.openExistingPrivateWindows(atomic.dir, &temp_name, .remediate_read_write);
    atomic.file_open = true;
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    if (replace) {
        try atomic.replace(io);
    } else try atomic.link(io);
}

fn readPrivateFileAllocWindows(allocator: std.mem.Allocator, io: std.Io, private_dir: std.Io.Dir, name: []const u8, limit: usize) ![]u8 {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (!singleSegment(name)) return error.InvalidPath;
    var file = try os_runtime.openExistingPrivateWindows(private_dir, name, .verify_only);
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.OutOfMemory, error.StreamTooLong => |e| return e,
    };
}

/// Read `backup_dir/latest.json`, require the included and excluded family
/// lists, and reopen the account snapshot as `scratch_dir/restored.wal`.
pub fn restoreDrill(allocator: std.mem.Allocator, io: std.Io, backup_dir: []const u8, scratch_dir: []const u8) !void {
    if (backup_dir.len == 0 or scratch_dir.len == 0) return error.InvalidManifest;
    if (comptime builtin.os.tag == .windows) {
        var private_backup_dir = try os_runtime.openPrivateDirectoryWindows(io, std.Io.Dir.cwd(), backup_dir);
        defer private_backup_dir.close(io);
        const text = try readPrivateFileAllocWindows(allocator, io, private_backup_dir, "latest.json", 1 << 20);
        defer allocator.free(text);
        const verified = try verify(allocator, text);
        defer verified.deinit(allocator);
        const snap = try readPrivateFileAllocWindows(allocator, io, private_backup_dir, verified.accounts_name, max_backup_file_bytes);
        defer {
            std.crypto.secureZero(u8, snap);
            allocator.free(snap);
        }
        if (snap.len == 0) return error.EmptySnapshot;

        var private_scratch_dir = try os_runtime.openPrivateDirectoryWindows(io, std.Io.Dir.cwd(), scratch_dir);
        defer private_scratch_dir.close(io);
        const old_wal: ?std.Io.File = os_runtime.openExistingPrivateWindows(private_scratch_dir, "restored.wal", .verify_only) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (old_wal) |file| file.close(io);
        private_scratch_dir.deleteFile(io, "restored.wal") catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try writePrivateFileAtomicInDirWindows(io, private_scratch_dir, "restored.wal.snap", snap, true);
        var restored = try store_mod.OroStore.openPrivateWindowsWithConfig(allocator, io, private_scratch_dir, "restored.wal", .{});
        restored.deinit();
        return;
    }
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/latest.json", .{backup_dir});
    defer allocator.free(manifest_path);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, manifest_path, allocator, .limited(1 << 20));
    defer allocator.free(text);
    const verified = try verify(allocator, text);
    defer verified.deinit(allocator);

    const snap_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ backup_dir, verified.accounts_name });
    defer allocator.free(snap_path);
    const snap = try std.Io.Dir.cwd().readFileAlloc(io, snap_path, allocator, .limited(max_backup_file_bytes));
    defer allocator.free(snap);
    if (snap.len == 0) return error.EmptySnapshot;

    std.Io.Dir.cwd().createDir(io, scratch_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const wal_path = try std.fmt.allocPrint(allocator, "{s}/restored.wal", .{scratch_dir});
    defer allocator.free(wal_path);
    std.Io.Dir.cwd().deleteFile(io, wal_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    const restored_snap = try std.fmt.allocPrint(allocator, "{s}/restored.wal.snap", .{scratch_dir});
    defer allocator.free(restored_snap);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = restored_snap, .data = snap });

    var restored = try store_mod.OroStore.open(allocator, io, std.Io.Dir.cwd(), wal_path);
    restored.deinit();
}

fn writeAll(w: *std.Io.Writer, text: []const u8) !void {
    try w.writeAll(text);
}

fn writeJsonString(w: *std.Io.Writer, text: []const u8) !void {
    try w.writeByte('"');
    for (text) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

fn jsonString(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn singleSegment(name: []const u8) bool {
    if (name.len == 0 or name.len > 200) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    if (comptime builtin.os.tag == .windows) {
        // Backup artifacts use generated ASCII names. Reject Windows alternate
        // streams, device syntax, and trailing-dot aliases in a manifest.
        if (name[0] == '.' or name[name.len - 1] == '.') return false;
        for (name) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return false;
        }
        const stem = name[0 .. std.mem.indexOfScalar(u8, name, '.') orelse name.len];
        for ([_][]const u8{ "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }) |device| {
            if (std.ascii.eqlIgnoreCase(stem, device)) return false;
        }
    }
    return true;
}

fn nameIndex(names: []const []const u8, name: []const u8) ?usize {
    for (names, 0..) |candidate, index| {
        if (std.mem.eql(u8, candidate, name)) return index;
    }
    return null;
}

fn consumeList(value: std.json.Value, base: []const []const u8, optional_name: []const u8) !bool {
    if (base.len > 8) return error.InvalidManifest;
    if (value != .array) return error.InvalidManifest;
    var seen: [8]bool = undefined;
    @memset(&seen, false);
    var optional_seen = false;
    for (value.array.items) |item| {
        if (item != .string) return error.InvalidManifest;
        const name = item.string;
        if (std.mem.eql(u8, name, optional_name)) {
            if (optional_seen) return error.InvalidManifest;
            optional_seen = true;
            continue;
        }
        const index = nameIndex(base, name) orelse return error.UnexpectedFamily;
        if (seen[index]) return error.InvalidManifest;
        seen[index] = true;
    }
    for (seen[0..base.len]) |present| {
        if (!present) return error.MissingFamily;
    }
    return optional_seen;
}

fn omitJsonString(allocator: std.mem.Allocator, manifest: []const u8, name: []const u8) ![]u8 {
    var needle_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, ",\"{s}\"", .{name}) catch return error.InvalidManifest;
    const at = std.mem.indexOf(u8, manifest, needle) orelse return error.InvalidManifest;
    const out = try allocator.alloc(u8, manifest.len - needle.len);
    @memcpy(out[0..at], manifest[0..at]);
    @memcpy(out[at..], manifest[at + needle.len ..]);
    return out;
}

fn expectFamily(restored: *store_mod.OroStore, family: store_mod.Family, key: []const u8, value: []const u8) !void {
    const got = restored.get(family, key) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(value, got);
}

test "DST GAP-D6 backup set lists families and restores into a scratch directory" {
    std.debug.print("GAP-D6 branch=backup set lists every orostore family and excludes search webhooks event_history and mail; chanstats is excluded when that snapshot is absent; restore drill reopens the snap in a scratch directory\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, drill_usage, "--restore-drill") != null);
    try std.testing.expect(std.mem.indexOf(u8, drill_usage, "--into") != null);

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "backup", .default_dir);
    if (comptime builtin.os.tag == .windows) {
        try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "backup");
        try tmp.dir.createDir(io, "scratch", .default_dir);
        try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "scratch");
    }

    var source = try store_mod.OroStore.open(allocator, io, tmp.dir, "src.wal");
    defer source.deinit();
    try source.put(.accounts, "d6acct", "plain-row");
    try source.put(.nicks, "d6nick", "nick-row");
    try source.put(.chanregs, "d6chan", "chan-row");
    try source.put(.bans, "shun:d6", "mute");
    try source.put(.memos, "d6memo", "memo-row");
    try source.put(.vhosts, "d6vh", "vhost-row");
    try source.put(.props, "d6prop", "prop-row");
    try source.put(.history, "d6hist", "history-row");
    try source.snapshotAndTruncate();

    const snap = try tmp.dir.readFileAlloc(io, "src.wal.snap", allocator, .limited(max_backup_file_bytes));
    defer allocator.free(snap);
    try std.testing.expect(snap.len != 0);
    const backup_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/backup", .{tmp.sub_path});
    defer allocator.free(backup_rel);
    if (comptime builtin.os.tag == .windows) {
        try writePrivateFileAtomicWindows(io, backup_rel, "accounts-1.db.snap", snap);
    } else try tmp.dir.writeFile(io, .{ .sub_path = "backup/accounts-1.db.snap", .data = snap });

    var manifest_buf: [4096]u8 = undefined;
    const manifest = try writeManifest(&manifest_buf, 1, &.{
        .{ .kind = "accounts", .name = "accounts-1.db.snap", .source = "src.wal.snap" },
    }, false);
    for (included_families) |name| try std.testing.expect(std.mem.indexOf(u8, manifest, name) != null);
    for (excluded_families) |name| try std.testing.expect(std.mem.indexOf(u8, manifest, name) != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, chanstats_name) != null);
    if (comptime builtin.os.tag == .windows) {
        try writePrivateFileAtomicWindows(io, backup_rel, "latest.json", manifest);
    } else try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = manifest });

    const scratch_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    defer allocator.free(scratch_rel);
    try restoreDrill(allocator, io, backup_rel, scratch_rel);

    const wal_path = try std.fmt.allocPrint(allocator, "{s}/restored.wal", .{scratch_rel});
    defer allocator.free(wal_path);
    var restored = if (comptime builtin.os.tag == .windows)
        try store_mod.OroStore.openPrivateWindowsWithConfig(allocator, io, std.Io.Dir.cwd(), wal_path, .{})
    else
        try store_mod.OroStore.open(allocator, io, std.Io.Dir.cwd(), wal_path);
    defer restored.deinit();
    try expectFamily(&restored, .accounts, "d6acct", "plain-row");
    try expectFamily(&restored, .nicks, "d6nick", "nick-row");
    try expectFamily(&restored, .chanregs, "d6chan", "chan-row");
    try expectFamily(&restored, .bans, "shun:d6", "mute");
    try expectFamily(&restored, .memos, "d6memo", "memo-row");
    try expectFamily(&restored, .vhosts, "d6vh", "vhost-row");
    try expectFamily(&restored, .props, "d6prop", "prop-row");
    try expectFamily(&restored, .history, "d6hist", "history-row");

    const missing_history = try omitJsonString(allocator, manifest, "history");
    defer allocator.free(missing_history);
    try std.testing.expect(std.mem.indexOf(u8, missing_history, "\"history\"") == null);
    if (comptime builtin.os.tag == .windows) {
        try writePrivateFileAtomicWindows(io, backup_rel, "latest.json", missing_history);
    } else try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = missing_history });
    const scratch_history = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch-history", .{tmp.sub_path});
    defer allocator.free(scratch_history);
    try std.testing.expectError(error.MissingFamily, restoreDrill(allocator, io, backup_rel, scratch_history));

    const missing_mail = try omitJsonString(allocator, manifest, "mail");
    defer allocator.free(missing_mail);
    try std.testing.expect(std.mem.indexOf(u8, missing_mail, "\"mail\"") == null);
    if (comptime builtin.os.tag == .windows) {
        try writePrivateFileAtomicWindows(io, backup_rel, "latest.json", missing_mail);
    } else try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = missing_mail });
    const scratch_mail = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch-mail", .{tmp.sub_path});
    defer allocator.free(scratch_mail);
    try std.testing.expectError(error.MissingFamily, restoreDrill(allocator, io, backup_rel, scratch_mail));
}

test "Windows backup set requires private directories and protects published and restored files" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "broad", .default_dir);
    try tmp.dir.createDir(io, "backup", .default_dir);
    try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "backup");
    try tmp.dir.createDir(io, "scratch", .default_dir);
    try os_runtime.protectEmptyDirectoryWindows(io, tmp.dir, "scratch");

    const broad_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/broad", .{tmp.sub_path});
    defer allocator.free(broad_rel);
    const backup_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/backup", .{tmp.sub_path});
    defer allocator.free(backup_rel);
    const scratch_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    defer allocator.free(scratch_rel);
    try std.testing.expectError(error.InsecurePermissions, writePrivateFileAtomicWindows(io, broad_rel, "accounts-1.db.snap", "secret"));
    try std.testing.expectError(error.InvalidPath, writePrivateFileAtomicWindows(io, backup_rel, "../outside", "secret"));
    try tmp.dir.writeFile(io, .{ .sub_path = "backup/stale.json", .data = "old" });
    try std.testing.expectError(error.InsecurePermissions, writePrivateFileAtomicWindows(io, backup_rel, "stale.json", "replacement must be refused"));
    var invalid_buf: [4096]u8 = undefined;
    for ([_][]const u8{ "accounts.db.snap:ads", "CON", "accounts.db.snap." }) |bad_name| {
        const invalid = try writeManifest(&invalid_buf, 1, &.{.{ .kind = "accounts", .name = bad_name, .source = "source.wal.snap" }}, false);
        try std.testing.expectError(error.InvalidManifest, verify(allocator, invalid));
    }

    var source = try store_mod.OroStore.open(allocator, io, tmp.dir, "source.wal");
    defer source.deinit();
    try source.put(.accounts, "private", "backup-secret");
    try source.snapshotAndTruncate();
    const snapshot = try tmp.dir.readFileAlloc(io, "source.wal.snap", allocator, .limited(max_backup_file_bytes));
    defer allocator.free(snapshot);
    try writePrivateFileAtomicWindows(io, backup_rel, "accounts-1.db.snap", snapshot);
    {
        var writer = try PrivateWriterWindows.open(io, backup_rel);
        defer writer.deinit();
        try writer.writeNewFile("accounts-2.db.snap", snapshot);
        try std.testing.expectError(error.PathAlreadyExists, writer.writeNewFile("accounts-1.db.snap", "replacement must be refused"));
    }
    var manifest_buf: [4096]u8 = undefined;
    const manifest = try writeManifest(&manifest_buf, 1, &.{.{ .kind = "accounts", .name = "accounts-1.db.snap", .source = "source.wal.snap" }}, false);
    try writePrivateFileAtomicWindows(io, backup_rel, "latest.json", manifest);
    {
        const backup_handle = try os_runtime.openPrivateDirectoryWindows(io, tmp.dir, "backup");
        defer backup_handle.close(io);
        const copied_snapshot = try os_runtime.openExistingPrivateWindows(backup_handle, "accounts-1.db.snap", .verify_only);
        copied_snapshot.close(io);
        const created_snapshot = try os_runtime.openExistingPrivateWindows(backup_handle, "accounts-2.db.snap", .verify_only);
        created_snapshot.close(io);
        const copied_manifest = try os_runtime.openExistingPrivateWindows(backup_handle, "latest.json", .verify_only);
        copied_manifest.close(io);
    }
    try std.testing.expectError(error.InsecurePermissions, restoreDrill(allocator, io, backup_rel, broad_rel));
    try restoreDrill(allocator, io, backup_rel, scratch_rel);
    {
        const scratch_handle = try os_runtime.openPrivateDirectoryWindows(io, tmp.dir, "scratch");
        defer scratch_handle.close(io);
        const recovered_snapshot = try os_runtime.openExistingPrivateWindows(scratch_handle, "restored.wal.snap", .verify_only);
        recovered_snapshot.close(io);
        const recovered_wal = try os_runtime.openExistingPrivateWindows(scratch_handle, "restored.wal", .verify_only);
        recovered_wal.close(io);
    }
    var restored = try store_mod.OroStore.openPrivateWindowsWithConfig(allocator, io, tmp.dir, "scratch/restored.wal", .{});
    defer restored.deinit();
    try std.testing.expectEqualStrings("backup-secret", restored.get(.accounts, "private") orelse return error.TestUnexpectedResult);
}
