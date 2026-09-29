// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backup-set manifest and restore drill.
//! One OroStore snapshot contains every column family. Search, webhook TSVs,
//! the event-history file, and mail are deliberately absent. Mail is not
//! created here.

const std = @import("std");
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

/// Read `backup_dir/latest.json`, require the included and excluded family
/// lists, and reopen the account snapshot as `scratch_dir/restored.wal`.
pub fn restoreDrill(allocator: std.mem.Allocator, io: std.Io, backup_dir: []const u8, scratch_dir: []const u8) !void {
    if (backup_dir.len == 0 or scratch_dir.len == 0) return error.InvalidManifest;
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
    try tmp.dir.writeFile(io, .{ .sub_path = "backup/accounts-1.db.snap", .data = snap });

    var manifest_buf: [4096]u8 = undefined;
    const manifest = try writeManifest(&manifest_buf, 1, &.{
        .{ .kind = "accounts", .name = "accounts-1.db.snap", .source = "src.wal.snap" },
    }, false);
    for (included_families) |name| try std.testing.expect(std.mem.indexOf(u8, manifest, name) != null);
    for (excluded_families) |name| try std.testing.expect(std.mem.indexOf(u8, manifest, name) != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, chanstats_name) != null);
    try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = manifest });

    const backup_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/backup", .{tmp.sub_path});
    defer allocator.free(backup_rel);
    const scratch_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch", .{tmp.sub_path});
    defer allocator.free(scratch_rel);
    try restoreDrill(allocator, io, backup_rel, scratch_rel);

    const wal_path = try std.fmt.allocPrint(allocator, "{s}/restored.wal", .{scratch_rel});
    defer allocator.free(wal_path);
    var restored = try store_mod.OroStore.open(allocator, io, std.Io.Dir.cwd(), wal_path);
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
    try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = missing_history });
    const scratch_history = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch-history", .{tmp.sub_path});
    defer allocator.free(scratch_history);
    try std.testing.expectError(error.MissingFamily, restoreDrill(allocator, io, backup_rel, scratch_history));

    const missing_mail = try omitJsonString(allocator, manifest, "mail");
    defer allocator.free(missing_mail);
    try std.testing.expect(std.mem.indexOf(u8, missing_mail, "\"mail\"") == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "backup/latest.json", .data = missing_mail });
    const scratch_mail = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/scratch-mail", .{tmp.sub_path});
    defer allocator.free(scratch_mail);
    try std.testing.expectError(error.MissingFamily, restoreDrill(allocator, io, backup_rel, scratch_mail));
}
