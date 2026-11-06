// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Q07 configuration change preview. Compares parsed TOML documents and
//! classifies every changed field as `reloadable`, `restart_required`,
//! `startup_only`, or `unclassified`. Nothing is applied.
//!
//! The walk iterates table keys directly, so a key holding a literal `.` is
//! one segment and never aliases a proven dotted field. A proven field is
//! compared as a whole subtree; other tables are descended to the first node
//! that is not a table on both sides. Every changed node is counted; at most
//! `max_listed_changes` names are listed, sorted by rendered name.
//!
//! Values are never rendered. Rendered key names contain printable ASCII only.
//!
//! Base selection matches what the running process actually uses: a
//! `reloadable` field is compared with the last REHASH-applied document (or
//! the boot document when none), and every other class is compared with the
//! boot document, because REHASH never applies those changes.
const std = @import("std");
const config_format = @import("config_format.zig");
const toml = @import("../proto/toml.zig");

pub const Class = enum {
    reloadable,
    restart_required,
    startup_only,
    /// Outside the proven field lists. Treat as restart-required.
    unclassified,
};

/// Class plus the reason rendered with it.
pub const Kind = enum {
    reloadable,
    /// A `ListenerSet` member: `config_format.listenerChangeError`.
    listener,
    /// Node identity or mesh realm: REHASH refuses the whole reload.
    cold_maintenance,
    startup_only,
    unclassified,

    pub fn class(kind: Kind) Class {
        return switch (kind) {
            .reloadable => .reloadable,
            .listener, .cold_maintenance => .restart_required,
            .startup_only => .startup_only,
            .unclassified => .unclassified,
        };
    }

    pub fn reason(kind: Kind) []const u8 {
        return switch (kind) {
            .reloadable => "applied live by REHASH",
            .listener => config_format.cold_restart_required_reason,
            .cold_maintenance => "REHASH refuses node identity or realm changes; cold maintenance required",
            .startup_only => "read only at process start; REHASH keeps the running value until restart",
            .unclassified => "not proven reloadable; treat as restart_required",
        };
    }
};

pub const max_listed_changes: usize = 32;
pub const max_field_name_bytes: usize = 128;
/// Longest accepted caller prefix. Keeps every rendered line far below the
/// IRC NOTICE budget, which drops (not truncates) overlong lines.
pub const max_prefix_bytes: usize = 24;
/// Tables nested deeper than this are compared whole and reported once.
const max_walk_depth: usize = 32;
/// Equality deeper than this fails closed as changed.
const max_equal_depth: usize = 64;

pub const Change = struct {
    name_buf: [max_field_name_bytes]u8 = undefined,
    name_len: usize = 0,
    kind: Kind,

    pub fn name(self: *const Change) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    fn lessThan(a: *const Change, b: *const Change) bool {
        return switch (std.mem.order(u8, a.name(), b.name())) {
            .lt => true,
            .gt => false,
            .eq => @backingInt(a.kind) < @backingInt(b.kind),
        };
    }
};

pub const Preview = struct {
    counts: std.EnumArray(Class, usize) = .initFill(0),
    listed: [max_listed_changes]Change = undefined,
    listed_len: usize = 0,

    pub fn count(self: *const Preview, class: Class) usize {
        return self.counts.get(class);
    }

    pub fn total(self: *const Preview) usize {
        var sum: usize = 0;
        for (self.counts.values) |n| sum += n;
        return sum;
    }

    pub fn changes(self: *const Preview) []const Change {
        return self.listed[0..self.listed_len];
    }

    pub fn omitted(self: *const Preview) usize {
        return self.total() - self.listed_len;
    }

    fn record(self: *Preview, path: []const []const u8, kind: Kind) void {
        self.counts.getPtr(kind.class()).* += 1;
        var entry: Change = .{ .kind = kind };
        entry.name_len = renderName(&entry.name_buf, path);
        var pos = self.listed_len;
        while (pos > 0 and entry.lessThan(&self.listed[pos - 1])) pos -= 1;
        if (pos >= max_listed_changes) return;
        const new_len = @min(self.listed_len + 1, max_listed_changes);
        var i = new_len - 1;
        while (i > pos) : (i -= 1) self.listed[i] = self.listed[i - 1];
        self.listed[pos] = entry;
        self.listed_len = new_len;
    }
};

pub const Documents = struct {
    /// The document the running process loaded at startup.
    boot: *const toml.Document,
    /// The document last committed by REHASH; null when none since startup.
    applied: ?*const toml.Document = null,
    proposed: *const toml.Document,
};

/// Fills `out` with the classified difference. Performs no allocation.
pub fn diff(docs: Documents, out: *Preview) void {
    out.* = .{};
    if (docs.applied) |applied| {
        var fixed: Walker = .{ .out = out, .keep = .fixed };
        fixed.walk(0, &docs.boot.root, &docs.proposed.root);
        var live: Walker = .{ .out = out, .keep = .reloadable };
        live.walk(0, &applied.root, &docs.proposed.root);
    } else {
        var all: Walker = .{ .out = out, .keep = .all };
        all.walk(0, &docs.boot.root, &docs.proposed.root);
    }
}

pub fn freeLines(allocator: std.mem.Allocator, lines: [][]u8) void {
    for (lines) |line| allocator.free(line);
    allocator.free(lines);
}

/// Owned notice bodies: one `<prefix> field <name>: <class> (<reason>)` line
/// per listed change, an omission line when names were dropped, then exactly
/// one summary line (`<prefix> fields: unchanged` when nothing changed). No
/// line contains a control byte.
pub fn render(allocator: std.mem.Allocator, prefix: []const u8, preview: *const Preview) error{OutOfMemory}![][]u8 {
    checkPrefix(prefix);
    var lines: std.ArrayList([]u8) = .empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }
    for (preview.changes()) |*change| {
        try pushFmt(allocator, &lines, "{s} field {s}: {s} ({s})", .{
            prefix,
            change.name(),
            @tagName(change.kind.class()),
            change.kind.reason(),
        });
    }
    if (preview.omitted() != 0) {
        try pushFmt(allocator, &lines, "{s} fields: {d} more changed field(s) not listed", .{ prefix, preview.omitted() });
    }
    if (preview.total() == 0) {
        try pushFmt(allocator, &lines, "{s} fields: unchanged", .{prefix});
    } else {
        try pushFmt(allocator, &lines, "{s} fields: {d} reloadable, {d} restart_required, {d} startup_only, {d} unclassified", .{
            prefix,
            preview.count(.reloadable),
            preview.count(.restart_required),
            preview.count(.startup_only),
            preview.count(.unclassified),
        });
    }
    return try lines.toOwnedSlice(allocator);
}

pub const Texts = struct {
    /// Raw text the running process loaded at startup; null when unknown.
    boot: ?[]const u8,
    /// Raw text last committed by REHASH; null when none since startup.
    applied: ?[]const u8 = null,
    proposed: []const u8,
};

/// Parses each text and renders the preview. A missing or unparsable input
/// yields exactly one `fields: unavailable` line; only allocation failure is
/// returned as an error. Parsed string bytes are wiped before release.
pub fn renderTexts(allocator: std.mem.Allocator, prefix: []const u8, texts: Texts) error{OutOfMemory}![][]u8 {
    checkPrefix(prefix);
    const boot_text = texts.boot orelse return unavailable(allocator, prefix, "no boot configuration snapshot");
    var boot = try parseOrNull(allocator, boot_text);
    defer if (boot) |*doc| wipeDeinit(allocator, doc);
    if (boot == null) return unavailable(allocator, prefix, "boot configuration does not parse");
    var applied: ?toml.Document = null;
    defer if (applied) |*doc| wipeDeinit(allocator, doc);
    if (texts.applied) |text| {
        applied = try parseOrNull(allocator, text);
        if (applied == null) return unavailable(allocator, prefix, "applied configuration does not parse");
    }
    var proposed = try parseOrNull(allocator, texts.proposed);
    defer if (proposed) |*doc| wipeDeinit(allocator, doc);
    if (proposed == null) return unavailable(allocator, prefix, "proposed configuration does not parse");

    const preview = try allocator.create(Preview);
    defer allocator.destroy(preview);
    diff(.{
        .boot = &boot.?,
        .applied = if (applied) |*doc| doc else null,
        .proposed = &proposed.?,
    }, preview);
    return render(allocator, prefix, preview);
}

fn checkPrefix(prefix: []const u8) void {
    std.debug.assert(prefix.len != 0 and prefix.len <= max_prefix_bytes);
    for (prefix) |c| std.debug.assert(c >= 0x20 and c < 0x7f);
}

fn unavailable(allocator: std.mem.Allocator, prefix: []const u8, why: []const u8) error{OutOfMemory}![][]u8 {
    const lines = try allocator.alloc([]u8, 1);
    errdefer allocator.free(lines);
    lines[0] = try std.fmt.allocPrint(allocator, "{s} fields: unavailable ({s}); treat every change as restart_required", .{ prefix, why });
    return lines;
}

fn parseOrNull(allocator: std.mem.Allocator, text: []const u8) error{OutOfMemory}!?toml.Document {
    return toml.parse(allocator, text) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

fn wipeDeinit(allocator: std.mem.Allocator, doc: *toml.Document) void {
    wipeValue(&doc.root);
    doc.deinit(allocator);
}

/// Zeroes string payloads (secrets may be inline). Recursion matches
/// `toml.Value.deinit`, which already walks the same tree.
fn wipeValue(value: *toml.Value) void {
    switch (value.*) {
        .string => |bytes| std.crypto.secureZero(u8, @constCast(bytes)),
        .array => |items| for (items) |*item| wipeValue(item),
        .table => |*map| {
            var it = map.valueIterator();
            while (it.next()) |child| wipeValue(child);
        },
        .integer, .float, .boolean => {},
    }
}

fn pushFmt(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8), comptime fmt: []const u8, args: anytype) error{OutOfMemory}!void {
    const line = try std.fmt.allocPrint(allocator, fmt, args);
    lines.append(allocator, line) catch |err| {
        allocator.free(line);
        return err;
    };
}

const Keep = enum { all, fixed, reloadable };

const Walker = struct {
    out: *Preview,
    keep: Keep,
    segments: [max_walk_depth][]const u8 = undefined,

    fn wants(self: *const Walker, kind: Kind) bool {
        return switch (self.keep) {
            .all => true,
            .reloadable => kind == .reloadable,
            .fixed => kind != .reloadable,
        };
    }

    fn walk(self: *Walker, depth: usize, a: ?*const toml.Value, b: ?*const toml.Value) void {
        const path = self.segments[0..depth];
        if (depth != 0) {
            if (provenKind(path)) |kind| {
                if (self.wants(kind) and !optionalEqual(a, b)) self.out.record(path, kind);
                return;
            }
        }
        const a_table = a == null or a.?.* == .table;
        const b_table = b == null or b.?.* == .table;
        // Reloadable walker only: a non-proven ancestor that is a table on one
        // side and a scalar on the other hides every proven leaf beneath it
        // (the parser treats `limits = 5` as "every limits.* field default").
        // Walk the table side against an absent counterpart so each proven
        // reloadable leaf it carries is still counted. The fixed walker keeps
        // reporting the node itself once as unclassified.
        if (self.keep == .reloadable and depth < max_walk_depth) {
            const a_is_table = a != null and a.?.* == .table;
            const b_is_table = b != null and b.?.* == .table;
            if (a_is_table and !b_table) return self.walk(depth, a, null);
            if (b_is_table and !a_table) return self.walk(depth, null, b);
        }
        if (a_table and b_table and depth < max_walk_depth) {
            if (a) |av| {
                var it = av.table.iterator();
                while (it.next()) |entry| {
                    self.segments[depth] = entry.key_ptr.*;
                    const other = if (b) |bv| bv.table.getPtr(entry.key_ptr.*) else null;
                    self.walk(depth + 1, entry.value_ptr, other);
                }
            }
            if (b) |bv| {
                var it = bv.table.iterator();
                while (it.next()) |entry| {
                    if (a) |av| if (av.table.contains(entry.key_ptr.*)) continue;
                    self.segments[depth] = entry.key_ptr.*;
                    self.walk(depth + 1, null, entry.value_ptr);
                }
            }
            return;
        }
        if (self.wants(.unclassified) and !optionalEqual(a, b)) self.out.record(path, .unclassified);
    }
};

fn provenKind(path: []const []const u8) ?Kind {
    for (config_format.classified_config_fields) |field| {
        if (!fieldMatches(path, field)) continue;
        return switch (config_format.configFieldClass(field)) {
            .reloadable => .reloadable,
            .startup_only => .startup_only,
            .restart_required => if (std.mem.startsWith(u8, field, "listen.") or std.mem.startsWith(u8, field, "tls."))
                .listener
            else
                .cold_maintenance,
        };
    }
    return null;
}

/// `config_format` names the OCG2 fields after the `Config.oper_ocg2` member;
/// the TOML document carries them under `[oper.ocg2]`.
const ocg2_field_prefix = "oper_ocg2.";

fn fieldMatches(path: []const []const u8, field: []const u8) bool {
    if (std.mem.startsWith(u8, field, ocg2_field_prefix)) {
        if (path.len < 2 or !std.mem.eql(u8, path[0], "oper") or !std.mem.eql(u8, path[1], "ocg2")) return false;
        return dottedEql(path[2..], field[ocg2_field_prefix.len..]);
    }
    return dottedEql(path, field);
}

fn dottedEql(path: []const []const u8, dotted: []const u8) bool {
    var it = std.mem.splitScalar(u8, dotted, '.');
    var i: usize = 0;
    while (it.next()) |segment| : (i += 1) {
        if (i >= path.len or !std.mem.eql(u8, path[i], segment)) return false;
    }
    return i == path.len;
}

fn optionalEqual(a: ?*const toml.Value, b: ?*const toml.Value) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return valuesEqual(a.?, b.?, 0);
}

fn valuesEqual(a: *const toml.Value, b: *const toml.Value, depth: usize) bool {
    if (depth >= max_equal_depth) return false;
    if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
    return switch (a.*) {
        .string => |s| std.mem.eql(u8, s, b.string),
        .integer => |n| n == b.integer,
        .float => |f| f == b.float or (std.math.isNan(f) and std.math.isNan(b.float)),
        .boolean => |v| v == b.boolean,
        .array => |items| blk: {
            if (items.len != b.array.len) break :blk false;
            for (items, b.array) |*x, *y| {
                if (!valuesEqual(x, y, depth + 1)) break :blk false;
            }
            break :blk true;
        },
        .table => |*map| blk: {
            if (map.count() != b.table.count()) break :blk false;
            var it = map.iterator();
            while (it.next()) |entry| {
                const other = b.table.getPtr(entry.key_ptr.*) orelse break :blk false;
                if (!valuesEqual(entry.value_ptr, other, depth + 1)) break :blk false;
            }
            break :blk true;
        },
    };
}

/// Dotted name with TOML-style quoting for non-bare segments. Bytes outside
/// printable ASCII render as `\xHH`. Overlong names end in `...`.
fn renderName(buf: *[max_field_name_bytes]u8, path: []const []const u8) usize {
    var w: NameWriter = .{ .buf = buf };
    for (path, 0..) |segment, i| {
        if (i != 0) w.put('.');
        if (isBare(segment)) {
            for (segment) |c| w.put(c);
            continue;
        }
        w.put('"');
        for (segment) |c| switch (c) {
            '"', '\\' => {
                w.put('\\');
                w.put(c);
            },
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => w.put(c),
            else => {
                const hex = "0123456789abcdef";
                w.put('\\');
                w.put('x');
                w.put(hex[c >> 4]);
                w.put(hex[c & 0xf]);
            },
        };
        w.put('"');
    }
    if (w.truncated) {
        @memcpy(buf[max_field_name_bytes - 3 ..], "...");
        return max_field_name_bytes;
    }
    return w.len;
}

const NameWriter = struct {
    buf: *[max_field_name_bytes]u8,
    len: usize = 0,
    truncated: bool = false,

    fn put(self: *NameWriter, c: u8) void {
        if (self.len == self.buf.len) {
            self.truncated = true;
            return;
        }
        self.buf[self.len] = c;
        self.len += 1;
    }
};

fn isBare(segment: []const u8) bool {
    if (segment.len == 0) return false;
    for (segment) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => {},
        else => return false,
    };
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const Fixture = struct {
    boot: toml.Document,
    applied: ?toml.Document,
    proposed: toml.Document,
    preview: Preview = .{},

    fn init(boot_text: []const u8, applied_text: ?[]const u8, proposed_text: []const u8) !*Fixture {
        const self = try testing.allocator.create(Fixture);
        errdefer testing.allocator.destroy(self);
        self.boot = try toml.parse(testing.allocator, boot_text);
        errdefer self.boot.deinit(testing.allocator);
        self.applied = if (applied_text) |t| try toml.parse(testing.allocator, t) else null;
        errdefer if (self.applied) |*d| d.deinit(testing.allocator);
        self.proposed = try toml.parse(testing.allocator, proposed_text);
        diff(.{
            .boot = &self.boot,
            .applied = if (self.applied) |*d| d else null,
            .proposed = &self.proposed,
        }, &self.preview);
        return self;
    }

    fn deinit(self: *Fixture) void {
        self.boot.deinit(testing.allocator);
        if (self.applied) |*d| d.deinit(testing.allocator);
        self.proposed.deinit(testing.allocator);
        testing.allocator.destroy(self);
    }

    fn only(self: *const Fixture) Change {
        std.debug.assert(self.preview.listed_len == 1);
        return self.preview.listed[0];
    }

    fn find(self: *const Fixture, name: []const u8) ?Change {
        for (self.preview.changes()) |c| if (std.mem.eql(u8, c.name(), name)) return c;
        return null;
    }
};

fn expectNoControlBytes(lines: []const []const u8) !void {
    for (lines) |line| {
        for (line) |c| try testing.expect(c >= 0x20 and c < 0x7f);
    }
}

test "config_change_preview: identical documents yield fields: unchanged and zero counts" {
    const text = "[limits]\nnick_delay = \"5s\"\n[listen]\nirc = 6667\n[network]\nname = \"Onyx\"\n";
    const fx = try Fixture.init(text, null, text);
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 0), fx.preview.total());
    for (std.enums.values(Class)) |class| try testing.expectEqual(@as(usize, 0), fx.preview.count(class));
    const lines = try render(testing.allocator, "config preview", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("config preview fields: unchanged", lines[0]);
}

test "config_change_preview: limits.nick_delay change classifies reloadable" {
    const fx = try Fixture.init("[limits]\nnick_delay = \"5s\"\n", null, "[limits]\nnick_delay = \"9s\"\n");
    defer fx.deinit();
    const change = fx.only();
    try testing.expectEqualStrings("limits.nick_delay", change.name());
    try testing.expectEqual(Class.reloadable, change.kind.class());
    try testing.expectEqual(@as(usize, 1), fx.preview.count(.reloadable));
    const lines = try render(testing.allocator, "REHASH DRY", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try testing.expectEqualStrings("REHASH DRY field limits.nick_delay: reloadable (applied live by REHASH)", lines[0]);
    try testing.expectEqualStrings("REHASH DRY fields: 1 reloadable, 0 restart_required, 0 startup_only, 0 unclassified", lines[1]);
}

test "config_change_preview: listen.irc / tls.port change classifies restart_required with cold_restart_required_reason" {
    const fx = try Fixture.init(
        "[listen]\nirc = 6667\n[tls]\nport = 6697\n",
        null,
        "[listen]\nirc = 6668\n[tls]\nport = 6698\n",
    );
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 2), fx.preview.count(.restart_required));
    try testing.expectEqual(@as(usize, 2), fx.preview.total());
    try testing.expectEqual(Kind.listener, fx.find("listen.irc").?.kind);
    try testing.expectEqual(Kind.listener, fx.find("tls.port").?.kind);
    const lines = try render(testing.allocator, "config preview", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try testing.expectEqual(@as(usize, 3), lines.len);
    for (lines[0..2]) |line| {
        try testing.expect(std.mem.indexOf(u8, line, ": restart_required (") != null);
        try testing.expect(std.mem.indexOf(u8, line, config_format.cold_restart_required_reason) != null);
    }
}

test "config_change_preview: node.id / mesh.realm change classifies restart_required cold maintenance" {
    const fx = try Fixture.init(
        "[node]\nid = 1\n[mesh]\nrealm = \"a\"\n",
        null,
        "[node]\nid = 2\n[mesh]\nrealm = \"b\"\n",
    );
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 2), fx.preview.count(.restart_required));
    try testing.expectEqual(Kind.cold_maintenance, fx.find("node.id").?.kind);
    try testing.expectEqual(Kind.cold_maintenance, fx.find("mesh.realm").?.kind);
    const lines = try render(testing.allocator, "config preview", &fx.preview);
    defer freeLines(testing.allocator, lines);
    for (lines[0..2]) |line| {
        try testing.expect(std.mem.indexOf(u8, line, "cold maintenance required") != null);
        try testing.expect(std.mem.indexOf(u8, line, config_format.cold_restart_required_reason) == null);
    }
}

test "config_change_preview: cloak.secret change classifies startup_only and never renders the secret" {
    const old_secret = "c4n4ry-old-cloak-secret-0123456789";
    const new_secret = "c4n4ry-new-cloak-secret-9876543210";
    const lines = try renderTexts(testing.allocator, "config preview", .{
        .boot = "[cloak]\nsecret = \"" ++ old_secret ++ "\"\n",
        .proposed = "[cloak]\nsecret = \"" ++ new_secret ++ "\"\n",
    });
    defer freeLines(testing.allocator, lines);
    try testing.expectEqual(@as(usize, 2), lines.len);
    try testing.expect(std.mem.startsWith(u8, lines[0], "config preview field cloak.secret: startup_only ("));
    try testing.expectEqualStrings("config preview fields: 0 reloadable, 0 restart_required, 1 startup_only, 0 unclassified", lines[1]);
    for (lines) |line| {
        try testing.expect(std.mem.indexOf(u8, line, old_secret) == null);
        try testing.expect(std.mem.indexOf(u8, line, new_secret) == null);
        try testing.expect(std.mem.indexOf(u8, line, "c4n4ry") == null);
    }
}

test "config_change_preview: unknown changed fields are reported as unclassified and counted, not dropped" {
    const fx = try Fixture.init(
        "[network]\nname = \"Old\"\n[tls]\nenable_resumption = false\n",
        null,
        "[network]\nname = \"New\"\n[tls]\nenable_resumption = true\n",
    );
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 2), fx.preview.count(.unclassified));
    try testing.expectEqual(@as(usize, 2), fx.preview.total());
    try testing.expectEqual(Kind.unclassified, fx.find("network.name").?.kind);
    try testing.expectEqual(Kind.unclassified, fx.find("tls.enable_resumption").?.kind);
    const lines = try render(testing.allocator, "config preview", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try testing.expectEqualStrings("config preview field network.name: unclassified (not proven reloadable; treat as restart_required)", lines[0]);
    try testing.expectEqualStrings("config preview fields: 0 reloadable, 0 restart_required, 0 startup_only, 2 unclassified", lines[2]);
}

test "config_change_preview: nested change under [class.default] is reported once as class reloadable" {
    const fx = try Fixture.init(
        "[class.default]\nsendq = 1000\nrecvq = 10\n[class.opers]\nsendq = 9\n",
        null,
        "[class.default]\nsendq = 2000\nrecvq = 20\n[class.opers]\nsendq = 9\n[class.extra]\nsendq = 1\n",
    );
    defer fx.deinit();
    const change = fx.only();
    try testing.expectEqualStrings("class", change.name());
    try testing.expectEqual(Kind.reloadable, change.kind);
    try testing.expectEqual(@as(usize, 1), fx.preview.total());
}

test "config_change_preview: field present in only one document counts as changed; absent in both does not" {
    {
        const fx = try Fixture.init("[limits]\nnick_delay = \"5s\"\n", null, "");
        defer fx.deinit();
        try testing.expectEqualStrings("limits.nick_delay", fx.only().name());
    }
    {
        const fx = try Fixture.init("", null, "[wasm]\nplugin_dir = \"/p\"\n[network]\nname = \"N\"\n");
        defer fx.deinit();
        try testing.expectEqual(@as(usize, 2), fx.preview.total());
        try testing.expectEqual(Kind.reloadable, fx.find("wasm.plugin_dir").?.kind);
        try testing.expectEqual(Kind.unclassified, fx.find("network.name").?.kind);
    }
    {
        // Absent in both, and an added empty table, are not changes.
        const fx = try Fixture.init("[limits]\n", null, "[limits]\n[wasm]\n");
        defer fx.deinit();
        try testing.expectEqual(@as(usize, 0), fx.preview.total());
    }
}

test "config_change_preview: literal-dot and hostile keys never alias proven fields and render escaped" {
    const fx = try Fixture.init(
        "",
        null,
        "\"limits.nick_delay\" = 1\n[limits]\n\"nick_delay.x\" = 2\n[\"listen\"]\n\"a\\r\\nPRIVMSG #x :hi\" = 3\n",
    );
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 3), fx.preview.count(.unclassified));
    try testing.expectEqual(@as(usize, 0), fx.preview.count(.reloadable));
    try testing.expectEqual(@as(usize, 0), fx.preview.count(.restart_required));
    try testing.expect(fx.find("\"limits.nick_delay\"") != null);
    try testing.expect(fx.find("limits.\"nick_delay.x\"") != null);
    try testing.expect(fx.find("listen.\"a\\x0d\\x0aPRIVMSG #x :hi\"") != null);
    const lines = try render(testing.allocator, "REHASH DRY", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try expectNoControlBytes(lines);
}

test "config_change_preview: OCG2 TOML fields under [oper.ocg2] classify startup_only" {
    const fx = try Fixture.init("[oper.ocg2]\nenabled = false\n", null, "[oper.ocg2]\nenabled = true\n");
    defer fx.deinit();
    const change = fx.only();
    try testing.expectEqualStrings("oper.ocg2.enabled", change.name());
    try testing.expectEqual(Kind.startup_only, change.kind);
}

test "config_change_preview: reloadable fields compare with applied, all others with boot" {
    // REHASH already applied nick_delay = 9s and accepted (but did not apply)
    // the cloak and network edits. Re-proposing the same file must report
    // no reloadable change yet still report the never-applied fields.
    const boot = "[limits]\nnick_delay = \"5s\"\n[cloak]\nsecret = \"a\"\n[network]\nname = \"Old\"\n";
    const applied = "[limits]\nnick_delay = \"9s\"\n[cloak]\nsecret = \"b\"\n[network]\nname = \"New\"\n";
    const fx = try Fixture.init(boot, applied, applied);
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 0), fx.preview.count(.reloadable));
    try testing.expectEqual(Kind.startup_only, fx.find("cloak.secret").?.kind);
    try testing.expectEqual(Kind.unclassified, fx.find("network.name").?.kind);
    try testing.expectEqual(@as(usize, 2), fx.preview.total());

    // A reloadable value moved back to the boot value is still a change
    // against the running (applied) value.
    const back = try Fixture.init(boot, applied, boot);
    defer back.deinit();
    try testing.expectEqualStrings("limits.nick_delay", back.only().name());
    try testing.expectEqual(Kind.reloadable, back.only().kind);
}

test "config_change_preview: type change at a non-proven ancestor reports one unclassified node" {
    const fx = try Fixture.init("[limits]\nnick_delay = \"5s\"\n", null, "limits = 5\n");
    defer fx.deinit();
    const change = fx.only();
    try testing.expectEqualStrings("limits", change.name());
    try testing.expectEqual(Kind.unclassified, change.kind);
}

test "config_change_preview: table-versus-scalar ancestor in the applied text still counts reloadable leaves" {
    // REHASH applied `limits = 5` (every limits.* field back to default);
    // re-proposing the boot text moves nick_delay from the default to 9s.
    const boot = "[limits]\nnick_delay = \"9s\"\n";
    const fx = try Fixture.init(boot, "limits = 5\n", boot);
    defer fx.deinit();
    try testing.expect(fx.preview.total() >= 1);
    try testing.expectEqual(Kind.reloadable, fx.find("limits.nick_delay").?.kind);
    try testing.expectEqual(@as(usize, 1), fx.preview.total());

    // Mirror image: applied table, proposed scalar. The live walker counts
    // the leaf that reverts; the fixed walker reports the node once.
    const flip = try Fixture.init(boot, boot, "limits = 5\n");
    defer flip.deinit();
    try testing.expectEqual(Kind.reloadable, flip.find("limits.nick_delay").?.kind);
    try testing.expectEqual(Kind.unclassified, flip.find("limits").?.kind);
    try testing.expectEqual(@as(usize, 2), flip.preview.total());

    // Without an applied text the single-walker contract is unchanged.
    const plain = try Fixture.init(boot, null, "limits = 5\n");
    defer plain.deinit();
    try testing.expectEqualStrings("limits", plain.only().name());
}

test "config_change_preview: arrays of tables compare whole" {
    const fx = try Fixture.init(
        "[[mesh.connect]]\nhost = \"a\"\n[[opers]]\naccount = \"x\"\n",
        null,
        "[[mesh.connect]]\nhost = \"b\"\n[[opers]]\naccount = \"y\"\n",
    );
    defer fx.deinit();
    try testing.expectEqual(Kind.unclassified, fx.find("mesh.connect").?.kind);
    try testing.expectEqual(Kind.reloadable, fx.find("opers").?.kind);
    try testing.expectEqual(@as(usize, 2), fx.preview.total());
}

test "config_change_preview: listing is bounded and sorted while every change is counted" {
    var proposed: std.ArrayList(u8) = .empty;
    defer proposed.deinit(testing.allocator);
    try proposed.appendSlice(testing.allocator, "[network]\n");
    var i: usize = 100;
    while (i > 0) {
        i -= 1;
        try proposed.print(testing.allocator, "k{d:0>3} = 1\n", .{i});
    }
    const fx = try Fixture.init("", null, proposed.items);
    defer fx.deinit();
    try testing.expectEqual(@as(usize, 100), fx.preview.count(.unclassified));
    try testing.expectEqual(max_listed_changes, fx.preview.listed_len);
    try testing.expectEqual(@as(usize, 100 - max_listed_changes), fx.preview.omitted());
    for (fx.preview.changes(), 0..) |c, n| {
        var want: [16]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "network.k{d:0>3}", .{n}), c.name());
    }
    const lines = try render(testing.allocator, "REHASH DRY", &fx.preview);
    defer freeLines(testing.allocator, lines);
    try testing.expectEqual(max_listed_changes + 2, lines.len);
    try testing.expectEqualStrings("REHASH DRY fields: 68 more changed field(s) not listed", lines[max_listed_changes]);
    try testing.expectEqualStrings("REHASH DRY fields: 0 reloadable, 0 restart_required, 0 startup_only, 100 unclassified", lines[max_listed_changes + 1]);
}

test "config_change_preview: overlong names truncate and deep tables stop at the walk bound" {
    const long_key: [300]u8 = @splat('x');
    {
        const fx = try Fixture.init("", null, "[network]\n" ++ &long_key ++ " = 1\n");
        defer fx.deinit();
        const name = fx.only().name();
        try testing.expectEqual(max_field_name_bytes, name.len);
        try testing.expect(std.mem.endsWith(u8, name, "..."));
        try testing.expect(std.mem.startsWith(u8, name, "network.xxx"));
    }
    {
        var header: std.ArrayList(u8) = .empty;
        defer header.deinit(testing.allocator);
        try header.append(testing.allocator, '[');
        for (0..40) |_| try header.appendSlice(testing.allocator, "d.");
        try header.appendSlice(testing.allocator, "leaf]\nv = ");
        const prefix_len = header.items.len;
        try header.appendSlice(testing.allocator, "1\n");
        const base_text = try testing.allocator.dupe(u8, header.items);
        defer testing.allocator.free(base_text);
        header.shrinkRetainingCapacity(prefix_len);
        try header.appendSlice(testing.allocator, "2\n");
        const fx = try Fixture.init(base_text, null, header.items);
        defer fx.deinit();
        const change = fx.only();
        try testing.expectEqual(Kind.unclassified, change.kind);
        // Reported at the walk bound: exactly max_walk_depth `d` segments.
        try testing.expectEqual(max_walk_depth * 2 - 1, change.name().len);
        const same = try Fixture.init(base_text, null, base_text);
        defer same.deinit();
        try testing.expectEqual(@as(usize, 0), same.preview.total());
    }
}

test "config_change_preview: missing or malformed inputs yield one unavailable line" {
    const cases = [_]struct { Texts, []const u8 }{
        .{ .{ .boot = null, .proposed = "" }, "no boot configuration snapshot" },
        .{ .{ .boot = "[[[", .proposed = "" }, "boot configuration does not parse" },
        .{ .{ .boot = "", .applied = "a = ", .proposed = "" }, "applied configuration does not parse" },
        .{ .{ .boot = "", .proposed = "a = 1\na = 2\n" }, "proposed configuration does not parse" },
    };
    for (cases) |case| {
        const lines = try renderTexts(testing.allocator, "REHASH DRY", case[0]);
        defer freeLines(testing.allocator, lines);
        try testing.expectEqual(@as(usize, 1), lines.len);
        try testing.expect(std.mem.startsWith(u8, lines[0], "REHASH DRY fields: unavailable ("));
        try testing.expect(std.mem.indexOf(u8, lines[0], case[1]) != null);
        try testing.expect(std.mem.endsWith(u8, lines[0], "treat every change as restart_required"));
    }
}

fn renderTextsProbe(allocator: std.mem.Allocator) !void {
    const lines = try renderTexts(allocator, "REHASH DRY", .{
        .boot = "[listen]\nirc = 6667\n[cloak]\nsecret = \"s\"\n[network]\nname = \"a\"\n",
        .applied = "[limits]\nnick_delay = \"5s\"\n[listen]\nirc = 6667\n",
        .proposed = "[limits]\nnick_delay = \"7s\"\n[listen]\nirc = 6668\n[cloak]\nsecret = \"t\"\n[network]\nname = \"b\"\n",
    });
    defer freeLines(allocator, lines);
    try testing.expectEqual(@as(usize, 5), lines.len);
}

test "config_change_preview: every allocation failure in renderTexts releases all memory" {
    // Fixed-buffer backing keeps in-place remap outcomes identical across
    // runs (the debug allocator's are state dependent). The sweep continues
    // until the first run that completes with no injected failure.
    const backing = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(backing);
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var fixed = std.heap.FixedBufferAllocator.init(backing);
        var failing = std.testing.FailingAllocator.init(fixed.allocator(), .{ .fail_index = fail_index });
        if (renderTextsProbe(failing.allocator())) |_| {
            try testing.expect(!failing.has_induced_failure);
            try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(failing.has_induced_failure);
            try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
    }
    try testing.expect(fail_index > 3);
    try renderTextsProbe(testing.allocator);
}
