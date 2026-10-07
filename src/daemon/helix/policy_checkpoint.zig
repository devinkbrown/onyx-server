// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for POLICY generations and the one-step undo.
//! The live WARD/KOSH/class/ban checkpoints carry current policy separately;
//! this row carries the *previous* policy that POLICY ROLLBACK can restore.

const std = @import("std");
const wire = @import("abuse_checkpoint_wire.zig");
const warden = @import("../warden.zig");
const conn_class = @import("../conn_class.zig");
const cidr = @import("../../proto/cidr.zig");

pub const checkpoint_magic = [_]u8{ 'P', 'O', 'L', 'Y' };
pub const max_checkpoint_bytes: usize = 64 * 1024 * 1024;
pub const max_wards: usize = 4096;
pub const max_patterns: usize = 4096;
pub const max_bans: usize = 65_535;
pub const max_text_bytes: usize = std.math.maxInt(u16);
pub const Error = wire.Error;
const domain = "onyx-policy-undo-checkpoint-v1";
const header_len: usize = 44;
const ward_row_min_len: usize = 3 + 2 + 2 + 2 + 8 + 8 + 1;
const ban_row_min_len: usize = 2 + 2 + 2 + 8 + 2;

pub const Generations = struct {
    ward: u32,
    filter: u32,
    class: u32,
    ban: u32,
    proof: u32,
};

/// Server may alias its private PolicyBanRow to this exact owning shape.
pub const BanRow = struct {
    channel: []u8,
    mask: []u8,
    setter: []u8,
    set_at: i64,
};

pub const UndoKind = enum(u8) { ward = 1, filter = 2, class = 3, ban = 4 };

pub const UndoView = union(UndoKind) {
    ward: struct { params: warden.Params, rows: []const warden.Ward },
    filter: struct { max_patterns: usize, max_pattern_len: usize, patterns: []const []u8 },
    class: ?*const conn_class.Registry,
    ban: []const BanRow,
};

pub const SnapshotView = struct {
    generations: Generations,
    previous_generation: u32 = 0,
    undo: ?UndoView = null,
};

pub const OwnedUndo = union(UndoKind) {
    ward: struct { params: warden.Params, rows: std.ArrayListUnmanaged(warden.Ward) },
    filter: struct { max_patterns: usize, max_pattern_len: usize, patterns: [][]u8 },
    class: ?conn_class.Registry,
    ban: []BanRow,
};

pub const OwnedSnapshot = struct {
    allocator: std.mem.Allocator,
    generations: Generations,
    previous_generation: u32,
    undo: ?OwnedUndo,

    pub fn takeUndo(self: *OwnedSnapshot) ?OwnedUndo {
        const result = self.undo;
        self.undo = null;
        return result;
    }

    pub fn deinit(self: *OwnedSnapshot) void {
        if (self.undo) |*value| switch (value.*) {
            .ward => |*w| warden.deinitWardList(self.allocator, &w.rows),
            .filter => |f| {
                for (f.patterns) |pattern| self.allocator.free(pattern);
                self.allocator.free(f.patterns);
            },
            .class => |*registry| if (registry.*) |*r| r.deinit(),
            .ban => |rows| {
                for (rows) |row| freeBan(self.allocator, row);
                self.allocator.free(rows);
            },
        };
        self.* = undefined;
    }
};

const Header = struct {
    generations: Generations,
    kind: ?UndoKind,
    previous_generation: u32,
    count: usize,
    body: []const u8,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const h = try parseHeader(bytes);
    var reader = wire.Reader{ .bytes = h.body };
    if (h.kind) |kind| switch (kind) {
        .ward => try validateWardRows(&reader, h.count),
        .filter => try validateFilterRows(&reader, h.count),
        .class => try validateClassRows(&reader, h.count),
        .ban => try validateBanRows(&reader, h.count),
    } else if (h.count != 0 or h.body.len != 0) return error.InvalidField;
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, snapshot: SnapshotView) Error![]u8 {
    try validateGenerations(snapshot.generations);
    const kind: ?UndoKind = if (snapshot.undo) |undo| std.meta.activeTag(undo) else null;
    try validateGenerationRelation(snapshot.generations, kind, snapshot.previous_generation);
    const count: usize = if (snapshot.undo) |undo| switch (undo) {
        .ward => |s| s.rows.len,
        .filter => |s| s.patterns.len,
        .class => |r| if (r) |registry| registry.classes.len else 0,
        .ban => |rows| rows.len,
    } else 0;
    if (count > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    var size: usize = header_len + wire.checksum_len;
    if (snapshot.undo) |undo| switch (undo) {
        .ward => |s| {
            try wardParams(s.params, count);
            try addLen(&size, 8);
            for (s.rows) |row| try wardSize(&size, row, s.params);
        },
        .filter => |s| {
            try filterLimits(s.max_patterns, s.max_pattern_len, count);
            try addLen(&size, 4);
            for (s.patterns) |pattern| try filterSize(&size, pattern, s.max_pattern_len);
        },
        .class => |r| {
            try addLen(&size, 8);
            if (r) |registry| {
                if (registry.classes.len > conn_class.max_classes) return error.CheckpointTooLarge;
                try validateClassRegistry(registry);
                for (registry.classes) |class| try classSize(&size, class);
            }
        },
        .ban => |rows| {
            if (rows.len > max_bans) return error.CheckpointTooLarge;
            for (rows) |row| try banSize(&size, row);
        },
    };
    if (size > max_checkpoint_bytes) return error.CheckpointTooLarge;
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU32(snapshot.generations.ward);
    writer.writeU32(snapshot.generations.filter);
    writer.writeU32(snapshot.generations.class);
    writer.writeU32(snapshot.generations.ban);
    writer.writeU32(snapshot.generations.proof);
    writer.writeByte(if (kind) |k| @intFromEnum(k) else 0);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(snapshot.previous_generation);
    writer.writeU32(@intCast(count));
    if (snapshot.undo) |undo| switch (undo) {
        .ward => |s| {
            writeWardParams(&writer, s.params);
            for (s.rows) |row| writeWard(&writer, row);
        },
        .filter => |s| {
            writer.writeU16(@intCast(s.max_patterns));
            writer.writeU16(@intCast(s.max_pattern_len));
            for (s.patterns) |pattern| {
                writer.writeU16(@intCast(pattern.len));
                writer.writeBytes(pattern);
            }
        },
        .class => |r| {
            writer.writeByte(@intFromBool(r != null));
            writer.writeBytes(&.{ 0, 0, 0 });
            writer.writeU16(if (r) |registry| @intCast(registry.user_idx) else 0);
            writer.writeU16(if (r) |registry| @intCast(registry.server_idx) else 0);
            if (r) |registry| for (registry.classes) |class| writeClass(&writer, class);
        },
        .ban => |rows| for (rows) |row| writeBan(&writer, row),
    };
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!OwnedSnapshot {
    try validateCheckpoint(bytes);
    const h = try parseHeader(bytes);
    var result: OwnedSnapshot = .{
        .allocator = allocator,
        .generations = h.generations,
        .previous_generation = h.previous_generation,
        .undo = null,
    };
    var reader = wire.Reader{ .bytes = h.body };
    if (h.kind) |kind| result.undo = switch (kind) {
        .ward => .{ .ward = try decodeWards(allocator, &reader, h.count) },
        .filter => .{ .filter = try decodeFilters(allocator, &reader, h.count) },
        .class => .{ .class = try decodeClassRegistry(allocator, &reader, h.count) },
        .ban => .{ .ban = try decodeBans(allocator, &reader, h.count) },
    };
    std.debug.assert(reader.remaining() == 0);
    return result;
}

fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const generations: Generations = .{
        .ward = std.mem.readInt(u32, bytes[12..16], .little),
        .filter = std.mem.readInt(u32, bytes[16..20], .little),
        .class = std.mem.readInt(u32, bytes[20..24], .little),
        .ban = std.mem.readInt(u32, bytes[24..28], .little),
        .proof = std.mem.readInt(u32, bytes[28..32], .little),
    };
    try validateGenerations(generations);
    if (!std.mem.eql(u8, bytes[33..36], &.{ 0, 0, 0 })) return error.InvalidField;
    const kind: ?UndoKind = if (bytes[32] == 0) null else std.enums.fromInt(UndoKind, bytes[32]) orelse return error.InvalidField;
    const previous_generation = std.mem.readInt(u32, bytes[36..40], .little);
    try validateGenerationRelation(generations, kind, previous_generation);
    return .{
        .generations = generations,
        .kind = kind,
        .previous_generation = previous_generation,
        .count = std.mem.readInt(u32, bytes[40..44], .little),
        .body = body,
    };
}

fn validateGenerations(g: Generations) Error!void {
    if (g.ward == 0 or g.filter == 0 or g.class == 0 or g.ban == 0 or g.proof == 0) return error.InvalidField;
}

fn validateGenerationRelation(g: Generations, kind: ?UndoKind, previous: u32) Error!void {
    if (kind) |k| {
        const current = switch (k) {
            .ward => g.ward,
            .filter => g.filter,
            .class => g.class,
            .ban => g.ban,
        };
        if (previous == 0 or previous > current or g.proof != current) return error.InvalidField;
        if (previous != current - @intFromBool(current != std.math.maxInt(u32))) return error.InvalidField;
    } else if (previous != 0) return error.InvalidField;
}

fn addLen(total: *usize, more: usize) Error!void {
    try wire.addLen(total, more);
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn freeBan(allocator: std.mem.Allocator, row: BanRow) void {
    allocator.free(row.channel);
    allocator.free(row.mask);
    allocator.free(row.setter);
}

fn wardParams(params: warden.Params, count: usize) Error!void {
    if (params.max_wards > max_wards or params.max_pattern > max_text_bytes or
        params.max_reason > max_text_bytes or params.max_setter > max_text_bytes or
        count > params.max_wards) return error.CheckpointTooLarge;
}

fn readWardParams(reader: *wire.Reader, count: usize) Error!warden.Params {
    const params: warden.Params = .{
        .max_wards = try reader.readU16(),
        .max_pattern = try reader.readU16(),
        .max_reason = try reader.readU16(),
        .max_setter = try reader.readU16(),
    };
    try wardParams(params, count);
    return params;
}

fn writeWardParams(writer: *wire.Writer, params: warden.Params) void {
    writer.writeU16(@intCast(params.max_wards));
    writer.writeU16(@intCast(params.max_pattern));
    writer.writeU16(@intCast(params.max_reason));
    writer.writeU16(@intCast(params.max_setter));
}

fn wardSize(size: *usize, row: warden.Ward, params: warden.Params) Error!void {
    if (row.pattern.len == 0 or row.pattern.len > params.max_pattern or
        row.reason.len > params.max_reason or row.set_by.len > params.max_setter) return error.InvalidField;
    try addLen(size, ward_row_min_len - 1 + row.pattern.len + row.reason.len + row.set_by.len);
}

fn writeWard(writer: *wire.Writer, row: warden.Ward) void {
    writer.writeByte(@intFromEnum(row.match));
    writer.writeByte(@intFromEnum(row.scope));
    writer.writeByte(@intFromEnum(row.action));
    writer.writeU16(@intCast(row.pattern.len));
    writer.writeU16(@intCast(row.reason.len));
    writer.writeU16(@intCast(row.set_by.len));
    writer.writeI64(row.created_ms);
    writer.writeI64(row.expires_ms);
    writer.writeBytes(row.pattern);
    writer.writeBytes(row.reason);
    writer.writeBytes(row.set_by);
}

fn readWard(reader: *wire.Reader, params: warden.Params) Error!warden.Ward {
    const match = std.enums.fromInt(warden.Match, try reader.readByte()) orelse return error.InvalidField;
    const scope = std.enums.fromInt(warden.Scope, try reader.readByte()) orelse return error.InvalidField;
    const action = std.enums.fromInt(warden.Action, try reader.readByte()) orelse return error.InvalidField;
    const pattern_len: usize = try reader.readU16();
    const reason_len: usize = try reader.readU16();
    const setter_len: usize = try reader.readU16();
    if (pattern_len == 0 or pattern_len > params.max_pattern or
        reason_len > params.max_reason or setter_len > params.max_setter) return error.InvalidField;
    const created_ms = try reader.readI64();
    const expires_ms = try reader.readI64();
    return .{
        .match = match,
        .scope = scope,
        .action = action,
        .pattern = try reader.take(pattern_len),
        .reason = try reader.take(reason_len),
        .set_by = try reader.take(setter_len),
        .created_ms = created_ms,
        .expires_ms = expires_ms,
    };
}

const WardIdentity = struct { match: warden.Match, pattern: []const u8 };

fn validateWardRows(reader: *wire.Reader, count: usize) Error!void {
    if (count > max_wards) return error.CheckpointTooLarge;
    if (reader.remaining() < 8 + count * ward_row_min_len) return error.Truncated;
    const params = try readWardParams(reader, count);
    var seen: [max_wards]WardIdentity = undefined;
    var table: [max_wards * 2]u16 = @splat(0);
    for (0..count) |index| {
        const row = try readWard(reader, params);
        var hash: u64 = 0xcbf29ce484222325;
        hash = (hash ^ @as(u64, @intFromEnum(row.match))) *% 0x100000001b3;
        for (row.pattern) |byte| hash = (hash ^ byte) *% 0x100000001b3;
        var slot: usize = @intCast(hash & (table.len - 1));
        while (table[slot] != 0) : (slot = (slot + 1) & (table.len - 1)) {
            const prior = seen[table[slot] - 1];
            if (prior.match == row.match and std.mem.eql(u8, prior.pattern, row.pattern)) return error.DuplicateEntry;
        }
        seen[index] = .{ .match = row.match, .pattern = row.pattern };
        table[slot] = @intCast(index + 1);
    }
}

fn decodeWards(allocator: std.mem.Allocator, reader: *wire.Reader, count: usize) Error!@FieldType(OwnedUndo, "ward") {
    const params = try readWardParams(reader, count);
    var rows: std.ArrayListUnmanaged(warden.Ward) = .empty;
    errdefer warden.deinitWardList(allocator, &rows);
    for (0..count) |_| {
        const row = try readWard(reader, params);
        const pattern = try allocator.dupe(u8, row.pattern);
        errdefer allocator.free(pattern);
        const reason = try allocator.dupe(u8, row.reason);
        errdefer allocator.free(reason);
        const setter = try allocator.dupe(u8, row.set_by);
        errdefer allocator.free(setter);
        try rows.append(allocator, .{
            .match = row.match,
            .scope = row.scope,
            .action = row.action,
            .pattern = pattern,
            .reason = reason,
            .set_by = setter,
            .created_ms = row.created_ms,
            .expires_ms = row.expires_ms,
        });
    }
    return .{ .params = params, .rows = rows };
}

fn filterLimits(limit: usize, max_len: usize, count: usize) Error!void {
    if (limit > max_patterns or max_len > max_text_bytes or count > limit) return error.CheckpointTooLarge;
}

fn filterSize(size: *usize, pattern: []const u8, max_len: usize) Error!void {
    if (pattern.len == 0 or pattern.len > max_len) return error.InvalidField;
    try addLen(size, 2 + pattern.len);
}

fn validateFilterRows(reader: *wire.Reader, count: usize) Error!void {
    if (count > max_patterns) return error.CheckpointTooLarge;
    if (reader.remaining() < 4 + count * 3) return error.Truncated;
    const limit: usize = try reader.readU16();
    const max_len: usize = try reader.readU16();
    try filterLimits(limit, max_len, count);
    var seen: [max_patterns][]const u8 = undefined;
    var table: [max_patterns * 2]u16 = @splat(0);
    for (0..count) |index| {
        const len: usize = try reader.readU16();
        if (len == 0 or len > max_len) return error.InvalidField;
        const pattern = try reader.take(len);
        var hash: u64 = 0xcbf29ce484222325;
        for (pattern) |byte| hash = (hash ^ std.ascii.toLower(byte)) *% 0x100000001b3;
        var slot: usize = @intCast(hash & (table.len - 1));
        while (table[slot] != 0) : (slot = (slot + 1) & (table.len - 1)) {
            if (std.ascii.eqlIgnoreCase(seen[table[slot] - 1], pattern)) return error.DuplicateEntry;
        }
        seen[index] = pattern;
        table[slot] = @intCast(index + 1);
    }
}

fn decodeFilters(allocator: std.mem.Allocator, reader: *wire.Reader, count: usize) Error!@FieldType(OwnedUndo, "filter") {
    const limit: usize = try reader.readU16();
    const max_len: usize = try reader.readU16();
    const patterns = try allocator.alloc([]u8, count);
    var copied: usize = 0;
    errdefer {
        for (patterns[0..copied]) |p| allocator.free(p);
        allocator.free(patterns);
    }
    for (patterns) |*p| {
        p.* = try allocator.dupe(u8, try reader.take(try reader.readU16()));
        copied += 1;
    }
    return .{ .max_patterns = limit, .max_pattern_len = max_len, .patterns = patterns };
}

const expected_policy_names = [_][]const u8{
    "sendq",            "recvq",           "max_clients",         "max_per_ip",        "max_per_account", "max_per_host", "max_channels",
    "ping_interval_ms", "ping_timeout_ms", "register_timeout_ms", "flood_lines",       "flood_window_ms", "flood_excess", "flood_targets",
    "require_tls",      "require_sasl",    "flood_exempt",        "nick_delay_exempt", "max_targets",     "monitor",      "silence",
};
const policy_struct = @typeInfo(conn_class.Policy).@"struct";
const policy_wire_len: usize = blk: {
    if (policy_struct.field_names.len != expected_policy_names.len) @compileError("POLY class policy fields changed; bump wire version");
    var total: usize = 0;
    for (policy_struct.field_names, policy_struct.field_types, 0..) |name, field_type, index| {
        if (!std.mem.eql(u8, name, expected_policy_names[index])) @compileError("POLY class policy field order changed; bump wire version");
        total += switch (field_type) {
            u64 => 8,
            u32 => 4,
            bool => 1,
            else => @compileError("POLY class policy field type changed; bump wire version"),
        };
    }
    break :blk total;
};
const class_row_min_len: usize = 8 + policy_wire_len + 1;

fn writePolicy(writer: *wire.Writer, policy: conn_class.Policy) void {
    inline for (policy_struct.field_names, policy_struct.field_types) |name, field_type| switch (field_type) {
        u64 => writer.writeU64(@field(policy, name)),
        u32 => writer.writeU32(@field(policy, name)),
        bool => writer.writeByte(@intFromBool(@field(policy, name))),
        else => unreachable,
    };
}

fn readPolicy(reader: *wire.Reader) Error!conn_class.Policy {
    var policy: conn_class.Policy = .{};
    inline for (policy_struct.field_names, policy_struct.field_types) |name, field_type| {
        @field(policy, name) = switch (field_type) {
            u64 => try reader.readU64(),
            u32 => try reader.readU32(),
            bool => blk: {
                const value = try reader.readByte();
                if (value > 1) return error.InvalidField;
                break :blk value == 1;
            },
            else => unreachable,
        };
    }
    return policy;
}

fn classSize(size: *usize, class: conn_class.Class) Error!void {
    if (class.name.len == 0 or class.name.len > conn_class.max_name_len or
        class.cidrs.len > conn_class.max_cidrs_per_class or
        (class.ident_glob != null and class.ident_glob.?.len > conn_class.max_glob_len) or
        (class.host_glob != null and class.host_glob.?.len > conn_class.max_glob_len)) return error.InvalidField;
    for (class.cidrs) |network| switch (network) {
        .v4 => |v| if (v.prefix > 32) return error.InvalidField,
        .v6 => |v| if (v.prefix > 128) return error.InvalidField,
    };
    try addLen(size, 8 + policy_wire_len + class.name.len + class.cidrs.len * 18 +
        (if (class.ident_glob) |glob| glob.len else 0) +
        (if (class.host_glob) |glob| glob.len else 0));
}

fn validateClassRegistry(registry: *const conn_class.Registry) Error!void {
    const classes = registry.classes;
    if (classes.len < 2 or classes.len > conn_class.max_classes or
        registry.user_idx >= classes.len or registry.server_idx >= classes.len or
        registry.user_idx == registry.server_idx or
        !std.ascii.eqlIgnoreCase(classes[registry.user_idx].name, "user") or
        !std.ascii.eqlIgnoreCase(classes[registry.server_idx].name, "server")) return error.InvalidField;
    var ignored_size: usize = 0;
    for (classes, 0..) |class, index| {
        try classSize(&ignored_size, class);
        for (classes[0..index]) |prior| if (std.ascii.eqlIgnoreCase(prior.name, class.name)) return error.DuplicateEntry;
    }
}

fn writeClass(writer: *wire.Writer, class: conn_class.Class) void {
    writer.writeByte(@intCast(class.name.len));
    writer.writeByte(@intCast(class.cidrs.len));
    var flags: u8 = 0;
    if (class.tls_only) flags |= 1;
    if (class.account_only) flags |= 2;
    if (class.oper_only) flags |= 4;
    if (class.ident_glob != null) flags |= 8;
    if (class.host_glob != null) flags |= 16;
    writer.writeByte(flags);
    writer.writeByte(0);
    writer.writeU16(if (class.ident_glob) |glob| @intCast(glob.len) else 0);
    writer.writeU16(if (class.host_glob) |glob| @intCast(glob.len) else 0);
    writePolicy(writer, class.policy);
    writer.writeBytes(class.name);
    for (class.cidrs) |network| {
        var address: [16]u8 = @splat(0);
        switch (network) {
            .v4 => |v| {
                writer.writeByte(0);
                writer.writeByte(v.prefix);
                std.mem.writeInt(u32, address[12..16], v.addr, .big);
            },
            .v6 => |v| {
                writer.writeByte(1);
                writer.writeByte(v.prefix);
                std.mem.writeInt(u128, &address, v.addr, .big);
            },
        }
        writer.writeBytes(&address);
    }
    if (class.ident_glob) |glob| writer.writeBytes(glob);
    if (class.host_glob) |glob| writer.writeBytes(glob);
}

const BorrowedClass = struct {
    name: []const u8,
    policy: conn_class.Policy,
    cidr_wire: []const u8,
    cidr_count: usize,
    tls_only: bool,
    account_only: bool,
    oper_only: bool,
    ident_glob: ?[]const u8,
    host_glob: ?[]const u8,
};

fn readClass(reader: *wire.Reader) Error!BorrowedClass {
    const name_len: usize = try reader.readByte();
    const cidr_count: usize = try reader.readByte();
    const flags = try reader.readByte();
    if ((flags & 0xe0) != 0 or try reader.readByte() != 0 or
        name_len == 0 or name_len > conn_class.max_name_len or
        cidr_count > conn_class.max_cidrs_per_class) return error.InvalidField;
    const ident_len: usize = try reader.readU16();
    const host_len: usize = try reader.readU16();
    if (ident_len > conn_class.max_glob_len or host_len > conn_class.max_glob_len or
        (flags & 8 == 0 and ident_len != 0) or (flags & 16 == 0 and host_len != 0)) return error.InvalidField;
    const policy = try readPolicy(reader);
    const name = try reader.take(name_len);
    const cidr_wire = try reader.take(cidr_count * 18);
    for (0..cidr_count) |index| {
        const bytes = cidr_wire[index * 18 ..][0..18];
        switch (bytes[0]) {
            0 => {
                if (bytes[1] > 32) return error.InvalidField;
                for (bytes[2..14]) |byte| if (byte != 0) return error.InvalidField;
            },
            1 => if (bytes[1] > 128) return error.InvalidField,
            else => return error.InvalidField,
        }
    }
    const ident = try reader.take(ident_len);
    const host = try reader.take(host_len);
    return .{
        .name = name,
        .policy = policy,
        .cidr_wire = cidr_wire,
        .cidr_count = cidr_count,
        .tls_only = flags & 1 != 0,
        .account_only = flags & 2 != 0,
        .oper_only = flags & 4 != 0,
        .ident_glob = if (flags & 8 != 0) ident else null,
        .host_glob = if (flags & 16 != 0) host else null,
    };
}

fn readClassHeader(reader: *wire.Reader, count: usize) Error!?struct { user_idx: usize, server_idx: usize } {
    const present = try reader.readByte();
    const reserved = try reader.take(3);
    const user_idx: usize = try reader.readU16();
    const server_idx: usize = try reader.readU16();
    if (present > 1 or !std.mem.eql(u8, reserved, &.{ 0, 0, 0 })) return error.InvalidField;
    if (present == 0) {
        if (count != 0 or user_idx != 0 or server_idx != 0) return error.InvalidField;
        return null;
    }
    if (count < 2 or count > conn_class.max_classes or user_idx >= count or server_idx >= count or user_idx == server_idx) return error.InvalidField;
    return .{ .user_idx = user_idx, .server_idx = server_idx };
}

fn validateClassRows(reader: *wire.Reader, count: usize) Error!void {
    if (count > conn_class.max_classes) return error.CheckpointTooLarge;
    if (reader.remaining() < 8) return error.Truncated;
    const header = try readClassHeader(reader, count) orelse return;
    if (reader.remaining() < count * class_row_min_len) return error.Truncated;
    var names: [conn_class.max_classes][]const u8 = undefined;
    for (0..count) |index| {
        const class = try readClass(reader);
        names[index] = class.name;
        for (names[0..index]) |prior| if (std.ascii.eqlIgnoreCase(prior, class.name)) return error.DuplicateEntry;
    }
    if (!std.ascii.eqlIgnoreCase(names[header.user_idx], "user") or
        !std.ascii.eqlIgnoreCase(names[header.server_idx], "server")) return error.InvalidField;
}

fn decodeClassRegistry(allocator: std.mem.Allocator, reader: *wire.Reader, count: usize) Error!?conn_class.Registry {
    const header = try readClassHeader(reader, count) orelse return null;
    const classes = try allocator.alloc(conn_class.Class, count);
    var copied: usize = 0;
    errdefer {
        for (classes[0..copied]) |class| freeClass(allocator, class);
        allocator.free(classes);
    }
    for (classes) |*class| {
        const source = try readClass(reader);
        const name = try allocator.dupe(u8, source.name);
        errdefer allocator.free(name);
        const networks = try allocator.alloc(cidr.Cidr, source.cidr_count);
        errdefer allocator.free(networks);
        for (networks, 0..) |*network, index| {
            const bytes = source.cidr_wire[index * 18 ..][0..18];
            network.* = if (bytes[0] == 0)
                .{ .v4 = .{ .addr = std.mem.readInt(u32, bytes[14..18], .big), .prefix = @intCast(bytes[1]) } }
            else
                .{ .v6 = .{ .addr = std.mem.readInt(u128, bytes[2..18], .big), .prefix = bytes[1] } };
        }
        const ident = if (source.ident_glob) |glob| try allocator.dupe(u8, glob) else null;
        errdefer if (ident) |glob| allocator.free(glob);
        const host = if (source.host_glob) |glob| try allocator.dupe(u8, glob) else null;
        class.* = .{
            .name = name,
            .policy = source.policy,
            .cidrs = networks,
            .tls_only = source.tls_only,
            .account_only = source.account_only,
            .oper_only = source.oper_only,
            .ident_glob = ident,
            .host_glob = host,
        };
        copied += 1;
    }
    return .{ .allocator = allocator, .classes = classes, .user_idx = header.user_idx, .server_idx = header.server_idx };
}

fn freeClass(allocator: std.mem.Allocator, class: conn_class.Class) void {
    allocator.free(class.name);
    allocator.free(class.cidrs);
    if (class.ident_glob) |glob| allocator.free(glob);
    if (class.host_glob) |glob| allocator.free(glob);
}

fn banSize(size: *usize, row: BanRow) Error!void {
    if (row.channel.len == 0 or row.mask.len == 0 or row.channel.len > max_text_bytes or
        row.mask.len > max_text_bytes or row.setter.len > max_text_bytes) return error.InvalidField;
    try addLen(size, ban_row_min_len - 2 + row.channel.len + row.mask.len + row.setter.len);
}

fn writeBan(writer: *wire.Writer, row: BanRow) void {
    writer.writeU16(@intCast(row.channel.len));
    writer.writeU16(@intCast(row.mask.len));
    writer.writeU16(@intCast(row.setter.len));
    writer.writeI64(row.set_at);
    writer.writeBytes(row.channel);
    writer.writeBytes(row.mask);
    writer.writeBytes(row.setter);
}

const BorrowedBan = struct {
    channel: []const u8,
    mask: []const u8,
    setter: []const u8,
    set_at: i64,
};

fn readBan(reader: *wire.Reader) Error!BorrowedBan {
    const channel_len: usize = try reader.readU16();
    const mask_len: usize = try reader.readU16();
    const setter_len: usize = try reader.readU16();
    if (channel_len == 0 or mask_len == 0) return error.InvalidField;
    const set_at = try reader.readI64();
    return .{
        .channel = try reader.take(channel_len),
        .mask = try reader.take(mask_len),
        .setter = try reader.take(setter_len),
        .set_at = set_at,
    };
}

fn validateBanRows(reader: *wire.Reader, count: usize) Error!void {
    if (count > max_bans) return error.CheckpointTooLarge;
    if (reader.remaining() < count * ban_row_min_len) return error.Truncated;
    for (0..count) |_| _ = try readBan(reader);
}

fn decodeBans(allocator: std.mem.Allocator, reader: *wire.Reader, count: usize) Error![]BanRow {
    const rows = try allocator.alloc(BanRow, count);
    var copied: usize = 0;
    errdefer {
        for (rows[0..copied]) |row| freeBan(allocator, row);
        allocator.free(rows);
    }
    for (rows) |*row| {
        const source = try readBan(reader);
        const channel = try allocator.dupe(u8, source.channel);
        errdefer allocator.free(channel);
        const mask = try allocator.dupe(u8, source.mask);
        errdefer allocator.free(mask);
        row.* = .{
            .channel = channel,
            .mask = mask,
            .setter = try allocator.dupe(u8, source.setter),
            .set_at = source.set_at,
        };
        copied += 1;
    }
    return rows;
}

test "POLY preserves absent undo and rejects noncanonical headers" {
    const a = std.testing.allocator;
    const g: Generations = .{ .ward = 4, .filter = 2, .class = 3, .ban = 1, .proof = 3 };
    const bytes = try encode(a, .{ .generations = g });
    defer a.free(bytes);
    var restored = try decode(a, bytes);
    defer restored.deinit();
    try std.testing.expectEqualDeep(g, restored.generations);
    try std.testing.expect(restored.undo == null);
    var bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    bad[33] = 1;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    bad[33] = 0;
    bad[32] = 7;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
}

test "POLY preserves exact WARD rollback order and filter spelling" {
    const a = std.testing.allocator;
    const wards = [_]warden.Ward{
        .{ .match = .account, .pattern = "First*", .scope = .mesh, .action = .require_auth, .reason = "watch", .set_by = "oper", .created_ms = 100, .expires_ms = 900 },
        .{ .match = .asn, .pattern = "64500", .scope = .node, .action = .quarantine, .reason = "reason", .set_by = "netadmin", .created_ms = 101 },
    };
    const ward_view: SnapshotView = .{
        .generations = .{ .ward = 2, .filter = 1, .class = 1, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .ward = .{ .params = .{ .max_wards = 8, .max_pattern = 64, .max_reason = 64, .max_setter = 32 }, .rows = &wards } },
    };
    const ward_bytes = try encode(a, ward_view);
    defer a.free(ward_bytes);
    var ward_copy = try decode(a, ward_bytes);
    defer ward_copy.deinit();
    const old = ward_copy.undo.?.ward;
    try std.testing.expectEqual(@as(u32, 1), ward_copy.previous_generation);
    try std.testing.expectEqual(@as(usize, 2), old.rows.items.len);
    try std.testing.expectEqualStrings("First*", old.rows.items[0].pattern);
    try std.testing.expectEqual(warden.Action.quarantine, old.rows.items[1].action);

    const patterns = [_][]u8{ @constCast("Bad Word"), @constCast("second") };
    const filter_bytes = try encode(a, .{
        .generations = .{ .ward = 2, .filter = 2, .class = 1, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .filter = .{ .max_patterns = 7, .max_pattern_len = 90, .patterns = &patterns } },
    });
    defer a.free(filter_bytes);
    var filter_copy = try decode(a, filter_bytes);
    defer filter_copy.deinit();
    const prior = filter_copy.undo.?.filter;
    try std.testing.expectEqual(@as(usize, 7), prior.max_patterns);
    try std.testing.expectEqualStrings("Bad Word", prior.patterns[0]);
    try std.testing.expectEqualStrings("second", prior.patterns[1]);
}

test "POLY owns exact class registry and prior ban rows" {
    const a = std.testing.allocator;
    var builder = conn_class.Builder.init(a);
    defer builder.deinit();
    try builder.add(.{
        .name = "trusted",
        .policy = .{ .sendq = 19 << 20, .max_per_ip = 7, .require_tls = true, .flood_exempt = true },
        .cidr_texts = &.{ "10.0.0.0/8", "2001:db8::/32" },
        .host_glob = "*.example.test",
    });
    var registry = try builder.finish();
    defer registry.deinit();
    const class_bytes = try encode(a, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 2, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .class = &registry },
    });
    defer a.free(class_bytes);
    var class_copy = try decode(a, class_bytes);
    defer class_copy.deinit();
    const old = class_copy.undo.?.class.?;
    try std.testing.expectEqual(@as(usize, 3), old.classes.len);
    try std.testing.expectEqual(@as(u32, 7), old.byName("trusted").?.policy.max_per_ip);
    try std.testing.expect(old.byName("trusted").?.cidrs[1].containsText("2001:db8::1") catch false);
    try std.testing.expectEqualStrings("user", old.classes[old.user_idx].name);

    const rows = [_]BanRow{
        .{ .channel = @constCast("#one"), .mask = @constCast("*!*@bad"), .setter = @constCast("alice"), .set_at = 88 },
        .{ .channel = @constCast("#two"), .mask = @constCast("*!*@worse"), .setter = @constCast("bob"), .set_at = 90 },
    };
    const ban_bytes = try encode(a, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 2, .ban = 2, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .ban = &rows },
    });
    defer a.free(ban_bytes);
    var ban_copy = try decode(a, ban_bytes);
    defer ban_copy.deinit();
    try std.testing.expectEqualStrings("#one", ban_copy.undo.?.ban[0].channel);
    try std.testing.expectEqualStrings("*!*@worse", ban_copy.undo.?.ban[1].mask);
    try std.testing.expectEqual(@as(i64, 90), ban_copy.undo.?.ban[1].set_at);
}

test "POLY validates duplicate undo identities and generations" {
    const a = std.testing.allocator;
    const wards = [_]warden.Ward{
        .{ .match = .account, .pattern = "same" },
        .{ .match = .account, .pattern = "same" },
    };
    try std.testing.expectError(error.DuplicateEntry, encode(a, .{
        .generations = .{ .ward = 2, .filter = 1, .class = 1, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .ward = .{ .params = .{}, .rows = &wards } },
    }));
    const patterns = [_][]u8{ @constCast("Deny"), @constCast("deny") };
    try std.testing.expectError(error.DuplicateEntry, encode(a, .{
        .generations = .{ .ward = 1, .filter = 2, .class = 1, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .filter = .{ .max_patterns = 7, .max_pattern_len = 90, .patterns = &patterns } },
    }));
    try std.testing.expectError(error.InvalidField, encode(a, .{
        .generations = .{ .ward = 2, .filter = 1, .class = 1, .ban = 1, .proof = 1 },
        .previous_generation = 1,
        .undo = .{ .ban = &.{} },
    }));
    const saturated = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidField, encode(a, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 1, .ban = saturated, .proof = saturated },
        .previous_generation = saturated - 1,
        .undo = .{ .ban = &.{} },
    }));
    const saturated_bytes = try encode(a, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 1, .ban = saturated, .proof = saturated },
        .previous_generation = saturated,
        .undo = .{ .ban = &.{} },
    });
    defer a.free(saturated_bytes);
    try validateCheckpoint(saturated_bytes);
}

test "POLY independent decode survives every allocation failure" {
    const a = std.testing.allocator;
    var builder = conn_class.Builder.init(a);
    defer builder.deinit();
    try builder.add(.{ .name = "trusted", .policy = .{ .max_per_ip = 3 }, .cidr_texts = &.{"192.0.2.0/24"} });
    var registry = try builder.finish();
    defer registry.deinit();
    const bytes = try encode(a, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 2, .ban = 1, .proof = 2 },
        .previous_generation = 1,
        .undo = .{ .class = &registry },
    });
    defer a.free(bytes);
    const Decode = struct {
        fn run(allocator: std.mem.Allocator, encoded: []const u8) !void {
            var decoded = try decode(allocator, encoded);
            defer decoded.deinit();
            try std.testing.expectEqual(@as(u32, 3), decoded.undo.?.class.?.byName("trusted").?.policy.max_per_ip);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Decode.run, .{bytes});
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}
