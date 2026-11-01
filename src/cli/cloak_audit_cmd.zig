// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline audit of explicitly supplied private checkpoint and provenance.
//! No config loader, environment lookup, socket, clock or live apply authority.
//! Linux custody only: all path components are opened without following links;
//! the final parent must be owned by the effective uid with mode 0700.
const std = @import("std");
const builtin = @import("builtin");
const audit = @import("../daemon/cloak_migration_audit.zig");
const cloak = @import("../proto/cloak.zig");
const policy_lists = @import("../daemon/cloak_policy_list_audit.zig");
const world_lists = @import("../daemon/cloak_world_audit.zig");
const durable = @import("../daemon/cloak_durable_audit.zig");

pub const usage = "usage: onyx-server cloak-audit --kind <access|saccess|akick|ward|world|akick-record|ward-record|saccess-record> --input <absolute-private-checkpoint> --witness <absolute-private-json> [--checkpoint-output <absolute-new-private-file>]\n";
pub const max_witness_bytes = 1024 * 1024;
const scratch_bytes = 8 * 1024 * 1024;
pub const Kind = enum { access, saccess, akick, ward, world, @"akick-record", @"ward-record", @"saccess-record" };
pub const Options = struct {
    kind: Kind,
    input: []const u8,
    witness: []const u8,
    checkpoint_output: ?[]const u8 = null,
};

fn validPath(path: []const u8) bool {
    if (path.len < 2 or path.len > 4096 or path[0] != '/' or std.mem.indexOfAny(u8, path, "\x00\r\n\\") != null) return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 255 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

pub fn parse(args: []const []const u8) error{InvalidArguments}!Options {
    if (args.len != 6 and args.len != 8) return error.InvalidArguments;
    var kind: ?Kind = null;
    var input: ?[]const u8 = null;
    var witness: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        const flag = args[i];
        const value = args[i + 1];
        if (std.mem.eql(u8, flag, "--kind") and kind == null) {
            kind = std.meta.stringToEnum(Kind, value) orelse return error.InvalidArguments;
        } else if (std.mem.eql(u8, flag, "--input") and input == null and validPath(value)) {
            input = value;
        } else if (std.mem.eql(u8, flag, "--witness") and witness == null and validPath(value)) {
            witness = value;
        } else if (std.mem.eql(u8, flag, "--checkpoint-output") and output == null and validPath(value)) {
            output = value;
        } else return error.InvalidArguments;
    }
    return .{ .kind = kind orelse return error.InvalidArguments, .input = input orelse return error.InvalidArguments, .witness = witness orelse return error.InvalidArguments, .checkpoint_output = output };
}

/// JSON transport is exactly 64 standard hex digits for the existing
/// SecretKey's 32 octets. Decode uses std.fmt.hexToBytes, without a KDF.
/// Keys and addresses occur only inside the private witness file, never argv.
/// Every field is mandatory except the explicitly nullable epoch/cadence and
/// target. No unknown/duplicate fields, trailing values or formula guessing.
pub const RawTarget = struct { key_hex: []const u8, suffix: []const u8, epoch: u64, cadence: u64 };
pub const RawWitness = struct {
    row: usize,
    expected_mask: []const u8,
    formula: audit.Formula,
    key_hex: []const u8,
    address: []const u8,
    suffix: []const u8,
    epoch: ?u64,
    cadence: ?u64,
};
pub const Document = struct { version: u8, target: ?RawTarget, witnesses: []RawWitness };

fn decodeKey(text: []const u8) !cloak.SecretKey {
    if (text.len != cloak.key_len * 2) return error.InvalidWitness;
    var bytes: [cloak.key_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    _ = std.fmt.hexToBytes(&bytes, text) catch return error.InvalidWitness;
    return cloak.SecretKey.fromSlice(&bytes);
}

fn document(allocator: std.mem.Allocator, text: []const u8, kind: Kind) !Document {
    if (text.len > max_witness_bytes) return error.LimitExceeded;
    const value = try std.json.parseFromSliceLeaky(Document, allocator, text, .{
        .ignore_unknown_fields = false,
        .duplicate_field_behavior = .@"error",
        .max_value_len = 512,
        .allocate = .alloc_always,
    });
    if (value.version != 1 or value.witnesses.len > 4096) return error.InvalidWitness;
    switch (kind) {
        .access, .akick, .ward, .world, .@"ward-record" => {
            const target = value.target orelse return error.InvalidWitness;
            var key = try decodeKey(target.key_hex);
            defer key.wipe();
            if (target.cadence == 0 or target.suffix.len > cloak.max_hostname_len) return error.InvalidWitness;
            var suffix: [cloak.max_hostname_len]u8 = undefined;
            _ = try cloak.normalizeSuffix(&suffix, target.suffix);
        },
        .saccess, .@"akick-record", .@"saccess-record" => if (value.target != null or value.witnesses.len != 0) return error.InvalidWitness,
    }
    if (kind == .@"ward-record" and value.witnesses.len > 1) return error.InvalidWitness;
    for (value.witnesses, 0..) |witness, i| {
        var key = try decodeKey(witness.key_hex);
        defer key.wipe();
        if (witness.row >= 4096 or witness.expected_mask.len == 0 or witness.expected_mask.len > 512 or witness.address.len > 128 or witness.suffix.len > cloak.max_hostname_len) return error.InvalidWitness;
        if (i != 0 and value.witnesses[i - 1].row >= witness.row) return error.InvalidWitness;
    }
    return value;
}

fn requirePrivate(handle: std.posix.fd_t, directory: bool) !void {
    const linux = std.os.linux;
    var info: linux.Statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(handle, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .NLINK = true }, &info))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.PrivateCustodyUnavailable,
    };
    if (!info.mask.TYPE or !info.mask.MODE or !info.mask.UID or !info.mask.NLINK or info.uid != linux.geteuid()) return error.InsecureInput;
    if (directory) {
        if (info.mode & std.posix.S.IFMT != std.posix.S.IFDIR or info.mode & 0o7777 != 0o700) return error.InsecureInput;
    } else if (info.mode & std.posix.S.IFMT != std.posix.S.IFREG or info.mode & 0o7077 != 0 or info.nlink != 1) return error.InsecureInput;
}

/// Component traversal keeps a descriptor for each next lookup and never
/// accepts symlink ancestors. A trusted owner can still alter their own files;
/// the witness proves only the supplied immutable in-memory checkpoint image.
fn privateParent(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!validPath(path)) return error.InvalidArguments;
    var dir = try std.Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer dir.close(io);
    const parent = std.fs.path.dirname(path).?;
    var parts = std.mem.tokenizeScalar(u8, parent, '/');
    while (parts.next()) |part| {
        const child = try dir.openDir(io, part, .{ .follow_symlinks = false });
        dir.close(io);
        dir = child;
    }
    try requirePrivate(dir.handle, true);
    return dir;
}

const PrivateBytes = struct {
    storage: []u8,
    len: usize,
    fn bytes(self: @This()) []const u8 {
        return self.storage[0..self.len];
    }
    fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.storage);
        allocator.free(self.storage);
    }
};

fn readPrivate(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) !PrivateBytes {
    const parent = try privateParent(io, path);
    defer parent.close(io);
    const held = try parent.openFile(io, std.fs.path.basename(path), .{ .path_only = true, .follow_symlinks = false });
    defer held.close(io);
    try requirePrivate(held.handle, false);
    var storage: [64]u8 = undefined;
    const fd_path = try std.fmt.bufPrint(&storage, "/proc/self/fd/{d}", .{held.handle});
    const file = try std.Io.Dir.openFileAbsolute(io, fd_path, .{});
    defer file.close(io);
    try requirePrivate(file.handle, false);
    if ((try file.stat(io)).inode != (try held.stat(io)).inode) return error.InsecureInput;
    const storage_bytes = try allocator.alloc(u8, limit + 1);
    errdefer {
        std.crypto.secureZero(u8, storage_bytes);
        allocator.free(storage_bytes);
    }
    var len: usize = 0;
    while (len < storage_bytes.len) {
        const n = file.readStreaming(io, &.{storage_bytes[len..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        len += n;
    }
    if (len > limit) return error.LimitExceeded;
    return .{ .storage = storage_bytes, .len = len };
}

// Typed checkpoint families share only ownership and redacted report
// interfaces. No checkpoint casts, row replay or metadata synthesis occur here.
const AuditPlan = union(enum) {
    access: audit.Plan,
    policy: policy_lists.Plan,
    world: world_lists.Plan,
    raw: durable.Plan,

    fn deinit(self: *AuditPlan) void {
        switch (self.*) {
            inline else => |*plan| plan.deinit(),
        }
        self.* = undefined;
    }
    fn checkpoint(self: *const AuditPlan) []const u8 {
        return switch (self.*) {
            .raw => |*plan| plan.record,
            inline else => |*plan| plan.checkpoint,
        };
    }
    fn forEachSummary(self: *const AuditPlan, ctx: anytype, comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        switch (self.*) {
            inline else => |*plan| try plan.forEachSummary(ctx, emit),
        }
    }
};

const Summary = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,
    fn emit(self: *@This(), line: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, line);
    }
};

/// Only the optional detached checkpoint is published, create-only and after
/// all parsing/auditing/report I/O succeeds. No fallible work follows link().
/// A report may already be visible if final publication fails; it asserts no
/// publication or live application. Default output is row/classification only.
pub fn run(allocator: std.mem.Allocator, io: std.Io, opts: Options, report_file: std.Io.File) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const input_limit: usize = switch (opts.kind) {
        .@"akick-record", .@"ward-record", .@"saccess-record" => 2048,
        else => 8 * 1024 * 1024,
    };
    const input = try readPrivate(allocator, io, opts.input, input_limit);
    defer input.deinit(allocator);
    const text = try readPrivate(allocator, io, opts.witness, max_witness_bytes);
    defer text.deinit(allocator);
    // Wipe the complete parser arena, including partial/error parses, decoded
    // escaped addresses, hex key strings and allocator relocation copies.
    const scratch = try allocator.alloc(u8, scratch_bytes);
    defer {
        std.crypto.secureZero(u8, scratch);
        allocator.free(scratch);
    }
    var arena = std.heap.FixedBufferAllocator.init(scratch);
    const a = arena.allocator();
    const doc = try document(a, text.bytes(), opts.kind);
    var plan: AuditPlan = switch (opts.kind) {
        .saccess => .{ .access = try audit.auditSaccess(allocator, input.bytes(), .{}) },
        .@"akick-record" => .{ .raw = try durable.audit(allocator, .akick_record, input.bytes(), null, null, .{}) },
        .@"saccess-record" => .{ .raw = try durable.audit(allocator, .saccess_record, input.bytes(), null, null, .{}) },
        .access, .akick, .ward, .world, .@"ward-record" => blk: {
            const raw = doc.target.?;
            var key = try decodeKey(raw.key_hex);
            defer key.wipe();
            const keys = try a.alloc(cloak.SecretKey, doc.witnesses.len);
            const witnesses = try a.alloc(audit.Witness, doc.witnesses.len);
            for (doc.witnesses, 0..) |row, i| {
                keys[i] = try decodeKey(row.key_hex);
                witnesses[i] = .{ .row = row.row, .expected_mask = row.expected_mask, .source = .{
                    .formula = row.formula,
                    .key = &keys[i],
                    .address = row.address,
                    .suffix = row.suffix,
                    .epoch = row.epoch,
                    .cadence = row.cadence,
                } };
            }
            const target: audit.Target = .{ .key = &key, .suffix = raw.suffix, .epoch = raw.epoch, .cadence = raw.cadence };
            break :blk switch (opts.kind) {
                .access => .{ .access = try audit.auditAccess(allocator, input.bytes(), witnesses, target, .{}) },
                .akick => .{ .policy = try policy_lists.auditAkick(allocator, input.bytes(), witnesses, target, .{}) },
                .ward => .{ .policy = try policy_lists.auditWard(allocator, input.bytes(), witnesses, target, .{}) },
                .world => .{ .world = try world_lists.audit(allocator, input.bytes(), witnesses, target, .{}) },
                .@"ward-record" => .{ .raw = try durable.audit(allocator, .ward_record, input.bytes(), if (witnesses.len == 0) null else witnesses[0], target, .{}) },
                .saccess, .@"akick-record", .@"saccess-record" => unreachable,
            };
        },
    };
    defer plan.deinit();
    var summary = Summary{ .allocator = allocator };
    defer summary.bytes.deinit(allocator);
    try plan.forEachSummary(&summary, Summary.emit);
    if (opts.checkpoint_output) |path| {
        const parent = try privateParent(io, path);
        defer parent.close(io);
        var output = try parent.createFileAtomic(io, std.fs.path.basename(path), .{ .replace = false, .permissions = .fromMode(0o600) });
        defer output.deinit(io);
        try output.file.writeStreamingAll(io, plan.checkpoint());
        try output.file.sync(io);
        try report_file.writeStreamingAll(io, summary.bytes.items);
        try output.link(io);
    } else try report_file.writeStreamingAll(io, summary.bytes.items);
}

test "cloak audit CLI: full argument grammar rejects duplicates aliases and traversal" {
    const testing = std.testing;
    const opts = try parse(&.{ "--kind", "access", "--input", "/private/input", "--witness", "/private/witness" });
    try testing.expect(opts.checkpoint_output == null);
    for ([_][]const []const u8{
        &.{},
        &.{ "--kind", "access", "--input", "/private/input", "--witness" },
        &.{ "--kind", "access", "--input", "/private/input", "--input", "/private/witness" },
        &.{ "--kind", "ACCESS", "--input", "/private/input", "--witness", "/private/witness" },
        &.{ "--kind", "access", "--input", "relative", "--witness", "/private/witness" },
        &.{ "--kind", "access", "--input", "/private/../input", "--witness", "/private/witness" },
        &.{ "--kind", "access", "--input", "/private/input", "--witness", "/private/witness", "--apply", "/private/output" },
    }) |bad| try testing.expectError(error.InvalidArguments, parse(bad));
    for ([_][]const u8{ "/a//b", "/a/./b", "/a/b/", "/", "/a\x00b" }) |bad| try testing.expect(!validPath(bad));
}

test "cloak audit CLI: strict witness schema rejects unknown duplicate trailing and unavailable SACCESS metadata" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const empty = "{\"version\":1,\"target\":null,\"witnesses\":[]}";
    _ = try document(a, empty, .saccess);
    try std.testing.expectError(error.InvalidWitness, document(a, empty, .access));
    try std.testing.expectError(error.UnknownField, document(a, "{\"version\":1,\"target\":null,\"witnesses\":[],\"apply\":true}", .saccess));
    try std.testing.expectError(error.DuplicateField, document(a, "{\"version\":1,\"version\":1,\"target\":null,\"witnesses\":[]}", .saccess));
    if (document(a, empty ++ " {}", .saccess)) |_| return error.TrailingValueAccepted else |_| {}
    try std.testing.expectError(error.InvalidWitness, document(a, "{\"version\":2,\"target\":null,\"witnesses\":[]}", .saccess));
}

fn testWrite(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

test "cloak audit CLI: private SACCESS output is exact redacted create-only and refuses symlinks and broad custody" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const saccess = @import("../proto/ircx_saccess.zig");
    const codec = @import("../daemon/helix/saccess_checkpoint.zig");
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const input = try std.fs.path.join(a, &.{ root, "input" });
    defer a.free(input);
    const witness = try std.fs.path.join(a, &.{ root, "witness" });
    defer a.free(witness);
    const output = try std.fs.path.join(a, &.{ root, "output" });
    defer a.free(output);
    var store = saccess.ServerAccessStore.init(a);
    defer store.deinit();
    try store.add(.{ .entry_type = .deny, .mask = "*!private@legacy.opq.onyx", .duration = 9, .reason = "private-reason" });
    const bytes = try codec.encode(a, &store);
    defer a.free(bytes);
    try testWrite(io, tmp.dir, "input", bytes);
    try testWrite(io, tmp.dir, "witness", "{\"version\":1,\"target\":null,\"witnesses\":[]}");
    const report = try tmp.dir.createFile(io, "report", .{ .permissions = .fromMode(0o600) });
    defer report.close(io);
    const opts = Options{ .kind = .saccess, .input = input, .witness = witness, .checkpoint_output = output };
    try run(a, io, opts, report);
    const artifact = try tmp.dir.readFileAlloc(io, "output", a, .limited(8192));
    defer a.free(artifact);
    try std.testing.expectEqualSlices(u8, bytes, artifact);
    const published = try tmp.dir.openFile(io, "output", .{});
    defer published.close(io);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), (try published.stat(io)).permissions.toMode() & 0o7777);
    const summary = try tmp.dir.readFileAlloc(io, "report", a, .limited(8192));
    defer a.free(summary);
    try std.testing.expectEqualStrings("row=0 classification=metadata_gap\n", summary);
    try std.testing.expectError(error.PathAlreadyExists, run(a, io, opts, report));
    const unchanged = try tmp.dir.readFileAlloc(io, "output", a, .limited(8192));
    defer a.free(unchanged);
    try std.testing.expectEqualSlices(u8, bytes, unchanged);
    const linked = try std.fs.path.join(a, &.{ root, "linked" });
    defer a.free(linked);
    try tmp.dir.symLink(io, "output", "linked", .{});
    var link_opts = opts;
    link_opts.checkpoint_output = linked;
    try std.testing.expectError(error.PathAlreadyExists, run(a, io, link_opts, report));
    link_opts.input = linked;
    link_opts.checkpoint_output = null;
    try std.testing.expectError(error.InsecureInput, run(a, io, link_opts, report));
    try tmp.dir.setFilePermissions(io, "witness", .fromMode(0o644), .{});
    try std.testing.expectError(error.InsecureInput, run(a, io, opts, report));
    try tmp.dir.setFilePermissions(io, "witness", .fromMode(0o600), .{});
    try tmp.dir.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(error.InsecureInput, run(a, io, opts, report));
}

test "cloak audit CLI: malformed witness or report write failure leaves output absent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const saccess = @import("../proto/ircx_saccess.zig");
    const codec = @import("../daemon/helix/saccess_checkpoint.zig");
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const input = try std.fs.path.join(a, &.{ root, "input" });
    defer a.free(input);
    const witness = try std.fs.path.join(a, &.{ root, "witness" });
    defer a.free(witness);
    const good_witness = try std.fs.path.join(a, &.{ root, "good-witness" });
    defer a.free(good_witness);
    const output = try std.fs.path.join(a, &.{ root, "output" });
    defer a.free(output);
    var store = saccess.ServerAccessStore.init(a);
    defer store.deinit();
    try store.add(.{ .entry_type = .deny, .mask = "*!private@legacy.opq.onyx", .duration = 0, .reason = null });
    const bytes = try codec.encode(a, &store);
    defer a.free(bytes);
    try testWrite(io, tmp.dir, "input", bytes);
    try testWrite(io, tmp.dir, "witness", "malformed private input");
    try testWrite(io, tmp.dir, "good-witness", "{\"version\":1,\"target\":null,\"witnesses\":[]}");
    const readonly = try tmp.dir.openFile(io, "input", .{});
    defer readonly.close(io);
    var opts = Options{ .kind = .saccess, .input = input, .witness = witness, .checkpoint_output = output };
    if (run(a, io, opts, readonly)) |_| return error.MalformedWitnessAccepted else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "output", .{}));
    opts.witness = good_witness;
    if (run(a, io, opts, readonly)) |_| return error.ReportFailurePublished else |_| {}
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(io, "output", .{}));
}

test "cloak audit CLI: explicit ACCESS provenance replaces only verified host and absent witness preserves image" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const access = @import("../proto/ircx_access_store.zig");
    const codec = @import("../daemon/helix/access_checkpoint.zig");
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const input = try std.fs.path.join(a, &.{ root, "input" });
    defer a.free(input);
    const witness_path = try std.fs.path.join(a, &.{ root, "witness" });
    defer a.free(witness_path);
    const missing_path = try std.fs.path.join(a, &.{ root, "missing-witness" });
    defer a.free(missing_path);
    const output = try std.fs.path.join(a, &.{ root, "output" });
    defer a.free(output);
    const unchanged_path = try std.fs.path.join(a, &.{ root, "unchanged" });
    defer a.free(unchanged_path);
    var key = cloak.SecretKey.init(@splat(0x6a));
    key.bytes[0] = 0x00;
    key.bytes[1] = 0x80;
    key.bytes[2] = 0xff;
    defer key.wipe();
    var target_key = cloak.SecretKey.init(@splat(0x6b));
    target_key.bytes[0] = 0xff;
    target_key.bytes[1] = 0x80;
    target_key.bytes[2] = 0x00;
    defer target_key.wipe();
    var source_hex = std.fmt.bytesToHex(key.bytes, .lower);
    defer std.crypto.secureZero(u8, &source_hex);
    var target_hex = std.fmt.bytesToHex(target_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &target_hex);
    var old_storage: [253]u8 = undefined;
    const old = try cloak.cloakOpaqueEpochV3(&old_storage, &key, "203.0.113.9", 7, .{ .suffix = "onyx" });
    var mask_storage: [256]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_storage, "N*!User?@{s}", .{old});
    var store = access.AccessStore.init(a);
    defer store.deinit();
    store.now_seconds = 100;
    try store.add("#Room", .deny, mask, "private-issuer", 30);
    const bytes = try codec.encode(a, &store);
    defer a.free(bytes);
    try testWrite(io, tmp.dir, "input", bytes);
    const target = RawTarget{ .key_hex = &target_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 };
    const witness = RawWitness{ .row = 0, .expected_mask = mask, .formula = .opaque_epoch_v3, .key_hex = &source_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null };
    var witness_rows = [_]RawWitness{witness};
    const full_doc = try std.json.Stringify.valueAlloc(a, Document{ .version = 1, .target = target, .witnesses = &witness_rows }, .{});
    defer a.free(full_doc);
    const empty_doc = try std.json.Stringify.valueAlloc(a, Document{ .version = 1, .target = target, .witnesses = &.{} }, .{});
    defer a.free(empty_doc);
    try testWrite(io, tmp.dir, "witness", full_doc);
    try testWrite(io, tmp.dir, "missing-witness", empty_doc);
    const report = try tmp.dir.createFile(io, "report", .{ .permissions = .fromMode(0o600) });
    defer report.close(io);
    try run(a, io, .{ .kind = .access, .input = input, .witness = witness_path, .checkpoint_output = output }, report);
    const artifact = try tmp.dir.readFileAlloc(io, "output", a, .limited(8192));
    defer a.free(artifact);
    var restored = try codec.decode(a, artifact);
    defer restored.deinit();
    var expected_storage: [253]u8 = undefined;
    const expected_host = try cloak.cloakOpaqueEpochV4(&expected_storage, &target_key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
    try std.testing.expectEqualStrings("N*!User?@", restored.entries.items[0].mask[0..9]);
    try std.testing.expectEqualStrings(expected_host, restored.entries.items[0].mask[9..]);
    try std.testing.expectEqualStrings("private-issuer", restored.entries.items[0].set_by);
    try std.testing.expectEqual(@as(?u64, 130), restored.entries.items[0].expires_at);
    try run(a, io, .{ .kind = .access, .input = input, .witness = missing_path, .checkpoint_output = unchanged_path }, report);
    const unchanged = try tmp.dir.readFileAlloc(io, "unchanged", a, .limited(8192));
    defer a.free(unchanged);
    try std.testing.expectEqualSlices(u8, bytes, unchanged);
    const summary = try tmp.dir.readFileAlloc(io, "report", a, .limited(8192));
    defer a.free(summary);
    try std.testing.expectEqualStrings("row=0 classification=verified_replacement\nrow=0 classification=missing_witness\n", summary);
}

test "cloak audit CLI: hex transport preserves arbitrary key octets and rejects malformed source or target keys" {
    const a = std.testing.allocator;
    var bytes: [cloak.key_len]u8 = @splat(0x6c);
    bytes[0] = 0x00;
    bytes[1] = 0x80;
    bytes[2] = 0xff;
    defer std.crypto.secureZero(u8, &bytes);
    var hex = std.fmt.bytesToHex(bytes, .lower);
    defer std.crypto.secureZero(u8, &hex);
    var key = try decodeKey(&hex);
    defer key.wipe();
    try std.testing.expectEqualSlices(u8, &bytes, &key.bytes);
    var bad_hex = hex;
    defer std.crypto.secureZero(u8, &bad_hex);
    bad_hex[63] = 'g';
    const short = hex[0..63];
    var long: [65]u8 = @splat('0');
    defer std.crypto.secureZero(u8, &long);
    for ([_][]const u8{ "", short, &long, &bad_hex }) |bad| try std.testing.expectError(error.InvalidWitness, decodeKey(bad));

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var rows = [_]RawWitness{.{ .row = 0, .expected_mask = "*!*@old.opq.onyx", .formula = .opaque_epoch_v3, .key_hex = &hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null }};
    var doc = Document{ .version = 1, .target = .{ .key_hex = &hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 }, .witnesses = &rows };
    for ([_][]const u8{ short, &bad_hex }) |bad| {
        doc.target.?.key_hex = bad;
        const text = try std.json.Stringify.valueAlloc(a, doc, .{});
        defer {
            std.crypto.secureZero(u8, text);
            a.free(text);
        }
        try std.testing.expectError(error.InvalidWitness, document(scratch, text, .access));
        doc.target.?.key_hex = &hex;
        rows[0].key_hex = bad;
        const source_text = try std.json.Stringify.valueAlloc(a, doc, .{});
        defer {
            std.crypto.secureZero(u8, source_text);
            a.free(source_text);
        }
        try std.testing.expectError(error.InvalidWitness, document(scratch, source_text, .access));
        rows[0].key_hex = &hex;
    }
}

test "cloak audit CLI: typed AKICK and WARD dispatch preserves private metadata and refuses cross-kind input" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const akick = @import("../daemon/svc_akick.zig");
    const warden = @import("../daemon/warden.zig");
    const akick_codec = @import("../daemon/helix/akick_checkpoint.zig");
    const ward_codec = @import("../daemon/helix/ward_checkpoint.zig");
    for ([_]Kind{ .akick, .ward }) |kind| {
        var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
        defer tmp.cleanup();
        try tmp.dir.setPermissions(io, .fromMode(0o700));
        const root = try tmp.dir.realPathFileAlloc(io, ".", a);
        defer a.free(root);
        const input = try std.fs.path.join(a, &.{ root, "input" });
        defer a.free(input);
        const witness_path = try std.fs.path.join(a, &.{ root, "witness" });
        defer a.free(witness_path);
        const output = try std.fs.path.join(a, &.{ root, "output" });
        defer a.free(output);
        const wrong_output = try std.fs.path.join(a, &.{ root, "wrong-kind-output" });
        defer a.free(wrong_output);
        var key = cloak.SecretKey.init(@splat(0x7a));
        defer key.wipe();
        var target_key = cloak.SecretKey.init(@splat(0x7b));
        defer target_key.wipe();
        var source_hex = std.fmt.bytesToHex(key.bytes, .lower);
        defer std.crypto.secureZero(u8, &source_hex);
        var target_hex = std.fmt.bytesToHex(target_key.bytes, .lower);
        defer std.crypto.secureZero(u8, &target_hex);
        var old_storage: [253]u8 = undefined;
        const old = try cloak.cloakOpaqueEpochV3(&old_storage, &key, "203.0.113.9", 7, .{ .suffix = "onyx" });
        var mask_storage: [512]u8 = undefined;
        const mask = if (kind == .akick) try std.fmt.bufPrint(&mask_storage, "n*!u@{s}", .{old}) else old;
        const bytes = if (kind == .akick) blk: {
            var store = akick.AkickStore.initCapacity(a, 7);
            defer store.deinit();
            try store.checkpointEnsureChannel("#empty");
            try store.add("#z", mask, "private-first", "PrivateIssuer", -42, 99);
            try store.add("#z", "account:operator*", "private-account", "OtherIssuer", 17, null);
            break :blk try akick_codec.encode(a, &store);
        } else blk: {
            var store = warden.Registry.init(a, .{ .max_wards = 9, .max_pattern = 256, .max_reason = 111, .max_setter = 63 });
            defer store.deinit();
            try store.add(.{ .match = .host, .pattern = mask, .scope = .mesh, .action = .quarantine, .reason = "private-first", .set_by = "PrivateIssuer", .created_ms = -42, .expires_ms = 99 });
            try store.add(.{ .match = .account, .pattern = "operator*", .scope = .node, .action = .require_auth, .reason = "private-account", .set_by = "OtherIssuer", .created_ms = 17, .expires_ms = 0 });
            break :blk try ward_codec.encode(a, &store);
        };
        defer a.free(bytes);
        try testWrite(io, tmp.dir, "input", bytes);
        var rows = [_]RawWitness{.{ .row = 0, .expected_mask = mask, .formula = .opaque_epoch_v3, .key_hex = &source_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null }};
        const text = try std.json.Stringify.valueAlloc(a, Document{ .version = 1, .target = .{ .key_hex = &target_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 }, .witnesses = &rows }, .{});
        defer {
            std.crypto.secureZero(u8, text);
            a.free(text);
        }
        try testWrite(io, tmp.dir, "witness", text);
        const report = try tmp.dir.createFile(io, "report", .{ .permissions = .fromMode(0o600) });
        defer report.close(io);
        const opts = try parse(&.{ "--kind", @tagName(kind), "--input", input, "--witness", witness_path, "--checkpoint-output", output });
        try std.testing.expectEqual(kind, opts.kind);
        try run(a, io, opts, report);
        const artifact = try tmp.dir.readFileAlloc(io, "output", a, .limited(8192));
        defer a.free(artifact);
        var expected_host_storage: [253]u8 = undefined;
        const expected_host = try cloak.cloakOpaqueEpochV4(&expected_host_storage, &target_key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
        if (kind == .akick) {
            var restored = try akick_codec.decode(a, artifact);
            defer restored.deinit();
            const entry = &restored.channels.getPtr("#z").?.entries.items[0];
            var expected_mask_storage: [512]u8 = undefined;
            const expected_mask = try std.fmt.bufPrint(&expected_mask_storage, "n*!u@{s}", .{expected_host});
            try std.testing.expectEqualStrings(expected_mask, entry.mask);
            const owned = try a.dupe(u8, mask);
            a.free(entry.mask);
            entry.mask = owned;
            entry.pattern = owned;
            const undone = try akick_codec.encode(a, &restored);
            defer a.free(undone);
            try std.testing.expectEqualSlices(u8, bytes, undone);
        } else {
            var restored = try ward_codec.decode(a, artifact);
            defer restored.deinit();
            const entry = &restored.wards.items[0];
            try std.testing.expectEqualStrings(expected_host, entry.pattern);
            const owned = try a.dupe(u8, mask);
            a.free(entry.pattern);
            entry.pattern = owned;
            const undone = try ward_codec.encode(a, &restored);
            defer a.free(undone);
            try std.testing.expectEqualSlices(u8, bytes, undone);
        }
        var wrong_opts = opts;
        wrong_opts.kind = if (kind == .akick) .ward else .akick;
        wrong_opts.checkpoint_output = wrong_output;
        if (run(a, io, wrong_opts, report)) |_| return error.CrossKindCheckpointAccepted else |_| {}
        if (tmp.dir.openFile(io, "wrong-kind-output", .{})) |file| {
            file.close(io);
            return error.CrossKindArtifactPublished;
        } else |err| if (err != error.FileNotFound) return err;
        const summary = try tmp.dir.readFileAlloc(io, "report", a, .limited(8192));
        defer a.free(summary);
        const expected_report = if (kind == .akick) "row=0 classification=verified_replacement\nrow=1 classification=account_rule\n" else "row=0 classification=verified_replacement\nrow=1 classification=non_host_facet\n";
        try std.testing.expectEqualStrings(expected_report, summary);
        const after = try tmp.dir.readFileAlloc(io, "input", a, .limited(8192));
        defer a.free(after);
        try std.testing.expectEqualSlices(u8, bytes, after);
    }
}

test "cloak audit CLI: World dispatch retains physical relations and emits only redacted rows" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    const Fixture = struct {
        const world_mod = @import("../daemon/world.zig");
        const codec = @import("../daemon/helix/world_checkpoint.zig");
        fn resolve(_: *anyopaque, id: world_mod.ClientId) ?codec.MemberIdentity {
            if (id.shard != 0 or id.gen != 7) return null;
            return switch (id.slot) {
                1 => .{ .join_key = 41, .nick = "Shared" },
                2 => .{ .join_key = 42, .nick = "InvitedOnly" },
                else => null,
            };
        }
        fn lookup(_: *anyopaque, key: u64) ?world_mod.ClientId {
            return switch (key) {
                41 => .{ .shard = 0, .slot = 1, .gen = 7 },
                42 => .{ .shard = 0, .slot = 2, .gen = 7 },
                else => null,
            };
        }
        fn make(alloc: std.mem.Allocator, mask: []const u8) ![]u8 {
            var world = world_mod.World.init(alloc);
            defer world.deinit();
            try world.initializeCheckpointImage(8, 100, 1_700_000_000);
            try world.restoreMember("#z", .{ .shard = 0, .slot = 1, .gen = 7 }, world_mod.MemberModes.fromModes(&.{.op}));
            try world.addInvite("#z", .{ .shard = 0, .slot = 2, .gen = 7 });
            _ = try world.addBan("#z", "$a:operator*", "GapSetter", -17);
            _ = try world.addBan("#z", mask, "PrivateIssuer", 19);
            var ctx: u8 = 0;
            world.lockRead();
            defer world.unlockRead();
            return codec.encodeLockedResolved(alloc, &world, .{ .context = &ctx, .resolve = resolve, .lookup = lookup });
        }
    };
    var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
    defer tmp.cleanup();
    try tmp.dir.setPermissions(io, .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);
    const input = try std.fs.path.join(a, &.{ root, "input" });
    defer a.free(input);
    const witness_path = try std.fs.path.join(a, &.{ root, "witness" });
    defer a.free(witness_path);
    const output = try std.fs.path.join(a, &.{ root, "output" });
    defer a.free(output);
    var source_key = cloak.SecretKey.init(@splat(0x31));
    defer source_key.wipe();
    var target_key = cloak.SecretKey.init(@splat(0x32));
    defer target_key.wipe();
    var source_hex = std.fmt.bytesToHex(source_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &source_hex);
    var target_hex = std.fmt.bytesToHex(target_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &target_hex);
    var old_host_buf: [253]u8 = undefined;
    var new_host_buf: [253]u8 = undefined;
    const old_host = try cloak.cloakOpaqueEpochV3(&old_host_buf, &source_key, "203.0.113.9", 7, .{ .suffix = "onyx" });
    const new_host = try cloak.cloakOpaqueEpochV4(&new_host_buf, &target_key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
    const old_mask = try std.fmt.allocPrint(a, "n*!u@{s}", .{old_host});
    defer a.free(old_mask);
    const new_mask = try std.fmt.allocPrint(a, "n*!u@{s}", .{new_host});
    defer a.free(new_mask);
    const bytes = try Fixture.make(a, old_mask);
    defer a.free(bytes);
    const expected = try Fixture.make(a, new_mask);
    defer a.free(expected);
    try testWrite(io, tmp.dir, "input", bytes);
    var rows = [_]RawWitness{.{ .row = 1, .expected_mask = old_mask, .formula = .opaque_epoch_v3, .key_hex = &source_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null }};
    const text = try std.json.Stringify.valueAlloc(a, Document{ .version = 1, .target = .{ .key_hex = &target_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 }, .witnesses = &rows }, .{});
    defer {
        std.crypto.secureZero(u8, text);
        a.free(text);
    }
    try testWrite(io, tmp.dir, "witness", text);
    const report = try tmp.dir.createFile(io, "report", .{ .permissions = .fromMode(0o600) });
    defer report.close(io);
    const opts = try parse(&.{ "--kind", "world", "--input", input, "--witness", witness_path, "--checkpoint-output", output });
    try std.testing.expectEqual(Kind.world, opts.kind);
    try run(a, io, opts, report);
    const artifact = try tmp.dir.readFileAlloc(io, "output", a, .limited(8192));
    defer a.free(artifact);
    try std.testing.expectEqualSlices(u8, expected, artifact);
    const summary = try tmp.dir.readFileAlloc(io, "report", a, .limited(8192));
    defer a.free(summary);
    try std.testing.expectEqualStrings("row=0 classification=metadata_gap\nrow=1 classification=verified_replacement\n", summary);
    const after = try tmp.dir.readFileAlloc(io, "input", a, .limited(8192));
    defer a.free(after);
    try std.testing.expectEqualSlices(u8, bytes, after);
}

test "cloak audit CLI: raw Services records preserve bytes and surface required Store key migration" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const a = std.testing.allocator;
    var source_key = cloak.SecretKey.init(@splat(0x31));
    defer source_key.wipe();
    var target_key = cloak.SecretKey.init(@splat(0x32));
    defer target_key.wipe();
    var source_hex = std.fmt.bytesToHex(source_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &source_hex);
    var target_hex = std.fmt.bytesToHex(target_key.bytes, .lower);
    defer std.crypto.secureZero(u8, &target_hex);
    var old_host_buf: [253]u8 = undefined;
    var new_host_buf: [253]u8 = undefined;
    const old_host = try cloak.cloakOpaqueEpochV3(&old_host_buf, &source_key, "203.0.113.9", 7, .{ .suffix = "onyx" });
    const new_host = try cloak.cloakOpaqueEpochV4(&new_host_buf, &target_key, "203.0.113.9", 90, 1_209_600, .{ .suffix = "onyx" });
    const old_mask = try std.fmt.allocPrint(a, "n*!u@{s}", .{old_host});
    defer a.free(old_mask);
    const new_mask = try std.fmt.allocPrint(a, "n*!u@{s}", .{new_host});
    defer a.free(new_mask);
    inline for ([_]Kind{ .@"akick-record", .@"ward-record", .@"saccess-record" }) |kind| {
        const changes = kind == .@"ward-record";
        var tmp = std.testing.tmpDir(.{ .iterate = true, .follow_symlinks = false });
        defer tmp.cleanup();
        try tmp.dir.setPermissions(io, .fromMode(0o700));
        const root = try tmp.dir.realPathFileAlloc(io, ".", a);
        defer a.free(root);
        const input = try std.fs.path.join(a, &.{ root, "input" });
        defer a.free(input);
        const witness_path = try std.fs.path.join(a, &.{ root, "witness" });
        defer a.free(witness_path);
        const output = try std.fs.path.join(a, &.{ root, "output" });
        defer a.free(output);
        const wrong_output = try std.fs.path.join(a, &.{ root, "wrong-kind-output" });
        defer a.free(wrong_output);
        const format = switch (kind) {
            .@"akick-record" => "K1|#Room|{s}|00112233445566778899aabbccddeeff|PrivateIssuer|private reason",
            .@"ward-record" => "W1|mask|{s}|mesh|quarantine|-042|0100|PrivateIssuer|private reason",
            .@"saccess-record" => "S1|DENY|{s}|00030|private reason",
            else => unreachable,
        };
        const bytes = try std.fmt.allocPrint(a, format, .{old_mask});
        defer a.free(bytes);
        const expected = try std.fmt.allocPrint(a, format, .{if (changes) new_mask else old_mask});
        defer a.free(expected);
        try testWrite(io, tmp.dir, "input", bytes);
        var rows = [_]RawWitness{.{ .row = 0, .expected_mask = old_mask, .formula = .opaque_epoch_v3, .key_hex = &source_hex, .address = "203.0.113.9", .suffix = "onyx", .epoch = 7, .cadence = null }};
        const text = try std.json.Stringify.valueAlloc(a, Document{
            .version = 1,
            .target = if (changes) .{ .key_hex = &target_hex, .suffix = "onyx", .epoch = 90, .cadence = 1_209_600 } else null,
            .witnesses = if (changes) &rows else &.{},
        }, .{});
        defer {
            std.crypto.secureZero(u8, text);
            a.free(text);
        }
        try testWrite(io, tmp.dir, "witness", text);
        const report = try tmp.dir.createFile(io, "report", .{ .permissions = .fromMode(0o600) });
        defer report.close(io);
        const opts = try parse(&.{ "--kind", @tagName(kind), "--input", input, "--witness", witness_path, "--checkpoint-output", output });
        try std.testing.expectEqual(kind, opts.kind);
        try run(a, io, opts, report);
        const artifact = try tmp.dir.readFileAlloc(io, "output", a, .limited(2048));
        defer a.free(artifact);
        try std.testing.expectEqualSlices(u8, expected, artifact);
        const summary = try tmp.dir.readFileAlloc(io, "report", a, .limited(2048));
        defer a.free(summary);
        try std.testing.expectEqualStrings(if (changes) "row=0 classification=verified_replacement key_migration=required order_proof=missing\n" else "row=0 classification=metadata_gap key_migration=none order_proof=not_needed\n", summary);
        var wrong_opts = opts;
        wrong_opts.kind = if (kind == .@"akick-record") .@"saccess-record" else .@"akick-record";
        wrong_opts.checkpoint_output = wrong_output;
        if (run(a, io, wrong_opts, report)) |_| return error.CrossKindRecordAccepted else |_| {}
        if (tmp.dir.openFile(io, "wrong-kind-output", .{})) |file| {
            file.close(io);
            return error.CrossKindArtifactPublished;
        } else |err| if (err != error.FileNotFound) return err;
        const after = try tmp.dir.readFileAlloc(io, "input", a, .limited(2048));
        defer a.free(after);
        try std.testing.expectEqualSlices(u8, bytes, after);
    }
}
