// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compile explicit service configuration data to canonical NSCF. This grants
//! no runtime authority; the root helper separately validates the protected file
//! and observes the actual su/daemon identity and execution context.
const std = @import("std");
const helper = @import("daemon/native_service_helper.zig");
const service = @import("daemon/native_service.zig");

const Rule = struct { min_soft: u64, max_soft: u64, max_hard: u64 };
const Limits = struct {
    cputime: Rule,
    filesize: Rule,
    datasize: Rule,
    stacksize: Rule,
    coredumpsize: Rule,
    memoryuse: Rule,
    memorylocked: Rule,
    maxproc: Rule,
    openfiles: Rule,
};
const Input = struct {
    helper: []const u8,
    executable: []const u8,
    config: []const u8,
    cwd: []const u8,
    user: []const u8,
    class: []const u8,
    uid: u32,
    gid: u32,
    groups: []const u32,
    rtable: u32,
    limits: Limits,
};

fn compile(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(Input, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    const input = parsed.value;
    if (input.groups.len > helper.group_max) return error.InvalidPolicy;
    var spec: helper.ServiceSpec = .{
        .helper = try service.Path.init(input.helper),
        .executable = try service.Path.init(input.executable),
        .config = try service.Path.init(input.config),
        .cwd = try service.Path.init(input.cwd),
        .user = try helper.Name.init(input.user),
        .class = try helper.Name.init(input.class),
        .uid = input.uid,
        .gid = input.gid,
        .group_count = @intCast(input.groups.len),
        .rtable = input.rtable,
    };
    @memcpy(spec.groups[0..input.groups.len], input.groups);
    inline for (@typeInfo(Limits).@"struct".field_names, 0..) |name, index| {
        const rule = @field(input.limits, name);
        spec.limits[index] = .{ .min_soft = rule.min_soft, .max_soft = rule.max_soft, .max_hard = rule.max_hard };
    }
    try spec.validate();
    return helper.encodeSpec(allocator, spec);
}

fn publish(io: std.Io, output: []const u8, bytes: []const u8) !void {
    _ = try service.Path.init(output);
    var file = try std.Io.Dir.cwd().createFileAtomic(io, output, .{ .permissions = .fromMode(0o600) });
    defer file.deinit(io);
    try file.file.writeStreamingAll(io, bytes);
    try file.file.setPermissions(io, .fromMode(0o600));
    try file.file.sync(io);
    // Complete bytes become visible together. Existing files and symlinks are
    // refused, including a concurrent creator; no policy is overwritten.
    try file.link(io);
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const input = args.next() orelse return error.InvalidArguments;
    const output = args.next() orelse return error.InvalidArguments;
    if (args.next() != null) return error.InvalidArguments;
    const json = try std.Io.Dir.cwd().readFileAlloc(init.io, input, init.gpa, .limited(16 * 1024));
    defer init.gpa.free(json);
    const bytes = try compile(init.gpa, json);
    defer init.gpa.free(bytes);
    try publish(init.io, output, bytes);
}

const fixture =
    \\{"helper":"/usr/local/libexec/onyx-server-helper","executable":"/usr/local/bin/onyx-server",
    \\"config":"/etc/onyx-server/onyx-server.toml","cwd":"/var/onyx-server",
    \\"user":"_onyx","class":"onyx","uid":1001,"gid":1001,"groups":[1001,1002],"rtable":0,
    \\"limits":{
    \\"cputime":{"min_soft":60,"max_soft":60,"max_hard":120},
    \\"filesize":{"min_soft":8388608,"max_soft":8388608,"max_hard":16777216},
    \\"datasize":{"min_soft":134217728,"max_soft":134217728,"max_hard":268435456},
    \\"stacksize":{"min_soft":8388608,"max_soft":8388608,"max_hard":8388608},
    \\"coredumpsize":{"min_soft":0,"max_soft":0,"max_hard":0},
    \\"memoryuse":{"min_soft":67108864,"max_soft":67108864,"max_hard":134217728},
    \\"memorylocked":{"min_soft":65536,"max_soft":65536,"max_hard":65536},
    \\"maxproc":{"min_soft":16,"max_soft":16,"max_hard":32},
    \\"openfiles":{"min_soft":64,"max_soft":128,"max_hard":128}}}
;

fn allocationControl(allocator: std.mem.Allocator) !void {
    const bytes = try compile(allocator, fixture);
    defer allocator.free(bytes);
    const spec = try helper.decodeSpec(bytes);
    try std.testing.expectEqual(@as(u8, 2), spec.group_count);
    try std.testing.expectEqual(@as(u64, 128), spec.limits[8].max_hard);
    const canonical = try helper.encodeSpec(allocator, spec);
    defer allocator.free(canonical);
    try std.testing.expectEqualSlices(u8, bytes, canonical);
}

test "native service policy compiler strict complete canonical configuration and OOM" {
    try allocationControl(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationControl, .{});
    try std.testing.expectError(error.MissingField, compile(std.testing.allocator, "{}"));
    const duplicate = try std.fmt.allocPrint(std.testing.allocator, "{s},\"uid\":1002}}", .{fixture[0 .. fixture.len - 1]});
    defer std.testing.allocator.free(duplicate);
    try std.testing.expectError(error.DuplicateField, compile(std.testing.allocator, duplicate));
    const unknown = try std.fmt.allocPrint(std.testing.allocator, "{s},\"ignored\":true}}", .{fixture[0 .. fixture.len - 1]});
    defer std.testing.allocator.free(unknown);
    try std.testing.expectError(error.UnknownField, compile(std.testing.allocator, unknown));
    try std.testing.expectError(error.MissingField, std.json.parseFromSlice(Rule, std.testing.allocator, "{\"min_soft\":0,\"max_soft\":1}", .{}));
}

test "native service policy compiler publishes complete bytes without replacing existing policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const output = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path, "policy.nscf" });
    defer std.testing.allocator.free(output);
    const bytes = try compile(std.testing.allocator, fixture);
    defer std.testing.allocator.free(bytes);
    try publish(std.testing.io, output, bytes);
    try std.testing.expectError(error.PathAlreadyExists, publish(std.testing.io, output, "replacement"));
    const actual = try tmp.dir.readFileAlloc(std.testing.io, "policy.nscf", std.testing.allocator, .limited(service.max_packet));
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualSlices(u8, bytes, actual);
    try std.testing.expectError(error.InvalidIdentity, publish(std.testing.io, "relative.nscf", bytes));
}
