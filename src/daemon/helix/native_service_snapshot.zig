// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict N1 service state, not a capsule activation. Decoding establishes data
//! shape only; authenticated descriptor transfer and real lifecycle are separate.
const std = @import("std");
const service = @import("../native_service.zig");
const managed = @import("../native_service_helper.zig");
const capsule = @import("capsule.zig");
const manifest = @import("native_manifest.zig");
pub const version: u16 = 2;
pub const Error = service.Error;
pub const HandoffError = Error || manifest.Error || error{ MissingNativeService, DuplicateNativeService, InvalidNativeService };

/// Borrow the bytes of the original Controller-owned one-shot Handoff plan.
/// The plan must remain alive until encoding completes. This stage neither
/// commits the predecessor nor certifies an executed successor's readiness.
pub fn capsuleFromHandoff(handoff: service.Handoff, fields: *[1]capsule.Field) HandoffError!capsule.Capsule {
    try handoff.validate();
    const bytes = try handoff.bytes();
    const state = try decode(bytes);
    if (state.phase != .quiesced or state.last == null or state.last.?.request.verb != .upgrade or state.last.?.result != .accepted) return error.InvalidNativeService;
    fields.* = .{.{ .ordinal = 1, .bytes = bytes }};
    return capsule.make(.native_service, fields);
}

pub fn decodeHandoffCapsule(item: capsule.Capsule, actual_upgrade_id: service.Id) HandoffError!service.State {
    if (!std.meta.eql(item.header, capsule.Header.init(.native_service)) or item.fields.len != 1 or item.fields[0].ordinal != 1) return error.InvalidNativeService;
    const state = try decode(item.fields[0].bytes);
    if (state.phase != .quiesced or state.last == null or state.last.?.request.verb != .upgrade or state.last.?.result != .accepted or !std.mem.eql(u8, &state.upgrade_id, &actual_upgrade_id)) return error.InvalidNativeService;
    return state;
}

/// Authenticated arena/descriptor join before canonical FD normalization.
/// Unmanaged handoffs omit both the family and complete pair. A managed carry
/// requires exactly one snapshot and the original named listener/lease inode
/// identities. Transport generation is not the service generation domain.
/// This grants close custody only; an inert Runtime/Controller source join and
/// executed-context observation are still required before lifecycle activation.
pub fn validateHandoff(capsules: []const capsule.Capsule, rows: []const manifest.Row, actual_upgrade_id: service.Id) HandoffError!?service.State {
    try manifest.validateServiceDescriptors(rows);
    var listener: ?manifest.Row = null;
    var lease: ?manifest.Row = null;
    for (rows) |row| switch (row.role) {
        .service_listener => listener = row,
        .service_lifetime_lease => lease = row,
        else => {},
    };
    var found: ?capsule.Capsule = null;
    for (capsules) |item| {
        if (item.header.kind != .native_service) continue;
        if (found != null) return error.DuplicateNativeService;
        found = item;
    }
    if (listener == null) {
        if (found != null) return error.InvalidNativeService;
        return null;
    }
    const state = try decodeHandoffCapsule(found orelse return error.MissingNativeService, actual_upgrade_id);
    if (listener.?.canonical != state.context.listener_canonical or lease.?.canonical != state.context.lease_canonical) return error.InvalidNativeService;
    try service.validateDescriptors(listener.?.fd, lease.?.fd, &state.context);
    return state;
}

pub fn encode(allocator: std.mem.Allocator, state: *const service.State) Error![]u8 {
    try state.validate();
    var buffer: [service.max_packet]u8 = undefined;
    var writer: Writer = .{ .buffer = &buffer };
    try writer.bytes("NSST");
    try writer.int(u16, version);
    try writer.int(u16, 0);
    try writer.bytes(&service.service_identity);
    try writer.bytes(&state.context.incarnation);
    try writer.int(u64, state.generation);
    try writer.int(u8, @intFromEnum(state.phase));
    try writer.bytes(&state.upgrade_id);
    const context = &state.context;
    try writer.path(&context.executable);
    try writer.path(&context.config);
    try writer.path(&context.cwd);
    try writer.path(&context.endpoint);
    try writer.int(u32, context.uid);
    try writer.int(u32, context.gid);
    try writer.int(u32, context.rtable);
    try writer.int(u32, context.policy_version);
    try writer.bytes(&context.config_commitment);
    for (context.listener_ports) |port| try writer.int(u16, port);
    try writer.int(i32, context.listener_canonical);
    try writer.int(i32, context.lease_canonical);
    for ([_]service.FileIdentity{ context.listener_identity, context.endpoint_identity, context.lease_identity }) |id| {
        try writer.int(u64, id.device);
        try writer.int(u64, id.inode);
    }
    // Canonical joined policy: paths/IDs already occur above and are joined by
    // Context.validate. Reconstructing those exact fields keeps every allowed
    // maximum-length policy below the existing 4096-byte transport budget.
    try writer.path(&context.managed_spec.helper);
    try writer.name(&context.managed_spec.user);
    try writer.name(&context.managed_spec.class);
    try writer.int(u8, context.managed_spec.group_count);
    for (context.managed_spec.groups[0..context.managed_spec.group_count]) |group| try writer.int(u32, group);
    for (context.managed_spec.limits) |rule| {
        try writer.int(u64, rule.min_soft);
        try writer.int(u64, rule.max_soft);
        try writer.int(u64, rule.max_hard);
    }
    const observation = &context.managed_observation;
    for (observation.uid) |id| try writer.int(u32, id);
    for (observation.gid) |id| try writer.int(u32, id);
    try writer.int(u8, observation.group_count);
    for (observation.groups[0..observation.group_count]) |group| try writer.int(u32, group);
    try writer.int(u32, observation.rtable);
    try writer.int(u64, observation.cwd.device);
    try writer.int(u64, observation.cwd.inode);
    for (observation.limits) |limit| {
        try writer.int(u64, limit.soft);
        try writer.int(u64, limit.hard);
    }
    try writer.int(u8, if (state.last != null) 1 else 0);
    if (state.last) |last| {
        const request = try last.request.encode();
        try writer.bytes(&request);
        try writer.int(u8, @intFromEnum(last.result));
    }
    return allocator.dupe(u8, buffer[0..writer.offset]);
}
pub fn decode(bytes: []const u8) Error!service.State {
    if (bytes.len > service.max_packet) return error.TooLarge;
    var reader: Reader = .{ .buffer = bytes };
    if (!std.mem.eql(u8, try reader.bytes(4), "NSST") or try reader.int(u16) != version or try reader.int(u16) != 0 or !std.mem.eql(u8, try reader.bytes(16), &service.service_identity)) return error.InvalidWire;
    const incarnation = (try reader.bytes(16))[0..16].*;
    const generation = try reader.int(u64);
    const phase = std.enums.fromInt(service.Phase, try reader.int(u8)) orelse return error.InvalidWire;
    const upgrade_id = (try reader.bytes(16))[0..16].*;
    var context: service.Context = undefined;
    context.incarnation = incarnation;
    context.executable = try reader.path();
    context.config = try reader.path();
    context.cwd = try reader.path();
    context.endpoint = try reader.path();
    context.uid = try reader.int(u32);
    context.gid = try reader.int(u32);
    context.rtable = try reader.int(u32);
    context.policy_version = try reader.int(u32);
    context.config_commitment = (try reader.bytes(32))[0..32].*;
    for (&context.listener_ports) |*port| port.* = try reader.int(u16);
    context.listener_canonical = try reader.int(i32);
    context.lease_canonical = try reader.int(i32);
    context.listener_identity = .{ .device = try reader.int(u64), .inode = try reader.int(u64) };
    context.endpoint_identity = .{ .device = try reader.int(u64), .inode = try reader.int(u64) };
    context.lease_identity = .{ .device = try reader.int(u64), .inode = try reader.int(u64) };
    context.managed_spec = .{
        .helper = try reader.path(),
        .executable = context.executable,
        .config = context.config,
        .cwd = context.cwd,
        .user = try reader.name(),
        .class = try reader.name(),
        .uid = context.uid,
        .gid = context.gid,
        .rtable = context.rtable,
        .groups = @splat(0),
        .group_count = try reader.int(u8),
        .limits = undefined,
    };
    if (context.managed_spec.group_count > managed.group_max) return error.InvalidWire;
    for (context.managed_spec.groups[0..context.managed_spec.group_count]) |*group| group.* = try reader.int(u32);
    for (&context.managed_spec.limits) |*rule| rule.* = .{ .min_soft = try reader.int(u64), .max_soft = try reader.int(u64), .max_hard = try reader.int(u64) };
    context.managed_observation = .{
        .uid = undefined,
        .gid = undefined,
        .groups = @splat(0),
        .group_count = 0,
        .rtable = 0,
        .cwd = undefined,
        .limits = undefined,
    };
    for (&context.managed_observation.uid) |*id| id.* = try reader.int(u32);
    for (&context.managed_observation.gid) |*id| id.* = try reader.int(u32);
    context.managed_observation.group_count = try reader.int(u8);
    if (context.managed_observation.group_count > managed.group_max) return error.InvalidWire;
    for (context.managed_observation.groups[0..context.managed_observation.group_count]) |*group| group.* = try reader.int(u32);
    context.managed_observation.rtable = try reader.int(u32);
    context.managed_observation.cwd = .{ .device = try reader.int(u64), .inode = try reader.int(u64) };
    for (&context.managed_observation.limits) |*limit| limit.* = .{ .soft = try reader.int(u64), .hard = try reader.int(u64) };
    const present = try reader.int(u8);
    if (present > 1) return error.InvalidWire;
    const last: ?service.Operation = if (present == 0) null else .{ .request = try service.Request.decode(try reader.bytes(service.Request.wire_len)), .result = std.enums.fromInt(service.Result, try reader.int(u8)) orelse return error.InvalidWire };
    if (reader.offset != bytes.len) return error.InvalidWire;
    const state: service.State = .{ .context = context, .generation = generation, .phase = phase, .upgrade_id = upgrade_id, .last = last };
    try state.validate();
    return state;
}
const Writer = struct {
    buffer: []u8,
    offset: usize = 0,
    fn bytes(self: *Writer, value: []const u8) Error!void {
        if (value.len > self.buffer.len - self.offset) return error.TooLarge;
        @memcpy(self.buffer[self.offset..][0..value.len], value);
        self.offset += value.len;
    }
    fn int(self: *Writer, comptime T: type, value: T) Error!void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        try self.bytes(&encoded);
    }
    fn path(self: *Writer, value: *const service.Path) Error!void {
        try self.int(u16, value.len);
        try self.bytes(value.bytes());
    }
    fn name(self: *Writer, value: *const managed.Name) Error!void {
        try self.int(u8, value.len);
        try self.bytes(value.bytes());
    }
};
const Reader = struct {
    buffer: []const u8,
    offset: usize = 0,
    fn bytes(self: *Reader, length: usize) Error![]const u8 {
        if (length > self.buffer.len - self.offset) return error.InvalidWire;
        const slice = self.buffer[self.offset..][0..length];
        self.offset += length;
        return slice;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        const encoded = try self.bytes(@sizeOf(T));
        return std.mem.readInt(T, encoded[0..@sizeOf(T)], .little);
    }
    fn path(self: *Reader) Error!service.Path {
        return service.Path.init(try self.bytes(try self.int(u16)));
    }
    fn name(self: *Reader) Error!managed.Name {
        return managed.Name.init(try self.bytes(try self.int(u8))) catch return error.InvalidWire;
    }
};

test "native service N1 snapshot exact owned context includes literal paths and distinct inode domains" {
    const context = try service.Fixture.context();
    const state: service.State = .{ .context = context };
    const bytes = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualDeep(state, try decode(bytes));
    const restored = try decode(bytes);
    try std.testing.expectEqualStrings("/etc/onyx-server/a config;$b.toml", restored.context.config.bytes());
    try std.testing.expect(!std.meta.eql(restored.context.listener_identity, restored.context.endpoint_identity));
    const again = try encode(std.testing.allocator, &restored);
    defer std.testing.allocator.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

fn prepareTestHandoff(owner: *service.Controller, id: service.Id) !service.Handoff {
    service.Fixture.ready(owner);
    const context = owner.inspect().context;
    _ = try service.Fixture.admitRequest(owner, .{ .verb = .upgrade, .incarnation = context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) });
    return owner.prepareHandoff(std.testing.allocator, id);
}

test "native Helix service carry: original Controller plan exact family refuses wrong envelope header and lifecycle" {
    // getsockname inspection has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const owner = try service.Controller.initStarting(std.testing.allocator, try service.Fixture.context());
    defer owner.deinit();
    const id: service.Id = @splat(12);
    const plan = try prepareTestHandoff(owner, id);
    defer plan.deinit();
    var fields: [1]capsule.Field = undefined;
    const item = try capsuleFromHandoff(plan, &fields);
    try std.testing.expectEqual(capsule.CapsuleKind.native_service, item.header.kind);
    try std.testing.expectEqual(@as(u16, version), item.header.version);
    try std.testing.expectEqual((try plan.bytes()).ptr, item.fields[0].bytes.ptr);
    const state = try decodeHandoffCapsule(item, id);
    try std.testing.expectEqual(service.Phase.quiesced, state.phase);
    try std.testing.expectEqual(service.Phase.current, owner.reply().phase);
    try std.testing.expectError(error.InvalidNativeService, decodeHandoffCapsule(item, @splat(13)));
    var wrong = item;
    wrong.header.max_supported += 1;
    try std.testing.expectError(error.InvalidNativeService, decodeHandoffCapsule(wrong, id));
    wrong = item;
    wrong.header.version = 1;
    try std.testing.expectError(error.InvalidNativeService, decodeHandoffCapsule(wrong, id));
    var wrong_fields = fields;
    wrong_fields[0].ordinal = 2;
    wrong = item;
    wrong.fields = &wrong_fields;
    try std.testing.expectError(error.InvalidNativeService, decodeHandoffCapsule(wrong, id));
    try std.testing.expect((try validateHandoff(&.{}, &.{}, id)) == null);
    try std.testing.expectError(error.InvalidNativeService, validateHandoff(&.{item}, &.{}, id));
    try plan.commit();
    try std.testing.expectError(error.StateChanged, capsuleFromHandoff(plan, &fields));
}

test "native Helix service carry: protected original Context requires exact mandatory family and pair" {
    // getsockname inspection has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var fixture = try service.Fixture.root();
    defer service.Fixture.closeRoot(&fixture);
    const source = &fixture.bootstrap;
    const owner = try service.Controller.initStarting(std.testing.allocator, source.state.context);
    defer owner.deinit();
    const id: service.Id = @splat(14);
    const plan = try prepareTestHandoff(owner, id);
    defer plan.deinit();
    var fields: [1]capsule.Field = undefined;
    const item = try capsuleFromHandoff(plan, &fields);
    const rows = [_]manifest.Row{
        .{ .canonical = source.listener, .fd = source.listener, .role = .service_listener, .shard = 0, .family = 0 },
        .{ .canonical = source.lease.fd, .fd = source.lease.fd, .role = .service_lifetime_lease, .shard = 0, .family = 0 },
    };
    const before = owner.inspect();
    const restored = (try validateHandoff(&.{item}, &rows, id)).?;
    try std.testing.expectEqualDeep(source.state.context, restored.context);
    try std.testing.expectEqualDeep(before, owner.inspect());
    try std.testing.expectError(error.MissingNativeService, validateHandoff(&.{}, &rows, id));
    try std.testing.expectError(error.DuplicateNativeService, validateHandoff(&.{ item, item }, &rows, id));
    try std.testing.expectError(error.InvalidManifest, validateHandoff(&.{item}, rows[0..1], id));
    var foreign_rows = rows;
    foreign_rows[1].canonical = @max(rows[0].canonical, rows[1].canonical) + 10;
    try std.testing.expectError(error.InvalidNativeService, validateHandoff(&.{item}, &foreign_rows, id));
    var foreign_state = restored;
    foreign_state.context.listener_identity.inode ^= 1;
    const foreign_bytes = try encode(std.testing.allocator, &foreign_state);
    defer std.testing.allocator.free(foreign_bytes);
    var foreign_fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = foreign_bytes }};
    const foreign_cap = capsule.make(.native_service, &foreign_fields);
    try std.testing.expectError(error.BadDescriptor, validateHandoff(&.{foreign_cap}, &rows, id));
    try service.validateDescriptors(source.listener, source.lease.fd, &source.state.context);
    try std.testing.expectEqualDeep(before, owner.inspect());
}
test "native service N1 snapshot every prefix and extra bytes refuse whole restore" {
    const state: service.State = .{ .context = try service.Fixture.context() };
    const bytes = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(bytes);
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidWire, decode(bytes[0..len]));
    const extra = try std.mem.concat(std.testing.allocator, u8, &.{ bytes, "x" });
    defer std.testing.allocator.free(extra);
    try std.testing.expectError(error.InvalidWire, decode(extra));
    const before = state;
    var corrupt = try std.testing.allocator.dupe(u8, bytes);
    defer std.testing.allocator.free(corrupt);
    corrupt[6] = 1;
    try std.testing.expectError(error.InvalidWire, decode(corrupt));
    @memcpy(corrupt, bytes);
    corrupt[8] ^= 1;
    try std.testing.expectError(error.InvalidWire, decode(corrupt));
    @memcpy(corrupt, bytes);
    corrupt[48] = 0; // Invalid phase, not a default.
    try std.testing.expectError(error.InvalidWire, decode(corrupt));
    try std.testing.expectEqualDeep(before, state);
}
test "native service N1 snapshot pending operation survives quiescence without candidate readiness" {
    const owner = try service.Controller.initStarting(std.testing.allocator, try service.Fixture.context());
    defer owner.deinit();
    service.Fixture.ready(owner);
    const context = owner.inspect().context;
    const request: service.Request = .{ .verb = .upgrade, .incarnation = context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) };
    _ = try service.Fixture.admitRequest(owner, request);
    const plan = try owner.prepareHandoff(std.testing.allocator, @splat(5));
    defer plan.deinit();
    const decoded = try decode(try plan.bytes());
    try std.testing.expectEqual(service.Phase.quiesced, decoded.phase);
    try std.testing.expectEqualDeep(request, decoded.last.?.request);
    try std.testing.expectEqual(service.Result.accepted, decoded.last.?.result);
    try std.testing.expectEqualSlices(u8, &(@as(service.Id, @splat(5))), &decoded.upgrade_id);
    try std.testing.expectEqual(service.Phase.current, owner.reply().phase);
    try plan.commit();
    try std.testing.expectEqual(service.Phase.quiesced, owner.reply().phase);
}
test "native service N1 snapshot rejects contradictory lifecycle operation and canonical FD aliases" {
    var state: service.State = .{ .context = try service.Fixture.context() };
    state.phase = .quiesced;
    try std.testing.expectError(error.InvalidState, encode(std.testing.allocator, &state));
    state.phase = .current;
    state.context.lease_canonical = state.context.listener_canonical;
    try std.testing.expectError(error.BadDescriptor, encode(std.testing.allocator, &state));
    state = .{ .context = try service.Fixture.context(), .phase = .current };
    state.last = .{ .request = .{ .verb = .upgrade, .incarnation = @splat(9), .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) }, .result = .accepted };
    try std.testing.expectError(error.InvalidState, encode(std.testing.allocator, &state));
    state.last.?.request.incarnation = state.context.incarnation;
    state.last.?.result = .succeeded;
    try std.testing.expectError(error.InvalidState, encode(std.testing.allocator, &state));
}
fn snapshotOom(allocator: std.mem.Allocator) !void {
    const state: service.State = .{ .context = try service.Fixture.context() };
    const before = state;
    const bytes = encode(allocator, &state) catch |err| {
        try std.testing.expectEqualDeep(before, state);
        const retry = try encode(std.testing.allocator, &state);
        defer std.testing.allocator.free(retry);
        try std.testing.expectEqualDeep(state, try decode(retry));
        return err;
    };
    defer allocator.free(bytes);
    try std.testing.expectEqualDeep(state, try decode(bytes));
}
test "native service N1 snapshot allocation sweep retains original and exact retry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, snapshotOom, .{});
}

test "native service policy2 snapshot preserves complete selected policy and observed post-NOFILE context" {
    var state: service.State = .{ .context = try service.Fixture.context() };
    for (&state.context.managed_spec.limits, &state.context.managed_observation.limits, 0..) |*rule, *limit, i| {
        rule.* = .{ .min_soft = @intCast(20 + i), .max_soft = @intCast(500 + i), .max_hard = @intCast(600 + i) };
        limit.* = .{ .soft = @intCast(100 + i), .hard = @intCast(200 + i) };
    }
    state.context.managed_observation.limits[8].soft = state.context.managed_observation.limits[8].hard;
    const wire = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(wire);
    const restored = try decode(wire);
    try std.testing.expectEqualDeep(state.context.managed_spec, restored.context.managed_spec);
    try std.testing.expectEqualDeep(state.context.managed_observation, restored.context.managed_observation);
    try std.testing.expectEqualDeep(state, restored);
    const again = try encode(std.testing.allocator, &restored);
    defer std.testing.allocator.free(again);
    try std.testing.expectEqualSlices(u8, wire, again);
    var old_version = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(old_version);
    std.mem.writeInt(u16, old_version[4..6], 1, .little);
    try std.testing.expectError(error.InvalidWire, decode(old_version));
}

test "native service policy2 maximum allowed paths names groups and operation fit existing packet bound" {
    var state: service.State = .{ .context = try service.Fixture.context(), .phase = .current };
    var text: [service.max_path]u8 = @splat('a');
    text[0] = '/';
    const path = try service.Path.init(&text);
    state.context.executable = path;
    state.context.config = path;
    state.context.cwd = path;
    state.context.managed_spec.executable = path;
    state.context.managed_spec.config = path;
    state.context.managed_spec.cwd = path;
    state.context.managed_spec.helper = path;
    const suffix = "/" ++ service.endpoint_name;
    @memcpy(text[text.len - suffix.len ..], suffix);
    state.context.endpoint = try service.Path.init(&text);
    const name: [63]u8 = @splat('x');
    state.context.managed_spec.user = try managed.Name.init(&name);
    state.context.managed_spec.class = try managed.Name.init(&name);
    state.context.managed_spec.group_count = managed.group_max;
    state.context.managed_observation.group_count = managed.group_max;
    for (&state.context.managed_spec.groups, &state.context.managed_observation.groups, 0..) |*expected, *observed, i| {
        expected.* = @intCast(1000 + i);
        observed.* = expected.*;
    }
    state.last = .{ .request = .{ .verb = .upgrade, .incarnation = state.context.incarnation, .generation = 0, .serial = 1, .nonce = @splat(3), .candidate_config = @splat(4) }, .result = .accepted };
    const wire = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(wire);
    try std.testing.expectEqual(@as(usize, 3509), wire.len);
    try std.testing.expect(wire.len <= service.max_packet);
    try std.testing.expectEqualDeep(state, try decode(wire));
    // Every missing byte refuses; no absent managed policy receives defaults.
    for (0..wire.len) |length| try std.testing.expectError(error.InvalidWire, decode(wire[0..length]));
}
