// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix custody for trap names, offender counters, and recent trips.

const std = @import("std");
const spamtrap = @import("../spamtrap.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'S', 'P', 'T', 'R' };
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;
const domain = "onyx-spamtrap-checkpoint-v1";
const params = spamtrap.Params{};
const header_len: usize = 44;

comptime {
    if (params.max_trap_nicks > std.math.maxInt(u16) or params.max_trap_channels > std.math.maxInt(u16) or
        params.max_offenders > std.math.maxInt(u16) or params.max_recent_trips > std.math.maxInt(u16) or
        params.max_nick_bytes > std.math.maxInt(u8) or params.max_channel_bytes > std.math.maxInt(u8) or
        params.max_actor_bytes > std.math.maxInt(u8)) @compileError("spamtrap checkpoint wire bounds exceeded");
}

const Counts = struct {
    nicks: usize,
    channels: usize,
    offenders: usize,
    recent: usize,
    total: u64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    const counts = try readCounts(bytes);
    var reader = wire.Reader{ .bytes = body };
    var prior: ?[]const u8 = null;
    for (0..counts.nicks) |_| {
        const nick = try reader.take(try reader.readByte());
        if (!validNick(nick) or !normalized(nick)) return error.InvalidField;
        try strictlyIncreasing(&prior, nick);
    }
    prior = null;
    for (0..counts.channels) |_| {
        const channel = try reader.take(try reader.readByte());
        if (!validChannel(channel) or !normalized(channel)) return error.InvalidField;
        try strictlyIncreasing(&prior, channel);
    }
    prior = null;
    var actors: [params.max_offenders][]const u8 = undefined;
    var actor_counts: [params.max_offenders]u64 = undefined;
    var sum: u64 = 0;
    for (0..counts.offenders) |index| {
        const len: usize = try reader.readByte();
        const count = try reader.readU64();
        const actor = try reader.take(len);
        if (!validActor(actor) or !normalized(actor) or count == 0) return error.InvalidField;
        try strictlyIncreasing(&prior, actor);
        sum = std.math.add(u64, sum, count) catch return error.InvalidField;
        actors[index] = actor;
        actor_counts[index] = count;
    }
    if (sum != counts.total or counts.recent > counts.total) return error.InvalidField;
    for (0..counts.recent) |_| {
        const actor_len: usize = try reader.readByte();
        const target_len: usize = try reader.readByte();
        const kind = std.enums.fromInt(spamtrap.TrapKind, try reader.readByte()) orelse return error.InvalidField;
        if (try reader.readByte() != 0) return error.InvalidField;
        const at_count = try reader.readU64();
        const actor = try reader.take(actor_len);
        const target = try reader.take(target_len);
        if (!validActor(actor) or !(switch (kind) {
            .nick => validNick(target),
            .channel => validChannel(target),
        }) or at_count == 0) return error.InvalidField;
        var normalized_actor: [params.max_actor_bytes]u8 = undefined;
        for (actor, 0..) |byte, i| normalized_actor[i] = std.ascii.toLower(byte);
        const index = findActor(actors[0..counts.offenders], normalized_actor[0..actor.len]) orelse return error.InvalidField;
        if (at_count > actor_counts[index]) return error.InvalidField;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encode(allocator: std.mem.Allocator, source: *const spamtrap.DefaultSpamtrap) Error![]u8 {
    const counts = Counts{
        .nicks = source.trapNickCount(),
        .channels = source.trapChannelCount(),
        .offenders = source.offenderCount(),
        .recent = source.recentTripCount(),
        .total = source.totalTripCount(),
    };
    if (counts.nicks > params.max_trap_nicks or counts.channels > params.max_trap_channels or
        counts.offenders > params.max_offenders or counts.recent > params.max_recent_trips)
        return error.CheckpointTooLarge;
    const nicks = try allocator.alloc([]const u8, counts.nicks);
    defer allocator.free(nicks);
    const channels = try allocator.alloc([]const u8, counts.channels);
    defer allocator.free(channels);
    const offenders = try allocator.alloc([]const u8, counts.offenders);
    defer allocator.free(offenders);
    var size: usize = header_len + wire.checksum_len;
    var index: usize = 0;
    var nit = source.trap_nicks.iterator();
    while (nit.next()) |entry| {
        nicks[index] = entry.key_ptr.*;
        try wire.addLen(&size, 1 + nicks[index].len);
        index += 1;
    }
    std.debug.assert(index == counts.nicks);
    index = 0;
    var cit = source.trap_channels.iterator();
    while (cit.next()) |entry| {
        channels[index] = entry.key_ptr.*;
        try wire.addLen(&size, 1 + channels[index].len);
        index += 1;
    }
    std.debug.assert(index == counts.channels);
    index = 0;
    var oit = source.offender_trips.iterator();
    while (oit.next()) |entry| {
        offenders[index] = entry.key_ptr.*;
        try wire.addLen(&size, 1 + 8 + offenders[index].len);
        index += 1;
    }
    std.debug.assert(index == counts.offenders);
    std.mem.sort([]const u8, nicks, {}, lessThan);
    std.mem.sort([]const u8, channels, {}, lessThan);
    std.mem.sort([]const u8, offenders, {}, lessThan);
    var recent_buf: [params.max_recent_trips]spamtrap.Trip = undefined;
    const recent = source.recentTrips(&recent_buf) catch return error.InvalidField;
    for (recent) |trip| try wire.addLen(&size, 12 + trip.actor.len + trip.target.len);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(counts.nicks));
    writer.writeU16(@intCast(counts.channels));
    writer.writeU16(@intCast(counts.offenders));
    writer.writeU16(@intCast(counts.recent));
    writer.writeU64(counts.total);
    writer.writeU16(@intCast(params.max_trap_nicks));
    writer.writeU16(@intCast(params.max_trap_channels));
    writer.writeU16(@intCast(params.max_offenders));
    writer.writeU16(@intCast(params.max_recent_trips));
    writer.writeU16(@intCast(params.max_nick_bytes));
    writer.writeU16(@intCast(params.max_channel_bytes));
    writer.writeU16(@intCast(params.max_actor_bytes));
    writer.writeU16(0);
    for (nicks) |nick| {
        if (nick.len > std.math.maxInt(u8)) return error.InvalidField;
        writer.writeByte(@intCast(nick.len));
        writer.writeBytes(nick);
    }
    for (channels) |channel| {
        if (channel.len > std.math.maxInt(u8)) return error.InvalidField;
        writer.writeByte(@intCast(channel.len));
        writer.writeBytes(channel);
    }
    for (offenders) |actor| {
        if (actor.len > std.math.maxInt(u8)) return error.InvalidField;
        writer.writeByte(@intCast(actor.len));
        writer.writeU64(source.offender_trips.get(actor).?);
        writer.writeBytes(actor);
    }
    for (recent) |trip| {
        if (trip.actor.len > std.math.maxInt(u8) or trip.target.len > std.math.maxInt(u8)) return error.InvalidField;
        writer.writeByte(@intCast(trip.actor.len));
        writer.writeByte(@intCast(trip.target.len));
        writer.writeByte(@intFromEnum(trip.kind));
        writer.writeByte(0);
        writer.writeU64(trip.count_for_actor);
        writer.writeBytes(trip.actor);
        writer.writeBytes(trip.target);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!spamtrap.DefaultSpamtrap {
    try validateCheckpoint(bytes);
    const counts = try readCounts(bytes);
    var result = spamtrap.DefaultSpamtrap.init(allocator);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..counts.nicks) |_| {
        const nick = try reader.take(try reader.readByte());
        result.addTrapNick(nick) catch |err| return convertStoreError(err);
    }
    for (0..counts.channels) |_| {
        const channel = try reader.take(try reader.readByte());
        result.addTrapChannel(channel) catch |err| return convertStoreError(err);
    }
    for (0..counts.offenders) |_| {
        const len: usize = try reader.readByte();
        const count = try reader.readU64();
        const actor = try reader.take(len);
        result.checkpointImportOffender(actor, count) catch |err| return convertStoreError(err);
    }
    for (0..counts.recent) |_| {
        const actor_len: usize = try reader.readByte();
        const target_len: usize = try reader.readByte();
        const kind = std.enums.fromInt(spamtrap.TrapKind, try reader.readByte()) orelse return error.InvalidField;
        _ = try reader.readByte();
        const at_count = try reader.readU64();
        const actor = try reader.take(actor_len);
        const target = try reader.take(target_len);
        result.checkpointAppendRecent(.{ .actor = actor, .kind = kind, .target = target, .count_for_actor = at_count }) catch |err| return convertStoreError(err);
    }
    result.total_trips = counts.total;
    return result;
}

fn readCounts(bytes: []const u8) Error!Counts {
    const counts = Counts{
        .nicks = std.mem.readInt(u16, bytes[12..14], .little),
        .channels = std.mem.readInt(u16, bytes[14..16], .little),
        .offenders = std.mem.readInt(u16, bytes[16..18], .little),
        .recent = std.mem.readInt(u16, bytes[18..20], .little),
        .total = std.mem.readInt(u64, bytes[20..28], .little),
    };
    if (counts.nicks > params.max_trap_nicks or counts.channels > params.max_trap_channels or
        counts.offenders > params.max_offenders or counts.recent > params.max_recent_trips)
        return error.CheckpointTooLarge;
    const expected = [_]u16{
        @intCast(params.max_trap_nicks),   @intCast(params.max_trap_channels), @intCast(params.max_offenders),
        @intCast(params.max_recent_trips), @intCast(params.max_nick_bytes),    @intCast(params.max_channel_bytes),
        @intCast(params.max_actor_bytes),
    };
    for (expected, 0..) |value, i| {
        if (std.mem.readInt(u16, bytes[28 + i * 2 ..][0..2], .little) != value) return error.InvalidField;
    }
    if (std.mem.readInt(u16, bytes[42..44], .little) != 0) return error.InvalidField;
    return counts;
}

fn validToken(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte <= ' ' or byte == ',' or byte == 0x7f) return false;
    }
    return true;
}

fn validNick(bytes: []const u8) bool {
    return bytes.len > 0 and bytes.len <= params.max_nick_bytes and
        bytes[0] != '#' and bytes[0] != '&' and validToken(bytes);
}

fn validChannel(bytes: []const u8) bool {
    return bytes.len >= 2 and bytes.len <= params.max_channel_bytes and
        bytes[0] == '#' and validToken(bytes);
}

fn validActor(bytes: []const u8) bool {
    return bytes.len > 0 and bytes.len <= params.max_actor_bytes and validToken(bytes);
}

fn normalized(bytes: []const u8) bool {
    for (bytes) |byte| if (std.ascii.isUpper(byte)) return false;
    return true;
}

fn strictlyIncreasing(prior: *?[]const u8, next: []const u8) Error!void {
    if (prior.*) |previous| {
        if (!std.mem.lessThan(u8, previous, next)) return error.NonCanonicalOrder;
    }
    prior.* = next;
}

fn findActor(actors: []const []const u8, key: []const u8) ?usize {
    var low: usize = 0;
    var high: usize = actors.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (std.mem.lessThan(u8, actors[mid], key)) low = mid + 1 else high = mid;
    }
    if (low < actors.len and std.mem.eql(u8, actors[low], key)) return low;
    return null;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn convertStoreError(err: anyerror) Error {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidField;
}

test "SPTR checkpoint retains normalized maps and original recent trip spelling" {
    const alloc = std.testing.allocator;
    var source = spamtrap.DefaultSpamtrap.init(alloc);
    defer source.deinit();
    try source.addTrapNick("Decoy");
    try source.addTrapChannel("#Honey");
    try std.testing.expect(try source.triggered("Actor", .nick, "DECOY", false));
    try std.testing.expect(try source.triggered("actor", .channel, "#HONEY", false));
    try source.removeTrapNick("decoy");
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decode(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u64, 2), restored.totalTripCount());
    try std.testing.expectEqual(@as(u64, 2), try restored.tripCount("ACTOR"));
    try std.testing.expectEqual(@as(usize, 0), restored.trapNickCount());
    try std.testing.expect(try restored.isTrapChannel("#honey"));
    var trips: [2]spamtrap.Trip = undefined;
    const recent = try restored.recentTrips(&trips);
    try std.testing.expectEqualStrings("Actor", recent[0].actor);
    try std.testing.expectEqualStrings("DECOY", recent[0].target);
    try std.testing.expectEqualStrings("actor", recent[1].actor);
    try std.testing.expectEqualStrings("#HONEY", recent[1].target);
    const again = try encode(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}

test "SPTR checkpoint rejects mismatched aggregate and malformed target" {
    const alloc = std.testing.allocator;
    var source = spamtrap.DefaultSpamtrap.init(alloc);
    defer source.deinit();
    try source.addTrapNick("x");
    try std.testing.expect(try source.triggered("a", .nick, "x", false));
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    var bad = try alloc.dupe(u8, bytes);
    defer alloc.free(bad);
    bad[20] = 2;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[42] = 1;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
}

test "SPTR checkpoint staged decode sweeps allocation failures" {
    const alloc = std.testing.allocator;
    var source = spamtrap.DefaultSpamtrap.init(alloc);
    defer source.deinit();
    try source.addTrapNick("x");
    try source.addTrapChannel("#x");
    try std.testing.expect(try source.triggered("Actor", .nick, "X", false));
    const Encode = struct {
        fn run(a: std.mem.Allocator, s: *const spamtrap.DefaultSpamtrap) !void {
            const encoded = try encode(a, s);
            defer a.free(encoded);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Encode.run, .{&source});
    const bytes = try encode(alloc, &source);
    defer alloc.free(bytes);
    const Decode = struct {
        fn run(a: std.mem.Allocator, b: []const u8) !void {
            var staged = try decode(a, b);
            defer staged.deinit();
            try std.testing.expectEqual(@as(u64, 1), staged.totalTripCount());
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Decode.run, .{bytes});
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}
