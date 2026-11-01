// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-global mesh-clock state carried across a Helix UPGRADE.
//!
//! Stable mesh event identity is the authenticated `(origin_node, hlc)` pair.
//! Re-execing with a fresh `MeshClock` can therefore reuse an identity when the
//! successor starts in the same wall-clock millisecond, or can regress for much
//! longer after a wall-clock step-back. This fixed-size snapshot preserves the
//! predecessor's complete HLC high-water mark so a successor's first stamp is
//! strictly newer even when its process-local sequence counter restarts.
//!
//! `last_stamp` and the process-global migration-offer epoch are serialized.
//! `last_physical` is redundant state and is
//! always reconstructed as `MeshClock.physicalOf(last_stamp)` on decode. That
//! makes an inconsistent pair unrepresentable in the handoff payload.
//!
//! Wire format (all integers little-endian):
//!   v1: [magic "MHLC"][u8 version=1][u64 last_stamp]
//!   v2: [magic "MHLC"][u8 version=2][u64 last_stamp][u64 migration_offer_epoch]
//!   v3: v2 + [u8 relay_v2_mode][u64 activation_epoch][32-byte roster_digest]
//!
//! The codec is allocation-free and fixed-size. Short, wrong-magic, unsupported,
//! and trailing payloads fail closed rather than partially restoring clock state.
const std = @import("std");
const mesh_clock = @import("../../substrate/undertow/mesh_clock.zig");
const relay_v2_activation = @import("../relay_v2_activation.zig");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
    InvalidActivation,
};

/// Wire version. V1 remains decodable with a zero migration-offer floor so a
/// cold compatibility fixture has deterministic semantics. Current hot-upgrade
/// producers always emit v3 and current adoption rejects v1/v2.
pub const version: u8 = 3;
pub const magic = [_]u8{ 'M', 'H', 'L', 'C' };
pub const v1_encoded_len: usize = magic.len + 1 + @sizeOf(u64);
pub const v2_encoded_len: usize = v1_encoded_len + @sizeOf(u64);
pub const encoded_len: usize = v2_encoded_len + 1 + @sizeOf(u64) + relay_v2_activation.digest_len;

pub const Snapshot = struct {
    clock: mesh_clock.MeshClock,
    migration_offer_epoch: u64,
    relay_v2_activation: relay_v2_activation.State,
};

/// Capture one process-global mesh clock into a fixed-size Helix payload.
/// `last_physical` is deliberately omitted; `decode` derives it canonically.
pub fn encode(
    clock: mesh_clock.MeshClock,
    migration_offer_epoch: u64,
    activation: relay_v2_activation.State,
) Error![encoded_len]u8 {
    relay_v2_activation.validate(activation) catch return error.InvalidActivation;
    var out: [encoded_len]u8 = undefined;
    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = version;
    std.mem.writeInt(u64, out[magic.len + 1 ..][0..8], clock.last_stamp, .little);
    std.mem.writeInt(u64, out[v1_encoded_len..][0..8], migration_offer_epoch, .little);
    out[v2_encoded_len] = @backingInt(activation.mode);
    std.mem.writeInt(u64, out[v2_encoded_len + 1 ..][0..8], activation.activation_epoch, .little);
    @memcpy(out[v2_encoded_len + 1 + @sizeOf(u64) ..], &activation.roster_digest);
    return out;
}

/// Decode and restore a process-global mesh clock. The returned clock always
/// satisfies `last_physical == MeshClock.physicalOf(last_stamp)`; the redundant
/// physical high-water mark is never trusted from handoff bytes.
fn decodeVersioned(bytes: []const u8, allow_legacy: bool) Error!Snapshot {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    const wire_version = bytes[magic.len];
    const wanted_len: usize = switch (wire_version) {
        1 => if (allow_legacy) v1_encoded_len else return error.UnsupportedVersion,
        2 => if (allow_legacy) v2_encoded_len else return error.UnsupportedVersion,
        version => encoded_len,
        else => return error.UnsupportedVersion,
    };
    if (bytes.len < wanted_len) return error.Truncated;
    if (bytes.len > wanted_len) return error.TrailingBytes;

    const last_stamp = std.mem.readInt(u64, bytes[magic.len + 1 ..][0..8], .little);
    return .{
        .clock = .{
            .last_physical = mesh_clock.MeshClock.physicalOf(last_stamp),
            .last_stamp = last_stamp,
        },
        .migration_offer_epoch = if (wire_version == 1)
            0
        else
            std.mem.readInt(u64, bytes[v1_encoded_len..][0..8], .little),
        .relay_v2_activation = if (wire_version < version)
            .{}
        else blk: {
            const mode = std.enums.fromInt(
                relay_v2_activation.Mode,
                bytes[v2_encoded_len],
            ) orelse return error.InvalidActivation;
            const activation = relay_v2_activation.State{
                .mode = mode,
                .activation_epoch = std.mem.readInt(
                    u64,
                    bytes[v2_encoded_len + 1 ..][0..8],
                    .little,
                ),
                .roster_digest = bytes[v2_encoded_len + 1 + @sizeOf(u64) ..][0..relay_v2_activation.digest_len].*,
            };
            relay_v2_activation.validate(activation) catch return error.InvalidActivation;
            break :blk activation;
        },
    };
}

/// Current Helix adoption is strict: older inner versions belong only to an
/// explicit cold migration path and may not silently reset activation state.
pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    return decodeVersioned(bytes, false);
}

/// Explicit cold-migration decoder for the legacy v1/v2 clock-only images.
/// Current v3 handoff never calls this and cannot silently default activation.
pub fn decodeLegacy(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (bytes[magic.len] != 1 and bytes[magic.len] != 2) return error.UnsupportedVersion;
    return decodeVersioned(bytes, true);
}

/// The unqualified API is intentionally current-only. Legacy call sites must
/// opt into `decodeLegacy` by name.
pub fn decode(bytes: []const u8) Error!Snapshot {
    return decodeCurrent(bytes);
}

const testing = std.testing;

test "mesh clock snapshot round-trips the complete HLC high-water mark" {
    var predecessor: mesh_clock.MeshClock = .{};
    const last = predecessor.stamp(1_700_000_000_000, 40_000);

    const activation = relay_v2_activation.State{
        .mode = .active,
        .activation_epoch = 77,
        .roster_digest = @splat(1),
    };
    const wire = try encode(predecessor, 991, activation);
    const successor = try decode(&wire);
    try testing.expectEqual(last, successor.clock.last_stamp);
    try testing.expectEqual(mesh_clock.MeshClock.physicalOf(last), successor.clock.last_physical);
    try testing.expectEqual(@as(u64, 991), successor.migration_offer_epoch);
    try testing.expectEqual(activation, successor.relay_v2_activation);
}

test "mesh clock snapshot canonicalizes redundant physical state" {
    // Even an inconsistent in-memory source cannot put an inconsistent
    // last_physical value on the wire: only last_stamp is authoritative.
    const stamp: u64 = (123_456 << mesh_clock.seq_bits) | 77;
    const wire = try encode(.{ .last_physical = 999_999, .last_stamp = stamp }, 0, .{});
    const restored = try decode(&wire);
    try testing.expectEqual(stamp, restored.clock.last_stamp);
    try testing.expectEqual(@as(u64, 123_456), restored.clock.last_physical);
}

test "mesh clock snapshot restores advancement after sequence reset and wall-clock step-back" {
    const wall_ms: u64 = 1_700_000_000_000;
    var predecessor: mesh_clock.MeshClock = .{};
    const before = predecessor.stamp(wall_ms, 60_000);

    const wire = try encode(predecessor, 0, .{});
    var successor = (try decode(&wire)).clock;
    // Models a successor whose process-local sequence restarted and whose wall
    // clock is behind the predecessor after an NTP correction.
    const after = successor.stamp(wall_ms - 10_000, 1);
    try testing.expect(after > before);
}

test "mesh clock snapshot preserves zero and maximum boundary stamps" {
    inline for (.{ @as(u64, 0), std.math.maxInt(u64) }) |last_stamp| {
        const wire = try encode(.{ .last_stamp = last_stamp }, last_stamp, .{});
        try testing.expectEqual(encoded_len, wire.len);
        const restored = try decode(&wire);
        try testing.expectEqual(last_stamp, restored.clock.last_stamp);
        try testing.expectEqual(mesh_clock.MeshClock.physicalOf(last_stamp), restored.clock.last_physical);
        try testing.expectEqual(last_stamp, restored.migration_offer_epoch);
    }
}

test "mesh clock snapshot has deterministic little-endian wire encoding" {
    const wire = try encode(.{ .last_stamp = 0x0102_0304_0506_0708 }, 0x1112_1314_1516_1718, .{});
    var expected: [encoded_len]u8 = @splat(0);
    @memcpy(
        expected[0..v2_encoded_len],
        "MHLC\x03\x08\x07\x06\x05\x04\x03\x02\x01\x18\x17\x16\x15\x14\x13\x12\x11",
    );
    try testing.expectEqualSlices(u8, &expected, &wire);
}

test "mesh clock snapshot rejects every truncation" {
    const wire = try encode(.{ .last_stamp = 7 }, 8, .{});
    var n: usize = 0;
    while (n < encoded_len) : (n += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..n]));
    }
}

test "mesh clock snapshot rejects bad magic too-new versions and trailing bytes" {
    var bad_magic = try encode(.{ .last_stamp = 7 }, 8, .{});
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decode(&bad_magic));

    var too_new = try encode(.{ .last_stamp = 7 }, 8, .{});
    too_new[magic.len] = version + 1;
    try testing.expectError(error.UnsupportedVersion, decode(&too_new));

    const trailing = (try encode(.{ .last_stamp = 7 }, 8, .{})) ++ [_]u8{0};
    try testing.expectError(error.TrailingBytes, decode(&trailing));
}

test "mesh clock snapshot v1 decodes migration offer epoch as zero" {
    var wire: [v1_encoded_len]u8 = undefined;
    @memcpy(wire[0..magic.len], &magic);
    wire[magic.len] = 1;
    std.mem.writeInt(u64, wire[magic.len + 1 ..][0..8], 77, .little);
    const restored = try decodeLegacy(&wire);
    try testing.expectEqual(@as(u64, 77), restored.clock.last_stamp);
    try testing.expectEqual(@as(u64, 0), restored.migration_offer_epoch);
    try testing.expectEqual(relay_v2_activation.State{}, restored.relay_v2_activation);
    try testing.expectError(error.UnsupportedVersion, decodeCurrent(&wire));
    try testing.expectError(error.UnsupportedVersion, decode(&wire));
}

test "mesh clock snapshot v2 is legacy-only and defaults activation to compat" {
    var wire: [v2_encoded_len]u8 = undefined;
    @memcpy(wire[0..magic.len], &magic);
    wire[magic.len] = 2;
    std.mem.writeInt(u64, wire[magic.len + 1 ..][0..8], 77, .little);
    std.mem.writeInt(u64, wire[v1_encoded_len..][0..8], 88, .little);
    const restored = try decodeLegacy(&wire);
    try testing.expectEqual(@as(u64, 77), restored.clock.last_stamp);
    try testing.expectEqual(@as(u64, 88), restored.migration_offer_epoch);
    try testing.expectEqual(relay_v2_activation.State{}, restored.relay_v2_activation);
    try testing.expectError(error.UnsupportedVersion, decodeCurrent(&wire));
    try testing.expectError(error.UnsupportedVersion, decode(&wire));
}

test "mesh clock current snapshot rejects invalid activation semantics" {
    var bad_mode = try encode(.{ .last_stamp = 1 }, 2, .{});
    bad_mode[v2_encoded_len] = 99;
    try testing.expectError(error.InvalidActivation, decodeCurrent(&bad_mode));

    var half_plan = try encode(.{ .last_stamp = 1 }, 2, .{});
    std.mem.writeInt(u64, half_plan[v2_encoded_len + 1 ..][0..8], 7, .little);
    try testing.expectError(error.InvalidActivation, decodeCurrent(&half_plan));

    var active_without_plan = try encode(.{ .last_stamp = 1 }, 2, .{});
    active_without_plan[v2_encoded_len] = @backingInt(relay_v2_activation.Mode.active);
    try testing.expectError(error.InvalidActivation, decodeCurrent(&active_without_plan));

    try testing.expectError(error.InvalidActivation, encode(.{}, 0, .{ .mode = .active }));
    const current = try encode(.{}, 0, .{});
    try testing.expectError(error.UnsupportedVersion, decodeLegacy(&current));
}
