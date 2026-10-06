// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated, one-use Windows custody for a detached active-media body.
//!
//! HXMC is a private-control record, not the media checkpoint itself. The
//! source must send it over the authenticated Windows Helix control endpoint.
//! A PID-scoped read-only section contains one AEAD-sealed HXMG graph, HXNA
//! native physical, or HXWA WebRTC physical body. A candidate takes each
//! section handle once, authenticates the complete arena, then decodes it into
//! private storage. Neither side publishes a media owner here. Active media
//! remains guarded until a single transaction joins all three bodies, both UDP
//! sockets, inherited IRC socket/ClientId remaps, and no-fail post-COMMIT
//! publication.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const graph_codec = @import("media_graph_checkpoint.zig");
const physical_codec = @import("native_windows_active_media_snapshot.zig");
const native = @import("../native_media_transport.zig");
const webrtc = @import("../media_plane.zig");
const media_transport = @import("../../substrate/media_transport.zig");
const sfu_srtp = @import("../sfu_srtp.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const magic = "HXMC";
const version: u16 = 1;
pub const frame_len: usize = 96;
pub const Frame = [frame_len]u8;
pub const Kind = enum(u8) { graph = 1, native_physical = 2, webrtc_physical = 3 };
const invalid_handle = std.math.maxInt(usize);

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows media custody exceeds authenticated control frame");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = arena_mod.Error || graph_codec.Error || physical_codec.Error || platform.EntropyError || error{
    InvalidTarget,
    InvalidFrame,
    InvalidSnapshot,
    DigestMismatch,
    WrongKind,
    AlreadyClaimed,
};

pub const Prepared = struct {
    arena: arena_mod.Arena,
    sealer: envelope.Sealer,
    body: Frame,

    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.sealer.deinit();
        std.crypto.secureZero(u8, &self.body);
    }
};

pub fn absentFrame(kind: Kind) Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    body[6] = @intFromEnum(kind);
    return body;
}

fn presentFrame(kind: Kind, target_pid: u32, remote_handle: usize, wire_size: usize, key: envelope.Key, digest: [32]u8) Frame {
    var body = absentFrame(kind);
    body[7] = 1;
    std.mem.writeInt(u32, body[8..12], target_pid, .big);
    std.mem.writeInt(u64, body[16..24], @intCast(remote_handle), .big);
    std.mem.writeInt(u64, body[24..32], @intCast(wire_size), .big);
    @memcpy(body[32..64], &key);
    @memcpy(body[64..96], &digest);
    return body;
}

fn validateTarget(target_process: usize, target_pid: u32) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (target_process == 0 or target_pid == 0 or GetProcessId(target_process) != target_pid)
        return error.InvalidTarget;
}

fn maxBody(kind: Kind) usize {
    return switch (kind) {
        .graph => graph_codec.max_wire_bytes,
        .native_physical, .webrtc_physical => physical_codec.max_wire_bytes,
    };
}

fn prepareBody(allocator: std.mem.Allocator, kind: Kind, snapshot: []const u8, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    if (snapshot.len == 0 or snapshot.len > maxBody(kind)) return error.InvalidSnapshot;
    var digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Sha256.hash(snapshot, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    errdefer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, snapshot);
    errdefer arena.deinit();
    const remote_handle = try arena.duplicateReadOnlyForProcess(target_process);
    return .{ .arena = arena, .sealer = sealer, .body = presentFrame(kind, target_pid, remote_handle, arena.size, sealer.key, digest) };
}

/// The caller supplies a graph Source captured under the joined paused cut.
/// Encoding validates its graph/room/bridge/client joins before any HANDLE is
/// duplicated. The candidate-owned duplicate is reaped with the candidate if
/// an upgrade aborts before the authenticated control frame is consumed.
pub fn prepareGraph(allocator: std.mem.Allocator, source: graph_codec.Source, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    try validateTarget(target_process, target_pid);
    const snapshot = try graph_codec.encode(allocator, source);
    defer graph_codec.freeEncoded(allocator, snapshot);
    return prepareBody(allocator, .graph, snapshot, target_process, target_pid, upgrade_id);
}

pub fn prepareNative(allocator: std.mem.Allocator, snapshot: *const native.PhysicalSnapshot, limits: physical_codec.Limits, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    try validateTarget(target_process, target_pid);
    const body = try physical_codec.encodeNative(allocator, snapshot, limits);
    defer physical_codec.freeEncoded(allocator, body);
    return prepareBody(allocator, .native_physical, body, target_process, target_pid, upgrade_id);
}

pub fn prepareWebrtc(allocator: std.mem.Allocator, snapshot: *const webrtc.PhysicalSnapshot, limits: webrtc.PhysicalSnapshot.Limits, target_process: usize, target_pid: u32, upgrade_id: envelope.UpgradeId) Error!Prepared {
    try validateTarget(target_process, target_pid);
    const body = try physical_codec.encodeWebrtc(allocator, snapshot, limits);
    defer physical_codec.freeEncoded(allocator, body);
    return prepareBody(allocator, .webrtc_physical, body, target_process, target_pid, upgrade_id);
}

const Parsed = struct {
    handle: usize,
    size: usize,
    key: envelope.Key,
    digest: [32]u8,
};

fn parseFrame(bytes: []const u8, kind: Kind, target_pid: u32, forbidden: []const usize) Error!?Parsed {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or bytes[6] != @intFromEnum(kind))
        return error.InvalidFrame;
    if (bytes[7] == 0) {
        const canonical = absentFrame(kind);
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidFrame;
        return null;
    }
    if (bytes[7] != 1 or target_pid == 0 or
        std.mem.readInt(u32, bytes[8..12], .big) != target_pid or
        std.mem.readInt(u32, bytes[12..16], .big) != 0)
        return error.InvalidFrame;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidFrame;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidFrame;
    if (handle == 0 or handle == invalid_handle or
        size <= envelope.header_len + envelope.tag_len or
        size > envelope.header_len + envelope.tag_len + maxBody(kind))
        return error.InvalidFrame;
    for (forbidden) |reserved| if (reserved == handle) return error.InvalidFrame;
    return .{ .handle = handle, .size = size, .key = bytes[32..64].*, .digest = bytes[64..96].* };
}

/// Validate the source's immutable READY witness without importing or
/// consuming the candidate's encrypted section HANDLE.
pub fn validateFrame(bytes: []const u8, kind: Kind, target_pid: u32) Error!bool {
    return (try parseFrame(bytes, kind, target_pid, &.{})) != null;
}

/// Owns exactly one candidate section HANDLE from an authenticated private
/// control record. An invalid frame does not take ownership of any HANDLE.
/// Do not copy this value after init; always call deinit on the original.
pub const Receiver = struct {
    kind: Kind,
    parsed: ?Parsed,
    claimed: bool = false,

    pub fn init(bytes: []const u8, kind: Kind, forbidden: []const usize) Error!Receiver {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        return .{ .kind = kind, .parsed = try parseFrame(bytes, kind, GetCurrentProcessId(), forbidden) };
    }

    pub fn deinit(self: *Receiver) void {
        if (self.parsed) |*record| {
            if (comptime builtin.os.tag == .windows) {
                if (record.handle != 0 and record.handle != invalid_handle) _ = CloseHandle(record.handle);
            }
            record.handle = 0;
            std.crypto.secureZero(u8, &record.key);
        }
        self.parsed = null;
        self.claimed = true;
    }

    /// A failed authentication or allocation also consumes the handle. The
    /// caller must abort this candidate and start a fresh upgrade.
    fn takePlain(self: *Receiver, allocator: std.mem.Allocator, kind: Kind, upgrade_id: envelope.UpgradeId) Error!?[]u8 {
        if (self.claimed) return error.AlreadyClaimed;
        self.claimed = true;
        const record = if (self.parsed) |*value| value else {
            if (self.kind != kind) return error.WrongKind;
            return null;
        };
        defer {
            _ = CloseHandle(record.handle);
            record.handle = 0;
            std.crypto.secureZero(u8, &record.key);
        }
        if (self.kind != kind) return error.WrongKind;
        const plaintext = try arena_mod.read(allocator, record.handle, record.size, record.key, upgrade_id);
        errdefer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        if (plaintext.len == 0 or plaintext.len > maxBody(kind)) return error.InvalidSnapshot;
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        Sha256.hash(plaintext, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, record.digest)) return error.DigestMismatch;
        return plaintext;
    }

    /// Decoding remains detached; publication belongs to the aggregate commit.
    pub fn takeGraph(self: *Receiver, allocator: std.mem.Allocator, upgrade_id: envelope.UpgradeId) Error!?graph_codec.Snapshot {
        const plaintext = (try self.takePlain(allocator, .graph, upgrade_id)) orelse return null;
        defer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        return try graph_codec.decode(allocator, plaintext);
    }

    pub fn takeNative(self: *Receiver, allocator: std.mem.Allocator, upgrade_id: envelope.UpgradeId, limits: physical_codec.Limits) Error!?native.PhysicalSnapshot {
        const plaintext = (try self.takePlain(allocator, .native_physical, upgrade_id)) orelse return null;
        defer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        return try physical_codec.decodeNative(allocator, plaintext, limits);
    }

    pub fn takeWebrtc(self: *Receiver, allocator: std.mem.Allocator, upgrade_id: envelope.UpgradeId, limits: webrtc.PhysicalSnapshot.Limits) Error!?webrtc.PhysicalSnapshot {
        const plaintext = (try self.takePlain(allocator, .webrtc_physical, upgrade_id)) orelse return null;
        defer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }
        return try physical_codec.decodeWebrtc(allocator, plaintext, limits);
    }
};

test "Windows media custody frame kinds and absence are exact" {
    const pid: u32 = 71;
    inline for (.{ Kind.graph, Kind.native_physical, Kind.webrtc_physical }) |kind| {
        var absent = absentFrame(kind);
        try std.testing.expect(!(try validateFrame(&absent, kind, pid)));
        absent[frame_len - 1] = 1;
        try std.testing.expectError(error.InvalidFrame, validateFrame(&absent, kind, pid));
        const canonical = absentFrame(kind);
        const wrong: Kind = if (kind == .graph) .native_physical else .graph;
        try std.testing.expectError(error.InvalidFrame, validateFrame(&canonical, wrong, pid));
    }
    var present = presentFrame(.graph, pid, 19, envelope.header_len + envelope.tag_len + 1, @splat(0x42), @splat(0x27));
    try std.testing.expect(try validateFrame(&present, .graph, pid));
    try std.testing.expectError(error.InvalidFrame, parseFrame(&present, .graph, pid, &.{19}));
    try std.testing.expectError(error.InvalidFrame, validateFrame(present[0 .. frame_len - 1], .graph, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&present, .graph, pid + 1));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&present, .native_physical, pid));
    present[12] = 1;
    try std.testing.expectError(error.InvalidFrame, validateFrame(&present, .graph, pid));
    present[12] = 0;
    std.mem.writeInt(u64, present[24..32], envelope.header_len + envelope.tag_len + graph_codec.max_wire_bytes + 1, .big);
    try std.testing.expectError(error.InvalidFrame, validateFrame(&present, .graph, pid));
}

const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    graph: @import("../../substrate/media_routing.zig").GraphSnapshot,
    rooms: @import("../media_room.zig").Snapshot,

    fn init() !Fixture {
        const routing = @import("../../substrate/media_routing.zig");
        const media = @import("../media_room.zig");
        const holder = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(holder);
        holder.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer holder.deinit();
        const a = holder.allocator();
        return .{
            .arena = holder,
            .graph = .{
                .allocator = a,
                .id = .{ .serial = 1 },
                .revision = 1,
                .next_call = 1,
                .next_endpoint = 1,
                .next_stream = 1,
                .next_scope = 1,
                .next_binding = 3,
                .native_binding_serial = 1,
                .webrtc_binding_serial = 2,
                .calls = try a.alloc(routing.GraphCall, 0),
                .endpoints = try a.alloc(routing.GraphEndpoint, 0),
                .memberships = try a.alloc(routing.GraphMembership, 0),
                .bridge_policy = try a.alloc(routing.GraphBridgePolicy, 0),
            },
            .rooms = .{
                .allocator = a,
                .config = media.Config{},
                .transport_revision = 1,
                .physical_profiles = try a.alloc(media.PhysicalProfileRow, 0),
                .physical_members = try a.alloc(media.PhysicalMemberRow, 0),
                .rooms = try a.alloc(media.RoomRow, 0),
                .breakouts = try a.alloc(media.StringRow([]u8), 0),
                .positions = try a.alloc(media.StringRow(media.Position), 0),
                .hands = try a.alloc(media.StringRow(void), 0),
                .profiles = try a.alloc(media.StringRow(media.CallProfile), 0),
                .participant_profiles = try a.alloc(media.StringRow(media.CallProfile), 0),
                .consents = try a.alloc(media.StringRow(void), 0),
                .recordings = try a.alloc(media.StringRow(media.Recording), 0),
                .qualities = try a.alloc(media.StringRow(media.Quality), 0),
                .queues = try a.alloc(media.QueueRow, 0),
            },
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        std.testing.allocator.destroy(self.arena);
    }

    fn source(self: *const Fixture) graph_codec.Source {
        return .{ .graph = &self.graph, .rooms = &self.rooms, .bridges = &.{}, .clients = &.{}, .attachments = &.{}, .bindings = &.{} };
    }
};

fn nativeFixture(allocator: std.mem.Allocator) !native.PhysicalSnapshot {
    const endpoints = try allocator.alloc(native.PhysicalSnapshot.Endpoint, 0);
    errdefer allocator.free(endpoints);
    const streams = try allocator.alloc(native.PhysicalSnapshot.Stream, 0);
    errdefer allocator.free(streams);
    const channels = try allocator.alloc(native.PhysicalSnapshot.Channel, 0);
    errdefer allocator.free(channels);
    const stream_index = try allocator.alloc(native.PhysicalSnapshot.ChannelIndex, 0);
    return .{ .allocator = allocator, .endpoints = endpoints, .streams = streams, .channels = channels, .stream_index = stream_index, .physical_revision = 1, .next_ingress_serial = 1, .routed_accepted = 0, .routed_refused = 0, .routed_errors = 0 };
}

fn nativeLimits() physical_codec.Limits {
    return .{ .max_participants = native.max_call_participants, .max_state_bytes = 1 << 20 };
}

fn webrtcLimits() webrtc.PhysicalSnapshot.Limits {
    return .{ .max_rows = 8, .max_offered = 8, .max_bytes = 16 * 1024 * 1024, .transport = .{ .max_endpoints = 8, .max_groups = 8, .max_bytes = 8 * 1024 * 1024 } };
}

fn webrtcFixture(allocator: std.mem.Allocator) !webrtc.PhysicalSnapshot {
    const limits = webrtcLimits();
    var transport_owner = media_transport.MediaTransport.init(allocator);
    defer transport_owner.deinit();
    var transport = try transport_owner.capture(allocator, limits.transport);
    errdefer transport.deinit();
    var srtp_owner = sfu_srtp.SfuSrtp.init(allocator);
    defer srtp_owner.wipe();
    var srtp = try srtp_owner.capture(allocator);
    errdefer srtp.deinit();
    const rows = try allocator.alloc(webrtc.PhysicalSnapshot.Row, 0);
    errdefer allocator.free(rows);
    const ufrags = try allocator.alloc(webrtc.PhysicalSnapshot.Ufrag, 0);
    errdefer allocator.free(ufrags);
    const groups = try allocator.alloc(webrtc.PhysicalSnapshot.Group, 0);
    errdefer allocator.free(groups);
    const offered = try allocator.alloc(webrtc.PhysicalSnapshot.Fingerprint, 0);
    errdefer allocator.free(offered);
    var rng = std.Random.DefaultCsprng.init(@splat(0x34));
    const snapshot: webrtc.PhysicalSnapshot = .{
        .allocator = allocator,
        .socket = .{ .device = 91, .inode = 0, .address_be = webrtc.loopback_be, .port = 9001, .recv_timeout_ms = 250 },
        .csprng = webrtc.RngState.capture(&rng),
        .stun_server = null,
        .discovered = null,
        .max_frame_bytes = 1200,
        .max_upload_bytes = 4096,
        .cross_configured = false,
        .dtls_enabled = false,
        .dtls_requested = false,
        .dtls13_enabled = false,
        .dtls13_requested = false,
        .dtls_fingerprint_buf = @splat(0),
        .dtls_fingerprint_len = 0,
        .dtls12 = null,
        .dtls13 = null,
        .srtp = srtp,
        .transport = transport,
        .rows = rows,
        .ufrags = ufrags,
        .groups = groups,
        .ssrcs = @splat(.{}),
        .crypto = @splat(.{}),
        .offered_fps = offered,
        .queue = .{ .capacity = 4, .payload_limit = 1024, .head = 0, .next_ordinal = 1, .completed = 0, .last_disposition = null, .next_fence = 1 },
        .rtcp_out_head = 0,
        .physical_revision = 1,
        .next_routing_inbound = 1,
        .routing_ingress_refused = 0,
        .routing_ingress_completed = 0,
        .routing_last_ingress_error = null,
    };
    try snapshot.validate(limits);
    return snapshot;
}

test "Windows media custody authenticates HXMG then consumes the handle once" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const absent = absentFrame(.graph);
    var empty = try Receiver.init(&absent, .graph, &.{});
    defer empty.deinit();
    try std.testing.expect((try empty.takeGraph(std.testing.allocator, @splat(0x5a))) == null);
    try std.testing.expectError(error.AlreadyClaimed, empty.takeGraph(std.testing.allocator, @splat(0x5a)));
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const upgrade_id: envelope.UpgradeId = @splat(0x5a);
    const pid = GetCurrentProcessId();
    var prepared = try prepareGraph(std.testing.allocator, fixture.source(), GetCurrentProcess(), pid, upgrade_id);
    defer prepared.deinit();
    try std.testing.expect(try validateFrame(&prepared.body, .graph, pid));
    var receiver = try Receiver.init(&prepared.body, .graph, &.{});
    defer receiver.deinit();
    var decoded = (try receiver.takeGraph(std.testing.allocator, upgrade_id)).?;
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u64, 1), decoded.graph.id.serial);
    try std.testing.expectEqual(@as(usize, 0), decoded.graph.calls.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.clients.len);
    try std.testing.expectError(error.AlreadyClaimed, receiver.takeGraph(std.testing.allocator, upgrade_id));
}

test "Windows media custody rejects wrong upgrade and consumes failed take" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const pid = GetCurrentProcessId();
    var prepared = try prepareGraph(std.testing.allocator, fixture.source(), GetCurrentProcess(), pid, @splat(0x31));
    defer prepared.deinit();
    var receiver = try Receiver.init(&prepared.body, .graph, &.{});
    defer receiver.deinit();
    try std.testing.expectError(error.WrongUpgrade, receiver.takeGraph(std.testing.allocator, @splat(0x32)));
    try std.testing.expectError(error.AlreadyClaimed, receiver.takeGraph(std.testing.allocator, @splat(0x31)));
}

test "Windows media custody rejects a physical kind passed to graph decoder" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const upgrade_id: envelope.UpgradeId = @splat(0x51);
    var prepared = try prepareGraph(std.testing.allocator, fixture.source(), GetCurrentProcess(), GetCurrentProcessId(), upgrade_id);
    defer prepared.deinit();
    var wrong_kind = prepared.body;
    defer std.crypto.secureZero(u8, &wrong_kind);
    wrong_kind[6] = @intFromEnum(Kind.native_physical);
    var receiver = try Receiver.init(&wrong_kind, .native_physical, &.{});
    defer receiver.deinit();
    try std.testing.expectError(error.WrongKind, receiver.takeGraph(std.testing.allocator, upgrade_id));
    try std.testing.expectError(error.AlreadyClaimed, receiver.takeGraph(std.testing.allocator, upgrade_id));
}

test "Windows media custody authenticates typed HXNA and HXWA bodies" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pid = GetCurrentProcessId();
    const upgrade_id: envelope.UpgradeId = @splat(0x73);
    var source_native = try nativeFixture(allocator);
    defer source_native.deinit();
    var prepared_native = try prepareNative(allocator, &source_native, nativeLimits(), GetCurrentProcess(), pid, upgrade_id);
    defer prepared_native.deinit();
    try std.testing.expect(try validateFrame(&prepared_native.body, .native_physical, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&prepared_native.body, .webrtc_physical, pid));
    var native_receiver = try Receiver.init(&prepared_native.body, .native_physical, &.{});
    defer native_receiver.deinit();
    var native_decoded = (try native_receiver.takeNative(allocator, upgrade_id, nativeLimits())).?;
    defer native_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 0), native_decoded.endpoints.len);
    try std.testing.expectEqual(@as(u64, 1), native_decoded.physical_revision);
    try std.testing.expectError(error.AlreadyClaimed, native_receiver.takeNative(allocator, upgrade_id, nativeLimits()));

    var source_webrtc = try webrtcFixture(allocator);
    defer source_webrtc.deinit();
    var prepared_webrtc = try prepareWebrtc(allocator, &source_webrtc, webrtcLimits(), GetCurrentProcess(), pid, upgrade_id);
    defer prepared_webrtc.deinit();
    try std.testing.expect(try validateFrame(&prepared_webrtc.body, .webrtc_physical, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&prepared_webrtc.body, .native_physical, pid));
    var webrtc_receiver = try Receiver.init(&prepared_webrtc.body, .webrtc_physical, &.{});
    defer webrtc_receiver.deinit();
    var webrtc_decoded = (try webrtc_receiver.takeWebrtc(allocator, upgrade_id, webrtcLimits())).?;
    defer webrtc_decoded.deinit();
    try std.testing.expectEqual(@as(usize, 0), webrtc_decoded.rows.len);
    try std.testing.expectEqual(@as(u64, 1), webrtc_decoded.physical_revision);
    try std.testing.expectError(error.AlreadyClaimed, webrtc_receiver.takeWebrtc(allocator, upgrade_id, webrtcLimits()));
}

test "Windows media custody physical digest and identity failure consume HANDLE" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pid = GetCurrentProcessId();
    const upgrade_id: envelope.UpgradeId = @splat(0x63);
    var source_native = try nativeFixture(allocator);
    defer source_native.deinit();
    var prepared_native = try prepareNative(allocator, &source_native, nativeLimits(), GetCurrentProcess(), pid, upgrade_id);
    defer prepared_native.deinit();
    prepared_native.body[64] ^= 1;
    var native_receiver = try Receiver.init(&prepared_native.body, .native_physical, &.{});
    defer native_receiver.deinit();
    try std.testing.expectError(error.DigestMismatch, native_receiver.takeNative(allocator, upgrade_id, nativeLimits()));
    try std.testing.expectError(error.AlreadyClaimed, native_receiver.takeNative(allocator, upgrade_id, nativeLimits()));

    var source_webrtc = try webrtcFixture(allocator);
    defer source_webrtc.deinit();
    var prepared_webrtc = try prepareWebrtc(allocator, &source_webrtc, webrtcLimits(), GetCurrentProcess(), pid, upgrade_id);
    defer prepared_webrtc.deinit();
    var webrtc_receiver = try Receiver.init(&prepared_webrtc.body, .webrtc_physical, &.{});
    defer webrtc_receiver.deinit();
    try std.testing.expectError(error.WrongUpgrade, webrtc_receiver.takeWebrtc(allocator, @splat(0x64), webrtcLimits()));
    try std.testing.expectError(error.AlreadyClaimed, webrtc_receiver.takeWebrtc(allocator, upgrade_id, webrtcLimits()));
}

fn decodeAllocationSweep(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const upgrade_id: envelope.UpgradeId = @splat(0x6c);
    var prepared = try prepareGraph(std.testing.allocator, fixture.source(), GetCurrentProcess(), GetCurrentProcessId(), upgrade_id);
    defer prepared.deinit();
    var receiver = try Receiver.init(&prepared.body, .graph, &.{});
    defer receiver.deinit();
    var decoded = (try receiver.takeGraph(allocator, upgrade_id)).?;
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u64, 1), decoded.graph.id.serial);
}

test "Windows media custody decode allocation failures close the one-use section" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeAllocationSweep, .{});
}

fn nativeDecodeAllocationSweep(allocator: std.mem.Allocator) !void {
    var source = try nativeFixture(std.testing.allocator);
    defer source.deinit();
    const upgrade_id: envelope.UpgradeId = @splat(0x81);
    var prepared = try prepareNative(std.testing.allocator, &source, nativeLimits(), GetCurrentProcess(), GetCurrentProcessId(), upgrade_id);
    defer prepared.deinit();
    var receiver = try Receiver.init(&prepared.body, .native_physical, &.{});
    defer receiver.deinit();
    var decoded = (try receiver.takeNative(allocator, upgrade_id, nativeLimits())).?;
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u64, 1), decoded.physical_revision);
}

fn webrtcDecodeAllocationSweep(allocator: std.mem.Allocator) !void {
    var source = try webrtcFixture(std.testing.allocator);
    defer source.deinit();
    const upgrade_id: envelope.UpgradeId = @splat(0x82);
    var prepared = try prepareWebrtc(std.testing.allocator, &source, webrtcLimits(), GetCurrentProcess(), GetCurrentProcessId(), upgrade_id);
    defer prepared.deinit();
    var receiver = try Receiver.init(&prepared.body, .webrtc_physical, &.{});
    defer receiver.deinit();
    var decoded = (try receiver.takeWebrtc(allocator, upgrade_id, webrtcLimits())).?;
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u64, 1), decoded.physical_revision);
}

test "Windows media custody physical decode allocation failures consume handles" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nativeDecodeAllocationSweep, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, webrtcDecodeAllocationSweep, .{});
}
