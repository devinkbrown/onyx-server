// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated, one-use Windows Helix custody for a paused active QUIC/H3
//! listener graph and its complete UDP + IRC bridge SOCKET transfer manifest.
//! The source retains all physical sockets until the whole server commits.
//! This module stages private candidate state only; it does not publish a
//! listener or weaken the active-QUIC guard in the existing runtime cut.

const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const listener = @import("../webtransport_listener.zig");
const io_backend = @import("../io_backend.zig");
const runtime_pause = @import("../runtime_pause.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const codec = @import("native_windows_active_webtransport_snapshot.zig");
const udp = @import("native_windows_udp_socket.zig");
const tcp = @import("native_windows_socket.zig");

const magic = "HXQC";
const version: u16 = 2;
const kind: u8 = 1;
pub const frame_len: usize = 96;
pub const Frame = [frame_len]u8;
const invalid_handle = std.math.maxInt(usize);

comptime {
    if (frame_len > @import("native_windows_control.zig").max_body)
        @compileError("Windows active WebTransport custody exceeds authenticated control frame");
}

extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = arena_mod.Error || codec.Error || udp.Error || tcp.Error || platform.EntropyError || error{
    InvalidTarget,
    InvalidFrame,
    InvalidSnapshot,
    DigestMismatch,
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
        self.* = undefined;
    }
};

/// Canonical observations of inherited, already-adopted IRC-side TCP clients.
/// The whole runtime must observe the actual candidate fd before READY and
/// provide every candidate client row (not only suspected WebTransport peers).
pub const AcceptedIrcSocket = codec.AcceptedIrcSocket;

fn canonicalTcpEndpoint(endpoint: io_backend.WindowsTcpEndpoint) !listener.TransportAddress {
    const bytes: []const u8 = switch (endpoint.address) {
        .ipv4 => |*address| address,
        .ipv6 => |*address| blk: {
            const mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            if (std.mem.eql(u8, address[0..12], &mapped)) break :blk address[12..16];
            break :blk address;
        },
    };
    return listener.TransportAddress.fromBytes(bytes, endpoint.port);
}

fn authenticatedPeerForSocket(peer: listener.TransportAddress, local: io_backend.WindowsTcpEndpoint) Error!io_backend.WindowsTcpEndpoint {
    if (peer.ip_len != 4 and peer.ip_len != 16) return error.InvalidSnapshot;
    const address: io_backend.PeerAddress = switch (local.address) {
        .ipv4 => blk: {
            if (peer.ip_len != 4) return error.InvalidSnapshot;
            break :blk .{ .ipv4 = peer.ip[0..4].* };
        },
        .ipv6 => blk: {
            if (peer.ip_len == 16) break :blk .{ .ipv6 = peer.ip };
            var mapped: [16]u8 = @splat(0);
            mapped[10] = 0xff;
            mapped[11] = 0xff;
            @memcpy(mapped[12..16], peer.ip[0..4]);
            break :blk .{ .ipv6 = mapped };
        },
    };
    return .{ .address = address, .port = peer.port };
}

/// Observe an adopted canonical IRC client descriptor through the existing
/// Windows getsockname/getpeername verifier, then normalize IPv4-mapped IPv6
/// to the same four-byte address representation as the listener bridge.
pub fn observeAcceptedIrcSocket(fd: usize) !AcceptedIrcSocket {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const canonical = std.math.cast(std.os.linux.fd_t, fd) orelse return error.InvalidSnapshot;
    const observed = try io_backend.observeWindowsConnectedTcpSocket(canonical);
    return .{
        .fd = fd,
        .local = try canonicalTcpEndpoint(observed.local),
        .peer = try canonicalTcpEndpoint(observed.peer),
    };
}

/// Require a one-to-one reverse TCP four-tuple for each live bridge. This is
/// the join between the listener's outgoing loopback SOCKET and the daemon's
/// accepted IRC client. A missing, duplicate, or reused client refuses READY.
pub fn validateAcceptedJoin(snapshot: *const listener.ActiveSnapshot, accepted: []const AcceptedIrcSocket) Error!void {
    try codec.validateAcceptedJoin(snapshot, accepted);
}

/// Revalidate an adopted canonical descriptor against the authenticated source
/// roster. AcceptEx can omit getpeername after WSADuplicateSocket; in that case
/// SO_CONNECT_TIME proves the imported socket is connected, while its actual
/// canonical fd and local endpoint must still match the source's exact row.
pub fn verifyImportedAcceptedIrcSocket(fd: usize, expected: AcceptedIrcSocket) Error!AcceptedIrcSocket {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    try codec.validateAcceptedRow(expected);
    if (fd != expected.fd) return error.InvalidSnapshot;
    const canonical = std.math.cast(std.os.linux.fd_t, fd) orelse return error.InvalidSnapshot;
    const observed = io_backend.observeWindowsHelixConnectedTcpSocketEndpoints(canonical) catch return error.InvalidSnapshot;
    const local = canonicalTcpEndpoint(observed.local) catch return error.InvalidSnapshot;
    if (!listener.TransportAddress.eql(local, expected.local)) return error.InvalidSnapshot;
    if (observed.peer) |peer| {
        const physical_peer = canonicalTcpEndpoint(peer) catch return error.InvalidSnapshot;
        if (!listener.TransportAddress.eql(physical_peer, expected.peer)) return error.InvalidSnapshot;
    }
    const witness = try authenticatedPeerForSocket(expected.peer, observed.local);
    io_backend.rememberWindowsHelixAcceptedTcpPeer(canonical, observed.local, witness) catch return error.InvalidSnapshot;
    return expected;
}

pub fn absentFrame() Frame {
    var body: Frame = @splat(0);
    @memcpy(body[0..4], magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    body[6] = kind;
    return body;
}

fn presentFrame(target_pid: u32, bridge_count: usize, remote_handle: usize, wire_size: usize, key: envelope.Key, digest: [32]u8) Frame {
    var body = absentFrame();
    body[7] = 1;
    std.mem.writeInt(u32, body[8..12], target_pid, .big);
    std.mem.writeInt(u32, body[12..16], @intCast(bridge_count), .big);
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

/// The source pump must be paused under this exact token. It cannot admit a
/// packet or bridge event until the encompassing transaction commits/aborts.
/// Every duplicate is PID-scoped; its provider record is encrypted inside the
/// read-only arena and the compact HXWC frame travels on private Helix control.
pub fn prepare(
    allocator: std.mem.Allocator,
    owner: *listener.WebTransportListener,
    token: runtime_pause.Token,
    accepted: []const AcceptedIrcSocket,
    target_process: usize,
    target_pid: u32,
    upgrade_id: envelope.UpgradeId,
) Error!Prepared {
    try validateTarget(target_process, target_pid);
    var snapshot = owner.capturePausedActive(token, allocator) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidSnapshot;
    var snapshot_owned = true;
    defer if (snapshot_owned) snapshot.deinit(allocator);
    if (accepted.len > codec.max_accepted_clients) return error.InvalidSnapshot;
    for (accepted) |entry| {
        const current = observeAcceptedIrcSocket(entry.fd) catch return error.InvalidSnapshot;
        if (!listener.TransportAddress.eql(current.local, entry.local) or
            !listener.TransportAddress.eql(current.peer, entry.peer)) return error.InvalidSnapshot;
    }
    const accepted_copy = try allocator.dupe(AcceptedIrcSocket, accepted);
    var accepted_owned = true;
    defer if (accepted_owned) allocator.free(accepted_copy);
    std.mem.sort(AcceptedIrcSocket, accepted_copy, {}, struct {
        fn less(_: void, a: AcceptedIrcSocket, b: AcceptedIrcSocket) bool {
            return a.fd < b.fd;
        }
    }.less);
    try codec.validateSortedAccepted(&snapshot, accepted_copy);
    const socket = owner.socket orelse return error.InvalidSnapshot;
    if (socket.fd == invalid_handle or socket.ipv4_fd != invalid_handle or
        snapshot.base.socket.primary.device != socket.fd) return error.InvalidSnapshot;
    var udp_transfer = try udp.duplicateForProcess(socket.fd, target_pid);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&udp_transfer.info));
    var bridges: std.ArrayList(listener.BridgeTransfer) = .empty;
    defer {
        for (bridges.items) |*bridge| std.crypto.secureZero(u8, std.mem.asBytes(&bridge.transfer.info));
        bridges.deinit(allocator);
    }
    for (snapshot.connections) |row| if (row.bridge) |bridge| {
        const duplicate = try tcp.duplicateForProcess(bridge.source_socket, target_pid);
        try bridges.append(allocator, .{
            .slot = row.slot,
            .source_socket = bridge.source_socket,
            .target_pid = target_pid,
            .transfer = duplicate,
        });
    };
    var body: codec.Body = .{
        .snapshot = snapshot,
        .udp_transfer = udp_transfer,
        .bridges = try bridges.toOwnedSlice(allocator),
        .accepted = accepted_copy,
    };
    snapshot_owned = false;
    accepted_owned = false;
    defer body.deinit(allocator);
    const plaintext = try codec.encode(allocator, &body, owner.tls, target_pid);
    defer codec.freeEncoded(allocator, plaintext);
    var digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});
    var sealer = try envelope.Sealer.initRandom();
    errdefer sealer.deinit();
    sealer.upgrade_id = upgrade_id;
    var arena = try arena_mod.Arena.create(allocator, &sealer, plaintext);
    errdefer arena.deinit();
    const remote = try arena.duplicateReadOnlyForProcess(target_process);
    return .{ .arena = arena, .sealer = sealer, .body = presentFrame(target_pid, body.bridges.len, remote, arena.size, sealer.key, digest) };
}

const Parsed = struct {
    handle: usize,
    size: usize,
    bridge_count: usize,
    key: envelope.Key,
    digest: [32]u8,
};

fn parseFrame(bytes: []const u8, target_pid: u32, forbidden: []const usize) Error!?Parsed {
    if (bytes.len != frame_len or !std.mem.eql(u8, bytes[0..4], magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or bytes[6] != kind) return error.InvalidFrame;
    if (bytes[7] == 0) {
        const canonical = absentFrame();
        if (!std.mem.eql(u8, bytes, &canonical)) return error.InvalidFrame;
        return null;
    }
    if (bytes[7] != 1 or target_pid == 0 or std.mem.readInt(u32, bytes[8..12], .big) != target_pid)
        return error.InvalidFrame;
    const bridge_count: usize = std.mem.readInt(u32, bytes[12..16], .big);
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[16..24], .big)) orelse return error.InvalidFrame;
    const size = std.math.cast(usize, std.mem.readInt(u64, bytes[24..32], .big)) orelse return error.InvalidFrame;
    if (bridge_count > listener.snapshot_max_slots or handle == 0 or handle == invalid_handle or
        size <= envelope.header_len + envelope.tag_len or
        size > envelope.header_len + envelope.tag_len + codec.max_wire_bytes) return error.InvalidFrame;
    for (forbidden) |reserved| if (reserved == handle) return error.InvalidFrame;
    return .{ .handle = handle, .size = size, .bridge_count = bridge_count, .key = bytes[32..64].*, .digest = bytes[64..96].* };
}

/// READY preflight on authenticated private control bytes. No section HANDLE
/// is consumed and no socket is imported by this check.
pub fn validateFrame(bytes: []const u8, target_pid: u32) Error!bool {
    return (try parseFrame(bytes, target_pid, &.{})) != null;
}

/// Owns one candidate section HANDLE from private control. A failed open or
/// decode consumes the handle and leaves the predecessor untouched.
pub const Receiver = struct {
    parsed: ?Parsed,
    claimed: bool = false,

    pub fn init(bytes: []const u8, forbidden: []const usize) Error!Receiver {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        return .{ .parsed = try parseFrame(bytes, GetCurrentProcessId(), forbidden) };
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

    pub fn take(self: *Receiver, allocator: std.mem.Allocator, tls: listener.TlsConfig, upgrade_id: envelope.UpgradeId) Error!?codec.Body {
        if (self.claimed) return error.AlreadyClaimed;
        self.claimed = true;
        const record = if (self.parsed) |*value| value else return null;
        defer {
            _ = CloseHandle(record.handle);
            record.handle = 0;
            std.crypto.secureZero(u8, &record.key);
        }
        const plaintext = try arena_mod.read(allocator, record.handle, record.size, record.key, upgrade_id);
        defer codec.freeEncoded(allocator, plaintext);
        if (plaintext.len == 0 or plaintext.len > codec.max_wire_bytes) return error.InvalidSnapshot;
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, record.digest)) return error.DigestMismatch;
        var body = try codec.decode(allocator, plaintext, tls, GetCurrentProcessId());
        errdefer body.deinit(allocator);
        if (body.bridges.len != record.bridge_count) return error.InvalidSnapshot;
        return body;
    }
};

test "HXQC control frame is exact, PID-bound, and role-specific" {
    const pid: u32 = 71;
    var absent = absentFrame();
    try std.testing.expect(!(try validateFrame(&absent, pid)));
    absent[frame_len - 1] = 1;
    try std.testing.expectError(error.InvalidFrame, validateFrame(&absent, pid));
    const framed = presentFrame(pid, 1, 17, envelope.header_len + envelope.tag_len + 8, @splat(0x31), @splat(0x42));
    try std.testing.expect(try validateFrame(&framed, pid));
    try std.testing.expectError(error.InvalidFrame, validateFrame(&framed, pid + 1));
    var tampered = framed;
    tampered[6] ^= 1;
    try std.testing.expectError(error.InvalidFrame, validateFrame(&tampered, pid));
    tampered = framed;
    tampered[5] ^= 1;
    try std.testing.expectError(error.InvalidFrame, validateFrame(&tampered, pid));
    tampered = framed;
    std.mem.writeInt(u32, tampered[12..16], @intCast(listener.snapshot_max_slots + 1), .big);
    try std.testing.expectError(error.InvalidFrame, validateFrame(&tampered, pid));
}

test "HXQC bridge join requires exactly one reverse accepted TCP four-tuple" {
    const bridge_local = try listener.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 50001);
    const bridge_peer = try listener.TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 6667);
    var rows: [1]listener.ActiveConnectionSnapshot = undefined;
    rows[0].bridge = .{ .source_socket = 17, .local = bridge_local, .peer = bridge_peer };
    var snapshot: listener.ActiveSnapshot = undefined;
    snapshot.connections = &rows;
    const accepted = AcceptedIrcSocket{ .fd = 31, .local = bridge_peer, .peer = bridge_local };
    try validateAcceptedJoin(&snapshot, &.{accepted});
    try std.testing.expectError(error.InvalidSnapshot, validateAcceptedJoin(&snapshot, &.{}));
    try std.testing.expectError(error.InvalidSnapshot, validateAcceptedJoin(&snapshot, &.{ accepted, accepted }));
    var wrong = accepted;
    wrong.peer.port +%= 1;
    try std.testing.expectError(error.InvalidSnapshot, validateAcceptedJoin(&snapshot, &.{wrong}));
    wrong = accepted;
    wrong.local.ip_len = 17;
    try std.testing.expectError(error.InvalidSnapshot, validateAcceptedJoin(&snapshot, &.{wrong}));
    rows[0].bridge = null;
    try std.testing.expectError(error.InvalidSnapshot, validateAcceptedJoin(&snapshot, &.{ accepted, accepted }));
}

test "HXQC read-only arena authenticates a paused listener before importing UDP" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const x509_selfsign = @import("../../proto/x509_selfsign.zig");
    const key = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "wt.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = key,
        .dns_names = &.{"wt.test"},
        .is_ca = true,
    });
    const chain = [_][]const u8{cert};
    const tls: listener.TlsConfig = .{ .cert_chain = &chain, .signing_key = .{ .ed25519 = key } };
    var source = listener.WebTransportListener.init(allocator, tls, 6667);
    defer source.deinit();
    try source.prepareColdResources(std.testing.io, .{ .v4_mapped = .{ 127, 0, 0, 1 } }, 0);
    try source.startPreparedLegacyWorker();
    const pause = try source.requestPause(42);
    try source.awaitPaused(pause, std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    defer source.resumePaused(pause) catch {};
    const pid = GetCurrentProcessId();
    const upgrade_id: envelope.UpgradeId = @splat(0x76);
    var prepared = try prepare(allocator, &source, pause, &.{}, GetCurrentProcess(), pid, upgrade_id);
    defer prepared.deinit();
    var receiver = try Receiver.init(&prepared.body, &.{});
    defer receiver.deinit();
    var received = (try receiver.take(allocator, tls, upgrade_id)) orelse return error.MissingActiveBody;
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), received.snapshot.connections.len);
    try std.testing.expectError(error.AlreadyClaimed, receiver.take(allocator, tls, upgrade_id));
    var candidate = try listener.WebTransportListener.initTransferred(allocator, tls, &received.udp_transfer, &received.snapshot.base);
    defer candidate.deinit();
    try candidate.prepareActiveConnectionsWindows(&received.snapshot, received.bridges);
    try std.testing.expect(received.udp_transfer.consumed);
    try std.testing.expectError(error.InvalidTarget, prepare(allocator, &source, pause, &.{}, 0, pid, upgrade_id));
}
