// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux WebTransport Helix ownership controller. The daemon supplies only
//! physical accepted-socket lookups and the shared quiescent lifecycle cut.
//! No server, session, World, routing, or reactor implementation is imported.
//! A candidate owns verified descriptor duplicates and a parked worker before
//! commit; publishing TLS custody and releasing that worker cannot allocate.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const managed_wt = @import("webtransport_listener.zig");
const runtime_pause = @import("runtime_pause.zig");
const gate_mod = @import("runtime_start_gate.zig");
const os_runtime = @import("os_runtime.zig");
const linux_wt_checkpoint = @import("helix/linux_webtransport_checkpoint.zig");
const native_windows_tls_material = @import("helix/native_windows_tls_material.zig");
const native_windows_tls_proof = @import("helix/native_windows_tls_proof.zig");

pub const Ports = struct { irc: u16, webtransport: u16 };
pub const Accepted = linux_wt_checkpoint.AcceptedIrcSocket;
pub const AcceptedSockets = struct {
    context: *anyopaque,
    /// Exactly one ordinary daemon-side TCP endpoint opposite this bridge.
    findBridgePeer: *const fn (*anyopaque, managed_wt.BridgeIdentity) anyerror!Accepted,
    /// Exactly one adopted ordinary client with this physical descriptor ID.
    findByFd: *const fn (*anyopaque, usize) anyerror!Accepted,
};

/// Main owns the stable slot and destroys its listener before unregistering.
/// This controller owns the inherited worker Gate and retained TLS generation.
pub const Controller = struct {
    slot: ?*?managed_wt.WebTransportListener = null,
    pause_epoch: u64 = 0,
    gate: ?gate_mod.Created = null,
    tls: ?native_windows_tls_material.Owned = null,

    pub fn register(self: *Controller, slot: ?*?managed_wt.WebTransportListener) !void {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        if (slot != null and self.slot != null) return error.ConfiguredOwnerMismatch;
        if (slot == null) {
            if (self.gate != null) return error.InvalidRuntime;
            if (self.tls) |*material| material.deinit();
            self.tls = null;
        }
        self.slot = slot;
    }

    pub fn owner(self: *Controller) ?*managed_wt.WebTransportListener {
        const slot = self.slot orelse return null;
        return if (slot.*) |*listener| listener else null;
    }

    pub fn stopWorker(self: *Controller) void {
        const gate = self.gate orelse return;
        const listener = self.owner() orelse unreachable;
        listener.requestStopAndWake();
        if (gate.view.inspect().phase == .preparing) gate.control.cancelAllAndJoin() else gate.control.joinAll();
        listener.detachAfterJoined() catch @panic("Linux WebTransport worker could not detach");
        gate.control.destroyJoined();
        self.gate = null;
    }

    pub fn rollbackCandidate(self: *Controller) void {
        self.stopWorker();
        self.slot.?.*.?.deinit();
        self.slot.?.* = null;
    }

    /// Transfer complete TLS custody at the whole-server no-fail commit edge.
    /// Fresh QUIC admissions use this source generation as well as carried ones.
    pub fn commitTls(self: *Controller, material: *?native_windows_tls_material.Owned) void {
        std.debug.assert(self.tls == null);
        self.tls = material.*;
        material.* = null;
    }

    pub fn releaseWorker(self: *Controller) void {
        if (self.gate) |gate| gate.control.releaseAll();
    }

    /// Retire references without shutdown: duplicates share the same socket.
    pub fn retireReferences(udp_fd: linux.fd_t, bridges: []const linux_wt_checkpoint.BridgeFd) void {
        os_runtime.close(udp_fd);
        for (bridges) |bridge| os_runtime.close(bridge.fd);
    }

    pub fn retainedTls(material: *const native_windows_tls_material.Owned) !managed_wt.TlsConfig {
        const loaded = material.default orelse return error.InvalidRuntime;
        if (material.tls12_mode != .disabled or material.generated_tls12 != null or
            material.reload_pending or material.reload_retry_after_ms != 0) return error.InvalidRuntime;
        const key: @import("../proto/quic_handshake.zig").SigningKey = switch (loaded.key_kind) {
            .ed25519 => .{ .ed25519 = loaded.signing_key orelse return error.InvalidRuntime },
            .ecdsa_p256 => .{ .ecdsa_p256 = loaded.ecdsa_p256_signing_key orelse return error.InvalidRuntime },
            .rsa => .{ .rsa = loaded.rsa_signing_key orelse return error.InvalidRuntime },
        };
        return .{ .cert_chain = loaded.cert_chain, .signing_key = key };
    }

    pub fn encodeTls(allocator: std.mem.Allocator, tls: managed_wt.TlsConfig) ![]u8 {
        var material = native_windows_tls_proof.Material{ .cert_chain = tls.cert_chain };
        switch (tls.signing_key) {
            .ed25519 => |*key| material.signing_key = key,
            .ecdsa_p256 => |*key| material.ecdsa_p256_signing_key = key,
            .rsa => |*key| material.rsa_signing_key = key,
        }
        return native_windows_tls_material.encodeSnapshot(allocator, .{ .default = material, .tls12_mode = .disabled });
    }

    pub fn capture(self: *Controller, allocator: std.mem.Allocator, token: runtime_pause.Token, sockets: AcceptedSockets) !linux_wt_checkpoint.Body {
        const listener = self.owner() orelse return error.ConfiguredOwnerMismatch;
        var snapshot = try listener.capturePausedActive(token, allocator);
        errdefer snapshot.deinit(allocator);
        var bridges: std.ArrayList(linux_wt_checkpoint.BridgeFd) = .empty;
        errdefer bridges.deinit(allocator);
        var accepted: std.ArrayList(Accepted) = .empty;
        errdefer accepted.deinit(allocator);
        for (snapshot.connections) |row| {
            const bridge = row.bridge orelse continue;
            const fd = std.math.cast(linux.fd_t, bridge.source_socket) orelse return error.InvalidInheritedHandoff;
            try bridges.append(allocator, try managed_wt.observeInheritedBridge(row.slot, fd));
            try accepted.append(allocator, try sockets.findBridgePeer(sockets.context, bridge));
        }
        const Sort = struct {
            fn less(_: void, left: Accepted, right: Accepted) bool {
                return left.fd < right.fd;
            }
        };
        std.mem.sort(Accepted, accepted.items, {}, Sort.less);
        const bridge_rows = try bridges.toOwnedSlice(allocator);
        errdefer allocator.free(bridge_rows);
        return .{
            .snapshot = snapshot,
            .udp_fd = listener.socket.?.fd,
            .bridges = bridge_rows,
            .accepted = try accepted.toOwnedSlice(allocator),
        };
    }

    pub fn validateAcceptedJoin(body: *const linux_wt_checkpoint.Body, sockets: AcceptedSockets) !void {
        for (body.accepted) |row| {
            const observed = try sockets.findByFd(sockets.context, row.fd);
            if (observed.fd != row.fd or !managed_wt.TransportAddress.eql(observed.local, row.local) or
                !managed_wt.TransportAddress.eql(observed.peer, row.peer)) return error.InvalidInheritedHandoff;
        }
    }

    /// The candidate lives at main's final address before its dormant thread is
    /// spawned. Failure retracts the inert slot and every duplicate descriptor;
    /// no packet or IRC byte can be read before the server's no-fail commit.
    pub fn prepareCandidate(self: *Controller, allocator: std.mem.Allocator, io: std.Io, ports: Ports, body: *const linux_wt_checkpoint.Body, tls: managed_wt.TlsConfig) !void {
        if (comptime builtin.os.tag != .linux) return error.Unsupported;
        const slot = self.slot orelse return error.ConfiguredOwnerMismatch;
        if (slot.* != null or self.gate != null) return error.ConfiguredOwnerMismatch;
        const irc_port = ports.irc;
        const expected = managed_wt.WebTransportListener.init(allocator, tls, irc_port);
        if (body.snapshot.base.socket.primary.port != ports.webtransport) return error.ConfiguredOwnerMismatch;
        try body.snapshot.base.validateConfiguration(tls, .{
            .irc_port = irc_port,
            .send_proxy_header = expected.send_proxy_header,
            .echo_wt_datagrams = expected.echo_wt_datagrams,
            .max_connections = expected.max_connections,
            .retry_policy = expected.retry_policy,
            .retry_load_threshold = expected.retry_load_threshold,
            .reset_rate_per_s = expected.reset_rate_per_s,
            .reset_burst = expected.reset_burst,
        });
        const duplicate_rc = linux.fcntl(body.udp_fd, posix.F.DUPFD_CLOEXEC, 0);
        if (linux.errno(duplicate_rc) != .SUCCESS) return error.InvalidInheritedHandoff;
        const duplicate: linux.fd_t = @intCast(duplicate_rc);
        var candidate = try managed_wt.WebTransportListener.initInherited(allocator, tls, duplicate, null, &body.snapshot.base);
        errdefer candidate.deinit();
        try candidate.prepareActiveConnectionsInherited(&body.snapshot, body.bridges);
        try candidate.prepareInheritedResources(io);
        slot.* = candidate;
        errdefer slot.* = null;
        const listener = &slot.*.?;
        const specs = [_]gate_mod.ParticipantSpec{.{ .kind = .webtransport, .instance = 0, .owner_identity = listener, .options = managed_wt.dormant_spawn_options }};
        const gate = try gate_mod.create(allocator, io, &specs);
        errdefer {
            listener.requestStopAndWake();
            gate.control.cancelAllAndJoin();
            listener.detachAfterJoined() catch unreachable;
            // candidate is an alias until this function succeeds; its defer
            // must observe the detached runtime after the worker has joined.
            candidate = listener.*;
            gate.control.destroyJoined();
        }
        try listener.prepareDormantWorker(gate.control, gate.view, try gate.view.slot(.webtransport, 0, listener));
        try gate.control.awaitAllParked(std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(30_000) }));
        self.gate = gate;
    }
};
