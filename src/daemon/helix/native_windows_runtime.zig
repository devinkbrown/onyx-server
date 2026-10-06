// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows full-daemon Helix producer. All mutable server owners are quiescent
//! while this leaf serializes state and duplicates live socket/WAL custody.
const std = @import("std");
const builtin = @import("builtin");
const server = @import("../server.zig");
const io_backend = @import("../io_backend.zig");
const platform = @import("../../substrate/platform.zig");
const live = @import("live.zig");
const capsule = @import("capsule.zig");
const session_snapshot = @import("session_snapshot.zig");
const s2s_snapshot = @import("s2s_snapshot.zig");
const envelope = @import("native_arena_envelope.zig");
const arena_mod = @import("native_windows_arena.zig");
const bootstrap = @import("native_windows_bootstrap.zig");
const process = @import("native_windows_process.zig");
const driver = @import("native_windows_driver.zig");
const store = @import("../store.zig");
const metrics_mod = @import("native_windows_metrics.zig");
const webhook_mod = @import("native_windows_webhook.zig");
const history_mod = @import("native_windows_history.zig");
const udp_mod = @import("native_windows_udp_custody.zig");
const active_wt_custody = @import("native_windows_active_webtransport_custody.zig");
const media_custody = @import("native_windows_media_custody.zig");
const active_media_udp = @import("native_windows_active_media_udp_custody.zig");

/// The three detached media bodies must describe the same physical endpoints
/// before any one of them is sealed for the candidate. Socket continuity and
/// publication remain separate, guarded transaction steps.
fn validateActiveMediaSource(source: server.NativeWindowsActiveMediaCarry) !void {
    try source.native_owner.runtime.pause.requirePaused(source.native_token);
    try source.webrtc_owner.runtime.pause.requirePaused(source.webrtc_token);
    try source.native_transport.validate();
    const native_socket = source.native_owner.socket orelse return error.InvalidSnapshot;
    const webrtc_socket = source.webrtc_owner.socket orelse return error.InvalidSnapshot;
    if (source.native_transport.socket.device != native_socket.fd or source.webrtc.socket.device != webrtc_socket.fd or
        source.native_transport.socket.inode != 0 or source.webrtc.socket.inode != 0 or
        native_socket.fd == webrtc_socket.fd) return error.InvalidSnapshot;
    try source.graph.validate();
    try source.native.validate(source.native_limits.max_participants, source.native_limits.max_state_bytes);
    try source.webrtc.validate(source.webrtc_limits);
    const physical_count = std.math.add(usize, source.native.endpoints.len, source.webrtc.rows.len) catch return error.InvalidSnapshot;
    if (source.graph.graph.endpoints.len != physical_count) {
        std.debug.print("onyx-server: Windows active media endpoint count mismatch: graph={d} native={d} webrtc={d}\n", .{ source.graph.graph.endpoints.len, source.native.endpoints.len, source.webrtc.rows.len });
        return error.InvalidSnapshot;
    }
    for (source.graph.graph.endpoints, 0..) |endpoint, endpoint_index| {
        var profile_count: usize = 0;
        for (source.graph.rooms.physical_profiles) |profile| if (std.meta.eql(profile.key, endpoint.key)) {
            profile_count += 1;
        };
        if (profile_count != 1) {
            std.debug.print("onyx-server: Windows active media graph endpoint {d} ({s}) has {d} room profiles\n", .{ endpoint_index, @tagName(endpoint.key.leg), profile_count });
            return error.InvalidSnapshot;
        }
        var physical_matches: usize = 0;
        switch (endpoint.key.leg) {
            .native => for (source.native.endpoints) |physical| if (std.meta.eql(physical.key, endpoint.key)) {
                if (!std.meta.eql(physical.identity, endpoint.row.observation)) {
                    std.debug.print("onyx-server: Windows active media native endpoint {d} observation mismatch\n", .{endpoint_index});
                    return error.InvalidSnapshot;
                }
                for (source.graph.rooms.physical_profiles) |profile| if (std.meta.eql(profile.key, endpoint.key) and
                    !profile.profile.eql(physical.profile))
                {
                    std.debug.print("onyx-server: Windows active media native endpoint {d} negotiated profile mismatch\n", .{endpoint_index});
                    return error.InvalidSnapshot;
                };
                physical_matches += 1;
            },
            .webrtc => for (source.webrtc.rows) |physical| if (std.meta.eql(physical.key, endpoint.key)) {
                if (!std.meta.eql(physical.identity, endpoint.row.observation)) {
                    std.debug.print("onyx-server: Windows active media WebRTC endpoint {d} observation mismatch\n", .{endpoint_index});
                    return error.InvalidSnapshot;
                }
                for (source.graph.rooms.physical_profiles) |profile| if (std.meta.eql(profile.key, endpoint.key) and
                    !profile.profile.eql(physical.profile))
                {
                    std.debug.print("onyx-server: Windows active media WebRTC endpoint {d} negotiated profile mismatch\n", .{endpoint_index});
                    return error.InvalidSnapshot;
                };
                physical_matches += 1;
            },
        }
        if (physical_matches != 1) {
            std.debug.print("onyx-server: Windows active media graph endpoint {d} ({s}) has {d} physical rows\n", .{ endpoint_index, @tagName(endpoint.key.leg), physical_matches });
            return error.InvalidSnapshot;
        }
    }
}

pub const timeout_ms: i64 = 30_000;

pub const Driver = struct {
    allocator: std.mem.Allocator,
    config_path: ?[]const u8 = null,
    source_digest: ?[32]u8 = null,
    candidate: ?process.Process = null,
    deadline: i64 = 0,

    pub fn hooks(self: *Driver) server.NativeUpgradeHooks {
        return .{ .ctx = self, .begin = begin, .transferAndCommit = transferAndCommit, .abort = abort };
    }

    fn begin(ctx: *anyopaque, executable: []const u8) !void {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        const self: *Driver = @ptrCast(@alignCast(ctx));
        if (self.candidate != null) return error.UpgradeAlreadyActive;
        if (self.source_digest == null or self.config_path == null or self.config_path.?.len == 0)
            return error.UnprovenConfigSource;
        self.deadline = platform.monotonicMillis() + timeout_ms;
        const generation: u64 = @intCast(@max(1, platform.monotonicMillis()));
        self.candidate = try process.Process.spawn(self.allocator, executable, self.config_path, generation, self.deadline);
    }

    fn abort(ctx: *anyopaque) void {
        const self: *Driver = @ptrCast(@alignCast(ctx));
        if (self.candidate) |*candidate| candidate.deinit();
        self.candidate = null;
    }

    fn stateRole(pieces: []const live.StatePiece, fd: i32) !bootstrap.Role {
        var role: ?bootstrap.Role = null;
        for (pieces) |piece| {
            const owned_fd = switch (piece.kind) {
                .clients => session_snapshot.peekFd(piece.bytes),
                .s2s_link => s2s_snapshot.peekFd(piece.bytes),
                else => null,
            };
            if (owned_fd != null and owned_fd.? == fd) {
                if (role != null) return error.DuplicateStateOwner;
                role = if (piece.kind == .clients) .client else .s2s_state;
            }
        }
        return role orelse error.MissingStateOwner;
    }

    fn lessRow(_: void, a: bootstrap.SourceRow, b: bootstrap.SourceRow) bool {
        return a.canonical < b.canonical;
    }

    fn transferAndCommit(ctx: *anyopaque, snapshot: server.NativeUpgradeSnapshot) !noreturn {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        const self: *Driver = @ptrCast(@alignCast(ctx));
        const candidate = if (self.candidate) |*p| p else return error.NoCandidate;
        const source_digest = snapshot.windows_source_digest orelse return error.UnprovenConfigSource;
        if (self.source_digest == null or
            !std.crypto.timing_safe.eql([32]u8, self.source_digest.?, source_digest))
            return error.UnprovenConfigSource;
        for (snapshot.pieces) |piece| if (piece.kind == .native_service) return error.UnboundNativeService;

        var manifested = try live.appendHandoffManifest(self.allocator, snapshot.pieces);
        defer manifested.deinit(self.allocator);
        var plaintext: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, plaintext.items);
            plaintext.deinit(self.allocator);
        }
        for (manifested.pieces) |piece| {
            var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
            var cap = capsule.make(piece.kind, &fields);
            if (piece.min_supported) |minimum| cap.header.min_supported = minimum;
            const encoded = try capsule.encode(self.allocator, cap);
            defer {
                std.crypto.secureZero(u8, encoded);
                self.allocator.free(encoded);
            }
            if (encoded.len > live.max_arena_bytes - plaintext.items.len) return error.ArenaTooLarge;
            try plaintext.appendSlice(self.allocator, encoded);
        }

        const rows = try self.allocator.alloc(bootstrap.SourceRow, snapshot.state_fds.len + snapshot.listeners.len);
        defer self.allocator.free(rows);
        for (snapshot.state_fds, 0..) |fd, index| {
            // AcceptEx sockets can have a missing peer sockaddr even on the
            // original owner. SO_CONNECT_TIME proves established TCP state.
            try io_backend.observeWindowsHelixConnectedTcpSocket(fd);
            rows[index] = .{
                .canonical = fd,
                .socket = try io_backend.helixWindowsSourceSocket(fd),
                .role = try stateRole(snapshot.pieces, fd),
            };
        }
        for (snapshot.listeners, 0..) |listener, index| {
            _ = try io_backend.observeWindowsListeningTcpSocket(listener.fd);
            rows[snapshot.state_fds.len + index] = .{
                .canonical = listener.fd,
                .socket = try io_backend.helixWindowsSourceSocket(listener.fd),
                .shard = listener.shard,
                .family = @intFromEnum(listener.family),
                .role = switch (listener.kind) {
                    .plain => .plain_listener,
                    .tls => .tls_listener,
                    .ws => .websocket_listener,
                    .s2s => .s2s_listener,
                },
            };
        }
        std.mem.sort(bootstrap.SourceRow, rows, {}, lessRow);

        var sealer = try envelope.Sealer.initRandom();
        defer sealer.deinit();
        sealer.upgrade_id = candidate.identity.upgrade_id;
        var arena = try arena_mod.Arena.create(self.allocator, &sealer, plaintext.items);
        defer arena.deinit();

        var wal_transfer: ?store.WindowsWalTransfer = null;
        defer if (wal_transfer) |*transfer| transfer.deinit();
        // A failed transfer must reap the child before closing its remote WAL
        // duplicate, while retaining the process HANDLE for DuplicateHandle.
        // The outer upgrade abort closes that HANDLE after this frame unwinds.
        errdefer candidate.reapUncommitted();
        if (snapshot.windows_account_store) |account_store|
            wal_transfer = try account_store.duplicatePrivateWalToWindowsProcess(candidate.process_handle);
        var metrics_prepared: ?metrics_mod.Prepared = null;
        defer if (metrics_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_metrics) |source|
            metrics_prepared = try metrics_mod.prepareSource(
                self.allocator,
                .{ .owner = source.owner, .carry = source.carry },
                candidate.process_handle,
                candidate.pid,
                candidate.identity.upgrade_id,
            );
        var webhook_prepared: ?webhook_mod.Prepared = null;
        defer if (webhook_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_webhook) |source|
            webhook_prepared = try webhook_mod.prepareSource(
                .{ .owner = source.owner, .carry = source.carry, .pause_token = source.pause_token },
                candidate.process_handle,
                candidate.pid,
            );
        var history_prepared: ?history_mod.Prepared = null;
        defer if (history_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_history) |source|
            history_prepared = try history_mod.prepareSource(
                .{ .owner = source.owner, .carry = source.carry, .pause_token = source.pause_token },
                candidate.process_handle,
                candidate.pid,
            );
        var wt_prepared: ?udp_mod.Prepared = null;
        defer if (wt_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_udp.webtransport) |source|
            wt_prepared = try udp_mod.prepareWebtransport(self.allocator, .{ .owner = source.owner, .carry = source.carry, .pause_token = source.pause_token }, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id);
        if (wt_prepared != null and snapshot.windows_active_webtransport != null) return error.InvalidSnapshot;
        var wt_active_prepared: ?active_wt_custody.Prepared = null;
        defer if (wt_active_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_active_webtransport) |source| {
            var accepted: std.ArrayList(active_wt_custody.AcceptedIrcSocket) = .empty;
            defer accepted.deinit(self.allocator);
            for (rows) |row| {
                if (row.role != .client) continue;
                try accepted.append(self.allocator, try active_wt_custody.observeAcceptedIrcSocket(@intCast(row.canonical)));
            }
            wt_active_prepared = try active_wt_custody.prepare(
                self.allocator,
                source.owner,
                source.pause_token,
                accepted.items,
                candidate.process_handle,
                candidate.pid,
                candidate.identity.upgrade_id,
            );
        }
        if ((snapshot.windows_udp.webrtc_media != null) != (snapshot.windows_udp.native_media != null) or
            (snapshot.windows_udp.media_domain != null) != (snapshot.windows_udp.webrtc_media != null))
            return error.InvalidSnapshot;
        const media_proof: ?udp_mod.PristineMediaProof = if (snapshot.windows_udp.media_domain) |domain| .{
            .domain = domain,
            .webrtc = snapshot.windows_udp.webrtc_media.?.owner,
            .webrtc_token = snapshot.windows_udp.webrtc_media.?.pause_token orelse return error.InvalidSnapshot,
            .native = snapshot.windows_udp.native_media.?.owner,
            .native_token = snapshot.windows_udp.native_media.?.pause_token orelse return error.InvalidSnapshot,
        } else null;
        var webrtc_prepared: ?udp_mod.Prepared = null;
        defer if (webrtc_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_udp.webrtc_media) |source|
            webrtc_prepared = try udp_mod.prepareWebrtc(self.allocator, .{ .owner = source.owner, .carry = source.carry, .pause_token = source.pause_token, .pristine = media_proof }, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id);
        var native_prepared: ?udp_mod.Prepared = null;
        defer if (native_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_udp.native_media) |source|
            native_prepared = try udp_mod.prepareNative(self.allocator, .{ .owner = source.owner, .carry = source.carry, .pause_token = source.pause_token, .pristine = media_proof }, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id);
        var graph_prepared: ?media_custody.Prepared = null;
        defer if (graph_prepared) |*prepared| prepared.deinit();
        var native_physical_prepared: ?media_custody.Prepared = null;
        defer if (native_physical_prepared) |*prepared| prepared.deinit();
        var webrtc_physical_prepared: ?media_custody.Prepared = null;
        defer if (webrtc_physical_prepared) |*prepared| prepared.deinit();
        var active_native_udp_prepared: ?active_media_udp.Prepared = null;
        defer if (active_native_udp_prepared) |*prepared| prepared.deinit();
        var active_webrtc_udp_prepared: ?active_media_udp.Prepared = null;
        defer if (active_webrtc_udp_prepared) |*prepared| prepared.deinit();
        if (snapshot.windows_active_media) |source| {
            if (media_proof != null) return error.InvalidSnapshot;
            validateActiveMediaSource(source) catch |err| {
                std.debug.print("onyx-server: Windows active media source join rejected: {s}\n", .{@errorName(err)});
                return err;
            };
            graph_prepared = media_custody.prepareGraph(self.allocator, source.graph, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id) catch |err| {
                std.debug.print("onyx-server: Windows active media HXMG preparation failed: {s}\n", .{@errorName(err)});
                return err;
            };
            native_physical_prepared = media_custody.prepareNative(self.allocator, source.native, source.native_limits, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id) catch |err| {
                std.debug.print("onyx-server: Windows active media HXNA preparation failed: {s}\n", .{@errorName(err)});
                return err;
            };
            webrtc_physical_prepared = media_custody.prepareWebrtc(self.allocator, source.webrtc, source.webrtc_limits, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id) catch |err| {
                std.debug.print("onyx-server: Windows active media HXWA preparation failed: {s}\n", .{@errorName(err)});
                return err;
            };
            active_native_udp_prepared = active_media_udp.prepareNative(self.allocator, source.native_transport, &native_physical_prepared.?.body, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id) catch |err| {
                std.debug.print("onyx-server: Windows active media native HXAU preparation failed: {s}\n", .{@errorName(err)});
                return err;
            };
            active_webrtc_udp_prepared = active_media_udp.prepareWebrtc(self.allocator, source.webrtc, &webrtc_physical_prepared.?.body, candidate.process_handle, candidate.pid, candidate.identity.upgrade_id) catch |err| {
                std.debug.print("onyx-server: Windows active media WebRTC HXAU preparation failed: {s}\n", .{@errorName(err)});
                return err;
            };
        }
        var sent = try bootstrap.sendWithWalDigestMetricsWebhookHistoryUdpMediaAndActiveTransfers(
            candidate,
            &arena,
            &sealer,
            rows,
            if (wal_transfer) |*transfer| transfer else null,
            source_digest,
            if (metrics_prepared) |*prepared| prepared else null,
            if (webhook_prepared) |*prepared| prepared else null,
            if (history_prepared) |*prepared| prepared else null,
            .{
                .webtransport = if (wt_prepared) |*prepared| prepared else null,
                .webrtc_media = if (webrtc_prepared) |*prepared| prepared else null,
                .native_media = if (native_prepared) |*prepared| prepared else null,
            },
            .{
                .graph = if (graph_prepared) |*prepared| prepared else null,
                .native_physical = if (native_physical_prepared) |*prepared| prepared else null,
                .webrtc_physical = if (webrtc_physical_prepared) |*prepared| prepared else null,
            },
            .{
                .native = if (active_native_udp_prepared) |*prepared| prepared else null,
                .webrtc = if (active_webrtc_udp_prepared) |*prepared| prepared else null,
            },
            if (wt_active_prepared) |*prepared| prepared else null,
            self.deadline,
        );
        const digest = try driver.sourceDigestWithWalConfigMetricsWebhookHistoryUdpMediaAndActiveTransfers(
            plaintext.items,
            rows,
            if (sent.wal) |*descriptor| descriptor else null,
            candidate.pid,
            source_digest,
            sent.metrics_body,
            sent.webhook_body,
            sent.history_body,
            sent.webtransport_udp_body,
            sent.webrtc_media_udp_body,
            sent.native_media_udp_body,
            sent.media_graph_body,
            sent.native_physical_body,
            sent.webrtc_physical_body,
            sent.active_native_udp_body,
            sent.active_webrtc_udp_body,
            sent.active_webtransport_body,
        );
        const ready = driver.parentAwaitReady(candidate, digest, rows.len, self.deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix READY failed: {s}\n", .{@errorName(err)});
            return err;
        };
        return try driver.parentCommitAndExit(candidate, ready, self.deadline);
    }
};
