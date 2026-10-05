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
        var sent = try bootstrap.sendWithWalDigestMetricsWebhookHistoryAndUdp(
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
            self.deadline,
        );
        const digest = try driver.sourceDigestWithWalConfigMetricsWebhookHistoryAndUdp(
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
        );
        const ready = driver.parentAwaitReady(candidate, digest, rows.len, self.deadline) catch |err| {
            std.debug.print("onyx-server: Windows Helix READY failed: {s}\n", .{@errorName(err)});
            return err;
        };
        return try driver.parentCommitAndExit(candidate, ready, self.deadline);
    }
};
