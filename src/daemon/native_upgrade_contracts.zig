// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed listener and native Helix handoff contracts.
//! Owners and snapshots are borrowed at the existing quiescent commit cut.

const std = @import("std");
const linux = std.os.linux;
const metrics_http = @import("metrics_http.zig");
const webhook_http = @import("webhook_http.zig");
const history_http = @import("history_http.zig");
const managed_wt = @import("webtransport_listener.zig");
const helix_media_graph = @import("helix/media_graph_checkpoint.zig");
const native_media_mod = @import("native_media_transport.zig");
const media_plane_mod = @import("media_plane.zig");
const helix_active_media = @import("helix/native_windows_active_media_snapshot.zig");
const media_routing = @import("../substrate/media_routing.zig");
const helix_live = @import("helix/live.zig");
const services_mod = @import("services.zig");

pub const ListenerKind = enum(u8) { plain, s2s, tls, ws };

pub const ListenerFamily = enum(u8) { ipv4 = 4, ipv6 = 6 };

/// Native Helix must transfer every listening socket, keyed by owner and role.
/// A wildcard OpenBSD endpoint has two rows with the same port and distinct
/// families; a numeric fd list alone cannot reconstruct its accept ownership.
pub const ListenerDescriptor = struct {
    shard: u12,
    kind: ListenerKind,
    family: ListenerFamily,
    fd: linux.fd_t,
};

/// Borrowed only for the duration of transferAndCommit, while every socket
/// owner is quiescent and World remains locked at the authoritative seal.
pub const NativeWindowsMetricsCarry = struct {
    owner: *metrics_http.MetricsServer,
    carry: *const metrics_http.Snapshot,
};

pub const NativeWindowsWebhookCarry = struct {
    owner: *webhook_http.WebhookServer,
    carry: *const webhook_http.Snapshot,
    pause_token: webhook_http.runtime_pause.Token,
};

pub const NativeWindowsHistoryCarry = struct {
    owner: *history_http.HttpsListener,
    carry: *const history_http.Snapshot,
    pause_token: history_http.runtime_pause.Token,
};

pub const NativeWindowsWebTransportCarry = struct {
    owner: *managed_wt.WebTransportListener,
    carry: *const managed_wt.Snapshot,
    pause_token: ?@import("runtime_pause.zig").Token = null,
};

pub const NativeWindowsActiveWebTransportCarry = struct {
    owner: *managed_wt.WebTransportListener,
    pause_token: @import("runtime_pause.zig").Token,
};

pub const NativeWindowsActiveMediaCarry = struct {
    graph: helix_media_graph.Source,
    native: *const native_media_mod.PhysicalSnapshot,
    webrtc: *const media_plane_mod.PhysicalSnapshot,
    native_transport: *const native_media_mod.PhysicalTransportSnapshot,
    native_owner: *native_media_mod.NativeMediaTransport,
    webrtc_owner: *media_plane_mod.MediaPlane,
    native_token: @import("runtime_pause.zig").Token,
    webrtc_token: @import("runtime_pause.zig").Token,
    native_limits: helix_active_media.Limits,
    webrtc_limits: media_plane_mod.PhysicalSnapshot.Limits,
};

pub const NativeWindowsWebrtcMediaCarry = struct {
    owner: *media_plane_mod.MediaPlane,
    carry: *const media_plane_mod.Snapshot,
    pause_token: ?@import("runtime_pause.zig").Token = null,
};

pub const NativeWindowsNativeMediaCarry = struct {
    owner: *native_media_mod.NativeMediaTransport,
    carry: *const native_media_mod.Snapshot,
    pause_token: ?@import("runtime_pause.zig").Token = null,
};

pub const NativeWindowsUdpCarry = struct {
    webtransport: ?NativeWindowsWebTransportCarry = null,
    webrtc_media: ?NativeWindowsWebrtcMediaCarry = null,
    native_media: ?NativeWindowsNativeMediaCarry = null,
    /// The exact original graph jointly authenticates both media snapshots.
    media_domain: ?*media_routing.Domain = null,
};

pub const NativeUpgradeSnapshot = struct {
    pieces: []const helix_live.StatePiece,
    state_fds: []const linux.fd_t,
    listeners: []const ListenerDescriptor,
    epoch: u64,
    now_ms: i64,
    /// Windows-only live source authority. Absent after any partial REHASH.
    windows_source_digest: ?[32]u8 = null,
    /// Borrowed exact private WAL owner; the native leaf duplicates its held
    /// HANDLE into the verified candidate before authenticated READY.
    windows_account_store: ?*services_mod.OroStore = null,
    /// Paused listener and exact exposition image, owned through COMMIT.
    windows_metrics: ?NativeWindowsMetricsCarry = null,
    /// Parked HTTP producer and exact bound listener, owned through COMMIT.
    windows_webhook: ?NativeWindowsWebhookCarry = null,
    /// Parked loopback HTTPS history listener, owned through COMMIT.
    windows_history: ?NativeWindowsHistoryCarry = null,
    /// Exact paused UDP listeners and secrets, borrowed through COMMIT.
    windows_udp: NativeWindowsUdpCarry = .{},
    /// Established QUIC/H3 sessions use a distinct authenticated aggregate.
    windows_active_webtransport: ?NativeWindowsActiveWebTransportCarry = null,
    /// Exact media graph and physical rows; the source guard remains until the
    /// joined UDP and candidate publication transaction is complete.
    windows_active_media: ?NativeWindowsActiveMediaCarry = null,
};

pub const NativeUpgradeHooks = struct {
    ctx: *anyopaque,
    /// Execute the inert successor and authenticate its actual capabilities
    /// before the server freezes any service/socket owner.
    begin: *const fn (*anyopaque, []const u8) anyerror!void,
    /// Launch the pinned boot image for automatic Windows descriptor rollover.
    /// Missing custody refuses the request before any owner is paused.
    beginSameImage: ?*const fn (*anyopaque) anyerror!void = null,
    /// Error returns are pre-COMMIT only. Success exits the predecessor without
    /// shutdown/deinit of sockets shared with the committed successor.
    transferAndCommit: *const fn (*anyopaque, NativeUpgradeSnapshot) anyerror!noreturn,
    /// Update the native driver's expected effective config commitment at the
    /// same World-locked cut as a proven live REHASH. Null refuses rebinding.
    setSourceDigest: ?*const fn (*anyopaque, [32]u8) void = null,
    abort: *const fn (*anyopaque) void,
};

pub const NativeAdoptBarrier = struct {
    ctx: *anyopaque,
    /// Any returned error is strictly pre-COMMIT. After authenticated COMMIT,
    /// return success or terminate; the serving predecessor cannot roll back.
    readyAndAwaitCommit: *const fn (*anyopaque) anyerror!void,
    /// Windows claims each validated inert state socket only after the complete
    /// capsule join. Any candidate failure after staging must exit directly so
    /// Server cleanup cannot shut down a predecessor-owned TCP endpoint.
    claimInertStateSocket: ?*const fn (*anyopaque, linux.fd_t) anyerror!void = null,
    /// The candidate claims a listener as soon as Server.init validates and
    /// adopts it. READY is forbidden until every staged listener is owned.
    claimInertListenerSocket: ?*const fn (*anyopaque, linux.fd_t) anyerror!void = null,
};
