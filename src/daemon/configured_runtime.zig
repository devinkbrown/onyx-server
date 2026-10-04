// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Construction-owned configured graph. Every companion is freshly created at
//! its final address; the opaque Runtime retains the sole graph Control and the
//! actual inline caller Thread. Observations describe source state; they do not
//! issue native-service, Helix or durable cold-restart receipts.
const std = @import("std");
const builtin = @import("builtin");
const server_mod = @import("server.zig");
const config_format = @import("config_format.zig");
const gate_mod = @import("runtime_start_gate.zig");
const rdns = @import("rdns.zig");
const dnsbl = @import("dnsbl_resolver.zig");
const mail = @import("mail_sender.zig");
const webpush = @import("webpush.zig");
const acme_runner = @import("acme_runner.zig");
const wt = @import("webtransport_listener.zig");
const dns = @import("../proto/dns.zig");
const ecdsa = @import("../crypto/ecdsa_p256.zig");
const lock_mod = @import("../substrate/rwlock.zig");
const supported = builtin.os.tag == .linux or builtin.os.tag == .openbsd;
const pause_mod = @import("runtime_pause.zig");

/// The journal branch retains the caller's actual Io/Dir owners through all
/// sender operations and joins. It does not certify journal settlement, lease
/// ownership or cold-restart SMTP reconciliation. Those require the Mail source
/// adapter's genuine journal custody, not these value/presence fields.
pub const MailFailureInput = union(enum) {
    terminal_without_wal,
    journal: struct { io: std.Io, dir: std.Io.Dir, path: []const u8 },
};
pub const MailDeliveryInput = struct {
    trust_anchors: []const []const u8 = &.{},
    failure: MailFailureInput,
};
pub const WebpushDeliveryInput = struct {
    vapid: ecdsa.KeyPair,
    trust_anchors: []const []const u8,
};
/// Values/resolved material and named lexical source borrows only. Neither a
/// preexisting worker nor a mutable Server/ACME/OCSP owner is an accepted input.
pub const ColdInputs = struct {
    core: server_mod.ManagedCoreInputs,
    dns_config: dns.ResolverConfig,
    mail_delivery: ?MailDeliveryInput = null,
    webpush_delivery: ?WebpushDeliveryInput = null,
};
pub const Observation = struct {
    core: server_mod.ManagedCoreObservation,
    gate: gate_mod.Status,
    rdns_worker: bool,
    dnsbl_worker: bool,
    mail: bool,
    webpush: bool,
    webtransport: bool,
};
pub const StopObservation = struct {
    gate: gate_mod.Status,
    inline_joined: bool,
    retained_rdns_jobs: usize,
    retained_dnsbl_jobs: usize,
    retained_webpush_jobs: usize,
};
const Phase = enum { allocating, constructed, preparing, prepared, publication_failed, published, stopping, consumers_stopping, joined_unsettled, joined, detached };
const InlineDecision = enum(u8) { pending, released };
const Backing = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lifecycle: lock_mod.RwLock = .{},
    busy: bool = false,
    policy: PolicyStorage,
    phase: Phase = .allocating,
    core: ?*server_mod.ManagedCore = null,
    run: std.atomic.Value(bool) = .init(true),
    control: ?*gate_mod.Control = null,
    view: ?*const gate_mod.View = null,
    rdns: ?*rdns.Resolver = null,
    dnsbl: ?*dnsbl.Resolver = null,
    mail: ?*mail.Sender = null,
    webpush: ?*webpush.Worker = null,
    webpush_resolver: ?*acme_runner.SystemResolver = null,
    webtransport: ?*wt.WebTransportListener = null,
    expected_dns: dns.ResolverConfig,
    expected_rdns_digest: [32]u8 = undefined,
    expected_dnsbl_digest: ?[32]u8 = null,
    expected_mail_digest: ?[32]u8 = null,
    expected_webpush_digest: ?[32]u8 = null,
    expected_mail_failure: ?MailFailureInput = null,
    expected_wt_tls: ?wt.TlsConfig = null,
    expected_wt_policy: ?wt.Policy = null,
    parsed: config_format.Config = undefined,
    inline_thread: ?std.Thread = null,
    inline_invocation: ?*server_mod.ManagedInlineInvocation = null,
    inline_custody: ?*server_mod.ManagedInlineCustody = null,
    inline_decision: std.atomic.Value(InlineDecision) = .init(.pending),
    inline_signal: std.Io.Event = .unset,
    inline_returned: std.Io.Event = .unset,
    inline_error: ?anyerror = null,
    inline_stop_requested: std.atomic.Value(bool) = .init(false),
    rdns_fence: ?pause_mod.ProducerFence = null,
    dnsbl_fence: ?pause_mod.ProducerFence = null,
    mail_fence: ?pause_mod.ProducerFence = null,
    webpush_fence: ?pause_mod.ProducerFence = null,
    rdns_pause: ?pause_mod.Token = null,
    dnsbl_pause: ?pause_mod.Token = null,
    webpush_pause: ?pause_mod.Token = null,
    rdns_retained: ?rdns.Snapshot = null,
    dnsbl_retained: ?dnsbl.Snapshot = null,
    webpush_retained: ?webpush.Snapshot = null,
    fixture: if (builtin.is_test) ?*FixtureState else void = if (builtin.is_test) null else {},
};
fn backing(self: *Runtime) *Backing {
    return @ptrCast(@alignCast(self));
}

pub const Runtime = opaque {
    /// Returns only after all cold resources and real wrappers are prepared.
    /// Every constructor failure destroys exactly the acquired NEW objects.
    pub fn createCold(allocator: std.mem.Allocator, io: std.Io, inputs: ColdInputs, deadline: std.Io.Clock.Timestamp) !*Runtime {
        return createColdImpl(allocator, io, inputs, deadline, if (builtin.is_test) null else {});
    }
    pub fn requirePrepared(self: *Runtime) !void {
        const b = backing(self);
        b.lifecycle.lockExclusive();
        defer b.lifecycle.unlockExclusive();
        if (b.busy) return error.OperationActive;
        if (b.phase != .prepared) return error.NotPrepared;
        try requirePreparedSources(b);
    }
    pub fn observe(self: *Runtime) !Observation {
        const b = backing(self);
        b.lifecycle.lockExclusive();
        defer b.lifecycle.unlockExclusive();
        if (b.busy) return error.OperationActive;
        if (b.phase != .prepared) return error.NotPrepared;
        try requirePreparedSources(b);
        return .{
            .core = try b.core.?.observe(),
            .gate = b.view.?.inspect(),
            .rdns_worker = b.expected_dns.nameserver_count != 0,
            .dnsbl_worker = b.dnsbl != null and b.expected_dns.nameserver_count != 0,
            .mail = b.mail != null,
            .webpush = b.webpush != null,
            .webtransport = b.webtransport != null,
        };
    }
    /// No caller receives Control, source pointers, or inline invocation
    /// capabilities. All fallible preparation (including the actual inline
    /// caller spawn) precedes the no-fail graph publication.
    pub fn publish(self: *Runtime) !void {
        const b = backing(self);
        try beginOperation(b);
        defer endOperation(b);
        if (b.phase != .prepared) return error.NotPrepared;
        try requirePreparedSources(b);
        if ((try b.core.?.observe()).reactor_count == 1) {
            const reservation = try b.core.?.reserveInlineInvocation();
            b.inline_invocation = reservation.invocation;
            b.inline_custody = reservation.custody;
            b.inline_thread = spawnInline(b) catch |err| {
                reservation.custody.cancelUncalled() catch @panic("uncalled inline reservation cancellation");
                b.inline_invocation = null;
                b.inline_custody = null;
                // One-shot source capabilities are never reissued. Abort this
                // unpublished candidate; retry constructs a NEW Runtime.
                b.phase = .publication_failed;
                return err;
            };
        }
        b.core.?.publishPrepared(b.control.?, b.view.?);
        b.phase = .published;
        b.control.?.releaseAll();
        b.inline_decision.store(.released, .release);
        b.inline_signal.set(b.io);
    }

    pub fn requireActivated(self: *Runtime) !void {
        const b = backing(self);
        try beginOperation(b);
        defer endOperation(b);
        if (b.phase != .published) return error.NotPublished;
        try b.core.?.requireActivated();
        if (b.expected_dns.nameserver_count != 0) try b.rdns.?.requireActivated();
        if (b.dnsbl) |owner| if (b.expected_dns.nameserver_count != 0) try owner.requireActivated();
        if (b.mail) |owner| try owner.requireActivated();
        if (b.webpush) |owner| try owner.requireActivated();
        if (b.webtransport) |owner| try owner.requireActivated();
    }

    /// Terminal stop, serialized by the original owner. No lifecycle/source
    /// lock spans waits or joins. Failure preserves the exact graph, fences,
    /// snapshots and live consumers for retry; deinit refuses that state.
    /// Resolver pending/cache outcomes remain retained until explicit deinit.
    /// This is a local terminal outcome, never a durable checkpoint receipt.
    pub fn stop(self: *Runtime, deadline: std.Io.Clock.Timestamp) !StopObservation {
        const b = backing(self);
        try beginOperation(b);
        defer endOperation(b);
        if (deadline.clock != .awake) return error.InvalidDeadline;
        _ = try stopDeadlineMillis(b, deadline);
        switch (b.phase) {
            .published => b.phase = .stopping,
            .stopping, .consumers_stopping, .joined_unsettled, .joined => {},
            else => return error.NotPublished,
        }
        if (b.phase == .stopping) {
            try fenceCompanions(b);
            b.inline_stop_requested.store(true, .release);
            try b.core.?.requestProducerStopAndWake(b.control.?);
            if (builtin.is_test) if (b.fixture) |fixture| if (fixture.release_inline_during_stop) fixture.allow_inline.set(b.io);
            try b.core.?.joinProducers(b.control.?, deadline);
            try retainResolverOutcomes(b, deadline);
            if (b.mail) |owner| try awaitMailSettled(b, owner, deadline);
            if (b.webpush) |owner| {
                if (b.webpush_retained == null) {
                    if (b.webpush_pause == null) b.webpush_pause = try owner.requestPause(1);
                    try owner.awaitPaused(b.webpush_pause.?, deadline);
                    b.webpush_retained = try owner.captureFrozen(snapshotAllocator(b), b.webpush_fence.?, b.webpush_pause, .{
                        .max_bytes = 4 * 1024 * 1024,
                        .max_dead_entries = webpush.max_queued_jobs,
                    });
                }
                owner.requestStopAndWake();
                try b.control.?.joinParticipantUntil(try b.view.?.slot(.webpush, 0, owner), deadline);
                try b.core.?.reconcileWebpushTerminal(deadline);
                // Pending queue/dead/overflow outcomes retain the exact source
                // and live Core. No destructive drain creates settlement.
                try owner.requireTerminalSettled(b.webpush_fence.?);
            }
            if (b.webtransport) |owner| {
                owner.requestStopAndWake();
                try b.control.?.joinParticipantUntil(try b.view.?.slot(.webtransport, 0, owner), deadline);
            }
            // Consumers remain live through the Core's fallible media egress
            // settlement. Companion sources remain paused/fenced for retry.
            const stop_ms = try stopDeadlineMillis(b, deadline);
            try b.core.?.requestReactorStopAndWake(b.control.?, stop_ms);
            b.phase = .consumers_stopping;
            b.rdns.?.requestStopAndWake();
            if (b.dnsbl) |owner| owner.requestStopAndWake();
            if (b.mail) |owner| owner.requestStopAndWake();
            if (b.webpush) |owner| owner.requestStopAndWake();
            if (b.webtransport) |owner| owner.requestStopAndWake();
        }
        if (b.phase == .consumers_stopping) {
            try b.control.?.joinAllUntil(deadline);
            if (b.inline_thread) |thread| {
                // Return/exited bits are never used as a join substitute.
                try b.inline_returned.waitTimeout(b.io, .{ .deadline = deadline });
                thread.join();
                b.inline_thread = null;
                try b.inline_custody.?.releaseAfterReturn();
                b.inline_custody = null;
                b.inline_invocation = null;
            }
            try detachSources(b);
            b.phase = .joined_unsettled;
        }
        try b.view.?.requireAllJoined();
        if (b.phase == .joined_unsettled) try b.core.?.finishStoppedRetirement(deadline);
        try b.core.?.requireStoppedOutcome();
        if (b.inline_error) |err| return err;
        b.phase = .joined;
        return .{
            .gate = b.view.?.inspect(),
            .inline_joined = b.inline_thread == null and b.inline_custody == null,
            .retained_rdns_jobs = if (b.rdns_retained) |snapshot| snapshot.job_count else 0,
            .retained_dnsbl_jobs = if (b.dnsbl_retained) |snapshot| snapshot.job_count else 0,
            .retained_webpush_jobs = if (b.webpush_retained) |snapshot| snapshot.jobs.len else 0,
        };
    }

    /// Unpublished abort or explicit disposal of a successfully joined graph.
    /// The caller retains all allocator/Io/Store/directory borrows through this
    /// return. Accepted resolver terminal outcomes are disposed here explicitly.
    pub fn deinit(self: *Runtime) void {
        const b = backing(self);
        b.lifecycle.lockExclusive();
        if (b.busy or (b.phase != .prepared and b.phase != .publication_failed and b.phase != .joined)) @panic("runtime requires completed operation and joined terminal stop before disposal");
        b.busy = true;
        b.lifecycle.unlockExclusive();
        const allocator = b.allocator;
        cleanupConstruction(b);
        std.crypto.secureZero(u8, std.mem.asBytes(b));
        allocator.destroy(b);
    }
};

fn beginOperation(b: *Backing) !void {
    b.lifecycle.lockExclusive();
    defer b.lifecycle.unlockExclusive();
    if (b.busy) return error.OperationActive;
    b.busy = true;
}
fn endOperation(b: *Backing) void {
    b.lifecycle.lockExclusive();
    defer b.lifecycle.unlockExclusive();
    std.debug.assert(b.busy);
    b.busy = false;
}
fn inlineWorker(b: *Backing) void {
    defer b.inline_returned.set(b.io);
    b.inline_signal.waitUncancelable(b.io);
    if (b.inline_decision.load(.acquire) != .released) return;
    if (builtin.is_test) if (b.fixture) |fixture| if (fixture.hold_inline_start) {
        fixture.held_inline.set(b.io);
        fixture.allow_inline.waitUncancelable(b.io);
    };
    b.inline_invocation.?.run() catch |err| {
        // The exact reserved caller can be scheduled after terminal stop
        // closes its idle source. Its actual handle/custody still must join.
        if (err != error.InlineClosedBeforeEntry or !b.inline_stop_requested.load(.acquire)) b.inline_error = err;
    };
}
fn spawnInline(b: *Backing) !std.Thread {
    if (builtin.is_test) if (b.fixture) |fixture| if (fixture.fail_inline_spawn) return error.SystemResources;
    return std.Thread.spawn(.{}, inlineWorker, .{b});
}
fn fenceCompanions(b: *Backing) !void {
    if (b.rdns_fence == null) b.rdns_fence = try b.rdns.?.fenceProducers();
    try b.rdns.?.requireProducersFrozen(b.rdns_fence.?);
    if (b.dnsbl) |owner| {
        if (b.dnsbl_fence == null) b.dnsbl_fence = try owner.fenceProducers();
        try owner.requireProducersFrozen(b.dnsbl_fence.?);
    }
    if (b.mail) |owner| {
        if (b.mail_fence == null) b.mail_fence = try owner.fenceProducers();
        try owner.requireProducersFrozen(b.mail_fence.?);
    }
    if (b.webpush) |owner| {
        if (b.webpush_fence == null) b.webpush_fence = try owner.fenceProducers();
        try owner.requireProducersFrozen(b.webpush_fence.?);
    }
}
fn retainResolverOutcomes(b: *Backing, deadline: std.Io.Clock.Timestamp) !void {
    const allocator = snapshotAllocator(b);
    const max_snapshot_bytes = 4 * 1024 * 1024;
    if (b.rdns_retained == null) {
        if (b.expected_dns.nameserver_count != 0) {
            if (b.rdns_pause == null) b.rdns_pause = try b.rdns.?.requestPause(1);
            try b.rdns.?.awaitPaused(b.rdns_pause.?, deadline);
        }
        b.rdns_retained = try b.rdns.?.captureFrozen(allocator, b.rdns_fence.?, b.rdns_pause, max_snapshot_bytes);
    }
    if (b.dnsbl) |owner| if (b.dnsbl_retained == null) {
        if (b.expected_dns.nameserver_count != 0) {
            if (b.dnsbl_pause == null) b.dnsbl_pause = try owner.requestPause(1);
            try owner.awaitPaused(b.dnsbl_pause.?, deadline);
        }
        b.dnsbl_retained = try owner.captureFrozen(allocator, b.dnsbl_fence.?, b.dnsbl_pause, max_snapshot_bytes);
    };
}
fn snapshotAllocator(b: *Backing) std.mem.Allocator {
    return if (builtin.is_test) if (b.fixture) |fixture| fixture.snapshot_allocator orelse b.allocator else b.allocator else b.allocator;
}
fn stopDeadlineMillis(b: *Backing, deadline: std.Io.Clock.Timestamp) !u64 {
    // Sample the target clock first. Scheduling delay before the fresh awake
    // sample shortens the remaining horizon; it can never extend the deadline.
    const monotonic_ms = @import("../substrate/platform.zig").monotonicMillis();
    const now = std.Io.Clock.awake.now(b.io);
    return checkedStopDeadlineMillis(deadline.raw.nanoseconds, now.nanoseconds, monotonic_ms);
}
fn checkedStopDeadlineMillis(deadline_ns: i96, now_ns: i96, monotonic_ms: i64) !u64 {
    const remaining_ns = std.math.sub(i96, deadline_ns, now_ns) catch return error.InvalidDeadline;
    const remaining_ms = @divTrunc(remaining_ns, std.time.ns_per_ms);
    if (remaining_ms <= 0) return error.Timeout;
    const timeout_ms = std.math.cast(u64, remaining_ms) orelse return error.InvalidDeadline;
    const now_ms = std.math.cast(u64, monotonic_ms) orelse return error.InvalidMonotonicClock;
    return std.math.add(u64, now_ms, timeout_ms) catch return error.InvalidDeadline;
}
fn awaitMailSettled(b: *Backing, owner: *mail.Sender, deadline: std.Io.Clock.Timestamp) !void {
    while (true) {
        owner.requireSettled(b.mail_fence.?) catch |err| switch (err) {
            error.OperationActive => {},
            error.FailureJournalPending => owner.reconcilePendingFailure(b.mail_fence.?) catch |reconcile_err| switch (reconcile_err) {
                error.OperationActive => {},
                else => return reconcile_err,
            },
            else => return err,
        };
        // Reconciliation can consume the pending row; require the actual source
        // to revalidate all custody/queue/in-flight facts before proceeding.
        if (owner.requireSettled(b.mail_fence.?)) |_| return else |err| switch (err) {
            error.OperationActive, error.FailureJournalPending => {},
            else => return err,
        }
        if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(b.io, .awake), .gte, deadline)) return error.Timeout;
        try std.Io.sleep(b.io, .fromMilliseconds(1), .awake);
    }
}
fn detachSources(b: *Backing) !void {
    try b.view.?.requireAllJoined();
    try b.rdns.?.detachAfterJoined();
    if (b.dnsbl) |owner| try owner.detachAfterJoined();
    if (b.mail) |owner| try owner.detachAfterJoined();
    if (b.webpush) |owner| try owner.detachAfterJoined();
    if (b.webtransport) |owner| try owner.detachAfterJoined();
    try b.core.?.detachAfterJoined();
}

fn createColdImpl(allocator: std.mem.Allocator, io: std.Io, inputs: ColdInputs, deadline: std.Io.Clock.Timestamp, fixture: if (builtin.is_test) ?*FixtureState else void) !*Runtime {
    if (comptime !supported) return error.Unsupported;
    try validateInputs(inputs);
    const b = try allocator.create(Backing);
    b.* = .{ .allocator = allocator, .io = io, .policy = .{ .owner = allocator }, .expected_dns = inputs.dns_config, .fixture = fixture };
    errdefer {
        cleanupConstruction(b);
        std.crypto.secureZero(u8, std.mem.asBytes(b));
        allocator.destroy(b);
    }
    const policy_allocator = b.policy.allocator();
    b.parsed = try clonePolicyValue(policy_allocator, inputs.core.parsed);
    b.expected_rdns_digest = try rdns.resolverConfigDigest(inputs.dns_config);
    b.rdns = blk: {
        const owner = try allocator.create(rdns.Resolver);
        errdefer allocator.destroy(owner);
        owner.* = try rdns.Resolver.initConfigured(allocator, io, inputs.dns_config);
        break :blk owner;
    };
    if (b.parsed.dnsbl.enabled and b.parsed.dnsbl.zones.len != 0) {
        b.expected_dnsbl_digest = try dnsbl.configDigest(inputs.dns_config, b.parsed.dnsbl.zones);
        b.dnsbl = blk: {
            const owner = try allocator.create(dnsbl.Resolver);
            errdefer allocator.destroy(owner);
            owner.* = try dnsbl.Resolver.initConfigured(allocator, io, inputs.dns_config, b.parsed.dnsbl.zones);
            break :blk owner;
        };
    }
    if (inputs.mail_delivery) |delivery| {
        const parsed = b.parsed.mail;
        var config: mail.Config = .{
            .relay_host = parsed.relay_host.?,
            .relay_port = parsed.relay_port,
            .starttls = parsed.starttls,
            .insecure_skip_verify = parsed.insecure_skip_verify,
            .trust_anchors = try clonePolicyValue(policy_allocator, delivery.trust_anchors),
            .ehlo_domain = try clonePolicyValue(policy_allocator, inputs.core.config.server_name),
            .from = parsed.from.?,
            .user = parsed.user,
            .pass = parsed.pass,
        };
        b.expected_mail_failure = switch (delivery.failure) {
            .terminal_without_wal => .terminal_without_wal,
            .journal => |journal| blk: {
                const path = try clonePolicyValue(policy_allocator, journal.path);
                config.failure_wal = path;
                config.failure_io = journal.io;
                config.failure_dir = journal.dir;
                break :blk .{ .journal = .{ .path = path, .io = journal.io, .dir = journal.dir } };
            },
        };
        b.expected_mail_digest = try mail.configDigest(config);
        b.mail = blk: {
            const owner = try allocator.create(mail.Sender);
            errdefer allocator.destroy(owner);
            owner.* = try mail.Sender.init(allocator, config);
            break :blk owner;
        };
    }
    if (inputs.webpush_delivery) |delivery| {
        const resolver = try allocator.create(acme_runner.SystemResolver);
        resolver.* = .{ .allocator = allocator, .io = io, .resolv_conf_max_bytes = @intCast(b.parsed.acme.resolv_conf_max_bytes), .dns_port = b.parsed.acme.dns_port };
        b.webpush_resolver = resolver;
        const owner = try allocator.create(webpush.Worker);
        owner.* = .{
            .allocator = allocator,
            .vapid = delivery.vapid,
            .subject = b.parsed.webpush.subject,
            .resolver = resolver.resolver(),
            .trust_anchors = &.{},
        };
        b.webpush = owner;
        owner.trust_anchors = try clonePolicyValue(policy_allocator, delivery.trust_anchors);
        // Independent expected digest uses a separate source value, before any
        // worker preparation mutates the actual owned Worker.
        var expected = owner.*;
        expected.system_resolver = resolver;
        b.expected_webpush_digest = try expected.configDigest();
        std.crypto.secureZero(u8, std.mem.asBytes(&expected.vapid));
    }
    b.core = try server_mod.ManagedCore.createCold(allocator, io, inputs.core, .{
        .rdns = b.rdns.?,
        .dnsbl = b.dnsbl,
        .mail = b.mail,
        .webpush = b.webpush,
    });
    if (inputs.core.config.webtransport_port != 0) {
        const config = inputs.core.config;
        const signing_key: @import("../proto/quic_handshake.zig").SigningKey =
            if (config.tls_ecdsa_signing_key) |key| .{ .ecdsa_p256 = key } else if (config.tls_signing_key) |key| .{ .ed25519 = key } else if (config.tls_rsa_signing_key) |key| .{ .rsa = key } else return error.WebTransportRequiresSigningKey;
        const tls = try clonePolicyValue(policy_allocator, wt.TlsConfig{ .cert_chain = config.tls_cert_chain, .signing_key = signing_key });
        const observation = try b.core.?.observe();
        b.expected_wt_tls = tls;
        b.expected_wt_policy = .{
            .irc_port = observation.bound_port,
            .send_proxy_header = false,
            .echo_wt_datagrams = false,
            .max_connections = wt.default_max_connections,
            .retry_policy = .never,
            .retry_load_threshold = wt.default_retry_load_threshold,
            .reset_rate_per_s = wt.default_reset_rate_per_s,
            .reset_burst = wt.default_reset_burst,
        };
        const owner = try allocator.create(wt.WebTransportListener);
        owner.* = wt.WebTransportListener.init(allocator, try clonePolicyValue(policy_allocator, tls), observation.bound_port);
        b.webtransport = owner;
    }
    b.phase = .constructed;
    try prepare(b, deadline);
    return @ptrCast(b);
}

fn validateInputs(inputs: ColdInputs) !void {
    try server_mod.validateManagedColdConfig(inputs.core.config);
    _ = try rdns.resolverConfigDigest(inputs.dns_config);
    const parsed = inputs.core.parsed;
    if (parsed.mail.enabled != (inputs.mail_delivery != null) or parsed.webpush.enabled != (inputs.webpush_delivery != null)) return error.ConfiguredOwnerMismatch;
    if (parsed.mail.enabled) {
        if (parsed.mail.relay_host == null or parsed.mail.relay_host.?.len == 0 or parsed.mail.from == null or parsed.mail.from.?.len == 0) return error.MailNotConfigured;
        if (inputs.mail_delivery.?.failure == .journal) {
            const journal = inputs.mail_delivery.?.failure.journal;
            if (journal.path.len == 0 or std.mem.indexOfScalar(u8, journal.path, 0) != null) return error.InvalidMailJournal;
        }
    }
    if (parsed.webpush.enabled) {
        if (inputs.core.accounts == null or !inputs.core.config.sasl_enabled or parsed.sasl.account_db == null) return error.WebpushRequiresAccounts;
        const delivery = inputs.webpush_delivery.?;
        const derived = try ecdsa.KeyPair.fromSecretKey(delivery.vapid.secret_key);
        const public_key = delivery.vapid.public_key.toUncompressedSec1();
        const expected_key = derived.public_key.toUncompressedSec1();
        if (!std.mem.eql(u8, &public_key, &expected_key)) return error.InvalidVapidKey;
        var encoded: [webpush.vapid_pub_b64_len]u8 = undefined;
        const vapid: webpush.Vapid = .{ .key_pair = delivery.vapid };
        if (!std.mem.eql(u8, inputs.core.config.webpush_vapid_pub, vapid.publicB64(&encoded))) return error.VapidPolicyMismatch;
        if (parsed.acme.resolv_conf_max_bytes == 0 or parsed.acme.resolv_conf_max_bytes > std.math.maxInt(usize) or parsed.acme.dns_port == 0) return error.InvalidResolverPolicy;
    }
    if (inputs.core.config.webtransport_port != 0 and inputs.core.config.tls_cert_chain.len == 0) return error.WebTransportRequiresCertificate;
}

fn prepare(b: *Backing, deadline: std.Io.Clock.Timestamp) !void {
    std.debug.assert(b.phase == .constructed);
    b.phase = .preparing;
    try b.core.?.prepareColdResources(&b.run);
    try b.rdns.?.prepareColdResources(b.io);
    if (b.dnsbl) |owner| try owner.prepareColdResources(b.io);
    if (b.mail) |owner| try owner.prepareColdResources(b.io);
    if (b.webpush) |owner| try owner.prepareColdResources(b.io, b.webpush_resolver.?);
    if (b.webtransport) |owner| try owner.prepareColdResources(b.io, .any, (try b.core.?.observe()).webtransport_port);
    const gate_allocator = if (builtin.is_test) if (b.fixture) |fixture| fixture.gate_allocator orelse b.allocator else b.allocator else b.allocator;
    // The Core constructs the complete spec array privately. No returned row
    // exposes its Server/ACME/OCSP owner addresses to this or another caller.
    const created = try b.core.?.createGraphControl(gate_allocator, b.webtransport);
    b.control = created.control;
    b.view = created.view;
    if (builtin.is_test) if (b.fixture) |fixture| if (fixture.fail_spawn) |index| gate_mod.Fixture.failSpawn(created.control, index);
    // Complete registration validation before any source flag or wrapper.
    try validateRegistrations(b, created.control, created.view);
    try b.core.?.prepareWorkers(created.control, created.view);
    if (b.expected_dns.nameserver_count != 0) try b.rdns.?.prepareDormantWorker(created.control, created.view, try created.view.slot(.rdns, 0, b.rdns.?));
    if (b.dnsbl) |owner| if (b.expected_dns.nameserver_count != 0) try owner.prepareDormantWorker(created.control, created.view, try created.view.slot(.dnsbl, 0, owner));
    if (b.mail) |owner| try owner.prepareDormantWorker(created.control, created.view, try created.view.slot(.mail, 0, owner));
    if (b.webpush) |owner| try owner.prepareDormantWorker(created.control, created.view, try created.view.slot(.webpush, 0, owner));
    if (b.webtransport) |owner| try owner.prepareDormantWorker(created.control, created.view, try created.view.slot(.webtransport, 0, owner));
    try created.control.awaitAllParked(deadline);
    try requirePreparedSources(b);
    b.phase = .prepared;
}
fn validateRegistrations(b: *Backing, control: *gate_mod.Control, view: *const gate_mod.View) !void {
    try control.requireView(view);
    if (b.expected_dns.nameserver_count != 0) try b.rdns.?.validateDormantRegistration(control, view, try view.slot(.rdns, 0, b.rdns.?));
    if (b.dnsbl) |owner| if (b.expected_dns.nameserver_count != 0) try owner.validateDormantRegistration(control, view, try view.slot(.dnsbl, 0, owner));
    if (b.mail) |owner| try owner.validateDormantRegistration(control, view, try view.slot(.mail, 0, owner));
    if (b.webpush) |owner| try owner.validateDormantRegistration(control, view, try view.slot(.webpush, 0, owner));
    if (b.webtransport) |owner| try owner.validateDormantRegistration(control, view, try view.slot(.webtransport, 0, owner));
}
fn requirePreparedSources(b: *Backing) !void {
    if (b.control == null or b.view == null or !b.run.load(.acquire)) return error.NotPrepared;
    try b.control.?.requireView(b.view.?);
    try b.view.?.requireAllParked();
    try b.core.?.requirePrepared();
    if (!std.mem.eql(u8, &b.expected_rdns_digest, &try rdns.resolverConfigDigest(b.rdns.?.cfg))) return error.ConfiguredOwnerMismatch;
    if (b.expected_dns.nameserver_count != 0) try b.rdns.?.requireParked();
    if (b.dnsbl) |owner| {
        if (!std.mem.eql(u8, &b.expected_dnsbl_digest.?, &try dnsbl.configDigest(owner.cfg, owner.zones[0..owner.zone_count]))) return error.ConfiguredOwnerMismatch;
        if (b.expected_dns.nameserver_count != 0) try owner.requireParked();
    }
    if (b.mail) |owner| {
        if (!std.mem.eql(u8, &b.expected_mail_digest.?, &try mail.configDigest(owner.config))) return error.ConfiguredOwnerMismatch;
        switch (b.expected_mail_failure.?) {
            .terminal_without_wal => if (owner.config.failure_io != null or owner.config.failure_dir != null) return error.ConfiguredOwnerMismatch,
            .journal => |journal| {
                const actual = owner.config.failure_io orelse return error.ConfiguredOwnerMismatch;
                if (actual.userdata != journal.io.userdata or actual.vtable != journal.io.vtable or (owner.config.failure_dir orelse return error.ConfiguredOwnerMismatch).handle != journal.dir.handle) return error.ConfiguredOwnerMismatch;
            },
        }
        try owner.requireParked();
    }
    if (b.webpush) |owner| {
        if (!std.mem.eql(u8, &b.expected_webpush_digest.?, &try owner.configDigest())) return error.ConfiguredOwnerMismatch;
        try owner.requireParked();
    }
    if (b.webtransport) |owner| try owner.requirePreparedConfiguration(b.expected_wt_tls.?, b.expected_wt_policy.?);
    if (!b.run.load(.acquire)) return error.Stopped;
}
fn cleanupConstruction(b: *Backing) void {
    if (b.control) |control| if (b.phase != .joined) {
        control.cancelAllAndJoin();
        if (builtin.is_test) if (b.fixture) |fixture| {
            fixture.canceled = b.view.?.inspect();
            if (b.core) |core| {
                const inspection = server_mod.ManagedCoreFixture.inspect(core) catch @panic("candidate source inspection");
                fixture.any_body_entered = inspection.any_reactor_entered or inspection.geo_entered or inspection.webhook_entered;
            }
            if (b.rdns) |owner| fixture.any_body_entered = fixture.any_body_entered or owner.runtime.entered.load(.acquire);
        };
        if (b.rdns) |owner| owner.detachAfterJoined() catch @panic("RDNS detach after candidate cancellation");
        if (b.dnsbl) |owner| owner.detachAfterJoined() catch @panic("DNSBL detach after candidate cancellation");
        if (b.mail) |owner| owner.detachAfterJoined() catch @panic("mail detach after candidate cancellation");
        if (b.webpush) |owner| owner.detachAfterJoined() catch @panic("webpush detach after candidate cancellation");
        if (b.webtransport) |owner| owner.detachAfterJoined() catch @panic("WebTransport detach after candidate cancellation");
        if (b.core) |core| core.detachAfterJoined() catch @panic("core detach after candidate cancellation");
    };
    // Core holds callbacks and borrowed source pointers into companions. Its
    // destruction precedes every companion, after the shared joins/detaches.
    if (b.core) |core| {
        if (builtin.is_test) if (b.fixture) |fixture| {
            fixture.webhook_fd = (server_mod.ManagedCoreFixture.inspect(core) catch @panic("candidate resource inspection")).webhook_fd;
            fixture.core_destroyed = true;
        };
        core.destroyDetached();
        b.core = null;
    }
    if (b.webtransport) |owner| {
        owner.deinit();
        wipeDestroy(b.allocator, owner);
        b.webtransport = null;
    }
    if (b.webpush) |owner| {
        owner.shutdown();
        wipeDestroy(b.allocator, owner);
        b.webpush = null;
    }
    if (b.webpush_resolver) |owner| {
        wipeDestroy(b.allocator, owner);
        b.webpush_resolver = null;
    }
    if (b.mail) |owner| {
        owner.deinit();
        wipeDestroy(b.allocator, owner);
        b.mail = null;
    }
    if (b.dnsbl) |owner| {
        owner.deinit();
        wipeDestroy(b.allocator, owner);
        b.dnsbl = null;
    }
    if (b.rdns) |owner| {
        owner.deinit();
        wipeDestroy(b.allocator, owner);
        b.rdns = null;
    }
    if (b.control) |control| {
        control.destroyJoined();
        b.control = null;
        b.view = null;
    }
    if (b.rdns_retained) |*snapshot| snapshot.deinit();
    if (b.dnsbl_retained) |*snapshot| snapshot.deinit();
    if (b.webpush_retained) |*snapshot| snapshot.deinit();
    b.policy.deinit();
    b.phase = .detached;
}
fn wipeDestroy(allocator: std.mem.Allocator, object: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(object));
    allocator.destroy(object);
}
const FixtureState = if (builtin.is_test) struct {
    fail_spawn: ?usize = null,
    fail_inline_spawn: bool = false,
    hold_inline_start: bool = false,
    release_inline_during_stop: bool = false,
    held_inline: std.Io.Event = .unset,
    allow_inline: std.Io.Event = .unset,
    gate_allocator: ?std.mem.Allocator = null,
    snapshot_allocator: ?std.mem.Allocator = null,
    canceled: ?gate_mod.Status = null,
    any_body_entered: bool = false,
    webhook_fd: ?std.posix.fd_t = null,
    core_destroyed: bool = false,
} else void;

const PolicyStorage = struct {
    owner: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    first: ?*Allocation = null,
    const Allocation = struct {
        next: ?*Allocation,
        bytes: []u8,
        alignment: std.mem.Alignment,
    };

    fn allocator(self: *PolicyStorage) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn lock(self: *PolicyStorage) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *PolicyStorage = @ptrCast(@alignCast(ctx));
        const node = self.owner.create(Allocation) catch return null;
        const bytes = self.owner.rawAlloc(len, alignment, ret_addr) orelse {
            self.owner.destroy(node);
            return null;
        };
        self.lock();
        defer self.mutex.unlock();
        node.* = .{ .next = self.first, .bytes = bytes[0..len], .alignment = alignment };
        self.first = node;
        return bytes;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *PolicyStorage = @ptrCast(@alignCast(ctx));
        self.lock();
        var cursor = &self.first;
        while (cursor.*) |node| {
            if (node.bytes.ptr == bytes.ptr) {
                std.debug.assert(node.bytes.len == bytes.len and node.alignment == alignment);
                cursor.* = node.next;
                self.mutex.unlock();
                std.crypto.secureZero(u8, node.bytes);
                self.owner.rawFree(node.bytes, node.alignment, ret_addr);
                self.owner.destroy(node);
                return;
            }
            cursor = &node.next;
        }
        self.mutex.unlock();
        @panic("foreign policy allocation");
    }
    /// Only after every policy borrower has joined/detached. This also handles
    /// allocations not yet installed into a fully constructed typed object.
    fn deinit(self: *PolicyStorage) void {
        while (self.first) |node| {
            self.first = node.next;
            std.crypto.secureZero(u8, node.bytes);
            self.owner.rawFree(node.bytes, node.alignment, @returnAddress());
            self.owner.destroy(node);
        }
    }
};

/// Data-only recursive clone. A source pointer/allocator/Io must instead have
/// an explicit typed lifetime binding; it cannot quietly pass through here.
fn clonePolicyValue(allocator: std.mem.Allocator, value: anytype) std.mem.Allocator.Error!@TypeOf(value) {
    const T = @TypeOf(value);
    return switch (@typeInfo(T)) {
        .pointer => |info| blk: {
            if (info.size != .slice or info.sentinel() != null) @compileError("policy clone requires an explicit source binding for this pointer");
            const out = try allocator.alloc(info.child, value.len);
            for (out, value) |*dst, src| dst.* = try clonePolicyValue(allocator, src);
            break :blk out;
        },
        .optional => if (value) |inner| try clonePolicyValue(allocator, inner) else null,
        .array => blk: {
            var out: T = undefined;
            for (&out, value) |*dst, src| dst.* = try clonePolicyValue(allocator, src);
            break :blk out;
        },
        .@"struct" => |info| blk: {
            var out: T = undefined;
            inline for (info.field_names) |name| @field(out, name) = try clonePolicyValue(allocator, @field(value, name));
            break :blk out;
        },
        .@"union" => |info| blk: {
            if (info.tag_type == null) @compileError("policy clone refuses untagged union");
            const tag = std.meta.activeTag(value);
            inline for (info.field_names) |name| {
                if (tag == @field(info.tag_type.?, name)) break :blk @unionInit(T, name, try clonePolicyValue(allocator, @field(value, name)));
            }
            unreachable;
        },
        .bool, .int, .float, .@"enum", .void => value,
        else => @compileError("policy clone encountered non-data state"),
    };
}

fn testDeadline() std.Io.Clock.Timestamp {
    return .{ .clock = .awake, .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(5000)) };
}
fn testInputs(shards: u16) ColdInputs {
    return .{ .core = .{
        .config = .{ .host = "127.0.0.1", .port = 0, .max_clients = 16, .num_shards = shards, .crypto_io = std.testing.io },
        .parsed = .{},
    }, .dns_config = .{} };
}
/// All references into this fixture remain at its caller-owned stable address.
const TestTls = struct {
    key: std.crypto.sign.Ed25519.KeyPair,
    certificate: [1024]u8,
    chain: [1][]const u8,
    seed: [32]u8,
    fn init(self: *TestTls, byte: u8) !void {
        self.seed = @splat(byte);
        self.key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seed);
        self.chain[0] = try @import("../proto/x509_selfsign.zig").buildSelfSigned(&self.certificate, .{
            .common_name = "runtime.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ byte, 1 },
            .key_pair = self.key,
            .dns_names = &.{"runtime.test"},
            .is_ca = true,
        });
    }
    fn install(self: *TestTls, inputs: *ColdInputs) void {
        inputs.core.config.tls_cert_chain = &self.chain;
        inputs.core.config.tls_signing_key = self.key;
        inputs.core.config.tls_port = 0;
    }
    fn deinit(self: *TestTls) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};
fn unusedTcpPort() !u16 {
    const fd = try @import("reuseport.zig").createReusePortListener("127.0.0.1", 0, 8);
    defer @import("os_runtime.zig").close(fd);
    // Linux reuseport deliberately binds IPv4 hosts through a dual-stack IPv6
    // socket; OpenBSD binds the host's native family. Observe the actual ABI.
    var address: std.posix.sockaddr.storage = undefined;
    var length: std.posix.socklen_t = @sizeOf(@TypeOf(address));
    if (std.posix.errno(std.posix.system.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS) return error.TestSocketObservation;
    const encoded_port = if (address.family == std.posix.AF.INET and length == @sizeOf(std.posix.sockaddr.in))
        @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&address))).port
    else if (address.family == std.posix.AF.INET6 and length == @sizeOf(std.posix.sockaddr.in6))
        @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&address))).port
    else
        return error.TestSocketObservation;
    const port = std.mem.bigToNative(u16, encoded_port);
    if (port == 0) return error.TestSocketObservation;
    return port;
}
fn unusedUdpPort() !u16 {
    const sockets = @import("../substrate/media_socket.zig");
    var socket = try sockets.MediaSocket.bind(sockets.any_be, 0);
    defer socket.deinit();
    return socket.localPort();
}
fn configuredResolver() dns.ResolverConfig {
    var config: dns.ResolverConfig = .{ .port = 1, .timeout_ms = 10, .attempts = 1 };
    config.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    return config;
}
fn waitResolver(resolver: *rdns.Resolver, ip: ?dns.Address) !void {
    const deadline = testDeadline();
    while (deadline.raw.nanoseconds > std.Io.Clock.awake.now(std.testing.io).nanoseconds) {
        if (resolver.runtime.entered.load(.acquire) and !resolver.runtime.exited.load(.acquire)) {
            if (ip) |address| {
                while (!resolver.mutex.tryLock()) std.atomic.spinLoopHint();
                var complete = false;
                for (resolver.entries) |entry| if (entry.has_key and std.meta.eql(entry.key, address) and entry.state == .ready) {
                    complete = true;
                    break;
                };
                resolver.mutex.unlock();
                if (complete) return;
            } else return;
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    return error.TestWorkerTimeout;
}

/// Stable fixture ownership for the public NEW-Core primitive. Production
/// Runtime never exposes these primitive bindings or its graph authority.
const TestPrimitiveCore = if (builtin.is_test) struct {
    resolver: ?*rdns.Resolver = null,
    core: ?*server_mod.ManagedCore = null,
    run: std.atomic.Value(bool) = .init(true),
    graph: ?gate_mod.Created = null,

    fn init(self: *@This(), shards: u16) !void {
        self.* = .{};
        errdefer self.deinit();
        const resolver = try std.testing.allocator.create(rdns.Resolver);
        errdefer if (self.resolver == null) std.testing.allocator.destroy(resolver);
        resolver.* = try rdns.Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
        self.resolver = resolver;
        var inputs = testInputs(shards);
        inputs.core.config.webhook_enabled = true;
        self.core = try server_mod.ManagedCore.createCold(std.testing.allocator, std.testing.io, inputs.core, .{
            .rdns = resolver,
            .dnsbl = null,
            .mail = null,
            .webpush = null,
        });
        try self.core.?.prepareColdResources(&self.run);
    }
    fn deinit(self: *@This()) void {
        if (self.graph) |graph| {
            graph.control.cancelAllAndJoin();
            if (self.core) |core| core.detachAfterJoined() catch @panic("primitive fixture core detach before destruction");
        }
        if (self.core) |core| {
            core.destroyDetached();
            self.core = null;
        }
        if (self.resolver) |resolver| {
            resolver.deinit();
            std.testing.allocator.destroy(resolver);
            self.resolver = null;
        }
        // The exact original View remains alive through all source cleanup.
        if (self.graph) |graph| graph.control.destroyJoined();
        self.graph = null;
    }
} else void;

test "configured runtime: real cold listeners and complete worker inventory stay inert behind one Gate" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(3);
    inputs.dns_config = configuredResolver();
    inputs.core.config.webhook_enabled = true;
    inputs.core.config.geo_enabled = true;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    var destroyed = false;
    defer if (!destroyed) runtime.deinit();
    try runtime.requirePrepared();
    const b = backing(runtime);
    const status = b.view.?.inspect();
    try std.testing.expectEqual(gate_mod.Phase.preparing, status.phase);
    try std.testing.expectEqual(@as(usize, 6), status.expected);
    try std.testing.expectEqual(status.expected, status.spawned);
    try std.testing.expectEqual(status.expected, status.arrived);
    try std.testing.expectEqual(@as(usize, 0), status.joined);
    const core = try server_mod.ManagedCoreFixture.inspect(b.core.?);
    try std.testing.expect(core.fabric_present and core.pool_count == 3 and !core.any_reactor_entered);
    try std.testing.expect(!core.geo_entered and !core.webhook_entered);
    try std.testing.expect(!b.rdns.?.runtime.entered.load(.acquire));
    const network = @import("native_network.zig");
    const os = @import("os_runtime.zig");
    const peer = try network.connect(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = core.webhook_port.? } }, 1000);
    defer os.close(peer);
    try network.writeAll(peer, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    var polls = [_]std.posix.pollfd{.{ .fd = peer, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&polls, 25));
    try os.setNonblocking(peer);
    var bytes: [64]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, os.read(peer, &bytes));
    runtime.deinit();
    destroyed = true;
    try std.testing.expect(!os.fdValid(core.webhook_fd.?));
}

test "configured runtime: inline shard has zero worker rows and no fabric" {
    if (comptime !supported) return error.SkipZigTest;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, testInputs(1), testDeadline());
    defer runtime.deinit();
    try runtime.requirePrepared();
    const observation = try runtime.observe();
    const core = try server_mod.ManagedCoreFixture.inspect(backing(runtime).core.?);
    try std.testing.expectEqual(@as(usize, 0), observation.gate.expected);
    try std.testing.expectEqual(@as(usize, 0), observation.gate.spawned);
    try std.testing.expectEqual(@as(usize, 0), core.pool_count);
    try std.testing.expect(!core.fabric_present and !core.any_reactor_entered);
    try std.testing.expectEqual(@as(usize, 1), observation.core.reactor_count);
    try std.testing.expect(!observation.rdns_worker);
}

test "configured runtime: prepared source callback and configured policy tampering cannot become a readiness receipt" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(1);
    inputs.core.config.webhook_enabled = true;
    inputs.core.config.geo_enabled = true;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    for ([_]server_mod.ManagedCoreFixture.Tamper{ .webhook_sink, .webhook_limit, .geo_weather, .server_name }) |kind| {
        try server_mod.ManagedCoreFixture.tamper(b.core.?, kind, true);
        try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
        try server_mod.ManagedCoreFixture.tamper(b.core.?, kind, false);
        try runtime.requirePrepared();
    }
    const core = try server_mod.ManagedCoreFixture.inspect(b.core.?);
    try std.testing.expect(!core.geo_entered and !core.webhook_entered);
    try std.testing.expectEqual(gate_mod.Phase.preparing, b.view.?.inspect().phase);
}

test "configured runtime: preexisting legacy and foreign controlled RDNS survive refused construction and complete actual queued work" {
    if (comptime !supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |managed| {
        var resolver = try rdns.Resolver.initConfigured(allocator, std.testing.io, configuredResolver());
        var gate: ?gate_mod.Created = null;
        defer {
            if (gate) |owned| {
                resolver.requestStopAndWake();
                owned.control.joinAll();
                resolver.detachAfterJoined() catch unreachable;
                owned.control.destroyJoined();
            }
            resolver.deinit();
        }
        if (managed) {
            try resolver.prepareColdResources(std.testing.io);
            const specs = [_]gate_mod.ParticipantSpec{.{ .kind = .rdns, .instance = 0, .owner_identity = &resolver, .options = rdns.dormant_spawn_options }};
            gate = try gate_mod.create(allocator, std.testing.io, &specs);
            try resolver.prepareDormantWorker(gate.?.control, gate.?.view, try gate.?.view.slot(.rdns, 0, &resolver));
            try gate.?.control.awaitAllParked(testDeadline());
            gate.?.control.releaseAll();
        } else {
            resolver.start();
            try std.testing.expect(resolver.thread != null);
        }
        try waitResolver(&resolver, null);
        const prior_thread = resolver.thread;
        const prior_view = resolver.runtime.view;
        const prior_slot = resolver.runtime.slot;
        const before = try rdns.resolverConfigDigest(resolver.cfg);
        var inputs = testInputs(1);
        inputs.core.config.rdns = &resolver;
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.PreexistingRuntimeOwner, Runtime.createCold(failing.allocator(), std.testing.io, inputs, testDeadline()));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(std.meta.eql(prior_thread, resolver.thread));
        try std.testing.expect(prior_view == resolver.runtime.view and std.meta.eql(prior_slot, resolver.runtime.slot));
        try std.testing.expect(std.mem.eql(u8, &before, &try rdns.resolverConfigDigest(resolver.cfg)));
        try std.testing.expect(!resolver.stop_flag.load(.acquire));
        const ip: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 51 } };
        resolver.request(ip);
        try waitResolver(&resolver, ip);
        try std.testing.expect(!resolver.runtime.exited.load(.acquire));
    }
}

test "configured runtime: partial actual spawn is canceled and joined before owned sources and listeners are destroyed" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(3);
    inputs.dns_config = configuredResolver();
    inputs.core.config.webhook_enabled = true;
    inputs.core.config.geo_enabled = true;
    var fixture: FixtureState = .{ .fail_spawn = 4 };
    try std.testing.expectError(error.SystemResources, createColdImpl(std.testing.allocator, std.testing.io, inputs, testDeadline(), &fixture));
    const status = fixture.canceled orelse return error.TestExpectedCancel;
    try std.testing.expectEqual(gate_mod.Phase.canceled, status.phase);
    try std.testing.expectEqual(@as(usize, 4), status.spawned);
    try std.testing.expectEqual(status.spawned, status.joined);
    try std.testing.expect(!fixture.any_body_entered);
    try std.testing.expect(fixture.core_destroyed);
    try std.testing.expect(!@import("os_runtime.zig").fdValid(fixture.webhook_fd.?));
}

test "configured runtime: synchronous media bind failure refunds earlier prepared resources and preserves the unrelated socket" {
    if (comptime !supported) return error.SkipZigTest;
    const sockets = @import("../substrate/media_socket.zig");
    var occupied = try sockets.MediaSocket.bind(sockets.any_be, 0);
    defer occupied.deinit();
    const original = try occupied.capture();
    var inputs = testInputs(2);
    inputs.core.config.media_enabled = true;
    inputs.core.config.media_port = try occupied.localPort();
    inputs.core.config.native_media_port = 0;
    inputs.core.config.media_dtls_srtp = false;
    inputs.core.config.media_dtls13 = false;
    try std.testing.expectError(error.BindFailed, Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline()));
    try std.testing.expect(std.meta.eql(original, try occupied.capture()));
    // No candidate Control/wrapper survives that synchronous source failure.
    inputs.core.config.media_port = 0;
    const retry = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer retry.deinit();
    try retry.requirePrepared();
    try std.testing.expect(std.meta.eql(original, try occupied.capture()));
}

test "configured runtime: Gate allocation sweep destroys every failed unpublished graph without leaking its real listener" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(1);
    inputs.core.config.webhook_enabled = true;
    var index: usize = 0;
    var failures: usize = 0;
    while (index < 8) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var fixture: FixtureState = .{ .gate_allocator = failing.allocator() };
        if (createColdImpl(std.testing.allocator, std.testing.io, inputs, testDeadline(), &fixture)) |runtime| {
            defer runtime.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try runtime.requirePrepared();
            try std.testing.expectEqual(@as(usize, 2), failures);
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(fixture.core_destroyed);
            try std.testing.expect(!@import("os_runtime.zig").fdValid(fixture.webhook_fd.?));
            failures += 1;
        }
    }
    return error.TestSweepIncomplete;
}

test "configured runtime: cold construction refuses every inherited input before allocation" {
    if (comptime !supported) return error.SkipZigTest;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var inputs = testInputs(1);
    for ([_]server_mod.Config{
        .{ .port = 0, .resume_arena_fd = 3 },                        .{ .port = 0, .native_arena_bytes = &.{0} },
        .{ .port = 0, .inherited_state_fd_manifest_present = true }, .{ .port = 0, .inherited_listener_fd = 4 },
    }) |config| {
        inputs.core.config = config;
        try std.testing.expectError(error.InheritedRuntimeRequiresCarry, Runtime.createCold(failing.allocator(), std.testing.io, inputs, testDeadline()));
    }
    try std.testing.expect(!failing.has_induced_failure);
}

test "configured runtime: foreign Control cannot operate on the private candidate View or alter real parked owners" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(2);
    inputs.dns_config = configuredResolver();
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    const other = try gate_mod.create(std.testing.allocator, std.testing.io, &.{});
    defer {
        other.control.cancelAllAndJoin();
        other.control.destroyJoined();
    }
    const original = b.view.?.inspect();
    try std.testing.expectError(error.InvalidGate, validateRegistrations(b, other.control, b.view.?));
    try std.testing.expect(std.meta.eql(original, b.view.?.inspect()));
    try runtime.requirePrepared();
    try std.testing.expect(!b.rdns.?.runtime.entered.load(.acquire));
    try std.testing.expect(!b.rdns.?.stop_flag.load(.acquire));
}

test "configured runtime: cloned full Mail policy rejects TLS credential trust and journal lineage mutation" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x47);
    defer keys.deinit();
    var password: [10]u8 = "secret-one".*;
    var relay: [9]u8 = "127.0.0.1".*;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var inputs = testInputs(1);
    inputs.core.parsed.mail = .{ .enabled = true, .relay_host = &relay, .from = "sender@localhost", .insecure_skip_verify = false, .user = "name", .pass = &password };
    const anchors = keys.chain;
    inputs.mail_delivery = .{ .trust_anchors = &anchors, .failure = .{ .journal = .{ .io = std.testing.io, .dir = tmp.dir, .path = "failed-delivery.wal" } } };
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    @memset(&password, 'x');
    @memset(&relay, 'x');
    try std.testing.expectEqualStrings("secret-one", b.mail.?.config.pass.?);
    try std.testing.expectEqualStrings("127.0.0.1", b.mail.?.config.relay_host);
    const prior = b.mail.?.config;
    b.mail.?.config.insecure_skip_verify = true;
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.mail.?.config = prior;
    b.mail.?.config.pass = "another-secret";
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.mail.?.config = prior;
    b.mail.?.config.trust_anchors = &.{};
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.mail.?.config = prior;
    b.mail.?.config.failure_dir = std.Io.Dir.cwd();
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.mail.?.config = prior;
    try runtime.requirePrepared();
    try std.testing.expect(!b.mail.?.runtime.entered.load(.acquire));
}

test "configured runtime: configured ACME and OCSP private reverse bindings preserve independent full policy" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x48);
    defer keys.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key_der: [@import("../proto/ed25519_pkcs8.zig").der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_der);
    const encoded_key = try @import("../proto/ed25519_pkcs8.zig").encode(&key_der, keys.seed);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "leaf.der", .data = keys.chain[0] });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "key.der", .data = encoded_key });
    // tmpDir owns this exact cwd-relative namespace. OpenBSD's std.Io backend
    // does not resolve a pathname from an arbitrary directory descriptor.
    const certificate_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/leaf.der", .{tmp.sub_path});
    defer std.testing.allocator.free(certificate_path);
    const key_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/key.der", .{tmp.sub_path});
    defer std.testing.allocator.free(key_path);
    var inputs = testInputs(1);
    keys.install(&inputs);
    inputs.core.parsed.acme = .{ .enabled = true, .domain = "localhost", .contact = "mailto:test@localhost" };
    inputs.core.parsed.tls = .{ .enabled = true, .cert_path = certificate_path, .key_path = key_path };
    inputs.core.parsed.ocsp.enabled = true;
    inputs.core.ocsp_trust_anchors = &keys.chain;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const observation = try runtime.observe();
    try std.testing.expect(observation.core.acme and observation.core.ocsp);
    try std.testing.expectEqual(@as(usize, 2), observation.gate.expected);
    for ([_]server_mod.ManagedCoreFixture.Tamper{ .acme_interval, .ocsp_interval }) |kind| {
        try server_mod.ManagedCoreFixture.tamper(backing(runtime).core.?, kind, true);
        try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
        try server_mod.ManagedCoreFixture.tamper(backing(runtime).core.?, kind, false);
        try runtime.requirePrepared();
    }
}

test "configured runtime: enabled real Webpush uses source demanded options and immutable resolved key subject and trust" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x49);
    defer keys.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try @import("store.zig").OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "accounts.wal");
    defer store.deinit();
    const pair = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(1)));
    const vapid: webpush.Vapid = .{ .key_pair = pair };
    var pubkey: [webpush.vapid_pub_b64_len]u8 = undefined;
    var inputs = testInputs(1);
    inputs.core.parsed.sasl.account_db = "accounts.wal";
    inputs.core.accounts = .{ .store = &store };
    inputs.core.parsed.webpush.enabled = true;
    inputs.core.config.webpush_vapid_pub = vapid.publicB64(&pubkey);
    inputs.webpush_delivery = .{ .vapid = pair, .trust_anchors = &keys.chain };
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    const slot = try b.view.?.slot(.webpush, 0, b.webpush.?);
    try b.view.?.requireSlot(slot, .webpush, 0, b.webpush.?, webpush.dormant_spawn_options);
    try std.testing.expectError(error.InvalidOptions, b.view.?.requireSlot(slot, .webpush, 0, b.webpush.?, .{}));
    try std.testing.expect(!b.webpush.?.runtime.entered.load(.acquire));
    const subject = b.webpush.?.subject;
    b.webpush.?.subject = "mailto:another@localhost";
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.webpush.?.subject = subject;
    const anchors = b.webpush.?.trust_anchors;
    b.webpush.?.trust_anchors = &.{};
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    b.webpush.?.trust_anchors = anchors;
    try runtime.requirePrepared();
}

test "configured runtime: private sealed NodeIdentity has independent secret-page custody through joined destruction" {
    if (comptime !supported) return error.SkipZigTest;
    var identity = try @import("node_identity.zig").fromSeed(@splat(0x27), "closed-runtime-fixture");
    defer identity.deinit();
    const original = identity.sign_kp.secretPage().?;
    var inputs = testInputs(1);
    inputs.core.config.node_identity = &identity;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    var destroyed = false;
    defer if (!destroyed) runtime.deinit();
    const observation = try server_mod.ManagedCoreFixture.inspect(backing(runtime).core.?);
    try std.testing.expect(observation.private_sign_page.? != @intFromPtr(original));
    const signature = try identity.sign_kp.sign("held-source-before-candidate-cleanup");
    runtime.deinit();
    destroyed = true;
    try std.testing.expect(identity.sign_kp.secretPage().? == original);
    try std.testing.expect(try @import("../crypto/sign.zig").verify("held-source-before-candidate-cleanup", signature, identity.sign_kp.public_key));
    _ = try identity.sign_kp.sign("source-still-live-after-candidate-cleanup");
}

test "configured runtime: real WebTransport and Metrics resources retain independent full policy behind the private Gate" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x4a);
    defer keys.deinit();
    var foreign: TestTls = undefined;
    try foreign.init(0x4b);
    defer foreign.deinit();
    var inputs = testInputs(2);
    keys.install(&inputs);
    inputs.core.config.webtransport_port = try unusedUdpPort();
    inputs.core.config.metrics_port = try unusedTcpPort();
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    const observation = try runtime.observe();
    try std.testing.expect(observation.core.metrics and observation.webtransport);
    try std.testing.expectEqual(@as(usize, 4), observation.gate.expected);
    try std.testing.expectEqual(observation.gate.expected, observation.gate.arrived);
    try std.testing.expect(!b.webtransport.?.runtime.entered.load(.acquire));
    const original_tls = b.webtransport.?.tls;
    b.webtransport.?.tls = .{ .cert_chain = &foreign.chain, .signing_key = .{ .ed25519 = foreign.key } };
    try std.testing.expectError(error.ConfigMismatch, runtime.requirePrepared());
    b.webtransport.?.tls = original_tls;
    const proxy = b.webtransport.?.send_proxy_header;
    b.webtransport.?.send_proxy_header = !proxy;
    try std.testing.expectError(error.ConfigMismatch, runtime.requirePrepared());
    b.webtransport.?.send_proxy_header = proxy;
    // Caller storage is no longer the graph's actual TLS or expected TLS.
    @memset(keys.certificate[0..keys.chain[0].len], 0);
    try runtime.requirePrepared();
    try std.testing.expect(b.webtransport.?.tls.cert_chain[0].ptr != b.expected_wt_tls.?.cert_chain[0].ptr);
    try std.testing.expectEqual(gate_mod.Phase.preparing, b.view.?.inspect().phase);
    const inspection = try server_mod.ManagedCoreFixture.inspect(b.core.?);
    const peer = try @import("native_network.zig").connect(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = inputs.core.config.metrics_port } }, 1000);
    defer @import("os_runtime.zig").close(peer);
    try @import("native_network.zig").writeAll(peer, "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    var polls = [_]std.posix.pollfd{.{ .fd = peer, .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&polls, 25));
    try std.testing.expect(!inspection.any_reactor_entered);
}

test "configured runtime: every owned allocation failure refunds construction and permits the same frozen inputs and source borrows to retry" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x4c);
    defer keys.deinit();
    var inputs = testInputs(1);
    inputs.core.config.max_clients = 2;
    inputs.core.config.webhook_enabled = true;
    inputs.core.parsed.dnsbl = .{ .enabled = true, .zones = &.{"dnsbl.runtime.test"} };
    inputs.core.parsed.mail = .{ .enabled = true, .relay_host = "127.0.0.1", .from = "sender@runtime.test", .user = "owner", .pass = "owned-secret-password" };
    inputs.mail_delivery = .{ .trust_anchors = &keys.chain, .failure = .terminal_without_wal };
    // Actual unrelated listener remains owned by its source throughout failure.
    const listener = try @import("reuseport.zig").createReusePortListener("127.0.0.1", 0, 8);
    defer @import("os_runtime.zig").close(listener);
    try @import("os_runtime.zig").setNonblocking(listener);
    try @import("native_network.zig").setTimeout(listener, 1000);
    const before = try @import("metrics_http.zig").observeListener(listener);
    var unlimited = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const complete = try Runtime.createCold(unlimited.allocator(), std.testing.io, inputs, testDeadline());
    try complete.requirePrepared();
    complete.deinit();
    try std.testing.expectEqual(unlimited.allocated_bytes, unlimited.freed_bytes);
    const allocation_count = unlimited.alloc_index;
    try std.testing.expect(allocation_count > 0);
    for (0..allocation_count) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var fixture: FixtureState = .{};
        try std.testing.expectError(error.OutOfMemory, createColdImpl(failing.allocator(), std.testing.io, inputs, testDeadline(), &fixture));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (fixture.canceled) |state| {
            try std.testing.expectEqual(gate_mod.Phase.canceled, state.phase);
            try std.testing.expectEqual(state.spawned, state.joined);
            try std.testing.expect(!fixture.any_body_entered);
        }
        if (fixture.webhook_fd) |fd| try std.testing.expect(!@import("os_runtime.zig").fdValid(fd));
        try std.testing.expect(std.meta.eql(before, try @import("metrics_http.zig").observeListener(listener)));
        failing.fail_index = std.math.maxInt(usize);
        const retry = try Runtime.createCold(failing.allocator(), std.testing.io, inputs, testDeadline());
        try retry.requirePrepared();
        retry.deinit();
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expect(std.meta.eql(before, try @import("metrics_http.zig").observeListener(listener)));
    }
}

test "configured runtime: prepared native and WebRTC media retain full policy and original UDP custody" {
    if (comptime !supported) return error.SkipZigTest;
    var inputs = testInputs(2);
    inputs.core.config.media_enabled = true;
    inputs.core.config.media_port = 0;
    inputs.core.config.native_media_port = 0;
    inputs.core.config.media_max_frame_bytes = 1200;
    inputs.core.config.media_max_upload_bytes = 123456;
    inputs.core.config.media_max_participants = 7;
    inputs.core.config.native_media_require_mac = true;
    inputs.core.config.media_dtls_srtp = false;
    inputs.core.config.media_dtls13 = false;
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    const b = backing(runtime);
    const observation = try runtime.observe();
    try std.testing.expect(observation.core.media);
    try std.testing.expectEqual(@as(usize, 4), observation.gate.expected);
    try std.testing.expectEqual(observation.gate.expected, observation.gate.arrived);
    try std.testing.expect(!((try server_mod.ManagedCoreFixture.inspect(b.core.?)).any_reactor_entered));
    for ([_]server_mod.ManagedCoreFixture.Tamper{
        .native_frame, .native_upload, .native_participants, .native_mac_key,       .native_mac_enabled,
        .media_frame,  .media_upload,  .media_stun,          .media_dtls_requested, .media_dtls13_requested,
    }) |kind| {
        try server_mod.ManagedCoreFixture.tamper(b.core.?, kind, true);
        try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
        try server_mod.ManagedCoreFixture.tamper(b.core.?, kind, false);
        try runtime.requirePrepared();
    }
    // Equal socket type/bind policy is insufficient to substitute another NEW
    // owner. Swapping both descriptor and advertised port preserves those
    // superficial relations but violates the retained preparation observations.
    server_mod.ManagedCoreFixture.swapPreparedMediaSockets(b.core.?);
    var swapped = true;
    defer if (swapped) server_mod.ManagedCoreFixture.swapPreparedMediaSockets(b.core.?);
    try std.testing.expectError(error.ConfiguredOwnerMismatch, runtime.requirePrepared());
    server_mod.ManagedCoreFixture.swapPreparedMediaSockets(b.core.?);
    swapped = false;
    try runtime.requirePrepared();
    try std.testing.expectEqual(gate_mod.Phase.preparing, b.view.?.inspect().phase);
}

test "configured runtime: same real Core retries every Gate allocation failure and refuses reissuance before and after cancellation" {
    if (comptime !supported) return error.SkipZigTest;
    var failures: usize = 0;
    var index: usize = 0;
    while (index < 8) : (index += 1) {
        // FailingAllocator must outlive the graph which borrows it.
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var owner: TestPrimitiveCore = .{};
        try owner.init(2);
        defer owner.deinit();
        const core = owner.core.?;
        const source_before = try server_mod.ManagedCoreFixture.inspect(core);
        const policy_before = try core.observe();
        const listener_before = try @import("metrics_http.zig").observeListener(source_before.webhook_fd.?);
        var induced = false;
        owner.graph = core.createGraphControl(failing.allocator(), null) catch |err| blk: {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            try std.testing.expect(std.meta.eql(source_before, try server_mod.ManagedCoreFixture.inspect(core)));
            try std.testing.expect(std.meta.eql(policy_before, try core.observe()));
            try std.testing.expect(std.meta.eql(listener_before, try @import("metrics_http.zig").observeListener(source_before.webhook_fd.?)));
            failures += 1;
            induced = true;
            // Retry this exact Core and its held original listener, not a new
            // candidate. Disable pressure on the same live allocator facade.
            failing.fail_index = std.math.maxInt(usize);
            break :blk try core.createGraphControl(failing.allocator(), null);
        };
        const graph = owner.graph.?;
        const allocated_after = failing.alloc_index;
        const status_after = graph.view.inspect();
        try std.testing.expectError(error.NotPrepared, core.createGraphControl(failing.allocator(), null));
        try std.testing.expectEqual(allocated_after, failing.alloc_index);
        try std.testing.expect(std.meta.eql(status_after, graph.view.inspect()));
        try std.testing.expect(std.meta.eql(source_before, try server_mod.ManagedCoreFixture.inspect(core)));
        try std.testing.expect(std.meta.eql(listener_before, try @import("metrics_http.zig").observeListener(source_before.webhook_fd.?)));
        try core.prepareWorkers(graph.control, graph.view);
        try graph.control.awaitAllParked(testDeadline());
        try core.requirePrepared();
        try std.testing.expect(!((try server_mod.ManagedCoreFixture.inspect(core)).any_reactor_entered));
        graph.control.cancelAllAndJoin();
        const canceled = graph.view.inspect();
        try std.testing.expectEqual(gate_mod.Phase.canceled, canceled.phase);
        try std.testing.expectEqual(canceled.spawned, canceled.joined);
        try std.testing.expectError(error.NotPrepared, core.createGraphControl(failing.allocator(), null));
        try std.testing.expectEqual(allocated_after, failing.alloc_index);
        try std.testing.expect(std.meta.eql(canceled, graph.view.inspect()));
        try std.testing.expect(std.meta.eql(listener_before, try @import("metrics_http.zig").observeListener(source_before.webhook_fd.?)));
        owner.deinit();
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expect(!@import("os_runtime.zig").fdValid(source_before.webhook_fd.?));
        if (!induced) {
            try std.testing.expectEqual(@as(usize, 2), failures);
            return;
        }
    }
    return error.TestSweepIncomplete;
}

test "configured runtime: two real Core Gate pairs reject valid foreign and mixed authority before mutation and then prepare independently" {
    if (comptime !supported) return error.SkipZigTest;
    var first: TestPrimitiveCore = .{};
    try first.init(2);
    defer first.deinit();
    var second: TestPrimitiveCore = .{};
    try second.init(3);
    defer second.deinit();
    first.graph = try first.core.?.createGraphControl(std.testing.allocator, null);
    second.graph = try second.core.?.createGraphControl(std.testing.allocator, null);
    const a = first.graph.?;
    const b = second.graph.?;
    const first_before = try server_mod.ManagedCoreFixture.inspect(first.core.?);
    const second_before = try server_mod.ManagedCoreFixture.inspect(second.core.?);
    const a_before = a.view.inspect();
    const b_before = b.view.inspect();
    try std.testing.expectError(error.NotPrepared, first.core.?.prepareWorkers(b.control, b.view));
    try std.testing.expectError(error.NotPrepared, second.core.?.prepareWorkers(a.control, a.view));
    try std.testing.expectError(error.InvalidGate, first.core.?.prepareWorkers(a.control, b.view));
    try std.testing.expectError(error.InvalidGate, second.core.?.prepareWorkers(b.control, a.view));
    try std.testing.expect(std.meta.eql(a_before, a.view.inspect()));
    try std.testing.expect(std.meta.eql(b_before, b.view.inspect()));
    try std.testing.expect(std.meta.eql(first_before, try server_mod.ManagedCoreFixture.inspect(first.core.?)));
    try std.testing.expect(std.meta.eql(second_before, try server_mod.ManagedCoreFixture.inspect(second.core.?)));
    try first.core.?.prepareWorkers(a.control, a.view);
    try a.control.awaitAllParked(testDeadline());
    try first.core.?.requirePrepared();
    // Preparing A neither spawns nor mutates B.
    try std.testing.expect(std.meta.eql(b_before, b.view.inspect()));
    try std.testing.expect(std.meta.eql(second_before, try server_mod.ManagedCoreFixture.inspect(second.core.?)));
    try second.core.?.prepareWorkers(b.control, b.view);
    try b.control.awaitAllParked(testDeadline());
    try second.core.?.requirePrepared();
    const a_parked = a.view.inspect();
    const b_parked = b.view.inspect();
    try std.testing.expectEqual(@as(usize, 3), a_parked.expected);
    try std.testing.expectEqual(@as(usize, 4), b_parked.expected);
    try std.testing.expectEqual(a_parked.expected, a_parked.arrived);
    try std.testing.expectEqual(b_parked.expected, b_parked.arrived);
    try std.testing.expect(!((try server_mod.ManagedCoreFixture.inspect(first.core.?)).any_reactor_entered));
    try std.testing.expect(!((try server_mod.ManagedCoreFixture.inspect(second.core.?)).any_reactor_entered));
    first.deinit();
    try second.core.?.requirePrepared();
    try std.testing.expect(std.meta.eql(b_parked, b.view.inspect()));
    try std.testing.expect(!@import("os_runtime.zig").fdValid(first_before.webhook_fd.?));
    try std.testing.expect(@import("os_runtime.zig").fdValid(second_before.webhook_fd.?));
}

fn awaitRuntimeActivated(runtime: *Runtime) !void {
    const deadline = testDeadline();
    while (true) {
        if (runtime.requireActivated()) |_| return else |err| switch (err) {
            error.RuntimeNotActivated, error.NotPrepared => {},
            else => return err,
        }
        if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(std.testing.io, .awake), .gte, deadline)) return error.TestWorkerTimeout;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
}
fn expectRuntimePing(runtime: *Runtime) !void {
    const network = @import("native_network.zig");
    const os = @import("os_runtime.zig");
    const port = (try backing(runtime).core.?.observe()).bound_port;
    const peer = try network.connect(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } }, 1000);
    defer os.close(peer);
    try network.writeAll(peer, "NICK runtime_peer\r\nUSER runtime_peer 0 * :Runtime peer\r\nPING :runtime_owned_graph\r\n");
    try os.setNonblocking(peer);
    var received: [4096]u8 = undefined;
    var used: usize = 0;
    const deadline = testDeadline();
    while (used < received.len) {
        const count = os.read(peer, received[used..]) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        used += count;
        if (std.mem.indexOf(u8, received[0..used], "PONG") != null and std.mem.indexOf(u8, received[0..used], "runtime_owned_graph") != null) return;
        if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(std.testing.io, .awake), .gte, deadline)) return error.TestTransportTimeout;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    return error.TestTransportOverflow;
}

test "configured runtime: original graph publishes inline and sharded real transports then joins every source before disposal" {
    if (comptime !supported) return error.SkipZigTest;
    for ([_]u16{ 1, 3 }) |shards| {
        var inputs = testInputs(shards);
        inputs.dns_config = configuredResolver();
        inputs.core.config.webhook_enabled = true;
        inputs.core.config.geo_enabled = true;
        inputs.core.parsed.dnsbl.enabled = true;
        inputs.core.parsed.dnsbl.zones = &.{"dnsbl.runtime.test"};
        inputs.core.parsed.mail.enabled = true;
        inputs.core.parsed.mail.relay_host = "127.0.0.1";
        inputs.core.parsed.mail.relay_port = 1;
        inputs.core.parsed.mail.from = "runtime@localhost";
        inputs.mail_delivery = .{ .failure = .terminal_without_wal };
        const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
        defer runtime.deinit();
        const b = backing(runtime);
        const original_core = b.core.?;
        const original_control = b.control.?;
        const original_view = b.view.?;
        const listener = (try server_mod.ManagedCoreFixture.inspect(b.core.?)).webhook_fd.?;
        try std.testing.expectError(error.NotPublished, runtime.requireActivated());
        try runtime.publish();
        defer _ = runtime.stop(testDeadline()) catch @panic("test graph must stop before disposal");
        try std.testing.expectError(error.NotPrepared, runtime.publish());
        try awaitRuntimeActivated(runtime);
        try expectRuntimePing(runtime);
        try std.testing.expect(b.core.? == original_core and b.control.? == original_control and b.view.? == original_view);
        const observation = try runtime.stop(testDeadline());
        try std.testing.expectEqual(gate_mod.Phase.released, observation.gate.phase);
        try std.testing.expectEqual(observation.gate.spawned, observation.gate.joined);
        try std.testing.expect(observation.inline_joined);
        try std.testing.expect(b.rdns_retained != null and b.dnsbl_retained != null);
        try std.testing.expect(b.rdns.?.runtime.view == null and b.mail.?.runtime.view == null);
        try std.testing.expect(@import("os_runtime.zig").fdValid(listener));
        try std.testing.expectError(error.NotPublished, runtime.requireActivated());
        // A repeated stop observes the same retained ownership and exact joins.
        try std.testing.expect(std.meta.eql(observation, try runtime.stop(testDeadline())));
    }
}

test "configured runtime: failed actual inline caller spawn leaves no publication and requires a fresh candidate" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture: FixtureState = .{ .fail_inline_spawn = true };
    const failed = try createColdImpl(std.testing.allocator, std.testing.io, testInputs(1), testDeadline(), &fixture);
    try std.testing.expectError(error.SystemResources, failed.publish());
    const b = backing(failed);
    try std.testing.expectEqual(Phase.publication_failed, b.phase);
    try std.testing.expectEqual(gate_mod.Phase.preparing, b.view.?.inspect().phase);
    try std.testing.expect(b.inline_thread == null and b.inline_custody == null);
    try std.testing.expect(!(try server_mod.ManagedCoreFixture.inspect(b.core.?)).any_reactor_entered);
    try std.testing.expectError(error.NotPrepared, failed.publish());
    failed.deinit();
    const fresh = try Runtime.createCold(std.testing.allocator, std.testing.io, testInputs(1), testDeadline());
    defer fresh.deinit();
    try fresh.publish();
    defer _ = fresh.stop(testDeadline()) catch @panic("fresh inline fixture stop");
    try awaitRuntimeActivated(fresh);
    try expectRuntimePing(fresh);
}

test "configured runtime: configured Webpush and WebTransport publish their real sources and retain joined settlement custody" {
    if (comptime !supported) return error.SkipZigTest;
    var keys: TestTls = undefined;
    try keys.init(0x57);
    defer keys.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try @import("store.zig").OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "accounts.wal");
    defer store.deinit();
    const pair = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(1)));
    const vapid: webpush.Vapid = .{ .key_pair = pair };
    var pubkey: [webpush.vapid_pub_b64_len]u8 = undefined;
    var inputs = testInputs(2);
    keys.install(&inputs);
    inputs.core.parsed.sasl.account_db = "accounts.wal";
    inputs.core.accounts = .{ .store = &store };
    inputs.core.parsed.webpush.enabled = true;
    inputs.core.config.webpush_vapid_pub = vapid.publicB64(&pubkey);
    inputs.webpush_delivery = .{ .vapid = pair, .trust_anchors = &keys.chain };
    inputs.core.config.webtransport_port = try unusedUdpPort();
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, inputs, testDeadline());
    defer runtime.deinit();
    try runtime.publish();
    defer _ = runtime.stop(testDeadline()) catch @panic("configured delivery source fixture stop");
    try awaitRuntimeActivated(runtime);
    try expectRuntimePing(runtime);
    const b = backing(runtime);
    try std.testing.expect(b.webpush.?.runtime.entered.load(.acquire));
    try std.testing.expect(b.webtransport.?.runtime.entered.load(.acquire));
    const stopped = try runtime.stop(testDeadline());
    try std.testing.expectEqual(stopped.gate.spawned, stopped.gate.joined);
    try std.testing.expectEqual(@as(usize, 0), stopped.retained_webpush_jobs);
    try std.testing.expect(b.webpush_retained != null);
    try std.testing.expect(b.webpush.?.runtime.exited.load(.acquire));
    try std.testing.expect(b.webtransport.?.runtime.exited.load(.acquire));
    try std.testing.expect(b.webpush.?.runtime.view == null and b.webtransport.?.runtime.view == null);
}

test "configured runtime: every resolver settlement allocation failure preserves the published paused source and retries same graph" {
    if (comptime !supported) return error.SkipZigTest;
    var failures: usize = 0;
    for (0..4) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        var fixture: FixtureState = .{ .snapshot_allocator = failing.allocator() };
        var inputs = testInputs(2);
        inputs.dns_config = configuredResolver();
        const runtime = try createColdImpl(std.testing.allocator, std.testing.io, inputs, testDeadline(), &fixture);
        defer runtime.deinit();
        try runtime.publish();
        defer _ = runtime.stop(testDeadline()) catch @panic("resolver pressure fixture stop");
        try awaitRuntimeActivated(runtime);
        const b = backing(runtime);
        const core = b.core.?;
        const control = b.control.?;
        const owner = b.rdns.?;
        b.rdns_pause = try owner.requestPause(1);
        try owner.awaitPaused(b.rdns_pause.?, testDeadline());
        const accepted: dns.Address = .{ .ipv4 = .{ 192, 0, 2, 123 } };
        owner.request(accepted);
        try std.testing.expectEqual(@as(usize, 1), owner.job_count);
        var induced = false;
        const result = runtime.stop(testDeadline()) catch |err| blk: {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            try std.testing.expect(b.core.? == core and b.control.? == control and b.rdns.? == owner);
            try std.testing.expect(b.run.load(.acquire));
            try std.testing.expectEqual(Phase.stopping, b.phase);
            try std.testing.expectEqual(@as(usize, 0), b.view.?.inspect().joined);
            try std.testing.expectEqual(@as(usize, 1), owner.job_count);
            try owner.requireProducersFrozen(b.rdns_fence.?);
            try owner.runtime.pause.requirePaused(b.rdns_pause.?);
            failures += 1;
            induced = true;
            failing.fail_index = std.math.maxInt(usize);
            break :blk try runtime.stop(testDeadline());
        };
        try std.testing.expectEqual(@as(usize, 1), result.retained_rdns_jobs);
        try std.testing.expect(std.meta.eql(accepted, b.rdns_retained.?.jobs[0]));
        try std.testing.expectEqual(result.gate.spawned, result.gate.joined);
        if (!induced) {
            try std.testing.expectEqual(@as(usize, 2), failures);
            return;
        }
    }
    return error.TestSweepIncomplete;
}

test "configured runtime: invalid terminal deadlines cannot publish a producer fence or stop any original source" {
    if (comptime !supported) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidMonotonicClock, checkedStopDeadlineMillis(2 * std.time.ns_per_ms, 0, -1));
    try std.testing.expectError(error.InvalidDeadline, checkedStopDeadlineMillis(std.math.maxInt(i96), -1, 1));
    try std.testing.expectError(error.InvalidDeadline, checkedStopDeadlineMillis(@as(i96, std.math.maxInt(u64)) * std.time.ns_per_ms, 0, 1));
    try std.testing.expectError(error.Timeout, checkedStopDeadlineMillis(0, 1, 1));
    // A delay after the earlier monotonic sample uses the later awake sample.
    // Crossing the original absolute deadline refuses instead of extending it.
    try std.testing.expectError(error.Timeout, checkedStopDeadlineMillis(5_000 * std.time.ns_per_ms, 10_000 * std.time.ns_per_ms, 100));
    try std.testing.expectEqual(@as(u64, 1100), try checkedStopDeadlineMillis(5_000 * std.time.ns_per_ms, 4_000 * std.time.ns_per_ms, 100));
    const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, testInputs(2), testDeadline());
    defer runtime.deinit();
    try runtime.publish();
    defer _ = runtime.stop(testDeadline()) catch @panic("invalid deadline fixture stop");
    try awaitRuntimeActivated(runtime);
    const b = backing(runtime);
    const before = b.view.?.inspect();
    const wrong_clock: std.Io.Clock.Timestamp = .{ .clock = .real, .raw = testDeadline().raw };
    try std.testing.expectError(error.InvalidDeadline, runtime.stop(wrong_clock));
    try std.testing.expect(std.meta.eql(before, b.view.?.inspect()));
    try std.testing.expectEqual(Phase.published, b.phase);
    try std.testing.expect(b.run.load(.acquire) and b.rdns_fence == null);
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .{ .nanoseconds = 0 } };
    try std.testing.expectError(error.Timeout, runtime.stop(expired));
    try std.testing.expect(std.meta.eql(before, b.view.?.inspect()));
    try std.testing.expectEqual(Phase.published, b.phase);
    try std.testing.expect(b.run.load(.acquire) and b.rdns_fence == null);
    try expectRuntimePing(runtime);
}

test "configured runtime: immediate terminal stop joins the actual late inline caller and cancels source entry without a permanent failure" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture: FixtureState = .{ .hold_inline_start = true, .release_inline_during_stop = true };
    const runtime = try createColdImpl(std.testing.allocator, std.testing.io, testInputs(1), testDeadline(), &fixture);
    defer runtime.deinit();
    try runtime.publish();
    defer _ = runtime.stop(testDeadline()) catch @panic("late inline fixture stop");
    try fixture.held_inline.waitTimeout(std.testing.io, .{ .deadline = testDeadline() });
    const b = backing(runtime);
    try std.testing.expect(b.inline_thread != null and b.inline_custody != null);
    try std.testing.expect(!(try server_mod.ManagedCoreFixture.inspect(b.core.?)).any_reactor_entered);
    try std.testing.expectError(error.RuntimeNotActivated, runtime.requireActivated());
    const result = try runtime.stop(testDeadline());
    try std.testing.expect(result.inline_joined);
    try std.testing.expect(b.inline_thread == null and b.inline_custody == null and b.inline_error == null);
    try std.testing.expect(std.meta.eql(result, try runtime.stop(testDeadline())));
}

const runtime_prune_accounts = [_][]const u8{ "alice", "bob", "carol" };
const runtime_prune_endpoint = "https://push.example.test/gone";

fn seedRuntimeWebpushAccounts(store: *@import("store.zig").OroStore, pair: ecdsa.KeyPair) !void {
    const svc_mod = @import("services.zig");
    var services = svc_mod.Services.initWithConfig(store, null, .{ .pbkdf2_rounds = 1 });
    var scratch: [4096]u8 = undefined;
    const subs = [_]webpush.Subscription{.{
        .endpoint = @constCast(runtime_prune_endpoint),
        .ua_public = pair.public_key.toUncompressedSec1(),
        .auth = @splat(9),
    }};
    const blob = try webpush.encodeList(std.testing.allocator, &subs);
    defer std.testing.allocator.free(blob);
    for (runtime_prune_accounts) |account| {
        _ = try services.registerAccount(account, "test-password", &scratch);
        try services.webpushPut(account, blob);
    }
}
fn runtimeWebpushInputs(store: *@import("store.zig").OroStore, pair: ecdsa.KeyPair, public_key: *[webpush.vapid_pub_b64_len]u8) ColdInputs {
    var inputs = testInputs(2);
    inputs.core.parsed.accounts.pbkdf2_rounds = 1;
    inputs.core.parsed.sasl.account_db = "runtime-prune.wal";
    inputs.core.accounts = .{ .store = store };
    inputs.core.parsed.webpush.enabled = true;
    const vapid: webpush.Vapid = .{ .key_pair = pair };
    inputs.core.config.webpush_vapid_pub = vapid.publicB64(public_key);
    inputs.webpush_delivery = .{ .vapid = pair, .trust_anchors = &.{} };
    return inputs;
}
fn expectRuntimeDeadSubscriptionsGone(store: *@import("store.zig").OroStore) !void {
    for (runtime_prune_accounts) |account| {
        var key: [64]u8 = undefined;
        const encoded = try std.fmt.bufPrint(&key, "wps\x00{s}", .{account});
        try std.testing.expect(store.family(.props).get(encoded) == null);
    }
}

test "configured runtime: seeded original Webpush outputs survive Store OOM with real graph custody then prune every account and never queue after cold reopen" {
    if (comptime !supported) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pair = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(1)));
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var store = try @import("store.zig").OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "runtime-prune.wal");
        defer store.deinit();
        try seedRuntimeWebpushAccounts(&store, pair);
        var public_key: [webpush.vapid_pub_b64_len]u8 = undefined;
        const runtime = try Runtime.createCold(std.testing.allocator, std.testing.io, runtimeWebpushInputs(&store, pair, &public_key), testDeadline());
        defer runtime.deinit();
        try runtime.publish();
        defer {
            server_mod.ManagedCoreFixture.setWebpushStoreFailure(backing(runtime).core.?, &failing, false) catch @panic("seeded output fixture source-owned disarm");
            _ = runtime.stop(testDeadline()) catch @panic("seeded output fixture genuine source retry before disposal");
        }
        try awaitRuntimeActivated(runtime);
        const b = backing(runtime);
        const owner = b.webpush.?;
        b.webpush_pause = try owner.requestPause(1);
        try owner.awaitPaused(b.webpush_pause.?, testDeadline());
        // Explicitly seed an original paused source outcome. This exercises
        // graph/Store consumer composition, not an HTTP 410 transport journey.
        const core = b.core.?;
        const control = b.control.?;
        const view = b.view.?;
        const sequence = store.next_seq;
        const offset = store.wal_offset;
        // Maintenance also consumes dead outcomes. Seed and arm failure in
        // one actual World→Worker cut, preventing a pre-stop pruning race.
        const gone = try server_mod.ManagedCoreFixture.seedWebpushDeadWithStoreFailure(core, runtime_prune_endpoint, &failing);
        try std.testing.expectError(error.OutOfMemory, runtime.stop(testDeadline()));
        try std.testing.expect(b.core.? == core and b.control.? == control and b.view.? == view and b.webpush.? == owner);
        try std.testing.expectEqual(Phase.stopping, b.phase);
        try std.testing.expect(b.run.load(.acquire));
        try view.requireSlotJoined(try view.slot(.webpush, 0, owner));
        try owner.requireProducersFrozen(b.webpush_fence.?);
        try std.testing.expectEqual(@as(usize, 1), owner.dead.items.len);
        try std.testing.expect(owner.dead.items[0].ptr == gone.ptr);
        try std.testing.expectEqualStrings(runtime_prune_endpoint, owner.dead.items[0]);
        try std.testing.expectEqual(@as(usize, 1), b.webpush_retained.?.dead.len);
        try std.testing.expectEqualStrings(runtime_prune_endpoint, b.webpush_retained.?.dead[0]);
        try std.testing.expectError(error.PendingOutput, owner.requireTerminalSettled(b.webpush_fence.?));
        try std.testing.expectEqual(sequence, store.next_seq);
        try std.testing.expectEqual(offset, store.wal_offset);
        try expectRuntimePing(runtime); // Original Core consumer is still live.
        {
            var world_entered: std.Io.Event = .unset;
            var world_release: std.Io.Event = .unset;
            const holder = try std.Thread.spawn(.{}, server_mod.ManagedCoreFixture.holdWorld, .{ core, &world_entered, &world_release });
            defer {
                // Join this actual fixture borrower before any source retry
                // or graph destruction, including assertion failure cleanup.
                world_release.set(std.testing.io);
                holder.join();
            }
            try world_entered.waitTimeout(std.testing.io, .{ .deadline = testDeadline() });
            const short: std.Io.Clock.Timestamp = .{
                .clock = .awake,
                .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(250)),
            };
            // Source producers already joined and snapshots already exist.
            // This retry must stop at the held original World's deadline.
            try std.testing.expectError(error.Timeout, runtime.stop(short));
            try std.testing.expectEqual(Phase.stopping, b.phase);
            try std.testing.expect(b.core.? == core and b.control.? == control and b.view.? == view and b.webpush.? == owner);
            try std.testing.expect(b.run.load(.acquire));
            try view.requireSlotJoined(try view.slot(.webpush, 0, owner));
            try owner.requireProducersFrozen(b.webpush_fence.?);
            try std.testing.expectEqual(@as(usize, 1), owner.dead.items.len);
            try std.testing.expect(owner.dead.items[0].ptr == gone.ptr);
            try std.testing.expectEqual(sequence, store.next_seq);
            try std.testing.expectEqual(offset, store.wal_offset);
        }
        try server_mod.ManagedCoreFixture.setWebpushStoreFailure(core, &failing, false);
        const stopped = try runtime.stop(testDeadline());
        try std.testing.expectEqual(stopped.gate.spawned, stopped.gate.joined);
        try std.testing.expectEqual(@as(usize, 0), owner.dead.items.len);
        try expectRuntimeDeadSubscriptionsGone(&store);
    }
    // The original graph and Store both closed above. Recover through a NEW
    // actual cold owner, retaining its own lexical Store loan through joins.
    var reopened = try @import("store.zig").OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "runtime-prune.wal");
    defer reopened.deinit();
    try expectRuntimeDeadSubscriptionsGone(&reopened);
    var public_key: [webpush.vapid_pub_b64_len]u8 = undefined;
    const fresh = try Runtime.createCold(std.testing.allocator, std.testing.io, runtimeWebpushInputs(&reopened, pair, &public_key), testDeadline());
    defer fresh.deinit();
    try fresh.publish();
    defer _ = fresh.stop(testDeadline()) catch @panic("cold pruned subscription fixture stop");
    try awaitRuntimeActivated(fresh);
    const b = backing(fresh);
    const worker = b.webpush.?;
    b.webpush_pause = try worker.requestPause(1);
    try worker.awaitPaused(b.webpush_pause.?, testDeadline());
    for (runtime_prune_accounts) |account|
        try server_mod.ManagedCoreFixture.notifyWebpush(b.core.?, account, "sender", "later message after cold reopen");
    while (!worker.mutex.tryLock()) std.atomic.spinLoopHint();
    const queued = worker.queue.items.len;
    worker.mutex.unlock();
    try std.testing.expectEqual(@as(usize, 0), queued);
    try expectRuntimePing(fresh);
}
