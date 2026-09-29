// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Apply one OCG2 projection generation to live sessions.
//!
//! The projection runtime stays session-free. This module drains one prepared
//! generation, reconciles each logged-in session against the durable image,
//! and records every privilege change on the audit trail. A failed apply
//! restores the session privilege image captured at the start of the pass and
//! aborts the generation, so the previously acknowledged baseline stays.

const std = @import("std");
const audit_trail = @import("audit_trail.zig");
const dispatch = @import("dispatch.zig");
const oper = @import("oper.zig");
const oper_session_provenance = @import("oper_session_provenance.zig");
const projection = @import("ocg2_projection_runtime.zig");
const services_mod = @import("services.zig");

const Session = dispatch.ClientSession;

pub const SessionRef = struct {
    session: *Session,
    configured_binding: ?oper_session_provenance.ConfiguredLocalBinding = null,
};

pub const Outcome = union(enum) {
    committed: usize,
    unchanged,
    aborted,
    busy,
    retryable: projection.Retryable,
    terminal: projection.Failure,
};

const Image = struct {
    is_oper: bool,
    oper_priv: oper.OperPrivileges,
    oper_provenance: oper_session_provenance.Provenance,
    oper_class_store: @FieldType(Session, "oper_class_store"),
    oper_title_store: @FieldType(Session, "oper_title_store"),
    umodes: @FieldType(Session, "umodes"),
    event_mask: @FieldType(Session, "event_mask"),
    event_min_severity: @FieldType(Session, "event_min_severity"),
    event_subject_masks: @FieldType(Session, "event_subject_masks"),
    ircx_event_mask: @FieldType(Session, "ircx_event_mask"),
    ircx_event_subject_masks: @FieldType(Session, "ircx_event_subject_masks"),
};

fn capture(session: *const Session) Image {
    return .{
        .is_oper = session.is_oper,
        .oper_priv = session.oper_priv,
        .oper_provenance = session.oper_provenance,
        .oper_class_store = session.oper_class_store,
        .oper_title_store = session.oper_title_store,
        .umodes = session.umodes,
        .event_mask = session.event_mask,
        .event_min_severity = session.event_min_severity,
        .event_subject_masks = session.event_subject_masks,
        .ircx_event_mask = session.ircx_event_mask,
        .ircx_event_subject_masks = session.ircx_event_subject_masks,
    };
}

fn restore(session: *Session, image: Image) void {
    session.is_oper = image.is_oper;
    session.oper_priv = image.oper_priv;
    session.oper_provenance = image.oper_provenance;
    session.oper_class_store = image.oper_class_store;
    session.oper_title_store = image.oper_title_store;
    session.umodes = image.umodes;
    session.event_mask = image.event_mask;
    session.event_min_severity = image.event_min_severity;
    session.event_subject_masks = image.event_subject_masks;
    session.ircx_event_mask = image.ircx_event_mask;
    session.ircx_event_subject_masks = image.ircx_event_subject_masks;
}

fn restoreAll(sessions: []const SessionRef, images: []const Image) void {
    for (sessions, images) |slot, image| restore(slot.session, image);
}

fn lookupFrom(inspection: projection.AccountInspection) oper_session_provenance.DurableOperLookup {
    return switch (inspection) {
        .unavailable, .terminal => .unavailable,
        .absent => .absent,
        .not_yet_valid => .not_yet_valid,
        .expired => .expired,
        .tombstone => .tombstone,
        .equivocation => .equivocation,
        .active => |grant| .{ .active = grant },
    };
}

fn storedBytes(store: anytype) []const u8 {
    return store.bytes[0..store.len];
}

fn privilegeChanged(before: Image, session: *const Session) bool {
    if (before.is_oper != session.is_oper) return true;
    if (before.oper_priv.toBits() != session.oper_priv.toBits()) return true;
    if (!std.mem.eql(u8, storedBytes(before.oper_class_store), session.operClass())) return true;
    if (!std.mem.eql(u8, storedBytes(before.oper_title_store), session.operTitle())) return true;
    return false;
}

const Change = enum { none, grant, revoke };

fn auditLine(audit: *audit_trail.AuditTrail, text: []const u8, at_ms: i64) !void {
    _ = try audit.append("ocg2", text, at_ms);
}

fn rollback(runtime: *projection.Runtime, cursor: projection.Ticket, sessions: []const SessionRef, images: []const Image, audit: *audit_trail.AuditTrail, at_ms: i64) Outcome {
    restoreAll(sessions, images);
    _ = runtime.abort(cursor);
    auditLine(audit, "rollback", at_ms) catch {};
    return .aborted;
}

/// Drain one generation and project it onto `sessions`.
/// `elapsed_ms` must be 0 on the first call for a runtime and must not go
/// backwards. Session privilege changes and an authority-image ack are
/// appended to `audit` before the generation is acknowledged.
pub fn projectOnce(
    allocator: std.mem.Allocator,
    runtime: *projection.Runtime,
    sessions: []const SessionRef,
    audit: *audit_trail.AuditTrail,
    now_ms: u64,
    elapsed_ms: u64,
) error{OutOfMemory}!Outcome {
    const prepared = runtime.prepare(now_ms, elapsed_ms);
    const ticket = switch (prepared) {
        .ready => |value| value,
        .busy => return .busy,
        .retryable => |reason| return .{ .retryable = reason },
        .terminal => |failure| return .{ .terminal = failure },
    };
    var cursor = ticket;
    while (true) switch (runtime.next(&cursor)) {
        .item => {},
        .done => break,
        .stale => return rollback(runtime, cursor, &.{}, &.{}, audit, 0),
        .terminal => |failure| return .{ .terminal = failure },
    };

    const security_now = runtime.summary().last_security_now_ms orelse {
        return rollback(runtime, cursor, &.{}, &.{}, audit, 0);
    };
    const at_ms = std.math.cast(i64, security_now) orelse {
        return rollback(runtime, cursor, &.{}, &.{}, audit, 0);
    };

    const images = allocator.alloc(Image, sessions.len) catch {
        _ = runtime.abort(cursor);
        return error.OutOfMemory;
    };
    defer allocator.free(images);
    const changes = allocator.alloc(Change, sessions.len) catch {
        _ = runtime.abort(cursor);
        return error.OutOfMemory;
    };
    defer allocator.free(changes);

    for (sessions, images, changes) |slot, *image, *change| {
        image.* = capture(slot.session);
        change.* = .none;
        const lookup: oper_session_provenance.DurableOperLookup = if (slot.session.account()) |account|
            lookupFrom(runtime.inspectAccount(account))
        else
            .absent;
        const reconciled = slot.session.reconcileOperAuthority(slot.configured_binding, lookup, security_now);
        if (reconciled == .authority_unavailable) return rollback(runtime, cursor, sessions, images, audit, at_ms);
        if (!privilegeChanged(image.*, slot.session)) continue;
        change.* = if (slot.session.isOper()) .grant else .revoke;
    }

    var transitions: usize = 0;
    for (sessions, changes) |slot, change| {
        if (change == .none) continue;
        var buf: [80]u8 = undefined;
        const account = slot.session.account() orelse "";
        const text = std.fmt.bufPrint(&buf, "{s} {s}", .{ @tagName(change), account }) catch @tagName(change);
        auditLine(audit, text, at_ms) catch return rollback(runtime, cursor, sessions, images, audit, at_ms);
        transitions += 1;
    }
    if (runtime.summary().pending_count > 0) {
        auditLine(audit, "ack", at_ms) catch return rollback(runtime, cursor, sessions, images, audit, at_ms);
    }

    return switch (runtime.ack(cursor)) {
        .committed => if (transitions == 0) .unchanged else .{ .committed = transitions },
        .stale, .not_drained => rollback(runtime, cursor, sessions, images, audit, at_ms),
        .terminal => |failure| .{ .terminal = failure },
    };
}

pub const Peer = struct {
    services: *services_mod.Services,
    runtime: *projection.Runtime,
    sessions: []const SessionRef,
    audit: *audit_trail.AuditTrail,
};

pub const MeshError = error{
    OutOfMemory,
    Rejected,
    RolledBack,
    Terminal,
    Busy,
    Retryable,
};

/// Commit one signed OCG2 record on every peer, then project it onto that
/// peer's live sessions. A peer that fails to project restores its previous
/// session image. The signed record is the mesh-wide revoke or grant.
pub fn commitMeshWide(
    allocator: std.mem.Allocator,
    wire: []const u8,
    now_ms: u64,
    elapsed_ms: u64,
    peers: []const Peer,
) MeshError!void {
    for (peers) |peer| {
        switch (peer.services.commitDurableOperRecord(wire, now_ms)) {
            .committed, .replay, .stale => {},
            else => return error.Rejected,
        }
    }
    for (peers) |peer| {
        switch (try projectOnce(allocator, peer.runtime, peer.sessions, peer.audit, now_ms, elapsed_ms)) {
            .committed, .unchanged => {},
            .aborted => return error.RolledBack,
            .busy => return error.Busy,
            .retryable => return error.Retryable,
            .terminal => return error.Terminal,
        }
    }
}

// ───────────────────────────── DST ──────────────────────────────

const durable_oper_authority = @import("durable_oper_authority.zig");
const durable_oper_authority_boot = @import("durable_oper_authority_boot.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");
const store_mod = @import("store.zig");

const accepted_storage = store_mod.Config{
    .max_record_bytes = durable_oper_authority.max_store_payload_bytes,
    .max_wal_bytes = durable_oper_authority.max_store_wal_record_bytes,
};

const FailFirst = struct {
    inner: std.mem.Allocator,
    armed: bool = true,

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *FailFirst = @ptrCast(@alignCast(ctx));
        if (self.armed) {
            self.armed = false;
            return null;
        }
        return self.inner.vtable.alloc(self.inner.ptr, len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *FailFirst = @ptrCast(@alignCast(ctx));
        return self.inner.vtable.resize(self.inner.ptr, memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *FailFirst = @ptrCast(@alignCast(ctx));
        return self.inner.vtable.remap(self.inner.ptr, memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *FailFirst = @ptrCast(@alignCast(ctx));
        self.inner.vtable.free(self.inner.ptr, memory, alignment, ret_addr);
    }

    fn allocator(self: *FailFirst) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
};

fn testAuthority(seed: u8) !struct { std.crypto.sign.Ed25519.KeyPair, durable_oper_authority.Config } {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
    const public_key = kp.public_key.toBytes();
    return .{ kp, .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    } };
}

fn openStore(tmp: std.testing.TmpDir, name: []const u8) !store_mod.OroStore {
    return store_mod.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, name, accepted_storage);
}

fn signGrant(
    kp: std.crypto.sign.Ed25519.KeyPair,
    auth: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
    expiry_ms: u64,
    out: []u8,
) ![]const u8 {
    const len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = account,
        .revision = revision,
        .privilege_bits = @as(u64, 1) << 3,
        .class = "moderator",
        .title = "Desk",
        .authority_node_id = auth.authority_node_id,
        .authority_pubkey = auth.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    }, issued_ms, out);
    return out[0..len];
}

fn signTombstone(
    kp: std.crypto.sign.Ed25519.KeyPair,
    auth: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
    out: []u8,
) ![]const u8 {
    const len = try oper_cred_share.signOcg2(kp, .{
        .kind = .tombstone,
        .account = account,
        .revision = revision,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = auth.authority_node_id,
        .authority_pubkey = auth.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = 0,
    }, issued_ms, out);
    return out[0..len];
}

fn auditHas(audit: *audit_trail.AuditTrail, text: []const u8) bool {
    var i: usize = 0;
    while (i < audit.count) : (i += 1) {
        const record = audit.records[(audit.start + i) % audit_trail.AuditTrail.cap] orelse continue;
        if (std.mem.eql(u8, record.event, text)) return true;
    }
    return false;
}

fn activate(store: *store_mod.OroStore, state: *durable_oper_authority.State) !services_mod.Services {
    var services = services_mod.Services.init(store, null);
    try services.activateDurableOperAuthority(state);
    return services;
}

test "DST GAP-A1 project durable authority onto live sessions across restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA1);
    const raw_ms: u64 = 1_000;
    const window_ms = services_mod.Services.durable_oper_security_horizon_window_ms;
    const ttl_ms = oper_cred_share.ocg2_max_ttl_ms;
    const threshold_ms = services_mod.Services.durable_oper_security_horizon_renewal_threshold_ms;
    // Reopen fast-forwards to the reserved horizon. Issue the grant on the last
    // millisecond that does not renew that horizon, with a full TTL, so the
    // restarted security time is still inside this same grant.
    const live_elapsed_ms = window_ms - threshold_ms - 1;
    const live_now_ms = raw_ms + live_elapsed_ms;
    const restart_floor_ms = raw_ms + window_ms;
    const grant_expiry_ms = live_now_ms + ttl_ms;
    try std.testing.expect(live_now_ms < restart_floor_ms);
    try std.testing.expect(restart_floor_ms < grant_expiry_ms);

    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const grant = try signGrant(auth[0], auth[1], "alice", 1, live_now_ms, grant_expiry_ms, &wire_buf);
    var grant_copy: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    @memcpy(grant_copy[0..grant.len], grant);
    const grant_wire = grant_copy[0..grant.len];
    var tomb_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tomb = try signTombstone(auth[0], auth[1], "alice", 2, live_now_ms, &tomb_buf);

    const other = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x5A)));
    var foreign_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    try std.testing.expectError(error.WrongAuthority, signGrant(other, auth[1], "alice", 1, live_now_ms, grant_expiry_ms, &foreign_buf));

    {
        var store = try openStore(tmp, "a1-project.wal");
        defer store.deinit();
        var state = try durable_oper_authority_boot.initialize(allocator, &store, auth[1]);
        defer state.deinit();
        var services = try activate(&store, &state);
        const runtime = try projection.Runtime.initDefault(allocator, &services);
        defer runtime.deinit();
        var audit = audit_trail.AuditTrail.init(allocator);
        defer audit.deinit();
        switch (try projectOnce(allocator, runtime, &.{}, &audit, raw_ms, 0)) {
            .committed, .unchanged => {},
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(services_mod.Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(grant_wire, live_now_ms));

        var session = Session.init();
        session.loginAs("alice");
        const slots = [_]SessionRef{.{ .session = &session }};

        var fail = FailFirst{ .inner = allocator };
        var failing_audit = audit_trail.AuditTrail.init(fail.allocator());
        defer failing_audit.deinit();
        try std.testing.expectEqual(Outcome.aborted, try projectOnce(allocator, runtime, &slots, &failing_audit, raw_ms, live_elapsed_ms));
        try std.testing.expect(!session.isOper());
        try std.testing.expectEqual(@as(usize, 0), runtime.summary().baseline_count);
        try std.testing.expect(auditHas(&failing_audit, "rollback"));

        switch (try projectOnce(allocator, runtime, &slots, &audit, raw_ms, live_elapsed_ms)) {
            .committed => |n| try std.testing.expect(n >= 1),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expect(session.isOper());
        try std.testing.expect(session.hasPriv(.client_moderate));
        try std.testing.expectEqualStrings("moderator", session.operClass());
        try std.testing.expect(auditHas(&audit, "grant alice"));
        try std.testing.expect(auditHas(&audit, "ack"));
        try std.testing.expectEqual(@as(usize, 1), runtime.summary().baseline_count);
    }

    var restarted = Session.init();
    restarted.loginAs("alice");
    var restarted_slots = [_]SessionRef{.{ .session = &restarted }};
    var store = try openStore(tmp, "a1-project.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.load(allocator, &store, auth[1]);
    defer state.deinit();
    var services = try activate(&store, &state);
    const runtime = try projection.Runtime.initDefault(allocator, &services);
    defer runtime.deinit();
    var audit = audit_trail.AuditTrail.init(allocator);
    defer audit.deinit();
    switch (try projectOnce(allocator, runtime, &restarted_slots, &audit, raw_ms, 0)) {
        .committed => |n| try std.testing.expect(n >= 1),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(restart_floor_ms, runtime.summary().last_security_now_ms orelse return error.TestUnexpectedResult);
    try std.testing.expect(restarted.isOper());
    try std.testing.expect(auditHas(&audit, "grant alice"));

    try std.testing.expectEqual(services_mod.Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tomb, live_now_ms));
    var fail_revoke = FailFirst{ .inner = allocator };
    var failing_revoke = audit_trail.AuditTrail.init(fail_revoke.allocator());
    defer failing_revoke.deinit();
    try std.testing.expectEqual(Outcome.aborted, try projectOnce(allocator, runtime, &restarted_slots, &failing_revoke, raw_ms, 0));
    try std.testing.expect(restarted.isOper());
    try std.testing.expectEqual(@as(usize, 1), runtime.summary().baseline_count);
    try std.testing.expect(auditHas(&failing_revoke, "rollback"));

    var peer_store = try openStore(tmp, "a1-peer.wal");
    defer peer_store.deinit();
    var peer_state = try durable_oper_authority_boot.initialize(allocator, &peer_store, auth[1]);
    defer peer_state.deinit();
    var peer_services = try activate(&peer_store, &peer_state);
    const peer_runtime = try projection.Runtime.initDefault(allocator, &peer_services);
    defer peer_runtime.deinit();
    var peer_session = Session.init();
    peer_session.loginAs("alice");
    const peer_slots = [_]SessionRef{.{ .session = &peer_session }};
    var peer_audit = audit_trail.AuditTrail.init(allocator);
    defer peer_audit.deinit();
    switch (try projectOnce(allocator, peer_runtime, &.{}, &peer_audit, raw_ms, 0)) {
        .committed, .unchanged => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(services_mod.Services.DurableOperMergeOutcome.committed, peer_services.commitDurableOperRecord(grant_wire, live_now_ms));
    switch (try projectOnce(allocator, peer_runtime, &peer_slots, &peer_audit, raw_ms, live_elapsed_ms)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(peer_session.isOper());

    const peers = [_]Peer{
        .{ .services = &services, .runtime = runtime, .sessions = &restarted_slots, .audit = &audit },
        .{ .services = &peer_services, .runtime = peer_runtime, .sessions = &peer_slots, .audit = &peer_audit },
    };
    try commitMeshWide(allocator, tomb, live_now_ms, live_elapsed_ms, &peers);
    try std.testing.expect(!restarted.isOper());
    try std.testing.expect(!peer_session.isOper());
    try std.testing.expect(auditHas(&audit, "revoke alice"));
    try std.testing.expect(auditHas(&peer_audit, "revoke alice"));
    std.debug.print("GAP-A1 branch=project across restart with rollback audit and mesh revoke\n", .{});
}
