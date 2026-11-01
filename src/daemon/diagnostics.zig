// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed connection diagnostics, bounded history and sink budgeting.
//! No transport/session ownership and no retained user text or credentials.
const std = @import("std");
const sessions = @import("sessions.zig");

pub const Event = enum {
    accepted,
    adopted,
    registered,
    closed,
    refused,
    recv_eof,
    recv_error,
    send_error,
    recv_buffer_missing,
    recv_buffer_bounds,
    recv_buffer_replenish,
    ktls_rx_close,
    tls_established,
    tls_kernel_handshake_conflict,
    tls_output_error,
    tls_error,
    command_quit,
    parser_error,
    recvq_limit,
    nick_auth_required,
    nick_denial_output,
    websocket_peer_close,
    websocket_close,
    ktls_tx_attach_failed,
    ktls_rx_attach_failed,
};

/// Only server-defined categories enter logs. QUIT reasons and other arbitrary
/// wire text can contain secrets, so unknown reasons are deliberately omitted.
pub const Reason = enum {
    none,
    generic_client_quit,
    ping_timeout,
    registration_timeout,
    tls_peer_alert,
    tls_record_failure,
    registered_nick,
    flood,
    line_too_long,
    server_draining,
    send_no_progress,
    send_completion,
    input_allocation_failure,
    other_redacted,
};

pub fn reasonFromText(reason: []const u8) Reason {
    const known = .{
        .{ "Client quit", Reason.generic_client_quit },
        .{ "Ping timeout", Reason.ping_timeout },
        .{ "Registration timeout", Reason.registration_timeout },
        .{ "TLS peer alert", Reason.tls_peer_alert },
        .{ "TLS record failure", Reason.tls_record_failure },
        .{ "Registered nickname requires authentication", Reason.registered_nick },
        .{ "Excess Flood", Reason.flood },
        .{ "Line too long", Reason.line_too_long },
        .{ "Server draining", Reason.server_draining },
        .{ "SEND made no progress", Reason.send_no_progress },
        .{ "Invalid SEND completion", Reason.send_completion },
        .{ "Invalid TLS prefix completion", Reason.send_completion },
        .{ "Input allocation failure", Reason.input_allocation_failure },
    };
    inline for (known) |entry| {
        if (std.mem.eql(u8, reason, entry[0])) return entry[1];
    }
    return if (reason.len == 0) .none else .other_redacted;
}

/// Process-local diagnostics never enter a session/checkpoint. Bound logging
/// during connection churn or repeated preregistration failures, and report
/// dropped lines on the next admitted event. No allocation or blocking lock.
pub const Budget = struct {
    window: std.atomic.Value(u64) = .init(0),
    suppressed: std.atomic.Value(u64) = .init(0),
    pub const per_second = 128;

    pub fn take(self: *Budget, now_ms: u64) ?u64 {
        const second = (now_ms / 1000) & 0x0000ffffffffffff;
        var old = self.window.load(.monotonic);
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            // A delayed thread must never reopen a spent earlier window and
            // then let another caller reset the current window's budget again.
            const effective_second = @max(second, old >> 16);
            const count = if (old >> 16 == effective_second) old & 0xffff else 0;
            if (count >= per_second) break;
            const next = (effective_second << 16) | (count + 1);
            if (self.window.cmpxchgWeak(old, next, .monotonic, .monotonic)) |observed| {
                old = observed;
            } else return self.suppressed.swap(0, .monotonic);
        }
        _ = self.suppressed.fetchAdd(1, .monotonic);
        return null;
    }
};

pub const PhysicalId = struct {
    shard: u16,
    slot: u32,
    generation: u32,
};

pub const Transport = enum { tcp, tls, ws, wss };

/// Copy-only metadata. Never add caller-owned slices or opaque payload pointers.
pub const Connection = struct {
    id: PhysicalId,
    fd: i64,
    transport: Transport,
    registered: bool,
    ktls_rx: bool,
    ktls_tx: bool,
    queued: u64,
    result: i32 = 0,
    failure: ?anyerror = null,
    reason: Reason = .none,
};

pub const Record = struct {
    sequence: u64,
    wall_ms: u64,
    monotonic_ms: u64,
    event: Event,
    connection: Connection,
};

pub const event_count = @typeInfo(Event).@"enum".field_names.len;
pub const history_capacity = 128;

/// Instance-owned, allocation-free state. All reactors may record concurrently.
/// Counters always advance; history recording drops on contention, never waits.
/// Sink suppression does not suppress counters or history. Snapshots are an
/// observation, not a transactionally consistent view of the atomic counters.
pub const Diagnostics = struct {
    counts: [event_count]std.atomic.Value(u64) = @splat(.init(0)),
    sink_suppressed: std.atomic.Value(u64) = .init(0),
    history_dropped: std.atomic.Value(u64) = .init(0),
    sequence: std.atomic.Value(u64) = .init(0),
    budget: Budget = .{},
    history_lock: std.atomic.Mutex = .unlocked,
    history: [history_capacity]Record = undefined,
    next: usize = 0,
    used: usize = 0,

    /// Returns suppressed-since-last-line if the external sink may log this
    /// event. The caller formats with its short-lived nick/peer view and dlog.
    pub fn record(self: *Diagnostics, wall_ms: u64, monotonic_ms: u64, event: Event, connection: Connection) ?u64 {
        _ = self.counts[@backingInt(event)].fetchAdd(1, .monotonic);
        const sequence = self.sequence.fetchAdd(1, .monotonic);
        if (self.history_lock.tryLock()) {
            self.history[self.next] = .{
                .sequence = sequence,
                .wall_ms = wall_ms,
                .monotonic_ms = monotonic_ms,
                .event = event,
                .connection = connection,
            };
            self.next = (self.next + 1) % history_capacity;
            self.used = @min(self.used + 1, history_capacity);
            self.history_lock.unlock();
        } else {
            _ = self.history_dropped.fetchAdd(1, .monotonic);
        }
        const admitted = self.budget.take(monotonic_ms);
        if (admitted == null) _ = self.sink_suppressed.fetchAdd(1, .monotonic);
        return admitted;
    }

    pub fn count(self: *const Diagnostics, event: Event) u64 {
        return self.counts[@backingInt(event)].load(.monotonic);
    }

    /// Fixed-cardinality metrics; connection identities are never labels.
    pub fn renderMetrics(self: *const Diagnostics, out: []u8) error{NoSpaceLeft}![]const u8 {
        var n: usize = 0;
        inline for (@typeInfo(Event).@"enum".field_names) |name| {
            const event: Event = @field(Event, name);
            n += (try std.fmt.bufPrint(out[n..], "onyx_connection_diagnostics_total{{event=\"{s}\"}} {d}\n", .{ name, self.count(event) })).len;
        }
        n += (try std.fmt.bufPrint(out[n..], "onyx_connection_diagnostics_sink_suppressed_total {d}\nonyx_connection_diagnostics_history_dropped_total {d}\n", .{
            self.sink_suppressed.load(.monotonic), self.history_dropped.load(.monotonic),
        })).len;
        return out[0..n];
    }

    /// `renderMetrics` plus attach-scope token-publication counters and the
    /// media FIR/PLI per-SSRC drop counter. Callers supply
    /// `SessionStore.tokenPublicationStatsSnapshot()` (attach-scope:
    /// `rotations_required`, `duplicate_publications_suppressed`) and the
    /// `MediaPlane.fir_pli_ssrc_budget.dropped` field value; taking plain
    /// values keeps this module free of a media-plane import. Fixed names
    /// only: no labels, account/token/SSRC values, or other user data.
    pub fn renderMetricsWithCounters(self: *const Diagnostics, out: []u8, token_publication: sessions.TokenPublicationStats, media_fir_pli_ssrc_dropped: u64) error{NoSpaceLeft}![]const u8 {
        var n = (try self.renderMetrics(out)).len;
        n += (try std.fmt.bufPrint(out[n..], "onyx_session_token_publication_rotations_required_total {d}\nonyx_session_token_publication_duplicate_publications_suppressed_total {d}\nonyx_media_fir_pli_ssrc_budget_dropped_total {d}\n", .{
            token_publication.rotations_required, token_publication.duplicate_publications_suppressed, media_fir_pli_ssrc_dropped,
        })).len;
        return out[0..n];
    }

    /// Newest `out.len` retained records, oldest-to-newest insertion order.
    /// Returns Busy instead of blocking a live producer. Record sequence is a
    /// correlation ID; concurrent producers may acquire the lock out of order.
    pub fn snapshot(self: *Diagnostics, out: []Record) error{Busy}![]Record {
        if (!self.history_lock.tryLock()) return error.Busy;
        defer self.history_lock.unlock();
        const n = @min(out.len, self.used);
        const start = (self.next + history_capacity - n) % history_capacity;
        for (out[0..n], 0..) |*item, index| item.* = self.history[(start + index) % history_capacity];
        return out[0..n];
    }
};

/// Oper-visible history has physical IDs but no nicknames, IPs or wire text.
pub fn formatRecord(out: []u8, record: Record) error{NoSpaceLeft}![]const u8 {
    const c = record.connection;
    return std.fmt.bufPrint(out, "seq={d} ts_ms={d} mono_ms={d} event={s} shard={d} slot={d} generation={d} fd={d} transport={s} queued={d} result={d} error={s} reason={s}", .{
        record.sequence,       record.wall_ms, record.monotonic_ms, @tagName(record.event),
        c.id.shard,            c.id.slot,      c.id.generation,     c.fd,
        @tagName(c.transport), c.queued,       c.result,            if (c.failure) |err| @errorName(err) else "none",
        @tagName(c.reason),
    });
}

pub fn escapeNick(nick: []const u8, out: *[256]u8) []const u8 {
    return escapeBounded(nick, 64, out);
}

fn escapeBounded(input: []const u8, comptime max_bytes: usize, out: *[max_bytes * 4]u8) []const u8 {
    const hex = "0123456789abcdef";
    var n: usize = 0;
    for (input[0..@min(input.len, max_bytes)]) |byte| {
        if (byte >= 0x21 and byte <= 0x7e and byte != '"' and byte != '\\') {
            out[n] = byte;
            n += 1;
        } else {
            out[n..][0..4].* = .{ '\\', 'x', hex[byte >> 4], hex[byte & 15] };
            n += 4;
        }
    }
    return out[0..n];
}

/// Immediate sink rendering only: caller retains ownership of nick/peer.
/// History cannot retain either string because Record has no slice fields.
pub fn formatConnection(out: []u8, wall_ms: u64, connection: Connection, event: Event, peer: []const u8, nick: []const u8, suppressed: u64) error{NoSpaceLeft}![]const u8 {
    var nick_buf: [256]u8 = undefined;
    var peer_buf: [256]u8 = undefined;
    return std.fmt.bufPrint(out, "onyx-server: connection ts_ms={d} event={s} shard={d} slot={d} generation={d} fd={d} peer={s} transport={s} nick=\"{s}\" registered={} ktls_rx={} ktls_tx={} queued={d} result={d} errno={d} error={s} reason={s} suppressed={d}\n", .{
        wall_ms,                     @tagName(event),       connection.id.shard,                                            connection.id.slot,
        connection.id.generation,    connection.fd,         escapeBounded(peer, 64, &peer_buf),                             @tagName(connection.transport),
        escapeNick(nick, &nick_buf), connection.registered, connection.ktls_rx,                                             connection.ktls_tx,
        connection.queued,           connection.result,     if (connection.result < 0) -@as(i64, connection.result) else 0, if (connection.failure) |err| @errorName(err) else "none",
        @tagName(connection.reason), suppressed,
    });
}

fn fixtureConnection() Connection {
    return .{
        .id = .{ .shard = 3, .slot = 7, .generation = 11 },
        .fd = 17,
        .transport = .tls,
        .registered = true,
        .ktls_rx = false,
        .ktls_tx = true,
        .queued = 5,
    };
}

test "diagnostics preserve counters and recent metadata when sink is suppressed" {
    var state: Diagnostics = .{};
    for (0..300) |i| {
        const admitted = state.record(@intCast(i), 1000, .recv_error, fixtureConnection());
        try std.testing.expectEqual(i < Budget.per_second, admitted != null);
    }
    try std.testing.expectEqual(@as(u64, 300), state.count(.recv_error));
    try std.testing.expectEqual(@as(u64, 172), state.sink_suppressed.load(.monotonic));
    var records: [history_capacity]Record = undefined;
    const recent = try state.snapshot(&records);
    try std.testing.expectEqual(history_capacity, recent.len);
    try std.testing.expectEqual(@as(u64, 172), recent[0].sequence);
    try std.testing.expectEqual(@as(u64, 299), recent[127].sequence);
    try std.testing.expectEqual(@as(?u64, 172), state.record(300, 2000, .closed, fixtureConnection()));
    var other: Diagnostics = .{};
    try std.testing.expectEqual(@as(u64, 0), other.count(.recv_error));
    try std.testing.expectEqual(@as(usize, 0), (try other.snapshot(&records)).len);
}

test "diagnostics contention never blocks and stale time cannot reopen budget" {
    var state: Diagnostics = .{};
    try std.testing.expect(state.history_lock.tryLock());
    _ = state.record(10, 1000, .accepted, fixtureConnection());
    var records: [2]Record = undefined;
    try std.testing.expectError(error.Busy, state.snapshot(&records));
    state.history_lock.unlock();
    try std.testing.expectEqual(@as(u64, 1), state.history_dropped.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), state.count(.accepted));
    for (1..Budget.per_second) |_| _ = state.record(10, 1000, .accepted, fixtureConnection());
    try std.testing.expect(state.record(10, 999, .accepted, fixtureConnection()) == null);
    try std.testing.expect(state.record(10, 1000, .accepted, fixtureConnection()) == null);
    try std.testing.expectEqual(@as(?u64, 2), state.record(10, 2000, .accepted, fixtureConnection()));
}

test "diagnostics formatting has bounded identifiers and no retained caller strings" {
    var connection = fixtureConnection();
    connection.result = std.math.minInt(i32);
    connection.reason = reasonFromText("QUIT secret wire payload");
    connection.failure = error.ConnectionReset;
    var out: [1280]u8 = undefined;
    const line = try formatConnection(&out, 123, connection, .recv_error, "127.0.0.1\r\n", "Ari\"\\adne", 9);
    try std.testing.expect(std.mem.indexOf(u8, line, "shard=3 slot=7 generation=11") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Ari\\x22\\x5cadne") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "peer=127.0.0.1\\x0d\\x0a") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "errno=2147483648") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secret") == null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
    try std.testing.expectEqual(Reason.other_redacted, connection.reason);
    try std.testing.expectError(error.NoSpaceLeft, formatConnection(out[0..1], 0, connection, .closed, "", "", 0));
    const longest = try formatConnection(&out, std.math.maxInt(u64), connection, .closed, &@as([64]u8, @splat('"')), &@as([64]u8, @splat('"')), std.math.maxInt(u64));
    try std.testing.expect(longest.len < out.len);
}

test "diagnostics metrics have bounded labels and independent instances" {
    var state: Diagnostics = .{};
    _ = state.record(1, 1, .registered, fixtureConnection());
    var out: [4096]u8 = undefined;
    const metrics = try state.renderMetrics(&out);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "onyx_connection_diagnostics_total{event=\"registered\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "slot=") == null);
    try std.testing.expectError(error.NoSpaceLeft, state.renderMetrics(out[0..4]));
    var records: [1]Record = undefined;
    const snapshot = try state.snapshot(&records);
    const line = try formatRecord(&out, snapshot[0]);
    try std.testing.expect(std.mem.indexOf(u8, line, "shard=3 slot=7 generation=11") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "nick=") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "peer=") == null);
}

test "diagnostics metrics render token publication and media FIR PLI counters" {
    const media_plane = @import("media_plane.zig");
    var store = sessions.SessionStore.init(std.testing.allocator);
    defer store.deinit();
    const token_a: sessions.Token = @splat(1);
    const token_b: sessions.Token = @splat(2);
    _ = try store.attach("canary-account", 1, token_a, 10);
    try std.testing.expect(store.markPortableResumeIssued("canary-account", 1));
    store.resetTokenPublicationStats();
    try std.testing.expect(store.markTokenReplicaDirty(token_a));
    try std.testing.expect(store.markTokenReplicaDirty(token_a));
    _ = try store.attach("canary-account", 1, token_b, 20);

    var plane = try media_plane.MediaPlane.initFallible(std.testing.allocator);
    defer plane.deinit();
    for (0..media_plane.MediaPlane.FirPliSsrcBudget.limit) |_| try std.testing.expect(plane.fir_pli_ssrc_budget.allow(4242, 1000));
    for (0..3) |_| try std.testing.expect(!plane.fir_pli_ssrc_budget.allow(4242, 1000));
    try std.testing.expectEqual(@as(u64, 3), plane.fir_pli_ssrc_budget.dropped);

    var state: Diagnostics = .{};
    var out: [4096]u8 = undefined;
    const metrics = try state.renderMetricsWithCounters(&out, store.tokenPublicationStatsSnapshot(), plane.fir_pli_ssrc_budget.dropped);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "onyx_session_token_publication_rotations_required_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "onyx_session_token_publication_duplicate_publications_suppressed_total 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "onyx_media_fir_pli_ssrc_budget_dropped_total 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "canary") == null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "account=") == null);
    try std.testing.expectError(error.NoSpaceLeft, state.renderMetricsWithCounters(out[0..4], store.tokenPublicationStatsSnapshot(), plane.fir_pli_ssrc_budget.dropped));
}

test "diagnostics concurrent producers retain exact totals without blocking" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    var state: Diagnostics = .{};
    const Producer = struct {
        fn run(d: *Diagnostics, shard: u16) void {
            var connection = fixtureConnection();
            connection.id.shard = shard;
            for (0..1000) |i| _ = d.record(@intCast(i), 1000, .accepted, connection);
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&threads, 0..) |*thread, shard| {
        thread.* = try std.Thread.spawn(.{}, Producer.run, .{ &state, @as(u16, @intCast(shard)) });
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try std.testing.expectEqual(@as(u64, 4000), state.count(.accepted));
    var records: [history_capacity]Record = undefined;
    for (try state.snapshot(&records)) |record| {
        try std.testing.expect(record.connection.id.shard < 4);
        try std.testing.expect(record.sequence < 4000);
    }
}
