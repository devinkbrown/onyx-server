// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free runtime counters for the daemon hot path.
//!
//! The hot path (accept/recv/send/line dispatch) must never allocate or take a
//! lock to record a metric, so counters are atomic values bumped inline.
//! Rendering — Prometheus exposition text or an oper STATS dump — is a
//! cold path that snapshots the counters into a caller-provided buffer.
//!
//! These complement the structured `qlog`/`trace` flight recorder (which keeps
//! the last N *events*); this keeps monotonic *totals* and a couple of gauges.
const std = @import("std");
const HdrHistogram = @import("../substrate/hdr_histogram.zig").HdrHistogram;

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}

/// Four fixed, unlabeled latency series. Each reactor owns one recording slot.
pub const LatencyStats = struct {
    pub const Series = enum(u2) {
        tls_handshake,
        privmsg_fanout,
        mooring_rtt,
        media_relay,
    };

    const series_count = 4;
    const bounds = [_]u64{ 100, 500, 1000, 5000, 10000, 50000, 100000 };
    const names = [_][]const u8{
        "onyx_tls_handshake_us",
        "onyx_privmsg_fanout_us",
        "onyx_mooring_rtt_us",
        "onyx_media_relay_us",
    };
    const config = @import("../substrate/hdr_histogram.zig").Config{
        .significant_figures = 2,
        .max_trackable_value = 60_000_000,
    };

    const Slot = struct {
        mutex: std.atomic.Mutex = .unlocked,
        histograms: [series_count]HdrHistogram,
        exact_sums: [series_count]u128 = .{ 0, 0, 0, 0 },
        boundary_corrections: [series_count][bounds.len]u64 = std.mem.zeroes([series_count][bounds.len]u64),
    };

    allocator: std.mem.Allocator,
    published: Slot,
    reactors: []Slot,

    pub fn init(allocator: std.mem.Allocator, reactor_count: usize) !LatencyStats {
        var published: Slot = undefined;
        var ready: usize = 0;
        errdefer for (published.histograms[0..ready]) |*hist| hist.deinit();
        for (&published.histograms) |*hist| {
            hist.* = try HdrHistogram.init(allocator, config);
            ready += 1;
        }
        published.exact_sums = .{ 0, 0, 0, 0 };
        published.boundary_corrections = std.mem.zeroes(@TypeOf(published.boundary_corrections));
        published.mutex = .unlocked;

        const reactors = try allocator.alloc(Slot, reactor_count);
        errdefer allocator.free(reactors);
        var initialized: usize = 0;
        errdefer {
            for (reactors[0..initialized]) |*slot| {
                for (&slot.histograms) |*hist| hist.deinit();
            }
        }
        for (reactors) |*slot| {
            var slot_ready: usize = 0;
            errdefer for (slot.histograms[0..slot_ready]) |*hist| hist.deinit();
            for (&slot.histograms) |*hist| {
                hist.* = try HdrHistogram.init(allocator, config);
                slot_ready += 1;
            }
            slot.exact_sums = .{ 0, 0, 0, 0 };
            slot.boundary_corrections = std.mem.zeroes(@TypeOf(slot.boundary_corrections));
            slot.mutex = .unlocked;
            initialized += 1;
        }
        return .{ .allocator = allocator, .published = published, .reactors = reactors };
    }

    pub fn deinit(self: *LatencyStats) void {
        for (&self.published.histograms) |*hist| hist.deinit();
        for (self.reactors) |*slot| {
            for (&slot.histograms) |*hist| hist.deinit();
        }
        self.allocator.free(self.reactors);
    }

    /// Recording is allocation-free. The caller must use its owning reactor index.
    pub fn record(self: *LatencyStats, series: Series, reactor_index: usize, value_us: u64) void {
        const idx = @backingInt(series);
        const slot = &self.reactors[reactor_index];
        lockSpin(&slot.mutex);
        defer slot.mutex.unlock();
        slot.histograms[idx].recordValue(value_us);
        slot.exact_sums[idx] += value_us;
        // HDR buckets can straddle a fixed Prometheus `le` boundary. Retain
        // the count on the included side so cumulative buckets stay exact.
        const sample = @max(@as(u64, 1), value_us);
        const magnitude = slot.histograms[idx].sub_bucket_half_count_magnitude;
        const bits_needed: u32 = 64 - @clz(sample);
        const bucket: u32 = if (bits_needed <= magnitude + 1) 0 else bits_needed - magnitude - 1;
        const width = @as(u64, 1) << @as(u6, @intCast(bucket));
        const lower = (sample / width) * width;
        for (bounds, 0..) |bound, bound_idx| {
            if (sample <= bound and lower + width - 1 > bound) {
                slot.boundary_corrections[idx][bound_idx] += 1;
            }
        }
    }

    /// Only reactor 0 may call this. Slot locks protect concurrent recorders.
    pub fn mergeShards(self: *LatencyStats) void {
        lockSpin(&self.published.mutex);
        defer self.published.mutex.unlock();
        for (self.reactors) |*slot| {
            {
                lockSpin(&slot.mutex);
                defer slot.mutex.unlock();
                for (0..series_count) |idx| {
                    self.published.histograms[idx].merge(slot.histograms[idx]) catch unreachable;
                    slot.histograms[idx].reset();
                    self.published.exact_sums[idx] += slot.exact_sums[idx];
                    slot.exact_sums[idx] = 0;
                    for (0..bounds.len) |bound_idx| {
                        self.published.boundary_corrections[idx][bound_idx] += slot.boundary_corrections[idx][bound_idx];
                        slot.boundary_corrections[idx][bound_idx] = 0;
                    }
                }
            }
        }
    }

    pub fn writePrometheus(self: *const LatencyStats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        const published = @constCast(&self.published);
        lockSpin(&published.mutex);
        defer published.mutex.unlock();
        for (names, 0..) |name, idx| {
            const hist = self.published.histograms[idx];
            try out.print(allocator, "# HELP {s} Observed latency in microseconds\n", .{name});
            try out.print(allocator, "# TYPE {s} histogram\n", .{name});
            for (bounds, 0..) |bound, bound_idx| {
                try out.print(allocator, "{s}_bucket{{le=\"{d}\"}} {d}\n", .{ name, bound, cumulativeCount(hist, bound) + self.published.boundary_corrections[idx][bound_idx] });
            }
            try out.print(allocator, "{s}_bucket{{le=\"+Inf\"}} {d}\n", .{ name, hist.totalCount() });
            try out.print(allocator, "{s}_count {d}\n", .{ name, hist.totalCount() });
            try out.print(allocator, "{s}_sum {d}\n", .{ name, self.published.exact_sums[idx] });
        }
    }

    /// Count buckets wholly below the boundary; exact straddling counts are
    /// added from the bounded correction counters recorded with each sample.
    fn cumulativeCount(hist: HdrHistogram, bound: u64) u64 {
        var count: u64 = 0;
        for (hist.counts, 0..) |n, index| {
            if (n == 0) continue;
            var lower: u64 = undefined;
            var width: u64 = undefined;
            if (index < hist.sub_bucket_count) {
                lower = @intCast(index);
                width = 1;
            } else {
                const relative = index - hist.sub_bucket_count;
                const bucket = relative / hist.sub_bucket_half_count + 1;
                const offset = relative % hist.sub_bucket_half_count;
                width = @as(u64, 1) << @as(u6, @intCast(bucket));
                lower = (@as(u64, hist.sub_bucket_half_count) + offset) * width;
            }
            if (lower + width - 1 <= bound) count += n;
        }
        return count;
    }
};

/// Monotonic counters (only ever increase) plus two gauges (active connections,
/// established S2S links) which move both ways. The server embeds one.
pub const Stats = struct {
    const AtomicU64 = std.atomic.Value(u64);
    const AtomicI64 = std.atomic.Value(i64);

    /// Unlabeled process-image totals. Helix starts a new image with zero totals;
    /// these are diagnostics, never checkpointed authority or retry state.
    pub const SessionPublication = enum { tracking_token_created, offer_mutation, offer_renewal, offer_retry_new, offer_retry_reused, lease_accepted, retry_attempt, retry_completed, fanout_queued, replay_queued };
    // --- counters (monotonic) ---
    connections_total: AtomicU64 = .init(0),
    s2s_accepts_total: AtomicU64 = .init(0),
    messages_in_total: AtomicU64 = .init(0),
    bytes_in_total: AtomicU64 = .init(0),
    bytes_out_total: AtomicU64 = .init(0),
    errors_total: AtomicU64 = .init(0),
    quits_total: AtomicU64 = .init(0),

    session_publications: [@typeInfo(SessionPublication).@"enum".field_names.len]AtomicU64 =
        @splat(.init(0)),

    // --- gauges (up/down) ---
    connections_active: AtomicI64 = .init(0),
    /// Mooring-/S2S-**established** peer links (AKE complete). Not TCP accepts.
    s2s_links_active: AtomicI64 = .init(0),
    /// TCP-level S2S peer slots currently open (inbound accept or outbound dial).
    /// Useful for "dial stuck before AKE" diagnosis; not the mesh-health signal.
    s2s_tcp_active: AtomicI64 = .init(0),
    /// Configured Mooring peers whose circuit breaker is open. The daemon
    /// stores the count; this gauge only publishes it.
    mooring_breakers_open: AtomicI64 = .init(0),

    pub fn onSessionPublication(self: *Stats, event: SessionPublication) void {
        _ = self.session_publications[@backingInt(event)].fetchAdd(1, .monotonic);
    }

    pub fn sessionPublicationCount(self: *const Stats, event: SessionPublication) u64 {
        return self.session_publications[@backingInt(event)].load(.acquire);
    }

    pub fn onAccept(self: *Stats) void {
        _ = self.connections_total.fetchAdd(1, .monotonic);
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    /// TCP S2S peer accepted or outbound dial slot opened. Does **not** mean
    /// Mooring is up — use `onS2sEstablished` for that.
    pub fn onS2sAccept(self: *Stats) void {
        _ = self.s2s_accepts_total.fetchAdd(1, .monotonic);
        _ = self.s2s_tcp_active.fetchAdd(1, .monotonic);
    }

    /// Secured (or plaintext CRDT) link finished handshake — mesh-routable peer.
    pub fn onS2sEstablished(self: *Stats) void {
        _ = self.s2s_links_active.fetchAdd(1, .monotonic);
    }

    /// A connection closed. `was_s2s` selects S2S gauges; `s2s_was_established`
    /// drops the Mooring-established gauge only when AKE had completed.
    pub fn onClose(self: *Stats, was_s2s: bool, s2s_was_established: bool) void {
        if (was_s2s) {
            decrementPositive(&self.s2s_tcp_active);
            if (s2s_was_established) decrementPositive(&self.s2s_links_active);
        } else {
            decrementPositive(&self.connections_active);
        }
    }

    /// Backward-compatible close for client-only paths.
    pub fn onCloseClient(self: *Stats) void {
        self.onClose(false, false);
    }

    pub fn onBytesIn(self: *Stats, n: usize) void {
        _ = self.bytes_in_total.fetchAdd(@as(u64, @intCast(n)), .monotonic);
    }

    pub fn onBytesOut(self: *Stats, n: usize) void {
        _ = self.bytes_out_total.fetchAdd(@as(u64, @intCast(n)), .monotonic);
    }

    pub fn onLine(self: *Stats) void {
        _ = self.messages_in_total.fetchAdd(1, .monotonic);
    }

    pub fn onError(self: *Stats) void {
        _ = self.errors_total.fetchAdd(1, .monotonic);
    }

    pub fn onQuit(self: *Stats) void {
        _ = self.quits_total.fetchAdd(1, .monotonic);
    }

    /// One metric's identity for rendering: Prometheus name, HELP text, type, and
    /// the live value. `prom` is the metric name; `irc` is the short token used
    /// in the oper STATS dump.
    const Row = struct {
        prom: []const u8,
        irc: []const u8,
        help: []const u8,
        kind: enum { counter, gauge },
        value: i128,
    };

    fn rows(self: *const Stats) [21]Row {
        return .{
            .{ .prom = "onyx_connections_total", .irc = "conns", .help = "Total client connections accepted", .kind = .counter, .value = self.connections_total.load(.acquire) },
            .{ .prom = "onyx_connections_active", .irc = "conns_active", .help = "Currently open client connections", .kind = .gauge, .value = self.connections_active.load(.acquire) },
            .{ .prom = "onyx_s2s_accepts_total", .irc = "s2s", .help = "Total server-to-server TCP peer slots opened", .kind = .counter, .value = self.s2s_accepts_total.load(.acquire) },
            .{ .prom = "onyx_s2s_tcp_active", .irc = "s2s_tcp", .help = "Currently open S2S TCP peer slots (pre- or post-AKE)", .kind = .gauge, .value = self.s2s_tcp_active.load(.acquire) },
            .{ .prom = "onyx_s2s_links_active", .irc = "s2s_active", .help = "Currently Mooring/CRDT-established S2S links", .kind = .gauge, .value = self.s2s_links_active.load(.acquire) },
            .{ .prom = "onyx_mooring_breakers_open", .irc = "mooring_open", .help = "Configured Mooring peers whose circuit breaker is open", .kind = .gauge, .value = self.mooring_breakers_open.load(.acquire) },
            .{ .prom = "onyx_messages_in_total", .irc = "msgs_in", .help = "Total complete protocol lines received", .kind = .counter, .value = self.messages_in_total.load(.acquire) },
            .{ .prom = "onyx_bytes_in_total", .irc = "bytes_in", .help = "Total bytes received from clients", .kind = .counter, .value = self.bytes_in_total.load(.acquire) },
            .{ .prom = "onyx_bytes_out_total", .irc = "bytes_out", .help = "Total bytes queued to clients", .kind = .counter, .value = self.bytes_out_total.load(.acquire) },
            .{ .prom = "onyx_quits_total", .irc = "quits", .help = "Total client disconnects", .kind = .counter, .value = self.quits_total.load(.acquire) },
            .{ .prom = "onyx_errors_total", .irc = "errors", .help = "Total recoverable hot-path errors", .kind = .counter, .value = self.errors_total.load(.acquire) },
            .{ .prom = "onyx_session_tracking_token_created_total", .irc = "session_tracking_token_created", .help = "Initial session tracking bearer rows accepted; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.tracking_token_created) },
            .{ .prom = "onyx_session_offer_mutation_total", .irc = "session_offer_mutation", .help = "Signed OFFERs accepted for local mutation; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.offer_mutation) },
            .{ .prom = "onyx_session_offer_renewal_total", .irc = "session_offer_renewal", .help = "Signed OFFERs accepted for scheduled renewal; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.offer_renewal) },
            .{ .prom = "onyx_session_offer_retry_new_total", .irc = "session_offer_retry_new", .help = "New signed OFFERs accepted during retry; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.offer_retry_new) },
            .{ .prom = "onyx_session_offer_retry_reused_total", .irc = "session_offer_retry_reused", .help = "Accepted OFFERs reused to finish a lease retry; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.offer_retry_reused) },
            .{ .prom = "onyx_session_lease_accepted_total", .irc = "session_lease_accepted", .help = "Signed attachment leases accepted; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.lease_accepted) },
            .{ .prom = "onyx_session_retry_attempt_total", .irc = "session_retry_attempt", .help = "Dirty token publication retry attempts; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.retry_attempt) },
            .{ .prom = "onyx_session_retry_completed_total", .irc = "session_retry_completed", .help = "Dirty token publication retries completed; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.retry_completed) },
            .{ .prom = "onyx_session_fanout_queued_total", .irc = "session_fanout_queued", .help = "Replica records encoded into live secured fanout; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.fanout_queued) },
            .{ .prom = "onyx_session_replay_queued_total", .irc = "session_replay_queued", .help = "Retained replica records admitted to secured replay queues; resets on exec", .kind = .counter, .value = self.sessionPublicationCount(.replay_queued) },
        };
    }

    fn decrementPositive(counter: *AtomicI64) void {
        var current = counter.load(.monotonic);
        while (current > 0) {
            if (counter.cmpxchgWeak(current, current - 1, .monotonic, .monotonic)) |next| {
                current = next;
            } else {
                return;
            }
        }
    }

    /// Append Prometheus exposition text (HELP/TYPE/sample per metric) to `out`.
    pub fn writePrometheus(self: *const Stats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        for (self.rows()) |row| {
            try out.print(allocator, "# HELP {s} {s}\n", .{ row.prom, row.help });
            try out.print(allocator, "# TYPE {s} {s}\n", .{ row.prom, @tagName(row.kind) });
            try out.print(allocator, "{s} {d}\n", .{ row.prom, row.value });
        }
    }

    /// Emit one compact `token=value` line per metric via `sink` (e.g. an oper
    /// notice callback). Never allocates; formats into a small stack buffer.
    pub fn forEachLine(
        self: *const Stats,
        ctx: anytype,
        comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void,
    ) !void {
        var buf: [96]u8 = undefined;
        for (self.rows()) |row| {
            const line = std.fmt.bufPrint(&buf, "{s} = {d}", .{ row.irc, row.value }) catch continue;
            try emit(ctx, line);
        }
    }
};

/// TLS listener counters. Every label set is a fixed enum, so a hostile peer
/// cannot grow the exposition: unknown suites, groups and error names fold
/// into `other`. All recording is an atomic add; rendering is a cold path.
pub const TlsStats = struct {
    const AtomicU64 = std.atomic.Value(u64);

    /// Why a handshake failed, by the engine error that ended it.
    pub const FailureClass = enum {
        peer_alert,
        protocol_version,
        no_shared_group,
        no_shared_cipher,
        bad_record,
        certificate,
        bad_handshake,
        ech,
        resource,
        other,
    };

    pub const Version = enum { tls13, tls12 };

    pub const Group = enum { x25519mlkem768, x25519, secp256r1, other };

    /// IANA names the engines report through `cipherName()`.
    pub const suite_names = [_][]const u8{
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    };
    const suite_slots = suite_names.len + 1; // + other

    pub const Completed = struct {
        version: Version,
        suite_name: ?[]const u8,
        /// Negotiated (EC)DHE group wire value; null when not applicable
        /// (TLS 1.2 is not split by group).
        group: ?u16 = null,
        resumed: bool = false,
        early_data_offered: bool = false,
        early_data_accepted: bool = false,
    };

    pub const KtlsDirection = enum { tx, rx };

    failures: [@typeInfo(FailureClass).@"enum".field_names.len]AtomicU64 = @splat(.init(0)),
    versions: [@typeInfo(Version).@"enum".field_names.len]AtomicU64 = @splat(.init(0)),
    suites: [suite_slots]AtomicU64 = @splat(.init(0)),
    groups: [@typeInfo(Group).@"enum".field_names.len]AtomicU64 = @splat(.init(0)),
    resumptions: [@typeInfo(Version).@"enum".field_names.len]AtomicU64 = @splat(.init(0)),
    early_data_accepted: AtomicU64 = .init(0),
    early_data_rejected: AtomicU64 = .init(0),
    ktls_offloads: [@typeInfo(KtlsDirection).@"enum".field_names.len]AtomicU64 = @splat(.init(0)),

    pub fn classifyFailure(err: anyerror) FailureClass {
        if (err == error.TlsAlert) return .peer_alert;
        if (err == error.ProtocolVersion or err == error.InappropriateFallback) return .protocol_version;
        if (err == error.UnsupportedGroup) return .no_shared_group;
        if (err == error.UnsupportedCipherSuite) return .no_shared_cipher;
        if (err == error.BadRecord or err == error.RecordAuthenticationFailed or
            err == error.RecordOverflow or err == error.AuthFailed) return .bad_record;
        if (err == error.NoCertificate or err == error.NoCompatibleCertificate or
            err == error.BadCertificate or err == error.CertificateVerifyFailed or
            err == error.LeafKeyMismatch or err == error.NoSigningKey or
            err == error.BadDelegatedCredential) return .certificate;
        if (err == error.BadHandshake or err == error.MissingExtension or
            err == error.FinishedMismatch or err == error.BadState or
            err == error.UnexpectedMessage or err == error.DecodeError or
            err == error.Truncated) return .bad_handshake;
        if (err == error.EchHrrUnsupported or err == error.BadEchConfig) return .ech;
        if (err == error.OutOfMemory) return .resource;
        return .other;
    }

    pub fn onHandshakeFailure(self: *TlsStats, err: anyerror) void {
        _ = self.failures[@backingInt(classifyFailure(err))].fetchAdd(1, .monotonic);
    }

    pub fn failureCount(self: *const TlsStats, class: FailureClass) u64 {
        return self.failures[@backingInt(class)].load(.acquire);
    }

    fn suiteSlot(name: ?[]const u8) usize {
        const n = name orelse return suite_names.len;
        for (suite_names, 0..) |known, index| {
            if (std.mem.eql(u8, known, n)) return index;
        }
        return suite_names.len;
    }

    fn groupOf(wire: u16) Group {
        return switch (wire) {
            0x11ec => .x25519mlkem768,
            0x001d => .x25519,
            0x0017 => .secp256r1,
            else => .other,
        };
    }

    pub fn onHandshakeComplete(self: *TlsStats, done: Completed) void {
        _ = self.versions[@backingInt(done.version)].fetchAdd(1, .monotonic);
        _ = self.suites[suiteSlot(done.suite_name)].fetchAdd(1, .monotonic);
        if (done.group) |wire| _ = self.groups[@backingInt(groupOf(wire))].fetchAdd(1, .monotonic);
        if (done.resumed) _ = self.resumptions[@backingInt(done.version)].fetchAdd(1, .monotonic);
        if (done.early_data_accepted) {
            _ = self.early_data_accepted.fetchAdd(1, .monotonic);
        } else if (done.early_data_offered) {
            _ = self.early_data_rejected.fetchAdd(1, .monotonic);
        }
    }

    pub fn onKtlsOffload(self: *TlsStats, direction: KtlsDirection) void {
        _ = self.ktls_offloads[@backingInt(direction)].fetchAdd(1, .monotonic);
    }

    fn header(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, help: []const u8) !void {
        try out.print(allocator, "# HELP {s} {s}\n# TYPE {s} counter\n", .{ name, help, name });
    }

    /// Append the counters as Prometheus exposition text. Every series is
    /// always present (zero until observed) so dashboards see a stable schema.
    pub fn writePrometheus(self: *const TlsStats, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        try header(allocator, out, "onyx_tls_handshake_failures_total", "TLS handshakes that ended in an error, by error class");
        inline for (@typeInfo(FailureClass).@"enum".field_names, 0..) |name, index| {
            try out.print(allocator, "onyx_tls_handshake_failures_total{{reason=\"{s}\"}} {d}\n", .{ name, self.failures[index].load(.acquire) });
        }
        try header(allocator, out, "onyx_tls_handshakes_total", "Completed TLS handshakes by negotiated protocol version");
        inline for (@typeInfo(Version).@"enum".field_names, 0..) |name, index| {
            try out.print(allocator, "onyx_tls_handshakes_total{{version=\"{s}\"}} {d}\n", .{ name, self.versions[index].load(.acquire) });
        }
        try header(allocator, out, "onyx_tls_handshake_cipher_total", "Completed TLS handshakes by negotiated cipher suite");
        for (0..suite_slots) |index| {
            const name = if (index < suite_names.len) suite_names[index] else "other";
            try out.print(allocator, "onyx_tls_handshake_cipher_total{{suite=\"{s}\"}} {d}\n", .{ name, self.suites[index].load(.acquire) });
        }
        try header(allocator, out, "onyx_tls_handshake_group_total", "Completed TLS 1.3 full handshakes by key exchange group");
        inline for (@typeInfo(Group).@"enum".field_names, 0..) |name, index| {
            try out.print(allocator, "onyx_tls_handshake_group_total{{group=\"{s}\"}} {d}\n", .{ name, self.groups[index].load(.acquire) });
        }
        try header(allocator, out, "onyx_tls_resumptions_total", "TLS handshakes that resumed a session ticket");
        inline for (@typeInfo(Version).@"enum".field_names, 0..) |name, index| {
            try out.print(allocator, "onyx_tls_resumptions_total{{version=\"{s}\"}} {d}\n", .{ name, self.resumptions[index].load(.acquire) });
        }
        try header(allocator, out, "onyx_tls_early_data_total", "TLS 1.3 0-RTT offers by outcome");
        try out.print(allocator, "onyx_tls_early_data_total{{result=\"accepted\"}} {d}\n", .{self.early_data_accepted.load(.acquire)});
        try out.print(allocator, "onyx_tls_early_data_total{{result=\"rejected\"}} {d}\n", .{self.early_data_rejected.load(.acquire)});
        try header(allocator, out, "onyx_tls_ktls_offloads_total", "TLS connections whose record crypto moved into the kernel, by direction");
        inline for (@typeInfo(KtlsDirection).@"enum".field_names, 0..) |name, index| {
            try out.print(allocator, "onyx_tls_ktls_offloads_total{{direction=\"{s}\"}} {d}\n", .{ name, self.ktls_offloads[index].load(.acquire) });
        }
    }
};

/// Write one Prometheus label value with the exposition-format escapes
/// (backslash, double quote, newline). Other bytes pass through.
pub fn writePromLabelValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    for (value) |byte| switch (byte) {
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '"' => try out.appendSlice(allocator, "\\\""),
        '\n' => try out.appendSlice(allocator, "\\n"),
        else => try out.append(allocator, byte),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "counters and gauges move as expected" {
    var s = Stats{};
    s.onAccept();
    s.onAccept();
    s.onBytesIn(100);
    s.onLine();
    s.onClose(false, false);
    try testing.expectEqual(@as(u64, 2), s.connections_total.load(.acquire));
    try testing.expectEqual(@as(i64, 1), s.connections_active.load(.acquire));
    try testing.expectEqual(@as(u64, 100), s.bytes_in_total.load(.acquire));
    try testing.expectEqual(@as(u64, 1), s.messages_in_total.load(.acquire));
}

test "gauges never go negative on extra closes" {
    var s = Stats{};
    s.onClose(false, false);
    s.onClose(true, false);
    s.onClose(true, true);
    try testing.expectEqual(@as(i64, 0), s.connections_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_tcp_active.load(.acquire));
}

test "s2s TCP accept is distinct from Mooring established" {
    var s = Stats{};
    s.onS2sAccept();
    try testing.expectEqual(@as(i64, 1), s.s2s_tcp_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.connections_active.load(.acquire));
    s.onS2sEstablished();
    try testing.expectEqual(@as(i64, 1), s.s2s_links_active.load(.acquire));
    s.onClose(true, true);
    try testing.expectEqual(@as(i64, 0), s.s2s_links_active.load(.acquire));
    try testing.expectEqual(@as(i64, 0), s.s2s_tcp_active.load(.acquire));
}

test "prometheus export carries HELP, TYPE, and samples" {
    const allocator = testing.allocator;
    var s = Stats{};
    s.onAccept();
    s.onBytesIn(42);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try s.writePrometheus(allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "# TYPE onyx_connections_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_bytes_in_total 42") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_connections_active 1") != null);
}

test "forEachLine emits one token line per metric" {
    var s = Stats{};
    s.onAccept();
    const Collector = struct {
        count: usize = 0,
        saw_conns: bool = false,
        fn emit(self: *@This(), line: []const u8) !void {
            self.count += 1;
            if (std.mem.startsWith(u8, line, "conns =")) self.saw_conns = true;
        }
    };
    var c = Collector{};
    try s.forEachLine(&c, Collector.emit);
    try testing.expectEqual(@as(usize, 21), c.count);
    try testing.expect(c.saw_conns);
}

test "GAP-O1 fixed histograms preserve counts sums and peer health" {
    const allocator = testing.allocator;
    var latency = try LatencyStats.init(allocator, 2);
    defer latency.deinit();
    latency.record(.tls_handshake, 0, 100);
    latency.record(.tls_handshake, 0, 100_000);
    latency.record(.privmsg_fanout, 1, 501);
    latency.record(.mooring_rtt, 0, 1_500_000);
    latency.record(.media_relay, 1, 1_001);
    latency.mergeShards();
    latency.mergeShards();

    var stats = Stats{};
    stats.onS2sEstablished();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try stats.writePrometheus(allocator, &out);
    try latency.writePrometheus(allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_s2s_links_active 1\n") != null);
    for ([_][]const u8{
        "onyx_tls_handshake_us_count 2\n",
        "onyx_tls_handshake_us_bucket{le=\"100000\"} 2\n",
        "onyx_tls_handshake_us_sum 100100\n",
        "onyx_privmsg_fanout_us_count 1\n",
        "onyx_mooring_rtt_us_count 1\n",
        "onyx_media_relay_us_count 1\n",
        "onyx_mooring_rtt_us_sum 1500000\n",
        "onyx_privmsg_fanout_us_sum 501\n",
    }) |expected| try testing.expect(std.mem.indexOf(u8, out.items, expected) != null);

    var bucket_lines: usize = 0;
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "_bucket{le=\"") == null) continue;
        bucket_lines += 1;
        var allowed = false;
        inline for ([_][]const u8{ "100", "500", "1000", "5000", "10000", "50000", "100000", "+Inf" }) |label| {
            const suffix = "_bucket{le=\"" ++ label ++ "\"}";
            if (std.mem.indexOf(u8, line, suffix) != null) allowed = true;
        }
        try testing.expect(allowed);
    }
    try testing.expectEqual(@as(usize, 32), bucket_lines);

    var empty = try LatencyStats.init(allocator, 1);
    defer empty.deinit();
    var down = Stats{};
    var empty_out: std.ArrayList(u8) = .empty;
    defer empty_out.deinit(allocator);
    try down.writePrometheus(allocator, &empty_out);
    try empty.writePrometheus(allocator, &empty_out);
    try testing.expect(std.mem.indexOf(u8, empty_out.items, "onyx_s2s_links_active 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, empty_out.items, "onyx_mooring_rtt_us_count 0\n") != null);
}

test "session publication counters expose accepted reasons separately from attempts and reset per image" {
    var stats = Stats{};
    stats.onSessionPublication(.retry_attempt);
    stats.onSessionPublication(.retry_attempt);
    stats.onSessionPublication(.lease_accepted);
    stats.onSessionPublication(.offer_retry_reused);
    stats.onSessionPublication(.retry_completed);
    try testing.expectEqual(@as(u64, 2), stats.sessionPublicationCount(.retry_attempt));
    try testing.expectEqual(@as(u64, 1), stats.sessionPublicationCount(.retry_completed));
    try testing.expectEqual(@as(u64, 0), stats.sessionPublicationCount(.offer_mutation));
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try stats.writePrometheus(testing.allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_session_retry_attempt_total 2") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "onyx_session_lease_accepted_total 1") != null);
    // A successor constructs Stats afresh; these totals never infer authority.
    const successor = Stats{};
    try testing.expectEqual(@as(u64, 0), successor.sessionPublicationCount(.retry_attempt));
}

test "TlsStats classifies handshake errors into a bounded reason set" {
    try testing.expectEqual(TlsStats.FailureClass.peer_alert, TlsStats.classifyFailure(error.TlsAlert));
    try testing.expectEqual(TlsStats.FailureClass.protocol_version, TlsStats.classifyFailure(error.ProtocolVersion));
    try testing.expectEqual(TlsStats.FailureClass.no_shared_group, TlsStats.classifyFailure(error.UnsupportedGroup));
    try testing.expectEqual(TlsStats.FailureClass.no_shared_cipher, TlsStats.classifyFailure(error.UnsupportedCipherSuite));
    try testing.expectEqual(TlsStats.FailureClass.bad_record, TlsStats.classifyFailure(error.RecordAuthenticationFailed));
    try testing.expectEqual(TlsStats.FailureClass.certificate, TlsStats.classifyFailure(error.NoCompatibleCertificate));
    try testing.expectEqual(TlsStats.FailureClass.bad_handshake, TlsStats.classifyFailure(error.FinishedMismatch));
    try testing.expectEqual(TlsStats.FailureClass.ech, TlsStats.classifyFailure(error.EchHrrUnsupported));
    try testing.expectEqual(TlsStats.FailureClass.resource, TlsStats.classifyFailure(error.OutOfMemory));
    try testing.expectEqual(TlsStats.FailureClass.other, TlsStats.classifyFailure(error.SomethingNobodyNamed));
}

test "TlsStats renders version, suite, group, resumption, 0-RTT and kTLS series" {
    const allocator = testing.allocator;
    var s = TlsStats{};
    s.onHandshakeComplete(.{ .version = .tls13, .suite_name = "TLS_AES_128_GCM_SHA256", .group = 0x11ec });
    s.onHandshakeComplete(.{ .version = .tls13, .suite_name = "TLS_AES_256_GCM_SHA384", .resumed = true, .early_data_offered = true, .early_data_accepted = true });
    s.onHandshakeComplete(.{ .version = .tls13, .suite_name = "TLS_AES_256_GCM_SHA384", .resumed = true, .early_data_offered = true });
    s.onHandshakeComplete(.{ .version = .tls12, .suite_name = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" });
    s.onHandshakeComplete(.{ .version = .tls13, .suite_name = "TLS_FUTURE_SUITE", .group = 0x9999 });
    s.onHandshakeFailure(error.UnsupportedGroup);
    s.onHandshakeFailure(error.UnsupportedGroup);
    s.onKtlsOffload(.tx);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try s.writePrometheus(allocator, &out);
    for ([_][]const u8{
        "# TYPE onyx_tls_handshake_failures_total counter\n",
        "onyx_tls_handshake_failures_total{reason=\"no_shared_group\"} 2\n",
        "onyx_tls_handshake_failures_total{reason=\"peer_alert\"} 0\n",
        "onyx_tls_handshakes_total{version=\"tls13\"} 4\n",
        "onyx_tls_handshakes_total{version=\"tls12\"} 1\n",
        "onyx_tls_handshake_cipher_total{suite=\"TLS_AES_256_GCM_SHA384\"} 2\n",
        "onyx_tls_handshake_cipher_total{suite=\"other\"} 1\n",
        "onyx_tls_handshake_group_total{group=\"x25519mlkem768\"} 1\n",
        "onyx_tls_handshake_group_total{group=\"other\"} 1\n",
        "onyx_tls_resumptions_total{version=\"tls13\"} 2\n",
        "onyx_tls_early_data_total{result=\"accepted\"} 1\n",
        "onyx_tls_early_data_total{result=\"rejected\"} 1\n",
        "onyx_tls_ktls_offloads_total{direction=\"tx\"} 1\n",
        "onyx_tls_ktls_offloads_total{direction=\"rx\"} 0\n",
    }) |needle| {
        if (std.mem.indexOf(u8, out.items, needle) == null) {
            std.debug.print("missing: {s}", .{needle});
            return error.TestExpectedEqual;
        }
    }
}

test "writePromLabelValue escapes exposition metacharacters" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writePromLabelValue(allocator, &out, "a\"b\\c\nd");
    try testing.expectEqualStrings("a\\\"b\\\\c\\nd", out.items);
}
