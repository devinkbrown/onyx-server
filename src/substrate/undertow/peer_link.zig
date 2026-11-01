// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure UNDERTOW S2S peer-link state machine.
//!
//! This layer intentionally owns no sockets, queues, or heap storage. Callers
//! (the `s2s_peer` driver) feed complete frame bytes in and provide output
//! buffers for any emitted bytes.
const std = @import("std");
const toml = @import("../../proto/toml.zig");

pub const State = enum {
    idle,
    handshaking,
    established,
    draining,
    closed,
};

pub const FrameKind = enum(u8) {
    delta = 1,
    ack = 2,
    heartbeat = 3,
    close = 4,
};

pub const TickEvent = enum {
    none,
    heartbeat_due,
    draining,
    closed,
};

pub const ReceiveEvent = enum {
    delta,
    ack,
    heartbeat,
    close,
};

pub const Clock = struct {
    ptr: *anyopaque,
    now_fn: *const fn (*anyopaque) u64,

    pub fn now(self: Clock) u64 {
        return self.now_fn(self.ptr);
    }
};

pub const Options = struct {
    clock: Clock,
    local_epoch_ms: u64,
    initial_send_credit: u32 = default_send_credit,
    replay_window: u64 = default_replay_window,
    handshake_timeout_ms: u64 = default_handshake_timeout_ms,
    heartbeat_interval_ms: u64 = default_heartbeat_interval_ms,
    idle_timeout_ms: u64 = default_idle_timeout_ms,
    drain_timeout_ms: u64 = default_drain_timeout_ms,
};

pub const EmitResult = struct {
    bytes: []const u8,
    seq: u64,
    ack: u64,
    credit: u32,
    send_credit: u32,
};

pub const ReceiveResult = struct {
    event: ReceiveEvent,
    seq: u64,
    ack: u64,
    credit: u32,
    payload: []const u8 = "",
};

pub const FrameView = struct {
    kind: FrameKind,
    epoch_ms: u64,
    seq: u64,
    ack: u64,
    credit: u32,
    payload: []const u8 = "",
};

pub const Error = error{
    InvalidState,
    NotEstablished,
    BadMagic,
    UnsupportedVersion,
    UnknownFrameKind,
    Truncated,
    TrailingBytes,
    PayloadTooLarge,
    BufferTooSmall,
    InsufficientCredit,
    CreditOverflow,
    SequenceOverflow,
    BadEpoch,
    AckAheadOfSend,
    ReplayedFrame,
    OutOfWindow,
};

pub const default_send_credit: u32 = 64 * 1024;
pub const default_replay_window: u64 = 64;
pub const default_handshake_timeout_ms: u64 = 10_000;
pub const default_heartbeat_interval_ms: u64 = 15_000;
pub const default_idle_timeout_ms: u64 = 45_000;
pub const default_drain_timeout_ms: u64 = 5_000;
pub const max_payload_len: usize = std.math.maxInt(u16);

/// Tunable peer-link transport parameters. Defaults mirror the `default_*`
/// constants above, so a `Config{}` is behaviorally identical to the prior
/// hardcoded values.
pub const Config = struct {
    send_credit: u32 = default_send_credit,
    replay_window: u64 = default_replay_window,
    handshake_timeout_ms: u64 = default_handshake_timeout_ms,
    heartbeat_interval_ms: u64 = default_heartbeat_interval_ms,
    idle_timeout_ms: u64 = default_idle_timeout_ms,
    drain_timeout_ms: u64 = default_drain_timeout_ms,

    /// Overlay `[mesh.link]` peer-link transport keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.link.send_credit_bytes")) |v| cfg.send_credit = @intCast(v);
        if (doc.getUint("mesh.link.replay_window")) |v| cfg.replay_window = v;
        if (doc.getUint("mesh.link.handshake_timeout_ms")) |v| cfg.handshake_timeout_ms = v;
        if (doc.getUint("mesh.link.heartbeat_interval_ms")) |v| cfg.heartbeat_interval_ms = v;
        if (doc.getUint("mesh.link.idle_timeout_ms")) |v| cfg.idle_timeout_ms = v;
        if (doc.getUint("mesh.link.drain_timeout_ms")) |v| cfg.drain_timeout_ms = v;
    }
};

const magic = [_]u8{ 'S', 'P', 'L', 'K' };
// Peer-link wire protocol major version.
const version: u8 = 1;

pub const header_len = magic.len + 1 + 1 + 8 + 8 + 8 + 4 + 4;

pub const PeerLink = struct {
    state: State = .idle,
    clock: Clock,
    local_epoch_ms: u64,
    remote_epoch_ms: ?u64 = null,
    send_credit: u32,
    pending_credit: u32 = 0,
    next_out_seq: u64 = 1,
    next_in_seq: u64 = 1,
    last_acked_by_remote: u64 = 0,
    replay_window: u64,
    handshake_timeout_ms: u64,
    heartbeat_interval_ms: u64,
    idle_timeout_ms: u64,
    drain_timeout_ms: u64,
    state_since_ms: u64,
    last_rx_ms: u64,
    last_tx_ms: u64,

    pub fn init(options: Options) PeerLink {
        const now_ms = options.clock.now();
        return .{
            .clock = options.clock,
            .local_epoch_ms = options.local_epoch_ms,
            .send_credit = options.initial_send_credit,
            .replay_window = options.replay_window,
            .handshake_timeout_ms = options.handshake_timeout_ms,
            .heartbeat_interval_ms = options.heartbeat_interval_ms,
            .idle_timeout_ms = options.idle_timeout_ms,
            .drain_timeout_ms = options.drain_timeout_ms,
            .state_since_ms = now_ms,
            .last_rx_ms = now_ms,
            .last_tx_ms = now_ms,
        };
    }

    pub fn beginHandshake(self: *PeerLink) Error!void {
        if (self.state != .idle) return error.InvalidState;
        self.enter(.handshaking);
    }

    pub fn finishHandshake(self: *PeerLink, remote_epoch_ms: u64) Error!void {
        if (self.state != .handshaking) return error.InvalidState;
        const now_ms = self.clock.now();
        self.remote_epoch_ms = remote_epoch_ms;
        self.state = .established;
        self.state_since_ms = now_ms;
        self.last_rx_ms = now_ms;
        self.last_tx_ms = now_ms;
    }

    pub fn drain(self: *PeerLink) void {
        if (self.state == .closed or self.state == .draining) return;
        self.enter(.draining);
    }

    pub fn close(self: *PeerLink) void {
        self.enter(.closed);
    }

    pub fn tick(self: *PeerLink) TickEvent {
        const now_ms = self.clock.now();
        switch (self.state) {
            .idle => return .none,
            .handshaking => {
                if (elapsedMs(now_ms, self.state_since_ms) >= self.handshake_timeout_ms) {
                    self.enterAt(.draining, now_ms);
                    return .draining;
                }
                return .none;
            },
            .established => {
                if (elapsedMs(now_ms, self.last_rx_ms) >= self.idle_timeout_ms) {
                    self.enterAt(.draining, now_ms);
                    return .draining;
                }
                if (elapsedMs(now_ms, self.last_tx_ms) >= self.heartbeat_interval_ms) {
                    return .heartbeat_due;
                }
                return .none;
            },
            .draining => {
                if (elapsedMs(now_ms, self.state_since_ms) >= self.drain_timeout_ms) {
                    self.enterAt(.closed, now_ms);
                    return .closed;
                }
                return .none;
            },
            .closed => return .none,
        }
    }

    pub fn emitDelta(self: *PeerLink, payload: []const u8, out: []u8) Error!EmitResult {
        if (self.state != .established) return error.NotEstablished;
        const cost = try wireCost(payload.len);
        if (cost > self.send_credit) return error.InsufficientCredit;
        if (self.next_out_seq == std.math.maxInt(u64)) return error.SequenceOverflow;

        const seq = self.next_out_seq;
        const credit = self.pending_credit;
        const frame = FrameView{
            .kind = .delta,
            .epoch_ms = self.local_epoch_ms,
            .seq = seq,
            .ack = self.next_in_seq - 1,
            .credit = credit,
            .payload = payload,
        };
        const bytes = try encodeFrame(frame, out);

        self.send_credit -= cost;
        self.pending_credit = 0;
        self.next_out_seq += 1;
        self.last_tx_ms = self.clock.now();
        return .{
            .bytes = bytes,
            .seq = seq,
            .ack = frame.ack,
            .credit = credit,
            .send_credit = self.send_credit,
        };
    }

    pub fn emitAck(self: *PeerLink, out: []u8) Error!EmitResult {
        return self.emitControl(.ack, out);
    }

    pub fn emitHeartbeat(self: *PeerLink, out: []u8) Error!EmitResult {
        return self.emitControl(.heartbeat, out);
    }

    pub fn emitClose(self: *PeerLink, out: []u8) Error!EmitResult {
        if (self.state == .idle or self.state == .closed) return error.InvalidState;
        const result = try self.emitControl(.close, out);
        self.drain();
        return result;
    }

    pub fn receive(self: *PeerLink, bytes: []const u8) Error!ReceiveResult {
        const view = try decodeFrame(bytes);
        try self.requireRemoteEpoch(view.epoch_ms);

        switch (view.kind) {
            .delta => {
                if (self.state != .established) return error.NotEstablished;
                try self.requireNextSeq(view.seq);
                try self.applyAck(view.ack, view.credit);
                try self.acceptDeltaCredit(bytes.len);
                self.next_in_seq += 1;
                self.last_rx_ms = self.clock.now();
                return .{
                    .event = .delta,
                    .seq = view.seq,
                    .ack = view.ack,
                    .credit = view.credit,
                    .payload = view.payload,
                };
            },
            .ack => {
                try self.requireEstablishedOrDraining();
                try self.applyAck(view.ack, view.credit);
                self.last_rx_ms = self.clock.now();
                return .{ .event = .ack, .seq = view.seq, .ack = view.ack, .credit = view.credit };
            },
            .heartbeat => {
                try self.requireEstablishedOrDraining();
                try self.applyAck(view.ack, view.credit);
                self.last_rx_ms = self.clock.now();
                return .{
                    .event = .heartbeat,
                    .seq = view.seq,
                    .ack = view.ack,
                    .credit = view.credit,
                };
            },
            .close => {
                try self.requireEstablishedOrDraining();
                try self.applyAck(view.ack, view.credit);
                self.last_rx_ms = self.clock.now();
                self.drain();
                return .{ .event = .close, .seq = view.seq, .ack = view.ack, .credit = view.credit };
            },
        }
    }

    pub fn remoteAckedThrough(self: *const PeerLink) u64 {
        return self.last_acked_by_remote;
    }

    pub fn nextOutboundSeq(self: *const PeerLink) u64 {
        return self.next_out_seq;
    }

    pub fn nextInboundSeq(self: *const PeerLink) u64 {
        return self.next_in_seq;
    }

    /// Bounded transport state needed to resume an established link across a Helix
    /// hot upgrade WITHOUT re-running the handshake. The peer never saw the socket
    /// drop, so its `remote_epoch_ms` + `next_in_seq` for us are unchanged — we
    /// MUST replay exactly these values or the peer rejects our next frame with
    /// BadEpoch / ReplayedFrame. Timeout clocks are intentionally excluded: they
    /// legitimately reset to "now" on the successor.
    pub const ResumeHeader = struct {
        local_epoch_ms: u64,
        remote_epoch_ms: u64,
        send_credit: u32,
        pending_credit: u32,
        next_out_seq: u64,
        next_in_seq: u64,
        last_acked_by_remote: u64,
    };

    pub fn snapshotResume(self: *const PeerLink) ResumeHeader {
        return .{
            .local_epoch_ms = self.local_epoch_ms,
            .remote_epoch_ms = self.remote_epoch_ms orelse 0,
            .send_credit = self.send_credit,
            .pending_credit = self.pending_credit,
            .next_out_seq = self.next_out_seq,
            .next_in_seq = self.next_in_seq,
            .last_acked_by_remote = self.last_acked_by_remote,
        };
    }

    /// Rebuild a link directly in the `established` state from a resume header,
    /// bypassing the handshake. `options` supplies the clock + tunables; the
    /// header supplies the exact sequencing/credit/epoch continuity the peer still
    /// expects. Timeout clocks start fresh at `options.clock.now()`.
    pub fn resumeEstablished(options: Options, hdr: ResumeHeader) PeerLink {
        var link = PeerLink.init(options);
        link.local_epoch_ms = hdr.local_epoch_ms;
        link.remote_epoch_ms = hdr.remote_epoch_ms;
        link.send_credit = hdr.send_credit;
        link.pending_credit = hdr.pending_credit;
        link.next_out_seq = hdr.next_out_seq;
        link.next_in_seq = hdr.next_in_seq;
        link.last_acked_by_remote = hdr.last_acked_by_remote;
        link.state = .established;
        return link;
    }

    fn emitControl(self: *PeerLink, kind: FrameKind, out: []u8) Error!EmitResult {
        try self.requireEstablishedOrDraining();
        const credit = self.pending_credit;
        const frame = FrameView{
            .kind = kind,
            .epoch_ms = self.local_epoch_ms,
            .seq = 0,
            .ack = self.next_in_seq - 1,
            .credit = credit,
        };
        const bytes = try encodeFrame(frame, out);
        self.pending_credit = 0;
        self.last_tx_ms = self.clock.now();
        return .{
            .bytes = bytes,
            .seq = 0,
            .ack = frame.ack,
            .credit = credit,
            .send_credit = self.send_credit,
        };
    }

    fn applyAck(self: *PeerLink, ack: u64, credit: u32) Error!void {
        const sent_high = self.next_out_seq - 1;
        if (ack > sent_high) return error.AckAheadOfSend;
        if (ack < self.last_acked_by_remote and credit != 0) return error.ReplayedFrame;
        if (ack > self.last_acked_by_remote) self.last_acked_by_remote = ack;
        if (credit == 0) return;
        self.send_credit = std.math.add(u32, self.send_credit, credit) catch
            return error.CreditOverflow;
    }

    fn acceptDeltaCredit(self: *PeerLink, wire_len: usize) Error!void {
        const credit: u32 = @intCast(wire_len);
        self.pending_credit = std.math.add(u32, self.pending_credit, credit) catch
            return error.CreditOverflow;
    }

    fn requireNextSeq(self: *const PeerLink, seq: u64) Error!void {
        const expected = self.next_in_seq;
        if (seq < expected) return error.ReplayedFrame;
        if (seq == expected) return;
        if (seq - expected > self.replay_window) return error.OutOfWindow;
        return error.OutOfWindow;
    }

    fn requireRemoteEpoch(self: *const PeerLink, epoch_ms: u64) Error!void {
        const remote_epoch_ms = self.remote_epoch_ms orelse return error.NotEstablished;
        if (epoch_ms != remote_epoch_ms) return error.BadEpoch;
    }

    fn requireEstablishedOrDraining(self: *const PeerLink) Error!void {
        if (self.state == .established or self.state == .draining) return;
        return error.NotEstablished;
    }

    fn enter(self: *PeerLink, state: State) void {
        self.enterAt(state, self.clock.now());
    }

    fn enterAt(self: *PeerLink, state: State, now_ms: u64) void {
        self.state = state;
        self.state_since_ms = now_ms;
        if (state == .closed) {
            self.remote_epoch_ms = null;
        }
    }
};

pub fn encodeFrame(frame: FrameView, out: []u8) Error![]const u8 {
    if (frame.payload.len > max_payload_len) return error.PayloadTooLarge;
    const total = header_len + frame.payload.len;
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = version;
    out[magic.len + 1] = @backingInt(frame.kind);

    var pos: usize = magic.len + 2;
    writeU64(out[pos..][0..8], frame.epoch_ms);
    pos += 8;
    writeU64(out[pos..][0..8], frame.seq);
    pos += 8;
    writeU64(out[pos..][0..8], frame.ack);
    pos += 8;
    std.mem.writeInt(u32, out[pos..][0..4], frame.credit, .little);
    pos += 4;
    std.mem.writeInt(u32, out[pos..][0..4], @intCast(frame.payload.len), .little);
    pos += 4;
    @memcpy(out[pos..total], frame.payload);
    return out[0..total];
}

pub fn decodeFrame(in: []const u8) Error!FrameView {
    if (in.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, in[0..magic.len], &magic)) return error.BadMagic;
    if (in[magic.len] != version) return error.UnsupportedVersion;

    const kind = decodeKind(in[magic.len + 1]) catch return error.UnknownFrameKind;

    var pos: usize = magic.len + 2;
    const epoch_ms = readU64(in[pos..][0..8]);
    pos += 8;
    const seq = readU64(in[pos..][0..8]);
    pos += 8;
    const ack = readU64(in[pos..][0..8]);
    pos += 8;
    const credit = std.mem.readInt(u32, in[pos..][0..4], .little);
    pos += 4;
    const payload_len = std.mem.readInt(u32, in[pos..][0..4], .little);
    pos += 4;
    if (payload_len > max_payload_len) return error.PayloadTooLarge;

    const total = header_len + @as(usize, @intCast(payload_len));
    if (in.len < total) return error.Truncated;
    if (in.len != total) return error.TrailingBytes;
    if (kind != .delta and payload_len != 0) return error.PayloadTooLarge;

    return .{
        .kind = kind,
        .epoch_ms = epoch_ms,
        .seq = seq,
        .ack = ack,
        .credit = credit,
        .payload = in[pos..total],
    };
}

fn decodeKind(value: u8) Error!FrameKind {
    return switch (value) {
        @backingInt(FrameKind.delta) => .delta,
        @backingInt(FrameKind.ack) => .ack,
        @backingInt(FrameKind.heartbeat) => .heartbeat,
        @backingInt(FrameKind.close) => .close,
        else => error.UnknownFrameKind,
    };
}

fn wireCost(payload_len: usize) Error!u32 {
    if (payload_len > max_payload_len) return error.PayloadTooLarge;
    return @intCast(header_len + payload_len);
}

fn elapsedMs(now_ms: u64, since_ms: u64) u64 {
    if (now_ms <= since_ms) return 0;
    return now_ms - since_ms;
}

fn writeU64(out: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, out, value, .little);
}

fn readU64(in: *const [8]u8) u64 {
    return std.mem.readInt(u64, in, .little);
}

const TestClock = struct {
    now_ms: u64,

    fn init(now_ms: u64) TestClock {
        return .{ .now_ms = now_ms };
    }

    fn clock(self: *TestClock) Clock {
        return .{ .ptr = self, .now_fn = nowFn };
    }

    fn advance(self: *TestClock, ms: u64) void {
        self.now_ms += ms;
    }

    fn nowFn(ptr: *anyopaque) u64 {
        const self: *TestClock = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }
};

fn establishedPair(clock: *TestClock, initial_credit: u32) !struct { a: PeerLink, b: PeerLink } {
    var a = PeerLink.init(.{
        .clock = clock.clock(),
        .local_epoch_ms = 10,
        .initial_send_credit = initial_credit,
    });
    var b = PeerLink.init(.{
        .clock = clock.clock(),
        .local_epoch_ms = 20,
        .initial_send_credit = default_send_credit,
    });
    try a.beginHandshake();
    try b.beginHandshake();
    try a.finishHandshake(20);
    try b.finishHandshake(10);
    return .{ .a = a, .b = b };
}

test "handshake transitions idle handshaking established" {
    const allocator = std.testing.allocator;
    var clock = TestClock.init(10);
    var link = PeerLink.init(.{ .clock = clock.clock(), .local_epoch_ms = 42 });

    var states: std.ArrayList(State) = .empty;
    defer states.deinit(allocator);
    try states.append(allocator, link.state);

    try link.beginHandshake();
    try states.append(allocator, link.state);
    try link.finishHandshake(99);
    try states.append(allocator, link.state);

    try std.testing.expectEqual(@as(usize, 3), states.items.len);
    try std.testing.expectEqual(State.idle, states.items[0]);
    try std.testing.expectEqual(State.handshaking, states.items[1]);
    try std.testing.expectEqual(State.established, states.items[2]);
    try std.testing.expectEqual(@as(?u64, 99), link.remote_epoch_ms);
}

test "credit exhaustion blocks send then resumes on ack" {
    const payload = "abc";
    const first_cost: u32 = @intCast(header_len + payload.len);
    var clock = TestClock.init(1_000);
    var pair = try establishedPair(&clock, first_cost);

    var a_to_b: [128]u8 = undefined;
    var b_to_a: [128]u8 = undefined;

    const first = try pair.a.emitDelta(payload, &a_to_b);
    try std.testing.expectEqual(@as(u32, 0), pair.a.send_credit);
    try std.testing.expectError(error.InsufficientCredit, pair.a.emitDelta(payload, &a_to_b));

    const received = try pair.b.receive(first.bytes);
    try std.testing.expectEqual(ReceiveEvent.delta, received.event);
    try std.testing.expectEqualSlices(u8, payload, received.payload);

    const ack = try pair.b.emitAck(&b_to_a);
    try std.testing.expectEqual(first.seq, ack.ack);
    try std.testing.expectEqual(first_cost, ack.credit);

    const acked = try pair.a.receive(ack.bytes);
    try std.testing.expectEqual(ReceiveEvent.ack, acked.event);
    try std.testing.expectEqual(first.seq, pair.a.remoteAckedThrough());

    const second = try pair.a.emitDelta(payload, &a_to_b);
    try std.testing.expectEqual(@as(u64, 2), second.seq);
}

test "out of window and replayed frames are rejected" {
    var clock = TestClock.init(1_000);
    var pair = try establishedPair(&clock, default_send_credit);
    var a_to_b: [128]u8 = undefined;
    var forged: [128]u8 = undefined;

    const sent = try pair.a.emitDelta("one", &a_to_b);
    _ = try pair.b.receive(sent.bytes);
    try std.testing.expectError(error.ReplayedFrame, pair.b.receive(sent.bytes));

    const future = try encodeFrame(.{
        .kind = .delta,
        .epoch_ms = pair.a.local_epoch_ms,
        .seq = pair.b.nextInboundSeq() + 1,
        .ack = 0,
        .credit = 0,
        .payload = "future",
    }, &forged);
    try std.testing.expectError(error.OutOfWindow, pair.b.receive(future));
}

test "resumeEstablished continues the exact seq/epoch stream the peer expects" {
    var clock = TestClock.init(1_000);
    var pair = try establishedPair(&clock, default_send_credit);
    var a_to_b: [256]u8 = undefined;
    var b_to_a: [256]u8 = undefined;

    // Advance the live stream: A sends two deltas, B acks, so A's next_out_seq,
    // last_acked_by_remote, and send_credit are all mid-stream (not initial).
    const d1 = try pair.a.emitDelta("one", &a_to_b);
    _ = try pair.b.receive(d1.bytes);
    const ack1 = try pair.b.emitAck(&b_to_a);
    _ = try pair.a.receive(ack1.bytes);
    const d2 = try pair.a.emitDelta("two", &a_to_b);
    _ = try pair.b.receive(d2.bytes);
    const ack2 = try pair.b.emitAck(&b_to_a);
    _ = try pair.a.receive(ack2.bytes);

    // Snapshot A across a simulated upgrade and rebuild it from the header alone —
    // B is untouched (it never saw a drop).
    const hdr = pair.a.snapshotResume();
    var a2 = PeerLink.resumeEstablished(.{
        .clock = clock.clock(),
        .local_epoch_ms = 10, // A's original epoch — B validates every frame against it
        .initial_send_credit = 1, // deliberately wrong; header must override
    }, hdr);

    try std.testing.expectEqual(State.established, a2.state);
    try std.testing.expectEqual(pair.a.next_out_seq, a2.next_out_seq);
    try std.testing.expectEqual(pair.a.send_credit, a2.send_credit);

    // The resumed A emits the NEXT delta; B accepts it at the continued seq/epoch.
    const d3 = try a2.emitDelta("three", &a_to_b);
    try std.testing.expectEqual(d2.seq + 1, d3.seq);
    const got = try pair.b.receive(d3.bytes);
    try std.testing.expectEqual(ReceiveEvent.delta, got.event);
    try std.testing.expectEqualSlices(u8, "three", got.payload);

    // And the resumed A still accepts B's next frame (recv epoch continuity).
    const bd = try pair.b.emitDelta("reply", &b_to_a);
    const gotb = try a2.receive(bd.bytes);
    try std.testing.expectEqual(ReceiveEvent.delta, gotb.event);
    try std.testing.expectEqualSlices(u8, "reply", gotb.payload);
}

test "heartbeat and timeout are deterministic with caller supplied clock" {
    var clock = TestClock.init(1_000);
    var pair = try establishedPair(&clock, default_send_credit);
    var heartbeat: [header_len]u8 = undefined;

    clock.advance(default_heartbeat_interval_ms);
    try std.testing.expectEqual(TickEvent.heartbeat_due, pair.a.tick());
    const hb = try pair.a.emitHeartbeat(&heartbeat);
    const got = try pair.b.receive(hb.bytes);
    try std.testing.expectEqual(ReceiveEvent.heartbeat, got.event);

    clock.advance(default_idle_timeout_ms);
    try std.testing.expectEqual(TickEvent.draining, pair.a.tick());
    try std.testing.expectEqual(State.draining, pair.a.state);
}

test {
    std.testing.refAllDecls(@This());
}

test "Config.applyToml overlays mesh.link transport keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.link]
        \\send_credit_bytes = 131072
        \\idle_timeout_ms = 90000
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(u32, 131072), cfg.send_credit);
    try std.testing.expectEqual(@as(u64, 90000), cfg.idle_timeout_ms);
    try std.testing.expectEqual(default_heartbeat_interval_ms, cfg.heartbeat_interval_ms); // default
}
