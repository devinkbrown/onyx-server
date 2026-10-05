// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows Helix READY/COMMIT/ABORT transaction after the typed transfer.
//! The candidate keeps every imported SOCKET inert through COMMIT and a
//! signaled predecessor process HANDLE. No server lifecycle is wired here.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("../../substrate/platform.zig");
const io_backend = @import("../io_backend.zig");
const control = @import("native_windows_control.zig");
const process = @import("native_windows_process.zig");
const bootstrap = @import("native_windows_bootstrap.zig");
const wal_mod = @import("native_windows_wal.zig");
const metrics_mod = @import("native_windows_metrics.zig");
const webhook_mod = @import("native_windows_webhook.zig");
const history_mod = @import("native_windows_history.zig");
const udp_mod = @import("native_windows_udp_custody.zig");
const store = @import("../store.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const ready_magic = "HXWR";
const ready_version: u16 = 1;
const ready_body_len = 64;
const wait_object_0: u32 = 0;
const wait_timeout: u32 = 258;
const wait_failed: u32 = 0xffff_ffff;
const digest_domain = "onyx-helix-windows-ready-v6";

extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetProcessId(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn WaitForSingleObject(handle: usize, ms: u32) callconv(.winapi) u32;
extern "kernel32" fn ExitProcess(code: u32) callconv(.winapi) noreturn;
extern "kernel32" fn GetSystemDirectoryW(buffer: [*]u16, size: u32) callconv(.winapi) u32;
extern "kernel32" fn CreateProcessW(application: [*:0]const u16, command_line: [*:0]u16, process_attributes: ?*anyopaque, thread_attributes: ?*anyopaque, inherit: i32, creation_flags: u32, environment: ?*anyopaque, cwd: ?[*:0]const u16, startup: *std.os.windows.STARTUPINFOW, information: *TestProcessInformation) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

const TestProcessInformation = extern struct {
    process: usize,
    thread: usize,
    pid: u32,
    thread_id: u32,
};

pub const Digest = [32]u8;
pub const Error = control.Error || bootstrap.Error || wal_mod.Error || io_backend.WindowsTcpObservationError || platform.EntropyError || error{
    InvalidCandidate,
    InvalidReady,
    InvalidDecision,
    InvalidReleaseState,
    Aborted,
    WaitFailed,
};

const Phase = enum(u16) { challenge = 1, response = 2, commit = 3, abort = 4, commit_ack = 5 };

const Ticket = struct {
    identity: control.Identity,
    nonce: [16]u8,
    digest: Digest,
    count: usize,
};

pub const ParentReady = Ticket;
pub const ChildReady = Ticket;

/// The server's strict capsule decoder and physical connection join must
/// finish here. A success means every mandatory state item is staged, without
/// publishing it or submitting AFD/IOCP work.
pub const Validator = struct {
    context: ?*anyopaque,
    run: *const fn (?*anyopaque, *bootstrap.Incoming) anyerror!void,
};

fn hashPrefix(hash: *Sha256, plaintext: []const u8, count: usize) void {
    hash.update(digest_domain);
    var numbers: [12]u8 = undefined;
    std.mem.writeInt(u64, numbers[0..8], @intCast(plaintext.len), .big);
    std.mem.writeInt(u32, numbers[8..12], @intCast(count), .big);
    hash.update(&numbers);
    hash.update(plaintext);
}

fn hashRow(hash: *Sha256, canonical: i32, shard: u16, role: bootstrap.Role, family: u8) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(i32, bytes[0..4], canonical, .big);
    std.mem.writeInt(u16, bytes[4..6], shard, .big);
    bytes[6] = @intFromEnum(role);
    bytes[7] = family;
    hash.update(&bytes);
}

/// The predecessor binds READY to the exact encrypted plaintext and indexed
/// socket manifest that it sent. A zero-state or listener-only manifest is
/// valid; no client row is synthesized.
pub fn sourceDigest(plaintext: []const u8, rows: []const bootstrap.SourceRow) Error!Digest {
    return sourceDigestWithWal(plaintext, rows, null, 1);
}

/// READY binds the exact candidate-local WAL HANDLE and witnessed file, or
/// the canonical absent frame, after the ordered state/socket manifest.
pub fn sourceDigestWithWal(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32) Error!Digest {
    return sourceDigestWithWalAndConfig(plaintext, rows, wal, target_pid, @splat(0));
}

/// The production challenge also binds the config source transcript delivered
/// over the authenticated control channel. A candidate compares that source
/// to its own boot parse before it can answer READY.
pub fn sourceDigestWithWalAndConfig(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32, source_digest: [32]u8) Error!Digest {
    return sourceDigestWithWalConfigAndMetrics(plaintext, rows, wal, target_pid, source_digest, metrics_mod.absentFrame());
}

/// The companion frame includes the exact source exposition digest and
/// candidate-local read-only section/socket capabilities. READY binds those
/// authenticated bytes even after the one-use Winsock record is consumed.
pub fn sourceDigestWithWalConfigAndMetrics(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32, source_digest: [32]u8, metrics_body: metrics_mod.Frame) Error!Digest {
    return sourceDigestWithWalConfigMetricsAndWebhook(plaintext, rows, wal, target_pid, source_digest, metrics_body, webhook_mod.absentFrame());
}

pub fn sourceDigestWithWalConfigMetricsAndWebhook(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32, source_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame) Error!Digest {
    return sourceDigestWithWalConfigMetricsWebhookAndHistory(plaintext, rows, wal, target_pid, source_digest, metrics_body, webhook_body, history_mod.absentFrame());
}

pub fn sourceDigestWithWalConfigMetricsWebhookAndHistory(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32, source_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame) Error!Digest {
    return sourceDigestWithWalConfigMetricsWebhookHistoryAndUdp(plaintext, rows, wal, target_pid, source_digest, metrics_body, webhook_body, history_body, udp_mod.absentFrame(.webtransport), udp_mod.absentFrame(.media), udp_mod.absentFrame(.native_media));
}

pub fn sourceDigestWithWalConfigMetricsWebhookHistoryAndUdp(plaintext: []const u8, rows: []const bootstrap.SourceRow, wal: ?*const store.WindowsWalDescriptor, target_pid: u32, source_digest: [32]u8, metrics_body: metrics_mod.Frame, webhook_body: webhook_mod.Frame, history_body: history_mod.Frame, wt_body: udp_mod.Frame, webrtc_body: udp_mod.Frame, native_body: udp_mod.Frame) Error!Digest {
    if (rows.len > bootstrap.max_sockets) return error.InvalidReady;
    _ = try metrics_mod.parseFrame(&metrics_body, target_pid, &.{});
    _ = try webhook_mod.parseFrame(&webhook_body, target_pid);
    _ = try history_mod.parseFrame(&history_body, target_pid);
    _ = try udp_mod.validateFrame(&wt_body, .webtransport, target_pid);
    _ = try udp_mod.validateFrame(&webrtc_body, .media, target_pid);
    _ = try udp_mod.validateFrame(&native_body, .native_media, target_pid);
    var hash = Sha256.init(.{});
    hashPrefix(&hash, plaintext, rows.len);
    for (rows) |row| hashRow(&hash, row.canonical, row.shard, row.role, row.family);
    const wal_body = try wal_mod.encode(wal, target_pid);
    hash.update(&wal_body);
    hash.update(&source_digest);
    hash.update(&metrics_body);
    hash.update(&webhook_body);
    hash.update(&history_body);
    hash.update(&wt_body);
    hash.update(&webrtc_body);
    hash.update(&native_body);
    var digest: Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn incomingDigest(incoming: *const bootstrap.Incoming) Digest {
    var hash = Sha256.init(.{});
    hashPrefix(&hash, incoming.plaintext, incoming.rows.len);
    for (incoming.rows) |row| hashRow(&hash, row.canonical, row.shard, row.role, row.family);
    // Bootstrap retains the authenticated bytes even after the candidate
    // transfers HANDLE custody to its read-only staged store before READY.
    hash.update(&incoming.wal_body);
    hash.update(&incoming.source_digest);
    hash.update(&incoming.metrics_body);
    hash.update(&incoming.webhook_body);
    hash.update(&incoming.history_body);
    hash.update(&incoming.webtransport_udp_body);
    hash.update(&incoming.webrtc_media_udp_body);
    hash.update(&incoming.native_media_udp_body);
    var digest: Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn body(phase: Phase, ticket: Ticket) [ready_body_len]u8 {
    var bytes: [ready_body_len]u8 = @splat(0);
    @memcpy(bytes[0..4], ready_magic);
    std.mem.writeInt(u16, bytes[4..6], ready_version, .big);
    std.mem.writeInt(u16, bytes[6..8], @intFromEnum(phase), .big);
    std.mem.writeInt(u32, bytes[8..12], @intCast(ticket.count), .big);
    @memcpy(bytes[16..32], &ticket.nonce);
    @memcpy(bytes[32..64], &ticket.digest);
    return bytes;
}

fn matches(message: *const control.Message, kind: control.Kind, phase: Phase, ticket: Ticket) bool {
    if (message.kind != kind or message.length != ready_body_len) return false;
    const expected = body(phase, ticket);
    return std.crypto.timing_safe.eql([ready_body_len]u8, message.body[0..ready_body_len].*, expected);
}

fn parseChallenge(message: *const control.Message, identity: control.Identity) Error!Ticket {
    const bytes = message.bytes();
    if (message.kind != .ready or bytes.len != ready_body_len or
        !std.mem.eql(u8, bytes[0..4], ready_magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != ready_version or
        std.mem.readInt(u16, bytes[6..8], .big) != @intFromEnum(Phase.challenge) or
        std.mem.readInt(u32, bytes[12..16], .big) != 0) return error.InvalidReady;
    const count: usize = std.mem.readInt(u32, bytes[8..12], .big);
    if (count > bootstrap.max_sockets) return error.InvalidReady;
    return .{ .identity = identity, .nonce = bytes[16..32].*, .digest = bytes[32..64].*, .count = count };
}

fn validateParent(candidate: *const process.Process) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (candidate.committed or candidate.process_handle == 0 or candidate.pid == 0 or
        candidate.pid == GetCurrentProcessId() or GetProcessId(candidate.process_handle) != candidate.pid or
        candidate.endpoint.role != .parent or !std.meta.eql(candidate.endpoint.identity, candidate.identity))
        return error.InvalidCandidate;
}

fn validateChild(child: *const process.Incoming, incoming: *const bootstrap.Incoming) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (child.parent_process == 0 or child.parent_pid == 0 or
        child.parent_pid == GetCurrentProcessId() or GetProcessId(child.parent_process) != child.parent_pid or
        child.endpoint.role != .child or !std.meta.eql(child.endpoint.identity, child.identity) or
        !std.meta.eql(incoming.identity, child.identity)) return error.InvalidCandidate;
}

fn observeRoles(incoming: *const bootstrap.Incoming) Error!void {
    for (incoming.rows) |row| switch (row.role) {
        .plain_listener, .tls_listener, .websocket_listener, .s2s_listener => {
            const observed = try io_backend.observeWindowsListeningTcpSocket(row.canonical);
            if ((row.family == 4 and std.meta.activeTag(observed.local.address) != .ipv4) or
                (row.family == 6 and std.meta.activeTag(observed.local.address) != .ipv6))
                return error.InvalidReady;
        },
        .client, .s2s_state => try io_backend.observeWindowsHelixConnectedTcpSocket(row.canonical),
    };
}

fn challenge(endpoint: *control.Endpoint, identity: control.Identity, digest: Digest, count: usize, deadline: i64) Error!ParentReady {
    if (endpoint.role != .parent or !std.meta.eql(endpoint.identity, identity) or count > bootstrap.max_sockets)
        return error.InvalidCandidate;
    var ticket = ParentReady{ .identity = identity, .nonce = undefined, .digest = digest, .count = count };
    try platform.fillOsEntropy(&ticket.nonce);
    const request = body(.challenge, ticket);
    try endpoint.send(.ready, &request, deadline);
    var response = try endpoint.receive(deadline);
    defer response.deinit();
    if (matches(&response, .abort, .abort, ticket)) return error.Aborted;
    if (!matches(&response, .ready, .response, ticket)) return error.InvalidReady;
    return ticket;
}

/// Challenge only an actual uncommitted child returned by CreateProcessW.
/// Any failure terminates and reaps it before the predecessor resumes I/O.
pub fn parentAwaitReady(candidate: *process.Process, digest: Digest, count: usize, deadline: i64) Error!ParentReady {
    errdefer candidate.deinit();
    try validateParent(candidate);
    return challenge(&candidate.endpoint, candidate.identity, digest, count, deadline);
}

fn answerChallenge(endpoint: *control.Endpoint, incoming: *bootstrap.Incoming, validator: Validator, deadline: i64) anyerror!ChildReady {
    var request = try endpoint.receive(deadline);
    defer request.deinit();
    const ticket = try parseChallenge(&request, endpoint.identity);
    var answered = false;
    errdefer if (!answered and !endpoint.poisoned and !endpoint.awaiting_response) {
        const refusal = body(.abort, ticket);
        endpoint.send(.abort, &refusal, deadline) catch {};
    };
    if (ticket.count != incoming.rows.len or !std.crypto.timing_safe.eql(Digest, ticket.digest, incomingDigest(incoming)))
        return error.InvalidReady;
    // Main stages before Server.init so inherited listeners can be validated
    // and claimed while the server is still inert. The standalone exchange
    // tests may stage here instead. A partial earlier attempt is never retried.
    if (!incoming.stage_attempted) {
        try incoming.stageInert();
    } else if (incoming.release_confirmed or incoming.staged_count != incoming.rows.len) {
        return error.InvalidReleaseState;
    }
    try observeRoles(incoming);
    try validator.run(validator.context, incoming);
    for (incoming.rows) |row| if (!row.server_owned) return error.InvalidReady;
    // A PID-scoped UDP provider record is only custody after the inert owner
    // imports it. READY cannot authorize COMMIT with an unused record.
    if (incoming.webtransport_udp) |received| if (!received.transfer.consumed) return error.InvalidReady;
    if (incoming.webrtc_media_udp) |received| if (!received.transfer.consumed) return error.InvalidReady;
    if (incoming.native_media_udp) |received| if (!received.transfer.consumed) return error.InvalidReady;
    const response = body(.response, ticket);
    try endpoint.send(.ready, &response, deadline);
    answered = true;
    return ticket;
}

/// The final descriptor ACK left this child endpoint awaiting a response.
/// Receiving the parent's READY challenge first clears that turn; the child
/// can then answer READY after exact-ID staging and strict validation.
pub fn childAnswerReady(child: *process.Incoming, incoming: *bootstrap.Incoming, validator: Validator, deadline: i64) anyerror!ChildReady {
    try validateChild(child, incoming);
    return answerChallenge(&child.endpoint, incoming, validator, deadline);
}

fn sendDecision(endpoint: *control.Endpoint, phase: Phase, ticket: ParentReady, deadline: i64) Error!void {
    if (endpoint.role != .parent or !std.meta.eql(endpoint.identity, ticket.identity) or
        (phase != .commit and phase != .abort)) return error.InvalidCandidate;
    const decision = body(phase, ticket);
    try endpoint.send(if (phase == .commit) .commit else .abort, &decision, deadline);
}

fn awaitCommitAck(endpoint: *control.Endpoint, ticket: ParentReady, deadline: i64) Error!void {
    var response = try endpoint.receive(deadline);
    defer response.deinit();
    if (!matches(&response, .commit_ack, .commit_ack, ticket)) return error.InvalidDecision;
}

fn sendCommitAck(endpoint: *control.Endpoint, ticket: ChildReady, deadline: i64) Error!void {
    const acknowledgement = body(.commit_ack, ticket);
    try endpoint.send(.commit_ack, &acknowledgement, deadline);
}

/// A successful COMMIT never returns to the predecessor event loop. Its
/// process exit closes old SOCKET and IOCP handles; the child observes that
/// exact process HANDLE before authorizing replacement association. The
/// caller must already have drained I/O and durably sealed the snapshot.
pub fn parentCommitAndExit(candidate: *process.Process, ticket: ParentReady, deadline: i64) Error!noreturn {
    errdefer candidate.deinit();
    try validateParent(candidate);
    if (!std.meta.eql(ticket.identity, candidate.identity)) return error.InvalidReady;
    try sendDecision(&candidate.endpoint, .commit, ticket, deadline);
    // The predecessor retains authority until the child proves it received
    // COMMIT. A child timing out at the old bootstrap deadline is rollback-
    // safe only while this process is still alive to resume every socket.
    try awaitCommitAck(&candidate.endpoint, ticket, deadline);
    candidate.committed = true;
    ExitProcess(0);
}

/// Post-READY rejection is authenticated when the channel can still send;
/// termination and reaping are the definitive abort, even if the pipe broke.
pub fn parentAbort(candidate: *process.Process, ticket: ParentReady, deadline: i64) Error!void {
    if (candidate.committed) return error.InvalidCandidate;
    defer candidate.deinit();
    try validateParent(candidate);
    if (!std.meta.eql(ticket.identity, candidate.identity)) return error.InvalidReady;
    sendDecision(&candidate.endpoint, .abort, ticket, deadline) catch {};
}

fn receiveDecision(endpoint: *control.Endpoint, ticket: ChildReady, deadline: i64) Error!void {
    var message = try endpoint.receive(deadline);
    defer message.deinit();
    if (matches(&message, .abort, .abort, ticket)) return error.Aborted;
    if (!matches(&message, .commit, .commit, ticket)) return error.InvalidDecision;
}

fn waitForPredecessorExit(parent_process: usize, parent_pid: u32, deadline: ?i64) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (parent_process == 0 or parent_pid == 0 or parent_pid == GetCurrentProcessId() or
        GetProcessId(parent_process) != parent_pid) return error.InvalidCandidate;
    // COMMIT is irreversible: the predecessor has promised to exit. Once that
    // authenticated decision arrives, never abandon live attachments because
    // the earlier bootstrap lease expired a moment before process exit.
    const remaining: u32 = if (deadline) |until| blk: {
        const now = platform.monotonicMillis();
        break :blk if (until <= now) 0 else @intCast(@min(@as(i64, std.math.maxInt(u32) - 1), until - now));
    } else 0xffff_ffff;
    switch (WaitForSingleObject(parent_process, remaining)) {
        wait_object_0 => {},
        wait_timeout => return error.Timeout,
        wait_failed => return error.WaitFailed,
        else => return error.WaitFailed,
    }
    if (GetProcessId(parent_process) != parent_pid) return error.InvalidCandidate;
}

/// COMMIT alone does not make a SOCKET active. The child waits for the exact
/// predecessor to exit, then explicitly marks each staged registry entry as
/// released. Only a later reactor may associate its new IOCP and submit I/O.
/// On any error the caller must tear down `incoming` and exit the candidate.
pub fn childAwaitCommit(child: *process.Incoming, incoming: *bootstrap.Incoming, ticket: ChildReady, deadline: i64) anyerror!void {
    try validateChild(child, incoming);
    if (!std.meta.eql(ticket.identity, child.identity) or !incoming.stage_attempted or
        incoming.release_confirmed or incoming.staged_count != incoming.rows.len)
        return error.InvalidReleaseState;
    try receiveDecision(&child.endpoint, ticket, deadline);
    try sendCommitAck(&child.endpoint, ticket, deadline);
    try waitForPredecessorExit(child.parent_process, child.parent_pid, null);
    try incoming.releaseAfterWitness();
}

/// A staged candidate must fail through process exit, not ordinary main/server
/// defers: server cleanup may call shutdown on shared TCP endpoints. Windows
/// closes all imported duplicate handles when this process exits.
pub fn candidateAbortNow() noreturn {
    if (comptime builtin.os.tag == .windows) ExitProcess(125);
    @panic("Windows Helix candidate abort requested on another platform");
}

test "Windows Helix READY challenge clears final ACK alternation and authenticates decision" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 33, .upgrade_id = @splat(7) };
    var parent = pair.takeParent(identity, @splat(9));
    defer parent.deinit();
    var child = pair.takeChild(identity, @splat(9));
    defer child.deinit();
    const deadline = platform.monotonicMillis() + 3000;
    try parent.send(.descriptors, "last", deadline);
    var last = try child.receive(deadline);
    last.deinit();
    try child.send(.ack, "last", deadline);
    var ack = try parent.receive(deadline);
    ack.deinit();
    try std.testing.expect(child.awaiting_response);
    const Runner = struct {
        endpoint: *control.Endpoint,
        ticket: ?ChildReady = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            var request = self.endpoint.receive(platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
            defer request.deinit();
            const ticket = parseChallenge(&request, self.endpoint.identity) catch |err| {
                self.failure = err;
                return;
            };
            const answer = body(.response, ticket);
            self.endpoint.send(.ready, &answer, platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
            self.ticket = ticket;
        }
    };
    var runner = Runner{ .endpoint = &child };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const parent_ticket = challenge(&parent, identity, @splat(3), 0, deadline);
    thread.join();
    const ticket = try parent_ticket;
    if (runner.failure) |err| return err;
    try std.testing.expect(runner.ticket != null);
    try std.testing.expectEqual(ticket.nonce, runner.ticket.?.nonce);
    try std.testing.expectEqual(@as(bool, false), parent.awaiting_response);
    try std.testing.expectEqual(@as(bool, true), child.awaiting_response);
    try sendDecision(&parent, .commit, ticket, deadline);
    try receiveDecision(&child, runner.ticket.?, deadline);
    try sendCommitAck(&child, runner.ticket.?, deadline);
    try awaitCommitAck(&parent, ticket, deadline);
}

test "Windows Helix READY digest binds zero-state and listener-only manifests" {
    const none = try sourceDigest("zero state", &.{});
    const listener = try sourceDigest("zero state", &.{.{ .canonical = 7, .socket = 12, .role = .plain_listener, .family = 4 }});
    try std.testing.expect(!std.mem.eql(u8, &none, &listener));
    const changed = try sourceDigest("different", &.{});
    try std.testing.expect(!std.mem.eql(u8, &none, &changed));
}

test "Windows Helix READY digest binds exact WAL custody and candidate PID" {
    const no_wal = try sourceDigestWithWal("capsules", &.{}, null, 17);
    const descriptor = store.WindowsWalDescriptor{
        .handle = 91,
        .destination_pid = 17,
        .witness = .{
            .file = .{ .volume_serial = 3, .file_id = @splat(4) },
            .parent_directory = .{ .volume_serial = 5, .file_id = @splat(6) },
            .name_digest = @splat(7),
            .length = 123,
        },
    };
    const with_wal = try sourceDigestWithWal("capsules", &.{}, &descriptor, 17);
    try std.testing.expect(!std.mem.eql(u8, &no_wal, &with_wal));
    var altered = descriptor;
    altered.witness.length += 1;
    const changed_length = try sourceDigestWithWal("capsules", &.{}, &altered, 17);
    try std.testing.expect(!std.mem.eql(u8, &with_wal, &changed_length));
    altered = descriptor;
    altered.handle += 1;
    const changed_handle = try sourceDigestWithWal("capsules", &.{}, &altered, 17);
    try std.testing.expect(!std.mem.eql(u8, &with_wal, &changed_handle));
    try std.testing.expectError(error.InvalidFrame, sourceDigestWithWal("capsules", &.{}, &descriptor, 18));
    const config_bound = try sourceDigestWithWalAndConfig("capsules", &.{}, &descriptor, 17, @splat(8));
    try std.testing.expect(!std.mem.eql(u8, &with_wal, &config_bound));
}

test "Windows Helix READY mismatch sends authenticated ABORT before staging" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 35, .upgrade_id = @splat(9) };
    var parent = pair.takeParent(identity, @splat(6));
    defer parent.deinit();
    var child = pair.takeChild(identity, @splat(6));
    defer child.deinit();
    const plaintext = try allocator.dupe(u8, "unchanged");
    const rows = try allocator.alloc(bootstrap.ReceivedRow, 0);
    var incoming = bootstrap.Incoming{ .allocator = allocator, .identity = identity, .plaintext = plaintext, .rows = rows };
    defer incoming.deinit();
    const ValidatorImpl = struct {
        fn run(_: ?*anyopaque, _: *bootstrap.Incoming) anyerror!void {
            return error.ValidatorMustNotRun;
        }
    };
    const Runner = struct {
        endpoint: *control.Endpoint,
        incoming: *bootstrap.Incoming,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            _ = answerChallenge(self.endpoint, self.incoming, .{ .context = null, .run = ValidatorImpl.run }, platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
            self.failure = error.UnexpectedReady;
        }
    };
    var runner = Runner{ .endpoint = &child, .incoming = &incoming };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const result = challenge(&parent, identity, @splat(0), 0, platform.monotonicMillis() + 3000);
    thread.join();
    try std.testing.expectError(error.Aborted, result);
    try std.testing.expectEqual(error.InvalidReady, runner.failure orelse return error.MissingRefusal);
    try std.testing.expect(!incoming.stage_attempted);
}

fn spawnExitedTestProcess(allocator: std.mem.Allocator) !TestProcessInformation {
    var system_directory: [300]u16 = undefined;
    const length: usize = GetSystemDirectoryW(&system_directory, system_directory.len);
    if (length == 0 or length >= system_directory.len) return error.InvalidCandidate;
    const directory = try std.unicode.wtf16LeToWtf8Alloc(allocator, system_directory[0..length]);
    defer allocator.free(directory);
    const executable = try std.fmt.allocPrint(allocator, "{s}\\cmd.exe", .{directory});
    defer allocator.free(executable);
    const application = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, executable);
    defer allocator.free(application);
    const command = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, "cmd.exe /c exit 0");
    defer allocator.free(command);
    var startup = std.mem.zeroes(std.os.windows.STARTUPINFOW);
    startup.cb = @sizeOf(std.os.windows.STARTUPINFOW);
    var information: TestProcessInformation = undefined;
    if (CreateProcessW(application.ptr, command.ptr, null, null, 0, 0x0800_0000, null, null, &startup, &information) == 0)
        return error.InvalidCandidate;
    _ = CloseHandle(information.thread);
    return information;
}

test "Windows Helix zero-state child commits only after authenticated READY and process exit witness" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const witness = try spawnExitedTestProcess(allocator);
    var pair = try control.Pair.init();
    defer pair.deinit();
    const identity: control.Identity = .{ .generation = 34, .upgrade_id = @splat(8) };
    var parent = pair.takeParent(identity, @splat(5));
    defer parent.deinit();
    var child = process.Incoming{
        .endpoint = pair.takeChild(identity, @splat(5)),
        .parent_process = witness.process,
        .parent_pid = witness.pid,
        .identity = identity,
    };
    defer child.deinit();
    const plaintext = try allocator.dupe(u8, "empty strict state");
    const rows = try allocator.alloc(bootstrap.ReceivedRow, 0);
    var incoming = bootstrap.Incoming{ .allocator = allocator, .identity = identity, .plaintext = plaintext, .rows = rows };
    defer incoming.deinit();
    const deadline = platform.monotonicMillis() + 3000;
    try parent.send(.descriptors, "final", deadline);
    var final = try child.endpoint.receive(deadline);
    final.deinit();
    try child.endpoint.send(.ack, "final", deadline);
    var ack = try parent.receive(deadline);
    ack.deinit();
    const ValidatorImpl = struct {
        fn run(_: ?*anyopaque, transfer: *bootstrap.Incoming) anyerror!void {
            try std.testing.expectEqualStrings("empty strict state", transfer.plaintext);
            try std.testing.expectEqual(@as(usize, 0), transfer.rows.len);
        }
    };
    const Runner = struct {
        child: *process.Incoming,
        incoming: *bootstrap.Incoming,
        ticket: ?ChildReady = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.ticket = childAnswerReady(self.child, self.incoming, .{ .context = null, .run = ValidatorImpl.run }, platform.monotonicMillis() + 3000) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var runner = Runner{ .child = &child, .incoming = &incoming };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    const digest = try sourceDigest(incoming.plaintext, &.{});
    const ready = challenge(&parent, identity, digest, 0, deadline);
    thread.join();
    const ticket = try ready;
    if (runner.failure) |err| return err;
    try std.testing.expect(incoming.stage_attempted);
    try std.testing.expect(!incoming.release_confirmed);
    try sendDecision(&parent, .commit, ticket, deadline);
    try childAwaitCommit(&child, &incoming, runner.ticket orelse return error.InvalidReady, deadline);
    try awaitCommitAck(&parent, ticket, deadline);
    try std.testing.expect(incoming.release_confirmed);
    try std.testing.expectError(error.InvalidReleaseState, incoming.releaseAfterWitness());
    try std.testing.expectError(error.InvalidCandidate, waitForPredecessorExit(witness.process, witness.pid + 1, deadline));
}

test "Windows READY digest binds the exact webhook frame after provider record consumption" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const webhook_http = @import("../webhook_http.zig");
    const webhook_store = @import("../webhook.zig");
    const Sink = struct {
        fn submit(_: *anyopaque, _: *const webhook_store.PendingPost) bool {
            return false;
        }
    };
    var marker: u8 = 0;
    const sink = webhook_store.PostSink{ .ctx = &marker, .submit = Sink.submit };
    var bindings = webhook_store.WebhookStore.init();
    var source = try webhook_http.WebhookServer.init(&bindings, sink, 0, .{});
    defer source.shutdown();
    try source.spawn();
    source.pause();
    const carry = try source.captureQuiescedAfterJoin();
    const pid = GetCurrentProcessId();
    var prepared = try webhook_mod.prepareSource(.{ .owner = &source, .carry = &carry }, GetCurrentProcess(), pid);
    defer prepared.deinit();
    const source_proof: [32]u8 = @splat(0x69);
    const expected = try sourceDigestWithWalConfigMetricsAndWebhook("fixed point", &.{}, null, pid, source_proof, metrics_mod.absentFrame(), prepared.body);
    const absent = try sourceDigestWithWalConfigMetricsAndWebhook("fixed point", &.{}, null, pid, source_proof, metrics_mod.absentFrame(), webhook_mod.absentFrame());
    try std.testing.expect(!std.mem.eql(u8, &expected, &absent));
    var received = (try webhook_mod.receive(&prepared.body, pid)) orelse return error.InvalidReady;
    defer received.deinit();
    var imported = try webhook_http.WebhookServer.initTransferred(&bindings, sink, &received.transfer, &received.carry, .{});
    defer imported.shutdown();
    try std.testing.expect(received.transfer.consumed);
    try std.testing.expectEqual(expected, try sourceDigestWithWalConfigMetricsAndWebhook("fixed point", &.{}, null, pid, source_proof, metrics_mod.absentFrame(), prepared.body));
}
