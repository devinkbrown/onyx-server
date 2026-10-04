// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native service leaf. Protected root namespace + actual Unix descriptor
//! custody authenticate the lineage; PID text and socket-path inode guesses do
//! not. No production ready/stop publisher exists until the main/Server bridge.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const runtime = @import("os_runtime.zig");
const lease_os = @import("mesh_presence_lease.zig");
const snapshot = @import("helix/native_service_snapshot.zig");
const managed = @import("native_service_helper.zig");
const rwlock = @import("../substrate/rwlock.zig");
const platform = @import("../substrate/platform.zig");
const supported = builtin.os.tag == .linux or builtin.os.tag == .openbsd;

pub const namespace_path = "/var/run/onyx_server";
pub const endpoint_name = "control.sock";
pub const lease_name = "lifetime.lease";
pub const service_identity: [16]u8 = "onyx_server\x00\x00\x00\x00\x00".*;
pub const version: u16 = 1;
pub const reply_version: u16 = 2;
pub const max_packet = 4096;
pub const max_path = 512;
pub const Id = [16]u8;
pub const Digest = [32]u8;
pub const Error = error{ Unsupported, InvalidWire, InvalidState, InvalidIdentity, TooLarge, NotRoot, WrongPeer, BadDescriptor, Namespace, Busy, WouldBlock, CounterExhausted, Stale, Conflict, NotCurrent, StateChanged, SocketFailed, SendFailed, ReceiveFailed, RandomSourceFailed } || std.mem.Allocator.Error;

fn isZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

pub const Path = struct {
    data: [max_path]u8 = @splat(0),
    len: u16 = 0,
    pub fn init(text: []const u8) Error!Path {
        if (text.len == 0 or text.len > max_path or text[0] != '/') return error.InvalidIdentity;
        for (text) |byte| if (byte == 0 or byte < 32 or byte == 127) return error.InvalidIdentity;
        if (text.len > 1) {
            var it = std.mem.splitScalar(u8, text[1..], '/');
            while (it.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidIdentity;
        }
        var result: Path = .{ .len = @intCast(text.len) };
        @memcpy(result.data[0..text.len], text);
        return result;
    }
    pub fn bytes(self: *const Path) []const u8 {
        return self.data[0..self.len];
    }
    pub fn validate(self: *const Path) Error!void {
        if (self.len > max_path) return error.InvalidIdentity;
        _ = try init(self.bytes());
        if (!isZero(self.data[self.len..])) return error.InvalidIdentity;
    }
};

pub const FileIdentity = struct { device: u64, inode: u64 };
pub const Context = struct {
    incarnation: Id,
    executable: Path,
    config: Path,
    cwd: Path,
    endpoint: Path,
    uid: u32,
    gid: u32,
    rtable: u32,
    policy_version: u32,
    managed_spec: managed.ServiceSpec,
    managed_observation: managed.Observation,
    config_commitment: Digest,
    // Exact configuredListenerSet order: IRC,TLS,WS,WT,S2S,media,native-media.
    listener_ports: [7]u16,
    listener_canonical: i32,
    lease_canonical: i32,
    listener_identity: FileIdentity,
    // The FS pathname identity is independently observed, NEVER socket fstat.
    endpoint_identity: FileIdentity,
    lease_identity: FileIdentity,

    pub fn validate(self: *const Context) Error!void {
        if (isZero(&self.incarnation) or isZero(&self.config_commitment) or self.policy_version != 2 or self.rtable > 255 or self.uid == 0 or self.gid == 0) return error.InvalidIdentity;
        try self.executable.validate();
        try self.config.validate();
        try self.cwd.validate();
        try self.endpoint.validate();
        // A snapshot retains the root-approved launch policy AND the actual
        // daemon context, including the sole permitted NOFILE normalization.
        // These are data joins; they do not grant readiness or OS custody.
        const spec = &self.managed_spec;
        if (!std.meta.eql(self.executable, spec.executable) or !std.meta.eql(self.config, spec.config) or !std.meta.eql(self.cwd, spec.cwd) or self.uid != spec.uid or self.gid != spec.gid or self.rtable != spec.rtable) return error.InvalidIdentity;
        managed.validateManagedObservation(spec, &self.managed_observation, .daemon) catch return error.InvalidIdentity;
        if (!std.mem.eql(u8, std.fs.path.basename(self.endpoint.bytes()), endpoint_name)) return error.InvalidIdentity;
        if (self.listener_canonical < 3 or self.lease_canonical < 3 or self.listener_canonical == self.lease_canonical) return error.BadDescriptor;
        for ([_]FileIdentity{ self.listener_identity, self.endpoint_identity, self.lease_identity }) |id| if (id.inode == 0) return error.InvalidIdentity;
    }
    /// Observe the executed process before installing inherited service state.
    /// A past observation alone cannot authorize a different successor context.
    pub fn validateExecutedContext(self: *const Context, allocator: std.mem.Allocator, io: std.Io) Error!void {
        try self.validate();
        const actual = managed.observeManagedContext(allocator, io, &self.managed_spec, .daemon) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidIdentity;
        if (!std.meta.eql(actual, self.managed_observation)) return error.InvalidIdentity;
    }
};
pub const Phase = enum(u8) { starting = 1, current, quiesced, candidate, stopping };
pub const Verb = enum(u8) { query = 1, upgrade, stop };
pub const Result = enum(u8) { none = 0, accepted, succeeded, refused, stopped };
pub const Request = struct {
    verb: Verb,
    incarnation: Id,
    generation: u64,
    serial: u64,
    nonce: Id,
    candidate_config: Digest,
    pub const wire_len = 92;

    pub fn validate(self: Request) Error!void {
        if (isZero(&self.nonce)) return error.InvalidWire;
        if (self.verb == .query) {
            if (self.serial != 0 or self.generation != 0 or !isZero(&self.candidate_config)) return error.InvalidWire;
        } else {
            if (isZero(&self.incarnation) or self.serial == 0) return error.InvalidWire;
            if ((self.verb == .upgrade) == isZero(&self.candidate_config)) return error.InvalidWire;
        }
    }
    pub fn encode(self: Request) Error![wire_len]u8 {
        try self.validate();
        var wire: [wire_len]u8 = @splat(0);
        @memcpy(wire[0..4], "NSRQ");
        std.mem.writeInt(u16, wire[4..6], version, .little);
        wire[6] = @intFromEnum(self.verb);
        std.mem.writeInt(u32, wire[8..12], wire_len, .little);
        @memcpy(wire[12..28], &self.incarnation);
        std.mem.writeInt(u64, wire[28..36], self.generation, .little);
        std.mem.writeInt(u64, wire[36..44], self.serial, .little);
        @memcpy(wire[44..60], &self.nonce);
        @memcpy(wire[60..92], &self.candidate_config);
        return wire;
    }
    pub fn decode(wire: []const u8) Error!Request {
        if (wire.len != wire_len or !std.mem.eql(u8, wire[0..4], "NSRQ") or std.mem.readInt(u16, wire[4..6], .little) != version or wire[7] != 0 or std.mem.readInt(u32, wire[8..12], .little) != wire_len) return error.InvalidWire;
        const request: Request = .{
            .verb = std.enums.fromInt(Verb, wire[6]) orelse return error.InvalidWire,
            .incarnation = wire[12..28].*,
            .generation = std.mem.readInt(u64, wire[28..36], .little),
            .serial = std.mem.readInt(u64, wire[36..44], .little),
            .nonce = wire[44..60].*,
            .candidate_config = wire[60..92].*,
        };
        try request.validate();
        return request;
    }
};

/// Receipt for the exact already completed stop, not another mutation. Root
/// credentials on the held endpoint authorize admission; this public data
/// alone cannot detach a graph or release its lifetime lease.
pub const StopAck = struct {
    request: Request,
    managed_spec_commitment: Digest,
    pub const wire_len = 132;

    pub fn validate(self: StopAck) Error!void {
        try self.request.validate();
        if (self.request.verb != .stop or isZero(&self.managed_spec_commitment)) return error.InvalidWire;
    }

    pub fn encode(self: StopAck) Error![wire_len]u8 {
        try self.validate();
        var wire: [wire_len]u8 = @splat(0);
        @memcpy(wire[0..4], "NSAK");
        std.mem.writeInt(u16, wire[4..6], 1, .little);
        const request_wire = try self.request.encode();
        @memcpy(wire[8..100], &request_wire);
        @memcpy(wire[100..132], &self.managed_spec_commitment);
        return wire;
    }

    pub fn decode(wire: []const u8) Error!StopAck {
        if (wire.len != wire_len or !std.mem.eql(u8, wire[0..4], "NSAK") or
            std.mem.readInt(u16, wire[4..6], .little) != 1 or !isZero(wire[6..8])) return error.InvalidWire;
        const ack: StopAck = .{
            .request = try Request.decode(wire[8..100]),
            .managed_spec_commitment = wire[100..132].*,
        };
        try ack.validate();
        return ack;
    }
};
pub const Operation = struct { request: Request, result: Result };
pub const State = struct {
    context: Context,
    generation: u64 = 0,
    phase: Phase = .starting,
    upgrade_id: Id = @splat(0),
    last: ?Operation = null,

    pub fn validate(self: *const State) Error!void {
        try self.context.validate();
        const transferring = self.phase == .quiesced or self.phase == .candidate;
        if (transferring == isZero(&self.upgrade_id)) return error.InvalidState;
        if (self.phase == .starting and (self.generation != 0 or self.last != null)) return error.InvalidState;
        try validateOperation(self.context.incarnation, self.generation, self.phase, self.last);
        if (self.last) |op| if (op.result == .succeeded and !std.mem.eql(u8, &self.context.config_commitment, &op.request.candidate_config)) return error.InvalidState;
    }
};

fn validateOperation(incarnation: Id, generation: u64, phase: Phase, last: ?Operation) Error!void {
    if (isZero(&incarnation)) return error.InvalidState;
    const op = last orelse {
        if (generation != 0 or (phase != .starting and phase != .current)) return error.InvalidState;
        return;
    };
    try op.request.validate();
    if (phase == .starting or op.request.verb == .query or !std.mem.eql(u8, &op.request.incarnation, &incarnation)) return error.InvalidState;
    switch (op.result) {
        .none => return error.InvalidState,
        .accepted => {
            if (generation != op.request.generation) return error.InvalidState;
            if (op.request.verb == .stop) {
                if (phase != .stopping) return error.InvalidState;
            } else if (phase != .current and phase != .quiesced and phase != .candidate) return error.InvalidState;
        },
        .refused => if (op.request.verb != .upgrade or phase != .current or generation != op.request.generation) return error.InvalidState,
        .succeeded => if (op.request.verb != .upgrade or phase != .current or op.request.generation == std.math.maxInt(u64) or generation != op.request.generation + 1) return error.InvalidState,
        .stopped => if (op.request.verb != .stop or phase != .stopping or generation != op.request.generation) return error.InvalidState,
    }
}

pub const Reply = struct {
    incarnation: Id,
    generation: u64,
    phase: Phase,
    next_serial: u64, // Zero means serial exhausted, never a wrapping next op.
    last: ?Operation,
    managed_spec_commitment: Digest,
    pub const wire_len = 172;
    pub fn validate(self: Reply) Error!void {
        if (isZero(&self.managed_spec_commitment)) return error.InvalidWire;
        validateOperation(self.incarnation, self.generation, self.phase, self.last) catch return error.InvalidWire;
        const serial = if (self.last) |last| last.request.serial else 0;
        const next = if (serial == std.math.maxInt(u64)) 0 else serial + 1;
        if (self.next_serial != next) return error.InvalidWire;
    }
    pub fn encode(self: Reply) Error![wire_len]u8 {
        try self.validate();
        var wire: [wire_len]u8 = @splat(0);
        @memcpy(wire[0..4], "NSRP");
        std.mem.writeInt(u16, wire[4..6], reply_version, .little);
        wire[6] = @intFromEnum(self.phase);
        @memcpy(wire[8..24], &self.incarnation);
        std.mem.writeInt(u64, wire[24..32], self.generation, .little);
        std.mem.writeInt(u64, wire[32..40], self.next_serial, .little);
        if (self.last) |last| {
            if (last.result == .none or last.request.verb == .query) return error.InvalidWire;
            wire[40] = @intFromEnum(last.result);
            const req = try last.request.encode();
            @memcpy(wire[48..140], &req);
        }
        @memcpy(wire[140..172], &self.managed_spec_commitment);
        return wire;
    }
    pub fn decode(wire: []const u8) Error!Reply {
        if (wire.len != wire_len or !std.mem.eql(u8, wire[0..4], "NSRP") or std.mem.readInt(u16, wire[4..6], .little) != reply_version or wire[7] != 0 or !isZero(wire[41..48])) return error.InvalidWire;
        const result = std.enums.fromInt(Result, wire[40]) orelse return error.InvalidWire;
        const reply: Reply = .{ .incarnation = wire[8..24].*, .generation = std.mem.readInt(u64, wire[24..32], .little), .phase = std.enums.fromInt(Phase, wire[6]) orelse return error.InvalidWire, .next_serial = std.mem.readInt(u64, wire[32..40], .little), .last = if (result == .none) null else .{ .request = try Request.decode(wire[48..140]), .result = result }, .managed_spec_commitment = wire[140..172].* };
        if (result == .none and !isZero(wire[48..140])) return error.InvalidWire;
        // Re-encoding also rejects a query disguised as an accepted mutation.
        _ = try reply.encode();
        return reply;
    }
};

const Plan = struct { issuance: u64, bytes: []u8, allocator: std.mem.Allocator, candidate: State, committed: bool = false };
const Backing = struct {
    mutex: rwlock.RwLock = .{},
    allocator: std.mem.Allocator,
    state: State,
    managed_spec_commitment: Digest,
    revision: u64 = 1,
    plan: ?Plan = null,
    // Only the closed runtime cleanup bridge may publish this in production.
    // Until that bridge exists, production starting controllers cannot ACK.
    graph_detached: bool = false,
    terminal_acknowledged: bool = false,
};
fn backing(controller: *Controller) *Backing {
    return @ptrCast(@alignCast(controller));
}

/// Opaque, source-owned backing. No public struct constructor or state field
/// can manufacture readiness or a stopped result. N2 must add real adapters.
pub const Controller = opaque {
    pub fn initStarting(allocator: std.mem.Allocator, context: Context) Error!*Controller {
        try context.validate();
        const commitment = managed.serviceSpecDigest(&context.managed_spec) catch return error.InvalidIdentity;
        const owned = try allocator.create(Backing);
        owned.* = .{ .allocator = allocator, .state = .{ .context = context }, .managed_spec_commitment = commitment };
        return @ptrCast(owned);
    }
    /// Tickets and borrowed snapshot bytes must not outlive this owner.
    pub fn deinit(self: *Controller) void {
        const owned = backing(self);
        if (owned.plan) |plan| plan.allocator.free(plan.bytes);
        owned.allocator.destroy(owned);
    }
    pub fn inspect(self: *const Controller) State {
        const owned = backing(@constCast(self));
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        return owned.state;
    }
    pub fn reply(self: *const Controller) Reply {
        const owned = backing(@constCast(self));
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        const state = &owned.state;
        const serial = if (state.last) |last| last.request.serial else 0;
        return .{ .incarnation = state.context.incarnation, .generation = state.generation, .phase = state.phase, .next_serial = if (serial == std.math.maxInt(u64)) 0 else serial + 1, .last = state.last, .managed_spec_commitment = owned.managed_spec_commitment };
    }
    pub fn receive(self: *Controller, fd: i32) Error!Admission {
        var message = try Message.receiveRoot(fd);
        defer message.deinit();
        if (message.fd_count != 0) return error.InvalidWire;
        const bytes = message.bytes();
        if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "NSAK"))
            return admitStopAck(backing(self), try StopAck.decode(bytes));
        return admit(backing(self), try Request.decode(message.bytes()));
    }
    pub const Admission = enum { query, execute, duplicate, stop_ack };

    /// Main's outer control lifetime observes this after an exact root ACK.
    /// It is never a substitute for the source-owned graph cleanup predicate.
    pub fn terminalAcknowledged(self: *const Controller) bool {
        const owned = backing(@constCast(self));
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        return owned.terminal_acknowledged;
    }
    pub fn prepareHandoff(self: *Controller, allocator: std.mem.Allocator, upgrade_id: Id) Error!Handoff {
        const owned = backing(self);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        if (owned.plan != null or owned.state.phase != .current or owned.state.last == null or owned.state.last.?.request.verb != .upgrade or owned.state.last.?.result != .accepted) return error.InvalidState;
        if (isZero(&upgrade_id)) return error.InvalidIdentity;
        if (owned.revision >= std.math.maxInt(u64) - 1) return error.CounterExhausted;
        var candidate = owned.state;
        candidate.phase = .quiesced;
        candidate.upgrade_id = upgrade_id;
        const bytes = try snapshot.encode(allocator, &candidate);
        const issuance = owned.revision;
        owned.revision += 1;
        owned.plan = .{ .issuance = issuance, .allocator = allocator, .bytes = bytes, .candidate = candidate };
        return .{ .owner = self, .issuance = issuance };
    }
};

fn admitStopAck(owned: *Backing, ack: StopAck) Error!Controller.Admission {
    try ack.validate();
    owned.mutex.lockExclusive();
    defer owned.mutex.unlockExclusive();
    const last = owned.state.last orelse return error.InvalidState;
    if (owned.plan != null or !owned.graph_detached or owned.state.phase != .stopping or
        last.request.verb != .stop or last.result != .stopped) return error.InvalidState;
    if (!std.meta.eql(last.request, ack.request) or
        !std.mem.eql(u8, &owned.managed_spec_commitment, &ack.managed_spec_commitment)) return error.Conflict;
    // No revision/serial is spent, even at exhaustion. The exact stop identity
    // and reply remain available until main joins the outer control owner.
    owned.terminal_acknowledged = true;
    return .stop_ack;
}
fn admit(owned: *Backing, request: Request) Error!Controller.Admission {
    owned.mutex.lockExclusive();
    defer owned.mutex.unlockExclusive();
    try request.validate();
    if (!isZero(&request.incarnation) and !std.mem.eql(u8, &request.incarnation, &owned.state.context.incarnation)) return error.Stale;
    if (request.verb == .query) return .query;
    if (owned.state.last) |last| {
        if (request.serial == last.request.serial) {
            if (!std.meta.eql(request, last.request)) return error.Conflict;
            return .duplicate;
        }
        if (request.serial < last.request.serial) return error.Stale;
    }
    if (owned.plan != null or owned.state.phase != .current or (owned.state.last != null and owned.state.last.?.result == .accepted)) return error.Busy;
    const last_serial = if (owned.state.last) |last| last.request.serial else 0;
    if (last_serial == std.math.maxInt(u64) or owned.revision == std.math.maxInt(u64) or (request.verb == .upgrade and owned.state.generation == std.math.maxInt(u64))) return error.CounterExhausted;
    if (request.serial != last_serial + 1 or request.generation != owned.state.generation) return error.Stale;
    if (owned.state.last) |last| if (std.mem.eql(u8, &request.nonce, &last.request.nonce)) return error.Conflict;
    owned.state.last = .{ .request = request, .result = .accepted };
    if (request.verb == .stop) owned.state.phase = .stopping;
    owned.revision += 1;
    return .execute;
}
/// Copyable token references exactly one private plan; it never owns the bytes
/// independently. A forged issuance cannot supply a candidate state, and copied
/// abort/commit/deinit calls cannot free or publish a second time.
pub const Handoff = struct {
    owner: *Controller,
    issuance: u64,
    pub fn validate(self: Handoff) Error!void {
        const owned = backing(self.owner);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        const plan = owned.plan orelse return error.StateChanged;
        if (plan.issuance != self.issuance or plan.committed) return error.StateChanged;
    }
    pub fn bytes(self: Handoff) Error![]const u8 {
        const owned = backing(self.owner);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        const plan = owned.plan orelse return error.StateChanged;
        if (plan.issuance != self.issuance) return error.StateChanged;
        return plan.bytes;
    }
    /// No allocation or OS mutation. Invalid tokens refuse before publication.
    pub fn commit(self: Handoff) Error!void {
        const owned = backing(self.owner);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        const plan = owned.plan orelse return error.StateChanged;
        if (plan.issuance != self.issuance or plan.committed) return error.StateChanged;
        if (owned.revision == std.math.maxInt(u64)) return error.CounterExhausted;
        owned.state = owned.plan.?.candidate;
        owned.revision += 1;
        owned.plan.?.committed = true;
    }
    pub fn deinit(self: Handoff) void {
        const owned = backing(self.owner);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        const plan = owned.plan orelse return;
        if (plan.issuance != self.issuance) return;
        owned.plan = null;
        plan.allocator.free(plan.bytes);
    }
};

pub const Peer = struct { uid: u32, gid: u32, pid: i32 };
pub fn peerCredentials(fd: i32) Error!Peer {
    if (comptime !supported) return error.Unsupported;
    try checkConnected(fd);
    if (comptime builtin.os.tag == .openbsd) {
        // OpenBSD socket.h sockpeercred is uid,gid,pid; these are the binder /
        // connect-time credentials, NOT the accepting process's current UID.
        var cred: extern struct { uid: u32, gid: u32, pid: i32 } = undefined;
        try getOption(fd, posix.SO.PEERCRED, &cred);
        return .{ .uid = cred.uid, .gid = cred.gid, .pid = cred.pid };
    } else {
        var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
        try getOption(fd, posix.SO.PEERCRED, &cred);
        return .{ .uid = cred.uid, .gid = cred.gid, .pid = cred.pid };
    }
}
fn requireRootPeer(fd: i32) Error!void {
    if ((try peerCredentials(fd)).uid != 0) return error.WrongPeer;
}
fn getOption(fd: i32, option: u32, value: anytype) Error!void {
    if (comptime !supported) return error.Unsupported;
    var len: posix.socklen_t = @sizeOf(@TypeOf(value.*));
    if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, option, @ptrCast(value), &len)) != .SUCCESS or len != @sizeOf(@TypeOf(value.*))) return error.BadDescriptor;
}
fn checkConnected(fd: i32) Error!void {
    if (comptime !supported) return error.Unsupported;
    if (fd < 3 or (runtime.socketType(fd) catch return error.BadDescriptor) != posix.SOCK.SEQPACKET) return error.BadDescriptor;
    var address: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getpeername(fd, @ptrCast(&address), &len)) != .SUCCESS or address.family != posix.AF.UNIX) return error.BadDescriptor;
}

// Fixed stack custody: no allocation after recvmsg, and every received FD is
// closed on any framing, credential, descriptor-count, or CLOEXEC rejection.
const cmsg_header = std.mem.alignForward(usize, @sizeOf(sys.cmsghdr), @sizeOf(usize));
const cmsg_capacity = cmsg_header + 8 * @sizeOf(i32);
pub const Message = struct {
    payload: [max_packet]u8 = undefined,
    length: usize = 0,
    fds: [8]i32 = @splat(-1),
    fd_count: usize = 0,
    pub fn bytes(self: *const Message) []const u8 {
        return self.payload[0..self.length];
    }
    pub fn deinit(self: *Message) void {
        if (comptime supported) for (self.fds[0..self.fd_count]) |fd| runtime.close(fd);
        self.* = .{};
    }
    pub fn receiveRoot(fd: i32) Error!Message {
        try requireRootPeer(fd);
        return receivePacket(fd);
    }
    fn receivePacket(fd: i32) Error!Message {
        if (comptime !supported) return error.Unsupported;
        try checkConnected(fd);
        var message: Message = .{};
        errdefer message.deinit();
        var control: [cmsg_capacity]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
        var iov: posix.iovec = .{ .base = &message.payload, .len = message.payload.len };
        var header: sys.msghdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
        const count = while (true) {
            const rc = sys.recvmsg(fd, &header, posix.MSG.DONTWAIT);
            switch (posix.errno(rc)) {
                .SUCCESS => break @as(usize, @intCast(rc)),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                else => return error.ReceiveFailed,
            }
        };
        var offset: usize = 0;
        const end = @min(control.len, @as(usize, header.controllen));
        var malformed = false;
        while (offset + @sizeOf(sys.cmsghdr) <= end) {
            const cmsg: *const sys.cmsghdr = @ptrCast(@alignCast(control[offset..].ptr));
            const length: usize = cmsg.len;
            if (length < cmsg_header or length > end - offset) {
                malformed = true;
                break;
            }
            const data_len = length - cmsg_header;
            if (cmsg.level != posix.SOL.SOCKET or cmsg.type != sys.SCM.RIGHTS or data_len == 0 or data_len % 4 != 0) malformed = true;
            if (cmsg.level == posix.SOL.SOCKET and cmsg.type == sys.SCM.RIGHTS) {
                var index: usize = 0;
                while (index + 4 <= data_len) : (index += 4) {
                    const delivered = std.mem.bytesToValue(i32, control[offset + cmsg_header + index ..][0..4]);
                    if (message.fd_count == message.fds.len) {
                        runtime.close(delivered);
                        malformed = true;
                    } else {
                        message.fds[message.fd_count] = delivered;
                        message.fd_count += 1;
                    }
                }
            }
            offset += std.mem.alignForward(usize, length, @sizeOf(usize));
        }
        if (malformed or count == 0 or count > max_packet or (header.flags & (posix.MSG.TRUNC | posix.MSG.CTRUNC)) != 0) return error.InvalidWire;
        for (message.fds[0..message.fd_count]) |delivered| runtime.setCloexec(delivered, true) catch return error.BadDescriptor;
        message.length = count;
        return message;
    }
};
pub fn send(fd: i32, bytes: []const u8, descriptors: []const i32) Error!void {
    if (comptime !supported) return error.Unsupported;
    try checkConnected(fd);
    if (bytes.len == 0 or bytes.len > max_packet or descriptors.len > 2) return error.TooLarge;
    var control: [cmsg_capacity]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    if (descriptors.len != 0) {
        const header: *sys.cmsghdr = @ptrCast(&control);
        header.* = .{ .len = @intCast(cmsg_header + descriptors.len * 4), .level = posix.SOL.SOCKET, .type = sys.SCM.RIGHTS };
        @memcpy(control[cmsg_header..][0 .. descriptors.len * 4], std.mem.sliceAsBytes(descriptors));
    }
    var iov: posix.iovec_const = .{ .base = bytes.ptr, .len = bytes.len };
    const header: sys.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = if (descriptors.len == 0) null else &control, .controllen = if (descriptors.len == 0) 0 else @intCast(cmsg_header + std.mem.alignForward(usize, descriptors.len * 4, @sizeOf(usize))), .flags = 0 };
    while (true) {
        const rc = sys.sendmsg(fd, &header, posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT);
        switch (posix.errno(rc)) {
            .SUCCESS => if (@as(usize, @intCast(rc)) == bytes.len) return else return error.SendFailed,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }
}

const Stat = struct { identity: FileIdentity, mode: u32, uid: u32, gid: u32, nlink: u64 };
fn bits(value: anytype) u64 {
    return @intCast(@as(@Int(.unsigned, @bitSizeOf(@TypeOf(value))), @bitCast(value)));
}
fn statAt(fd: i32, name: ?[:0]const u8) Error!Stat {
    if (comptime !supported) return error.Unsupported;
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = std.mem.zeroes(linux.Statx);
        const flags: u32 = if (name == null) linux.AT.EMPTY_PATH else linux.AT.SYMLINK_NOFOLLOW;
        while (true) {
            switch (linux.errno(linux.statx(fd, if (name) |path| path.ptr else "", flags, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .NLINK = true, .INO = true }, &st))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.Namespace,
            }
        }
        if (!st.mask.TYPE or !st.mask.MODE or !st.mask.UID or !st.mask.GID or !st.mask.NLINK or !st.mask.INO) return error.Namespace;
        return .{ .identity = .{ .device = (@as(u64, st.dev_major) << 32) | st.dev_minor, .inode = st.ino }, .mode = st.mode, .uid = st.uid, .gid = st.gid, .nlink = st.nlink };
    } else {
        var st: posix.Stat = undefined;
        while (true) {
            const rc = if (name) |path| sys.fstatat(fd, path.ptr, &st, posix.AT.SYMLINK_NOFOLLOW) else sys.fstat(fd, &st);
            switch (posix.errno(rc)) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.Namespace,
            }
        }
        return .{ .identity = .{ .device = bits(st.dev), .inode = bits(st.ino) }, .mode = st.mode, .uid = st.uid, .gid = st.gid, .nlink = st.nlink };
    }
}
fn protectedDirectory(fd: i32) Error!void {
    const st = try statAt(fd, null);
    if ((st.mode & posix.S.IFMT) != posix.S.IFDIR or st.uid != 0 or (st.mode & 0o022) != 0) return error.Namespace;
}
fn directory(path: [:0]const u8, parent: i32) Error!i32 {
    if (comptime !supported) return error.Unsupported;
    const rc = sys.openat(parent, path.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(posix.mode_t, 0));
    if (posix.errno(rc) != .SUCCESS) return error.Namespace;
    return @intCast(rc);
}
fn pathZ(path: *const Path, buffer: *[max_path + 1]u8) [:0]const u8 {
    @memcpy(buffer[0..path.len], path.bytes());
    buffer[path.len] = 0;
    return buffer[0..path.len :0];
}

/// Namespace is an owned directory capability. Public production construction
/// is only the selected fixed root namespace; fixtures cannot add a fallback.
pub const RootNamespace = struct {
    fd: i32 = -1,
    path: Path,
    pub fn open() Error!RootNamespace {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        return openChecked(try Path.init(namespace_path));
    }
    fn openChecked(path: Path) Error!RootNamespace {
        if (comptime !supported) return error.Unsupported;
        // Walk without following ANY mutable ancestor symlink; never grant
        // arbitrary /var/run write permissions or assume the final node alone.
        var fd = try directory("/", posix.AT.FDCWD);
        errdefer runtime.close(fd);
        try protectedDirectory(fd);
        var it = std.mem.splitScalar(u8, path.bytes()[1..], '/');
        var part_buffer: [max_path + 1]u8 = undefined;
        while (it.next()) |part| {
            @memcpy(part_buffer[0..part.len], part);
            part_buffer[part.len] = 0;
            const next = try directory(part_buffer[0..part.len :0], fd);
            runtime.close(fd);
            fd = next;
            try protectedDirectory(fd);
        }
        return .{ .fd = fd, .path = path };
    }
    pub fn deinit(self: *RootNamespace) void {
        if (comptime supported) runtime.close(self.fd);
        self.fd = -1;
    }
    pub fn endpoint(self: *const RootNamespace) Error!Path {
        var buffer: [max_path]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ self.path.bytes(), endpoint_name }) catch return error.TooLarge;
        return Path.init(path);
    }
    fn acquireLease(self: *const RootNamespace, name: [:0]const u8) Error!Lease {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        try protectedDirectory(self.fd);
        // NONBLOCK prevents an attacker-substituted FIFO from hanging before
        // the type check. Never truncate/replace the stable lease file.
        const rc = sys.openat(self.fd, name.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(posix.mode_t, 0o600));
        if (posix.errno(rc) != .SUCCESS) return error.Namespace;
        const fd: i32 = @intCast(rc);
        errdefer runtime.close(fd);
        const st = try statAt(fd, null);
        if ((st.mode & posix.S.IFMT) != posix.S.IFREG or st.uid != 0 or (st.mode & 0o777) != 0o600 or st.nlink != 1 or !std.meta.eql(st.identity, (try statAt(self.fd, name)).identity)) return error.Namespace;
        lease_os.reaffirmExclusive(fd) catch |err| return if (err == error.WouldBlock) error.Busy else error.BadDescriptor;
        return .{ .fd = fd, .identity = st.identity };
    }
    pub fn acquireLifetime(self: *const RootNamespace) Error!Lease {
        return self.acquireLease(lease_name);
    }
    pub fn acquireMutation(self: *const RootNamespace) Error!Lease {
        return self.acquireLease("mutation.lock");
    }
    /// Explicit root-owned pathname identity is required. Held lease custody
    /// prevents another cooperating launcher, never unlock during this check.
    pub fn removeOwnedEndpoint(self: *const RootNamespace, lease: *const Lease, expected: FileIdentity) Error!void {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        try lease.validate(self, lease_name);
        const actual = try statAt(self.fd, endpoint_name);
        if (actual.uid != 0 or (actual.mode & posix.S.IFMT) != posix.S.IFSOCK or (actual.mode & 0o777) != 0o600 or !std.meta.eql(actual.identity, expected)) return error.Namespace;
        if (posix.errno(sys.unlinkat(self.fd, endpoint_name, 0)) != .SUCCESS) return error.Namespace;
    }
};
pub const Lease = struct {
    fd: i32 = -1,
    identity: FileIdentity,
    pub fn deinit(self: *Lease) void {
        if (comptime supported) runtime.close(self.fd);
        self.fd = -1;
    }
    pub fn validate(self: *const Lease, ns: *const RootNamespace, name: [:0]const u8) Error!void {
        if (comptime !supported) return error.Unsupported;
        const actual = try statAt(self.fd, null);
        if ((actual.mode & posix.S.IFMT) != posix.S.IFREG or actual.uid != 0 or (actual.mode & 0o777) != 0o600 or actual.nlink != 1 or !std.meta.eql(actual.identity, self.identity) or !std.meta.eql(actual.identity, (try statAt(ns.fd, name)).identity)) return error.BadDescriptor;
        lease_os.reaffirmExclusive(self.fd) catch |err| return if (err == error.WouldBlock) error.Busy else error.BadDescriptor;
    }
};

fn unixAddress(path: *const Path) Error!posix.sockaddr.un {
    if (comptime !supported) return error.Unsupported;
    var address: posix.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return error.TooLarge;
    @memcpy(address.path[0..path.len], path.bytes());
    if (comptime @hasField(posix.sockaddr.un, "len")) address.len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    return address;
}
fn addressLength(address: *const posix.sockaddr.un) posix.socklen_t {
    return @intCast(@offsetOf(posix.sockaddr.un, "path") + std.mem.indexOfScalar(u8, &address.path, 0).? + 1);
}
// Observe the shared open description; validation must never normalize an
// inherited predecessor's flags while deciding whether to accept its custody.
fn requireNonblocking(fd: i32) Error!void {
    if (comptime !supported) return error.Unsupported;
    while (true) {
        const rc = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const flags: posix.O = @bitCast(@as(u32, @intCast(rc)));
                if (!flags.NONBLOCK) return error.BadDescriptor;
                return;
            },
            .INTR => continue,
            else => return error.BadDescriptor,
        }
    }
}
pub fn inspectListener(fd: i32, path: *const Path) Error!FileIdentity {
    if (comptime !supported) return error.Unsupported;
    if (fd < 3 or (runtime.socketType(fd) catch return error.BadDescriptor) != posix.SOCK.SEQPACKET) return error.BadDescriptor;
    try requireNonblocking(fd);
    var listening: u32 = 0;
    try getOption(fd, posix.SO.ACCEPTCONN, &listening);
    // SO_ACCEPTCONN is a boolean: OpenBSD returns its option bit (2),
    // while Linux returns 1. Only zero denotes a non-listening socket.
    if (listening == 0) return error.BadDescriptor;
    var address: posix.sockaddr.un = .{ .path = @splat(0) };
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    if (posix.errno(sys.getsockname(fd, @ptrCast(&address), &length)) != .SUCCESS or address.family != posix.AF.UNIX or length > @sizeOf(@TypeOf(address)) or length <= @offsetOf(posix.sockaddr.un, "path")) return error.BadDescriptor;
    const expected = try unixAddress(path);
    // OpenBSD names a Unix socket with the complete sockaddr_un, including
    // sun_len and zero padding; Linux reports the minimal pathname extent.
    const expected_length: posix.socklen_t = if (builtin.os.tag == .openbsd) @sizeOf(posix.sockaddr.un) else addressLength(&expected);
    if (length != expected_length or !std.mem.eql(u8, &address.path, &expected.path)) return error.BadDescriptor;
    if (comptime builtin.os.tag == .openbsd) {
        if (address.len != length) return error.BadDescriptor;
    }
    const st = try statAt(fd, null);
    if ((st.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.BadDescriptor;
    return st.identity;
}
fn removeCreatedEndpoint(ns: *const RootNamespace, expected: FileIdentity) void {
    const actual = statAt(ns.fd, endpoint_name) catch return;
    if (actual.uid == 0 and (actual.mode & posix.S.IFMT) == posix.S.IFSOCK and std.meta.eql(actual.identity, expected)) _ = sys.unlinkat(ns.fd, endpoint_name, 0);
}
pub const Launch = struct { executable: Path, config: Path, cwd: Path, uid: u32, gid: u32, rtable: u32, managed_spec: managed.ServiceSpec, managed_observation: managed.Observation, config_commitment: Digest, listener_ports: [7]u16 };
pub const Bootstrap = struct {
    ns: RootNamespace,
    lease: Lease,
    listener: i32 = -1,
    state: State,
    /// Acquire without stale-unlink guesswork. A stale node requires a separately
    /// proven root-owned pathname receipt and removeOwnedEndpoint first.
    pub fn acquire(launch: Launch) Error!Bootstrap {
        var ns = try RootNamespace.open();
        errdefer ns.deinit();
        var lease = try ns.acquireLifetime();
        errdefer lease.deinit();
        return acquireFromLease(&ns, &lease, launch);
    }
    /// Consume the already-held root namespace and lifetime lease only after
    /// the complete starting endpoint has been prepared. The helper keeps this
    /// same lease across stale-node cleanup and binding; no reopen or unlock
    /// creates a second launcher window. Failure leaves both owned FDs intact.
    pub fn acquireFromLease(ns: *RootNamespace, lease: *Lease, launch: Launch) Error!Bootstrap {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        try ns.path.validate();
        if (!std.mem.eql(u8, ns.path.bytes(), namespace_path)) return error.Namespace;
        return acquireCheckedFromLease(ns, lease, launch);
    }
    fn acquireCheckedFromLease(ns: *RootNamespace, lease: *Lease, launch: Launch) Error!Bootstrap {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        try ns.path.validate();
        if (ns.fd < 3 or lease.fd < 3 or ns.fd == lease.fd) return error.BadDescriptor;
        // A public struct value is not namespace authority. Walk the protected
        // path again and join its exact directory identity to the held FD.
        var observed = try RootNamespace.openChecked(ns.path);
        defer observed.deinit();
        try protectedDirectory(ns.fd);
        if (!std.meta.eql((try statAt(observed.fd, null)).identity, (try statAt(ns.fd, null)).identity)) return error.Namespace;
        try lease.validate(ns, lease_name);
        const result = try bindOwned(ns.*, lease.*, launch);
        ns.fd = -1;
        lease.fd = -1;
        return result;
    }
    fn bindOwned(ns: RootNamespace, lease: Lease, launch: Launch) Error!Bootstrap {
        if (comptime !supported) return error.Unsupported;
        if (sys.geteuid() != 0) return error.NotRoot;
        const endpoint = try ns.endpoint();
        var address = try unixAddress(&endpoint);
        const rc = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        const listener: i32 = @intCast(rc);
        errdefer runtime.close(listener);
        runtime.setNonblocking(listener) catch return error.BadDescriptor;
        if (posix.errno(sys.bind(listener, @ptrCast(&address), addressLength(&address))) != .SUCCESS) return error.Namespace;
        // Root namespace prevents client access during mode tightening. The
        // selected constructor does not guess ownership if bind itself failed.
        var buffer: [max_path + 1]u8 = undefined;
        const node = try statAt(ns.fd, endpoint_name);
        errdefer removeCreatedEndpoint(&ns, node.identity);
        if (posix.errno(sys.chmod(pathZ(&endpoint, &buffer).ptr, @as(posix.mode_t, 0o600))) != .SUCCESS) return error.Namespace;
        if (posix.errno(sys.listen(listener, 8)) != .SUCCESS) return error.SocketFailed;
        var incarnation: Id = undefined;
        try platform.fillOsEntropy(&incarnation);
        if (isZero(&incarnation)) return error.InvalidIdentity;
        const state: State = .{ .context = .{
            .incarnation = incarnation,
            .executable = launch.executable,
            .config = launch.config,
            .cwd = launch.cwd,
            .endpoint = endpoint,
            .uid = launch.uid,
            .gid = launch.gid,
            .rtable = launch.rtable,
            .policy_version = 2,
            .managed_spec = launch.managed_spec,
            .managed_observation = launch.managed_observation,
            .config_commitment = launch.config_commitment,
            .listener_ports = launch.listener_ports,
            .listener_canonical = listener,
            .lease_canonical = lease.fd,
            .listener_identity = try inspectListener(listener, &endpoint),
            .endpoint_identity = node.identity,
            .lease_identity = lease.identity,
        } };
        try state.validate();
        return .{ .ns = ns, .lease = lease, .listener = listener, .state = state };
    }
    pub fn deinit(self: *Bootstrap) void {
        if (comptime supported) runtime.close(self.listener);
        self.listener = -1;
        self.lease.deinit();
        self.ns.deinit();
        // Never unlink on a descriptor close; a successor may own duplicates.
    }
    pub fn sendTo(self: *const Bootstrap, allocator: std.mem.Allocator, channel: i32) Error!void {
        try requireRootPeer(channel);
        const bytes = try snapshot.encode(allocator, &self.state);
        defer allocator.free(bytes);
        try send(channel, bytes, &.{ self.listener, self.lease.fd });
    }
};

/// Received descriptors have independent close-only custody. The channel is
/// borrowed, never consumed/closed here. No public ready-state construction.
pub const Incoming = struct {
    listener: i32 = -1,
    lease: Lease,
    state: State,
    pub fn receive(channel: i32) Error!Incoming {
        var message = try Message.receiveRoot(channel);
        defer message.deinit();
        if (message.fd_count != 2) return error.InvalidWire;
        const state = try snapshot.decode(message.bytes());
        if (state.phase != .starting) return error.InvalidState;
        try validateDescriptors(message.fds[0], message.fds[1], &state.context);
        const result: Incoming = .{ .listener = message.fds[0], .lease = .{ .fd = message.fds[1], .identity = state.context.lease_identity }, .state = state };
        message.fds[0] = -1;
        message.fds[1] = -1;
        return result;
    }
    pub fn deinit(self: *Incoming) void {
        if (comptime supported) runtime.close(self.listener);
        self.listener = -1;
        self.lease.deinit();
    }
};
pub fn validateDescriptors(listener: i32, lease_fd: i32, context: *const Context) Error!void {
    if (comptime !supported) return error.Unsupported;
    if (listener < 3 or lease_fd < 3 or listener == lease_fd) return error.BadDescriptor;
    try context.validate();
    if (!std.meta.eql(try inspectListener(listener, &context.endpoint), context.listener_identity)) return error.BadDescriptor;
    const parent = std.fs.path.dirname(context.endpoint.bytes()) orelse return error.Namespace;
    if (!std.mem.eql(u8, std.fs.path.basename(context.endpoint.bytes()), endpoint_name)) return error.Namespace;
    var ns = try RootNamespace.openChecked(try Path.init(parent));
    defer ns.deinit();
    const node = try statAt(ns.fd, endpoint_name);
    if (node.uid != 0 or (node.mode & posix.S.IFMT) != posix.S.IFSOCK or (node.mode & 0o777) != 0o600 or !std.meta.eql(node.identity, context.endpoint_identity)) return error.Namespace;
    const held: Lease = .{ .fd = lease_fd, .identity = context.lease_identity };
    try held.validate(&ns, lease_name);
}

pub fn acceptRoot(listener: i32) Error!i32 {
    if (comptime !supported) return error.Unsupported;
    try requireNonblocking(listener); // accept4 flags affect only the new FD.
    const rc = sys.accept4(listener, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .AGAIN => return error.WouldBlock,
        else => return error.SocketFailed,
    }
    const accepted: i32 = @intCast(rc);
    errdefer runtime.close(accepted);
    try requireRootPeer(accepted);
    return accepted;
}
pub fn connectRoot(context: *const Context) Error!i32 {
    if (comptime !supported) return error.Unsupported;
    if (sys.geteuid() != 0) return error.NotRoot;
    try context.validate();
    const parent = std.fs.path.dirname(context.endpoint.bytes()) orelse return error.Namespace;
    var ns = try RootNamespace.openChecked(try Path.init(parent));
    defer ns.deinit();
    const node = try statAt(ns.fd, endpoint_name);
    if ((node.mode & posix.S.IFMT) != posix.S.IFSOCK or node.uid != 0 or (node.mode & 0o777) != 0o600 or !std.meta.eql(node.identity, context.endpoint_identity)) return error.Namespace;
    var address = try unixAddress(&context.endpoint);
    const rc = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer runtime.close(fd);
    switch (posix.errno(sys.connect(fd, @ptrCast(&address), addressLength(&address)))) {
        .SUCCESS => {},
        // No request has been admitted or sent. Dispose this newly owned FD and
        // let the caller retry; never expose an unauthenticated pending socket.
        .AGAIN, .INPROGRESS, .ALREADY, .INTR => return error.WouldBlock,
        else => return error.SocketFailed,
    }
    try requireRootPeer(fd); // Expected root BINDER, not the nonroot acceptor.
    return fd;
}

// The only simulated lifecycle publisher is removed from production builds.
pub const Fixture = if (builtin.is_test) struct {
    /// Real protected namespace, locked lease and bound listener; test-only.
    pub fn root() !RootFixture {
        return RootFixture.init();
    }
    pub fn closeRoot(fixture: *RootFixture) void {
        fixture.deinit();
    }
    pub fn ready(controller: *Controller) void {
        const owned = backing(controller);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        std.debug.assert(owned.state.phase == .starting);
        owned.state.phase = .current;
    }
    pub fn admitRequest(controller: *Controller, request: Request) Error!Controller.Admission {
        return admit(backing(controller), request);
    }
    pub fn refused(controller: *Controller) void {
        const owned = backing(controller);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        std.debug.assert(owned.plan == null);
        owned.state.phase = .current;
        owned.state.upgrade_id = @splat(0);
        owned.state.last.?.result = .refused;
        owned.revision += 1;
    }
    pub fn succeeded(controller: *Controller) void {
        const owned = backing(controller);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        std.debug.assert(owned.plan == null);
        owned.state.phase = .current;
        owned.state.upgrade_id = @splat(0);
        owned.state.generation += 1;
        owned.state.last.?.result = .succeeded;
        owned.state.context.config_commitment = owned.state.last.?.request.candidate_config;
        owned.revision += 1;
    }
    pub fn stopped(controller: *Controller) void {
        const owned = backing(controller);
        owned.mutex.lockExclusive();
        defer owned.mutex.unlockExclusive();
        std.debug.assert(owned.state.phase == .stopping);
        owned.graph_detached = true;
        owned.state.last.?.result = .stopped;
        owned.revision += 1;
    }
    pub fn admitStopReceipt(controller: *Controller, ack: StopAck) Error!Controller.Admission {
        return admitStopAck(backing(controller), ack);
    }
    pub fn context() !Context {
        const spec: managed.ServiceSpec = .{
            .helper = try Path.init("/usr/local/libexec/onyx-server-helper"),
            .executable = try Path.init("/usr/local/bin/onyx-server"),
            .config = try Path.init("/etc/onyx-server/a config;$b.toml"),
            .cwd = try Path.init("/var/onyx-server"),
            .user = try managed.Name.init("_onyx"),
            .class = try managed.Name.init("daemon"),
            .uid = 65534,
            .gid = 65534,
            .groups = .{65534} ++ @as([managed.group_max - 1]u32, @splat(0)),
            .group_count = 1,
        };
        const observation: managed.Observation = .{
            .uid = @splat(spec.uid),
            .gid = @splat(spec.gid),
            .groups = spec.groups,
            .group_count = spec.group_count,
            .rtable = spec.rtable,
            .cwd = .{ .device = 2, .inode = 40 },
            .limits = @splat(.{ .soft = 256, .hard = 256 }),
        };
        return .{ .incarnation = @splat(1), .executable = spec.executable, .config = spec.config, .cwd = spec.cwd, .endpoint = try Path.init(namespace_path ++ "/" ++ endpoint_name), .uid = spec.uid, .gid = spec.gid, .rtable = spec.rtable, .policy_version = 2, .managed_spec = spec, .managed_observation = observation, .config_commitment = @splat(2), .listener_ports = .{ 6680, 6697, 0, 0, 7000, 0, 0 }, .listener_canonical = 3, .lease_canonical = 4, .listener_identity = .{ .device = 1, .inode = 10 }, .endpoint_identity = .{ .device = 2, .inode = 20 }, .lease_identity = .{ .device = 2, .inode = 30 } };
    }
} else void;

fn testRequest(controller: *const Controller, verb: Verb, nonce: u8) Request {
    const state = controller.inspect();
    return .{ .verb = verb, .incarnation = state.context.incarnation, .generation = state.generation, .serial = controller.reply().next_serial, .nonce = @splat(nonce), .candidate_config = if (verb == .upgrade) @splat(nonce) else @splat(0) };
}
test "native service StopAck canonical exact stop identity and strict packet shape" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    const ack: StopAck = .{ .request = testRequest(owner, .stop, 3), .managed_spec_commitment = owner.reply().managed_spec_commitment };
    const wire = try ack.encode();
    try std.testing.expectEqual(@as(usize, 132), wire.len);
    try std.testing.expectEqualSlices(u8, &try ack.request.encode(), wire[8..100]);
    try std.testing.expectEqualDeep(ack, try StopAck.decode(&wire));
    for (0..wire.len) |len| try std.testing.expectError(error.InvalidWire, StopAck.decode(wire[0..len]));
    const trailing = wire ++ [_]u8{0};
    try std.testing.expectError(error.InvalidWire, StopAck.decode(&trailing));
    for ([_]usize{ 0, 4, 5, 6, 7, 8, 12, 13, 15, 16 }) |offset| {
        var malformed = wire;
        malformed[offset] ^= 128;
        try std.testing.expectError(error.InvalidWire, StopAck.decode(&malformed));
    }
    var wrong = ack;
    wrong.request = testRequest(owner, .upgrade, 4);
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong.request = .{ .verb = .query, .incarnation = @splat(0), .generation = 0, .serial = 0, .nonce = @splat(4), .candidate_config = @splat(0) };
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = ack;
    wrong.managed_spec_commitment = @splat(0);
    try std.testing.expectError(error.InvalidWire, wrong.encode());
}
test "native service StopAck only exact detached stop and duplicates spend no counter" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    var ack: StopAck = .{ .request = testRequest(owner, .stop, 3), .managed_spec_commitment = owner.reply().managed_spec_commitment };
    try std.testing.expectError(error.InvalidState, Fixture.admitStopReceipt(owner, ack));
    try std.testing.expect(!owner.terminalAcknowledged());
    Fixture.ready(owner);
    try std.testing.expectEqual(Controller.Admission.execute, try Fixture.admitRequest(owner, ack.request));
    const accepted = try owner.reply().encode();
    try std.testing.expectError(error.InvalidState, Fixture.admitStopReceipt(owner, ack));
    try std.testing.expectEqualSlices(u8, &accepted, &try owner.reply().encode());
    // This is a test-only lifecycle simulation, not a production cleanup proof.
    Fixture.stopped(owner);
    const stopped = try owner.reply().encode();
    const revision = backing(owner).revision;
    for (0..5) |field| {
        var wrong = ack;
        switch (field) {
            0 => wrong.request.incarnation[0] ^= 128,
            1 => wrong.request.generation += 1,
            2 => wrong.request.serial += 1,
            3 => wrong.request.nonce[0] ^= 128,
            4 => wrong.managed_spec_commitment[0] ^= 128,
            else => unreachable,
        }
        try std.testing.expectError(error.Conflict, Fixture.admitStopReceipt(owner, wrong));
        try std.testing.expect(!owner.terminalAcknowledged());
        try std.testing.expectEqual(revision, backing(owner).revision);
        try std.testing.expectEqualSlices(u8, &stopped, &try owner.reply().encode());
    }
    // Even the last serial and exhausted issuance counter cannot prevent ACK.
    backing(owner).state.last.?.request.serial = std.math.maxInt(u64);
    backing(owner).revision = std.math.maxInt(u64);
    ack.request.serial = std.math.maxInt(u64);
    const exhausted = try owner.reply().encode();
    for (0..3) |_| try std.testing.expectEqual(Controller.Admission.stop_ack, try Fixture.admitStopReceipt(owner, ack));
    try std.testing.expect(owner.terminalAcknowledged());
    try std.testing.expectEqual(std.math.maxInt(u64), backing(owner).revision);
    try std.testing.expectEqualSlices(u8, &exhausted, &try owner.reply().encode());
}
test "native service N1 wire rejects truncation reserved bits unknown verbs trailing bytes" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    const request = testRequest(owner, .upgrade, 3);
    var wire = try request.encode();
    try std.testing.expectEqualDeep(request, try Request.decode(&wire));
    for (0..wire.len) |len| try std.testing.expectError(error.InvalidWire, Request.decode(wire[0..len]));
    wire[7] = 1;
    try std.testing.expectError(error.InvalidWire, Request.decode(&wire));
    wire = try request.encode();
    wire[6] = 255;
    try std.testing.expectError(error.InvalidWire, Request.decode(&wire));
    var too_long: [Request.wire_len + 1]u8 = @splat(0);
    @memcpy(too_long[0..wire.len], &(try request.encode()));
    try std.testing.expectError(error.InvalidWire, Request.decode(&too_long));
}
test "native service N1 context rejects relative alias control and FD identities" {
    for ([_][]const u8{ "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\n", "/a\x00b" }) |path| try std.testing.expectError(error.InvalidIdentity, Path.init(path));
    const literal = try Path.init("/etc/a config;$literal.toml");
    try std.testing.expectEqualStrings("/etc/a config;$literal.toml", literal.bytes());
    var context = try Fixture.context();
    context.lease_canonical = context.listener_canonical;
    try std.testing.expectError(error.BadDescriptor, context.validate());
    context = try Fixture.context();
    context.incarnation = @splat(0);
    try std.testing.expectError(error.InvalidIdentity, context.validate());
    context = try Fixture.context();
    context.uid = 0;
    try std.testing.expectError(error.InvalidIdentity, context.validate());
    context = try Fixture.context();
    context.rtable = 256;
    try std.testing.expectError(error.InvalidIdentity, context.validate());
}
test "native service N1 production controller is opaque and starts without ready authority" {
    try std.testing.expect(@typeInfo(Controller) == .@"opaque");
    try std.testing.expect(!@hasDecl(Controller, "ready") and !@hasDecl(Controller, "completeStop"));
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    try std.testing.expectEqual(Phase.starting, owner.reply().phase);
    try std.testing.expectError(error.Busy, Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3)));
    try std.testing.expect(owner.reply().last == null);
}
test "native service policy2 joins selected launch paths IDs and every actual context constraint" {
    const original = try Fixture.context();
    try original.validate();
    var wrong = original;
    wrong.policy_version = 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_spec.config = try Path.init("/etc/onyx-server/other.toml");
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_spec.uid += 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_spec.gid += 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_spec.rtable += 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    for (0..3) |i| {
        wrong = original;
        wrong.managed_observation.uid[i] += 1;
        try std.testing.expectError(error.InvalidIdentity, wrong.validate());
        wrong = original;
        wrong.managed_observation.gid[i] += 1;
        try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    }
    wrong = original;
    wrong.managed_observation.groups[0] += 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_observation.groups[managed.group_max - 1] = 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_observation.rtable += 1;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    wrong = original;
    wrong.managed_observation.cwd.inode = 0;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    for (0..managed.limit_count) |i| {
        wrong = original;
        wrong.managed_spec.limits[i].max_hard = 255;
        wrong.managed_spec.limits[i].max_soft = 255;
        try std.testing.expectError(error.InvalidIdentity, wrong.validate());
        wrong = original;
        wrong.managed_observation.limits[i].soft = 257;
        try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    }
    wrong = original;
    wrong.managed_observation.limits[8].soft = 128;
    try std.testing.expectError(error.InvalidIdentity, wrong.validate());
    try std.testing.expectEqualDeep(original, try Fixture.context());
}
test "native service N1 lost reply duplicate failed upgrade and stale replay preserve exact operation" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    const first = testRequest(owner, .upgrade, 3);
    try std.testing.expectEqual(Controller.Admission.execute, try Fixture.admitRequest(owner, first));
    try std.testing.expectEqual(Controller.Admission.duplicate, try Fixture.admitRequest(owner, first));
    var conflict = first;
    conflict.nonce[0] ^= 1;
    try std.testing.expectError(error.Conflict, Fixture.admitRequest(owner, conflict));
    try std.testing.expectError(error.Busy, Fixture.admitRequest(owner, testRequest(owner, .stop, 4)));
    Fixture.refused(owner);
    try std.testing.expectEqual(Controller.Admission.duplicate, try Fixture.admitRequest(owner, first));
    const second = testRequest(owner, .upgrade, 4);
    try std.testing.expectEqual(Controller.Admission.execute, try Fixture.admitRequest(owner, second));
    Fixture.succeeded(owner);
    try std.testing.expectEqual(@as(u64, 1), owner.reply().generation);
    try std.testing.expectError(error.Stale, Fixture.admitRequest(owner, first));
    try std.testing.expectEqual(Controller.Admission.duplicate, try Fixture.admitRequest(owner, second));
    try owner.inspect().validate();
}
test "native service N1 stop excludes upgrade until fixture cleanup result and serial does not wrap" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    const stop = testRequest(owner, .stop, 3);
    try std.testing.expectEqual(Controller.Admission.execute, try Fixture.admitRequest(owner, stop));
    try std.testing.expectEqual(Phase.stopping, owner.reply().phase);
    try std.testing.expectError(error.Busy, Fixture.admitRequest(owner, testRequest(owner, .upgrade, 4)));
    Fixture.stopped(owner);
    try std.testing.expectEqual(Result.stopped, owner.reply().last.?.result);
    try std.testing.expectEqual(Controller.Admission.duplicate, try Fixture.admitRequest(owner, stop));
    try owner.inspect().validate();
    // Explicit test-only source state at the nonwrapping terminal serial.
    backing(owner).state.last.?.request.serial = std.math.maxInt(u64);
    try std.testing.expectEqual(@as(u64, 0), owner.reply().next_serial);
}
test "native service N1 query and mutation nonce generation serial checks have no partial admission" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    var request = testRequest(owner, .upgrade, 3);
    const before = owner.inspect();
    request.generation += 1;
    try std.testing.expectError(error.Stale, Fixture.admitRequest(owner, request));
    request = testRequest(owner, .upgrade, 3);
    request.serial += 1;
    try std.testing.expectError(error.Stale, Fixture.admitRequest(owner, request));
    request = testRequest(owner, .upgrade, 3);
    request.incarnation[0] ^= 1;
    try std.testing.expectError(error.Stale, Fixture.admitRequest(owner, request));
    request = testRequest(owner, .upgrade, 3);
    request.nonce = @splat(0);
    try std.testing.expectError(error.InvalidWire, Fixture.admitRequest(owner, request));
    try std.testing.expectEqualDeep(before, owner.inspect());
    const query: Request = .{ .verb = .query, .incarnation = @splat(0), .generation = 0, .serial = 0, .nonce = @splat(4), .candidate_config = @splat(0) };
    try std.testing.expectEqual(Controller.Admission.query, try Fixture.admitRequest(owner, query));
    try std.testing.expectEqualDeep(before, owner.inspect());
}
test "native service N1 handoff copied abort stale token and forged issuance cannot publish twice" {
    // getsockname inspection has no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    _ = try Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3));
    const before = owner.inspect();
    const first = try owner.prepareHandoff(std.testing.allocator, @splat(9));
    const copy = first;
    const forged: Handoff = .{ .owner = owner, .issuance = first.issuance + 1 };
    try std.testing.expectError(error.StateChanged, forged.commit());
    forged.deinit();
    try std.testing.expectEqualDeep(before, owner.inspect());
    try std.testing.expectEqual(Phase.quiesced, (try snapshot.decode(try first.bytes())).phase);
    first.deinit();
    copy.deinit();
    try std.testing.expectError(error.StateChanged, copy.commit());
    const second = try owner.prepareHandoff(std.testing.allocator, @splat(10));
    defer second.deinit();
    copy.deinit();
    try second.commit();
    try std.testing.expectEqual(Phase.quiesced, owner.reply().phase);
    try std.testing.expectError(error.StateChanged, second.commit());
    try owner.inspect().validate();
}
fn preparationOom(allocator: std.mem.Allocator) !void {
    const owner = try Controller.initStarting(allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    _ = try Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3));
    const before = owner.inspect();
    const handoff = owner.prepareHandoff(allocator, @splat(9)) catch |err| {
        try std.testing.expectEqualDeep(before, owner.inspect());
        try std.testing.expect(backing(owner).plan == null);
        const retry = try owner.prepareHandoff(std.testing.allocator, @splat(9));
        defer retry.deinit();
        try retry.commit();
        return err;
    };
    defer handoff.deinit();
    try std.testing.expectEqualDeep(before, owner.inspect());
    try handoff.commit();
    try std.testing.expectEqual(Phase.quiesced, owner.reply().phase);
}
test "native service N1 preparation OOM retains operation and allows exact retry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, preparationOom, .{});
}
test "native service N1 reply latest identity is exact and reserved payload rejects" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    _ = try Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3));
    var bytes = try owner.reply().encode();
    try std.testing.expectEqualDeep(owner.reply(), try Reply.decode(&bytes));
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidWire, Reply.decode(bytes[0..len]));
    bytes[47] = 1;
    try std.testing.expectError(error.InvalidWire, Reply.decode(&bytes));
}
test "native service N1 Reply2 binds immutable complete managed policy" {
    const context = try Fixture.context();
    const owner = try Controller.initStarting(std.testing.allocator, context);
    defer owner.deinit();
    const reply = owner.reply();
    try std.testing.expectEqualSlices(u8, &try managed.serviceSpecDigest(&context.managed_spec), &reply.managed_spec_commitment);
    var bytes = try reply.encode();
    try std.testing.expectEqualDeep(reply, try Reply.decode(&bytes));
    std.mem.writeInt(u16, bytes[4..6], 1, .little);
    try std.testing.expectError(error.InvalidWire, Reply.decode(&bytes));
    bytes = try reply.encode();
    try std.testing.expectError(error.InvalidWire, Reply.decode(bytes[0..140]));
    @memset(bytes[140..172], 0);
    try std.testing.expectError(error.InvalidWire, Reply.decode(&bytes));
    var changed = context.managed_spec;
    changed.user = try managed.Name.init("other");
    try std.testing.expect(!std.mem.eql(u8, &try managed.serviceSpecDigest(&changed), &reply.managed_spec_commitment));
    Fixture.ready(owner);
    const request = testRequest(owner, .upgrade, 11);
    const request_bytes = try request.encode();
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, request_bytes[4..6], .little));
    _ = try Fixture.admitRequest(owner, request);
    const accepted = owner.reply();
    _ = try Fixture.admitRequest(owner, request);
    try std.testing.expectEqualDeep(accepted, owner.reply());
    try std.testing.expectEqualSlices(u8, &reply.managed_spec_commitment, &accepted.managed_spec_commitment);
}
fn socketPair() ![2]i32 {
    // Comptime gate (not just the runtime skip below the call would need):
    // `sys.socketpair` does not exist on Windows, so the body must not be
    // analyzed there. POSIX/macOS behavior is unchanged.
    if (comptime !supported) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &fds)));
    return fds;
}
test "native service N1 actual Unix peer ABI root refusal and descriptor type" {
    if (comptime !supported) return error.SkipZigTest;
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    const peer = try peerCredentials(pair[0]);
    try std.testing.expectEqual(@as(u32, @intCast(sys.geteuid())), peer.uid);
    try std.testing.expectEqual(@as(u32, @intCast(sys.getegid())), peer.gid);
    if (sys.geteuid() != 0) {
        try std.testing.expectError(error.WrongPeer, Message.receiveRoot(pair[0]));
        try std.testing.expectError(error.NotRoot, RootNamespace.open());
    }
    var stream: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &stream)));
    defer for (stream) |fd| runtime.close(fd);
    try std.testing.expectError(error.BadDescriptor, peerCredentials(stream[0]));
}
test "native service N1 actual seqpacket wouldblock exact payload SCM independent custody and extraFD refusal" {
    if (comptime !supported) return error.SkipZigTest;
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    try std.testing.expectError(error.WouldBlock, Message.receivePacket(pair[0]));
    const carried = try socketPair();
    defer for (carried) |fd| runtime.close(fd);
    try send(pair[0], "owned", &.{carried[0]});
    var message = try Message.receivePacket(pair[1]);
    defer message.deinit();
    try std.testing.expectEqualStrings("owned", message.bytes());
    try std.testing.expectEqual(@as(usize, 1), message.fd_count);
    const received = message.fds[0];
    const flags = sys.fcntl(received, posix.F.GETFD, @as(c_int, 0));
    try std.testing.expect(posix.errno(flags) == .SUCCESS and (flags & posix.FD_CLOEXEC) != 0);
    message.deinit();
    try std.testing.expect(!runtime.fdValid(received));
    try std.testing.expect(runtime.fdValid(carried[0]));
    if (sys.geteuid() == 0) {
        const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
        defer owner.deinit();
        Fixture.ready(owner);
        const bytes = try testRequest(owner, .upgrade, 3).encode();
        try send(pair[0], &bytes, &.{carried[0]});
        try std.testing.expectError(error.InvalidWire, owner.receive(pair[1]));
        try std.testing.expect(owner.reply().last == null);
        try std.testing.expect(runtime.fdValid(carried[0]));
    }
}

const RootFixture = struct {
    bootstrap: Bootstrap,
    path: Path,
    fn init() !RootFixture {
        if (comptime !supported) return error.SkipZigTest;
        if (sys.geteuid() != 0) return error.SkipZigTest;
        var buffer: [96]u8 = undefined;
        var random: u64 = undefined;
        std.testing.io.random(std.mem.asBytes(&random));
        const path = try Path.init(try std.fmt.bufPrint(&buffer, "{s}/onyx-n1-{x}", .{ if (builtin.os.tag == .openbsd) @as([]const u8, "/var/run") else "/run", random }));
        try std.Io.Dir.createDirAbsolute(std.testing.io, path.bytes(), .fromMode(0o755));
        errdefer std.Io.Dir.cwd().deleteTree(std.testing.io, path.bytes()) catch {};
        var ns = try RootNamespace.openChecked(path);
        errdefer ns.deinit();
        var lease = try ns.acquireLifetime();
        errdefer lease.deinit();
        const context = try Fixture.context();
        const owned = try Bootstrap.bindOwned(ns, lease, .{ .executable = context.executable, .config = context.config, .cwd = context.cwd, .uid = context.uid, .gid = context.gid, .rtable = context.rtable, .managed_spec = context.managed_spec, .managed_observation = context.managed_observation, .config_commitment = context.config_commitment, .listener_ports = context.listener_ports });
        return .{ .bootstrap = owned, .path = path };
    }
    fn deinit(self: *RootFixture) void {
        self.bootstrap.deinit();
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.path.bytes()) catch @panic("N1 fixture cleanup");
    }
};
test "native service N1 root lifetime lease duplicate retains lock independent reopen cannot acquire" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const parent = &fixture.bootstrap.lease;
    var duplicate: Lease = .{ .fd = try runtime.duplicate(parent.fd), .identity = parent.identity };
    defer duplicate.deinit();
    try duplicate.validate(&fixture.bootstrap.ns, lease_name);
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    parent.deinit();
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    duplicate.deinit();
    var acquired = try fixture.bootstrap.ns.acquireLifetime();
    defer acquired.deinit();
    try std.testing.expectEqualDeep(parent.identity, acquired.identity);
}
test "native service N1 root actual listener path and socket identities bootstrap descriptor custody" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    try fixture.bootstrap.sendTo(std.testing.allocator, pair[0]);
    var received = try Incoming.receive(pair[1]);
    defer received.deinit();
    try std.testing.expectEqual(Phase.starting, received.state.phase);
    try std.testing.expectEqualDeep(fixture.bootstrap.state, received.state);
    const transferred = received.listener;
    try std.testing.expect(transferred != fixture.bootstrap.listener);
    received.deinit();
    try std.testing.expect(!runtime.fdValid(transferred));
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    const context = &fixture.bootstrap.state.context;
    // Path and socket FD are independently captured and validated, with no
    // equality assertion between their unrelated inode domains.
    var wrong = context.*;
    wrong.endpoint_identity.inode ^= 1;
    try std.testing.expectError(error.Namespace, validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.lease.fd, &wrong));
    wrong = context.*;
    wrong.listener_identity.inode ^= 1;
    try std.testing.expectError(error.BadDescriptor, validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.lease.fd, &wrong));
    try std.testing.expectError(error.BadDescriptor, validateDescriptors(fixture.bootstrap.listener, fixture.bootstrap.listener, context));
}
test "native service N1 root already held lease failure retries same owned descriptors then transfers once" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const context = fixture.bootstrap.state.context;
    var launch: Launch = .{ .executable = context.executable, .config = context.config, .cwd = context.cwd, .uid = context.uid, .gid = context.gid, .rtable = context.rtable, .managed_spec = context.managed_spec, .managed_observation = context.managed_observation, .config_commitment = context.config_commitment, .listener_ports = context.listener_ports };
    try fixture.bootstrap.ns.removeOwnedEndpoint(&fixture.bootstrap.lease, context.endpoint_identity);
    runtime.close(fixture.bootstrap.listener);
    fixture.bootstrap.listener = -1;
    const directory_fd = fixture.bootstrap.ns.fd;
    const lease_fd = fixture.bootstrap.lease.fd;
    const lease_identity = fixture.bootstrap.lease.identity;
    launch.uid = 0;
    // The failure occurs AFTER bind/listen. Only the newly created endpoint
    // and listener are removed; the caller's original lease stays locked.
    try std.testing.expectError(error.InvalidIdentity, Bootstrap.acquireCheckedFromLease(&fixture.bootstrap.ns, &fixture.bootstrap.lease, launch));
    try std.testing.expectEqual(directory_fd, fixture.bootstrap.ns.fd);
    try std.testing.expectEqual(lease_fd, fixture.bootstrap.lease.fd);
    try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    try std.testing.expectError(error.Namespace, statAt(directory_fd, endpoint_name));
    launch.uid = context.uid;
    var acquired = try Bootstrap.acquireCheckedFromLease(&fixture.bootstrap.ns, &fixture.bootstrap.lease, launch);
    defer acquired.deinit();
    try std.testing.expectEqual(@as(i32, -1), fixture.bootstrap.ns.fd);
    try std.testing.expectEqual(@as(i32, -1), fixture.bootstrap.lease.fd);
    try std.testing.expectEqual(directory_fd, acquired.ns.fd);
    try std.testing.expectEqual(lease_fd, acquired.lease.fd);
    try std.testing.expectEqualDeep(lease_identity, acquired.lease.identity);
    try std.testing.expectError(error.Busy, acquired.ns.acquireLifetime());
    try std.testing.expectError(error.BadDescriptor, Bootstrap.acquireCheckedFromLease(&fixture.bootstrap.ns, &fixture.bootstrap.lease, launch));
    fixture.bootstrap.ns.deinit();
    fixture.bootstrap.lease.deinit();
    try acquired.lease.validate(&acquired.ns, lease_name);
    try validateDescriptors(acquired.listener, acquired.lease.fd, &acquired.state.context);
}
test "native service N1 root already held lease rejects forged directory identity without changing owners" {
    var first = try RootFixture.init();
    defer first.deinit();
    var second = try RootFixture.init();
    defer second.deinit();
    const context = first.bootstrap.state.context;
    const launch: Launch = .{ .executable = context.executable, .config = context.config, .cwd = context.cwd, .uid = context.uid, .gid = context.gid, .rtable = context.rtable, .managed_spec = context.managed_spec, .managed_observation = context.managed_observation, .config_commitment = context.config_commitment, .listener_ports = context.listener_ports };
    var forged: RootNamespace = .{ .fd = second.bootstrap.ns.fd, .path = first.bootstrap.ns.path };
    const before = first.bootstrap.lease.fd;
    try std.testing.expectError(error.Namespace, Bootstrap.acquireCheckedFromLease(&forged, &first.bootstrap.lease, launch));
    try std.testing.expectEqual(before, first.bootstrap.lease.fd);
    try first.bootstrap.lease.validate(&first.bootstrap.ns, lease_name);
    try second.bootstrap.lease.validate(&second.bootstrap.ns, lease_name);
    try validateDescriptors(first.bootstrap.listener, before, &context);
    try std.testing.expectError(error.Busy, first.bootstrap.ns.acquireLifetime());
    try std.testing.expectError(error.Busy, second.bootstrap.ns.acquireLifetime());
}
test "native service N1 public held lease join cannot select a fixture namespace" {
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const context = fixture.bootstrap.state.context;
    const launch: Launch = .{ .executable = context.executable, .config = context.config, .cwd = context.cwd, .uid = context.uid, .gid = context.gid, .rtable = context.rtable, .managed_spec = context.managed_spec, .managed_observation = context.managed_observation, .config_commitment = context.config_commitment, .listener_ports = context.listener_ports };
    const ns_fd = fixture.bootstrap.ns.fd;
    const lease_fd = fixture.bootstrap.lease.fd;
    try std.testing.expectError(error.Namespace, Bootstrap.acquireFromLease(&fixture.bootstrap.ns, &fixture.bootstrap.lease, launch));
    try std.testing.expectEqual(ns_fd, fixture.bootstrap.ns.fd);
    try std.testing.expectEqual(lease_fd, fixture.bootstrap.lease.fd);
    try validateDescriptors(fixture.bootstrap.listener, lease_fd, &context);
}
test "native service N1 root endpoint foreign replacement prevents unlink and namespace write refusal" {
    // Raw-fd syscalls (openat/symlinkat/fchmod/socket) have no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const ns = &fixture.bootstrap.ns;
    var wrong = fixture.bootstrap.state.context.endpoint_identity;
    wrong.inode ^= 1;
    try std.testing.expectError(error.Namespace, ns.removeOwnedEndpoint(&fixture.bootstrap.lease, wrong));
    const expected = fixture.bootstrap.state.context.endpoint_identity;
    try ns.removeOwnedEndpoint(&fixture.bootstrap.lease, expected);
    const rc = sys.openat(ns.fd, endpoint_name, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true }, @as(posix.mode_t, 0o600));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const foreign: i32 = @intCast(rc);
    defer runtime.close(foreign);
    try std.testing.expectError(error.Namespace, ns.removeOwnedEndpoint(&fixture.bootstrap.lease, expected));
    try std.testing.expectEqual(posix.S.IFREG, (try statAt(ns.fd, endpoint_name)).mode & posix.S.IFMT);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.fchmod(ns.fd, @as(posix.mode_t, 0o777))));
    try std.testing.expectError(error.Namespace, ns.acquireMutation());
}

const AdmissionRace = struct {
    owner: *Controller,
    request: Request,
    start: *std.atomic.Value(bool),
    outcome: ?Controller.Admission = null,
    failure: ?Error = null,
    fn run(self: *AdmissionRace) void {
        while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
        self.outcome = Fixture.admitRequest(self.owner, self.request) catch |err| {
            self.failure = err;
            return;
        };
    }
};
test "native service N1 concurrent same serial executes once conflicting nonce has no second mutation" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    var start = std.atomic.Value(bool).init(false);
    var first: AdmissionRace = .{ .owner = owner, .request = testRequest(owner, .upgrade, 3), .start = &start };
    var second: AdmissionRace = .{ .owner = owner, .request = testRequest(owner, .upgrade, 4), .start = &start };
    const a = try std.Thread.spawn(.{}, AdmissionRace.run, .{&first});
    // If the second spawn fails, let the first finish before its stack leaves.
    const b = std.Thread.spawn(.{}, AdmissionRace.run, .{&second}) catch |err| {
        start.store(true, .release);
        a.join();
        return err;
    };
    start.store(true, .release);
    a.join();
    b.join();
    try std.testing.expect((first.outcome == .execute and (second.failure != null and second.failure.? == error.Conflict)) or (second.outcome == .execute and (first.failure != null and first.failure.? == error.Conflict)));
    const accepted = owner.reply().last.?.request;
    try std.testing.expectEqual(@as(u64, 2), owner.reply().next_serial);
    try std.testing.expectEqual(Controller.Admission.duplicate, try Fixture.admitRequest(owner, accepted));
    try owner.inspect().validate();
}
test "native service N1 generation and plan issuance exhaustion refuse before any source mutation" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    backing(owner).revision = std.math.maxInt(u64);
    var before = owner.inspect();
    try std.testing.expectError(error.CounterExhausted, Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3)));
    try std.testing.expectEqualDeep(before, owner.inspect());
    backing(owner).revision = 1;
    backing(owner).state.generation = std.math.maxInt(u64);
    before = owner.inspect();
    try std.testing.expectError(error.CounterExhausted, Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3)));
    try std.testing.expectEqualDeep(before, owner.inspect());
    backing(owner).state.generation = 0;
    _ = try Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3));
    backing(owner).revision = std.math.maxInt(u64) - 1;
    before = owner.inspect();
    try std.testing.expectError(error.CounterExhausted, owner.prepareHandoff(std.testing.allocator, @splat(9)));
    try std.testing.expectEqualDeep(before, owner.inspect());
    try std.testing.expect(backing(owner).plan == null);
}
test "native service N1 replies refuse contradictory incarnation serial phase and result" {
    const owner = try Controller.initStarting(std.testing.allocator, try Fixture.context());
    defer owner.deinit();
    Fixture.ready(owner);
    _ = try Fixture.admitRequest(owner, testRequest(owner, .upgrade, 3));
    const valid = owner.reply();
    var wrong = valid;
    wrong.next_serial += 1;
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = valid;
    wrong.incarnation[0] ^= 1;
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = valid;
    wrong.phase = .stopping;
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = valid;
    wrong.last.?.result = .stopped;
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = valid;
    wrong.last.?.result = .succeeded;
    try std.testing.expectError(error.InvalidWire, wrong.encode());
    wrong = valid;
    wrong.phase = .candidate;
    try std.testing.expectEqualDeep(wrong, try Reply.decode(&(try wrong.encode())));
}

// Test-only subprocesses do not allocate or acquire inherited Zig mutexes after
// fork. All endpoint/path material and descriptor custody is staged beforehand.
fn childExit(status: u8) noreturn {
    if (comptime builtin.os.tag == .linux) std.os.linux.exit_group(status);
    if (comptime builtin.os.tag == .openbsd) sys._exit(status);
    unreachable;
}
const OwnedChild = struct {
    pid: i32,
    fn fork() !OwnedChild {
        if (comptime !supported) return error.SkipZigTest;
        const rc = sys.fork();
        if (posix.errno(rc) != .SUCCESS) return error.ForkFailed;
        return .{ .pid = @intCast(rc) };
    }
    fn deinit(self: *OwnedChild) void {
        if (comptime !supported) return;
        if (self.pid <= 0) return;
        _ = sys.kill(self.pid, posix.SIG.KILL);
        var status: c_int = 0;
        while (posix.errno(sys.waitpid(self.pid, &status, 0)) == .INTR) {}
        self.pid = -1;
    }
    fn expectSuccess(self: *OwnedChild) !void {
        try std.testing.expect(self.pid > 0);
        var status: c_int = 0;
        while (true) {
            const rc = sys.waitpid(self.pid, &status, 0);
            if (posix.errno(rc) == .INTR) continue;
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
            try std.testing.expectEqual(self.pid, @as(i32, @intCast(rc)));
            self.pid = -1;
            try std.testing.expectEqual(@as(c_int, 0), status);
            return;
        }
    }
};
fn pollReadable(fd: i32) !void {
    if (comptime !supported) return error.Unsupported;
    var pollfd: posix.pollfd = .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 };
    while (true) {
        const rc = sys.poll(@ptrCast(&pollfd), 1, 3000);
        if (posix.errno(rc) == .INTR) continue;
        if (posix.errno(rc) != .SUCCESS or rc != 1 or (pollfd.revents & posix.POLL.IN) == 0) return error.ReceiveFailed;
        return;
    }
}
fn receiveReady(fd: i32) !Message {
    try pollReadable(fd);
    return Message.receivePacket(fd);
}
fn dropTestIdentity() bool {
    if (comptime !supported) return false;
    return posix.errno(sys.setresgid(65534, 65534, 65534)) == .SUCCESS and posix.errno(sys.setresuid(65534, 65534, 65534)) == .SUCCESS and sys.geteuid() == 65534 and sys.getegid() == 65534;
}
test "native service N1 root binder credentials survive nonroot inherited listener acceptor" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    var child = try OwnedChild.fork();
    if (child.pid == 0) {
        runtime.close(pair[0]);
        if (!dropTestIdentity()) childExit(10);
        send(pair[1], "nonroot-ready", &.{}) catch childExit(11);
        pollReadable(fixture.bootstrap.listener) catch childExit(12);
        const accepted = acceptRoot(fixture.bootstrap.listener) catch childExit(13);
        defer runtime.close(accepted);
        // Actual root-client credentials remain distinct from our actual UID.
        const peer = peerCredentials(accepted) catch childExit(14);
        if (peer.uid != 0 or sys.geteuid() != 65534) childExit(15);
        send(accepted, "root-binder/nonroot-acceptor", &.{}) catch childExit(16);
        // Keep this real accepted peer alive until the parent has completed
        // its connected-credential and exact payload checks; queued bytes
        // alone do not retain OpenBSD's connected peer after child exit.
        pollReadable(pair[1]) catch childExit(17);
        var ack = Message.receivePacket(pair[1]) catch childExit(18);
        defer ack.deinit();
        if (!std.mem.eql(u8, ack.bytes(), "binder-credentials-checked")) childExit(19);
        childExit(0);
    }
    defer child.deinit();
    var ready = try receiveReady(pair[0]);
    defer ready.deinit();
    try std.testing.expectEqualStrings("nonroot-ready", ready.bytes());
    const client = try connectRoot(&fixture.bootstrap.state.context);
    defer runtime.close(client);
    const peer = try peerCredentials(client);
    try std.testing.expectEqual(@as(u32, 0), peer.uid);
    var reply = try receiveReady(client);
    defer reply.deinit();
    try std.testing.expectEqualStrings("root-binder/nonroot-acceptor", reply.bytes());
    try send(pair[0], "binder-credentials-checked", &.{});
    try child.expectSuccess();
}
test "native service N1 nonroot connector is rejected by mode and actual accept credentials" {
    // Raw-fd syscalls (openat/symlinkat/fchmod/socket) have no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    // A restrictive root test umask must not make parent traversal the reason
    // for BOTH connection refusals. Reach the socket mode and peer checks below.
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.fchmod(fixture.bootstrap.ns.fd, @as(posix.mode_t, 0o755))));
    try std.testing.expectEqual(@as(u32, 0o755), (try statAt(fixture.bootstrap.ns.fd, null)).mode & 0o777);
    // A deliberately world-accessible TEST endpoint is needed to reach the
    // credential rejection behind the production 0600 pathname restriction.
    var path_buffer: [max_path + 1]u8 = undefined;
    const endpoint_z = pathZ(&fixture.bootstrap.state.context.endpoint, &path_buffer);
    var address = try unixAddress(&fixture.bootstrap.state.context.endpoint);
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    var first = try OwnedChild.fork();
    if (first.pid == 0) {
        runtime.close(pair[0]);
        if (!dropTestIdentity()) childExit(20);
        const fd = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0);
        if (posix.errno(fd) != .SUCCESS) childExit(21);
        if (posix.errno(sys.connect(@intCast(fd), @ptrCast(&address), addressLength(&address))) != .ACCES) childExit(22);
        childExit(0);
    }
    defer first.deinit();
    try first.expectSuccess();
    try std.testing.expectError(error.WouldBlock, acceptRoot(fixture.bootstrap.listener));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.chmod(endpoint_z.ptr, @as(posix.mode_t, 0o666))));
    var second = try OwnedChild.fork();
    if (second.pid == 0) {
        runtime.close(pair[0]);
        if (!dropTestIdentity()) childExit(23);
        const fd = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0);
        if (posix.errno(fd) != .SUCCESS) childExit(24);
        if (posix.errno(sys.connect(@intCast(fd), @ptrCast(&address), addressLength(&address))) != .SUCCESS) childExit(25);
        send(pair[1], "connected", &.{}) catch childExit(26);
        pollReadable(pair[1]) catch childExit(27);
        childExit(0);
    }
    defer second.deinit();
    var ready = try receiveReady(pair[0]);
    defer ready.deinit();
    try std.testing.expectEqualStrings("connected", ready.bytes());
    try std.testing.expectError(error.WrongPeer, acceptRoot(fixture.bootstrap.listener));
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
    try send(pair[0], "done", &.{});
    try second.expectSuccess();
}
test "native service N1 root malformed bootstrap retains sender and closes rejected lease copies" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    var bytes = try snapshot.encode(std.testing.allocator, &fixture.bootstrap.state);
    defer std.testing.allocator.free(bytes);
    bytes[0] ^= 1;
    try send(pair[0], bytes, &.{ fixture.bootstrap.listener, fixture.bootstrap.lease.fd });
    try std.testing.expectError(error.InvalidWire, Incoming.receive(pair[1]));
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
    const identity = fixture.bootstrap.lease.identity;
    fixture.bootstrap.lease.deinit();
    // A leaked SCM lease would still hold the flock and make this fail Busy.
    fixture.bootstrap.lease = try fixture.bootstrap.ns.acquireLifetime();
    try std.testing.expectEqualDeep(identity, fixture.bootstrap.lease.identity);
    try send(pair[0], "wrong-fd-count", &.{fixture.bootstrap.lease.fd});
    try std.testing.expectError(error.InvalidWire, Incoming.receive(pair[1]));
    fixture.bootstrap.lease.deinit();
    fixture.bootstrap.lease = try fixture.bootstrap.ns.acquireLifetime();
}

test "native service N1 root lease path rejects final symlink hardlink and nonregular FD" {
    // Raw-fd syscalls (openat/symlinkat/fchmod/socket) have no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const ns = &fixture.bootstrap.ns;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.symlinkat(lease_name, ns.fd, "mutation.lock")));
    try std.testing.expectError(error.Namespace, ns.acquireMutation());
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.unlinkat(ns.fd, "mutation.lock", 0)));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.linkat(ns.fd, lease_name, ns.fd, "mutation.lock", 0)));
    try std.testing.expectError(error.Namespace, ns.acquireMutation());
    try std.testing.expectError(error.BadDescriptor, fixture.bootstrap.lease.validate(ns, lease_name));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.unlinkat(ns.fd, "mutation.lock", 0)));
    try fixture.bootstrap.lease.validate(ns, lease_name);
    // `pipe2` exists only on Linux/OpenBSD; this test already skipped above
    // via `RootFixture.init` on other targets, so skip before touching it.
    if (comptime !supported) return error.SkipZigTest;
    var pipe: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.pipe2(&pipe, .{ .CLOEXEC = true, .NONBLOCK = true })));
    defer for (pipe) |fd| runtime.close(fd);
    const invalid: Lease = .{ .fd = pipe[0], .identity = fixture.bootstrap.lease.identity };
    try std.testing.expectError(error.BadDescriptor, invalid.validate(ns, lease_name));
}
fn bootstrapOom(allocator: std.mem.Allocator, fixture: *RootFixture, channel: [2]i32) !void {
    if (comptime !supported) return error.SkipZigTest;
    fixture.bootstrap.sendTo(allocator, channel[0]) catch |err| {
        try std.testing.expectError(error.WouldBlock, Message.receiveRoot(channel[1]));
        try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
        try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
        try fixture.bootstrap.sendTo(std.testing.allocator, channel[0]);
        var retry = try Incoming.receive(channel[1]);
        defer retry.deinit();
        try std.testing.expectEqualDeep(fixture.bootstrap.state, retry.state);
        return err;
    };
    var received = try Incoming.receive(channel[1]);
    defer received.deinit();
    try std.testing.expectEqualDeep(fixture.bootstrap.state, received.state);
}
test "native service N1 root bootstrap encode OOM sends no rights and preserves exact retry" {
    // Scenario is a skip-stub where supported is false; checkAllAllocationFailures needs a real OOM-capable fn.
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, bootstrapOom, .{ &fixture, pair });
}
test "native service N1 root transferred current state cannot manufacture ready bootstrap" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    var simulated = fixture.bootstrap.state;
    simulated.phase = .current;
    const bytes = try snapshot.encode(std.testing.allocator, &simulated);
    defer std.testing.allocator.free(bytes);
    try send(pair[0], bytes, &.{ fixture.bootstrap.listener, fixture.bootstrap.lease.fd });
    try std.testing.expectError(error.InvalidState, Incoming.receive(pair[1]));
    try std.testing.expectEqual(Phase.starting, fixture.bootstrap.state.phase);
    fixture.bootstrap.lease.deinit();
    fixture.bootstrap.lease = try fixture.bootstrap.ns.acquireLifetime();
}
test "native service N1 actual oversized seqpacket refuses truncation without returning prefix" {
    if (comptime !supported) return error.SkipZigTest;
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    const bytes: [max_packet + 1]u8 = @splat(7);
    try std.testing.expectError(error.TooLarge, send(pair[0], &bytes, &.{}));
    try std.testing.expectError(error.WouldBlock, Message.receivePacket(pair[1]));
    const rc = sys.sendto(pair[0], &bytes, bytes.len, posix.MSG.NOSIGNAL, null, 0);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    try std.testing.expectEqual(bytes.len, @as(usize, @intCast(rc)));
    try std.testing.expectError(error.InvalidWire, Message.receivePacket(pair[1]));
    try std.testing.expectError(error.WouldBlock, Message.receivePacket(pair[1]));
}

test "native service N1 root actual named FIFO lease path is rejected without blocking" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    var buffer: [max_path]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, "{s}/mutation.lock", .{fixture.path.bytes()});
    // Fixture setup only, using the selected base utility and an argv vector;
    // neither product code nor user/config text is passed through a shell.
    const mkfifo_path = if (builtin.os.tag == .openbsd) "/sbin/mkfifo" else "/usr/bin/mkfifo";
    const made = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ mkfifo_path, "-m", "600", path },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
    });
    defer std.testing.allocator.free(made.stdout);
    defer std.testing.allocator.free(made.stderr);
    std.debug.print("N1 fixture argv=[{s},-m,600,{s}] term={any}\n", .{ mkfifo_path, path, made.term });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, made.term);
    const actual = try statAt(fixture.bootstrap.ns.fd, "mutation.lock");
    try std.testing.expectEqual(posix.S.IFIFO, actual.mode & posix.S.IFMT);
    try std.testing.expectError(error.Namespace, fixture.bootstrap.ns.acquireMutation());
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.unlinkat(fixture.bootstrap.ns.fd, "mutation.lock", 0)));
    var regular = try fixture.bootstrap.ns.acquireMutation();
    defer regular.deinit();
    try regular.validate(&fixture.bootstrap.ns, "mutation.lock");
}

test "native service N1 root bound endpoint lost reply reconnect returns duplicate operation" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const owner = try Controller.initStarting(std.testing.allocator, fixture.bootstrap.state.context);
    defer owner.deinit();
    // Lifecycle simulation is explicit and excluded from production. The
    // transport, root peer admission, operation parser and retained reply are real.
    Fixture.ready(owner);
    const request = testRequest(owner, .upgrade, 3);
    const wire = try request.encode();
    var client = try connectRoot(&fixture.bootstrap.state.context);
    defer runtime.close(client);
    var accepted = try acceptRoot(fixture.bootstrap.listener);
    defer runtime.close(accepted);
    try send(client, &wire, &.{});
    try std.testing.expectEqual(Controller.Admission.execute, try owner.receive(accepted));
    const once = backing(owner).revision;
    // Drop the connection before any reply; reconnecting cannot re-execute.
    runtime.close(client);
    client = -1;
    runtime.close(accepted);
    accepted = -1;
    client = try connectRoot(&fixture.bootstrap.state.context);
    accepted = try acceptRoot(fixture.bootstrap.listener);
    try send(client, &wire, &.{});
    try std.testing.expectEqual(Controller.Admission.duplicate, try owner.receive(accepted));
    try std.testing.expectEqual(once, backing(owner).revision);
    const reply = try owner.reply().encode();
    try send(accepted, &reply, &.{});
    var observed = try Message.receiveRoot(client);
    defer observed.deinit();
    const result = try Reply.decode(observed.bytes());
    try std.testing.expectEqualDeep(request, result.last.?.request);
    try std.testing.expectEqual(Result.accepted, result.last.?.result);
    try std.testing.expectEqual(@as(u64, 2), result.next_serial);
}

test "native service StopAck root endpoint retains stop receipt and refuses unexpected FD" {
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    var allowance = try FixtureFdAllowance.acquire();
    defer allowance.deinit();
    const owner = try Controller.initStarting(std.testing.allocator, fixture.bootstrap.state.context);
    defer owner.deinit();
    // Only lifecycle publication is simulated. The endpoint, credentials,
    // packet parsing, SCM ownership and retained lifetime lock are real.
    Fixture.ready(owner);
    const request = testRequest(owner, .stop, 3);
    var client = try connectRoot(&fixture.bootstrap.state.context);
    defer runtime.close(client);
    var accepted = try acceptRoot(fixture.bootstrap.listener);
    defer runtime.close(accepted);
    try send(client, &try request.encode(), &.{});
    try std.testing.expectEqual(Controller.Admission.execute, try owner.receive(accepted));
    const ack: StopAck = .{ .request = request, .managed_spec_commitment = owner.reply().managed_spec_commitment };
    const ack_wire = try ack.encode();
    try send(client, &ack_wire, &.{});
    try std.testing.expectError(error.InvalidState, owner.receive(accepted));
    try std.testing.expect(!owner.terminalAcknowledged());
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    Fixture.stopped(owner);
    const stopped_wire = try owner.reply().encode();
    try send(accepted, &stopped_wire, &.{});
    var receipt = try Message.receiveRoot(client);
    defer receipt.deinit();
    try std.testing.expectEqualDeep(owner.reply(), try Reply.decode(receipt.bytes()));
    const before_fds = childDescriptorSet();
    try requireDescriptorCoverage(&before_fds);
    try send(client, &ack_wire, &.{fixture.bootstrap.lease.fd});
    try std.testing.expectError(error.InvalidWire, owner.receive(accepted));
    try std.testing.expectEqualDeep(before_fds, childDescriptorSet());
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.lease.fd));
    try std.testing.expect(!owner.terminalAcknowledged());
    // Drop a response/connection and recover the SAME stop identity.
    runtime.close(client);
    client = -1;
    runtime.close(accepted);
    accepted = -1;
    client = try connectRoot(&fixture.bootstrap.state.context);
    accepted = try acceptRoot(fixture.bootstrap.listener);
    try send(client, &try request.encode(), &.{});
    try std.testing.expectEqual(Controller.Admission.duplicate, try owner.receive(accepted));
    for (0..2) |_| {
        try send(client, &ack_wire, &.{});
        try std.testing.expectEqual(Controller.Admission.stop_ack, try owner.receive(accepted));
        try std.testing.expectEqualSlices(u8, &stopped_wire, &try owner.reply().encode());
    }
    try std.testing.expect(owner.terminalAcknowledged());
    // ACK does not itself close caller-owned custody or pretend cleanup ran.
    try std.testing.expectError(error.Busy, fixture.bootstrap.ns.acquireLifetime());
    fixture.bootstrap.lease.deinit();
    var released = try fixture.bootstrap.ns.acquireLifetime();
    defer released.deinit();
}

// These liveness fixtures use actual kernel sockets and forked operation calls.
// The parent owns every child, watches a bounded result channel, and kills/reaps
// on every error path. No timeout is added around a production blocking syscall.
fn expectChildSuccessBounded(child: *OwnedChild) !void {
    if (comptime !supported) return error.SkipZigTest;
    const deadline = std.Io.Clock.awake.now(std.testing.io).nanoseconds + 3 * std.time.ns_per_s;
    while (true) {
        var status: c_int = 0;
        const rc = sys.waitpid(child.pid, &status, posix.W.NOHANG);
        switch (posix.errno(rc)) {
            .INTR => continue,
            .SUCCESS => {},
            else => return error.ChildWaitFailed,
        }
        if (rc != 0) {
            try std.testing.expectEqual(child.pid, @as(i32, @intCast(rc)));
            child.pid = -1;
            try std.testing.expectEqual(@as(c_int, 0), status);
            return;
        }
        if (std.Io.Clock.awake.now(std.testing.io).nanoseconds >= deadline) return error.ChildDeadline;
        std.atomic.spinLoopHint();
    }
}
fn fixtureStatusFlags(fd: i32) !u32 {
    // Test-only fixture: raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const rc = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (posix.errno(rc) != .SUCCESS) return error.BadDescriptor;
    return @intCast(rc);
}
fn fixtureSetBlocking(fd: i32) !void {
    // Test-only fixture: raw-fd fcntl has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var flags: posix.O = @bitCast(try fixtureStatusFlags(fd));
    flags.NONBLOCK = false;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.fcntl(fd, posix.F.SETFL, @as(usize, @as(u32, @bitCast(flags))))));
}
// Root-only saturation needs 241 queued Unix clients on OpenBSD's actual
// minimum backlog. This scoped fixture budget changes no production policy or
// hard limit, and restores the complete original soft/hard pair on every exit.
const FixtureFdAllowance = if (builtin.is_test and supported) struct {
    previous: sys.rlimit,
    fn acquire() !@This() {
        var previous: sys.rlimit = undefined;
        if (posix.errno(sys.getrlimit(.NOFILE, &previous)) != .SUCCESS) return error.FdBudgetPrecondition;
        if (previous.max < 512) return error.FdBudgetPrecondition;
        var selected = previous;
        selected.cur = 512;
        if (posix.errno(sys.setrlimit(.NOFILE, &selected)) != .SUCCESS) return error.FdBudgetPrecondition;
        errdefer if (posix.errno(sys.setrlimit(.NOFILE, &previous)) != .SUCCESS) @panic("N1 fixture FD limit restoration");
        var actual: sys.rlimit = undefined;
        if (posix.errno(sys.getrlimit(.NOFILE, &actual)) != .SUCCESS or !std.meta.eql(selected, actual)) return error.FdBudgetPrecondition;
        return .{ .previous = previous };
    }
    fn deinit(self: *@This()) void {
        if (posix.errno(sys.setrlimit(.NOFILE, &self.previous)) != .SUCCESS) @panic("N1 fixture FD limit restoration");
        var actual: sys.rlimit = undefined;
        if (posix.errno(sys.getrlimit(.NOFILE, &actual)) != .SUCCESS or !std.meta.eql(self.previous, actual)) @panic("N1 fixture FD limit restoration mismatch");
    }
} else struct {
    // Present so N1 tests compile on unsupported targets. Every caller also
    // reaches `RootFixture.init`'s `SkipZigTest` (before or after this call),
    // so the skip below never masks a runnable fixture.
    fn acquire() !@This() {
        return error.SkipZigTest;
    }
    fn deinit(_: *@This()) void {}
};

fn childDescriptorSet() [512]bool {
    var set: [512]bool = undefined;
    for (&set, 0..) |*open, i| open.* = posix.errno(sys.fcntl(@intCast(i), posix.F.GETFD, @as(c_int, 0))) == .SUCCESS;
    return set;
}

fn requireDescriptorCoverage(set: *const [512]bool) !void {
    // connectRoot has at most two additional live descriptors: directory-walk
    // parent+child, or the held namespace+new socket. Both kernel open/socket
    // operations select the lowest free FD. Three available observed slots
    // conservatively cover all new custody in this single-threaded fork child.
    var free: usize = 0;
    for (set) |open| if (!open) {
        free += 1;
    };
    if (free < 3) return error.FdCoveragePrecondition;
}

test "native service N1 bounded imported blocking listener refuses exact SCM custody unchanged" {
    // Raw-fd listener fixture has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (comptime !supported) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    const shared = try runtime.duplicate(fixture.bootstrap.listener);
    defer runtime.close(shared);
    try fixtureSetBlocking(shared); // The SAME open description; no inode substitution.
    const before_flags = try fixtureStatusFlags(fixture.bootstrap.listener);
    const flags: posix.O = @bitCast(before_flags);
    try std.testing.expect(!flags.NONBLOCK);
    try std.testing.expectEqualDeep(fixture.bootstrap.state.context.listener_identity, (try statAt(shared, null)).identity);
    try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
    try fixture.bootstrap.sendTo(std.testing.allocator, pair[0]);
    // Refusal closes only SCM copies, leaving the predecessor's flags and custody.
    const result = Incoming.receive(pair[1]);
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit();
    } else |err| try std.testing.expectEqual(error.BadDescriptor, err);
    try std.testing.expectEqual(before_flags, try fixtureStatusFlags(shared));
    try std.testing.expectEqual(before_flags, try fixtureStatusFlags(fixture.bootstrap.listener));
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
    try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
    fixture.bootstrap.lease.deinit();
    fixture.bootstrap.lease = try fixture.bootstrap.ns.acquireLifetime();
    // A rejected leaked SCM lease would keep the original flock and fail above.
    try std.testing.expectError(error.BadDescriptor, result);
    try std.testing.expectError(error.BadDescriptor, inspectListener(shared, &fixture.bootstrap.state.context.endpoint));
    try std.testing.expectError(error.BadDescriptor, validateDescriptors(shared, fixture.bootstrap.lease.fd, &fixture.bootstrap.state.context));
}

test "native service N1 bounded public blocking listener rejects without waiting then empty queue control" {
    // Raw-fd listener fixture has no libc-free Windows mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    try fixtureSetBlocking(fixture.bootstrap.listener);
    const before_flags = try fixtureStatusFlags(fixture.bootstrap.listener);
    var child = try OwnedChild.fork();
    if (child.pid == 0) {
        runtime.close(pair[0]);
        const result = acceptRoot(fixture.bootstrap.listener);
        if (result) |unexpected| {
            runtime.close(unexpected);
            childExit(40);
        } else |err| if (err != error.BadDescriptor) childExit(41);
        send(pair[1], "blocking-listener-refused", &.{}) catch childExit(42);
        childExit(0);
    }
    defer child.deinit();
    var observed = try receiveReady(pair[0]);
    defer observed.deinit();
    try std.testing.expectEqualStrings("blocking-listener-refused", observed.bytes());
    try expectChildSuccessBounded(&child);
    try std.testing.expectEqual(before_flags, try fixtureStatusFlags(fixture.bootstrap.listener));
    try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
    // Test-owned restoration only, never implicit production adopt normalization.
    try runtime.setNonblocking(fixture.bootstrap.listener);
    try std.testing.expectError(error.WouldBlock, acceptRoot(fixture.bootstrap.listener));
    const client = try connectRoot(&fixture.bootstrap.state.context);
    defer runtime.close(client);
    const accepted = try acceptRoot(fixture.bootstrap.listener);
    defer runtime.close(accepted);
    try std.testing.expect((@as(posix.O, @bitCast(try fixtureStatusFlags(accepted)))).NONBLOCK);
    try requireRootPeer(accepted);
}

test "native service N1 bounded root connect full backlog refuses owned pending FD then available retry" {
    // Raw-fd syscalls (openat/symlinkat/fchmod/socket) have no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fd_allowance = try FixtureFdAllowance.acquire();
    defer fd_allowance.deinit();
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    var address = try unixAddress(&fixture.bootstrap.state.context.endpoint);
    var admitted: [256]i32 = @splat(-1);
    var count: usize = 0;
    defer for (admitted[0..count]) |fd| runtime.close(fd);
    var full = false;
    var backlog_errno: posix.E = .SUCCESS;
    for (&admitted) |*slot| {
        const rc = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
        const fd: i32 = @intCast(rc);
        const connected_errno = posix.errno(sys.connect(fd, @ptrCast(&address), addressLength(&address)));
        switch (connected_errno) {
            .SUCCESS => {
                slot.* = fd;
                count += 1;
            },
            .AGAIN, .INPROGRESS, .CONNREFUSED => {
                backlog_errno = connected_errno;
                runtime.close(fd);
                full = true;
                break;
            },
            else => {
                runtime.close(fd);
                return error.BacklogPrecondition;
            },
        }
    }
    try std.testing.expect(full and count > 0);
    try requireDescriptorCoverage(&childDescriptorSet()); // Fail, never skip, if not covered.
    std.debug.print("N1 full-backlog actual admitted={d} saturation_errno={any}\n", .{ count, backlog_errno });
    const pair = try socketPair();
    defer for (pair) |fd| runtime.close(fd);
    var child = try OwnedChild.fork();
    if (child.pid == 0) {
        runtime.close(pair[0]);
        const before = childDescriptorSet();
        requireDescriptorCoverage(&before) catch childExit(47);
        const result = connectRoot(&fixture.bootstrap.state.context);
        if (result) |unexpected| {
            runtime.close(unexpected);
            childExit(43);
        } else |err| {
            // BSD Unix backlog admission may refuse synchronously. That is a
            // bounded failure, distinct from a pending nonblocking connection.
            const expected = if (backlog_errno == .CONNREFUSED) error.SocketFailed else error.WouldBlock;
            if (err != expected) childExit(44);
        }
        if (!std.mem.eql(bool, &before, &childDescriptorSet())) childExit(45);
        send(pair[1], "full-backlog-refused-owned-fd-closed", &.{}) catch childExit(46);
        childExit(0);
    }
    defer child.deinit();
    var observed = try receiveReady(pair[0]);
    defer observed.deinit();
    try std.testing.expectEqualStrings("full-backlog-refused-owned-fd-closed", observed.bytes());
    try expectChildSuccessBounded(&child);
    try std.testing.expect(runtime.fdValid(fixture.bootstrap.listener));
    try fixture.bootstrap.lease.validate(&fixture.bootstrap.ns, lease_name);
    // Every pre-admitted peer remains queued: no failed operation stole a slot.
    for (0..count) |_| {
        const accepted = try acceptRoot(fixture.bootstrap.listener);
        runtime.close(accepted);
    }
    try std.testing.expectError(error.WouldBlock, acceptRoot(fixture.bootstrap.listener));
    const client = try connectRoot(&fixture.bootstrap.state.context);
    defer runtime.close(client);
    try std.testing.expect((@as(posix.O, @bitCast(try fixtureStatusFlags(client)))).NONBLOCK);
    try requireRootPeer(client);
    const accepted = try acceptRoot(fixture.bootstrap.listener);
    defer runtime.close(accepted);
    try send(client, "available-retry", &.{});
    var retry = try Message.receiveRoot(accepted);
    defer retry.deinit();
    try std.testing.expectEqualStrings("available-retry", retry.bytes());
}

test "native service N1 actual listener boolean and canonical named address reject nonlistener and wrong path" {
    // Raw-fd socket() has no libc-free Windows mapping yet.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fixture = try RootFixture.init();
    defer fixture.deinit();
    var buffer: [max_path]u8 = undefined;
    const path = try Path.init(try std.fmt.bufPrint(&buffer, "{s}/abi.sock", .{fixture.path.bytes()}));
    var address = try unixAddress(&path);
    const rc = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    const fd: i32 = @intCast(rc);
    defer runtime.close(fd);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&address), addressLength(&address))));
    var listening: u32 = 99;
    try getOption(fd, posix.SO.ACCEPTCONN, &listening);
    try std.testing.expectEqual(@as(u32, 0), listening);
    // It is a bound, correctly typed/named, nonblocking socket, but not yet a listener.
    try std.testing.expectError(error.BadDescriptor, inspectListener(fd, &path));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.listen(fd, 8)));
    try getOption(fd, posix.SO.ACCEPTCONN, &listening);
    const expected_boolean: u32 = if (builtin.os.tag == .openbsd) 2 else 1;
    try std.testing.expectEqual(expected_boolean, listening);
    var named: posix.sockaddr.un = .{ .path = @splat(0) };
    var length: posix.socklen_t = @sizeOf(posix.sockaddr.un);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&named), &length)));
    const expected_length: posix.socklen_t = if (builtin.os.tag == .openbsd) @sizeOf(posix.sockaddr.un) else addressLength(&address);
    try std.testing.expectEqual(expected_length, length);
    if (comptime builtin.os.tag == .openbsd) try std.testing.expectEqual(length, @as(posix.socklen_t, named.len));
    try std.testing.expectEqual(posix.AF.UNIX, named.family);
    try std.testing.expectEqualSlices(u8, &address.path, &named.path);
    try std.testing.expectEqualDeep((try statAt(fd, null)).identity, try inspectListener(fd, &path));
    try std.testing.expectError(error.BadDescriptor, inspectListener(fd, &fixture.bootstrap.state.context.endpoint));
    std.debug.print("N1 actual listener ABI boolean={d} namedlen={d} pathname_extent={d}\n", .{ listening, length, addressLength(&address) });
}
