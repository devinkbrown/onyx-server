// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Root-managed OpenBSD service launch/control. A launch grant transfers the
//! listener/lease to the real daemon; timeout after that cut never kills it.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const service = @import("native_service.zig");
const kernel = @import("kernel_other.zig");
const runtime = @import("os_runtime.zig");
const platform = @import("../substrate/platform.zig");
const control = @import("helix/native_control.zig");
const snapshot = @import("helix/native_service_snapshot.zig");

pub const child_arg = "--onyx-service-child-v1";
pub const managed_arg = "--onyx-service-managed-v1";
pub const activation_arg = "--onyx-activate-v1";
pub const policy_version: u16 = 1;
pub const managed_policy_version: u16 = 2;
pub const group_max = 16; // OpenBSD sys/syslimits.h NGROUPS_MAX, not a truncation.
pub const limit_count = 9;
pub const max_spec_wire = 33 + 4 * (2 + service.max_path) + 2 * (1 + 63) + 12 + 1 + group_max * 4 + limit_count * 24;
pub const max_observation_wire = 24 + 1 + group_max * 4 + 4 + 16 + limit_count * 16;
pub const max_managed_policy_wire = 10 + max_spec_wire + max_observation_wire;
pub const Error = service.Error || kernel.ContextError || control.Error || error{
    InvalidPolicy,
    ContextMismatch,
    Timeout,
    NoService,
    ChildFailed,
    ExecFailed,
    ForkFailed,
    IoFailed,
    OutcomeUnknown,
};
pub const Action = enum { check, status, configtest, start, reload, stop, restart };
pub const Purpose = enum(u8) { preflight = 1, serve = 2 };
pub const Outcome = union(enum) { current: service.Reply, status: service.Reply, configured: Loaded, stopped, not_running, pending };
pub const Name = struct {
    data: [63]u8 = @splat(0),
    len: u8 = 0,
    pub fn init(text: []const u8) Error!Name {
        if (text.len == 0 or text.len > 63 or text[0] == '-') return error.InvalidPolicy;
        for (text) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return error.InvalidPolicy;
        var value: Name = .{ .len = @intCast(text.len) };
        @memcpy(value.data[0..text.len], text);
        return value;
    }
    pub fn bytes(self: *const Name) []const u8 {
        return self.data[0..self.len];
    }
    fn validate(self: *const Name) Error!void {
        if (self.len > self.data.len) return error.InvalidPolicy;
        _ = try init(self.bytes());
        for (self.data[self.len..]) |b| if (b != 0) return error.InvalidPolicy;
    }
};
pub const LimitRule = struct { min_soft: u64 = 0, max_soft: u64 = std.math.maxInt(u64), max_hard: u64 = std.math.maxInt(u64) };
pub const Limit = struct { soft: u64, hard: u64 };
pub const ServiceSpec = struct {
    helper: service.Path,
    executable: service.Path,
    config: service.Path,
    cwd: service.Path,
    user: Name,
    class: Name,
    uid: u32,
    gid: u32,
    groups: [group_max]u32 = @splat(0),
    group_count: u8 = 0,
    rtable: u32 = 0,
    limits: [limit_count]LimitRule = @splat(.{}),
    pub fn validate(self: *const ServiceSpec) Error!void {
        for ([_]*const service.Path{ &self.helper, &self.executable, &self.config, &self.cwd }) |p| try p.validate();
        try self.user.validate();
        try self.class.validate();
        if (self.uid == 0 or self.gid == 0 or self.rtable > 255 or self.group_count > group_max) return error.InvalidPolicy;
        for (self.groups[0..self.group_count], 0..) |g, i| if (i > 0 and self.groups[i - 1] >= g) return error.InvalidPolicy;
        for (self.groups[self.group_count..]) |g| if (g != 0) return error.InvalidPolicy;
        for (self.limits) |l| if (l.min_soft > l.max_soft or l.max_soft > l.max_hard) return error.InvalidPolicy;
    }
};
pub const Observation = struct {
    uid: [3]u32,
    gid: [3]u32,
    groups: [group_max]u32,
    group_count: u8,
    rtable: u32,
    cwd: service.FileIdentity,
    limits: [limit_count]Limit,
};
pub const LoadedConfig = struct { config_commitment: service.Digest, listener_ports: [7]u16 };
pub const Loaded = struct { config_commitment: service.Digest, listener_ports: [7]u16, observation: Observation };
pub const ObservationPhase = enum { child, daemon };
pub const ManagedPolicy = struct { spec: ServiceSpec, observation: Observation };
const Kind = enum(u8) { child_policy = 1, child_observed, daemon_policy, loaded };
const Policy = struct { spec: ServiceSpec, purpose: Purpose, nonce: service.Id, deadline: i64 };
const Wire = struct { bytes: [service.max_packet]u8 = undefined, len: usize = 0 };
const Writer = struct {
    wire: *Wire,
    fn bytes(self: *Writer, value: []const u8) Error!void {
        if (value.len > self.wire.bytes.len - self.wire.len) return error.TooLarge;
        @memcpy(self.wire.bytes[self.wire.len..][0..value.len], value);
        self.wire.len += value.len;
    }
    fn int(self: *Writer, comptime T: type, n: T) Error!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, n, .little);
        try self.bytes(&b);
    }
    fn path(self: *Writer, p: *const service.Path) Error!void {
        try self.int(u16, p.len);
        try self.bytes(p.bytes());
    }
    fn name(self: *Writer, n: *const Name) Error!void {
        try self.int(u8, n.len);
        try self.bytes(n.bytes());
    }
};
const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,
    fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.bytes.len - self.offset) return error.InvalidWire;
        const v = self.bytes[self.offset..][0..len];
        self.offset += len;
        return v;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn path(self: *Reader) Error!service.Path {
        return service.Path.init(try self.take(try self.int(u16)));
    }
    fn name(self: *Reader) Error!Name {
        return Name.init(try self.take(try self.int(u8)));
    }
    fn done(self: *const Reader) Error!void {
        if (self.offset != self.bytes.len) return error.InvalidWire;
    }
};
fn header(w: *Writer, kind: Kind, nonce: service.Id) Error!void {
    try w.bytes("NSHP");
    try w.int(u16, policy_version);
    try w.int(u8, @intFromEnum(kind));
    try w.int(u8, 0);
    try w.bytes(&nonce);
}
fn readHeader(r: *Reader, kind: Kind) Error!service.Id {
    if (!std.mem.eql(u8, try r.take(4), "NSHP") or try r.int(u16) != policy_version or try r.int(u8) != @intFromEnum(kind) or try r.int(u8) != 0) return error.InvalidWire;
    const id = (try r.take(16))[0..16].*;
    if (std.mem.allEqual(u8, &id, 0)) return error.InvalidWire;
    return id;
}
fn encodePolicy(policy: *const Policy, kind: Kind) Error!Wire {
    try policy.spec.validate();
    if (policy.deadline <= 0 or std.mem.allEqual(u8, &policy.nonce, 0)) return error.InvalidPolicy;
    var wire: Wire = .{};
    var w: Writer = .{ .wire = &wire };
    try header(&w, kind, policy.nonce);
    try w.int(u8, @intFromEnum(policy.purpose));
    try w.int(i64, policy.deadline);
    const s = &policy.spec;
    for ([_]*const service.Path{ &s.helper, &s.executable, &s.config, &s.cwd }) |p| try w.path(p);
    try w.name(&s.user);
    try w.name(&s.class);
    try w.int(u32, s.uid);
    try w.int(u32, s.gid);
    try w.int(u32, s.rtable);
    try w.int(u8, s.group_count);
    for (s.groups[0..s.group_count]) |g| try w.int(u32, g);
    for (s.limits) |l| {
        try w.int(u64, l.min_soft);
        try w.int(u64, l.max_soft);
        try w.int(u64, l.max_hard);
    }
    return wire;
}
fn decodePolicy(bytes: []const u8, kind: Kind) Error!Policy {
    if (bytes.len > service.max_packet) return error.TooLarge;
    var r: Reader = .{ .bytes = bytes };
    const nonce = try readHeader(&r, kind);
    const purpose = std.enums.fromInt(Purpose, try r.int(u8)) orelse return error.InvalidWire;
    const deadline = try r.int(i64);
    var s: ServiceSpec = .{ .helper = try r.path(), .executable = try r.path(), .config = try r.path(), .cwd = try r.path(), .user = try r.name(), .class = try r.name(), .uid = try r.int(u32), .gid = try r.int(u32), .rtable = try r.int(u32) };
    s.group_count = try r.int(u8);
    if (s.group_count > group_max) return error.InvalidWire;
    for (s.groups[0..s.group_count]) |*g| g.* = try r.int(u32);
    for (&s.limits) |*l| l.* = .{ .min_soft = try r.int(u64), .max_soft = try r.int(u64), .max_hard = try r.int(u64) };
    try r.done();
    try s.validate();
    if (deadline <= 0) return error.InvalidWire;
    return .{ .spec = s, .purpose = purpose, .nonce = nonce, .deadline = deadline };
}
fn putObservation(w: *Writer, value: *const Observation) Error!void {
    for (value.uid) |v| try w.int(u32, v);
    for (value.gid) |v| try w.int(u32, v);
    try w.int(u8, value.group_count);
    for (value.groups[0..value.group_count]) |g| try w.int(u32, g);
    try w.int(u32, value.rtable);
    try w.int(u64, value.cwd.device);
    try w.int(u64, value.cwd.inode);
    for (value.limits) |l| {
        try w.int(u64, l.soft);
        try w.int(u64, l.hard);
    }
}
fn getObservation(r: *Reader) Error!Observation {
    var o: Observation = undefined;
    for (&o.uid) |*v| v.* = try r.int(u32);
    for (&o.gid) |*v| v.* = try r.int(u32);
    o.group_count = try r.int(u8);
    if (o.group_count > group_max) return error.InvalidWire;
    o.groups = @splat(0);
    for (o.groups[0..o.group_count]) |*v| v.* = try r.int(u32);
    o.rtable = try r.int(u32);
    o.cwd = .{ .device = try r.int(u64), .inode = try r.int(u64) };
    for (&o.limits) |*l| l.* = .{ .soft = try r.int(u64), .hard = try r.int(u64) };
    return o;
}
fn waitFd(fd: i32, writing: bool, deadline: i64) Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    var polls = [_]posix.pollfd{.{ .fd = fd, .events = if (writing) posix.POLL.OUT else posix.POLL.IN, .revents = 0 }};
    while (true) {
        const now = platform.monotonicMillis();
        if (now >= deadline) return error.Timeout;
        const rc = sys.poll(&polls, 1, @intCast(@min(deadline - now, std.math.maxInt(c_int))));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.Timeout;
                if (polls[0].revents & polls[0].events != 0) return;
                return error.ReceiveFailed;
            },
            .INTR => continue,
            else => return error.ReceiveFailed,
        }
    }
}
fn sendPacket(fd: i32, bytes: []const u8, descriptors: []const i32, deadline: i64) Error!void {
    // One syscall per deadline check; unlike the general N1 helper, no hidden
    // unbounded EINTR loop can outlive the caller's absolute deadline.
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    const hsize = comptime std.mem.alignForward(usize, @sizeOf(sys.cmsghdr), @sizeOf(usize));
    if (bytes.len == 0 or bytes.len > service.max_packet or descriptors.len > 2) return error.TooLarge;
    var ancillary: [hsize + 8]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    if (descriptors.len > 0) {
        const h: *sys.cmsghdr = @ptrCast(&ancillary);
        h.* = .{ .len = @intCast(hsize + descriptors.len * 4), .level = posix.SOL.SOCKET, .type = sys.SCM.RIGHTS };
        @memcpy(ancillary[hsize..][0 .. descriptors.len * 4], std.mem.sliceAsBytes(descriptors));
    }
    var iov: posix.iovec_const = .{ .base = bytes.ptr, .len = bytes.len };
    const msg: sys.msghdr_const = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = if (descriptors.len == 0) null else &ancillary, .controllen = if (descriptors.len == 0) 0 else @intCast(hsize + std.mem.alignForward(usize, descriptors.len * 4, @sizeOf(usize))), .flags = 0 };
    while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        const rc = sys.sendmsg(fd, &msg, posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (@as(usize, @intCast(rc)) != bytes.len) return error.OutcomeUnknown;
                return;
            },
            .INTR => continue,
            .AGAIN => try waitFd(fd, true, deadline),
            else => {
                // Causal-only observer: record the actual failed syscall, never
                // substitute its return value or production classification.
                if (comptime builtin.is_test) if (query_send_fixture) |fixture| {
                    if (fixture.active_fd == fd) {
                        fixture.failed_sends += 1;
                        fixture.failed_rc = @intCast(rc);
                        fixture.failed_errno = posix.errno(rc);
                    }
                };
                return error.SendFailed;
            },
        }
    }
}
fn receivePacket(fd: i32, deadline: i64) Error!service.Message {
    return receiveDescriptors(fd, deadline, 0);
}
fn receiveDescriptors(fd: i32, deadline: i64, expected: usize) Error!service.Message {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if ((try service.peerCredentials(fd)).uid != 0) return error.WrongPeer;
    const hs = comptime std.mem.alignForward(usize, @sizeOf(sys.cmsghdr), @sizeOf(usize));
    var message: service.Message = .{};
    errdefer message.deinit();
    var ancillary: [hs + 32]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    var iov: posix.iovec = .{ .base = &message.payload, .len = message.payload.len };
    const count: usize = while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        var msg: sys.msghdr = .{ .name = null, .namelen = 0, .iov = @ptrCast(&iov), .iovlen = 1, .control = &ancillary, .controllen = ancillary.len, .flags = 0 };
        const rc = sys.recvmsg(fd, &msg, posix.MSG.DONTWAIT);
        switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => {
                try waitFd(fd, false, deadline);
                continue;
            },
            .SUCCESS => {},
            else => return error.ReceiveFailed,
        }
        // Every delivered descriptor gets close custody even though this
        // helper protocol permits none. Never leak an ancillary rejection.
        var offset: usize = 0;
        const end = @min(ancillary.len, @as(usize, msg.controllen));
        var invalid = false;
        while (offset + @sizeOf(sys.cmsghdr) <= end) {
            const h: *const sys.cmsghdr = @ptrCast(@alignCast(ancillary[offset..].ptr));
            const length: usize = h.len;
            if (length < hs or length > end - offset) {
                invalid = true;
                break;
            }
            if (h.level == posix.SOL.SOCKET and h.type == sys.SCM.RIGHTS) {
                if (length == hs or (length - hs) % 4 != 0) invalid = true;
                var n: usize = hs;
                while (n + 4 <= length) : (n += 4) {
                    const received = std.mem.bytesToValue(i32, ancillary[offset + n ..][0..4]);
                    if (message.fd_count == message.fds.len) {
                        runtime.close(received);
                        invalid = true;
                    } else {
                        message.fds[message.fd_count] = received;
                        message.fd_count += 1;
                    }
                }
            } else invalid = true;
            offset += std.mem.alignForward(usize, length, @sizeOf(usize));
        }
        if (offset < end) invalid = true;
        if (invalid or message.fd_count != expected or rc > message.payload.len or msg.flags & (posix.MSG.TRUNC | posix.MSG.CTRUNC) != 0) return error.InvalidWire;
        // A closed peer may have accepted the operation before its result was
        // received. Preserve transport-loss recovery without accepting a packet.
        if (rc == 0) return error.ReceiveFailed;
        break @intCast(rc);
    };
    for (message.fds[0..message.fd_count]) |fd_value| runtime.setCloexec(fd_value, true) catch return error.BadDescriptor;
    message.length = count;
    return message;
}
fn rootOnly() Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (sys.getuid() != 0 or sys.geteuid() != 0) return error.NotRoot;
}
fn pathZ(path: *const service.Path, storage: *[service.max_path + 1]u8) [:0]const u8 {
    @memcpy(storage[0..path.len], path.bytes());
    storage[path.len] = 0;
    return storage[0..path.len :0];
}
fn identity(st: *const sys.Stat) service.FileIdentity {
    return .{ .device = @intCast(st.dev), .inode = @intCast(st.ino) };
}
fn statFd(fd: i32) Error!sys.Stat {
    var st: sys.Stat = undefined;
    if (posix.errno(sys.fstat(fd, &st)) != .SUCCESS) return error.IoFailed;
    return st;
}
fn rootDirectory(fd: i32) Error!void {
    const s = try statFd(fd);
    if (s.uid != 0 or (s.mode & posix.S.IFMT) != posix.S.IFDIR or s.mode & 0o022 != 0) return error.Namespace;
}
fn openDir(parent: i32, name: [:0]const u8) Error!i32 {
    const rc = sys.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(posix.mode_t, 0));
    if (posix.errno(rc) != .SUCCESS) return error.Namespace;
    return @intCast(rc);
}
fn namespace(create: bool) Error!service.RootNamespace {
    try rootOnly();
    var fd = try openDir(posix.AT.FDCWD, "/");
    defer runtime.close(fd);
    try rootDirectory(fd);
    for ([_][:0]const u8{ "var", "run" }) |part| {
        const next = try openDir(fd, part);
        runtime.close(fd);
        fd = next;
        try rootDirectory(fd);
    }
    var created = false;
    if (create) {
        const rc = sys.mkdirat(fd, "onyx_server", @as(posix.mode_t, 0o755));
        if (posix.errno(rc) != .SUCCESS and posix.errno(rc) != .EXIST) return error.Namespace;
        created = posix.errno(rc) == .SUCCESS;
    }
    const rc = sys.openat(fd, "onyx_server", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(posix.mode_t, 0));
    if (posix.errno(rc) == .NOENT and !create) return error.NoService;
    if (posix.errno(rc) != .SUCCESS) return error.Namespace;
    const owned: i32 = @intCast(rc);
    defer runtime.close(owned);
    try rootDirectory(owned);
    // mkdir is affected by the invoking root's umask. Set exact0755 only for
    // the directory this invocation created; never repair a preexisting node.
    if (created and posix.errno(sys.fchmod(owned, @as(posix.mode_t, 0o755))) != .SUCCESS) return error.Namespace;
    const s = try statFd(owned);
    if (s.uid != 0 or (s.mode & 0o777) != 0o755) return error.Namespace;
    var result = try service.RootNamespace.open();
    errdefer result.deinit();
    const reopened = try statFd(result.fd);
    if (!std.meta.eql(identity(&s), identity(&reopened))) return error.StateChanged;
    return result;
}
fn openProtectedFile(path: *const service.Path, executable: bool) Error!i32 {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    try path.validate();
    var fd = try openDir(posix.AT.FDCWD, "/");
    defer runtime.close(fd);
    try rootDirectory(fd);
    var parts = std.mem.splitScalar(u8, path.bytes()[1..], '/');
    var buf: [service.max_path + 1]u8 = undefined;
    while (parts.next()) |part| {
        @memcpy(buf[0..part.len], part);
        buf[part.len] = 0;
        const name = buf[0..part.len :0];
        if (parts.peek() != null) {
            const next = try openDir(fd, name);
            runtime.close(fd);
            fd = next;
            try rootDirectory(fd);
            continue;
        }
        const rc = sys.openat(fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, @as(posix.mode_t, 0));
        if (posix.errno(rc) != .SUCCESS) return error.InvalidPolicy;
        const file: i32 = @intCast(rc);
        errdefer runtime.close(file);
        const st = try statFd(file);
        if (st.uid != 0 or st.mode & 0o022 != 0 or (st.mode & posix.S.IFMT) != posix.S.IFREG or (executable and (st.mode & 0o6000 != 0 or st.mode & 0o111 == 0))) return error.InvalidPolicy;
        return file;
    }
    return error.InvalidPolicy;
}
fn protectedFile(path: *const service.Path, executable: bool) Error!void {
    const fd = try openProtectedFile(path, executable);
    runtime.close(fd);
}
/// Returns actual process observations, not a service readiness capability.
pub fn observeManagedContext(allocator: std.mem.Allocator, io: std.Io, s: *const ServiceSpec, phase: ObservationPhase) !Observation {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    try s.validate();
    var o: Observation = .{ .uid = undefined, .gid = undefined, .groups = @splat(0), .group_count = 0, .rtable = try kernel.openBsdRoutingTable(), .cwd = undefined, .limits = undefined };
    if (posix.errno(sys.getresuid(&o.uid[0], &o.uid[1], &o.uid[2])) != .SUCCESS or posix.errno(sys.getresgid(&o.gid[0], &o.gid[1], &o.gid[2])) != .SUCCESS) return error.ObservationFailed;
    const groups = try kernel.openBsdGroups(&o.groups);
    o.group_count = @intCast(groups.len);
    std.mem.sort(u32, groups, {}, std.sort.asc(u32));
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    if (!std.mem.eql(u8, cwd, s.cwd.bytes())) return error.ContextMismatch;
    const fd = try openDir(posix.AT.FDCWD, ".");
    defer runtime.close(fd);
    const st = try statFd(fd);
    o.cwd = identity(&st);
    for (&o.limits, 0..) |*l, i| {
        var v: sys.rlimit = undefined;
        if (posix.errno(sys.getrlimit(@enumFromInt(i), &v)) != .SUCCESS) return error.ObservationFailed;
        l.* = .{ .soft = @intCast(v.cur), .hard = @intCast(v.max) };
    }
    try validateManagedObservation(s, &o, phase);
    return o;
}
pub fn validateManagedObservation(s: *const ServiceSpec, o: *const Observation, phase: ObservationPhase) Error!void {
    try s.validate();
    if (o.group_count > group_max) return error.ContextMismatch;
    for (o.groups[o.group_count..]) |g| if (g != 0) return error.ContextMismatch;
    for (o.uid) |v| if (v != s.uid) return error.ContextMismatch;
    for (o.gid) |v| if (v != s.gid) return error.ContextMismatch;
    if (o.group_count != s.group_count or o.rtable != s.rtable or o.cwd.inode == 0 or !std.mem.eql(u32, o.groups[0..o.group_count], s.groups[0..s.group_count])) return error.ContextMismatch;
    for (o.limits, s.limits) |l, r| if (l.soft > l.hard or l.soft < r.min_soft or l.soft > r.max_soft or l.hard > r.max_hard) return error.ContextMismatch;
    if (phase == .daemon and o.limits[8].soft != o.limits[8].hard) return error.ContextMismatch;
}

const ManagedBacking = struct { allocator: std.mem.Allocator, fd: i32, policy: Policy, observed: Observation, loaded: ?LoadedConfig = null, consumed: bool = false };
pub const ManagedPrelude = opaque {
    fn backing(self: *ManagedPrelude) *ManagedBacking {
        return @ptrCast(@alignCast(self));
    }
    pub fn spec(self: *ManagedPrelude) ServiceSpec {
        return self.backing().policy.spec;
    }
    pub fn purpose(self: *ManagedPrelude) Purpose {
        return self.backing().policy.purpose;
    }
    pub fn observation(self: *ManagedPrelude) Observation {
        return self.backing().observed;
    }
    pub fn deinit(self: *ManagedPrelude) void {
        const b = self.backing();
        runtime.close(b.fd);
        const a = b.allocator;
        a.destroy(b);
    }
    pub fn reportLoaded(self: *ManagedPrelude, loaded: LoadedConfig) Error!void {
        const b = self.backing();
        if (b.loaded != null or b.consumed or std.mem.allEqual(u8, &loaded.config_commitment, 0)) return error.InvalidState;
        var wire: Wire = .{};
        var w: Writer = .{ .wire = &wire };
        try header(&w, .loaded, b.policy.nonce);
        try putObservation(&w, &b.observed);
        try w.bytes(&loaded.config_commitment);
        for (loaded.listener_ports) |p| try w.int(u16, p);
        try sendPacket(b.fd, wire.bytes[0..wire.len], &.{}, b.policy.deadline);
        b.loaded = loaded;
    }
    pub fn finishPreflight(self: *ManagedPrelude) Error!void {
        const b = self.backing();
        if (b.policy.purpose != .preflight or b.loaded == null or b.consumed) return error.InvalidState;
        b.consumed = true;
    }
    pub fn receiveBootstrap(self: *ManagedPrelude) Error!service.Incoming {
        const b = self.backing();
        const loaded = b.loaded orelse return error.InvalidState;
        if (b.policy.purpose != .serve or b.consumed) return error.InvalidState;
        {
            var message = try receiveDescriptors(b.fd, b.policy.deadline, 2);
            defer message.deinit();
            const state = try snapshot.decode(message.bytes());
            if (state.phase != .starting) return error.InvalidState;
            try service.validateDescriptors(message.fds[0], message.fds[1], &state.context);
            var incoming: service.Incoming = .{ .listener = message.fds[0], .lease = .{ .fd = message.fds[1], .identity = state.context.lease_identity }, .state = state };
            message.fd_count = 0;
            errdefer incoming.deinit();
            const c = &incoming.state.context;
            const s = &b.policy.spec;
            if (!std.meta.eql(c.executable, s.executable) or !std.meta.eql(c.config, s.config) or !std.meta.eql(c.cwd, s.cwd) or c.uid != s.uid or c.gid != s.gid or c.rtable != s.rtable or !std.mem.eql(u8, &c.config_commitment, &loaded.config_commitment) or !std.mem.eql(u16, &c.listener_ports, &loaded.listener_ports)) return error.ContextMismatch;
            if (!std.meta.eql(c.managed_spec, s.*) or !std.meta.eql(c.managed_observation, b.observed)) return error.ContextMismatch;
            b.consumed = true;
            return incoming;
        }
    }
};
pub fn receiveManaged(allocator: std.mem.Allocator, io: std.Io, fd: i32, first_deadline: i64) !*ManagedPrelude {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (fd != 3) return error.BadDescriptor;
    try runtime.setCloexec(fd, true);
    try runtime.setNonblocking(fd);
    var message = try receivePacket(fd, first_deadline);
    defer message.deinit();
    const policy = try decodePolicy(message.bytes(), .daemon_policy);
    if (platform.monotonicMillis() >= policy.deadline) return error.Timeout;
    const observed = try observeManagedContext(allocator, io, &policy.spec, .daemon);
    const b = try allocator.create(ManagedBacking);
    b.* = .{ .allocator = allocator, .fd = fd, .policy = policy, .observed = observed };
    return @ptrCast(b);
}

/// The su child consumes only the helper policy. The daemon subsequently receives
/// a separate root policy and the root's ORIGINAL Bootstrap directly on fd3.
pub fn runChild(allocator: std.mem.Allocator, io: std.Io, fd: i32, environ: std.process.Environ, first_deadline: i64) !noreturn {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    if (fd != 3) return error.BadDescriptor;
    var message = try receivePacket(fd, first_deadline);
    defer message.deinit();
    const policy = try decodePolicy(message.bytes(), .child_policy);
    if (platform.monotonicMillis() >= policy.deadline) return error.Timeout;
    const observed = try observeManagedContext(allocator, io, &policy.spec, .child);
    try protectedFile(&policy.spec.executable, true);
    var wire: Wire = .{};
    var w: Writer = .{ .wire = &wire };
    try header(&w, .child_observed, policy.nonce);
    try putObservation(&w, &observed);
    try sendPacket(fd, wire.bytes[0..wire.len], &.{}, policy.deadline);
    const executable = try allocator.dupeSentinel(u8, policy.spec.executable.bytes(), 0);
    defer allocator.free(executable);
    const argv = [_:null]?[*:0]const u8{ executable.ptr, activation_arg, managed_arg, "3" };
    var env = try std.process.Environ.createPosixBlock(environ, allocator, .{ .zig_progress_fd = -1 });
    defer env.deinit(allocator);
    try kernel.openBsdCloseFrom(4);
    try runtime.setCloexec(fd, false);
    _ = sys.execve(executable, &argv, env.slice.ptr);
    return error.ExecFailed;
}

const Child = struct {
    pid: i32 = -1,
    fd: i32 = -1,
    grant_attempted: bool = false,
    observation: Observation = undefined,
    fn deinit(self: *Child) void {
        if (comptime builtin.os.tag != .openbsd) return;
        runtime.close(self.fd);
        self.fd = -1;
        if (self.pid > 0 and !self.grant_attempted) {
            // Unreaped own child only; an observed exit is reaped here as well.
            _ = sys.kill(self.pid, posix.SIG.KILL);
            while (true) {
                const rc = sys.waitpid(self.pid, null, 0);
                if (posix.errno(rc) != .INTR) break;
            }
        } else if (self.pid > 0) {
            _ = sys.waitpid(self.pid, null, posix.W.NOHANG);
        }
        self.pid = -1;
    }
};
fn resetChildSignals() Error!void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    var empty: sys.sigset_t = undefined;
    if (sys.sigemptyset(&empty) != 0) return error.IoFailed;
    const action: sys.Sigaction = .{ .handler = .{ .handler = sys.SIG.DFL }, .mask = empty, .flags = 0 };
    for (1..sys.NSIG) |number| {
        const signal: sys.SIG = @enumFromInt(number);
        // OpenBSD reserves SIGTHR (32) for libc thread cancellation; public
        // sigaction may reject it. It is not a service launch signal.
        if (signal == .KILL or signal == .STOP or number == 32) continue;
        if (sys.sigaction(signal, &action, null) != 0) return error.IoFailed;
    }
    if (sys.sigprocmask(sys.SIG.SETMASK, &empty, null) != 0) return error.IoFailed;
}
fn spawn(allocator: std.mem.Allocator, policy: *const Policy) !Child {
    try rootOnly();
    var child_action: sys.Sigaction = undefined;
    if (sys.sigaction(.CHLD, null, &child_action) != 0 or child_action.handler.handler != sys.SIG.DFL or child_action.flags & sys.SA.NOCLDWAIT != 0) return error.InvalidState;
    for (0..3) |n| if (sys.fcntl(@intCast(n), posix.F.GETFD, @as(c_int, 0)) < 0) return error.BadDescriptor;
    try policy.spec.validate();
    try protectedFile(&policy.spec.helper, true);
    try protectedFile(&policy.spec.executable, true);
    try protectedFile(&policy.spec.config, false);
    var pair = try control.Pair.init();
    defer pair.deinit();
    const helper = try allocator.dupeSentinel(u8, policy.spec.helper.bytes(), 0);
    defer allocator.free(helper);
    const user = try allocator.dupeSentinel(u8, policy.spec.user.bytes(), 0);
    defer allocator.free(user);
    const class = try allocator.dupeSentinel(u8, policy.spec.class.bytes(), 0);
    defer allocator.free(class);
    const argv = [_:null]?[*:0]const u8{ "/usr/bin/su", "-l", "-c", class, "-s", helper, user, child_arg, "3" };
    const env = [_:null]?[*:0]const u8{};
    const null_rc = sys.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, @as(posix.mode_t, 0));
    if (posix.errno(null_rc) != .SUCCESS) return error.IoFailed;
    const null_fd: i32 = @intCast(null_rc);
    defer runtime.close(null_fd);
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        resetChildSignals() catch sys._exit(127);
        // Pair descriptors are >=3 because the CLI keeps0/1/2 open. Preserve the
        // channel before duplicating null over stdio; it cannot alias null_fd.
        _ = sys.close(pair.parent);
        for (0..3) |n| if (sys.dup2(null_fd, @intCast(n)) < 0) sys._exit(127);
        if (pair.child != 3 and sys.dup2(pair.child, 3) < 0) sys._exit(127);
        kernel.openBsdCloseFrom(4) catch sys._exit(127);
        if (sys.fcntl(3, posix.F.SETFD, @as(c_int, 0)) != 0 or sys.setsid() < 0) sys._exit(127);
        _ = sys.execve("/usr/bin/su", &argv, &env);
        sys._exit(127);
    }
    runtime.close(pair.child);
    pair.child = -1;
    var child: Child = .{ .pid = pid, .fd = pair.parent };
    pair.parent = -1;
    errdefer child.deinit();
    const wire = try encodePolicy(policy, .child_policy);
    try sendPacket(child.fd, wire.bytes[0..wire.len], &.{}, policy.deadline);
    var observed_packet = try receivePacket(child.fd, policy.deadline);
    defer observed_packet.deinit();
    var r: Reader = .{ .bytes = observed_packet.bytes() };
    const nonce = try readHeader(&r, .child_observed);
    if (!std.mem.eql(u8, &nonce, &policy.nonce)) return error.InvalidWire;
    const observed = try getObservation(&r);
    try r.done();
    try validateManagedObservation(&policy.spec, &observed, .child);
    child.observation = observed;
    const main_policy = try encodePolicy(policy, .daemon_policy);
    try sendPacket(child.fd, main_policy.bytes[0..main_policy.len], &.{}, policy.deadline);
    return child;
}
fn loadedFrom(child: *Child, policy: *const Policy) Error!Loaded {
    var message = try receivePacket(child.fd, policy.deadline);
    defer message.deinit();
    var r: Reader = .{ .bytes = message.bytes() };
    const nonce = try readHeader(&r, .loaded);
    if (!std.mem.eql(u8, &nonce, &policy.nonce)) return error.InvalidWire;
    const observed = try getObservation(&r);
    try validateManagedObservation(&policy.spec, &observed, .daemon);
    try compareDaemonObservation(&child.observation, &observed);
    var loaded: Loaded = .{ .config_commitment = (try r.take(32))[0..32].*, .listener_ports = undefined, .observation = observed };
    for (&loaded.listener_ports) |*p| p.* = try r.int(u16);
    try r.done();
    if (std.mem.allEqual(u8, &loaded.config_commitment, 0)) return error.InvalidWire;
    return loaded;
}
fn policyFor(spec: ServiceSpec, purpose: Purpose, deadline: i64) Error!Policy {
    try spec.validate();
    if (platform.monotonicMillis() >= deadline) return error.Timeout;
    var nonce: service.Id = undefined;
    platform.fillOsEntropy(&nonce) catch return error.RandomSourceFailed;
    if (std.mem.allEqual(u8, &nonce, 0)) return error.RandomSourceFailed;
    return .{ .spec = spec, .purpose = purpose, .nonce = nonce, .deadline = deadline };
}
fn preflight(allocator: std.mem.Allocator, spec: ServiceSpec, deadline: i64) !Loaded {
    const p = try policyFor(spec, .preflight, deadline);
    var child = try spawn(allocator, &p);
    defer child.deinit();
    const loaded = try loadedFrom(&child, &p);
    // A successful payload is insufficient: require real daemon preflight exit0.
    while (true) {
        var status: c_int = 0;
        const rc = sys.waitpid(child.pid, &status, posix.W.NOHANG);
        if (rc == child.pid) {
            child.pid = -1;
            if (!posix.W.IFEXITED(@bitCast(status)) or posix.W.EXITSTATUS(@bitCast(status)) != 0) return error.ChildFailed;
            return loaded;
        }
        if (rc < 0 and posix.errno(rc) != .INTR) return error.ChildFailed;
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        // Bounded poll yields to child exit without any new timeout budget.
        var none: [0]posix.pollfd = .{};
        _ = sys.poll(&none, 0, 1);
    }
}

fn endpointNode(ns: *const service.RootNamespace) Error!?service.FileIdentity {
    var st: sys.Stat = undefined;
    const rc = sys.fstatat(ns.fd, service.endpoint_name, &st, posix.AT.SYMLINK_NOFOLLOW);
    if (posix.errno(rc) == .NOENT) return null;
    if (posix.errno(rc) != .SUCCESS) return error.Namespace;
    if (st.uid != 0 or st.mode & 0o777 != 0o600 or (st.mode & posix.S.IFMT) != posix.S.IFSOCK) return error.Namespace;
    return identity(&st);
}
fn connectCurrent(ns: *const service.RootNamespace) Error!i32 {
    const before = (try endpointNode(ns)) orelse return error.NoService;
    const path = try ns.endpoint();
    var address: posix.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return error.TooLarge;
    @memcpy(address.path[0..path.len], path.bytes());
    const len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    if (comptime @hasField(posix.sockaddr.un, "len")) address.len = @intCast(len);
    const rc = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer runtime.close(fd);
    switch (posix.errno(sys.connect(fd, @ptrCast(&address), len))) {
        .SUCCESS => {},
        .AGAIN, .INPROGRESS, .ALREADY, .INTR => return error.WouldBlock,
        else => return error.SocketFailed,
    }
    if ((try service.peerCredentials(fd)).uid != 0) return error.WrongPeer;
    const after = (try endpointNode(ns)) orelse return error.StateChanged;
    if (!std.meta.eql(before, after)) return error.StateChanged;
    return fd;
}
fn exchange(ns: *const service.RootNamespace, request: service.Request, expected_spec: service.Digest, deadline: i64) Error!service.Reply {
    const fd = try connectCurrent(ns);
    defer runtime.close(fd);
    if (comptime builtin.is_test) if (query_send_fixture) |fixture| {
        if (request.verb == .query) try fixture.beforeQuery(fd, deadline);
    };
    defer if (comptime builtin.is_test) {
        if (query_send_fixture) |fixture| fixture.active_fd = -1;
    };
    const wire = try request.encode();
    try sendPacket(fd, &wire, &.{}, deadline);
    var reply = try receivePacket(fd, deadline);
    defer reply.deinit();
    const decoded = try service.Reply.decode(reply.bytes());
    if (!std.mem.eql(u8, &decoded.managed_spec_commitment, &expected_spec)) return error.ContextMismatch;
    return decoded;
}
fn query(ns: *const service.RootNamespace, incarnation: service.Id, expected_spec: service.Digest, deadline: i64) Error!service.Reply {
    var nonce: service.Id = undefined;
    platform.fillOsEntropy(&nonce) catch return error.RandomSourceFailed;
    const reply = try exchange(ns, .{ .verb = .query, .incarnation = incarnation, .generation = 0, .serial = 0, .nonce = nonce, .candidate_config = @splat(0) }, expected_spec, deadline);
    if (!std.mem.allEqual(u8, &incarnation, 0) and !std.mem.eql(u8, &reply.incarnation, &incarnation)) return error.StateChanged;
    return reply;
}
fn retryPause(deadline: i64) Error!void {
    if (platform.monotonicMillis() >= deadline) return error.Timeout;
    var none: [0]posix.pollfd = .{};
    _ = sys.poll(&none, 0, 1);
}
fn retryableControl(err: anyerror) bool {
    return switch (err) {
        error.SocketFailed, error.SendFailed, error.ReceiveFailed, error.WouldBlock, error.Timeout, error.NoService => true,
        else => false,
    };
}
fn lifetimeReleased(ns: *const service.RootNamespace) Error!bool {
    var lease = ns.acquireLifetime() catch |err| {
        if (err == error.Busy) return false;
        return err;
    };
    lease.deinit();
    return true;
}
/// Used only while the root mutator holds the mutation lease. Null means actual
/// lifetime exclusion, NOT proof that an unobserved stop completed gracefully.
fn ownerOrIdle(ns: *const service.RootNamespace, expected_spec: service.Digest, deadline: i64) Error!?service.Reply {
    while (true) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        return query(ns, @splat(0), expected_spec, deadline) catch |err| {
            if (!retryableControl(err)) return err;
            if (platform.monotonicMillis() >= deadline) return error.Timeout;
            if (try lifetimeReleased(ns)) return null;
            try retryPause(deadline);
            continue;
        };
    }
}
fn stopRequest(reply: service.Reply, expected_spec: service.Digest) Error!service.Request {
    try reply.validate();
    if (!std.mem.eql(u8, &reply.managed_spec_commitment, &expected_spec)) return error.ContextMismatch;
    const last = reply.last orelse return error.InvalidState;
    if (reply.phase != .stopping or last.request.verb != .stop or
        (last.result != .accepted and last.result != .stopped)) return error.InvalidState;
    return last.request;
}
/// The caller already owns an authenticated stopped receipt. The exact ACK has
/// no independent mutation serial and needs no reply; actual lease exclusion is
/// the final observation. Connection loss alone can never complete this path.
fn finishRecordedStop(ns: *const service.RootNamespace, stopped: service.Reply, expected_spec: service.Digest, deadline: i64) Error!Outcome {
    const request = try stopRequest(stopped, expected_spec);
    if (stopped.last.?.result != .stopped) return error.InvalidState;
    const ack: service.StopAck = .{ .request = request, .managed_spec_commitment = expected_spec };
    const bytes = try ack.encode();
    while (true) {
        if (platform.monotonicMillis() >= deadline) return .pending;
        const fd = connectCurrent(ns) catch |err| blk: {
            if (!retryableControl(err)) return err;
            break :blk -1;
        };
        if (fd >= 0) {
            defer runtime.close(fd);
            sendPacket(fd, &bytes, &.{}, deadline) catch |err| {
                if (!retryableControl(err)) return err;
            };
        }
        if (platform.monotonicMillis() >= deadline) return .pending;
        if (try lifetimeReleased(ns)) return .stopped;
        retryPause(deadline) catch return .pending;
        const reply = ownerOrIdle(ns, expected_spec, deadline) catch |err| {
            if (err == error.Timeout) return .pending;
            return err;
        };
        // A stopped receipt is already owned here. If the ACK was consumed and
        // the owner disappeared before a response, exclusion is sufficient.
        const retained = reply orelse return .stopped;
        if (!std.meta.eql(try stopRequest(retained, expected_spec), request) or retained.last.?.result != .stopped)
            return error.StateChanged;
    }
}
fn recoverRecordedStop(ns: *const service.RootNamespace, initial: service.Reply, expected_spec: service.Digest, deadline: i64) Error!Outcome {
    const request = try stopRequest(initial, expected_spec);
    var latest = initial;
    while (true) {
        if (!std.meta.eql(try stopRequest(latest, expected_spec), request)) return error.StateChanged;
        if (latest.last.?.result == .stopped) return finishRecordedStop(ns, latest, expected_spec, deadline);
        retryPause(deadline) catch return .pending;
        const reply = ownerOrIdle(ns, expected_spec, deadline) catch |err| {
            if (err == error.Timeout) return .pending;
            return err;
        };
        // No stopped receipt was received. Preserve the distinction even if
        // the old process released its lease or died while cleanup was pending.
        latest = reply orelse return .not_running;
    }
}
fn start(allocator: std.mem.Allocator, ns: *service.RootNamespace, spec: ServiceSpec, deadline: i64) !Outcome {
    const expected_spec = try serviceSpecDigest(&spec);
    var lease: service.Lease = undefined;
    while (true) {
        if (platform.monotonicMillis() >= deadline) return .pending;
        lease = ns.acquireLifetime() catch |err| {
            if (err != error.Busy) return err;
            const reply = (ownerOrIdle(ns, expected_spec, deadline) catch |observe_err| {
                if (observe_err == error.Timeout) return .pending;
                return observe_err;
            }) orelse continue;
            if (reply.phase == .current) return .{ .current = reply };
            if (reply.phase != .stopping) return error.Busy;
            const recovered = try recoverRecordedStop(ns, reply, expected_spec, deadline);
            if (recovered != .stopped and recovered != .not_running) return recovered;
            continue;
        };
        break;
    }
    defer lease.deinit();
    if (try endpointNode(ns)) |node| try ns.removeOwnedEndpoint(&lease, node);
    const policy = try policyFor(spec, .serve, deadline);
    var child = try spawn(allocator, &policy);
    defer child.deinit();
    const loaded = try loadedFrom(&child, &policy);
    var bootstrap = try service.Bootstrap.acquireFromLease(ns, &lease, .{ .executable = spec.executable, .config = spec.config, .cwd = spec.cwd, .uid = spec.uid, .gid = spec.gid, .rtable = spec.rtable, .config_commitment = loaded.config_commitment, .listener_ports = loaded.listener_ports, .managed_spec = spec, .managed_observation = loaded.observation });
    defer bootstrap.deinit();
    const incarnation = bootstrap.state.context.incarnation;
    const bytes = try snapshot.encode(allocator, &bootstrap.state);
    defer allocator.free(bytes);
    // From this first syscall attempt, disposal is close-only. Even a partial/
    // uncertain result must not let a timeout destroy an already granted child.
    child.grant_attempted = true;
    sendPacket(child.fd, bytes, &.{ bootstrap.listener, bootstrap.lease.fd }, deadline) catch return .pending;
    // Release every helper duplicate, including the shared lease description.
    bootstrap.deinit();
    var current_ns = try namespace(false);
    defer current_ns.deinit();
    while (true) {
        const reply = query(&current_ns, incarnation, expected_spec, deadline) catch |err| switch (err) {
            error.WouldBlock, error.SocketFailed, error.ReceiveFailed, error.NoService => {
                retryPause(deadline) catch return .pending;
                continue;
            },
            error.Timeout => return .pending,
            else => return err,
        };
        if (reply.phase == .current) return .{ .current = reply };
        retryPause(deadline) catch return .pending;
    }
}
fn mutate(ns: *const service.RootNamespace, verb: service.Verb, config_digest: service.Digest, expected_spec: service.Digest, deadline: i64) Error!Outcome {
    var current = (ownerOrIdle(ns, expected_spec, deadline) catch |err| {
        if (err == error.Timeout) return .pending;
        return err;
    }) orelse return .not_running;
    while (current.phase != .current or (current.last != null and current.last.?.result == .accepted)) {
        if (current.phase == .stopping) {
            const recovered = try recoverRecordedStop(ns, current, expected_spec, deadline);
            if (recovered == .stopped and verb == .upgrade) return .not_running;
            return recovered;
        }
        try retryPause(deadline);
        current = try query(ns, current.incarnation, expected_spec, deadline);
    }
    var nonce: service.Id = undefined;
    platform.fillOsEntropy(&nonce) catch return error.RandomSourceFailed;
    const request: service.Request = .{ .verb = verb, .incarnation = current.incarnation, .generation = current.generation, .serial = current.next_serial, .nonce = nonce, .candidate_config = config_digest };
    var latest: ?service.Reply = exchange(ns, request, expected_spec, deadline) catch |err| blk: {
        if (!retryableControl(err)) return err;
        break :blk null;
    };
    while (true) {
        const reply = latest orelse {
            retryPause(deadline) catch return .pending;
            latest = query(ns, request.incarnation, expected_spec, deadline) catch |err| switch (err) {
                error.SocketFailed, error.ReceiveFailed, error.WouldBlock, error.Timeout, error.NoService => null,
                else => return err,
            };
            continue;
        };
        if (!std.mem.eql(u8, &reply.incarnation, &request.incarnation)) return error.StateChanged;
        if (reply.last) |last| if (std.meta.eql(last.request, request)) {
            switch (last.result) {
                .refused => return error.NotCurrent,
                .stopped => {
                    if (verb != .stop) return error.InvalidState;
                    return finishRecordedStop(ns, reply, expected_spec, deadline);
                },
                .succeeded => {
                    if (verb != .upgrade or reply.phase != .current or request.generation == std.math.maxInt(u64) or reply.generation != request.generation + 1) return error.InvalidState;
                    return .{ .current = reply };
                },
                else => {},
            }
        };
        retryPause(deadline) catch return .pending;
        // A connection can fail before the request reaches the owner. Only
        // retry the SAME identity, and only while the authenticated current
        // owner still exposes that exact next serial. Never mint another op.
        latest = if (reply.phase == .current and reply.generation == request.generation and reply.next_serial == request.serial)
            exchange(ns, request, expected_spec, deadline) catch |err| blk: {
                if (!retryableControl(err)) return err;
                break :blk null;
            }
        else
            query(ns, request.incarnation, expected_spec, deadline) catch |err| switch (err) {
                error.SocketFailed, error.ReceiveFailed, error.WouldBlock, error.Timeout, error.NoService => null,
                else => return err,
            };
    }
}
/// Root mutations use one mutation-lock lifetime, including BOTH restart legs.
pub fn runRoot(allocator: std.mem.Allocator, io: std.Io, action: Action, spec: ServiceSpec, deadline: i64) !Outcome {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    _ = io;
    try rootOnly();
    try spec.validate();
    if (platform.monotonicMillis() >= deadline) return error.Timeout;
    if (action == .configtest) return .{ .configured = try preflight(allocator, spec, deadline) };
    const expected_spec = try serviceSpecDigest(&spec);
    var ns = namespace(action == .start or action == .restart) catch |err| {
        if (err == error.NoService) return .not_running;
        return err;
    };
    defer ns.deinit();
    if (action == .check or action == .status) {
        const reply = try query(&ns, @splat(0), expected_spec, deadline);
        if (action == .check and reply.phase != .current) return error.NotCurrent;
        return if (action == .check) .{ .current = reply } else .{ .status = reply };
    }
    var mutation = try ns.acquireMutation();
    defer mutation.deinit();
    return switch (action) {
        .start => start(allocator, &ns, spec, deadline),
        .reload => blk: {
            const loaded = try preflight(allocator, spec, deadline);
            break :blk try mutate(&ns, .upgrade, loaded.config_commitment, expected_spec, deadline);
        },
        .stop => mutate(&ns, .stop, @splat(0), expected_spec, deadline),
        .restart => blk: {
            const stopped = try mutate(&ns, .stop, @splat(0), expected_spec, deadline);
            if (stopped != .stopped and stopped != .not_running) break :blk stopped;
            break :blk try start(allocator, &ns, spec, deadline);
        },
        else => unreachable,
    };
}

fn compareDaemonObservation(before: *const Observation, after: *const Observation) Error!void {
    var allowed = before.*;
    // This is the sole existing main normalization, not an arbitrary fresh
    // policy or an allowance to change another class-derived soft/hard limit.
    allowed.limits[8].soft = allowed.limits[8].hard;
    if (!std.meta.eql(allowed, after.*)) return error.ContextMismatch;
}

/// Root-owned configuration data, not a received launch capability. The same
/// checked geometry is reused, with a distinct magic and canonical constants.
pub fn encodeSpec(allocator: std.mem.Allocator, spec: ServiceSpec) Error![]u8 {
    var wire = try encodePolicy(&.{ .spec = spec, .purpose = .preflight, .nonce = @splat(1), .deadline = 1 }, .child_policy);
    @memcpy(wire.bytes[0..4], "NSCF");
    return allocator.dupe(u8, wire.bytes[0..wire.len]);
}
/// Domain-separated commitment to the complete canonical selected policy.
/// Data only: live owner authority still comes from the authenticated N1 reply.
/// Validation and encoding use bounded stack storage, with no allocator or
/// fallible operation after a Controller caches this from a valid Context.
pub fn serviceSpecDigest(spec: *const ServiceSpec) Error!service.Digest {
    var wire = try encodePolicy(&.{ .spec = spec.*, .purpose = .preflight, .nonce = @splat(1), .deadline = 1 }, .child_policy);
    @memcpy(wire.bytes[0..4], "NSCF");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/native-service/spec-v1\x00");
    hash.update(wire.bytes[0..wire.len]);
    return hash.finalResult();
}
pub fn decodeSpec(bytes: []const u8) Error!ServiceSpec {
    if (bytes.len < 4 or bytes.len > service.max_packet or !std.mem.eql(u8, bytes[0..4], "NSCF")) return error.InvalidWire;
    var wire: Wire = .{ .len = bytes.len };
    @memcpy(wire.bytes[0..bytes.len], bytes);
    @memcpy(wire.bytes[0..4], "NSHP");
    const p = try decodePolicy(wire.bytes[0..wire.len], .child_policy);
    if (p.purpose != .preflight or p.deadline != 1 or !std.mem.allEqual(u8, &p.nonce, 1)) return error.InvalidWire;
    return p.spec;
}
/// Canonical data for the mandatory managed-policy snapshot. It grants no
/// readiness or owner authority; the successor must observe its real process.
pub fn encodeManagedPolicy(allocator: std.mem.Allocator, value: *const ManagedPolicy) Error![]u8 {
    try validateManagedObservation(&value.spec, &value.observation, .daemon);
    var spec_wire = try encodePolicy(&.{ .spec = value.spec, .purpose = .preflight, .nonce = @splat(1), .deadline = 1 }, .child_policy);
    @memcpy(spec_wire.bytes[0..4], "NSCF");
    var wire: Wire = .{};
    var w: Writer = .{ .wire = &wire };
    try w.bytes("NSMP");
    try w.int(u16, managed_policy_version);
    try w.int(u16, 0);
    try w.int(u16, @intCast(spec_wire.len));
    try w.bytes(spec_wire.bytes[0..spec_wire.len]);
    try putObservation(&w, &value.observation);
    return allocator.dupe(u8, wire.bytes[0..wire.len]);
}
pub fn decodeManagedPolicy(bytes: []const u8) Error!ManagedPolicy {
    if (bytes.len > service.max_packet) return error.TooLarge;
    var r: Reader = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try r.take(4), "NSMP") or try r.int(u16) != managed_policy_version or try r.int(u16) != 0) return error.InvalidWire;
    const spec = try decodeSpec(try r.take(try r.int(u16)));
    const observed = try getObservation(&r);
    try r.done();
    try validateManagedObservation(&spec, &observed, .daemon);
    return .{ .spec = spec, .observation = observed };
}
pub fn loadSpec(path: service.Path, deadline: i64) Error!ServiceSpec {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    try rootOnly();
    if (platform.monotonicMillis() >= deadline) return error.Timeout;
    const fd = try openProtectedFile(&path, false);
    defer runtime.close(fd);
    var bytes: [service.max_packet + 1]u8 = undefined;
    var count: usize = 0;
    while (count < bytes.len) {
        if (platform.monotonicMillis() >= deadline) return error.Timeout;
        const rc = sys.read(fd, bytes[count..].ptr, bytes.len - count);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return decodeSpec(bytes[0..count]);
                count += @intCast(rc);
            },
            .INTR => continue,
            else => return error.IoFailed,
        }
    }
    return error.TooLarge;
}

fn fixtureSpec() !ServiceSpec {
    return .{
        .helper = try service.Path.init("/usr/local/libexec/onyx-server-helper"),
        .executable = try service.Path.init("/usr/local/bin/onyx-server"),
        .config = try service.Path.init("/etc/onyx-server/a config;$`b\".toml"),
        .cwd = try service.Path.init("/var/onyx-server"),
        .user = try Name.init("_onyx"),
        .class = try Name.init("daemon"),
        .uid = 1001,
        .gid = 1002,
        .groups = .{1002} ++ @as([group_max - 1]u32, @splat(0)),
        .group_count = 1,
    };
}
fn fixtureObservation() !Observation {
    const s = try fixtureSpec();
    return .{ .uid = @splat(s.uid), .gid = @splat(s.gid), .groups = s.groups, .group_count = s.group_count, .rtable = 0, .cwd = .{ .device = 2, .inode = 10 }, .limits = @splat(.{ .soft = 128, .hard = 256 }) };
}
test "native service helper policy preserves literal arguments and all limits without ambient authority" {
    const spec = try fixtureSpec();
    const p: Policy = .{ .spec = spec, .nonce = @splat(7), .purpose = .serve, .deadline = 9000 };
    const wire = try encodePolicy(&p, .child_policy);
    try std.testing.expectEqualDeep(p, try decodePolicy(wire.bytes[0..wire.len], .child_policy));
    try std.testing.expectError(error.InvalidWire, decodePolicy(wire.bytes[0..wire.len], .daemon_policy));
    try std.testing.expectError(error.InvalidPolicy, Name.init("_onyx:passwd"));
    try std.testing.expectError(error.InvalidPolicy, Name.init("-m"));
    var wrong = spec;
    wrong.groups[1] = 1002;
    wrong.group_count = 2;
    try std.testing.expectError(error.InvalidPolicy, wrong.validate());
    wrong = spec;
    wrong.uid = 0;
    try std.testing.expectError(error.InvalidPolicy, wrong.validate());
    wrong = spec;
    wrong.limits[0].min_soft = 100;
    wrong.limits[0].max_soft = 99;
    try std.testing.expectError(error.InvalidPolicy, wrong.validate());
}
test "native service helper policy every truncated prefix trailing bytes version and noncanonical constants refuse" {
    const bytes = try encodeSpec(std.testing.allocator, try fixtureSpec());
    defer std.testing.allocator.free(bytes);
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidWire, decodeSpec(bytes[0..len]));
    const longer = try std.mem.concat(std.testing.allocator, u8, &.{ bytes, "x" });
    defer std.testing.allocator.free(longer);
    try std.testing.expectError(error.InvalidWire, decodeSpec(longer));
    var bad = try std.testing.allocator.dupe(u8, bytes);
    defer std.testing.allocator.free(bad);
    bad[4] = 2;
    try std.testing.expectError(error.InvalidWire, decodeSpec(bad));
    @memcpy(bad, bytes);
    bad[8] = 2;
    try std.testing.expectError(error.InvalidWire, decodeSpec(bad));
    @memcpy(bad, bytes);
    bad[24] = @intFromEnum(Purpose.serve);
    try std.testing.expectError(error.InvalidWire, decodeSpec(bad));
    const again = try encodeSpec(std.testing.allocator, try decodeSpec(bytes));
    defer std.testing.allocator.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
}
test "native service helper actual observation relation refuses hidden identity and resource changes" {
    const spec = try fixtureSpec();
    const before = try fixtureObservation();
    try validateManagedObservation(&spec, &before, .child);
    var after = before;
    after.limits[8].soft = after.limits[8].hard;
    try compareDaemonObservation(&before, &after);
    after.uid[2] = 0;
    try std.testing.expectError(error.ContextMismatch, validateManagedObservation(&spec, &after, .child));
    after = before;
    after.limits[8].soft = after.limits[8].hard;
    after.limits[3].soft += 1;
    try std.testing.expectError(error.ContextMismatch, compareDaemonObservation(&before, &after));
    after = before;
    after.rtable = 1;
    try std.testing.expectError(error.ContextMismatch, validateManagedObservation(&spec, &after, .child));
    after = before;
    after.groups[0] += 1;
    try std.testing.expectError(error.ContextMismatch, validateManagedObservation(&spec, &after, .child));
    after = before;
    after.cwd.inode = 0;
    try std.testing.expectError(error.ContextMismatch, validateManagedObservation(&spec, &after, .child));
}
fn specAllocation(allocator: std.mem.Allocator) !void {
    const spec = try fixtureSpec();
    const bytes = try encodeSpec(allocator, spec);
    defer allocator.free(bytes);
    try std.testing.expectEqualDeep(spec, try decodeSpec(bytes));
}
test "native service helper selected policy commitment binds every policy dimension canonically" {
    const original = try fixtureSpec();
    const digest = try serviceSpecDigest(&original);
    var expected: service.Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, "a2744fa44eb980f3e3ef42d2d10da4f7608f6529c0c2cab444ab46e6fe008b04");
    try std.testing.expectEqualSlices(u8, &expected, &digest);
    for (0..12) |field| {
        var changed = original;
        switch (field) {
            0 => changed.helper = try service.Path.init("/usr/local/libexec/other-helper"),
            1 => changed.executable = try service.Path.init("/usr/local/bin/other-server"),
            2 => changed.config = try service.Path.init("/etc/onyx-server/other.toml"),
            3 => changed.cwd = try service.Path.init("/var/other-server"),
            4 => changed.user = try Name.init("_other"),
            5 => changed.class = try Name.init("otherclass"),
            6 => changed.uid += 1,
            7 => changed.gid += 1,
            8 => changed.groups[0] += 1,
            9 => changed.rtable = 1,
            10 => changed.limits[0].min_soft = 1,
            11 => changed.limits[8].max_hard -= 1,
            else => unreachable,
        }
        if (field == 11) changed.limits[8].max_soft = changed.limits[8].max_hard;
        const other = try serviceSpecDigest(&changed);
        try std.testing.expect(!std.mem.eql(u8, &digest, &other));
    }
    var malformed = original;
    malformed.user.len = 255;
    try std.testing.expectError(error.InvalidPolicy, serviceSpecDigest(&malformed));
    malformed = original;
    malformed.groups[15] = 1;
    try std.testing.expectError(error.InvalidPolicy, serviceSpecDigest(&malformed));
}
test "native service helper specification allocation failure never mutates or authorizes a launch" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, specAllocation, .{});
}
fn managedPolicyAllocation(allocator: std.mem.Allocator) !void {
    var value: ManagedPolicy = .{ .spec = try fixtureSpec(), .observation = try fixtureObservation() };
    value.observation.limits[8].soft = value.observation.limits[8].hard;
    const bytes = try encodeManagedPolicy(allocator, &value);
    defer allocator.free(bytes);
    try std.testing.expectEqualDeep(value, try decodeManagedPolicy(bytes));
}
test "native service helper managed policy carries exact groups all limits and rejects every missing prefix" {
    var value: ManagedPolicy = .{ .spec = try fixtureSpec(), .observation = try fixtureObservation() };
    value.observation.limits[8].soft = value.observation.limits[8].hard;
    const bytes = try encodeManagedPolicy(std.testing.allocator, &value);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualDeep(value, try decodeManagedPolicy(bytes));
    for (0..bytes.len) |n| {
        if (decodeManagedPolicy(bytes[0..n])) |_| return error.TestExpectedTruncationRefusal else |_| {}
    }
    bytes[4] = 1;
    try std.testing.expectError(error.InvalidWire, decodeManagedPolicy(bytes));
    bytes[4] = 2;
    var extra = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(extra);
    @memcpy(extra[0..bytes.len], bytes);
    extra[bytes.len] = 0;
    try std.testing.expectError(error.InvalidWire, decodeManagedPolicy(extra));
    value.observation.limits[8].soft -= 1;
    try std.testing.expectError(error.ContextMismatch, encodeManagedPolicy(std.testing.allocator, &value));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, managedPolicyAllocation, .{});
}
test "native service helper maximal supported policy fits its exact packet bound without range cuts" {
    var value: ManagedPolicy = .{ .spec = try fixtureSpec(), .observation = try fixtureObservation() };
    var path: [service.max_path]u8 = @splat('p');
    path[0] = '/';
    path[255] = '/';
    for ([_]*service.Path{ &value.spec.helper, &value.spec.executable, &value.spec.config, &value.spec.cwd }) |p| p.* = try service.Path.init(&path);
    value.spec.user = try Name.init(&(@as([63]u8, @splat('u'))));
    value.spec.class = try Name.init(&(@as([63]u8, @splat('c'))));
    value.spec.group_count = group_max;
    value.observation.group_count = group_max;
    for (&value.spec.groups, &value.observation.groups, 0..) |*expected, *actual, i| {
        expected.* = @intCast(i + 1);
        actual.* = expected.*;
    }
    value.observation.limits[8].soft = value.observation.limits[8].hard;
    const spec = try encodeSpec(std.testing.allocator, value.spec);
    defer std.testing.allocator.free(spec);
    try std.testing.expectEqual(@as(usize, 2510), spec.len);
    try std.testing.expectEqual(max_spec_wire, spec.len);
    const pair = try encodeManagedPolicy(std.testing.allocator, &value);
    defer std.testing.allocator.free(pair);
    try std.testing.expectEqual(@as(usize, 2773), pair.len);
    try std.testing.expectEqual(max_managed_policy_wire, pair.len);
    try std.testing.expect(pair.len <= service.max_packet);
    try std.testing.expectEqualDeep(value, try decodeManagedPolicy(pair));
}
test "native service helper unsupported host cannot execute root operations" {
    if (comptime builtin.os.tag != .openbsd) {
        try std.testing.expectError(error.Unsupported, runRoot(std.testing.allocator, std.testing.io, .start, try fixtureSpec(), 1));
        try std.testing.expectError(error.Unsupported, kernel.openBsdRoutingTable());
    }
}
test "native service helper native deadline and unexpected descriptor ownership use real seqpacket" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    if (sys.geteuid() != 0) return error.SkipZigTest; // root peer is the tested boundary
    try std.testing.expectError(error.Timeout, loadSpec((try fixtureSpec()).config, platform.monotonicMillis()));
    var pair = try control.Pair.init();
    defer pair.deinit();
    const deadline = platform.monotonicMillis() + 1000;
    try sendPacket(pair.parent, "owned packet", &.{}, deadline);
    var packet = try receivePacket(pair.child, deadline);
    defer packet.deinit();
    try std.testing.expectEqualStrings("owned packet", packet.bytes());
    try std.testing.expectError(error.Timeout, receivePacket(pair.child, platform.monotonicMillis()));
    try sendPacket(pair.parent, "unexpected", &.{pair.parent}, deadline);
    try std.testing.expectError(error.InvalidWire, receivePacket(pair.child, deadline));
    try std.testing.expect(runtime.fdValid(pair.parent));
    try sendPacket(pair.parent, "two", &.{ pair.parent, pair.child }, deadline);
    var two = try receiveDescriptors(pair.child, deadline, 2);
    const copied = two.fds;
    try std.testing.expectEqual(@as(usize, 2), two.fd_count);
    try std.testing.expect(two.fds[0] != pair.parent and two.fds[1] != pair.child);
    for (two.fds[0..2]) |fd| try std.testing.expect(sys.fcntl(fd, posix.F.GETFD, @as(c_int, 0)) & posix.FD_CLOEXEC != 0);
    two.deinit();
    try std.testing.expect(!runtime.fdValid(copied[0]) and !runtime.fdValid(copied[1]));
    try std.testing.expect(runtime.fdValid(pair.parent) and runtime.fdValid(pair.child));
    runtime.close(pair.parent);
    pair.parent = -1;
    try std.testing.expectError(error.ReceiveFailed, receivePacket(pair.child, deadline));
}

// Only the test owns this PID. Every failure either joins its observed exit or
// kills/reaps it before allowing the fixture's stack/channel lifetime to end.
fn joinTestChild(pid: i32, expected: u8) !void {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    var reaped = false;
    defer if (!reaped) {
        _ = sys.kill(pid, .KILL);
        while (sys.waitpid(pid, null, 0) < 0 and posix.errno(-1) == .INTR) {}
    };
    const deadline = platform.monotonicMillis() + 2000;
    while (true) {
        var status: c_int = 0;
        const rc = sys.waitpid(pid, &status, posix.W.NOHANG);
        if (rc == pid) {
            reaped = true;
            try std.testing.expect(posix.W.IFEXITED(@bitCast(status)));
            try std.testing.expectEqual(expected, @as(u8, @intCast(posix.W.EXITSTATUS(@bitCast(status)))));
            return;
        }
        if (rc < 0 and posix.errno(rc) != .INTR) return error.ChildFailed;
        try retryPause(deadline);
    }
}

test "native service helper target context wrappers read complete real groups and routing table" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    var groups: [group_max]posix.gid_t = undefined;
    const actual = try kernel.openBsdGroups(&groups);
    try std.testing.expect(actual.len <= group_max);
    if (actual.len > 0) try std.testing.expectError(error.GroupBufferTooSmall, kernel.openBsdGroups(groups[0 .. actual.len - 1]));
    try std.testing.expect(try kernel.openBsdRoutingTable() <= 255);
    try std.testing.expect(runtime.fdValid(0));
}

test "native service helper child descriptor closure and signal reset preserve only actual launch channel" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const extra = sys.fcntl(pair.child, posix.F.DUPFD, @as(c_int, 64));
    if (extra < 0) return error.IoFailed;
    defer runtime.close(extra);
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        if (pair.child != 3 and sys.dup2(pair.child, 3) < 0) sys._exit(10);
        var mask: sys.sigset_t = undefined;
        if (sys.sigemptyset(&mask) != 0 or sys.sigaddset(&mask, .TERM) != 0 or sys.sigprocmask(sys.SIG.SETMASK, &mask, null) != 0) sys._exit(11);
        const ignored: sys.Sigaction = .{ .handler = .{ .handler = sys.SIG.IGN }, .mask = mask, .flags = 0 };
        if (sys.sigaction(.PIPE, &ignored, null) != 0) sys._exit(12);
        resetChildSignals() catch sys._exit(13);
        var actual: sys.Sigaction = undefined;
        if (sys.sigaction(.PIPE, null, &actual) != 0 or actual.handler.handler != sys.SIG.DFL) sys._exit(14);
        if (sys.sigprocmask(sys.SIG.SETMASK, null, &mask) != 0 or sys.sigismember(&mask, .TERM) != 0) sys._exit(15);
        kernel.openBsdCloseFrom(4) catch sys._exit(16);
        if (sys.fcntl(extra, posix.F.GETFD, @as(c_int, 0)) >= 0 or !runtime.fdValid(3)) sys._exit(17);
        sys._exit(0);
    }
    try joinTestChild(pid, 0);
    try std.testing.expect(runtime.fdValid(extra) and runtime.fdValid(pair.parent) and runtime.fdValid(pair.child));
}

test "native service helper after grant cleanup closes channel without killing the actual owned child" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    const Barrier = struct {
        fn receive(fd: i32, expected: []const u8, deadline: i64) !void {
            var bytes: [8]u8 = undefined;
            while (true) {
                if (platform.monotonicMillis() >= deadline) return error.Timeout;
                // This is the independently owned fixture channel to our fork,
                // not an authority transport. Check each EINTR against the same
                // deadline rather than using control.receive's inner retry loop.
                const rc = sys.recv(fd, &bytes, bytes.len, posix.MSG.DONTWAIT);
                switch (posix.errno(rc)) {
                    .INTR => continue,
                    .AGAIN => {
                        try waitFd(fd, false, deadline);
                        continue;
                    },
                    .SUCCESS => {},
                    else => return error.ReceiveFailed,
                }
                if (rc <= 0) return error.ReceiveFailed;
                try std.testing.expectEqualSlices(u8, expected, bytes[0..@intCast(rc)]);
                return;
            }
        }
        fn disposeOwned(pid: i32) void {
            // A failed oracle may have observed/reaped the child already. Never
            // signal a numeric PID after waitpid says it is no longer ours.
            while (true) {
                const rc = sys.waitpid(pid, null, posix.W.NOHANG);
                if (rc == pid or (rc < 0 and posix.errno(rc) != .INTR)) return;
                if (rc < 0) continue;
                _ = sys.kill(pid, .KILL);
                while (true) {
                    const waited = sys.waitpid(pid, null, 0);
                    if (waited >= 0 or posix.errno(waited) != .INTR) return;
                }
            }
        }
    };
    var pair = try control.Pair.init();
    defer pair.deinit();
    var barrier = try control.Pair.init();
    defer barrier.deinit();
    const deadline = platform.monotonicMillis() + 5000;
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        _ = sys.close(pair.parent);
        _ = sys.close(barrier.parent);
        var byte: [1]u8 = undefined;
        while (platform.monotonicMillis() < deadline) {
            const rc = sys.recv(pair.child, &byte, 1, posix.MSG.DONTWAIT);
            if (rc == 0) {
                sendPacket(barrier.child, "eof", &.{}, deadline) catch sys._exit(12);
                // This independently owned socket keeps the child alive past
                // Child.deinit's WNOHANG until the parent explicitly releases it.
                Barrier.receive(barrier.child, "release", deadline) catch sys._exit(13);
                sys._exit(42);
            }
            if (rc < 0 and posix.errno(rc) != .AGAIN and posix.errno(rc) != .INTR) sys._exit(10);
            retryPause(deadline) catch break;
        }
        sys._exit(11);
    }
    var owns_child = true;
    defer if (owns_child) Barrier.disposeOwned(pid);
    runtime.close(pair.child);
    pair.child = -1;
    runtime.close(barrier.child);
    barrier.child = -1;
    var child: Child = .{ .pid = pid, .fd = pair.parent, .grant_attempted = true };
    pair.parent = -1;
    child.deinit();
    try std.testing.expectEqual(@as(i32, -1), child.pid);
    try std.testing.expectEqual(@as(i32, -1), child.fd);
    try Barrier.receive(barrier.parent, "eof", deadline);
    try std.testing.expectEqual(@as(c_int, 0), sys.waitpid(pid, null, posix.W.NOHANG));
    try sendPacket(barrier.parent, "release", &.{}, deadline);
    owns_child = false; // joinTestChild now exclusively owns failure cleanup.
    try joinTestChild(pid, 42);
}

test "native service helper before grant cleanup reaps only its owned child and remains idempotent" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const pid = sys.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        resetChildSignals() catch sys._exit(12);
        var none: [0]posix.pollfd = .{};
        _ = sys.poll(&none, 0, 2000); // finite fixture watchdog, no daemon work
        sys._exit(11);
    }
    var child: Child = .{ .pid = pid, .fd = pair.parent };
    pair.parent = -1;
    child.deinit();
    try std.testing.expectEqual(@as(i32, -1), child.pid);
    try std.testing.expectEqual(posix.E.CHILD, posix.errno(sys.waitpid(pid, null, posix.W.NOHANG)));
    child.deinit();
    try std.testing.expect(runtime.fdValid(pair.child));
}

test "native service helper lost mutation reply queries or retries exactly the same authenticated identity" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    if (sys.geteuid() != 0) return error.SkipZigTest;
    // This tests the real helper socket client against a finite protocol peer.
    // The peer's explicit Reply data is not daemon readiness/Helix evidence.
    const Peer = struct {
        listener: i32,
        accepted_before_loss: bool,
        wrong_policy: bool,
        expected_spec: service.Digest,
        deadline: i64,
        cancel: std.atomic.Value(bool) = .init(false),
        request: ?service.Request = null,
        mutations_received: usize = 0,
        executions: usize = 0,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }
        fn serve(self: *@This()) !void {
            var current: service.Reply = .{ .managed_spec_commitment = self.expected_spec, .incarnation = @splat(77), .generation = 0, .phase = .current, .next_serial = 1, .last = null };
            if (self.wrong_policy) current.managed_spec_commitment[0] ^= 1;
            while (!self.cancel.load(.acquire)) {
                const fd = service.acceptRoot(self.listener) catch |err| {
                    if (err != error.WouldBlock) return err;
                    try retryPause(self.deadline);
                    continue;
                };
                defer runtime.close(fd);
                var packet = try receivePacket(fd, self.deadline);
                defer packet.deinit();
                const request = try service.Request.decode(packet.bytes());
                if (request.verb == .upgrade) {
                    self.mutations_received += 1;
                    if (self.request) |old| {
                        try std.testing.expectEqualDeep(old, request);
                    } else self.request = request;
                    if (self.mutations_received == 1 and !self.accepted_before_loss) continue;
                    self.executions += 1;
                    current.generation = 1;
                    current.next_serial = 2;
                    current.last = .{ .request = request, .result = .succeeded };
                    if (self.mutations_received == 1) continue; // accepted, reply lost
                }
                const bytes = try current.encode();
                try sendPacket(fd, &bytes, &.{}, self.deadline);
                if (current.generation == 1 or self.wrong_policy) return;
            }
        }
    };
    for (0..3) |case_index| {
        const accepted_before_loss = case_index == 1;
        const wrong_policy = case_index == 2;
        const expected_spec = try serviceSpecDigest(&(try fixtureSpec()));
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
        defer std.testing.allocator.free(cwd);
        const path = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path });
        defer std.testing.allocator.free(path);
        const namespace_path_value = try service.Path.init(path);
        const path_z = try std.testing.allocator.dupeSentinel(u8, path, 0);
        defer std.testing.allocator.free(path_z);
        const dir_fd = try openDir(posix.AT.FDCWD, path_z);
        var ns: service.RootNamespace = .{ .fd = dir_fd, .path = namespace_path_value };
        defer ns.deinit();
        try rootDirectory(ns.fd);
        const endpoint = try ns.endpoint();
        var address: posix.sockaddr.un = .{ .path = @splat(0) };
        if (endpoint.len >= address.path.len) return error.TooLarge;
        @memcpy(address.path[0..endpoint.len], endpoint.bytes());
        const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + endpoint.len + 1);
        address.len = @intCast(length);
        const listener = sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        if (listener < 0) return error.SocketFailed;
        defer runtime.close(listener);
        if (sys.bind(listener, @ptrCast(&address), length) != 0 or sys.fchmodat(ns.fd, service.endpoint_name, @as(posix.mode_t, 0o600), 0) != 0 or sys.listen(listener, 4) != 0) return error.SocketFailed;
        var peer: Peer = .{ .listener = listener, .deadline = platform.monotonicMillis() + 5000, .accepted_before_loss = accepted_before_loss, .wrong_policy = wrong_policy, .expected_spec = expected_spec };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) {
            peer.cancel.store(true, .release);
            thread.join();
        };
        if (wrong_policy) {
            try std.testing.expectError(error.ContextMismatch, mutate(&ns, .upgrade, @splat(44), expected_spec, peer.deadline));
            thread.join();
            joined = true;
            if (peer.failure) |err| return err;
            try std.testing.expectEqual(@as(usize, 0), peer.mutations_received);
            try std.testing.expectEqual(@as(usize, 0), peer.executions);
            continue;
        }
        const outcome = try mutate(&ns, .upgrade, @splat(44), expected_spec, peer.deadline);
        thread.join();
        joined = true;
        if (peer.failure) |err| return err;
        try std.testing.expect(outcome == .current);
        try std.testing.expectEqual(@as(u64, 1), outcome.current.generation);
        try std.testing.expectEqual(@as(usize, 1), peer.executions);
        try std.testing.expectEqual(@as(usize, if (accepted_before_loss) 1 else 2), peer.mutations_received);
    }
}

// Private, per-test-thread synchronization. Production has no storage, hook or
// callback authority. The peer closes the REAL accepted socket and acknowledges
// over another independently owned channel before the real query sendmsg runs.
const QuerySendFixture = if (builtin.is_test) struct {
    sync_fd: i32,
    deadline: i64,
    repeat: bool,
    queries: usize = 0,
    active_fd: i32 = -1,
    failed_sends: usize = 0,
    failed_rc: isize = 0,
    failed_errno: ?posix.E = null,
    fn beforeQuery(self: *@This(), fd: i32, deadline: i64) Error!void {
        if (deadline != self.deadline) return error.InvalidState;
        self.queries += 1;
        if (self.queries != 2 and !(self.repeat and self.queries > 2)) return;
        try sendPacket(self.sync_fd, "close", &.{}, deadline);
        var acknowledgment = try receivePacket(self.sync_fd, deadline);
        defer acknowledgment.deinit();
        if (!std.mem.eql(u8, acknowledgment.bytes(), "closed")) return error.InvalidWire;
        self.active_fd = fd;
    }
} else void;
threadlocal var query_send_fixture: if (builtin.is_test) ?*QuerySendFixture else void = if (builtin.is_test) null else {};

const QuerySendCase = enum { starting, prior_accepted, lost_reply, accepted_reply, deadline, wrong_policy, foreign_incarnation, malformed, extra_descriptor };

fn querySendRequireHeld(result: service.Error!service.Lease) !void {
    if (result) |granted| {
        var unexpected = granted;
        unexpected.deinit();
        return error.TestUnexpectedLeaseAcquisition;
    } else |err| try std.testing.expectEqual(error.Busy, err);
}

fn querySendLossCausal(scenario: QuerySendCase) !void {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    if (sys.geteuid() != 0) return error.SkipZigTest;
    // This finite protocol peer supplies explicit Reply data, not actual daemon
    // publication authority. No mocked syscall/error and no accept-close race.
    const Peer = struct {
        ns: *const service.RootNamespace,
        listener: i32,
        sync_fd: i32,
        scenario: QuerySendCase,
        expected_spec: service.Digest,
        deadline: i64,
        cancel: std.atomic.Value(bool) = .init(false),
        connections: usize = 0,
        dropped: usize = 0,
        mutations: usize = 0,
        executions: usize = 0,
        request: ?service.Request = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                if (err != error.Timeout or self.scenario != .deadline) self.failure = err;
            };
        }
        fn serve(self: *@This()) !void {
            const prior: service.Request = .{ .verb = .upgrade, .incarnation = @splat(77), .generation = 0, .serial = 1, .nonce = @splat(55), .candidate_config = @splat(22) };
            var reply: service.Reply = .{ .managed_spec_commitment = self.expected_spec, .incarnation = prior.incarnation, .generation = 0, .phase = if (self.scenario == .starting) .starting else .current, .next_serial = if (self.scenario == .prior_accepted) 2 else 1, .last = if (self.scenario == .prior_accepted) .{ .request = prior, .result = .accepted } else null };
            const waiting = self.scenario == .starting or self.scenario == .prior_accepted;
            const drop_connection: usize = if (waiting) 2 else 3;
            while (!self.cancel.load(.acquire)) {
                var fd = service.acceptRoot(self.listener) catch |err| {
                    if (err != error.WouldBlock) return err;
                    try retryPause(self.deadline);
                    continue;
                };
                defer if (fd >= 0) runtime.close(fd);
                self.connections += 1;
                try querySendRequireHeld(self.ns.acquireMutation());
                try querySendRequireHeld(self.ns.acquireLifetime());
                if (self.connections == drop_connection or (self.scenario == .deadline and self.connections > drop_connection)) {
                    var signal = try receivePacket(self.sync_fd, self.deadline);
                    defer signal.deinit();
                    try std.testing.expectEqualStrings("close", signal.bytes());
                    runtime.close(fd);
                    fd = -1;
                    self.dropped += 1;
                    try sendPacket(self.sync_fd, "closed", &.{}, self.deadline);
                    continue;
                }
                var packet = try receivePacket(fd, self.deadline);
                defer packet.deinit();
                const request = try service.Request.decode(packet.bytes());
                if (request.verb == .upgrade) {
                    self.mutations += 1;
                    if (self.request) |original| {
                        try std.testing.expectEqualDeep(original, request);
                    } else {
                        self.request = request;
                        self.executions += 1;
                    }
                    try std.testing.expectEqual(@as(u64, if (self.scenario == .prior_accepted) 1 else 0), request.generation);
                    try std.testing.expectEqual(@as(u64, if (self.scenario == .prior_accepted) 2 else 1), request.serial);
                    try std.testing.expectEqualSlices(u8, &(@as(service.Digest, @splat(44))), &request.candidate_config);
                    reply.next_serial = request.serial + 1;
                    reply.last = .{ .request = request, .result = if (waiting or self.scenario == .lost_reply) .succeeded else .accepted };
                    if (reply.last.?.result == .succeeded) reply.generation = request.generation + 1;
                    if (self.scenario == .lost_reply) continue;
                } else {
                    try std.testing.expectEqual(service.Verb.query, request.verb);
                    if (self.connections > drop_connection) {
                        reply.phase = .current;
                        if (reply.last) |*last| {
                            last.result = .succeeded;
                            reply.generation = last.request.generation + 1;
                        }
                        switch (self.scenario) {
                            .wrong_policy => reply.managed_spec_commitment[0] ^= 1,
                            .foreign_incarnation => {
                                reply.incarnation[0] ^= 1;
                                if (reply.last) |*last| last.request.incarnation = reply.incarnation;
                            },
                            else => {},
                        }
                    }
                }
                var bytes = try reply.encode();
                if (self.connections > drop_connection and self.scenario == .malformed) bytes[0] ^= 1;
                const descriptor = self.connections > drop_connection and self.scenario == .extra_descriptor;
                try sendPacket(fd, &bytes, if (descriptor) &.{self.listener} else &.{}, self.deadline);
                if (self.connections > drop_connection and (!waiting or self.mutations != 0)) return;
            }
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
    defer std.testing.allocator.free(cwd);
    const path = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path });
    defer std.testing.allocator.free(path);
    const path_z = try std.testing.allocator.dupeSentinel(u8, path, 0);
    defer std.testing.allocator.free(path_z);
    var ns: service.RootNamespace = .{ .fd = try openDir(posix.AT.FDCWD, path_z), .path = try service.Path.init(path) };
    defer ns.deinit();
    try rootDirectory(ns.fd);
    var lease = try ns.acquireLifetime();
    defer lease.deinit();
    var mutation = try ns.acquireMutation();
    defer mutation.deinit();
    const endpoint = try ns.endpoint();
    var address: posix.sockaddr.un = .{ .path = @splat(0) };
    if (endpoint.len >= address.path.len) return error.TooLarge;
    @memcpy(address.path[0..endpoint.len], endpoint.bytes());
    const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + endpoint.len + 1);
    address.len = @intCast(length);
    const listener: i32 = @intCast(sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0));
    if (listener < 0) return error.SocketFailed;
    defer runtime.close(listener);
    if (sys.bind(listener, @ptrCast(&address), length) != 0 or sys.fchmodat(ns.fd, service.endpoint_name, @as(posix.mode_t, 0o600), 0) != 0 or sys.listen(listener, 4) != 0) return error.SocketFailed;
    var pair = try control.Pair.init();
    defer pair.deinit();
    const deadline = platform.monotonicMillis() + if (scenario == .deadline) @as(i64, 500) else @as(i64, 5000);
    const expected_spec = try serviceSpecDigest(&(try fixtureSpec()));
    var fixture: QuerySendFixture = .{ .sync_fd = pair.parent, .deadline = deadline, .repeat = scenario == .deadline };
    std.debug.assert(query_send_fixture == null);
    query_send_fixture = &fixture;
    defer query_send_fixture = null;
    var peer: Peer = .{ .ns = &ns, .listener = listener, .sync_fd = pair.child, .scenario = scenario, .expected_spec = expected_spec, .deadline = deadline };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.cancel.store(true, .release);
        thread.join();
    };
    const result = mutate(&ns, .upgrade, @splat(44), expected_spec, deadline);
    const completed_at = platform.monotonicMillis();
    peer.cancel.store(true, .release);
    thread.join();
    joined = true;
    if (peer.failure) |err| return err;
    std.debug.print("query-send causal {s}: actual failures={d}, rc={d}, errno={?}, peer closes={d}, remaining_ms={d}\n", .{ @tagName(scenario), fixture.failed_sends, fixture.failed_rc, fixture.failed_errno, peer.dropped, deadline - completed_at });
    try std.testing.expect(fixture.failed_sends > 0);
    try std.testing.expect(fixture.failed_rc < 0);
    try std.testing.expect(fixture.failed_errno != null and fixture.failed_errno.? != .SUCCESS and fixture.failed_errno.? != .INTR and fixture.failed_errno.? != .AGAIN);
    if (scenario == .deadline) {
        // The final original-deadline check can stop between peer close/ACK and
        // the attempted send. At most that one in-flight close lacks a syscall.
        try std.testing.expect(peer.dropped >= fixture.failed_sends);
        try std.testing.expect(peer.dropped - fixture.failed_sends <= 1);
    } else try std.testing.expectEqual(peer.dropped, fixture.failed_sends);
    try querySendRequireHeld(ns.acquireMutation());
    try querySendRequireHeld(ns.acquireLifetime());
    switch (scenario) {
        .wrong_policy => try std.testing.expectError(error.ContextMismatch, result),
        .foreign_incarnation => try std.testing.expectError(error.StateChanged, result),
        .malformed, .extra_descriptor => try std.testing.expectError(error.InvalidWire, result),
        .deadline => {
            try std.testing.expect((try result) == .pending);
            try std.testing.expect(completed_at >= deadline);
            try std.testing.expectEqual(@as(usize, 1), peer.executions);
        },
        else => {
            const outcome = try result;
            try std.testing.expect(outcome == .current);
            try std.testing.expectEqualDeep(peer.request.?, outcome.current.last.?.request);
            try std.testing.expectEqual(@as(usize, 1), peer.mutations);
            try std.testing.expectEqual(@as(usize, 1), peer.executions);
        },
    }
}

test "native query send causal initial starting wait retains original deadline" {
    try querySendLossCausal(.starting);
}
test "native query send causal initial accepted wait retains original deadline" {
    try querySendLossCausal(.prior_accepted);
}
test "native query send causal lost mutation reply retains exact operation" {
    try querySendLossCausal(.lost_reply);
}
test "native query send causal accepted reply retains exact operation" {
    try querySendLossCausal(.accepted_reply);
}
test "native query send causal repeated real loss ends pending at original deadline" {
    try querySendLossCausal(.deadline);
}
test "native query send causal policy mismatch after loss remains refusal" {
    try querySendLossCausal(.wrong_policy);
}
test "native query send causal foreign incarnation after loss remains refusal" {
    try querySendLossCausal(.foreign_incarnation);
}
test "native query send causal malformed reply after loss remains refusal" {
    try querySendLossCausal(.malformed);
}
test "native query send causal extra descriptor after loss remains refusal" {
    try querySendLossCausal(.extra_descriptor);
}

test "native service helper recorded stop proof rejects nonterminal and foreign policy" {
    const spec = try serviceSpecDigest(&(try fixtureSpec()));
    const request: service.Request = .{ .verb = .stop, .incarnation = @splat(77), .generation = 4, .serial = 9, .nonce = @splat(31), .candidate_config = @splat(0) };
    var reply: service.Reply = .{ .managed_spec_commitment = spec, .incarnation = request.incarnation, .generation = request.generation, .phase = .stopping, .next_serial = 10, .last = .{ .request = request, .result = .accepted } };
    try std.testing.expectEqualDeep(request, try stopRequest(reply, spec));
    reply.last.?.result = .stopped;
    try std.testing.expectEqualDeep(request, try stopRequest(reply, spec));
    reply.managed_spec_commitment[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, stopRequest(reply, spec));
    reply.managed_spec_commitment = spec;
    reply.phase = .current;
    try std.testing.expectError(error.InvalidWire, stopRequest(reply, spec));
}

test "native service helper exact terminal ACK recovers lost results without inventing stopped" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    if (sys.geteuid() != 0) return error.SkipZigTest;
    // Actual root sockets and lifetime/mutation locks with a finite protocol
    // peer. Explicit Reply data is not real daemon graph teardown authority.
    const Case = enum { lost_ack, accepted, lost_result, held_lease, no_result, wrong_policy, changed_identity, reload };
    const Peer = struct {
        listener: *i32,
        lease: *service.Lease,
        ns: *const service.RootNamespace,
        scenario: Case,
        expected_spec: service.Digest,
        deadline: i64,
        cancel: std.atomic.Value(bool) = .init(false),
        queries: usize = 0,
        mutations: usize = 0,
        acks: usize = 0,
        first_ack: ?[service.StopAck.wire_len]u8 = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                if (err != error.Timeout or self.scenario != .held_lease) self.failure = err;
            };
        }
        fn release(self: *@This()) void {
            self.lease.deinit();
            runtime.close(self.listener.*);
            self.listener.* = -1;
        }
        fn serve(self: *@This()) !void {
            var request: service.Request = .{ .verb = .stop, .incarnation = @splat(77), .generation = 4, .serial = 9, .nonce = @splat(31), .candidate_config = @splat(0) };
            var reply: service.Reply = .{ .managed_spec_commitment = self.expected_spec, .incarnation = request.incarnation, .generation = request.generation, .phase = .stopping, .next_serial = 10, .last = .{ .request = request, .result = if (self.scenario == .accepted or self.scenario == .no_result) .accepted else .stopped } };
            if (self.scenario == .lost_result) {
                reply.generation = 0;
                reply.next_serial = 1;
                reply.last = null;
                reply.phase = .current;
            }
            if (self.scenario == .wrong_policy) reply.managed_spec_commitment[0] ^= 1;
            while (!self.cancel.load(.acquire)) {
                const fd = service.acceptRoot(self.listener.*) catch |err| {
                    if (err != error.WouldBlock) return err;
                    try retryPause(self.deadline);
                    continue;
                };
                defer runtime.close(fd);
                var packet = try receivePacket(fd, self.deadline);
                defer packet.deinit();
                // The caller's original mutation lease spans every recovery/ACK.
                try std.testing.expectError(error.Busy, self.ns.acquireMutation());
                if (packet.bytes().len >= 4 and std.mem.eql(u8, packet.bytes()[0..4], "NSAK")) {
                    const ack = try service.StopAck.decode(packet.bytes());
                    try std.testing.expectEqualDeep(request, ack.request);
                    try std.testing.expectEqualSlices(u8, &self.expected_spec, &ack.managed_spec_commitment);
                    self.acks += 1;
                    if (self.first_ack) |original| try std.testing.expectEqualSlices(u8, &original, packet.bytes()) else self.first_ack = packet.bytes()[0..service.StopAck.wire_len].*;
                    if (self.scenario == .held_lease or (self.scenario == .lost_ack and self.acks == 1)) continue;
                    if (self.scenario == .changed_identity) {
                        reply.last.?.request.nonce[0] ^= 1;
                        continue;
                    }
                    // No response: the real lock release is the helper's proof.
                    self.release();
                    return;
                }
                const received = try service.Request.decode(packet.bytes());
                if (received.verb == .stop) {
                    try std.testing.expectEqual(Case.lost_result, self.scenario);
                    self.mutations += 1;
                    try std.testing.expectEqual(@as(usize, 1), self.mutations);
                    request = received;
                    reply.phase = .stopping;
                    reply.next_serial = received.serial + 1;
                    reply.last = .{ .request = received, .result = .stopped };
                    continue; // accepted stop, but the entire result is lost
                }
                try std.testing.expectEqual(service.Verb.query, received.verb);
                self.queries += 1;
                if (self.scenario == .accepted and self.queries >= 2) reply.last.?.result = .stopped;
                const bytes = try reply.encode();
                try sendPacket(fd, &bytes, &.{}, self.deadline);
                if (self.scenario == .wrong_policy) return;
                if (self.scenario == .no_result) {
                    self.release();
                    return;
                }
            }
        }
    };
    for (std.enums.values(Case)) |scenario| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const cwd = try std.process.currentPathAlloc(std.testing.io, std.testing.allocator);
        defer std.testing.allocator.free(cwd);
        const path = try std.fs.path.join(std.testing.allocator, &.{ cwd, ".zig-cache", "tmp", &tmp.sub_path });
        defer std.testing.allocator.free(path);
        const path_z = try std.testing.allocator.dupeSentinel(u8, path, 0);
        defer std.testing.allocator.free(path_z);
        var ns: service.RootNamespace = .{ .fd = try openDir(posix.AT.FDCWD, path_z), .path = try service.Path.init(path) };
        defer ns.deinit();
        try rootDirectory(ns.fd);
        var lease = try ns.acquireLifetime();
        defer lease.deinit();
        var mutation = try ns.acquireMutation();
        defer mutation.deinit();
        const endpoint = try ns.endpoint();
        var address: posix.sockaddr.un = .{ .path = @splat(0) };
        if (endpoint.len >= address.path.len) return error.TooLarge;
        @memcpy(address.path[0..endpoint.len], endpoint.bytes());
        const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + endpoint.len + 1);
        if (comptime @hasField(posix.sockaddr.un, "len")) address.len = @intCast(length);
        var listener: i32 = @intCast(sys.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0));
        if (listener < 0) return error.SocketFailed;
        defer if (listener >= 0) runtime.close(listener);
        if (sys.bind(listener, @ptrCast(&address), length) != 0 or sys.fchmodat(ns.fd, service.endpoint_name, @as(posix.mode_t, 0o600), 0) != 0 or sys.listen(listener, 4) != 0) return error.SocketFailed;
        const expected_spec = try serviceSpecDigest(&(try fixtureSpec()));
        var peer: Peer = .{ .listener = &listener, .lease = &lease, .ns = &ns, .scenario = scenario, .expected_spec = expected_spec, .deadline = platform.monotonicMillis() + if (scenario == .held_lease) @as(i64, 500) else @as(i64, 5000) };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) {
            peer.cancel.store(true, .release);
            thread.join();
        };
        const result = mutate(&ns, if (scenario == .reload) .upgrade else .stop, if (scenario == .reload) @splat(44) else @splat(0), expected_spec, peer.deadline);
        peer.cancel.store(true, .release);
        thread.join();
        joined = true;
        if (peer.failure) |err| return err;
        switch (scenario) {
            .wrong_policy => try std.testing.expectError(error.ContextMismatch, result),
            .changed_identity => try std.testing.expectError(error.StateChanged, result),
            .held_lease => try std.testing.expect((try result) == .pending),
            .no_result, .reload => try std.testing.expect((try result) == .not_running),
            else => try std.testing.expect((try result) == .stopped),
        }
        try std.testing.expectError(error.Busy, ns.acquireMutation());
        try std.testing.expectEqual(@as(usize, if (scenario == .lost_result) 1 else 0), peer.mutations);
        if (scenario == .wrong_policy or scenario == .no_result) try std.testing.expectEqual(@as(usize, 0), peer.acks) else try std.testing.expect(peer.acks > 0);
        if (scenario == .lost_ack) try std.testing.expectEqual(@as(usize, 2), peer.acks);
        if (scenario == .held_lease or scenario == .wrong_policy or scenario == .changed_identity)
            try std.testing.expectError(error.Busy, ns.acquireLifetime())
        else
            try std.testing.expect(try lifetimeReleased(&ns));
    }
}
