// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! I/O backend for accept, recv, send, poll, cancel, and timeout.
//!
//! Linux keeps today's Ringlane ring (`ringlane.zig`). FreeBSD, OpenBSD,
//! NetBSD, and Dragonfly implement the same operations on a kqueue fd.
//! Windows implements them on an I/O completion port: AFD receive and send,
//! AFD wait-for-listen and AFD poll, ConnectEx, `NtCancelIoFileEx`, and
//! monotonic timers.
//! `Iocp.open` loads the Winsock Registered I/O function table and returns
//! `error.MissingOp` when that table is missing. `dequeueRegistered` is what
//! calls those pointers. `reap` reports one-shot completions: the ring
//! reports the completion, kqueue performs the syscall, and IOCP collects
//! `NtRemoveIoCompletion` then adopts a waited listen. A failed individual
//! request has a negative result; an unusable port or queue fails closed.
//! Helix USR2 adoption stays on `LinuxServer`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const ringlane = @import("ringlane.zig");
const capsule = @import("helix/capsule.zig");
const helix_windows_socket = @import("helix/native_windows_socket.zig");

const Allocator = std.mem.Allocator;

pub const Family = enum { ringlane, iocp, kqueue };

pub const Op = enum { accept, recv, send, poll, cancel, timeout, connect };

pub const required_ops = [_]Op{ .accept, .recv, .send, .poll, .cancel, .timeout };

/// One finished accept, recv, send, poll, timeout, or connect from `reap`.
/// `result` is the new socket for accept, the byte count for recv and send,
/// or a negative errno. Timeout uses `0`.
pub const Reaped = struct {
    op: Op,
    token: ringlane.FdToken,
    result: i32,
};

pub const Listener = struct {
    fd: linux.fd_t,
    port: u16,
};

/// The portable server still passes i32 descriptors, while Winsock SOCKET is a
/// pointer-sized value. Keep an opaque descriptor at that boundary instead of
/// narrowing a live SOCKET (or refusing every handle above INT_MAX).
const WindowsSockets = struct {
    // File HANDLE descriptors occupy the upper positive-i32 quarter. Split
    // the socket quarter into a slot and a generation so a closed slot can be
    // reused without ever making an old descriptor valid again. A slot retires
    // when its generation is spent; reusing its exact ID would be unsafe.
    const slot_bits = 20;
    const slot_count: u32 = 1 << slot_bits;
    const slot_mask: u32 = slot_count - 1;
    const max_generation: u16 = (1 << (30 - slot_bits)) - 1;
    // Start a same-image Helix rollover with half the namespace still free.
    // The successor imports only live IDs into a fresh process registry.
    const rollover_claimed_ids: u64 = 1 << 29;
    const Carry = enum { ordinary, helix_staged, helix_released, helix_poisoned };
    const Entry = struct {
        handle: usize,
        associated_port: usize = 0,
        accepted_peer: ?WindowsTcpEndpoint = null,
        carry: Carry = .ordinary,
    };
    const Slot = struct {
        highest_generation: u16,
        live_count: u32 = 1,
        free_next: ?u32 = null,
        on_free_list: bool = false,
    };

    lock: std.atomic.Mutex = .unlocked,
    handles: std.AutoHashMapUnmanaged(linux.fd_t, Entry) = .empty,
    slots: std.AutoHashMapUnmanaged(u32, Slot) = .empty,
    allocator: Allocator = std.heap.page_allocator,
    next_slot: u32 = 1,
    free_head: ?u32 = null,
    last_imported_fd: linux.fd_t = 0,
    ordinary_seen: bool = false,
    /// Number of unique IDs no longer available in this process. Imports also
    /// claim lower generations in their slots, even if those IDs are not live.
    claimed_id_count: u64 = 0,

    fn lockSpin(self: *WindowsSockets) void {
        while (!self.lock.tryLock()) std.Thread.yield() catch {};
    }

    fn register(self: *WindowsSockets, handle: usize) !linux.fd_t {
        return self.registerWithPeer(handle, null);
    }

    fn registerWithPeer(self: *WindowsSockets, handle: usize, peer: ?WindowsTcpEndpoint) !linux.fd_t {
        if (handle == std.math.maxInt(usize)) return error.InvalidSocket;
        self.lockSpin();
        defer self.lock.unlock();
        if (self.free_head) |slot| {
            const state = self.slots.getPtr(slot).?;
            std.debug.assert(state.live_count == 0 and state.on_free_list and state.highest_generation < max_generation);
            const generation = state.highest_generation + 1;
            const fd = encodeId(slot, generation);
            try self.handles.put(self.allocator, fd, .{ .handle = handle, .accepted_peer = peer });
            self.free_head = state.free_next;
            state.* = .{ .highest_generation = generation };
            self.ordinary_seen = true;
            self.claimed_id_count += 1;
            return fd;
        }
        const slot = self.findUnusedSlot() orelse return error.SocketIdsExhausted;
        const fd = encodeId(slot, 0);
        try self.slots.put(self.allocator, slot, .{ .highest_generation = 0 });
        errdefer _ = self.slots.remove(slot);
        try self.handles.put(self.allocator, fd, .{ .handle = handle, .accepted_peer = peer });
        self.ordinary_seen = true;
        self.claimed_id_count += 1;
        return fd;
    }

    fn rolloverDue(self: *WindowsSockets) bool {
        self.lockSpin();
        defer self.lock.unlock();
        return self.claimed_id_count >= rollover_claimed_ids;
    }

    fn encodeId(slot: u32, generation: u16) linux.fd_t {
        return @intCast((@as(u32, generation) << slot_bits) | slot);
    }

    fn findUnusedSlot(self: *WindowsSockets) ?u32 {
        // Slot zero exists only for imported canonical IDs with a nonzero
        // generation. Ordinary IDs start at one, as POSIX descriptors do.
        var checked: u32 = 0;
        while (checked < slot_mask) : (checked += 1) {
            const slot = self.next_slot;
            self.next_slot = if (slot == slot_mask) 1 else slot + 1;
            if (!self.slots.contains(slot)) return slot;
        }
        return null;
    }

    fn unlinkFreeSlot(self: *WindowsSockets, slot: u32) void {
        var link = &self.free_head;
        while (link.*) |current| {
            const state = self.slots.getPtr(current).?;
            if (current == slot) {
                link.* = state.free_next;
                state.free_next = null;
                state.on_free_list = false;
                return;
            }
            link = &state.free_next;
        }
        unreachable;
    }

    fn releaseSlot(self: *WindowsSockets, fd: linux.fd_t) void {
        const slot: u32 = @as(u32, @intCast(fd)) & slot_mask;
        const state = self.slots.getPtr(slot).?;
        std.debug.assert(state.live_count != 0);
        state.live_count -= 1;
        if (state.live_count == 0 and state.highest_generation < max_generation) {
            std.debug.assert(!state.on_free_list);
            state.free_next = self.free_head;
            state.on_free_list = true;
            self.free_head = slot;
        }
    }

    /// The successor imports canonical IDs in ascending order before any
    /// ordinary socket registration. Multiple live IDs can occupy one slot
    /// when an older monotonic-ID predecessor crosses a slot boundary; that
    /// slot remains unavailable until every imported ID has been removed.
    fn registerHelixImported(self: *WindowsSockets, fd: linux.fd_t, handle: usize) !void {
        if (fd <= 0 or fd >= 0x4000_0000) return error.InvalidSocketId;
        if (handle == std.math.maxInt(usize)) return error.InvalidSocket;
        self.lockSpin();
        defer self.lock.unlock();
        if (self.handles.contains(fd)) return error.SocketIdCollision;
        if (self.ordinary_seen or fd <= self.last_imported_fd) return error.ImportOutOfOrder;
        const slot: u32 = @as(u32, @intCast(fd)) & slot_mask;
        const generation: u16 = @intCast(@as(u32, @intCast(fd)) >> slot_bits);
        const prior = self.slots.getPtr(slot);
        if (prior) |state| {
            if (generation <= state.highest_generation) return error.ImportOutOfOrder;
        } else {
            try self.slots.put(self.allocator, slot, .{ .highest_generation = generation, .live_count = 0 });
        }
        const newly_claimed: u64 = if (prior) |state|
            @as(u64, generation - state.highest_generation)
        else
            @as(u64, generation) + 1;
        errdefer {
            if (prior == null) _ = self.slots.remove(slot);
        }
        try self.handles.put(self.allocator, fd, .{ .handle = handle, .carry = .helix_staged });
        const state = self.slots.getPtr(slot).?;
        if (state.on_free_list) self.unlinkFreeSlot(slot);
        state.highest_generation = generation;
        state.live_count += 1;
        self.last_imported_fd = fd;
        self.claimed_id_count += newly_claimed;
        if (generation == 0 and slot >= self.next_slot)
            self.next_slot = if (slot == slot_mask) 1 else slot + 1;
    }

    fn helixSourceHandle(self: *WindowsSockets, fd: linux.fd_t) !usize {
        if (fd <= 0 or fd >= 0x4000_0000) return error.InvalidSocketId;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return error.InvalidSocketId;
        if (entry.carry != .ordinary) return error.InvalidReleaseState;
        return entry.handle;
    }

    fn takeHelixStaged(self: *WindowsSockets, fd: linux.fd_t) !usize {
        if (fd <= 0 or fd >= 0x4000_0000) return error.InvalidSocketId;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return error.InvalidSocketId;
        if (entry.carry != .helix_staged) return error.InvalidReleaseState;
        const handle = (self.handles.fetchRemove(fd) orelse unreachable).value.handle;
        self.releaseSlot(fd);
        return handle;
    }

    fn takeHelixUnassociated(self: *WindowsSockets, fd: linux.fd_t) !usize {
        if (fd <= 0 or fd >= 0x4000_0000) return error.InvalidSocketId;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return error.InvalidSocketId;
        if ((entry.carry != .helix_staged and entry.carry != .helix_released) or entry.associated_port != 0)
            return error.InvalidReleaseState;
        const handle = (self.handles.fetchRemove(fd) orelse unreachable).value.handle;
        self.releaseSlot(fd);
        return handle;
    }

    /// Called only after the authenticated native successor receives the
    /// predecessor's release receipt. A staged socket cannot post AFD I/O.
    fn confirmHelixReleased(self: *WindowsSockets, fd: linux.fd_t) !void {
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.getPtr(fd) orelse return error.InvalidSocketId;
        if (entry.carry != .helix_staged or entry.associated_port != 0) return error.InvalidReleaseState;
        entry.carry = .helix_released;
    }

    fn get(self: *WindowsSockets, fd: linux.fd_t) ?usize {
        if (fd <= 0) return null;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return null;
        return entry.handle;
    }

    fn acceptedPeer(self: *WindowsSockets, fd: linux.fd_t) ?PeerAddress {
        if (fd <= 0) return null;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return null;
        return if (entry.accepted_peer) |peer| peer.address else null;
    }

    fn acceptedEndpoint(self: *WindowsSockets, fd: linux.fd_t) ?WindowsTcpEndpoint {
        if (fd <= 0) return null;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return null;
        return entry.accepted_peer;
    }

    fn rememberHelixAcceptedEndpoint(self: *WindowsSockets, fd: linux.fd_t, peer: WindowsTcpEndpoint) WindowsTcpObservationError!void {
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.getPtr(fd) orelse return error.InvalidSocket;
        if (entry.carry != .helix_staged or peer.port == 0) return error.NotConnected;
        if (entry.accepted_peer) |prior| {
            if (!std.meta.eql(prior, peer)) return error.NotConnected;
        } else entry.accepted_peer = peer;
    }

    fn associatedPort(self: *WindowsSockets, fd: linux.fd_t) ?usize {
        if (fd <= 0) return null;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.get(fd) orelse return null;
        return entry.associated_port;
    }

    fn associate(self: *WindowsSockets, fd: linux.fd_t, handle: usize, port: usize) !void {
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        if (port == 0) return error.MissingOp;
        self.lockSpin();
        defer self.lock.unlock();
        const entry = self.handles.getPtr(fd) orelse return error.MissingOp;
        if (entry.handle != handle) return error.MissingOp;
        if (entry.carry == .helix_staged or entry.carry == .helix_poisoned) return error.MissingOp;
        if (entry.associated_port == port) return;
        if (entry.associated_port != 0) return error.MissingOp;
        const w = std.os.windows;
        var info = extern struct {
            port: w.HANDLE,
            key: ?*anyopaque,
        }{
            .port = @ptrFromInt(port),
            .key = @ptrFromInt(handle),
        };
        var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        if (entry.carry == .helix_released) {
            helix_windows_socket.replaceCompletionPort(handle, port, handle) catch return error.MissingOp;
        } else {
            const status = w.ntdll.NtSetInformationFile(
                @ptrFromInt(handle),
                &iosb,
                @ptrCast(&info),
                @sizeOf(@TypeOf(info)),
                .Completion,
            );
            if (status != .SUCCESS) {
                std.debug.print("GAP-X1 windows iocp status=0x{x} op=associate\n", .{@intFromEnum(status)});
                return error.MissingOp;
            }
        }
        // A synchronous success is returned inline. Suppress its otherwise
        // duplicate port packet before the first AFD request is submitted.
        if (SetFileCompletionNotificationModes(@ptrFromInt(handle), 0x1) == 0) {
            if (entry.carry == .helix_released) entry.carry = .helix_poisoned;
            return error.MissingOp;
        }
        entry.associated_port = port;
        // After the successor has associated and activated the imported socket,
        // it is an ordinary live owner again and may be sealed by the next
        // Helix generation.
        if (entry.carry == .helix_released) entry.carry = .ordinary;
    }

    fn take(self: *WindowsSockets, fd: linux.fd_t) ?usize {
        if (fd <= 0) return null;
        self.lockSpin();
        defer self.lock.unlock();
        const removed = self.handles.fetchRemove(fd) orelse return null;
        self.releaseSlot(fd);
        return removed.value.handle;
    }

    fn deinit(self: *WindowsSockets) void {
        self.handles.deinit(self.allocator);
        self.handles = .empty;
        self.slots.deinit(self.allocator);
        self.slots = .empty;
    }
};

var windows_sockets: WindowsSockets = .{};
var winsock_start_lock: std.atomic.Mutex = .unlocked;
var winsock_started: bool = false;

fn ensureWinsock() error{SocketUnavailable}!void {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    while (!winsock_start_lock.tryLock()) std.Thread.yield() catch {};
    defer winsock_start_lock.unlock();
    if (winsock_started) return;
    // WSADATA is 408 bytes on Win64. A failed WSAStartup does not acquire a
    // Winsock reference, so a later call may retry; one success lasts for the
    // process and is intentionally not paired with per-socket WSACleanup.
    var startup: [408]u8 = @splat(0);
    if (WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    winsock_started = true;
}

/// Transfer ownership of a Winsock SOCKET created by a caller into the
/// portable descriptor namespace. On success, close it with `closeSocket`.
pub fn adoptWindowsSocket(socket: usize) !linux.fd_t {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    return windows_sockets.register(socket);
}

/// True once half the per-process socket-ID namespace is claimed. Reactor 0
/// can then schedule a same-image Helix rollover with ample retry headroom.
pub fn windowsSocketIdRolloverDue() bool {
    if (comptime builtin.os.tag != .windows) return false;
    return windows_sockets.rolloverDue();
}

/// Stage an inherited Helix socket under the predecessor's exact opaque ID.
/// The transfer must come from the authenticated candidate control channel;
/// call `confirmHelixPredecessorReleasedWindows` only after the predecessor's
/// owner has drained I/O, closed its completion port, and released custody.
pub fn stageHelixWindowsSocketAtCanonicalId(fd: linux.fd_t, transfer: *helix_windows_socket.Transfer) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (fd <= 0 or fd >= 0x4000_0000) return error.InvalidSocketId;
    const socket = try transfer.import();
    errdefer _ = closesocket(socket);
    try windows_sockets.registerHelixImported(fd, socket);
}

/// Borrow the source's actual ordinary SOCKET while its owner has quiesced
/// and drained I/O. The caller must retain that registry entry through the
/// WSADuplicateSocketW call and until rollback is no longer possible.
pub fn helixWindowsSourceSocket(fd: linux.fd_t) !usize {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    return windows_sockets.helixSourceHandle(fd);
}

/// Abort custody only while the imported socket is inert. Never shut down the
/// shared TCP endpoint: closing this duplicate leaves the predecessor live.
pub fn abortHelixStagedWindowsSocket(fd: linux.fd_t) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = try windows_sockets.takeHelixStaged(fd);
    if (closesocket(socket) != 0) return error.SocketCloseFailed;
}

/// Failure cleanup while no candidate AFD request has been posted. This also
/// closes entries already marked released if a later entry fails the same
/// release batch. It never shuts down the shared TCP endpoint.
pub fn discardHelixUnassociatedWindowsSocket(fd: linux.fd_t) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = try windows_sockets.takeHelixUnassociated(fd);
    if (closesocket(socket) != 0) return error.SocketCloseFailed;
}

/// A live successor's authenticated release barrier is responsible for this
/// call. Until then the imported socket cannot submit to a new IOCP.
pub fn confirmHelixPredecessorReleasedWindows(fd: linux.fd_t) !void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    try windows_sockets.confirmHelixReleased(fd);
}

pub fn windowsSocketValid(fd: linux.fd_t) bool {
    if (comptime builtin.os.tag != .windows) return false;
    return windows_sockets.get(fd) != null;
}

pub fn windowsSocketType(fd: linux.fd_t) error{SocketFailed}!u32 {
    if (comptime builtin.os.tag != .windows) return error.SocketFailed;
    const socket = windows_sockets.get(fd) orelse return error.SocketFailed;
    var kind: i32 = 0;
    var kind_len: i32 = @sizeOf(i32);
    if (getsockopt(socket, 0xFFFF, 0x1008, &kind, &kind_len) != 0 or kind_len != @sizeOf(i32) or kind < 0)
        return error.SocketFailed;
    return @intCast(kind);
}

/// Address family and bytes returned by Winsock for an adopted socket.
/// Dual-stack IPv4 peers arrive as IPv4-mapped IPv6 addresses.
pub const PeerAddress = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
};

pub const WindowsTcpEndpoint = struct {
    address: PeerAddress,
    port: u16,
};

pub const WindowsListenerObservation = struct { local: WindowsTcpEndpoint };
pub const WindowsConnectedObservation = struct { local: WindowsTcpEndpoint, peer: WindowsTcpEndpoint };
pub const WindowsHelixConnectedObservation = struct { local: WindowsTcpEndpoint, peer: ?WindowsTcpEndpoint };
pub const WindowsTcpObservationError = error{ Unsupported, InvalidSocket, NotTcp, NotListening, NotConnected, SocketFailed };

fn windowsTcpStatus(handle: usize) WindowsTcpObservationError!bool {
    var info = std.mem.zeroes(helix_windows_socket.ProtocolInfo);
    var info_len: i32 = @sizeOf(helix_windows_socket.ProtocolInfo);
    if (getsockopt(handle, 0xFFFF, 0x2005, &info, &info_len) != 0 or
        info_len != @sizeOf(helix_windows_socket.ProtocolInfo)) return error.SocketFailed;
    if ((info.address_family != wsa_af_inet and info.address_family != wsa_af_inet6) or
        info.socket_type != wsa_sock_stream or info.protocol != wsa_ipproto_tcp) return error.NotTcp;
    var listening: i32 = 0;
    var listening_len: i32 = @sizeOf(i32);
    if (getsockopt(handle, 0xFFFF, 0x0002, &listening, &listening_len) != 0 or
        listening_len != @sizeOf(i32)) return error.SocketFailed;
    return listening != 0;
}

fn windowsTcpEndpoint(name: RioSockAddr6) WindowsTcpObservationError!WindowsTcpEndpoint {
    return .{
        .address = switch (name.family) {
            wsa_af_inet => .{ .ipv4 = @bitCast(@as(*const RioSockAddr, @ptrCast(&name)).addr) },
            wsa_af_inet6 => .{ .ipv6 = name.addr },
            else => return error.SocketFailed,
        },
        .port = std.mem.bigToNative(u16, name.port),
    };
}

/// Observe the actual bound endpoint of a registered listening TCP SOCKET.
/// This is the authoritative family/host/port for the strict listener join.
pub fn observeWindowsListeningTcpSocket(fd: linux.fd_t) WindowsTcpObservationError!WindowsListenerObservation {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.InvalidSocket;
    if (!try windowsTcpStatus(socket)) return error.NotListening;
    const name = socketName(socket) catch return error.SocketFailed;
    const local = try windowsTcpEndpoint(name);
    if (local.port == 0) return error.NotListening;
    return .{ .local = local };
}

/// A state socket must have a live TCP peer; an unbound or listening stream
/// cannot stand in for a client or Mooring connection during Helix staging.
pub fn observeWindowsConnectedTcpSocket(fd: linux.fd_t) WindowsTcpObservationError!WindowsConnectedObservation {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.InvalidSocket;
    if (try windowsTcpStatus(socket)) return error.NotConnected;
    const name = socketName(socket) catch return error.NotConnected;
    const local = try windowsTcpEndpoint(name);
    var peer_name = std.mem.zeroes(RioSockAddr6);
    var peer_len: i32 = @sizeOf(RioSockAddr6);
    var peer: ?WindowsTcpEndpoint = null;
    if (getpeername(socket, @ptrCast(&peer_name), &peer_len) == 0 and
        ((peer_name.family == wsa_af_inet and peer_len == @sizeOf(RioSockAddr)) or
            (peer_name.family == wsa_af_inet6 and peer_len == @sizeOf(RioSockAddr6))))
        peer = try windowsTcpEndpoint(peer_name);
    if (peer == null or peer.?.port == 0) {
        // AFD's accept completion captured this peer from the kernel. Some
        // connected AcceptEx sockets still report an empty getpeername until
        // after a process-local duplicate is imported. Require the live TCP
        // connection as well as the saved completion endpoint.
        try observeWindowsHelixConnectedTcpSocket(fd);
        peer = windows_sockets.acceptedEndpoint(fd) orelse return error.NotConnected;
    }
    if (local.port == 0 or peer.?.port == 0 or std.meta.activeTag(local.address) != std.meta.activeTag(peer.?.address))
        return error.NotConnected;
    return .{ .local = local, .peer = peer.? };
}

/// AcceptEx sockets can report an empty peer sockaddr even while the TCP
/// connection is established. SO_CONNECT_TIME verifies that state without
/// consuming I/O or depending on per-descriptor accept context.
pub fn observeWindowsHelixConnectedTcpSocket(fd: linux.fd_t) WindowsTcpObservationError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.InvalidSocket;
    if (try windowsTcpStatus(socket)) return error.NotConnected;
    var connected_seconds: u32 = std.math.maxInt(u32);
    var length: i32 = @sizeOf(u32);
    if (getsockopt(socket, 0xFFFF, 0x700C, @ptrCast(&connected_seconds), &length) != 0 or
        length != @sizeOf(u32) or connected_seconds == std.math.maxInt(u32))
    {
        std.debug.print("onyx-server: Windows Helix SO_CONNECT_TIME failed for socket {d} (WSA {d}, length {d}, value {d})\n", .{ fd, WSAGetLastError(), length, connected_seconds });
        return error.NotConnected;
    }
    const local = try windowsTcpEndpoint(socketName(socket) catch {
        std.debug.print("onyx-server: Windows Helix local endpoint failed for socket {d} (WSA {d})\n", .{ fd, WSAGetLastError() });
        return error.NotConnected;
    });
    if (local.port == 0) {
        std.debug.print("onyx-server: Windows Helix local port is zero for socket {d}\n", .{fd});
        return error.NotConnected;
    }
}

/// Imported AcceptEx sockets can lose their process-local peer observation.
/// Return the verified live local endpoint and any Winsock peer observation;
/// an authenticated handoff may then compare its source peer witness with
/// this socket only after the established TCP check succeeds.
pub fn observeWindowsHelixConnectedTcpSocketEndpoints(fd: linux.fd_t) WindowsTcpObservationError!WindowsHelixConnectedObservation {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    try observeWindowsHelixConnectedTcpSocket(fd);
    const socket = windows_sockets.get(fd) orelse return error.InvalidSocket;
    const local = try windowsTcpEndpoint(socketName(socket) catch return error.NotConnected);
    var peer_name = std.mem.zeroes(RioSockAddr6);
    var peer_len: i32 = @sizeOf(RioSockAddr6);
    const peer: ?WindowsTcpEndpoint = if (getpeername(socket, @ptrCast(&peer_name), &peer_len) == 0 and
        ((peer_name.family == wsa_af_inet and peer_len == @sizeOf(RioSockAddr)) or
            (peer_name.family == wsa_af_inet6 and peer_len == @sizeOf(RioSockAddr6))))
    blk: {
        const observed = try windowsTcpEndpoint(peer_name);
        break :blk if (observed.port == 0) null else observed;
    } else null;
    return .{ .local = local, .peer = peer };
}

/// Preserve the signed predecessor's accepted peer witness on a staged socket.
/// AcceptEx does not always expose getpeername after WSADuplicateSocket, and a
/// successor can itself become the next Helix source. The caller supplies the
/// peer only after authenticating its source roster; this function independently
/// checks the imported canonical descriptor and established local endpoint.
pub fn rememberWindowsHelixAcceptedTcpPeer(fd: linux.fd_t, local: WindowsTcpEndpoint, peer: WindowsTcpEndpoint) WindowsTcpObservationError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (peer.port == 0 or std.meta.activeTag(local.address) != std.meta.activeTag(peer.address)) return error.NotConnected;
    const observed = try observeWindowsHelixConnectedTcpSocketEndpoints(fd);
    if (!std.meta.eql(observed.local, local)) return error.NotConnected;
    if (observed.peer) |actual| if (!std.meta.eql(actual, peer)) return error.NotConnected;
    try windows_sockets.rememberHelixAcceptedEndpoint(fd, peer);
}

test "Windows Helix TCP observation distinguishes listening and connected registry sockets" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const observed = try observeWindowsListeningTcpSocket(listener.fd);
    try std.testing.expectEqual(listener.port, observed.local.port);
    try std.testing.expectEqual(PeerAddress{ .ipv4 = .{ 127, 0, 0, 1 } }, observed.local.address);
    try std.testing.expectError(error.NotConnected, observeWindowsConnectedTcpSocket(listener.fd));
    try std.testing.expectError(error.NotConnected, observeWindowsHelixConnectedTcpSocket(listener.fd));

    const client = try openWindowsTcpSocket(wsa_af_inet);
    defer closeSocket(client);
    try std.testing.expectError(error.NotListening, observeWindowsListeningTcpSocket(client));
    try std.testing.expectError(error.NotConnected, observeWindowsConnectedTcpSocket(client));
    try std.testing.expectError(error.NotConnected, observeWindowsHelixConnectedTcpSocket(client));
    const destination = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = try ipv4Bits("127.0.0.1"),
        .zero = @splat(0),
    };
    const client_raw = windows_sockets.get(client) orelse return error.InvalidSocket;
    if (connect(client_raw, &destination, @sizeOf(RioSockAddr)) != 0) return error.ConnectFailed;
    const listener_raw = windows_sockets.get(listener.fd) orelse return error.InvalidSocket;
    const accepted_raw = accept(listener_raw, null, null);
    if (accepted_raw == std.math.maxInt(usize)) return error.AcceptFailed;
    const accepted = adoptWindowsSocket(accepted_raw) catch |err| {
        _ = closesocket(accepted_raw);
        return err;
    };
    defer closeSocket(accepted);
    const connected = try observeWindowsConnectedTcpSocket(client);
    try std.testing.expectEqual(listener.port, connected.peer.port);
    try std.testing.expectEqual(PeerAddress{ .ipv4 = .{ 127, 0, 0, 1 } }, connected.peer.address);
    _ = try observeWindowsConnectedTcpSocket(accepted);
    try observeWindowsHelixConnectedTcpSocket(client);
    try observeWindowsHelixConnectedTcpSocket(accepted);
}

pub fn socketPort(fd: linux.fd_t) error{ Unsupported, SocketFailed }!u16 {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const handle = windows_sockets.get(fd) orelse return error.SocketFailed;
    const name = try socketName(handle);
    return std.mem.bigToNative(u16, name.port);
}

pub fn socketPeerAddress(fd: linux.fd_t) error{ Unsupported, SocketFailed }!PeerAddress {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const handle = windows_sockets.get(fd) orelse return error.SocketFailed;
    if (windows_sockets.acceptedPeer(fd)) |peer| return peer;
    var name = std.mem.zeroes(RioSockAddr6);
    var name_len: i32 = @sizeOf(RioSockAddr6);
    if (getpeername(handle, @ptrCast(&name), &name_len) != 0) return error.SocketFailed;
    return switch (name.family) {
        wsa_af_inet => if (name_len >= @sizeOf(RioSockAddr))
            .{ .ipv4 = @bitCast(@as(*const RioSockAddr, @ptrCast(&name)).addr) }
        else
            error.SocketFailed,
        wsa_af_inet6 => if (name_len >= @sizeOf(RioSockAddr6))
            .{ .ipv6 = name.addr }
        else
            error.SocketFailed,
        else => error.SocketFailed,
    };
}

pub const WindowsSocketError = error{
    Unsupported,
    InvalidAddress,
    PermissionDenied,
    AddressInUse,
    SocketUnavailable,
    Unexpected,
};

/// Open an overlapped Winsock stream and register its pointer-sized SOCKET in
/// the descriptor table used by the IOCP reactor. Close with `closeSocket`.
pub fn openWindowsTcpSocket(family: u16) WindowsSocketError!linux.fd_t {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (family != wsa_af_inet and family != wsa_af_inet6) return error.InvalidAddress;
    try ensureWinsock();
    const socket = WSASocketW(@intCast(family), wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (socket == std.math.maxInt(usize)) return windowsSocketError();
    if (family == wsa_af_inet6) {
        // Mesh dials carry a canonical sockaddr_in6, including mapped IPv4.
        // Windows defaults IPv6 sockets to V6ONLY, which would reject those
        // mapped addresses before ConnectEx could reach an IPv4 peer.
        const no: i32 = 0;
        if (setsockopt(socket, 41, 27, &no, @sizeOf(i32)) != 0) {
            const err = windowsSocketError();
            _ = closesocket(socket);
            return err;
        }
    }
    return adoptWindowsSocket(socket) catch {
        _ = closesocket(socket);
        return error.SocketUnavailable;
    };
}

pub fn bindWindowsSocket(fd: linux.fd_t, addr: *const std.posix.sockaddr, addrlen: std.posix.socklen_t) WindowsSocketError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.SocketUnavailable;
    if (addrlen > std.math.maxInt(i32)) return error.InvalidAddress;
    if (bind(socket, addr, @intCast(addrlen)) != 0) return windowsSocketError();
}

pub fn listenWindowsSocket(fd: linux.fd_t, backlog: u31) WindowsSocketError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.SocketUnavailable;
    if (listen(socket, @intCast(backlog)) != 0) return windowsSocketError();
}

pub fn setWindowsSocketOption(fd: linux.fd_t, level: i32, optname: i32, opt: []const u8) WindowsSocketError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.SocketUnavailable;
    if (opt.len > std.math.maxInt(i32)) return error.Unexpected;
    if (setsockopt(socket, level, optname, @ptrCast(opt.ptr), @intCast(opt.len)) != 0) return windowsSocketError();
}

/// Set per-socket TCP keepalive state and timing. Winsock's
/// SIO_KEEPALIVE_VALS uses milliseconds and leaves the probe count at the OS
/// setting (normally ten on modern Windows).
/// A synchronous call (null OVERLAPPED) completes before this returns.
pub fn setWindowsTcpKeepalive(fd: linux.fd_t, enabled: bool, idle_ms: u32, interval_ms: u32) WindowsSocketError!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    const socket = windows_sockets.get(fd) orelse return error.SocketUnavailable;
    const values = TcpKeepalive{
        .onoff = @intFromBool(enabled),
        .keepalivetime = idle_ms,
        .keepaliveinterval = interval_ms,
    };
    var bytes: u32 = 0;
    if (WSAIoctl(socket, sio_keepalive_vals, &values, @sizeOf(TcpKeepalive), null, 0, &bytes, null, null) != 0)
        return windowsSocketError();
}

const TcpKeepalive = extern struct {
    onoff: u32,
    keepalivetime: u32,
    keepaliveinterval: u32,
};

// _WSAIOW(IOC_VENDOR, 4), from Winsock's mstcpip.h/winsock2.h.
const sio_keepalive_vals: u32 = 0x9800_0004;

test "Windows accepted TCP keepalive sets state and per-socket timing" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(TcpKeepalive));
    try std.testing.expectEqual(@as(u32, 0x9800_0004), sio_keepalive_vals);

    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const client = try openWindowsTcpSocket(wsa_af_inet);
    defer closeSocket(client);
    const destination = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = try ipv4Bits("127.0.0.1"),
        .zero = @splat(0),
    };
    const client_raw = windows_sockets.get(client) orelse return error.InvalidSocket;
    if (connect(client_raw, &destination, @sizeOf(RioSockAddr)) != 0) return error.ConnectFailed;
    const listener_raw = windows_sockets.get(listener.fd) orelse return error.InvalidSocket;
    const accepted_raw = accept(listener_raw, null, null);
    if (accepted_raw == std.math.maxInt(usize)) return error.AcceptFailed;
    const accepted = adoptWindowsSocket(accepted_raw) catch |err| {
        _ = closesocket(accepted_raw);
        return err;
    };
    defer closeSocket(accepted);

    try setWindowsTcpKeepalive(accepted, true, 30_000, 3_000);
    var keepalive: i32 = 0;
    var length: i32 = @sizeOf(i32);
    try std.testing.expectEqual(@as(i32, 0), getsockopt(accepted_raw, sol_socket, 0x0008, &keepalive, &length));
    try std.testing.expect(length == 1 or length == @sizeOf(i32));
    try std.testing.expect(keepalive != 0);

    // TCP_KEEPIDLE (3) and TCP_KEEPINTVL (17) report seconds on Windows 10
    // version 1709 and later. The native Windows test host supports both.
    var idle_seconds: u32 = 0;
    length = @sizeOf(u32);
    try std.testing.expectEqual(@as(i32, 0), getsockopt(accepted_raw, wsa_ipproto_tcp, 3, &idle_seconds, &length));
    try std.testing.expectEqual(@as(i32, @sizeOf(u32)), length);
    try std.testing.expectEqual(@as(u32, 30), idle_seconds);
    var interval_seconds: u32 = 0;
    length = @sizeOf(u32);
    try std.testing.expectEqual(@as(i32, 0), getsockopt(accepted_raw, wsa_ipproto_tcp, 17, &interval_seconds, &length));
    try std.testing.expectEqual(@as(i32, @sizeOf(u32)), length);
    try std.testing.expectEqual(@as(u32, 3), interval_seconds);

    try setWindowsTcpKeepalive(accepted, false, 30_000, 3_000);
    length = @sizeOf(i32);
    try std.testing.expectEqual(@as(i32, 0), getsockopt(accepted_raw, sol_socket, 0x0008, &keepalive, &length));
    try std.testing.expectEqual(@as(i32, 0), keepalive);

    closeSocket(accepted);
    try std.testing.expectError(error.SocketUnavailable, setWindowsTcpKeepalive(accepted, true, 30_000, 3_000));
}

fn windowsSocketError() WindowsSocketError {
    return switch (WSAGetLastError()) {
        10013 => error.PermissionDenied,
        10048 => error.AddressInUse,
        10049 => error.InvalidAddress,
        10024, 10055 => error.SocketUnavailable,
        else => error.Unexpected,
    };
}

test "Windows socket descriptors preserve pointer-sized handles and retire stale ids" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const high: usize = @as(usize, std.math.maxInt(i32)) + 0x1_0000_0000;
    const first = try sockets.register(high);
    try std.testing.expect(first > 0);
    try std.testing.expectEqual(@as(?usize, high), sockets.get(first));
    try std.testing.expectEqual(@as(?usize, high), sockets.take(first));
    try std.testing.expectEqual(@as(?usize, null), sockets.get(first));
    const second = try sockets.register(high);
    try std.testing.expect(second != first);
    try std.testing.expectEqual(@as(?usize, null), sockets.take(first));
    try std.testing.expectEqual(@as(?usize, high), sockets.take(second));
    const zero = try sockets.register(0);
    try std.testing.expectEqual(@as(?usize, 0), sockets.get(zero));
    try std.testing.expectEqual(@as(?usize, 0), sockets.take(zero));
    try std.testing.expectError(error.InvalidSocket, sockets.register(std.math.maxInt(usize)));
    try std.testing.expectEqual(@as(u32, @intCast(first)) & WindowsSockets.slot_mask, @as(u32, @intCast(second)) & WindowsSockets.slot_mask);
    try std.testing.expectEqual(@as(u32, @intCast(first)) & WindowsSockets.slot_mask, @as(u32, @intCast(zero)) & WindowsSockets.slot_mask);
    try std.testing.expect(first != second and second != zero);
}

test "Windows socket IDs recycle slots through generations without reviving stale IDs" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const first = try sockets.register(0x1_0000_0001);
    try std.testing.expectEqual(@as(?usize, 0x1_0000_0001), sockets.take(first));

    // This crosses several generation limits while retaining constant-size
    // active custody. The allocator moves to a fresh slot at each limit.
    var last = first;
    var count: usize = 0;
    while (count < 5000) : (count += 1) {
        const current = try sockets.register(count + 1);
        try std.testing.expect(current != last);
        try std.testing.expectEqual(@as(?usize, null), sockets.get(last));
        try std.testing.expectEqual(@as(?usize, null), sockets.take(last));
        try std.testing.expectEqual(@as(?usize, null), sockets.get(first));
        try std.testing.expectEqual(@as(?usize, count + 1), sockets.take(current));
        last = current;
    }
    try std.testing.expect(sockets.slots.count() > 1);
}

test "Windows socket ID generation wrap permanently retires a slot" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const slot: u32 = 7;
    const penultimate = WindowsSockets.encodeId(slot, WindowsSockets.max_generation - 1);
    try sockets.registerHelixImported(penultimate, 0x1001);
    try std.testing.expectEqual(@as(?usize, 0x1001), sockets.take(penultimate));
    const final = try sockets.register(0x2002);
    try std.testing.expectEqual(WindowsSockets.encodeId(slot, WindowsSockets.max_generation), final);
    try std.testing.expectEqual(@as(?usize, 0x2002), sockets.take(final));
    try std.testing.expectEqual(@as(?usize, null), sockets.get(penultimate));
    try std.testing.expectEqual(@as(?usize, null), sockets.get(final));
    const next = try sockets.register(0x3003);
    try std.testing.expect(next != final and next != penultimate);
    try std.testing.expect((@as(u32, @intCast(next)) & WindowsSockets.slot_mask) != slot);
    try std.testing.expectEqual(@as(?usize, 0x3003), sockets.take(next));
}

test "Windows socket ID rollover starts before exhaustion and preserves stale rejection" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    try std.testing.expect(!sockets.rolloverDue());
    sockets.claimed_id_count = WindowsSockets.rollover_claimed_ids - 1;
    const fd = try sockets.register(0x2002);
    try std.testing.expect(sockets.rolloverDue());
    try std.testing.expectEqual(@as(?usize, 0x2002), sockets.take(fd));
    try std.testing.expectEqual(@as(?usize, null), sockets.get(fd));
    try std.testing.expect(sockets.rolloverDue());
}

test "Windows Helix import credits skipped generations to rollover budget" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const first = WindowsSockets.encodeId(7, 5);
    const later = WindowsSockets.encodeId(7, 8);
    try sockets.registerHelixImported(first, 0x1001);
    try std.testing.expectEqual(@as(u64, 6), sockets.claimed_id_count);
    try sockets.registerHelixImported(later, 0x2002);
    try std.testing.expectEqual(@as(u64, 9), sockets.claimed_id_count);
    try std.testing.expectEqual(@as(?usize, 0x1001), sockets.take(first));
    try std.testing.expectEqual(@as(?usize, 0x2002), sockets.take(later));
}

test "Windows Helix imports overlapping legacy slot generations without aliasing" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const old: linux.fd_t = 7;
    const newer = WindowsSockets.encodeId(7, 1);
    try sockets.registerHelixImported(old, 0x1001);
    try sockets.registerHelixImported(newer, 0x2002);
    try std.testing.expectEqual(@as(?usize, 0x1001), sockets.take(old));
    try std.testing.expectEqual(@as(?usize, 0x2002), sockets.get(newer));
    const fresh = try sockets.register(0x3003);
    try std.testing.expect((@as(u32, @intCast(fresh)) & WindowsSockets.slot_mask) != 7);
    try std.testing.expectEqual(@as(?usize, 0x2002), sockets.take(newer));
    try std.testing.expectEqual(@as(?usize, 0x3003), sockets.take(fresh));
}

test "Windows Helix canonical socket IDs reject collision, invalid IDs and late import" {
    var sockets = WindowsSockets{ .allocator = std.testing.allocator };
    defer sockets.deinit();
    const raw: usize = 0x1234;
    try std.testing.expectError(error.InvalidSocketId, sockets.registerHelixImported(0, raw));
    try std.testing.expectError(error.InvalidSocketId, sockets.registerHelixImported(0x4000_0000, raw));
    try std.testing.expectError(error.InvalidSocket, sockets.registerHelixImported(1, std.math.maxInt(usize)));
    try sockets.registerHelixImported(7, raw);
    try std.testing.expectEqual(raw, sockets.get(7).?);
    try std.testing.expectError(error.SocketIdCollision, sockets.registerHelixImported(7, raw + 1));
    try std.testing.expectError(error.ImportOutOfOrder, sockets.registerHelixImported(6, raw + 1));
    try std.testing.expectError(error.InvalidSocketId, sockets.confirmHelixReleased(1));
    try sockets.confirmHelixReleased(7);
    try std.testing.expectError(error.InvalidReleaseState, sockets.confirmHelixReleased(7));
    try std.testing.expectEqual(@as(linux.fd_t, 8), try sockets.register(raw + 1));
    try std.testing.expectError(error.ImportOutOfOrder, sockets.registerHelixImported(9, raw + 2));
    try std.testing.expectEqual(@as(?usize, raw), sockets.take(7));
    try std.testing.expectEqual(@as(?usize, raw + 1), sockets.take(8));
}

test "Windows Helix source and abort access stay within their custody states" {
    var source = WindowsSockets{ .allocator = std.testing.allocator };
    defer source.deinit();
    const ordinary = try source.register(0x1001);
    try std.testing.expectEqual(@as(usize, 0x1001), try source.helixSourceHandle(ordinary));
    try std.testing.expectError(error.InvalidReleaseState, source.takeHelixStaged(ordinary));
    try std.testing.expectEqual(@as(?usize, 0x1001), source.take(ordinary));
    try std.testing.expectError(error.InvalidSocketId, source.helixSourceHandle(ordinary));

    var candidate = WindowsSockets{ .allocator = std.testing.allocator };
    defer candidate.deinit();
    try candidate.registerHelixImported(7, 0x2002);
    try std.testing.expectError(error.InvalidReleaseState, candidate.helixSourceHandle(7));
    try std.testing.expectEqual(@as(usize, 0x2002), try candidate.takeHelixStaged(7));
    try std.testing.expectError(error.InvalidSocketId, candidate.takeHelixStaged(7));
    try candidate.registerHelixImported(8, 0x3003);
    try candidate.confirmHelixReleased(8);
    try std.testing.expectError(error.InvalidReleaseState, candidate.takeHelixStaged(8));
    try std.testing.expectEqual(@as(?usize, 0x3003), candidate.take(8));
}

extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

test "Windows Helix imported SOCKET keeps exact ID and replaces IOCP only after release" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try ensureWinsock();
    const source = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped | 0x80);
    if (source == std.math.maxInt(usize)) return error.SocketCreationFailed;
    var source_open = true;
    defer if (source_open) {
        _ = closesocket(source);
    };
    var predecessor = WindowsSockets{ .allocator = std.testing.allocator };
    defer predecessor.deinit();
    const canonical = try predecessor.register(source);
    const old_port = try Iocp.openHandle();
    var old_port_open = true;
    defer if (old_port_open) {
        _ = std.os.windows.ntdll.NtClose(@ptrFromInt(old_port));
    };
    try predecessor.associate(canonical, source, old_port);

    var transfer = try helix_windows_socket.duplicateForProcess(source, GetCurrentProcessId());
    const imported = try transfer.import();
    defer _ = closesocket(imported);
    var successor = WindowsSockets{ .allocator = std.testing.allocator };
    defer successor.deinit();
    try successor.registerHelixImported(canonical, imported);
    try std.testing.expectEqual(imported, successor.get(canonical).?);
    const new_port = try Iocp.openHandle();
    defer _ = std.os.windows.ntdll.NtClose(@ptrFromInt(new_port));
    try std.testing.expectError(error.MissingOp, successor.associate(canonical, imported, new_port));
    try std.testing.expectEqual(@as(?usize, 0), successor.associatedPort(canonical));

    _ = predecessor.take(canonical);
    _ = closesocket(source);
    source_open = false;
    _ = std.os.windows.ntdll.NtClose(@ptrFromInt(old_port));
    old_port_open = false;
    try successor.confirmHelixReleased(canonical);
    try successor.associate(canonical, imported, new_port);
    try successor.associate(canonical, imported, new_port);
    try std.testing.expectEqual(@as(?usize, new_port), successor.associatedPort(canonical));
    try std.testing.expectError(error.MissingOp, successor.associate(canonical, imported, old_port));
    try std.testing.expectEqual(@as(?usize, imported), successor.take(canonical));
}

test "IOCP transfer completion cannot exceed the submitted buffer" {
    var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
    iosb.u.Status = .SUCCESS;
    const token = ringlane.FdToken{ .slot = 9, .gen = 4 };
    const token_key = Iocp.packToken(token);
    inline for (.{ Iocp.op_recv, Iocp.op_send }) |op| {
        const packet = Iocp.Packet{ .op = op, .length = 512, .token = token_key };
        iosb.Information = 513;
        const oversized = Iocp.finishPosted(packet, iosb, "", null);
        try std.testing.expectEqual(@as(i32, -1), oversized.result);
        try std.testing.expectEqual(token, oversized.token);
        iosb.Information = 512;
        try std.testing.expectEqual(@as(i32, 512), Iocp.finishPosted(packet, iosb, "", null).result);
    }
}

test "IOCP cancellation identifies the original request" {
    const token = Iocp.packToken(.{ .slot = 7, .gen = 2 });
    const pending = Iocp.Packet{ .op = Iocp.op_recv, .handle = 0x1234, .token = token, .serial = 55 };
    const cancel = Iocp.Packet{ .op = Iocp.op_cancel, .handle = 0x1234, .length = Iocp.op_recv, .token = token, .serial = 55 };
    try std.testing.expect(Iocp.matchesCancel(cancel, pending));
    try std.testing.expect(!Iocp.matchesCancel(cancel, .{ .op = Iocp.op_send, .handle = 0x1234, .token = token }));
    try std.testing.expect(!Iocp.matchesCancel(cancel, .{ .op = Iocp.op_recv, .handle = 0x1235, .token = token }));
    try std.testing.expect(!Iocp.matchesCancel(cancel, .{ .op = Iocp.op_recv, .handle = 0x1234, .token = token + 1 }));
    try std.testing.expect(!Iocp.matchesCancel(cancel, .{ .op = Iocp.op_recv, .handle = 0x1234, .token = token, .serial = 56 }));

    var backend = Iocp.unopened(4);
    defer backend.deinit();
    const original = try backend.remember(token, 0x1234, Iocp.op_recv);
    try std.testing.expectError(error.MissingOp, backend.remember(token, 0x1234, Iocp.op_recv));
    backend.forgetSerial(original);
    const replacement = try backend.remember(token, 0x1234, Iocp.op_recv);
    try std.testing.expect(replacement != original);
    backend.forgetSerial(replacement);
    try backend.pushReady(.{ .op = .recv, .token = .{ .slot = 7, .gen = 2 }, .result = 1 });
    try backend.enqueueCancel(.recv, .{ .slot = 7, .gen = 2 });
    try std.testing.expectEqual(@as(u16, 0), backend.n);

    const connecting = Iocp.Packet{ .op = Iocp.op_connect, .handle = 0x1234, .token = token, .serial = 88 };
    const cancel_connect = Iocp.Packet{ .op = Iocp.op_cancel, .handle = 0x1234, .length = Iocp.op_connect, .token = token, .serial = 88 };
    try std.testing.expect(Iocp.matchesCancel(cancel_connect, connecting));
    try std.testing.expect(!Iocp.matchesCancel(cancel_connect, .{ .op = Iocp.op_connect, .handle = 0x1234, .token = token, .serial = 89 }));

    var cancelled_iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
    cancelled_iosb.u.Status = .CANCELLED;
    const canceled_connect = Iocp.finishPosted(connecting, cancelled_iosb, "", null);
    try std.testing.expectEqual(Op.connect, canceled_connect.op);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), canceled_connect.result);
}

test "IOCP ready queue preserves order while growing past one submit batch" {
    var backend = Iocp.unopened(32);
    defer backend.deinit();
    try backend.ensureReadyCapacity(320);
    for (0..320) |i| {
        try backend.pushReady(.{ .op = .send, .token = .{ .slot = @intCast(i + 1), .gen = 1 }, .result = @intCast(i) });
    }
    for (0..100) |i| {
        const event = backend.popReady().?;
        try std.testing.expectEqual(@as(u32, @intCast(i + 1)), event.token.slot);
    }
    try backend.ensureReadyCapacity(100);
    for (320..420) |i| {
        try backend.pushReady(.{ .op = .send, .token = .{ .slot = @intCast(i + 1), .gen = 1 }, .result = @intCast(i) });
    }
    for (100..420) |i| {
        const event = backend.popReady().?;
        try std.testing.expectEqual(@as(u32, @intCast(i + 1)), event.token.slot);
        try std.testing.expectEqual(@as(i32, @intCast(i)), event.result);
    }
    try std.testing.expectEqual(@as(?Reaped, null), backend.popReady());
}

test "Windows IOCP keeps slab status addresses stable across 320 pending accepts" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 32, .{});
    defer backend.deinit();
    var listeners: [320]linux.fd_t = @splat(-1);
    defer for (listeners) |fd| closeSocket(fd);
    defer backend.quiesce() catch @panic("IOCP slab test requests remained in use");
    var first_iosb: usize = 0;
    for (&listeners, 0..) |*fd, i| {
        const listener = try listenTcp("127.0.0.1", 0);
        fd.* = listener.fd;
        try backend.accept(.{ .slot = @intCast(i + 1), .gen = 7 }, listener.fd);
        if (backend.queuedCount() == 32) {
            try std.testing.expectEqual(@as(u32, 32), try backend.submit());
            if (i == 31) {
                const slab = backend.iocp.?.slabs.items[0];
                for (&slab.slots) |*slot| {
                    if (slot.live and slot.packet.token == Iocp.packToken(.{ .slot = 1, .gen = 7 })) {
                        first_iosb = @intFromPtr(&slot.iosb);
                        break;
                    }
                }
                try std.testing.expect(first_iosb != 0);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 320), backend.iocp.?.liveCount());
    try std.testing.expect(backend.iocp.?.slabs.items.len >= 2);
    try std.testing.expectEqual(first_iosb, @intFromPtr(&backend.iocp.?.findSlotByApc(first_iosb).?.iosb));

    const first = ringlane.FdToken{ .slot = 1, .gen = 7 };
    const last = ringlane.FdToken{ .slot = 320, .gen = 7 };
    try backend.cancel(.accept, first);
    try backend.cancel(.accept, last);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    var events: [2]Reaped = undefined;
    var seen_first = false;
    var seen_last = false;
    for (0..20) |_| {
        const count = try backend.reap(&events, 100);
        for (events[0..count]) |event| {
            try std.testing.expectEqual(Op.accept, event.op);
            try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), event.result);
            if (std.meta.eql(event.token, first)) seen_first = true else if (std.meta.eql(event.token, last)) seen_last = true else return error.UnexpectedToken;
        }
        if (seen_first and seen_last) break;
    }
    try std.testing.expect(seen_first and seen_last);
    try std.testing.expectEqual(@as(usize, 318), backend.iocp.?.liveCount());
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());

    // A later failed post must not strand the first kernel request or leave
    // the never-posted request registered for a token that cannot complete.
    const posted = ringlane.FdToken{ .slot = 321, .gen = 7 };
    const unposted = ringlane.FdToken{ .slot = 322, .gen = 7 };
    try backend.accept(posted, listeners[0]);
    backend.iocp.?.packets[backend.iocp.?.n] = .{ .op = 0xff };
    backend.iocp.?.n += 1;
    try backend.accept(unposted, listeners[1]);
    try std.testing.expectError(error.MissingOp, backend.submit());
    try std.testing.expect(backend.iocp.?.submit_failed);
    try std.testing.expectEqual(@as(usize, 1), backend.iocp.?.liveCount());
    try std.testing.expect(backend.iocp.?.lookup(Iocp.packToken(unposted), Iocp.op_accept) == null);
    try std.testing.expectError(error.MissingOp, backend.accept(.{ .slot = 323, .gen = 7 }, listeners[2]));
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());
}

test "Windows IOCP quiesce releases never-posted token registrations" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 4, .{});
    defer backend.deinit();
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    defer backend.quiesce() catch @panic("IOCP queued-token test requests remained in use");

    const token = ringlane.FdToken{ .slot = 451, .gen = 12 };
    try backend.accept(token, listener.fd);
    try std.testing.expectEqual(@as(usize, 1), backend.queuedCount());
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.queuedCount());
    try backend.accept(token, listener.fd);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    try backend.cancel(.accept, token);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    var event: [1]Reaped = undefined;
    try std.testing.expectEqual(@as(u32, 1), try backend.reap(&event, 1000));
    try std.testing.expectEqual(Op.accept, event[0].op);
    try std.testing.expectEqual(token, event[0].token);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), event[0].result);
}

test "IOCP AFD poll decodes output events instead of IOSB byte count" {
    try std.testing.expectEqual(
        afd_poll_receive | afd_poll_accept | afd_poll_disconnect | afd_poll_abort | afd_poll_local_close,
        Iocp.afdPollRequest(linux.POLL.IN),
    );
    try std.testing.expectEqual(
        afd_poll_send | afd_poll_connect_fail | afd_poll_disconnect | afd_poll_abort | afd_poll_local_close,
        Iocp.afdPollRequest(linux.POLL.OUT),
    );
    const token = ringlane.FdToken{ .slot = 33, .gen = 4 };
    const packet = Iocp.Packet{ .op = Iocp.op_poll, .handle = 0x1234, .length = linux.POLL.IN | linux.POLL.OUT, .token = Iocp.packToken(token) };
    var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
    iosb.u.Status = .SUCCESS;
    iosb.Information = @sizeOf(AfdPollInfo);
    var output = AfdPollInfo{ .timeout = 0, .handle_count = 1, .exclusive = 0, .handles = .{ .handle = packet.handle, .events = afd_poll_send, .status = 0 } };
    var done = Iocp.finishPosted(packet, iosb, "", &output);
    try std.testing.expectEqual(Op.poll, done.op);
    try std.testing.expectEqual(token, done.token);
    try std.testing.expectEqual(@as(i32, linux.POLL.OUT), done.result);
    output.handles.events = afd_poll_receive;
    done = Iocp.finishPosted(packet, iosb, "", &output);
    try std.testing.expectEqual(@as(i32, linux.POLL.IN), done.result);
    output.handles.events = afd_poll_disconnect;
    done = Iocp.finishPosted(packet, iosb, "", &output);
    try std.testing.expectEqual(@as(i32, linux.POLL.IN | linux.POLL.HUP), done.result);
    output.handle_count = 0;
    try std.testing.expectEqual(@as(i32, -1), Iocp.finishPosted(packet, iosb, "", &output).result);
    output.handle_count = 1;
    output.handles.handle = 0x9999;
    try std.testing.expectEqual(@as(i32, -1), Iocp.finishPosted(packet, iosb, "", &output).result);
    iosb.u.Status = .CANCELLED;
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), Iocp.finishPosted(packet, iosb, "", &output).result);
}

test "Windows IOCP AFD poll reports native loopback readiness masks" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const peer = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(peer)) return error.SocketUnavailable;
    defer _ = closesocket(peer);
    const addr = RioSockAddr{ .family = @intCast(wsa_af_inet), .port = std.mem.nativeToBig(u16, listener.port), .addr = std.mem.nativeToBig(u32, 0x7f000001), .zero = @splat(0) };
    if (connect(peer, &addr, @sizeOf(RioSockAddr)) != 0) return error.SocketUnavailable;
    const accepted = try pullAccept(listener.fd);
    defer closeSocket(accepted);
    defer backend.quiesce() catch @panic("AFD poll test request remained in use");
    const writable_token = ringlane.FdToken{ .slot = 51, .gen = 1 };
    try backend.poll(writable_token, accepted, linux.POLL.OUT);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    var events: [1]Reaped = undefined;
    try std.testing.expectEqual(@as(u32, 1), try backend.reap(&events, 1000));
    try std.testing.expectEqual(Op.poll, events[0].op);
    try std.testing.expectEqual(writable_token, events[0].token);
    try std.testing.expectEqual(@as(i32, linux.POLL.OUT), events[0].result);

    const readable_token = ringlane.FdToken{ .slot = 52, .gen = 1 };
    try backend.poll(readable_token, accepted, linux.POLL.IN);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    const payload: []const u8 = "p";
    try std.testing.expectEqual(@as(i32, 1), send(peer, payload.ptr, 1, 0));
    try std.testing.expectEqual(@as(u32, 1), try backend.reap(&events, 1000));
    try std.testing.expectEqual(Op.poll, events[0].op);
    try std.testing.expectEqual(readable_token, events[0].token);
    try std.testing.expectEqual(@as(i32, linux.POLL.IN), events[0].result);
}

test "Windows IOCP ConnectEx completes loopback and cancels exact outbound token" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    const canceled_listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(canceled_listener.fd);
    const live_listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(live_listener.fd);
    const canceled_socket = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(canceled_socket)) return error.SocketUnavailable;
    const canceled_fd = adoptWindowsSocket(canceled_socket) catch |err| {
        _ = closesocket(canceled_socket);
        return err;
    };
    defer closeSocket(canceled_fd);
    const live_socket = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(live_socket)) return error.SocketUnavailable;
    const live_fd = adoptWindowsSocket(live_socket) catch |err| {
        _ = closesocket(live_socket);
        return err;
    };
    defer closeSocket(live_fd);
    defer backend.quiesce() catch @panic("ConnectEx test requests remained in use");

    var canceled_addr = RioSockAddr{ .family = @intCast(wsa_af_inet), .port = std.mem.nativeToBig(u16, canceled_listener.port), .addr = std.mem.nativeToBig(u32, 0x7f000001), .zero = @splat(0) };
    var live_addr = RioSockAddr{ .family = @intCast(wsa_af_inet), .port = std.mem.nativeToBig(u16, live_listener.port), .addr = std.mem.nativeToBig(u32, 0x7f000001), .zero = @splat(0) };
    const canceled_token = ringlane.FdToken{ .slot = 41, .gen = 5 };
    const live_token = ringlane.FdToken{ .slot = 42, .gen = 5 };
    try backend.connect(canceled_token, canceled_fd, @ptrCast(&canceled_addr), @sizeOf(RioSockAddr));
    try backend.connect(live_token, live_fd, @ptrCast(&live_addr), @sizeOf(RioSockAddr));
    // Enqueue copies the endpoint: these caller-owned addresses can change
    // before submit without redirecting the pending request.
    canceled_addr.port = 0;
    live_addr.port = 0;
    try backend.cancel(.connect, canceled_token);
    try std.testing.expectEqual(@as(u32, 3), try backend.submit());

    var events: [2]Reaped = undefined;
    var seen_canceled = false;
    var seen_live = false;
    for (0..20) |_| {
        const count = try backend.reap(&events, 100);
        for (events[0..count]) |event| {
            try std.testing.expectEqual(Op.connect, event.op);
            if (std.meta.eql(event.token, canceled_token)) {
                try std.testing.expect(!seen_canceled);
                try std.testing.expect(event.result == 0 or event.result == -@as(i32, @intFromEnum(linux.E.CANCELED)));
                seen_canceled = true;
            } else {
                try std.testing.expectEqual(live_token, event.token);
                try std.testing.expect(!seen_live);
                try std.testing.expectEqual(@as(i32, 0), event.result);
                seen_live = true;
            }
        }
        if (seen_canceled and seen_live) break;
    }
    try std.testing.expect(seen_canceled and seen_live);
    const accepted = try pullAccept(live_listener.fd);
    defer closeSocket(accepted);
    var recv_timeout: i32 = 1000;
    try std.testing.expectEqual(@as(i32, 0), setsockopt(windows_sockets.get(accepted).?, sol_socket, so_rcvtimeo, &recv_timeout, @sizeOf(i32)));
    try std.testing.expectEqual(@as(i32, 0), shutdown(live_socket, 1));
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 0), recv(windows_sockets.get(accepted).?, &one, 1, 0));
}

test "Windows IOCP associates each socket lifetime and drains cancellation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    var previous_fd: linux.fd_t = -1;
    for (0..24) |iteration| {
        const listener = try listenTcp("127.0.0.1", 0);
        defer closeSocket(listener.fd);
        try std.testing.expect(listener.fd != previous_fd);
        try std.testing.expectEqual(@as(?usize, 0), windows_sockets.associatedPort(listener.fd));
        const token = ringlane.FdToken{ .slot = @intCast(iteration + 1), .gen = 1 };
        try backend.accept(token, listener.fd);
        try std.testing.expectEqual(@as(u32, 1), try backend.submit());
        try std.testing.expectEqual(@as(usize, 1), backend.iocp.?.liveCount());
        try std.testing.expectEqual(@as(?usize, backend.iocp.?.port), windows_sockets.associatedPort(listener.fd));
        try backend.cancel(.accept, token);
        _ = try backend.submit();
        try backend.quiesce();
        try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());
        previous_fd = listener.fd;
    }
}

test "Windows IOCP quiesce drains more than 64 pending requests" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 128, .{});
    defer backend.deinit();
    var listeners: [96]linux.fd_t = @splat(-1);
    defer for (listeners) |fd| closeSocket(fd);
    for (&listeners, 0..) |*fd, i| {
        const listener = try listenTcp("127.0.0.1", 0);
        fd.* = listener.fd;
        try backend.accept(.{ .slot = @intCast(i + 1), .gen = 1 }, listener.fd);
    }
    try std.testing.expectEqual(@as(u32, listeners.len), try backend.submit());
    try std.testing.expectEqual(listeners.len, backend.iocp.?.liveCount());
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());
}

test "Windows IOCP quiesce retains pending recv and send buffers" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const peer = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(peer)) return error.SocketUnavailable;
    defer _ = closesocket(peer);
    const addr = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (connect(peer, &addr, @sizeOf(RioSockAddr)) != 0) return error.SocketUnavailable;
    var accepted = try pullAccept(listener.fd);
    defer if (accepted >= 0) closeSocket(accepted);
    const accepted_handle = windows_sockets.get(accepted).?;
    var sndbuf: i32 = 4096;
    try std.testing.expectEqual(@as(i32, 0), setsockopt(accepted_handle, sol_socket, 0x1001, &sndbuf, @sizeOf(i32)));

    var recv_buf: [64]u8 = undefined;
    const send_buf = try std.testing.allocator.alloc(u8, 16 * 1024 * 1024);
    defer std.testing.allocator.free(send_buf);
    @memset(send_buf, 's');
    // On any assertion failure, drain before either buffer's defer runs.
    defer backend.quiesce() catch @panic("IOCP test buffers remained in use");
    try backend.recv(.{ .slot = 1, .gen = 1 }, accepted, &recv_buf);
    for (0..4) |i| {
        try backend.send(.{ .slot = @intCast(i + 2), .gen = 1 }, accepted, send_buf);
    }
    try std.testing.expectEqual(@as(u32, 5), try backend.submit());
    // Recv has no incoming data; repeated sends fill the small socket buffer
    // and leave at least one send waiting for the unread peer.
    try std.testing.expect(backend.iocp.?.liveCount() >= 2);
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());

    // A closed socket makes NtCancelIoFileEx report INVALID_HANDLE while the
    // original completion can still be queued. The IOSB must survive until
    // that queued completion is collected.
    var late_recv: [32]u8 = undefined;
    try backend.recv(.{ .slot = 12, .gen = 1 }, accepted, &late_recv);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    closeSocket(accepted);
    accepted = -1;
    try backend.quiesce();
    try std.testing.expectEqual(@as(usize, 0), backend.iocp.?.liveCount());
}

test "Windows IOCP delivers exact timeout tokens and cancels only the target" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    const canceled = ringlane.FdToken{ .slot = 17, .gen = 3 };
    const expired = ringlane.FdToken{ .slot = 18, .gen = 4 };
    var long = linux.kernel_timespec{ .sec = 10, .nsec = 0 };
    var short = linux.kernel_timespec{ .sec = 0, .nsec = 20_000_000 };
    try backend.timeout(canceled, &long);
    try backend.timeout(expired, &short);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    try backend.cancel(.timeout, canceled);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    var events: [2]Reaped = undefined;
    try std.testing.expectEqual(@as(u32, 1), try backend.reap(&events, 500));
    try std.testing.expectEqual(Op.timeout, events[0].op);
    try std.testing.expectEqual(expired, events[0].token);
    try std.testing.expectEqual(@as(i32, 0), events[0].result);
    try std.testing.expectEqual(@as(u32, 0), try backend.reap(&events, 0));
    try std.testing.expectError(error.MissingOp, backend.cancel(.timeout, canceled));
    try std.testing.expectError(error.MissingOp, backend.cancel(.timeout, expired));

    // A canceled operation may be replaced under the same public token
    // before the old completion is collected. Its serial keeps cancel exact.
    try backend.timeout(canceled, &long);
    _ = try backend.submit();
    try backend.cancel(.timeout, canceled);
    try backend.timeout(canceled, &short);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    try std.testing.expectEqual(@as(u32, 1), try backend.reap(&events, 500));
    try std.testing.expectEqual(canceled, events[0].token);
    try std.testing.expectEqual(@as(u32, 0), try backend.reap(&events, 0));
}

test "Windows IOCP reuses timer storage after repeated expiry" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    var instant = linux.kernel_timespec{ .sec = 0, .nsec = 0 };
    var events: [1]Reaped = undefined;
    for (0..100) |i| {
        const token = ringlane.FdToken{ .slot = @intCast(i + 1), .gen = 7 };
        try backend.timeout(token, &instant);
        try std.testing.expectEqual(@as(u32, 1), try backend.submit());
        try std.testing.expectEqual(@as(u32, 1), try backend.reap(&events, 0));
        try std.testing.expectEqual(Op.timeout, events[0].op);
        try std.testing.expectEqual(token, events[0].token);
        try std.testing.expectEqual(@as(usize, 8), backend.iocp.?.timers.len);
    }
    const canceled = ringlane.FdToken{ .slot = 200, .gen = 8 };
    try backend.timeout(canceled, &instant);
    try backend.cancel(.timeout, canceled);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    try std.testing.expectEqual(@as(u32, 0), try backend.reap(&events, 0));
}

test "Windows AFD adopted sockets can half-close with a TCP FIN" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.iocp, 8, .{});
    defer backend.deinit();
    for (0..16) |i| {
        const listener = try listenTcp("127.0.0.1", 0);
        defer closeSocket(listener.fd);
        try backend.accept(.{ .slot = @intCast(i + 1), .gen = 1 }, listener.fd);
        try std.testing.expectEqual(@as(u32, 1), try backend.submit());
        const peer = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
        if (!socketLive(peer)) return error.SocketUnavailable;
        defer _ = closesocket(peer);
        var recv_timeout: i32 = 1000;
        try std.testing.expectEqual(@as(i32, 0), setsockopt(peer, sol_socket, so_rcvtimeo, &recv_timeout, @sizeOf(i32)));
        const addr = RioSockAddr{
            .family = @intCast(wsa_af_inet),
            .port = std.mem.nativeToBig(u16, listener.port),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
            .zero = @splat(0),
        };
        try std.testing.expectEqual(@as(i32, 0), connect(peer, &addr, @sizeOf(RioSockAddr)));
        var events: [1]Reaped = undefined;
        var n: u32 = 0;
        for (0..10) |_| {
            n = try backend.reap(&events, 100);
            if (n != 0) break;
        }
        try std.testing.expectEqual(@as(u32, 1), n);
        try std.testing.expectEqual(Op.accept, events[0].op);
        try std.testing.expect(events[0].result >= 0);
        const accepted = events[0].result;
        defer closeSocket(accepted);
        var recv_buf: [16]u8 = undefined;
        const recv_token = ringlane.FdToken{ .slot = @intCast(i + 100), .gen = 2 };
        try backend.recv(recv_token, accepted, &recv_buf);
        _ = try backend.submit();
        try backend.cancel(.recv, recv_token);
        _ = try backend.submit();
        n = 0;
        for (0..10) |_| {
            n = try backend.reap(&events, 100);
            if (n != 0) break;
        }
        try std.testing.expectEqual(@as(u32, 1), n);
        try std.testing.expectEqual(Op.recv, events[0].op);
        try std.testing.expect(events[0].result < 0);
        try std.testing.expectEqual(@as(i32, 0), shutdown(windows_sockets.get(accepted).?, 1));
        var one: [1]u8 = undefined;
        try std.testing.expectEqual(@as(i32, 0), recv(peer, &one, 1, 0));
    }
}

pub const ListenError = error{ InvalidAddress, SocketUnavailable, AddressInUse, PermissionDenied, Unsupported };

/// One `RIODequeueCompletion` against the table `Iocp.open` stored.
/// `ok` is true only when that call returned a 4-byte success and the peer
/// socket read those same bytes. A closed port, a non-Windows host, or a
/// kernel error leaves `ok` false and names the failing `stage`.
pub const RioWitness = struct {
    ok: bool = false,
    stage: []const u8 = "",
    count: u32 = 0,
    status: i32 = 0,
    bytes: u32 = 0,
    errno: i32 = 0,
};

pub fn familyFor(tag: std.Target.Os.Tag) Family {
    return switch (tag) {
        .linux => .ringlane,
        .windows => .iocp,
        .freebsd, .netbsd, .openbsd, .dragonfly, .macos, .ios => .kqueue,
        else => .kqueue,
    };
}

pub const IoBackend = struct {
    family: Family,
    entries: u16,
    features: ringlane.RingFeatures = .{},
    owned: ?ringlane.Ring = null,
    borrowed: ?*ringlane.Ring = null,
    /// Heap kqueue state. Null on the Linux ring path so a borrowed backend
    /// stays a pointer, not a change batch, on the hot path.
    kq: ?*Kqueue = null,
    /// Heap IOCP state. Null on the Linux ring path.
    iocp: ?*Iocp = null,

    pub fn openOwned(family: Family, entries: u16, features: ringlane.RingFeatures) !IoBackend {
        switch (family) {
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                return .{
                    .family = .ringlane,
                    .entries = entries,
                    .features = features,
                    .owned = try ringlane.Ring.init(entries, features),
                };
            },
            .iocp => {
                const opened = try Iocp.open(entries);
                const iocp = std.heap.page_allocator.create(Iocp) catch {
                    var doomed = opened;
                    doomed.deinit();
                    return error.OutOfMemory;
                };
                iocp.* = opened;
                return .{
                    .family = .iocp,
                    .entries = entries,
                    .iocp = iocp,
                };
            },
            .kqueue => {
                const opened = try Kqueue.open(entries);
                const kq = std.heap.page_allocator.create(Kqueue) catch {
                    var doomed = opened;
                    doomed.deinit();
                    return error.OutOfMemory;
                };
                kq.* = opened;
                return .{
                    .family = .kqueue,
                    .entries = entries,
                    .kq = kq,
                };
            },
        }
    }

    pub fn closed(family: Family, entries: u16) IoBackend {
        return .{ .family = family, .entries = entries };
    }

    pub fn borrow(ring: *ringlane.Ring) IoBackend {
        return .{
            .family = .ringlane,
            .entries = 0,
            .features = ring.features,
            .borrowed = ring,
        };
    }

    pub fn deinit(self: *IoBackend) void {
        if (comptime builtin.os.tag == .linux) {
            if (self.owned) |*ring| ring.deinit();
        }
        self.owned = null;
        self.borrowed = null;
        if (self.kq) |kq| {
            kq.deinit();
            std.heap.page_allocator.destroy(kq);
            self.kq = null;
        }
        if (self.iocp) |iocp| {
            iocp.deinit();
            std.heap.page_allocator.destroy(iocp);
            self.iocp = null;
        }
    }

    /// Finish every posted Windows request before its caller-owned buffers or
    /// the backend's IO_STATUS_BLOCK storage can be released.
    pub fn quiesce(self: *IoBackend) !void {
        if (comptime builtin.os.tag != .windows) return;
        if (self.family != .iocp) return;
        const iocp = self.iocp orelse return;
        try iocp.quiesceWindows();
    }

    /// Move the owned Linux ring out. The caller deinits that ring.
    /// IOCP and kqueue have nothing to move.
    pub fn detachOwned(self: *IoBackend) ?ringlane.Ring {
        if (self.family != .ringlane) return null;
        const ring = self.owned orelse return null;
        self.owned = null;
        return ring;
    }

    fn ringPtr(self: *IoBackend) ?*ringlane.Ring {
        if (self.borrowed) |ring| return ring;
        if (self.owned) |*ring| return ring;
        return null;
    }

    pub fn opImplemented(self: *IoBackend, op: Op) bool {
        switch (self.family) {
            .ringlane => return self.ringPtr() != null,
            .kqueue => {
                const kq = self.kq orelse return false;
                if (kq.fd < 0) return false;
                return switch (op) {
                    .accept, .recv, .send, .poll, .cancel, .timeout, .connect => true,
                };
            },
            .iocp => {
                const iocp = self.iocp orelse return false;
                if (iocp.port == 0) return false;
                return switch (op) {
                    .accept, .recv, .send, .poll, .cancel, .timeout, .connect => true,
                };
            },
        }
    }

    fn kqueuePtr(self: *IoBackend) !*Kqueue {
        if (self.family != .kqueue) return error.MissingOp;
        if (self.kq) |kq| return kq;
        const kq = std.heap.page_allocator.create(Kqueue) catch return error.OutOfMemory;
        kq.* = Kqueue.unopened(self.entries);
        self.kq = kq;
        return kq;
    }

    fn iocpPtr(self: *IoBackend) !*Iocp {
        if (self.family != .iocp) return error.MissingOp;
        if (self.iocp) |iocp| return iocp;
        const iocp = std.heap.page_allocator.create(Iocp) catch return error.OutOfMemory;
        iocp.* = Iocp.unopened(self.entries);
        self.iocp = iocp;
        return iocp;
    }

    /// Filter and flags recorded for a kqueue change that was not submitted.
    /// `error.MissingOp` when that slot was not described.
    pub fn describedChange(self: *IoBackend, index: usize) error{MissingOp}!Kqueue.Queued {
        const kq = self.kq orelse return error.MissingOp;
        if (index >= kq.n) return error.MissingOp;
        const change = kq.changes[index];
        return .{
            .filter = change.filter,
            .flags = change.flags,
            .ident = change.ident,
            .data = change.data,
        };
    }

    /// Packet recorded for an IOCP op that was not submitted.
    /// `error.MissingOp` when that slot was not described.
    pub fn describedPacket(self: *IoBackend, index: usize) error{MissingOp}!Iocp.Packet {
        const iocp = self.iocp orelse return error.MissingOp;
        if (index >= iocp.n) return error.MissingOp;
        return iocp.packets[index];
    }

    pub fn requireAll(self: *IoBackend) error{MissingOp}!void {
        for (required_ops) |op| {
            if (!self.opImplemented(op)) return error.MissingOp;
        }
    }

    pub fn accept(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueAccept(token, fd),
            .iocp => return (try self.iocpPtr()).enqueueAccept(token, fd),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitAccept(token, fd);
            },
        }
    }

    pub fn recv(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueRecv(token, fd, buffer),
            .iocp => return (try self.iocpPtr()).enqueueRecv(token, fd, buffer),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitRecv(token, fd, buffer);
            },
        }
    }

    pub fn send(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueSend(token, fd, buffer),
            .iocp => return (try self.iocpPtr()).enqueueSend(token, fd, buffer),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitSend(token, fd, buffer);
            },
        }
    }

    /// Full daemon sockets use one operation per completion, like Ringlane.
    /// The small PortableServer retains its existing persistent read watches.
    pub fn useStreamCompletions(self: *IoBackend) !void {
        const kq = try self.kqueuePtr();
        if (kq.n != 0 or kq.regs.len != 0) return error.MissingOp;
        kq.stream_completions = true;
    }

    pub fn queuedCount(self: *const IoBackend) u32 {
        if (self.kq) |kq| return kq.n;
        if (self.iocp) |iocp| return iocp.n;
        return 0;
    }

    pub fn connect(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, addr: *const std.posix.sockaddr, addrlen: std.posix.socklen_t) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueConnect(token, fd, addr, addrlen),
            .iocp => return (try self.iocpPtr()).enqueueConnect(token, fd, addr, addrlen),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                return (self.ringPtr() orelse return error.MissingOp).submitConnect(token, fd, addr, addrlen);
            },
        }
    }

    pub fn poll(self: *IoBackend, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueuePoll(token, fd, poll_mask),
            .iocp => return (try self.iocpPtr()).enqueuePoll(token, fd, poll_mask),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitPollAdd(token, fd, poll_mask);
            },
        }
    }

    pub fn cancel(self: *IoBackend, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueCancel(kind, token),
            .iocp => return (try self.iocpPtr()).enqueueCancel(kind, token),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitExactCancel(kind, token);
            },
        }
    }

    pub fn timeout(self: *IoBackend, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).enqueueTimeout(token, ts),
            .iocp => return (try self.iocpPtr()).enqueueTimeout(token, ts),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submitTimeout(token, ts);
            },
        }
    }

    pub fn submit(self: *IoBackend) !u32 {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).submit(),
            .iocp => return (try self.iocpPtr()).submit(),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                const ring = self.ringPtr() orelse return error.MissingOp;
                return ring.submit();
            },
        }
    }

    /// kqueue stays armed after a successful submit. The ring and IOCP post
    /// one operation and the caller queues the next one.
    pub fn levelTriggered(self: *const IoBackend) bool {
        return self.family == .kqueue;
    }

    pub fn queueFd(self: *const IoBackend) linux.fd_t {
        if (self.kq) |kq| return kq.fd;
        return -1;
    }

    /// Wait up to `wait_ms` for completions. `0` does not block. A closed
    /// backend is `error.MissingOp`. An empty wait is `0`, not a transfer.
    pub fn reap(self: *IoBackend, out: []Reaped, wait_ms: u32) !u32 {
        switch (self.family) {
            .kqueue => return (try self.kqueuePtr()).reap(out, wait_ms),
            .iocp => return (try self.iocpPtr()).reap(out, wait_ms),
            .ringlane => {
                if (comptime builtin.os.tag != .linux) return error.MissingOp;
                return self.reapRing(out, wait_ms);
            },
        }
    }

    fn reapRing(self: *IoBackend, out: []Reaped, wait_ms: u32) !u32 {
        const ring = self.ringPtr() orelse return error.MissingOp;
        var cqes: [32]linux.io_uring_cqe = undefined;
        const Sink = struct {
            dest: []Reaped,
            n: usize = 0,

            pub fn onCompletion(sink: *@This(), completion: ringlane.Completion) void {
                if (sink.n >= sink.dest.len) return;
                const item: ?Reaped = switch (completion) {
                    .accept => |ev| .{ .op = .accept, .token = ev.token, .result = ev.res },
                    .recv => |ev| .{ .op = .recv, .token = ev.token, .result = ev.res },
                    .send => |ev| .{ .op = .send, .token = ev.token, .result = ev.res },
                    .poll => |ev| .{ .op = .poll, .token = ev.token, .result = ev.res },
                    .timeout => .{ .op = .timeout, .token = .{ .slot = 0, .gen = 0 }, .result = 0 },
                    .connect => |ev| .{ .op = .connect, .token = ev.token, .result = ev.res },
                    .other => null,
                };
                if (item) |got| {
                    sink.dest[sink.n] = got;
                    sink.n += 1;
                }
            }
        };
        var sink = Sink{ .dest = out };
        const wait_nr: u32 = if (wait_ms == 0) 0 else 1;
        try ring.reapCompletions(cqes[0..@min(cqes.len, @max(out.len, 1))], wait_nr, &sink);
        return @intCast(sink.n);
    }

    /// Send four bytes through the Registered I/O table stored on this port
    /// and dequeue that send. This does not issue a second `WSAIoctl`. Off
    /// Windows, and on a port whose table was not loaded, it returns before
    /// any function pointer is called.
    pub fn dequeueRegistered(self: *IoBackend) RioWitness {
        if (comptime builtin.os.tag != .windows) return .{ .stage = "off-windows" };
        const iocp = self.iocp orelse return .{ .stage = "closed" };
        if (iocp.port == 0 or !rioTableUsable(&iocp.rio)) return .{ .stage = "closed" };
        return dequeueLoadedRio(&iocp.rio);
    }

    /// Look at a capsule and refuse it. This function does not adopt sessions.
    /// Linux adoption stays `LinuxServer.adoptInheritedSessions`.
    pub fn refuseCapsule(self: *const IoBackend, allocator: Allocator, bytes: []const u8) error{Usr2Refused}!void {
        if (capsule.decode(allocator, bytes)) |decoded| {
            var owned = decoded;
            owned.deinit(allocator);
        } else |_| {}
        switch (self.family) {
            .ringlane, .iocp, .kqueue => return error.Usr2Refused,
        }
    }
};

pub fn openLinuxRing(entries: u16, features: ringlane.RingFeatures) !ringlane.Ring {
    var backend = try IoBackend.openOwned(.ringlane, entries, features);
    return backend.detachOwned() orelse {
        backend.deinit();
        return error.Unsupported;
    };
}

pub fn submitAccept(ring: anytype, token: ringlane.FdToken, fd: linux.fd_t) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitAccept(token, fd);
    var backend = IoBackend.borrow(ring);
    return backend.accept(token, fd) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitRecv(ring: anytype, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitRecv(token, fd, buffer);
    var backend = IoBackend.borrow(ring);
    return backend.recv(token, fd, buffer) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitSend(ring: anytype, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitSend(token, fd, buffer);
    var backend = IoBackend.borrow(ring);
    return backend.send(token, fd, buffer) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitPoll(ring: anytype, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitPollAdd(token, fd, poll_mask);
    var backend = IoBackend.borrow(ring);
    return backend.poll(token, fd, poll_mask) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitCancel(ring: anytype, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitExactCancel(kind, token);
    var backend = IoBackend.borrow(ring);
    return backend.cancel(kind, token) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

pub fn submitTimeout(ring: anytype, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
    if (comptime builtin.os.tag != .linux) return ring.submitTimeout(token, ts);
    var backend = IoBackend.borrow(ring);
    return backend.timeout(token, ts) catch |err| switch (err) {
        error.MissingOp => unreachable,
        else => |e| return e,
    };
}

/// Opens the native backend and requires every op. A missing op is
/// `error.Unsupported`. The Linux ring used by `LinuxServer` is `openLinuxRing`.
pub fn refusePortableReactor(tag: std.Target.Os.Tag, entries: u16) error{Unsupported}!void {
    var backend = IoBackend.openOwned(familyFor(tag), entries, .{}) catch return error.Unsupported;
    defer backend.deinit();
    backend.requireAll() catch return error.Unsupported;
}

/// Non-Linux Helix path. Refuses adoption; does not decode a capsule into a session.
pub fn refuseForeignCapsule() error{Unsupported}!void {
    const backend = IoBackend.closed(switch (builtin.os.tag) {
        .windows => .iocp,
        else => .kqueue,
    }, 0);
    switch (backend.family) {
        .iocp, .kqueue => return error.Unsupported,
        .ringlane => return error.Unsupported,
    }
}

fn kqueueOs() bool {
    return switch (builtin.os.tag) {
        .freebsd, .openbsd, .netbsd, .dragonfly => true,
        else => false,
    };
}

/// BSD kqueue. Full-runtime operations own one original completion. Every
/// changelist uses matched EV_RECEIPT acknowledgements; ambiguous failure
/// closes the queue before returning BackendPoisoned and prevents publication.
const Kqueue = struct {
    allocator: Allocator = std.heap.page_allocator,
    fd: i32 = -1,
    cap: u16 = 0,
    n: u16 = 0,
    changes: [submit_batch]Change = @splat(.{}),
    regs: []Reg = &.{},
    stream_completions: bool = false,
    pending: [submit_batch]Reaped = undefined,
    pending_n: usize = 0,

    pub const submit_batch = 256;

    pub const evfilt_read: i16 = -1;
    pub const evfilt_write: i16 = -2;
    pub const evfilt_timer: i16 = -7;
    pub const ev_add: u16 = 0x0001;
    pub const ev_delete: u16 = 0x0002;
    pub const ev_enable: u16 = 0x0004;
    pub const ev_oneshot: u16 = 0x0010;
    pub const ev_receipt: u16 = 0x0040;
    pub const ev_error: u16 = 0x4000;
    pub const ev_eof: u16 = 0x8000;

    pub const Change = struct {
        ident: usize = 0,
        filter: i16 = 0,
        flags: u16 = 0,
        fflags: u32 = 0,
        data: i64 = 0,
        udata: usize = 0,
        canceled: ?Reaped = null,
        connect_addr: ?*const std.posix.sockaddr = null,
        connect_len: std.posix.socklen_t = 0,
    };

    pub const Queued = struct {
        filter: i16,
        flags: u16,
        ident: usize,
        data: i64,
    };

    const Reg = struct {
        token: usize = 0,
        ident: usize = 0,
        filter: i16 = 0,
        live: bool = false,
        kind: ringlane.OpKind = .other,
        buf_ptr: usize = 0,
        len: usize = 0,
    };

    pub fn unopened(entries: u16) Kqueue {
        return .{ .fd = -1, .cap = batchCap(entries) };
    }

    pub fn open(entries: u16) !Kqueue {
        if (entries == 0) return error.MissingOp;
        if (comptime !kqueueOs()) return error.MissingOp;
        return .{ .fd = try openFd(), .cap = batchCap(entries) };
    }

    pub fn deinit(self: *Kqueue) void {
        if (comptime kqueueOs()) self.closeQueue();
        self.fd = -1;
        self.n = 0;
        if (self.regs.len != 0) {
            self.allocator.free(self.regs);
            self.regs = &.{};
        }
    }

    pub fn enqueueAccept(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t) !void {
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable | self.streamFlags(), 0, false, .accept, "");
    }

    pub fn enqueueRecv(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        if (buffer.len == 0) return error.MissingOp;
        return self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable | self.streamFlags(), 0, false, .recv, buffer);
    }

    pub fn enqueueSend(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (buffer.len == 0) return error.MissingOp;
        return self.enqueueFilter(token, fd, evfilt_write, ev_add | ev_enable | self.streamFlags(), 0, false, .send, buffer);
    }

    fn streamFlags(self: *const Kqueue) u16 {
        return if (self.stream_completions) ev_oneshot else 0;
    }

    fn reservedPending(self: *const Kqueue) usize {
        var count = self.pending_n;
        for (self.changes[0..self.n]) |change| {
            if (change.canceled != null or change.connect_addr != null) count += 1;
        }
        return count;
    }

    pub fn enqueueConnect(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, addr: *const std.posix.sockaddr, addrlen: std.posix.socklen_t) !void {
        if (!self.stream_completions or addrlen == 0) return error.MissingOp;
        if (self.reservedPending() >= self.pending.len) return error.SubmissionQueueFull;
        try self.enqueueFilter(token, fd, evfilt_write, ev_add | ev_enable | ev_oneshot, 0, false, .connect, "");
        self.changes[self.n - 1].connect_addr = addr;
        self.changes[self.n - 1].connect_len = addrlen;
    }

    pub fn enqueuePoll(self: *Kqueue, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        const supported = linux.POLL.IN | linux.POLL.OUT;
        if (fd < 0 or poll_mask == 0 or poll_mask & ~@as(u32, supported) != 0) return error.MissingOp;
        const count: u16 = @as(u16, @intFromBool(poll_mask & linux.POLL.IN != 0)) + @as(u16, @intFromBool(poll_mask & linux.POLL.OUT != 0));
        if (count > self.cap - self.n) return error.MissingOp;
        if (self.fd >= 0) {
            for (self.regs) |reg| {
                if (reg.live and (reg.ident == @as(usize, @intCast(fd)) or reg.token == packToken(token)) and
                    ((reg.filter == evfilt_read and poll_mask & linux.POLL.IN != 0) or
                        (reg.filter == evfilt_write and poll_mask & linux.POLL.OUT != 0))) return error.MissingOp;
            }
        }
        // Reserve both registrations before publishing either half of a dual
        // read/write poll. An allocation failure leaves the pending batch intact.
        try self.ensureFreeRegs(count);
        if (poll_mask & linux.POLL.IN != 0) {
            try self.enqueueFilter(token, fd, evfilt_read, ev_add | ev_enable | ev_oneshot, 0, false, .poll, "");
        }
        if (poll_mask & linux.POLL.OUT != 0) {
            try self.enqueueFilter(token, fd, evfilt_write, ev_add | ev_enable | ev_oneshot, 0, false, .poll, "");
        }
    }

    pub fn enqueueCancel(self: *Kqueue, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        const token_key = packToken(token);
        // A completion already copied to the backend FIFO owns the original
        // outcome. Do not manufacture a second original cancellation outcome.
        if (self.stream_completions) {
            for (self.pending[0..self.pending_n]) |done| {
                if (done.op == opForKind(kind) and packToken(done.token) == token_key) return;
            }
            for (self.changes[0..self.n]) |change| {
                if (change.canceled) |done| {
                    if (done.op == opForKind(kind) and packToken(done.token) == token_key) return error.MissingOp;
                }
            }
            if (self.reservedPending() >= self.pending.len) return error.SubmissionQueueFull;
            const filter = switch (kind) {
                .accept, .recv => evfilt_read,
                .send, .connect => evfilt_write,
                else => return error.MissingOp,
            };
            const reg = self.findReg(token_key, filter) orelse return error.MissingOp;
            if (reg.kind != kind) return error.MissingOp;
            try self.enqueueDelete(token_key, filter);
            self.changes[self.n - 1].canceled = .{
                .op = opForKind(kind),
                .token = token,
                .result = -@as(i32, @intFromEnum(std.posix.E.CANCELED)),
            };
            return;
        }
        switch (kind) {
            .other => return error.MissingOp,
            .poll => {
                if (self.fd < 0) return error.MissingOp;
                var count: u16 = 0;
                for (self.regs) |reg| {
                    if (reg.live and reg.token == token_key and reg.kind == .poll) count += 1;
                }
                if (count == 0 or count > self.cap - self.n) return error.MissingOp;
                for (self.regs) |reg| {
                    if (reg.live and reg.token == token_key and reg.kind == .poll) try self.enqueueDelete(token_key, reg.filter);
                }
            },
            .timeout => try self.enqueueDelete(token_key, evfilt_timer),
            .accept, .recv => try self.enqueueDelete(token_key, evfilt_read),
            .send, .connect => try self.enqueueDelete(token_key, evfilt_write),
        }
    }

    pub fn enqueueTimeout(self: *Kqueue, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        const ms = try timeoutMillis(ts);
        return self.enqueueFilter(token, 0, evfilt_timer, ev_add | ev_oneshot, ms, true, .timeout, "");
    }

    pub fn submit(self: *Kqueue) !u32 {
        if (self.fd < 0) return error.MissingOp;
        if (self.n == 0) return 0;
        const count = self.n;
        const submitted = if (comptime kqueueOs()) try self.submitReceipts() else return error.MissingOp;
        // Retire canceled ownership before starting any queued connects.
        for (self.changes[0..count]) |change| {
            if (change.flags & ev_delete != 0) self.forget(change.udata, change.filter);
        }
        // A successful delete is the kernel ownership boundary. Only now may
        // the full daemon observe the original canceled completion and reclaim.
        for (self.changes[0..count]) |change| {
            if (change.canceled) |done| self.appendPending(done);
            if (change.connect_addr) |addr| {
                if (comptime kqueueOs()) try self.startConnect(change, addr);
            }
        }
        return submitted;
    }

    pub fn reap(self: *Kqueue, out: []Reaped, wait_ms: u32) !u32 {
        if (self.fd < 0) return error.MissingOp;
        if (comptime !kqueueOs()) return error.MissingOp;
        if (self.pending_n != 0) {
            const n = @min(out.len, self.pending_n);
            @memcpy(out[0..n], self.pending[0..n]);
            std.mem.copyForwards(Reaped, self.pending[0 .. self.pending_n - n], self.pending[n..self.pending_n]);
            self.pending_n -= n;
            return @intCast(n);
        }
        return self.reapNative(out, wait_ms);
    }

    fn enqueueFilter(
        self: *Kqueue,
        token: ringlane.FdToken,
        fd: linux.fd_t,
        filter: i16,
        flags: u16,
        data: i64,
        timer: bool,
        kind: ringlane.OpKind,
        buf: []const u8,
    ) !void {
        // Check before remember() changes a live buffer pointer or allocates a
        // registration. A full batch must not alter the operation already armed.
        if (self.n >= self.cap) return if (self.stream_completions) error.SubmissionQueueFull else error.MissingOp;
        const token_key = packToken(token);
        const ident: usize = if (timer) token_key else blk: {
            if (fd < 0) return error.MissingOp;
            break :blk @as(usize, @intCast(fd));
        };
        const change = Change{
            .ident = ident,
            .filter = filter,
            .flags = flags,
            .data = data,
            .udata = token_key,
        };
        if (self.fd >= 0) {
            for (self.regs) |reg| {
                // kqueue keys registrations by (descriptor, filter), not by
                // user token. Never redirect another operation's readiness or
                // cancellation to this token/buffer.
                if (reg.live and reg.ident == ident and reg.filter == filter and
                    (self.stream_completions or reg.token != token_key or reg.kind != kind)) return error.MissingOp;
                if (reg.live and reg.token == token_key and reg.filter == filter and reg.ident != ident) return error.MissingOp;
            }
        }
        try self.remember(change, kind, if (buf.len == 0) 0 else @intFromPtr(buf.ptr), buf.len);
        return self.pushStored(change);
    }

    fn enqueueDelete(self: *Kqueue, token_key: usize, filter: i16) !void {
        const ident = self.lookup(token_key, filter) orelse return error.MissingOp;
        const before = self.n;
        self.pushStored(.{
            .ident = ident,
            .filter = filter,
            .flags = ev_delete,
            .udata = token_key,
        }) catch |err| {
            if (self.n != before) self.forget(token_key, filter);
            return err;
        };
        if (!self.stream_completions) self.forget(token_key, filter);
    }

    fn pushStored(self: *Kqueue, change: Change) !void {
        if (self.n >= self.cap) return if (self.stream_completions) error.SubmissionQueueFull else error.MissingOp;
        self.changes[self.n] = change;
        self.n += 1;
        if (self.fd < 0) return error.MissingOp;
    }

    fn remember(self: *Kqueue, change: Change, kind: ringlane.OpKind, buf_ptr: usize, len: usize) !void {
        var i: usize = 0;
        while (i < self.regs.len) : (i += 1) {
            if (self.regs[i].live and self.regs[i].token == change.udata and self.regs[i].filter == change.filter) {
                self.regs[i].ident = change.ident;
                self.regs[i].kind = kind;
                self.regs[i].buf_ptr = buf_ptr;
                self.regs[i].len = len;
                return;
            }
        }
        i = 0;
        while (i < self.regs.len) : (i += 1) {
            if (!self.regs[i].live) {
                self.regs[i] = .{
                    .token = change.udata,
                    .ident = change.ident,
                    .filter = change.filter,
                    .live = true,
                    .kind = kind,
                    .buf_ptr = buf_ptr,
                    .len = len,
                };
                return;
            }
        }
        try self.ensureFreeRegs(1);
        return self.remember(change, kind, buf_ptr, len);
    }

    fn ensureFreeRegs(self: *Kqueue, needed: usize) !void {
        var free: usize = 0;
        for (self.regs) |reg| {
            if (!reg.live) free += 1;
        }
        if (free >= needed) return;
        const old = self.regs;
        const missing = needed - free;
        const min_len = std.math.add(usize, old.len, missing) catch return error.OutOfMemory;
        const doubled = if (old.len == 0) @as(usize, 16) else std.math.mul(usize, old.len, 2) catch return error.OutOfMemory;
        const grown = self.allocator.alloc(Reg, @max(min_len, doubled)) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            self.allocator.free(old);
        }
        var z: usize = old.len;
        while (z < grown.len) : (z += 1) grown[z] = .{};
        self.regs = grown;
    }

    fn lookup(self: *const Kqueue, token: usize, filter: i16) ?usize {
        var i: usize = self.regs.len;
        while (i > 0) {
            i -= 1;
            if (self.regs[i].live and self.regs[i].token == token and self.regs[i].filter == filter) return self.regs[i].ident;
        }
        return null;
    }

    fn forget(self: *Kqueue, token: usize, filter: i16) void {
        for (self.regs) |*reg| {
            if (reg.live and reg.token == token and reg.filter == filter) reg.live = false;
        }
    }

    fn batchCap(entries: u16) u16 {
        return @min(entries, @as(u16, submit_batch));
    }

    fn packToken(token: ringlane.FdToken) usize {
        return (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    }

    fn timeoutMillis(ts: *const linux.kernel_timespec) !i64 {
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return error.MissingOp;
        const sec_ms = std.math.mul(i64, ts.sec, 1000) catch return error.MissingOp;
        return std.math.add(i64, sec_ms, @divTrunc(ts.nsec, 1_000_000)) catch return error.MissingOp;
    }

    fn openFd() !i32 {
        const raw = std.c.kqueue();
        if (raw < 0) return error.MissingOp;
        // F_SETFD = 2, FD_CLOEXEC = 1. std.c.F is `void` on FreeBSD.
        const cloexec = std.c.fcntl(raw, @as(i32, 2), @as(i32, 1));
        if (cloexec < 0) {
            _ = std.c.close(raw);
            return error.MissingOp;
        }
        // Reachable only if kqueue() returned the minimum i32. The branch
        // keeps the kevent body in the FreeBSD daemon's analysis.
        if (raw == std.math.minInt(i32)) freebsdTypecheck(raw);
        return raw;
    }

    fn closeQueue(self: *Kqueue) void {
        if (self.fd >= 0) _ = std.c.close(self.fd);
    }

    fn poison(self: *Kqueue) error{BackendPoisoned} {
        self.closeQueue();
        self.fd = -1;
        return error.BackendPoisoned;
    }

    fn submitReceipts(self: *Kqueue) !u32 {
        const count: usize = self.n;
        var batch: [submit_batch]std.c.Kevent = undefined;
        for (self.changes[0..count], 0..) |change, i| {
            batch[i] = fillKevent(change);
            batch[i].flags |= ev_receipt;
        }
        var receipts: [submit_batch]std.c.Kevent = undefined;
        const timeout = std.c.timespec{ .sec = 0, .nsec = 0 };
        const rc = std.c.kevent(self.fd, &batch, @intCast(count), &receipts, @intCast(count), &timeout);
        // Earlier changes may already have applied even when a later one fails.
        // Queue closure resolves all kernel buffer/watch ownership atomically.
        if (rc != @as(c_int, @intCast(count))) return self.poison();
        for (receipts[0..count], batch[0..count]) |receipt, change| {
            if (receipt.flags & ev_error == 0 or receipt.data != 0 or
                receipt.ident != change.ident or receipt.filter != change.filter or
                receipt.udata != change.udata) return self.poison();
        }
        self.n = 0;
        return @intCast(count);
    }

    fn fillKevent(change: Change) std.c.Kevent {
        var ev = std.mem.zeroes(std.c.Kevent);
        ev.ident = change.ident;
        ev.filter = @intCast(change.filter);
        ev.flags = @intCast(change.flags);
        ev.fflags = @intCast(change.fflags);
        ev.data = @intCast(change.data);
        ev.udata = change.udata;
        return ev;
    }

    fn appendPending(self: *Kqueue, done: Reaped) void {
        std.debug.assert(self.pending_n < self.pending.len);
        self.pending[self.pending_n] = done;
        self.pending_n += 1;
    }

    fn startConnect(self: *Kqueue, change: Change, addr: *const std.posix.sockaddr) !void {
        const reg = self.findReg(change.udata, evfilt_write) orelse return;
        if (reg.kind != .connect or reg.ident != change.ident) return;
        const fd: i32 = @intCast(change.ident);
        var result: ?i32 = null;
        if (!setNonBlock(fd) or !setCloseOnExec(fd)) {
            result = -positiveErrno();
        } else if (nativeConnect(fd, addr, change.connect_len) == 0) {
            result = 0;
        } else {
            const err = positiveErrno();
            if (err != @as(i32, @intFromEnum(std.posix.E.INPROGRESS)) and
                err != @as(i32, @intFromEnum(std.posix.E.ALREADY))) result = -err;
        }
        if (result) |done| {
            try self.deleteFilterChecked(change.ident, evfilt_write);
            reg.live = false;
            self.appendPending(.{ .op = .connect, .token = unpackToken(change.udata), .result = done });
        }
    }

    fn nativeConnect(fd: i32, addr: *const std.posix.sockaddr, len: std.posix.socklen_t) c_int {
        // Full Server stores canonical mapped IPv4 endpoints in sockaddr.in6,
        // but opens AF_INET sockets for them on BSD. Translate only that exact
        // representation; real IPv6 keeps its native scope and flow fields.
        if (len == @sizeOf(std.posix.sockaddr.in6) and addr.family == std.c.AF.INET6) {
            const v6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            const mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            if (std.mem.eql(u8, v6.addr[0..12], &mapped)) {
                var v4 = std.mem.zeroes(std.c.sockaddr.in);
                v4.len = @sizeOf(std.c.sockaddr.in);
                v4.family = std.c.AF.INET;
                v4.port = v6.port;
                @memcpy(std.mem.asBytes(&v4.addr), v6.addr[12..16]);
                return std.c.connect(fd, @ptrCast(&v4), @sizeOf(@TypeOf(v4)));
            }
        }
        return std.c.connect(fd, @ptrCast(addr), len);
    }

    fn connectReady(ident: usize) i32 {
        var result: c_int = 0;
        var len: std.c.socklen_t = @sizeOf(c_int);
        if (std.c.getsockopt(@intCast(ident), std.c.SOL.SOCKET, std.c.SO.ERROR, &result, &len) < 0)
            return -positiveErrno();
        if (len != @sizeOf(c_int)) return -@as(i32, @intFromEnum(std.posix.E.IO));
        return -result;
    }

    fn reapNative(self: *Kqueue, out: []Reaped, wait_ms: u32) !u32 {
        var evs: [32]std.c.Kevent = undefined;
        const max: usize = @min(out.len, evs.len);
        if (max == 0) return 0;
        var none: [1]std.c.Kevent = .{std.mem.zeroes(std.c.Kevent)};
        const ts = std.c.timespec{
            .sec = @intCast(wait_ms / 1000),
            .nsec = @intCast(@as(u64, wait_ms % 1000) * 1_000_000),
        };
        const rc = std.c.kevent(self.fd, &none, 0, &evs, @intCast(max), &ts);
        if (rc < 0) {
            // Signals wake the reactor without retiring any armed operation.
            // Return to its loop so stop/Helix state is observed promptly.
            if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) return 0;
            return error.MissingOp;
        }
        const got: usize = @intCast(rc);
        var n: usize = 0;
        var i: usize = 0;
        while (i < got and n < out.len) : (i += 1) {
            const ev = evs[i];
            const filter: i16 = @intCast(ev.filter);
            const flags: u16 = @truncate(ev.flags);
            const data: i64 = @intCast(ev.data);
            const token = unpackToken(ev.udata);
            const reg = self.findReg(ev.udata, filter) orelse continue;
            // Kernel event batches can contain readiness for an operation that
            // was cancelled or whose descriptor has since been reused.
            if (reg.ident != ev.ident) continue;
            if ((flags & ev_error) != 0) {
                const errno: i32 = if (data > 0 and data <= std.math.maxInt(i32)) @intCast(data) else 1;
                out[n] = .{ .op = opForKind(reg.kind), .token = token, .result = -errno };
                if (self.stream_completions) {
                    if (reg.kind == .poll) try self.finishPoll(ev.udata, filter, true) else reg.live = false;
                } else if (reg.kind == .send or reg.kind == .connect) {
                    self.deleteFilter(ev.ident, filter);
                    reg.live = false;
                } else if (reg.kind == .poll) {
                    try self.finishPoll(ev.udata, filter, true);
                } else if (reg.kind == .timeout) {
                    reg.live = false;
                }
                n += 1;
                continue;
            }
            if (reg.kind == .poll) {
                var ready: u32 = if (filter == evfilt_write) linux.POLL.OUT else linux.POLL.IN;
                if (flags & ev_eof != 0) ready |= linux.POLL.HUP;
                out[n] = .{ .op = .poll, .token = token, .result = @intCast(ready) };
                // Poll is a single completion, like the ring backend. The
                // current filter is EV_ONESHOT; remove the other half before
                // permitting another operation to reuse its identity.
                try self.finishPoll(ev.udata, filter, true);
                n += 1;
                continue;
            }
            if (filter == evfilt_timer) {
                reg.live = false;
                out[n] = .{ .op = .timeout, .token = token, .result = 0 };
                n += 1;
                continue;
            }
            if (filter == evfilt_read) {
                if (reg.kind == .accept) {
                    out[n] = .{ .op = .accept, .token = token, .result = self.acceptReady(ev.ident) };
                    if (self.stream_completions) reg.live = false;
                    n += 1;
                    continue;
                }
                out[n] = .{ .op = .recv, .token = token, .result = transfer(.recv, ev.ident, reg) };
                if (self.stream_completions) reg.live = false;
                n += 1;
                continue;
            }
            if (filter == evfilt_write) {
                out[n] = .{
                    .op = opForKind(reg.kind),
                    .token = token,
                    .result = if (reg.kind == .connect) connectReady(ev.ident) else transfer(.send, ev.ident, reg),
                };
                if (!self.stream_completions) self.deleteFilter(ev.ident, filter);
                reg.live = false;
                n += 1;
            }
        }
        return @intCast(n);
    }

    fn acceptReady(self: *Kqueue, ident: usize) i32 {
        _ = self;
        const listened: i32 = @intCast(ident);
        const fd = std.c.accept(listened, null, null);
        if (fd < 0) return -positiveErrno();
        // accept() does not inherit the listener's close-on-exec flag. Publish
        // the new descriptor only after both ownership flags are installed.
        if (!setCloseOnExec(fd) or !setNonBlock(fd)) {
            const err = positiveErrno();
            _ = std.c.close(fd);
            return -err;
        }
        return fd;
    }

    fn deleteFilter(self: *Kqueue, ident: usize, filter: i16) void {
        self.deleteFilterChecked(ident, filter) catch {};
    }

    fn deleteFilterChecked(self: *Kqueue, ident: usize, filter: i16) !void {
        var batch: [1]std.c.Kevent = .{fillKevent(.{
            .ident = ident,
            .filter = filter,
            .flags = ev_delete,
        })};
        var out: [1]std.c.Kevent = undefined;
        const timeout = std.c.timespec{ .sec = 0, .nsec = 0 };
        if (std.c.kevent(self.fd, &batch, 1, &out, 0, &timeout) != 0) {
            if (positiveErrno() == @as(i32, @intFromEnum(std.posix.E.NOENT))) return;
            return self.poison();
        }
    }

    fn findReg(self: *Kqueue, token: usize, filter: i16) ?*Reg {
        var i: usize = self.regs.len;
        while (i > 0) {
            i -= 1;
            if (self.regs[i].live and self.regs[i].token == token and self.regs[i].filter == filter) return &self.regs[i];
        }
        return null;
    }

    fn finishPoll(self: *Kqueue, token: usize, filter: i16, oneshot_removed: bool) !void {
        for (self.regs) |*reg| {
            if (reg.live and reg.token == token and reg.kind == .poll) {
                if (reg.filter != filter or !oneshot_removed) {
                    // The sibling may also be in this copied EV_ONESHOT batch.
                    // ENOENT proves it is already retired; any other failure
                    // closes the queue before a stale watch can be reused.
                    self.deleteFilterChecked(reg.ident, reg.filter) catch |err| return err;
                }
                reg.live = false;
            }
        }
    }

    fn unpackToken(key: usize) ringlane.FdToken {
        return .{ .slot = @truncate(key), .gen = @truncate(key >> 32) };
    }

    fn opForKind(kind: ringlane.OpKind) Op {
        return switch (kind) {
            .accept => .accept,
            .recv, .other => .recv,
            .send => .send,
            .connect => .connect,
            .poll => .poll,
            .timeout => .timeout,
        };
    }

    fn positiveErrno() i32 {
        const err = std.c._errno().*;
        if (err <= 0) return 1;
        return err;
    }

    fn setNonBlock(fd: i32) bool {
        // F_GETFL = 3, F_SETFL = 4, O_NONBLOCK = 4 on these BSDs.
        const flags = std.c.fcntl(fd, @as(i32, 3), @as(i32, 0));
        if (flags < 0) return false;
        return std.c.fcntl(fd, @as(i32, 4), flags | @as(@TypeOf(flags), 4)) >= 0;
    }

    fn setCloseOnExec(fd: i32) bool {
        const flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (flags < 0) return false;
        return std.c.fcntl(fd, std.c.F.SETFD, flags | @as(@TypeOf(flags), std.c.FD_CLOEXEC)) >= 0;
    }

    fn transfer(kind: ringlane.OpKind, ident: usize, reg: ?*Reg) i32 {
        const slot = reg orelse return -1;
        if (slot.buf_ptr == 0 or slot.len == 0) return -1;
        const fd: i32 = @intCast(ident);
        var done: usize = 0;
        while (done < slot.len) {
            const ptr: [*]u8 = @ptrFromInt(slot.buf_ptr + done);
            const n: isize = if (kind == .recv)
                std.c.recv(fd, ptr, slot.len - done, 0)
            else
                // A client closing its read side must yield EPIPE, not kill
                // the process before the completion reaches the daemon.
                std.c.send(fd, ptr, slot.len - done, std.c.MSG.NOSIGNAL);
            if (n < 0) {
                const err = std.c._errno().*;
                if (err == 4) continue;
                if (err == 35) {
                    if (done == 0) return -35;
                    break;
                }
                if (done == 0) return if (err == 0) -1 else -err;
                break;
            }
            if (n == 0) break;
            done += @intCast(n);
            if (kind == .recv) break;
        }
        if (done > std.math.maxInt(i32)) return std.math.maxInt(i32);
        return @intCast(done);
    }

    fn bsdStreamSocket() !i32 {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
        if (fd < 0) return error.MissingOp;
        return fd;
    }

    fn proveQueued(backend: *IoBackend, sock: linux.fd_t) !u32 {
        const token = ringlane.FdToken{ .slot = 1, .gen = 1 };
        var buf: [4]u8 = .{ 0, 0, 0, 0 };
        // Queue registration/cancellation pairs. A native kqueue has only one
        // registration per (fd, filter), so these different operation kinds
        // cannot all remain armed on the same socket at once.
        try backend.accept(token, sock);
        try backend.cancel(.accept, token);
        try backend.recv(token, sock, &buf);
        try backend.cancel(.recv, token);
        try backend.send(token, sock, "x");
        try backend.cancel(.send, token);
        try backend.poll(token, sock, linux.POLL.IN);
        try backend.cancel(.poll, token);
        var ts = linux.kernel_timespec{ .sec = 1, .nsec = 0 };
        try backend.timeout(token, &ts);
        try backend.cancel(.timeout, token);
        const submitted = try backend.submit();
        if (submitted == 0) return error.MissingOp;
        backend.poll(token, sock, 0) catch |err| switch (err) {
            error.MissingOp => {},
            else => |e| return e,
        };
        return submitted;
    }

    fn exerciseLive() !void {
        var backend = try IoBackend.openOwned(.kqueue, 32, .{});
        defer backend.deinit();
        try backend.requireAll();
        const sock = try bsdStreamSocket();
        defer {
            if (comptime kqueueOs()) _ = std.c.close(sock);
        }
        const submitted = try proveQueued(&backend, sock);
        if (submitted == 0) return error.MissingOp;
    }

    fn freebsdTypecheck(fd: i32) void {
        var queue = Kqueue.unopened(32);
        queue.fd = fd;
        var backend = IoBackend{
            .family = .kqueue,
            .entries = 32,
            .kq = &queue,
        };
        _ = proveQueued(&backend, fd) catch {};
        backend.kq = null;
        if (bsdStreamSocket()) |sock| {
            _ = std.c.close(sock);
        } else |_| {}
        exerciseLive() catch {};
        if (listenTcp("127.0.0.1", 0)) |listener| {
            closeSocket(listener.fd);
        } else |_| {}
    }
};

/// Windows completion port. One submit posts at most `submit_batch` kernel
/// requests; that bound is the batch, not a connection ceiling. A closed
/// port, a full batch, an unknown cancel, or a status other than success,
/// pending, or a closed connection returns `error.MissingOp`. A closed
/// connection is that operation's result and does not stop the listener.
///
/// Accept is AFD wait-for-listen (`0x1200C`) completed by `IOCTL_AFD_ACCEPT`
/// (`0x12010`) onto a new socket. Poll is AFD select (`0x12024`). The packing
/// is `(FILE_DEVICE_NETWORK << 12) | (operation << 2) | method`. Recv and
/// send are `IOCTL_AFD_RECEIVE` / `IOCTL_AFD_SEND` (`0x12017` / `0x1201F`).
/// A raw `NtReadFile` on an AFD socket returns `STATUS_INVALID_PARAMETER`.
/// Timeout uses a monotonic deadline and is returned by `reap` with its
/// original token. A timer does not need an NT handle or completion packet.
/// `STATUS_SUCCESS` is a finished AFD operation and `reap` returns it before
/// waiting. `STATUS_PENDING` is reported only from `NtRemoveIoCompletion`.
/// A duplicate port packet for that slot is discarded. Winsock `accept`
/// after wait-for-listen returns `WSAEWOULDBLOCK` or a socket whose first
/// receive is `STATUS_CONNECTION_RESET`, so the sequence from the wait is
/// what adopts the connection.
///
/// Open also loads `RIO_EXTENSION_FUNCTION_TABLE` through `WSAIoctl`. A failed
/// or partial table closes the new port and returns `error.MissingOp`.
/// `dequeueRegistered` calls that stored table; nothing else does.
///
/// `ntdll` and `ws2_32` calls sit in functions that are not analyzed unless
/// `builtin.os.tag == .windows`. This Linux host does not execute them.
///
/// `AFD_POLL_INFO` for one handle. `exclusive` is the `BOOLEAN Unique` byte
/// plus the three padding bytes AFD.sys expects before the handle (mio layout).
const AfdPollHandle = extern struct {
    handle: usize,
    events: u32,
    status: i32,
};

const AfdPollInfo = extern struct {
    timeout: i64,
    handle_count: u32,
    exclusive: u32,
    handles: AfdPollHandle,
};

const afd_poll_receive: u32 = 0x0001;
const afd_poll_send: u32 = 0x0004;
const afd_poll_disconnect: u32 = 0x0008;
const afd_poll_abort: u32 = 0x0010;
const afd_poll_local_close: u32 = 0x0020;
const afd_poll_accept: u32 = 0x0080;
const afd_poll_connect_fail: u32 = 0x0100;

/// `WSABUF` and `AFD_RECV_INFO` / `AFD_SEND_INFO`. The pointer inside the
/// info struct must stay valid until the request completes.
const AfdWsaBuf = extern struct {
    len: u32,
    buf: [*]u8,
};

const AfdDataInfo = extern struct {
    buffers: *AfdWsaBuf,
    count: u32,
    afd_flags: u32,
    tdi_flags: u32,
};

/// `AFD_ACCEPT_INFO`. `SanActive` is a `BOOLEAN` followed by padding so
/// `Sequence` is at offset 4 and `AcceptHandle` is at offset 8. A zero flag
/// has the same first four bytes as a `ULONG` flag.
const AfdAcceptInfo = extern struct {
    san_active: u8,
    sequence: i32,
    accept_handle: usize,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(AfdPollInfo) != 32) @compileError("AFD_POLL_INFO is 32 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdWsaBuf) != 16) @compileError("WSABUF is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdDataInfo) != 24) @compileError("AFD_RECV_INFO is 24 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(AfdAcceptInfo) != 16) @compileError("AFD_ACCEPT_INFO is 16 bytes");
    if (@offsetOf(AfdAcceptInfo, "sequence") != 4) @compileError("AFD_ACCEPT_INFO sequence");
    if (@offsetOf(AfdAcceptInfo, "accept_handle") != 8) @compileError("AFD_ACCEPT_INFO handle");
}

const Iocp = struct {
    port: usize = 0,
    cap: u16 = 0,
    n: u16 = 0,
    /// Empty unless `open` stored a table `rioTableUsable` accepted.
    rio: RioTable = .{},
    packets: [submit_batch]Packet = @splat(.{}),
    regs: []Reg = &.{},
    timers: []Timer = &.{},
    next_serial: u64 = 1,
    /// Every slab is separately allocated and never moves while the port is
    /// live. The kernel may write any slot's IOSB, OVERLAPPED, AFD input or
    /// output after submit returns. The pointer vectors themselves may grow.
    slabs: std.ArrayList(*Slab) = .empty,
    free_slots: std.ArrayList(*Slot) = .empty,
    live_slots: usize = 0,
    /// Inline completions are reserved before posting a batch, so a finished
    /// kernel request never needs an allocation to publish its result.
    ready: std.ArrayList(Reaped) = .empty,
    ready_head: usize = 0,
    /// A failed kernel post can follow successful posts from the same batch.
    /// Only reaping and quiesce are safe after that partial submission.
    submit_failed: bool = false,

    pub const submit_batch = 256;
    const slab_size = 256;

    pub const op_accept: u8 = 1;
    pub const op_recv: u8 = 2;
    pub const op_send: u8 = 3;
    pub const op_timeout: u8 = 4;
    pub const op_poll: u8 = 6;
    pub const op_cancel: u8 = 7;
    pub const op_connect: u8 = 8;

    /// FILE_DEVICE_NETWORK is 0x12. AFD wait-for-listen is operation 3,
    /// METHOD_BUFFERED. AFD receive is operation 5 and AFD send is operation
    /// 7, both METHOD_NEITHER. AFD select (poll) is operation 9, METHOD_BUFFERED.
    pub const ioctl_afd_wait_for_listen: u32 = (0x12 << 12) | (3 << 2) | 0;
    pub const ioctl_afd_accept: u32 = (0x12 << 12) | (4 << 2) | 0;
    pub const ioctl_afd_receive: u32 = (0x12 << 12) | (5 << 2) | 3;
    pub const ioctl_afd_send: u32 = (0x12 << 12) | (7 << 2) | 3;
    pub const ioctl_afd_poll: u32 = (0x12 << 12) | (9 << 2) | 0;

    pub const Packet = struct {
        op: u8 = 0,
        handle: usize = 0,
        socket_fd: linux.fd_t = -1,
        length: u32 = 0,
        token: usize = 0,
        ioctl: u32 = 0,
        buf: usize = 0,
        serial: u64 = 0,
        connect_addr: [28]u8 = @splat(0),
        connect_len: u8 = 0,
    };

    const Slot = struct {
        live: bool = false,
        packet: Packet = .{},
        iosb: std.os.windows.IO_STATUS_BLOCK = undefined,
        cancel_iosb: std.os.windows.IO_STATUS_BLOCK = undefined,
        connect_overlapped: WsaOverlapped = undefined,
        connect_addr: [28]u8 = undefined,
        connect_sent: u32 = undefined,
        poll_info: AfdPollInfo = undefined,
        poll_out: AfdPollInfo = undefined,
        wsa_buf: AfdWsaBuf = undefined,
        data_info: AfdDataInfo = undefined,
        /// `AFD_LISTEN_RESPONSE_INFO_TL` is a sequence plus a `SOCKADDR`.
        accept_out: [128]u8 = undefined,
    };

    const Slab = struct {
        slots: [slab_size]Slot = @splat(.{}),
    };

    const Reg = struct {
        token: usize = 0,
        handle: usize = 0,
        op: u8 = 0,
        serial: u64 = 0,
        live: bool = false,
    };

    const Timer = struct {
        token: usize = 0,
        serial: u64 = 0,
        deadline_ms: u64 = 0,
        live: bool = false,
    };

    pub fn unopened(entries: u16) Iocp {
        return .{ .port = 0, .cap = batchCap(entries) };
    }

    pub fn open(entries: u16) !Iocp {
        if (entries == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        const port = try openHandle();
        var opened = Iocp{
            .port = port,
            .cap = batchCap(entries),
        };
        // The Registered I/O table is part of opening the Windows backend.
        // A missing table is not an open port with ordinary sockets underneath.
        opened.rio = loadRioForDaemon() catch |err| {
            opened.deinit();
            return err;
        };
        if (!rioTableUsable(&opened.rio)) {
            opened.deinit();
            return error.MissingOp;
        }
        return opened;
    }

    pub fn deinit(self: *Iocp) void {
        if (comptime builtin.os.tag == .windows) {
            // A caller may forget the explicit quiesce. Never free an IOSB
            // while the kernel can still write to it.
            self.quiesceWindows() catch @panic("IOCP requests could not be drained");
            self.closeWindows();
        }
        self.port = 0;
        self.n = 0;
        self.rio = .{};
        if (self.regs.len != 0) {
            std.heap.page_allocator.free(self.regs);
            self.regs = &.{};
        }
        if (self.timers.len != 0) {
            std.heap.page_allocator.free(self.timers);
            self.timers = &.{};
        }
        for (self.slabs.items) |slab| std.heap.page_allocator.destroy(slab);
        self.slabs.deinit(std.heap.page_allocator);
        self.slabs = .empty;
        self.free_slots.deinit(std.heap.page_allocator);
        self.free_slots = .empty;
        self.ready.deinit(std.heap.page_allocator);
        self.ready = .empty;
        self.ready_head = 0;
        self.live_slots = 0;
    }

    pub fn enqueueAccept(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t) !void {
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        const handle = try handleOf(fd);
        const serial = try self.remember(packToken(token), handle, op_accept);
        return self.pushStored(.{
            .op = op_accept,
            .handle = handle,
            .socket_fd = fd,
            .token = packToken(token),
            .serial = serial,
            .ioctl = ioctl_afd_wait_for_listen,
        });
    }

    pub fn enqueueRecv(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, buffer: []u8) !void {
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        if (buffer.len == 0 or buffer.len > std.math.maxInt(u32)) return error.MissingOp;
        const handle = try handleOf(fd);
        const serial = try self.remember(packToken(token), handle, op_recv);
        return self.pushStored(.{
            .op = op_recv,
            .handle = handle,
            .socket_fd = fd,
            .length = @intCast(buffer.len),
            .token = packToken(token),
            .serial = serial,
            .buf = @intFromPtr(buffer.ptr),
            .ioctl = ioctl_afd_receive,
        });
    }

    pub fn enqueueSend(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, buffer: []const u8) !void {
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        if (buffer.len == 0 or buffer.len > std.math.maxInt(u32)) return error.MissingOp;
        const handle = try handleOf(fd);
        const serial = try self.remember(packToken(token), handle, op_send);
        return self.pushStored(.{
            .op = op_send,
            .handle = handle,
            .socket_fd = fd,
            .length = @intCast(buffer.len),
            .token = packToken(token),
            .serial = serial,
            .buf = @intFromPtr(buffer.ptr),
            .ioctl = ioctl_afd_send,
        });
    }

    pub fn enqueuePoll(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, poll_mask: u32) !void {
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        const supported = linux.POLL.IN | linux.POLL.OUT;
        if (poll_mask == 0 or poll_mask & ~@as(u32, supported) != 0) return error.MissingOp;
        const handle = try handleOf(fd);
        const serial = try self.remember(packToken(token), handle, op_poll);
        return self.pushStored(.{
            .op = op_poll,
            .handle = handle,
            .socket_fd = fd,
            .length = poll_mask,
            .token = packToken(token),
            .serial = serial,
            .ioctl = ioctl_afd_poll,
        });
    }

    pub fn enqueueConnect(self: *Iocp, token: ringlane.FdToken, fd: linux.fd_t, addr: *const std.posix.sockaddr, addrlen: std.posix.socklen_t) !void {
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        const len: usize = @intCast(addrlen);
        if (len != @sizeOf(RioSockAddr) and len != @sizeOf(RioSockAddr6)) return error.MissingOp;
        const bytes = @as([*]const u8, @ptrCast(addr))[0..len];
        const family = std.mem.readInt(u16, bytes[0..2], .native);
        if ((family == wsa_af_inet and len != @sizeOf(RioSockAddr)) or
            (family == wsa_af_inet6 and len != @sizeOf(RioSockAddr6)) or
            (family != wsa_af_inet and family != wsa_af_inet6)) return error.MissingOp;
        const handle = try handleOf(fd);
        const serial = try self.remember(packToken(token), handle, op_connect);
        var packet = Packet{
            .op = op_connect,
            .handle = handle,
            .socket_fd = fd,
            .token = packToken(token),
            .serial = serial,
            .connect_len = @intCast(len),
        };
        @memcpy(packet.connect_addr[0..len], bytes);
        return self.pushStored(packet);
    }

    pub fn enqueueCancel(self: *Iocp, kind: ringlane.OpKind, token: ringlane.FdToken) !void {
        if (self.submit_failed) return error.MissingOp;
        const op: u8 = switch (kind) {
            .accept => op_accept,
            .recv => op_recv,
            .send => op_send,
            .timeout => op_timeout,
            .poll => op_poll,
            .connect => op_connect,
            .other => return error.MissingOp,
        };
        const token_key = packToken(token);
        const reg = self.lookup(token_key, op) orelse {
            // An inline completion has already retired its registration but
            // may still be in the ready queue. There is nothing left to
            // cancel; keep its original result for the next reap.
            if (self.readyHas(token_key, op)) return;
            return error.MissingOp;
        };
        const before = self.n;
        self.pushStored(.{
            .op = op_cancel,
            .handle = reg.handle,
            .length = op,
            .token = token_key,
            .serial = reg.serial,
        }) catch |err| {
            if (self.n != before) self.forgetSerial(reg.serial);
            return err;
        };
        self.forgetSerial(reg.serial);
    }

    pub fn enqueueTimeout(self: *Iocp, token: ringlane.FdToken, ts: *const linux.kernel_timespec) !void {
        const ms = timeoutMillis(ts) orelse return error.MissingOp;
        if (ms > std.math.maxInt(u32)) return error.MissingOp;
        if (self.n >= self.cap or self.lookup(packToken(token), op_timeout) != null) return error.MissingOp;
        const serial = try self.remember(packToken(token), 0, op_timeout);
        return self.pushStored(.{
            .op = op_timeout,
            .length = @intCast(ms),
            .token = packToken(token),
            .serial = serial,
        });
    }

    pub fn submit(self: *Iocp) !u32 {
        if (self.submit_failed) return error.MissingOp;
        if (self.port == 0) return error.MissingOp;
        if (self.n == 0) return 0;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        return self.submitWindows();
    }

    pub fn reap(self: *Iocp, out: []Reaped, wait_ms: u32) !u32 {
        if (self.port == 0) return error.MissingOp;
        if (comptime builtin.os.tag != .windows) return error.MissingOp;
        return self.reapWindows(out, wait_ms);
    }

    fn pushStored(self: *Iocp, packet: Packet) !void {
        if (self.submit_failed) return error.MissingOp;
        if (self.n >= self.cap) return error.SubmissionQueueFull;
        self.packets[self.n] = packet;
        self.n += 1;
        if (self.port == 0) return error.MissingOp;
    }

    fn remember(self: *Iocp, token_key: usize, handle: usize, op: u8) !u64 {
        if (self.submit_failed) return error.MissingOp;
        if (self.next_serial == std.math.maxInt(u64)) return error.MissingOp;
        const serial = self.next_serial;
        var i: usize = 0;
        while (i < self.regs.len) : (i += 1) {
            if (self.regs[i].live and self.regs[i].token == token_key and self.regs[i].op == op) {
                return error.MissingOp;
            }
        }
        i = 0;
        while (i < self.regs.len) : (i += 1) {
            if (!self.regs[i].live) {
                self.regs[i] = .{ .token = token_key, .handle = handle, .op = op, .serial = serial, .live = true };
                self.next_serial += 1;
                return serial;
            }
        }
        const old = self.regs;
        const new_len = if (old.len == 0) @as(usize, 16) else std.math.mul(usize, old.len, 2) catch return error.OutOfMemory;
        const grown = std.heap.page_allocator.alloc(Reg, new_len) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            std.heap.page_allocator.free(old);
        }
        var z: usize = old.len;
        while (z < grown.len) : (z += 1) grown[z] = .{};
        grown[old.len] = .{ .token = token_key, .handle = handle, .op = op, .serial = serial, .live = true };
        self.regs = grown;
        self.next_serial += 1;
        return serial;
    }

    fn lookup(self: *Iocp, token_key: usize, op: u8) ?Reg {
        for (self.regs) |reg| {
            if (reg.live and reg.token == token_key and reg.op == op) return reg;
        }
        return null;
    }

    fn forgetSerial(self: *Iocp, serial: u64) void {
        for (self.regs) |*reg| {
            if (reg.live and reg.serial == serial) reg.live = false;
        }
    }

    fn batchCap(entries: u16) u16 {
        if (entries == 0 or entries > submit_batch) return submit_batch;
        return entries;
    }

    fn packToken(token: ringlane.FdToken) usize {
        return (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    }

    fn handleOf(fd: linux.fd_t) !usize {
        if (fd < 0) return error.MissingOp;
        if (comptime builtin.os.tag == .windows) return windows_sockets.get(fd) orelse error.MissingOp;
        return @intCast(fd);
    }

    fn timeoutMillis(ts: *const linux.kernel_timespec) ?i64 {
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return null;
        const sec_ms = std.math.mul(i64, ts.sec, 1000) catch return null;
        // Rounding down would expire a positive sub-millisecond timeout early.
        return std.math.add(i64, sec_ms, @divTrunc(ts.nsec + 999_999, 1_000_000)) catch null;
    }

    fn afdPollRequest(mask: u32) u32 {
        var events: u32 = afd_poll_disconnect | afd_poll_abort | afd_poll_local_close;
        if (mask & linux.POLL.IN != 0) events |= afd_poll_receive | afd_poll_accept;
        if (mask & linux.POLL.OUT != 0) events |= afd_poll_send | afd_poll_connect_fail;
        return events;
    }

    fn afdPollResult(packet: Packet, info: *const AfdPollInfo) i32 {
        if (info.handle_count != 1 or info.handles.handle != packet.handle or info.handles.status != 0)
            return -1;
        const events = info.handles.events;
        var ready: u32 = 0;
        if (packet.length & linux.POLL.IN != 0 and events & (afd_poll_receive | afd_poll_accept | afd_poll_disconnect | afd_poll_abort) != 0)
            ready |= linux.POLL.IN;
        if (packet.length & linux.POLL.OUT != 0 and events & afd_poll_send != 0)
            ready |= linux.POLL.OUT;
        if (events & afd_poll_disconnect != 0) ready |= linux.POLL.HUP;
        if (events & afd_poll_abort != 0) ready |= linux.POLL.ERR | linux.POLL.HUP;
        if (events & afd_poll_connect_fail != 0) ready |= linux.POLL.ERR | linux.POLL.HUP;
        if (events & afd_poll_local_close != 0) ready |= linux.POLL.NVAL;
        return if (ready == 0) -1 else @intCast(ready);
    }

    fn openHandle() !usize {
        const w = std.os.windows;
        var handle: w.HANDLE = undefined;
        const status = NtCreateIoCompletion(&handle, w.ACCESS_MASK.Specific.IoCompletion.ALL_ACCESS, null, 0);
        if (status != .SUCCESS) return error.MissingOp;
        const raw = @intFromPtr(handle);
        if (raw == 0) windowsTypecheck(raw);
        return raw;
    }

    fn closeWindows(self: *Iocp) void {
        const w = std.os.windows;
        while (self.popReady()) |ev| {
            if (ev.op == .accept and ev.result >= 0) closeSocket(ev.result);
        }
        if (self.port != 0) {
            _ = w.ntdll.NtClose(@ptrFromInt(self.port));
            self.port = 0;
        }
    }

    fn liveCount(self: *const Iocp) usize {
        return self.live_slots;
    }

    fn ensureFreeSlots(self: *Iocp, need: usize) !void {
        const allocator = std.heap.page_allocator;
        while (self.free_slots.items.len < need) {
            const total_slots = std.math.mul(usize, self.slabs.items.len + 1, slab_size) catch return error.OutOfMemory;
            try self.slabs.ensureUnusedCapacity(allocator, 1);
            // Reserve for every slot, including those currently in flight.
            // A completion only appends its pointer and must never allocate.
            try self.free_slots.ensureTotalCapacity(allocator, total_slots);
            const slab = try allocator.create(Slab);
            slab.* = .{};
            self.slabs.appendAssumeCapacity(slab);
            for (&slab.slots) |*slot| self.free_slots.appendAssumeCapacity(slot);
        }
    }

    fn retireSlot(self: *Iocp, slot: *Slot) void {
        std.debug.assert(slot.live and self.live_slots != 0);
        slot.live = false;
        self.live_slots -= 1;
        self.free_slots.appendAssumeCapacity(slot);
    }

    fn findSlotByApc(self: *Iocp, apc_addr: usize) ?*Slot {
        for (self.slabs.items) |slab| {
            const start = @intFromPtr(&slab.slots);
            if (apc_addr < start or apc_addr - start >= @sizeOf(Slab)) continue;
            const index = (apc_addr - start) / @sizeOf(Slot);
            const slot = &slab.slots[index];
            if (!slot.live) return null;
            const request_addr = if (slot.packet.op == op_connect)
                @intFromPtr(&slot.connect_overlapped)
            else
                @intFromPtr(&slot.iosb);
            return if (request_addr == apc_addr) slot else null;
        }
        return null;
    }

    fn ensureReadyCapacity(self: *Iocp, additional: usize) !void {
        if (self.ready_head != 0) {
            const count = self.ready.items.len - self.ready_head;
            std.mem.copyForwards(Reaped, self.ready.items[0..count], self.ready.items[self.ready_head..]);
            self.ready.items.len = count;
            self.ready_head = 0;
        }
        try self.ready.ensureUnusedCapacity(std.heap.page_allocator, additional);
    }

    fn quiesceWindows(self: *Iocp) !void {
        if (self.port == 0) return;
        // The caller must stop posting while quiesce runs. Queued requests
        // never reached the kernel and require no cancellation, but their
        // token registrations must retire before this port can be reused.
        for (self.packets[0..self.n]) |packet| self.forgetSerial(packet.serial);
        self.n = 0;
        for (self.timers) |*timer| {
            if (!timer.live) continue;
            timer.live = false;
            self.forgetSerial(timer.serial);
        }
        while (self.popReady()) |ev| {
            if (ev.op == .accept and ev.result >= 0) closeSocket(ev.result);
        }
        for (self.slabs.items) |slab| {
            for (&slab.slots) |*slot| {
                if (slot.live) try self.cancelSlot(slot);
            }
        }
        const start_ms = GetTickCount64();
        const drain_limit_ms: u64 = 10_000;
        while (self.liveCount() != 0) {
            const elapsed_ms = GetTickCount64() -% start_ms;
            if (elapsed_ms >= drain_limit_ms) return error.DrainTimedOut;
            const remaining_ms: u32 = @intCast(drain_limit_ms - elapsed_ms);
            const ev = self.takeOne(@min(remaining_ms, 1000)) catch |err| switch (err) {
                error.Unmatched => continue,
                else => return err,
            };
            if (ev) |done| {
                if (done.op == .accept and done.result >= 0) closeSocket(done.result);
            }
        }
    }

    fn rememberTimer(self: *Iocp, token: usize, serial: u64, deadline_ms: u64) !void {
        for (self.timers) |*timer| {
            if (timer.live) continue;
            timer.* = .{ .token = token, .serial = serial, .deadline_ms = deadline_ms, .live = true };
            return;
        }
        const old = self.timers;
        const new_len = if (old.len == 0) @as(usize, 8) else std.math.mul(usize, old.len, 2) catch return error.OutOfMemory;
        const grown = std.heap.page_allocator.alloc(Timer, new_len) catch return error.OutOfMemory;
        if (old.len != 0) {
            @memcpy(grown[0..old.len], old);
            std.heap.page_allocator.free(old);
        }
        @memset(grown[old.len..], .{});
        grown[old.len] = .{ .token = token, .serial = serial, .deadline_ms = deadline_ms, .live = true };
        self.timers = grown;
    }

    fn cancelTimer(self: *Iocp, serial: u64) !void {
        for (self.timers) |*timer| {
            if (!timer.live or timer.serial != serial) continue;
            timer.live = false;
            return;
        }
        // A zero-delay timer may already have been reaped. Its registration
        // was valid when cancel was queued, so cancellation is then a no-op.
    }

    fn dueTimer(self: *Iocp, now_ms: u64) ?Reaped {
        for (self.timers) |*timer| {
            if (!timer.live or timer.deadline_ms > now_ms) continue;
            timer.live = false;
            self.forgetSerial(timer.serial);
            return .{ .op = .timeout, .token = .{
                .slot = @truncate(timer.token),
                .gen = @truncate(timer.token >> 32),
            }, .result = 0 };
        }
        return null;
    }

    fn nextTimerWait(self: *const Iocp, now_ms: u64) ?u32 {
        var nearest: ?u64 = null;
        for (self.timers) |timer| {
            if (!timer.live) continue;
            const left = timer.deadline_ms -| now_ms;
            nearest = if (nearest) |prev| @min(prev, left) else left;
        }
        return if (nearest) |left| @intCast(@min(left, std.math.maxInt(u32))) else null;
    }

    fn submitWindows(self: *Iocp) !u32 {
        const n_packets = self.n;
        if (n_packets == 0 or n_packets > submit_batch) return error.MissingOp;
        var need: usize = 0;
        for (self.packets[0..n_packets]) |packet| {
            switch (packet.op) {
                op_accept, op_recv, op_send, op_poll, op_connect => need += 1,
                else => {},
            }
        }
        // Both allocations happen before the first kernel post. Already
        // pending slots remain in immutable slabs, and an inline completion
        // cannot be lost because the ready queue runs out of space.
        try self.ensureReadyCapacity(need);
        try self.ensureFreeSlots(need);
        var queued: [submit_batch]Packet = undefined;
        @memcpy(queued[0..n_packets], self.packets[0..n_packets]);
        self.n = 0;
        var i: u16 = 0;
        while (i < n_packets) : (i += 1) {
            self.postOne(queued[i]) catch |err| {
                // Some earlier requests may already own kernel storage. Keep
                // their slots live for reap/quiesce; reject further enqueue
                // and submit calls, and retire registrations for requests
                // that never reached the kernel.
                self.submit_failed = true;
                for (queued[i..n_packets]) |remaining| self.forgetSerial(remaining.serial);
                return err;
            };
        }
        return n_packets;
    }

    fn claimSlot(self: *Iocp, packet: Packet) !*Slot {
        const slot = self.free_slots.pop() orelse return error.MissingOp;
        std.debug.assert(!slot.live);
        slot.live = true;
        slot.packet = packet;
        slot.iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
        self.live_slots += 1;
        return slot;
    }

    fn postOne(self: *Iocp, packet: Packet) !void {
        switch (packet.op) {
            op_cancel => return self.cancelOne(packet),
            op_timeout => return self.armTimer(packet),
            op_accept, op_recv, op_send, op_poll, op_connect => {},
            else => return error.MissingOp,
        }
        if ((packet.op == op_recv or packet.op == op_send) and
            (packet.buf == 0 or packet.length == 0 or packet.ioctl == 0))
        {
            return error.MissingOp;
        }
        const slot = try self.claimSlot(packet);
        errdefer {
            if (slot.live) self.retireSlot(slot);
            self.forgetSerial(packet.serial);
        }
        const iosb = &slot.iosb;
        const done = switch (packet.op) {
            op_accept => blk: {
                const out = &slot.accept_out;
                @memset(out, 0);
                break :blk try self.device(packet, iosb, "", out);
            },
            op_recv, op_send => blk: {
                if (packet.buf == 0 or packet.length == 0 or packet.ioctl == 0) return error.MissingOp;
                const wsa = &slot.wsa_buf;
                wsa.* = .{
                    .len = packet.length,
                    .buf = @ptrFromInt(packet.buf),
                };
                const info = &slot.data_info;
                // AFD_OVERLAPPED is 0x2. TDI_RECEIVE_NORMAL is 0x20. Send uses
                // no TDI flag; the kernel rejects a raw NtReadFile / NtWriteFile.
                info.* = .{
                    .buffers = wsa,
                    .count = 1,
                    .afd_flags = 0x2,
                    .tdi_flags = if (packet.op == op_recv) @as(u32, 0x20) else 0,
                };
                var none: [0]u8 = .{};
                break :blk try self.device(packet, iosb, std.mem.asBytes(info), &none);
            },
            op_poll => blk: {
                // AFD poll is METHOD_BUFFERED and reads the handle list from
                // the input. The kernel reports readiness in the output
                // handle's Events field, not in IOSB.Information (byte count).
                const info = &slot.poll_info;
                info.* = .{
                    .timeout = std.math.maxInt(i64),
                    .handle_count = 1,
                    .exclusive = 0,
                    .handles = .{
                        .handle = packet.handle,
                        .events = afdPollRequest(packet.length),
                        .status = 0,
                    },
                };
                const out = &slot.poll_out;
                out.* = std.mem.zeroes(AfdPollInfo);
                break :blk try self.device(packet, iosb, std.mem.asBytes(info), std.mem.asBytes(out));
            },
            op_connect => try self.postConnect(slot, packet),
            else => return error.MissingOp,
        };
        if (done) try self.finishInline(slot);
    }

    fn postConnect(self: *Iocp, slot: *Slot, packet: Packet) !bool {
        try self.associate(packet);
        const family = std.mem.readInt(u16, packet.connect_addr[0..2], .native);
        const bound = if (family == wsa_af_inet) blk: {
            const addr = RioSockAddr{ .family = @intCast(wsa_af_inet), .port = 0, .addr = 0, .zero = @splat(0) };
            break :blk bind(packet.handle, &addr, @sizeOf(RioSockAddr));
        } else blk: {
            const addr = RioSockAddr6{ .family = @intCast(wsa_af_inet6), .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
            break :blk bind(packet.handle, &addr, @sizeOf(RioSockAddr6));
        };
        // ConnectEx requires a bound socket. WSAEINVAL means the caller had
        // already bound it; ConnectEx will validate that state itself.
        if (bound != 0 and WSAGetLastError() != 10022) {
            slot.iosb.u.Status = .UNSUCCESSFUL;
            return true;
        }
        const connect_ex = loadConnectEx(packet.handle) catch {
            slot.iosb.u.Status = .UNSUCCESSFUL;
            return true;
        };
        slot.connect_addr = packet.connect_addr;
        slot.connect_sent = 0;
        slot.connect_overlapped = std.mem.zeroes(WsaOverlapped);
        const ok = connect_ex(
            packet.handle,
            @ptrCast(&slot.connect_addr),
            packet.connect_len,
            null,
            0,
            &slot.connect_sent,
            &slot.connect_overlapped,
        );
        if (ok != 0) {
            slot.iosb.u.Status = .SUCCESS;
            return true;
        }
        if (WSAGetLastError() == 997) return false;
        slot.iosb.u.Status = .UNSUCCESSFUL;
        return true;
    }

    fn finishInline(self: *Iocp, slot: *Slot) !void {
        const packet = slot.packet;
        const iosb = slot.iosb;
        const poll_out: ?*const AfdPollInfo = if (packet.op == op_poll) &slot.poll_out else null;
        const ev = finishPosted(packet, iosb, &slot.accept_out, poll_out);
        self.retireSlot(slot);
        self.forgetSerial(packet.serial);
        self.pushReady(ev) catch |err| {
            if (ev.op == .accept and ev.result >= 0) closeSocket(ev.result);
            return err;
        };
    }

    fn pushReady(self: *Iocp, ev: Reaped) !void {
        try self.ready.append(std.heap.page_allocator, ev);
    }

    fn popReady(self: *Iocp) ?Reaped {
        if (self.ready_head == self.ready.items.len) return null;
        const ev = self.ready.items[self.ready_head];
        self.ready_head += 1;
        if (self.ready_head == self.ready.items.len) {
            self.ready.clearRetainingCapacity();
            self.ready_head = 0;
        }
        return ev;
    }

    fn readyHas(self: *const Iocp, token_key: usize, op: u8) bool {
        const result_op: Op = switch (op) {
            op_accept => .accept,
            op_recv => .recv,
            op_send => .send,
            op_poll => .poll,
            op_timeout => .timeout,
            op_connect => .connect,
            else => return false,
        };
        for (self.ready.items[self.ready_head..]) |ev| {
            if (ev.op == result_op and packToken(ev.token) == token_key) return true;
        }
        return false;
    }

    fn associate(self: *Iocp, packet: Packet) !void {
        // The opaque descriptor identifies the socket's lifetime. A recycled
        // raw SOCKET value belongs to a new descriptor and must be associated
        // with the completion port and configured again.
        return windows_sockets.associate(packet.socket_fd, packet.handle, self.port);
    }

    /// `true` means the ioctl finished inline. The bytes are already in the
    /// caller buffer and `reap` must observe them without waiting for a port
    /// packet that may never arrive.
    fn device(self: *Iocp, packet: Packet, iosb: *std.os.windows.IO_STATUS_BLOCK, in_buf: []const u8, out: []u8) !bool {
        const w = std.os.windows;
        try self.associate(packet);
        iosb.* = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const code: w.CTL_CODE = @bitCast(packet.ioctl);
        const status = w.ntdll.NtDeviceIoControlFile(
            @ptrFromInt(packet.handle),
            null,
            null,
            @ptrCast(iosb),
            iosb,
            code,
            if (in_buf.len == 0) null else @ptrCast(in_buf.ptr),
            @intCast(in_buf.len),
            if (out.len == 0) null else @ptrCast(out.ptr),
            @intCast(out.len),
        );
        if (status == .SUCCESS) return true;
        if (status == .PENDING) return false;
        // One peer reset is that operation's result. MissingOp here ends the
        // listen loop, which is what a reset of the accepted socket did.
        if (closedConnection(status)) {
            iosb.u.Status = status;
            return true;
        }
        std.debug.print("GAP-X1 windows iocp status=0x{x} op={d}\n", .{ @intFromEnum(status), packet.op });
        return error.MissingOp;
    }

    fn cancelOne(self: *Iocp, packet: Packet) !void {
        if (packet.length == op_timeout) {
            return self.cancelTimer(packet.serial);
        }
        for (self.slabs.items) |slab| {
            for (&slab.slots) |*slot| {
                if (!slot.live or !matchesCancel(packet, slot.packet)) continue;
                try self.cancelSlot(slot);
            }
        }
        // The request may have completed inline or already queued a packet.
        // Its slot then needs no cancellation, but its ready result still
        // belongs to the normal reap/quiesce path.
    }

    fn matchesCancel(cancel: Packet, pending: Packet) bool {
        return cancel.handle == pending.handle and
            cancel.token == pending.token and
            cancel.serial == pending.serial and
            cancel.length == pending.op;
    }

    fn cancelSlot(self: *Iocp, slot: *Slot) !void {
        const w = std.os.windows;
        _ = self;
        slot.cancel_iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
        const status = NtCancelIoFileEx(
            @ptrFromInt(slot.packet.handle),
            if (slot.packet.op == op_connect) @ptrCast(&slot.connect_overlapped) else &slot.iosb,
            &slot.cancel_iosb,
        );
        // NtCancelIoFileEx normally completes its own status synchronously.
        // If that contract changes, do not recycle this slot or free its
        // output status while the kernel can still write to it.
        if (status == .PENDING) @panic("pending NtCancelIoFileEx result");
        // A socket can close between dispatch and shutdown. Closing it
        // cancels outstanding I/O, and its completion still owns the IOSB
        // until the port delivers it. Continue draining that packet.
        if (status != .SUCCESS and status != .NOT_FOUND and @intFromEnum(status) != 0xC0000008) {
            std.debug.print("windows iocp cancel failed: status=0x{x} op={d}\n", .{ @intFromEnum(status), slot.packet.op });
            return error.MissingOp;
        }
    }

    fn armTimer(self: *Iocp, packet: Packet) !void {
        const deadline_ms = std.math.add(u64, GetTickCount64(), packet.length) catch return error.MissingOp;
        try self.rememberTimer(packet.token, packet.serial, deadline_ms);
    }

    fn reapWindows(self: *Iocp, out: []Reaped, wait_ms: u32) !u32 {
        var n: u32 = 0;
        while (n < out.len) {
            const ev = self.popReady() orelse break;
            out[n] = ev;
            n += 1;
        }
        var waited = n != 0;
        var skips: usize = 0;
        while (n < out.len) {
            const item = self.takeOne(if (waited) 0 else wait_ms) catch |err| switch (err) {
                error.Unmatched => {
                    skips += 1;
                    if (skips > self.slabs.items.len * slab_size + submit_batch) return error.MissingOp;
                    waited = true;
                    continue;
                },
                else => return err,
            };
            waited = true;
            if (item) |got| {
                out[n] = got;
                n += 1;
            } else break;
        }
        return n;
    }

    fn takeOne(self: *Iocp, wait_ms: u32) !?Reaped {
        const w = std.os.windows;
        const end_ms = std.math.add(u64, GetTickCount64(), wait_ms) catch return error.MissingOp;
        while (true) {
            const now_ms = GetTickCount64();
            if (self.dueTimer(now_ms)) |ev| return ev;
            const remaining: u32 = @intCast(@min(end_ms -| now_ms, std.math.maxInt(u32)));
            const timer_wait = self.nextTimerWait(now_ms) orelse remaining;
            const period = @min(remaining, timer_wait);
            var key: ?*anyopaque = null;
            var apc: ?*anyopaque = null;
            var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
            const due: w.LARGE_INTEGER = if (period == 0) 0 else -@as(w.LARGE_INTEGER, period) * 10_000;
            const status = NtRemoveIoCompletion(@ptrFromInt(self.port), &key, &apc, &iosb, &due);
            if (status == .TIMEOUT) {
                if (period == 0 or GetTickCount64() >= end_ms) return self.dueTimer(GetTickCount64());
                continue;
            }
            if (status != .SUCCESS) {
                std.debug.print("windows iocp dequeue failed: status=0x{x}\n", .{@intFromEnum(status)});
                return error.MissingOp;
            }
            const apc_addr = @intFromPtr(apc);
            if (self.findSlotByApc(apc_addr)) |slot| {
                const packet = slot.packet;
                const poll_out: ?*const AfdPollInfo = if (packet.op == op_poll) &slot.poll_out else null;
                const result = finishPosted(packet, iosb, &slot.accept_out, poll_out);
                self.retireSlot(slot);
                self.forgetSerial(packet.serial);
                return result;
            }
            // A synchronous completion or AFD accept adoption can leave an
            // extra packet. It has no live slot and is safe to discard.
            return error.Unmatched;
        }
    }

    fn finishPosted(packet: Packet, iosb: std.os.windows.IO_STATUS_BLOCK, accept_out: []const u8, poll_out: ?*const AfdPollInfo) Reaped {
        const token = ringlane.FdToken{
            .slot = @truncate(packet.token),
            .gen = @truncate(packet.token >> 32),
        };
        const op: Op = switch (packet.op) {
            op_accept => .accept,
            op_recv => .recv,
            op_send => .send,
            op_poll => .poll,
            op_connect => .connect,
            else => .cancel,
        };
        if (iosb.u.Status == .CANCELLED) return .{ .op = op, .token = token, .result = -@as(i32, @intFromEnum(linux.E.CANCELED)) };
        if (iosb.u.Status != .SUCCESS) return .{ .op = op, .token = token, .result = -1 };
        if (packet.op == op_accept) {
            const sock = acceptSequence(packet.handle, accept_out) catch {
                return .{ .op = .accept, .token = token, .result = -1 };
            };
            return .{ .op = .accept, .token = token, .result = sock };
        }
        if (packet.op == op_connect) {
            if (comptime builtin.os.tag == .windows) {
                if (setsockopt(packet.handle, sol_socket, so_update_connect_context, null, 0) != 0)
                    return .{ .op = .connect, .token = token, .result = -1 };
            }
            return .{ .op = .connect, .token = token, .result = 0 };
        }
        if (packet.op == op_poll)
            return .{ .op = .poll, .token = token, .result = if (poll_out) |info| afdPollResult(packet, info) else -1 };
        // AFD completions must never grant access past the submitted buffer.
        // Treat a larger count as a failed operation, including after an IOCP
        // slot was reused and a late packet arrived for its former request.
        if ((packet.op == op_recv or packet.op == op_send) and
            iosb.Information > @as(usize, packet.length))
        {
            return .{ .op = op, .token = token, .result = -1 };
        }
        if (iosb.Information > std.math.maxInt(i32)) {
            return .{ .op = op, .token = token, .result = std.math.maxInt(i32) };
        }
        return .{ .op = op, .token = token, .result = @intCast(iosb.Information) };
    }

    fn proveQueued(backend: *IoBackend, sock: linux.fd_t) !u32 {
        const token = ringlane.FdToken{ .slot = 1, .gen = 1 };
        var buf: [4]u8 = .{ 0, 0, 0, 0 };
        try backend.accept(token, sock);
        try backend.recv(token, sock, &buf);
        try backend.send(token, sock, "x");
        try backend.poll(token, sock, linux.POLL.IN);
        var ts = linux.kernel_timespec{ .sec = 1, .nsec = 0 };
        try backend.timeout(token, &ts);
        try backend.cancel(.timeout, token);
        const submitted = try backend.submit();
        if (submitted == 0) return error.MissingOp;
        return submitted;
    }

    fn exerciseLive() !void {
        var backend = try IoBackend.openOwned(.iocp, 32, .{});
        defer backend.deinit();
        try backend.requireAll();
        const submitted = try proveQueued(&backend, 1);
        if (submitted == 0) return error.MissingOp;
    }

    fn windowsTypecheck(raw: usize) void {
        var port = Iocp.unopened(32);
        port.port = raw;
        var backend = IoBackend{
            .family = .iocp,
            .entries = 32,
            .iocp = &port,
        };
        _ = proveQueued(&backend, 1) catch {};
        backend.iocp = null;
        var key: ?*anyopaque = null;
        var apc: ?*anyopaque = null;
        var iosb = std.mem.zeroes(std.os.windows.IO_STATUS_BLOCK);
        _ = NtRemoveIoCompletion(@ptrFromInt(raw), &key, &apc, &iosb, null);
        exerciseLive() catch {};
        if (listenTcp("127.0.0.1", 0)) |listener| {
            closeSocket(listener.fd);
        } else |_| {}
    }
};

extern "ntdll" fn NtCreateIoCompletion(
    IoCompletionHandle: *std.os.windows.HANDLE,
    DesiredAccess: std.os.windows.ACCESS_MASK,
    ObjectAttributes: ?*const anyopaque,
    Count: std.os.windows.ULONG,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtRemoveIoCompletion(
    IoCompletionHandle: std.os.windows.HANDLE,
    KeyContext: *?*anyopaque,
    ApcContext: *?*anyopaque,
    IoStatusBlock: *std.os.windows.IO_STATUS_BLOCK,
    Timeout: ?*const std.os.windows.LARGE_INTEGER,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtCancelIoFileEx(
    FileHandle: std.os.windows.HANDLE,
    IoRequestToCancel: *std.os.windows.IO_STATUS_BLOCK,
    IoStatusBlock: *std.os.windows.IO_STATUS_BLOCK,
) callconv(.winapi) std.os.windows.NTSTATUS;

/// `WSAID_MULTIPLE_RIO` from `mswsock.h`: `8509e081-96dd-4005-b165-9e2ee8c79e3f`.
pub const RioGuid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

pub const rio_guid: RioGuid = .{
    .data1 = 0x8509e081,
    .data2 = 0x96dd,
    .data3 = 0x4005,
    .data4 = .{ 0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f },
};

/// `_WSAIORW(IOC_WS2, 36)` = `IOC_INOUT | IOC_WS2 | 36`.
pub const sio_get_multiple_rio: u32 = 0xC8000024;
const sio_get_extension_function_pointer: u32 = 0xC8000006;
const connect_ex_guid = RioGuid{
    .data1 = 0x25a207b9,
    .data2 = 0xddf3,
    .data3 = 0x4660,
    .data4 = .{ 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e },
};
pub const wsa_flag_overlapped: u32 = 0x01;
pub const wsa_flag_registered_io: u32 = 0x100;
pub const wsa_af_inet: i32 = 2;
pub const wsa_af_inet6: i32 = 23;
pub const wsa_sock_stream: i32 = 1;
pub const wsa_ipproto_tcp: i32 = 6;

/// One pointer from `RIO_EXTENSION_FUNCTION_TABLE`. The daemon calls these
/// only from `dequeueRegistered`. Ordinary accept, recv, and send stay on
/// `IOCTL_AFD_RECEIVE` and `IOCTL_AFD_SEND`.
pub const RioFn = ?*anyopaque;

/// Userspace image of `RIO_EXTENSION_FUNCTION_TABLE`. On 64-bit Windows the
/// `u32` size is padded to the first pointer, then thirteen pointers: 112 bytes.
pub const RioTable = extern struct {
    cb_size: u32 = 0,
    receive: RioFn = null,
    receive_ex: RioFn = null,
    send: RioFn = null,
    send_ex: RioFn = null,
    close_completion_queue: RioFn = null,
    create_completion_queue: RioFn = null,
    create_request_queue: RioFn = null,
    dequeue_completion: RioFn = null,
    deregister_buffer: RioFn = null,
    notify: RioFn = null,
    register_buffer: RioFn = null,
    resize_completion_queue: RioFn = null,
    resize_request_queue: RioFn = null,
};

/// `RIO_BUF`. `buffer_id` is the value `RIORegisterBuffer` returned.
const RioBuf = extern struct {
    buffer_id: usize,
    offset: u32,
    length: u32,
};

/// `RIORESULT`. `status` is 0 on success. `request_context` is the pointer
/// value passed to `RIOSend`, not a length the caller invents after the fact.
const RioResult = extern struct {
    status: i32 = -1,
    bytes: u32 = 0,
    socket_context: u64 = 0,
    request_context: u64 = 0,
};

/// `sockaddr_in` for the loopback pair the dequeue uses. 16 bytes.
const RioSockAddr = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

const RioSockAddr6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

fn socketName(handle: usize) error{SocketFailed}!RioSockAddr6 {
    var name = std.mem.zeroes(RioSockAddr6);
    var name_len: i32 = @sizeOf(RioSockAddr6);
    if (getsockname(handle, @ptrCast(&name), &name_len) != 0) return error.SocketFailed;
    if ((name.family == wsa_af_inet and name_len == @sizeOf(RioSockAddr)) or
        (name.family == wsa_af_inet6 and name_len == @sizeOf(RioSockAddr6))) return name;
    return error.SocketFailed;
}

/// Winsock OVERLAPPED begins with an IO_STATUS_BLOCK-compatible status and
/// information pair. ConnectEx holds this storage until its port completion.
const WsaOverlapped = extern struct {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: ?std.os.windows.HANDLE,
};

const ConnectExFn = *const fn (
    socket: usize,
    address: *const anyopaque,
    address_len: i32,
    send_buffer: ?*const anyopaque,
    send_len: u32,
    bytes_sent: *u32,
    overlapped: *WsaOverlapped,
) callconv(.winapi) i32;

/// `(RIO_BUFFERID)(ULONG_PTR)0xFFFFFFFF` from the Windows SDK.
const rio_invalid_buffer_id: usize = 0xFFFFFFFF;
/// `RIO_CORRUPT_CQ`. A dequeue count of this value is a failed queue, not a transfer.
pub const rio_corrupt_cq: u32 = 0xFFFFFFFF;
/// Opaque `RIOSend` request context. The kernel must copy it into `RIORESULT`.
const rio_request_context: u64 = 0x33554144;
const rio_payload = "RIO!";

comptime {
    if (@sizeOf(RioGuid) != 16) @compileError("WSAID_MULTIPLE_RIO is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(RioTable) != 112) {
        @compileError(std.fmt.comptimePrint(
            "RIO_EXTENSION_FUNCTION_TABLE is {d} bytes, want 112",
            .{@sizeOf(RioTable)},
        ));
    }
    if (@sizeOf(usize) == 8 and @sizeOf(RioBuf) != 16) @compileError("RIO_BUF is 16 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(RioResult) != 24) @compileError("RIORESULT is 24 bytes");
    if (@sizeOf(RioSockAddr) != 16) @compileError("sockaddr_in is 16 bytes");
    if (@sizeOf(RioSockAddr6) != 28) @compileError("sockaddr_in6 is 28 bytes");
    if (@sizeOf(usize) == 8 and @sizeOf(WsaOverlapped) != 32) @compileError("OVERLAPPED is 32 bytes");
}

const rio_fields = [_][]const u8{
    "receive",
    "receive_ex",
    "send",
    "send_ex",
    "close_completion_queue",
    "create_completion_queue",
    "create_request_queue",
    "dequeue_completion",
    "deregister_buffer",
    "notify",
    "register_buffer",
    "resize_completion_queue",
    "resize_request_queue",
};

/// True only when `cbSize` is the struct size and every required pointer is set.
/// A zero table, a short `cbSize`, or any null function is unusable.
pub fn rioTableUsable(table: *const RioTable) bool {
    if (table.cb_size != @sizeOf(RioTable)) return false;
    inline for (rio_fields) |name| {
        if (@field(table, name) == null) return false;
    }
    return true;
}

/// Loads the RIO table for an existing socket. `INVALID_SOCKET` fails before
/// `WSAIoctl`. Every non-Windows host fails before `WSAIoctl`.
pub fn loadRegisteredIo(socket: usize) !RioTable {
    if (socket == std.math.maxInt(usize)) return error.MissingOp;
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    return ioctlRegisteredIo(socket);
}

/// Socket plus table load used by `Iocp.open`. Off Windows this is `MissingOp`
/// and does not call Winsock. The probe socket is closed; the function
/// pointers are what open keeps. `WSACleanup` is not called.
fn loadRioForDaemon() !RioTable {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    std.mem.doNotOptimizeAway(&loadRegisteredIo);
    const sock = try openRegisteredSocket();
    defer closeRegisteredSocket(sock);
    const table = try loadRegisteredIo(sock);
    if (!rioTableUsable(&table)) return error.MissingOp;
    return table;
}

fn openRegisteredSocket() !usize {
    if (comptime builtin.os.tag != .windows) return error.MissingOp;
    if (comptime @sizeOf(usize) != 8) return error.MissingOp;
    ensureWinsock() catch return error.MissingOp;
    const sock = WSASocketW(
        wsa_af_inet,
        wsa_sock_stream,
        wsa_ipproto_tcp,
        null,
        0,
        wsa_flag_overlapped | wsa_flag_registered_io,
    );
    if (sock == std.math.maxInt(usize)) return error.MissingOp;
    return sock;
}

fn closeRegisteredSocket(socket: usize) void {
    if (comptime builtin.os.tag != .windows) return;
    if (socket == std.math.maxInt(usize)) return;
    _ = closesocket(socket);
}

fn ioctlRegisteredIo(socket: usize) !RioTable {
    var table = RioTable{ .cb_size = @intCast(@sizeOf(RioTable)) };
    var bytes: u32 = 0;
    const rc = WSAIoctl(
        socket,
        sio_get_multiple_rio,
        &rio_guid,
        @sizeOf(RioGuid),
        &table,
        @intCast(@sizeOf(RioTable)),
        &bytes,
        null,
        null,
    );
    if (rc != 0) return error.MissingOp;
    if (bytes < @sizeOf(RioTable)) return error.MissingOp;
    if (!rioTableUsable(&table)) return error.MissingOp;
    return table;
}

fn loadConnectEx(socket: usize) !ConnectExFn {
    var raw: ?*anyopaque = null;
    var bytes: u32 = 0;
    if (WSAIoctl(
        socket,
        sio_get_extension_function_pointer,
        &connect_ex_guid,
        @sizeOf(RioGuid),
        @ptrCast(&raw),
        @sizeOf(?*anyopaque),
        &bytes,
        null,
        null,
    ) != 0 or bytes != @sizeOf(?*anyopaque)) return error.MissingOp;
    return rioPtr(ConnectExFn, raw) orelse error.MissingOp;
}

extern "ws2_32" fn WSAStartup(
    version_requested: u16,
    data: *anyopaque,
) callconv(.winapi) i32;

extern "ws2_32" fn WSASocketW(
    address_family: i32,
    socket_type: i32,
    protocol: i32,
    protocol_info: ?*anyopaque,
    group: u32,
    flags: u32,
) callconv(.winapi) usize;

extern "ws2_32" fn WSAIoctl(
    socket: usize,
    control_code: u32,
    in_buffer: ?*const anyopaque,
    in_bytes: u32,
    out_buffer: ?*anyopaque,
    out_bytes: u32,
    bytes_returned: *u32,
    overlapped: ?*anyopaque,
    completion: ?*anyopaque,
) callconv(.winapi) i32;

extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;

extern "ws2_32" fn shutdown(socket: usize, how: i32) callconv(.winapi) i32;

extern "ws2_32" fn bind(socket: usize, addr: *const anyopaque, namelen: i32) callconv(.winapi) i32;

extern "ws2_32" fn listen(socket: usize, backlog: i32) callconv(.winapi) i32;

extern "ws2_32" fn getsockname(socket: usize, addr: *anyopaque, namelen: *i32) callconv(.winapi) i32;

extern "ws2_32" fn getpeername(socket: usize, addr: *anyopaque, namelen: *i32) callconv(.winapi) i32;

extern "ws2_32" fn getsockopt(socket: usize, level: i32, name: i32, value: *anyopaque, len: *i32) callconv(.winapi) i32;

extern "ws2_32" fn connect(socket: usize, addr: *const RioSockAddr, namelen: i32) callconv(.winapi) i32;

extern "ws2_32" fn accept(socket: usize, addr: ?*anyopaque, namelen: ?*i32) callconv(.winapi) usize;

extern "ws2_32" fn recv(socket: usize, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;

extern "ws2_32" fn send(socket: usize, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;

extern "ws2_32" fn setsockopt(socket: usize, level: i32, name: i32, value: ?*const anyopaque, len: i32) callconv(.winapi) i32;

extern "ws2_32" fn select(nfds: i32, readfds: ?*RioFdSet, writefds: ?*RioFdSet, exceptfds: ?*RioFdSet, timeout: ?*RioTimeval) callconv(.winapi) i32;

extern "ws2_32" fn WSAGetLastError() callconv(.winapi) i32;

fn acceptOne(handle: usize) error{ WouldBlock, SocketFailed }!i32 {
    const sock = accept(handle, null, null);
    if (sock == std.math.maxInt(usize)) {
        if (WSAGetLastError() == 10035) return error.WouldBlock;
        return error.SocketFailed;
    }
    return windows_sockets.register(sock) catch {
        _ = closesocket(sock);
        return error.SocketFailed;
    };
}

fn closedConnection(status: std.os.windows.NTSTATUS) bool {
    return switch (@intFromEnum(status)) {
        // DISCONNECTED, RESET, LOCAL_DISCONNECT, REMOTE_DISCONNECT,
        // REFUSED, INVALID, ABORTED.
        0xC000020C, 0xC000020D, 0xC000013B, 0xC000013C, 0xC0000236, 0xC000023A, 0xC0000241 => true,
        else => false,
    };
}

fn afdAcceptPeer(out: []const u8) ?WindowsTcpEndpoint {
    // AFD_LISTEN_RESPONSE_INFO_TL starts with a sequence (four bytes) and a
    // native sockaddr. The peer bytes are authoritative even when Winsock's
    // getpeername on the adopted socket reports an empty sockaddr.
    if (out.len < 4 + @sizeOf(RioSockAddr)) return null;
    const family = std.mem.readInt(u16, out[4..6], .native);
    const port = std.mem.readInt(u16, out[6..8], .big);
    if (port == 0) return null;
    if (family == wsa_af_inet) return .{ .address = .{ .ipv4 = out[8..12].* }, .port = port };
    if (family == wsa_af_inet6 and out.len >= 4 + @sizeOf(RioSockAddr6))
        return .{ .address = .{ .ipv6 = out[12..28].* }, .port = port };
    return null;
}

test "AFD accept peer keeps the exact TCP port for Windows Helix joins" {
    var v4: [4 + @sizeOf(RioSockAddr)]u8 = @splat(0);
    std.mem.writeInt(u16, v4[4..6], wsa_af_inet, .native);
    std.mem.writeInt(u16, v4[6..8], 49152, .big);
    @memcpy(v4[8..12], &[_]u8{ 127, 0, 0, 1 });
    const peer = afdAcceptPeer(&v4) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 49152), peer.port);
    try std.testing.expectEqualDeep(PeerAddress{ .ipv4 = .{ 127, 0, 0, 1 } }, peer.address);
    std.mem.writeInt(u16, v4[6..8], 0, .big);
    try std.testing.expect(afdAcceptPeer(&v4) == null);
}

/// Move the connection named by the wait-for-listen sequence onto a new
/// overlapped socket. The first four bytes of `out` are that sequence.
fn acceptSequence(listener: usize, out: []const u8) error{SocketFailed}!i32 {
    const w = std.os.windows;
    if (out.len < 4) return error.SocketFailed;
    const sequence = std.mem.readInt(i32, out[0..4], .little);
    const peer = afdAcceptPeer(out) orelse return error.SocketFailed;
    const listener_name = try socketName(listener);
    const sock = WSASocketW(@intCast(listener_name.family), wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (sock == std.math.maxInt(usize)) return error.SocketFailed;
    errdefer _ = closesocket(sock);
    var event: w.HANDLE = undefined;
    if (w.ntdll.NtCreateEvent(&event, w.ACCESS_MASK.Specific.Event.ALL_ACCESS, null, .Synchronization, .FALSE) != .SUCCESS)
        return error.SocketFailed;
    defer _ = w.ntdll.NtClose(event);
    const info = AfdAcceptInfo{
        .san_active = 0,
        .sequence = sequence,
        .accept_handle = sock,
    };
    var iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
    const code: w.CTL_CODE = @bitCast(Iocp.ioctl_afd_accept);
    const status = w.ntdll.NtDeviceIoControlFile(
        @ptrFromInt(listener),
        event,
        null,
        null,
        &iosb,
        code,
        &info,
        @sizeOf(AfdAcceptInfo),
        null,
        0,
    );
    if (status == .PENDING) {
        // AFD may finish adoption asynchronously. Keep the input, IOSB and
        // socket alive until it signals completion; a pending request must
        // never write back into a returned stack frame.
        const wait_limit: w.LARGE_INTEGER = -50_000_000; // five seconds in 100 ns units
        const first_wait = w.ntdll.NtWaitForSingleObject(event, .FALSE, &wait_limit);
        if (first_wait == .TIMEOUT) {
            // The wait-for-listen sequence is no longer allowed to stall the
            // reactor forever. Cancel this exact IOSB and retain every stack
            // input until the event confirms the kernel stopped using it.
            var cancel_iosb = std.mem.zeroes(w.IO_STATUS_BLOCK);
            const canceled = NtCancelIoFileEx(@ptrFromInt(listener), &iosb, &cancel_iosb);
            if (canceled == .PENDING) @panic("pending AFD accept cancellation could not be drained");
            if (canceled != .SUCCESS and canceled != .NOT_FOUND)
                @panic("pending AFD accept cancellation failed");
            if (w.ntdll.NtWaitForSingleObject(event, .FALSE, &wait_limit) != .SUCCESS)
                @panic("pending AFD accept could not be drained after cancellation");
        } else if (first_wait != .SUCCESS) {
            @panic("pending AFD accept wait failed");
        }
    } else if (status != .SUCCESS) {
        std.debug.print("GAP-X1 windows afd accept status=0x{x} seq={d}\n", .{ @intFromEnum(status), sequence });
        return error.SocketFailed;
    }
    if (iosb.u.Status != .SUCCESS) return error.SocketFailed;
    // AFD adoption, like AcceptEx, must copy the listener's Winsock context
    // before shutdown/getpeername/getsockopt may operate on the new socket.
    if (setsockopt(sock, sol_socket, so_update_accept_context, &listener, @sizeOf(usize)) != 0) {
        std.debug.print("windows AFD accept context failed: WSA {d}\n", .{WSAGetLastError()});
        return error.SocketFailed;
    }
    return windows_sockets.registerWithPeer(sock, peer) catch {
        return error.SocketFailed;
    };
}

/// One `accept` on a blocking listener. Off Windows this is `SocketFailed`
/// and does not call the host `accept`.
pub fn pullAccept(fd: linux.fd_t) error{ WouldBlock, SocketFailed }!linux.fd_t {
    if (comptime builtin.os.tag != .windows) return error.SocketFailed;
    return acceptOne(windows_sockets.get(fd) orelse return error.SocketFailed);
}

extern "kernel32" fn Sleep(milliseconds: u32) callconv(.winapi) void;
extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
extern "kernel32" fn SetFileCompletionNotificationModes(file: std.os.windows.HANDLE, flags: u8) callconv(.winapi) i32;

fn rioPtr(comptime T: type, ptr: RioFn) ?T {
    const raw = ptr orelse return null;
    return @as(T, @ptrFromInt(@intFromPtr(raw)));
}

fn socketLive(socket: usize) bool {
    return socket != std.math.maxInt(usize);
}

fn rioCloseCq(table: *const RioTable, cq: *anyopaque) void {
    const Func = *const fn (*anyopaque) callconv(.winapi) void;
    const func = rioPtr(Func, table.close_completion_queue) orelse return;
    func(cq);
}

fn rioDeregister(table: *const RioTable, buffer_id: usize) void {
    const Func = *const fn (usize) callconv(.winapi) void;
    const func = rioPtr(Func, table.deregister_buffer) orelse return;
    func(buffer_id);
}

/// `SOL_SOCKET` and `SO_RCVTIMEO`. Winsock takes milliseconds in a `DWORD`.
const sol_socket: i32 = 0xFFFF;
const so_update_accept_context: i32 = 0x700B;
const so_update_connect_context: i32 = 0x7010;
const so_rcvtimeo: i32 = 0x1006;

/// Windows `fd_set` is a count plus sockets, not a POSIX bitmask.
/// `long` in `timeval` is 32 bits on x64 Windows.
const RioFdSet = extern struct {
    count: u32,
    pad: u32 = 0,
    array: [64]usize = @splat(0),
};

const RioTimeval = extern struct {
    sec: i32,
    usec: i32,
};

comptime {
    if (@sizeOf(usize) == 8 and @sizeOf(RioFdSet) != 520) @compileError("WINSOCK fd_set is 520 bytes");
    if (@sizeOf(RioTimeval) != 8) @compileError("WINSOCK timeval is 8 bytes");
}

const RioConnect = struct {
    socket: usize,
    addr: RioSockAddr,
    len: i32,
    rc: i32 = 1,
    err: i32 = 0,
};

fn rioConnect(job: *RioConnect) void {
    job.rc = connect(job.socket, &job.addr, job.len);
    if (job.rc != 0) job.err = WSAGetLastError();
}

/// Calls the table `Iocp.open` already loaded. The listening socket is a
/// normal overlapped socket. The client is `WSA_FLAG_REGISTERED_IO`. A
/// registered socket rejects `FIONBIO` (`WSAEOPNOTSUPP`), so `connect` runs
/// on a second thread and `select` waits on the listener. One `RIOSend` of
/// `RIO!` is dequeued, then the accepted socket must read those four bytes.
/// A null pointer, a refused call, an empty queue, or a peer mismatch
/// returns a witness with `ok` false and does not invent a count.
fn dequeueLoadedRio(table: *const RioTable) RioWitness {
    const invalid = std.math.maxInt(usize);
    var listener: usize = invalid;
    var client: usize = invalid;
    var accepted: usize = invalid;
    var cq: ?*anyopaque = null;
    var buffer_id: usize = 0;
    const payload = std.heap.page_allocator.alloc(u8, rio_payload.len) catch {
        return .{ .stage = "memory" };
    };
    defer std.heap.page_allocator.free(payload);
    defer {
        if (socketLive(client)) _ = closesocket(client);
        if (cq) |queue| rioCloseCq(table, queue);
        if (buffer_id != 0 and buffer_id != rio_invalid_buffer_id) rioDeregister(table, buffer_id);
        if (socketLive(accepted)) _ = closesocket(accepted);
        if (socketLive(listener)) _ = closesocket(listener);
    }
    @memcpy(payload, rio_payload);

    listener = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (!socketLive(listener)) return .{ .stage = "socket", .errno = WSAGetLastError() };
    var addr = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = @splat(0),
    };
    if (bind(listener, &addr, @sizeOf(RioSockAddr)) != 0) return .{ .stage = "bind", .errno = WSAGetLastError() };
    if (listen(listener, 1) != 0) return .{ .stage = "listen", .errno = WSAGetLastError() };
    var name_len: i32 = @sizeOf(RioSockAddr);
    if (getsockname(listener, &addr, &name_len) != 0) return .{ .stage = "name", .errno = WSAGetLastError() };

    client = WSASocketW(
        wsa_af_inet,
        wsa_sock_stream,
        wsa_ipproto_tcp,
        null,
        0,
        wsa_flag_overlapped | wsa_flag_registered_io,
    );
    if (!socketLive(client)) return .{ .stage = "client", .errno = WSAGetLastError() };
    var job = RioConnect{ .socket = client, .addr = addr, .len = name_len };
    var connector: ?std.Thread = null;
    defer if (connector) |thread| thread.join();
    connector = std.Thread.spawn(.{}, rioConnect, .{&job}) catch return .{ .stage = "thread" };

    var ready = RioFdSet{ .count = 1 };
    ready.array[0] = listener;
    var wait = RioTimeval{ .sec = 2, .usec = 0 };
    const selected = select(0, &ready, null, null, &wait);
    if (selected <= 0) {
        const err = if (selected < 0) WSAGetLastError() else job.err;
        if (socketLive(client)) {
            _ = closesocket(client);
            client = std.math.maxInt(usize);
        }
        return .{ .stage = "select", .errno = err };
    }
    accepted = accept(listener, null, null);
    if (!socketLive(accepted)) return .{ .stage = "accept", .errno = WSAGetLastError() };
    var timeout_ms: i32 = 2000;
    _ = setsockopt(accepted, sol_socket, so_rcvtimeo, &timeout_ms, @sizeOf(i32));

    const CreateCq = *const fn (u32, ?*anyopaque) callconv(.winapi) ?*anyopaque;
    const create_cq = rioPtr(CreateCq, table.create_completion_queue) orelse return .{ .stage = "table" };
    cq = create_cq(32, null);
    const queue = cq orelse return .{ .stage = "cq", .errno = WSAGetLastError() };

    const CreateRq = *const fn (usize, u32, u32, u32, u32, *anyopaque, *anyopaque, ?*anyopaque) callconv(.winapi) ?*anyopaque;
    const create_rq = rioPtr(CreateRq, table.create_request_queue) orelse return .{ .stage = "table" };
    const rq = create_rq(client, 1, 1, 1, 1, queue, queue, @ptrFromInt(0x22115249)) orelse {
        return .{ .stage = "rq", .errno = WSAGetLastError() };
    };

    const Register = *const fn ([*]u8, u32) callconv(.winapi) usize;
    const register = rioPtr(Register, table.register_buffer) orelse return .{ .stage = "table" };
    buffer_id = register(payload.ptr, @intCast(payload.len));
    if (buffer_id == 0 or buffer_id == rio_invalid_buffer_id) {
        return .{ .stage = "register", .errno = WSAGetLastError() };
    }

    var rio_buf = RioBuf{
        .buffer_id = buffer_id,
        .offset = 0,
        .length = @intCast(payload.len),
    };
    const Send = *const fn (*anyopaque, *RioBuf, u32, u32, ?*anyopaque) callconv(.winapi) i32;
    const rio_send = rioPtr(Send, table.send) orelse return .{ .stage = "table" };
    if (rio_send(rq, &rio_buf, 1, 0, @ptrFromInt(@as(usize, rio_request_context))) == 0) {
        return .{ .stage = "send", .errno = WSAGetLastError() };
    }

    const Dequeue = *const fn (*anyopaque, [*]RioResult, u32) callconv(.winapi) u32;
    const dequeue = rioPtr(Dequeue, table.dequeue_completion) orelse return .{ .stage = "table" };
    var results: [4]RioResult = @splat(.{});
    var count: u32 = 0;
    var polls: u32 = 0;
    while (polls < 200) : (polls += 1) {
        count = dequeue(queue, &results, results.len);
        if (count == rio_corrupt_cq) return .{ .stage = "corrupt", .errno = WSAGetLastError() };
        if (count != 0) break;
        Sleep(10);
    }
    if (count == 0 or count > results.len) {
        return .{ .stage = "empty", .count = count, .errno = 0 };
    }

    var found = false;
    var got = RioResult{};
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        if (results[index].request_context == rio_request_context) {
            got = results[index];
            found = true;
            break;
        }
    }
    if (!found) {
        return .{
            .stage = "context",
            .count = count,
            .status = results[0].status,
            .bytes = results[0].bytes,
            .errno = 0,
        };
    }
    if (got.status != 0) {
        return .{ .stage = "status", .count = count, .status = got.status, .bytes = got.bytes, .errno = 0 };
    }
    if (got.bytes != rio_payload.len) {
        return .{ .stage = "short", .count = count, .status = got.status, .bytes = got.bytes, .errno = 0 };
    }

    var peer: [4]u8 = @splat(0);
    const n = recv(accepted, &peer, @intCast(peer.len), 0);
    if (n != @as(i32, rio_payload.len) or !std.mem.eql(u8, peer[0..rio_payload.len], rio_payload)) {
        return .{
            .stage = "peer",
            .count = count,
            .status = got.status,
            .bytes = if (n > 0) @intCast(n) else 0,
            .errno = WSAGetLastError(),
        };
    }
    return .{
        .ok = true,
        .stage = "dequeued",
        .count = count,
        .status = got.status,
        .bytes = got.bytes,
        .errno = 0,
    };
}

fn ipv4Bits(host: []const u8) ListenError!u32 {
    if (host.len == 0 or std.mem.eql(u8, host, "0.0.0.0")) return 0;
    const parsed = std.Io.net.Ip4Address.parse(host, 0) catch return error.InvalidAddress;
    return @bitCast(parsed.bytes);
}

/// Bind an IPv4 TCP listener. `port` 0 asks the kernel for an ephemeral port.
/// The returned fd is close-on-exec. BSD listeners are nonblocking so a second
/// `accept` cannot stall the reap loop. The Linux ring path stays blocking;
/// io_uring waits, and userspace does not call `accept` again.
pub fn listenTcp(host: []const u8, port: u16) ListenError!Listener {
    if (comptime builtin.os.tag == .linux) return listenLinux(host, port);
    if (comptime builtin.os.tag == .windows) return listenWindows(host, port);
    if (comptime kqueueOs()) return listenBsd(host, port);
    return error.Unsupported;
}

/// Flush small IRC lines. `TCP_NODELAY` is 1 and `IPPROTO_TCP` is 6 on Linux,
/// FreeBSD, OpenBSD, and Windows. Best-effort: a refused option leaves the
/// kernel default in place.
pub fn setTcpNoDelay(fd: linux.fd_t) void {
    if (fd < 0) return;
    const on: i32 = 1;
    if (comptime builtin.os.tag == .linux) {
        _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&on), @sizeOf(i32));
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        const socket = windows_sockets.get(fd) orelse return;
        _ = setsockopt(socket, 6, 1, &on, @intCast(@sizeOf(i32)));
        return;
    }
    if (comptime kqueueOs()) {
        _ = std.c.setsockopt(fd, 6, 1, &on, @sizeOf(i32));
    }
}

pub fn closeSocket(fd: linux.fd_t) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .linux) {
        _ = linux.close(fd);
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        if (windows_sockets.take(fd)) |socket| _ = closesocket(socket);
        return;
    }
    if (comptime kqueueOs()) _ = std.c.close(fd);
}

/// Best-effort TCP FIN after the final queued send has completed. The caller
/// must keep receiving or otherwise drain outstanding I/O before closing the
/// socket; closing with unread data may still reset the peer's connection.
pub fn shutdownSocketWrite(fd: linux.fd_t) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .windows) {
        const socket = windows_sockets.get(fd) orelse return;
        if (shutdown(socket, 1) != 0) // SD_SEND
            std.debug.print("windows TCP write shutdown failed: WSA {d}\n", .{WSAGetLastError()});
    }
}

/// Interrupt both TCP directions while retaining the opaque descriptor until
/// every overlapped completion has retired. Callers must still cancel exact
/// recv/send/connect requests and drain their completions before freeing the
/// buffers those requests reference.
pub fn shutdownSocketBoth(fd: linux.fd_t) void {
    if (fd < 0) return;
    if (comptime builtin.os.tag == .windows) {
        const socket = windows_sockets.get(fd) orelse return;
        _ = shutdown(socket, 2); // SD_BOTH
    }
}

fn listenLinux(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    const rc = linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    const fd: linux.fd_t = switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.SocketUnavailable,
    };
    errdefer _ = linux.close(fd);
    var yes: i32 = 1;
    _ = linux.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(i32));
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
    };
    switch (std.posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.SocketUnavailable,
    }
    switch (std.posix.errno(linux.listen(fd, 128))) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        else => return error.SocketUnavailable,
    }
    var storage: linux.sockaddr.storage = undefined;
    var slen: std.posix.socklen_t = @sizeOf(linux.sockaddr.storage);
    if (std.posix.errno(linux.getsockname(fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SocketUnavailable;
    const bound: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

fn listenBsd(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) return error.SocketUnavailable;
    errdefer _ = std.c.close(fd);
    var yes: i32 = 1;
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &yes, @sizeOf(i32));
    var addr = std.c.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
    };
    const addr_ptr: *std.c.sockaddr = @ptrCast(&addr);
    if (std.c.bind(fd, addr_ptr, @intCast(@sizeOf(std.c.sockaddr.in))) != 0) return bsdListenError();
    if (std.c.listen(fd, 128) != 0) return bsdListenError();
    if (std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) < 0) return error.SocketUnavailable;
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(i32, 0));
    if (flags < 0) return error.SocketUnavailable;
    if (std.c.fcntl(fd, std.c.F.SETFL, flags | @as(@TypeOf(flags), 4)) < 0) return error.SocketUnavailable;
    var len: std.c.socklen_t = @intCast(@sizeOf(std.c.sockaddr.in));
    if (std.c.getsockname(fd, addr_ptr, &len) != 0) return error.SocketUnavailable;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

fn bsdListenError() ListenError {
    const err = std.c._errno().*;
    if (err == 48 or err == 98) return error.AddressInUse;
    if (err == 1 or err == 13) return error.PermissionDenied;
    return error.SocketUnavailable;
}

fn listenWindows(host: []const u8, port: u16) ListenError!Listener {
    const ip = try ipv4Bits(host);
    try ensureWinsock();
    const sock = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    if (sock == std.math.maxInt(usize)) return error.SocketUnavailable;
    errdefer _ = closesocket(sock);
    const exclusive: i32 = 1;
    if (setsockopt(sock, sol_socket, ~@as(i32, 0x0004), &exclusive, @sizeOf(i32)) != 0)
        return windowsListenError();
    var addr = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
        .zero = @splat(0),
    };
    if (bind(sock, &addr, @sizeOf(RioSockAddr)) != 0) return windowsListenError();
    if (listen(sock, 128) != 0) return windowsListenError();
    var name_len: i32 = @sizeOf(RioSockAddr);
    if (getsockname(sock, &addr, &name_len) != 0) return error.SocketUnavailable;
    const fd = windows_sockets.register(sock) catch return error.SocketUnavailable;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port) };
}

fn windowsListenError() ListenError {
    const err = WSAGetLastError();
    if (err == 10048) return error.AddressInUse;
    if (err == 10013) return error.PermissionDenied;
    return error.SocketUnavailable;
}

test "Windows IO backend listener rejects a reuse-address competing bind" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const competitor = WSASocketW(wsa_af_inet, wsa_sock_stream, wsa_ipproto_tcp, null, 0, wsa_flag_overlapped);
    try std.testing.expect(competitor != std.math.maxInt(usize));
    defer _ = closesocket(competitor);
    const reuse: i32 = 1;
    try std.testing.expectEqual(@as(i32, 0), setsockopt(competitor, sol_socket, 0x0004, &reuse, @sizeOf(i32)));
    var address = RioSockAddr{
        .family = @intCast(wsa_af_inet),
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = try ipv4Bits("127.0.0.1"),
        .zero = @splat(0),
    };
    try std.testing.expect(bind(competitor, &address, @sizeOf(RioSockAddr)) != 0);
}

fn posixSocket() !linux.fd_t {
    const rc = linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.SocketUnavailable,
    }
}

test "GAP-X1 IoBackend queues accept recv send poll cancel and timeout on the linux ring and iocp and kqueue fail closed" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const token = ringlane.FdToken{ .slot = 7, .gen = 3 };
    var live = try IoBackend.openOwned(.ringlane, 32, .{});
    defer live.deinit();
    try live.requireAll();
    try std.testing.expect(!live.features.sqpoll);
    try std.testing.expect(!live.features.defer_taskrun);
    for (required_ops) |op| try std.testing.expect(live.opImplemented(op));

    const fd = try posixSocket();
    defer _ = linux.close(fd);
    var buf: [4]u8 = .{ 0, 0, 0, 0 };
    try live.accept(token, fd);
    try live.recv(token, fd, &buf);
    try live.send(token, fd, "x");
    try live.poll(token, fd, linux.POLL.IN);
    var ts = linux.kernel_timespec{ .sec = 60, .nsec = 0 };
    try live.timeout(token, &ts);
    try live.cancel(.accept, token);
    const queued = live.ringPtr() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 6), queued.inner.sq_ready());
    try std.testing.expect(try live.submit() >= 1);

    var moved = try openLinuxRing(32, .{});
    defer moved.deinit();
    try std.testing.expect(!moved.features.sqpoll);
    try std.testing.expect(!moved.features.defer_taskrun);
    try submitAccept(&moved, token, fd);
    try submitRecv(&moved, token, fd, &buf);
    try submitSend(&moved, token, fd, "x");
    try submitPoll(&moved, token, fd, linux.POLL.IN);
    try submitTimeout(&moved, token, &ts);
    try submitCancel(&moved, .accept, token);
    try std.testing.expectEqual(@as(u32, 6), moved.inner.sq_ready());
    try std.testing.expect(try moved.submit() >= 1);

    const allocator = std.testing.allocator;
    const encoded = try capsule.encode(allocator, capsule.make(.monitor_list, &.{}));
    defer allocator.free(encoded);
    {
        var decoded = try capsule.decode(allocator, encoded);
        defer decoded.deinit(allocator);
        try std.testing.expectEqual(capsule.CapsuleKind.monitor_list, decoded.header.kind);
    }

    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.iocp, 32, .{}));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.kqueue, 32, .{}));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.kqueue, 0, .{}));

    var closed_kq = IoBackend.closed(.kqueue, 32);
    defer closed_kq.deinit();
    try std.testing.expectError(error.MissingOp, closed_kq.requireAll());
    for (required_ops) |op| try std.testing.expect(!closed_kq.opImplemented(op));
    try std.testing.expectError(error.MissingOp, closed_kq.accept(token, fd));
    try std.testing.expectError(error.MissingOp, closed_kq.recv(token, fd, &buf));
    try std.testing.expectError(error.MissingOp, closed_kq.send(token, fd, "x"));
    try std.testing.expectError(error.MissingOp, closed_kq.poll(token, fd, linux.POLL.IN));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.recv, token));
    try std.testing.expectError(error.MissingOp, closed_kq.timeout(token, &ts));
    const token_key = (@as(usize, token.gen) << 32) | @as(usize, token.slot);
    const fd_ident: usize = @intCast(fd);
    const described = [_]struct { filter: i16, flags: u16, ident: usize, data: i64 }{
        .{ .filter = -1, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -2, .flags = 0x0005, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0015, .ident = fd_ident, .data = 0 },
        .{ .filter = -1, .flags = 0x0002, .ident = fd_ident, .data = 0 },
        .{ .filter = -7, .flags = 0x0011, .ident = token_key, .data = 60_000 },
    };
    for (described, 0..) |want, index| {
        const got = try closed_kq.describedChange(index);
        try std.testing.expectEqual(want.filter, got.filter);
        try std.testing.expectEqual(want.flags, got.flags);
        try std.testing.expectEqual(want.ident, got.ident);
        try std.testing.expectEqual(want.data, got.data);
    }
    try std.testing.expectEqual(@as(u16, 0x0001 | 0x0004), (try closed_kq.describedChange(0)).flags);
    try std.testing.expectEqual(@as(u16, 0x0001 | 0x0010), (try closed_kq.describedChange(5)).flags);
    const queued_n = closed_kq.kq.?.n;
    try std.testing.expectError(error.MissingOp, closed_kq.poll(token, fd, 0));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.other, token));
    try std.testing.expectError(error.MissingOp, closed_kq.cancel(.poll, token));
    try std.testing.expectEqual(queued_n, closed_kq.kq.?.n);
    try std.testing.expectError(error.MissingOp, closed_kq.submit());
    try std.testing.expectEqual(queued_n, closed_kq.kq.?.n);
    try std.testing.expectError(error.Usr2Refused, closed_kq.refuseCapsule(allocator, encoded));

    var one = IoBackend.closed(.kqueue, 1);
    defer one.deinit();
    try std.testing.expectError(error.MissingOp, one.accept(token, fd));
    try std.testing.expectEqual(@as(u16, 1), one.kq.?.n);
    try std.testing.expectError(error.MissingOp, one.recv(token, fd, &buf));
    try std.testing.expectEqual(@as(u16, 1), one.kq.?.n);
    try std.testing.expectError(error.MissingOp, one.describedChange(1));

    var bad_ts = linux.kernel_timespec{ .sec = -1, .nsec = 0 };
    const before_bad = closed_kq.kq.?.n;
    try std.testing.expectError(error.MissingOp, closed_kq.timeout(token, &bad_ts));
    try std.testing.expectEqual(before_bad, closed_kq.kq.?.n);
    try std.testing.expectError(error.MissingOp, closed_kq.accept(token, -1));
    try std.testing.expectEqual(before_bad, closed_kq.kq.?.n);

    var closed_iocp = IoBackend.closed(.iocp, 32);
    defer closed_iocp.deinit();
    try std.testing.expectError(error.MissingOp, closed_iocp.requireAll());
    for (required_ops) |op| try std.testing.expect(!closed_iocp.opImplemented(op));
    try std.testing.expectEqual(Iocp.ioctl_afd_wait_for_listen, @as(u32, 0x1200c));
    try std.testing.expectEqual(Iocp.ioctl_afd_accept, @as(u32, 0x12010));
    try std.testing.expectEqual(Iocp.ioctl_afd_receive, @as(u32, 0x12017));
    try std.testing.expectEqual(Iocp.ioctl_afd_send, @as(u32, 0x1201f));
    try std.testing.expectEqual(Iocp.ioctl_afd_poll, @as(u32, 0x12024));
    var send_bytes = [_]u8{'x'};
    try std.testing.expectError(error.MissingOp, closed_iocp.accept(token, fd));
    try std.testing.expectError(error.MissingOp, closed_iocp.recv(token, fd, &buf));
    try std.testing.expectError(error.MissingOp, closed_iocp.send(token, fd, &send_bytes));
    try std.testing.expectError(error.MissingOp, closed_iocp.poll(token, fd, linux.POLL.IN));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.recv, token));
    try std.testing.expectError(error.MissingOp, closed_iocp.timeout(token, &ts));
    const iocp_packets = [_]Iocp.Packet{
        .{ .op = Iocp.op_accept, .handle = fd_ident, .token = token_key, .ioctl = Iocp.ioctl_afd_wait_for_listen },
        .{ .op = Iocp.op_recv, .handle = fd_ident, .length = buf.len, .token = token_key, .buf = @intFromPtr(&buf), .ioctl = Iocp.ioctl_afd_receive },
        .{ .op = Iocp.op_send, .handle = fd_ident, .length = 1, .token = token_key, .buf = @intFromPtr(&send_bytes), .ioctl = Iocp.ioctl_afd_send },
        .{ .op = Iocp.op_poll, .handle = fd_ident, .length = linux.POLL.IN, .token = token_key, .ioctl = Iocp.ioctl_afd_poll },
        .{ .op = Iocp.op_cancel, .handle = fd_ident, .length = Iocp.op_recv, .token = token_key },
        .{ .op = Iocp.op_timeout, .length = 60_000, .token = token_key },
    };
    for (iocp_packets, 0..) |want, index| {
        const got = try closed_iocp.describedPacket(index);
        try std.testing.expectEqual(want.op, got.op);
        try std.testing.expectEqual(want.handle, got.handle);
        try std.testing.expectEqual(want.length, got.length);
        try std.testing.expectEqual(want.token, got.token);
        try std.testing.expectEqual(want.ioctl, got.ioctl);
        try std.testing.expectEqual(want.buf, got.buf);
    }
    const iocp_n = closed_iocp.iocp.?.n;
    try std.testing.expectError(error.MissingOp, closed_iocp.poll(token, fd, 0));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.other, token));
    try std.testing.expectError(error.MissingOp, closed_iocp.cancel(.poll, token));
    try std.testing.expectEqual(iocp_n, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, closed_iocp.submit());
    try std.testing.expectEqual(iocp_n, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.Usr2Refused, closed_iocp.refuseCapsule(allocator, encoded));

    var one_iocp = IoBackend.closed(.iocp, 1);
    defer one_iocp.deinit();
    try std.testing.expectError(error.MissingOp, one_iocp.accept(token, fd));
    try std.testing.expectEqual(@as(u16, 1), one_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, one_iocp.recv(token, fd, &buf));
    try std.testing.expectEqual(@as(u16, 1), one_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, one_iocp.describedPacket(1));
    const before_iocp_bad = closed_iocp.iocp.?.n;
    try std.testing.expectError(error.MissingOp, closed_iocp.timeout(token, &bad_ts));
    try std.testing.expectEqual(before_iocp_bad, closed_iocp.iocp.?.n);
    try std.testing.expectError(error.MissingOp, closed_iocp.accept(token, -1));
    try std.testing.expectEqual(before_iocp_bad, closed_iocp.iocp.?.n);

    try std.testing.expectError(error.Usr2Refused, live.refuseCapsule(allocator, encoded));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.freebsd, 32));
    try refusePortableReactor(.linux, live.entries);
    try std.testing.expectError(error.Unsupported, refuseForeignCapsule());
    if (comptime builtin.os.tag == .freebsd) try Kqueue.exerciseLive();
    if (comptime builtin.os.tag == .windows) try Iocp.exerciseLive();

    std.debug.print("GAP-X1 branch=linux ring queued six ops; this host did not execute kqueue or IOCP; closed kqueue describes FreeBSD filters; closed IOCP describes AFD wait-for-listen and AFD poll and returns MissingOp; portable init opens the native backend and refuses a missing op; USR2 capsule refused\n", .{});
}

test "kqueue: full change batch preserves the armed buffer and permits retry" {
    var queue = Kqueue.unopened(1);
    defer queue.deinit();
    const token = ringlane.FdToken{ .slot = 1, .gen = 3 };
    var first: [1]u8 = undefined;
    var second: [2]u8 = undefined;
    try std.testing.expectError(error.MissingOp, queue.enqueueRecv(token, 7, &first));
    const saved = queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.*;
    try std.testing.expectError(error.MissingOp, queue.enqueueRecv(token, 7, &second));
    try std.testing.expectEqual(saved, queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.*);
    try std.testing.expectEqual(@as(u16, 1), queue.n);
    queue.n = 0;
    try std.testing.expectError(error.MissingOp, queue.enqueueRecv(token, 7, &second));
    try std.testing.expectEqual(@intFromPtr(&second), queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.buf_ptr);
    // Two filters must fit before either half of a read/write poll is queued.
    queue.n = 0;
    try std.testing.expectError(error.MissingOp, queue.enqueuePoll(token, 7, linux.POLL.IN | linux.POLL.OUT));
    try std.testing.expectEqual(@as(u16, 0), queue.n);
    try std.testing.expectEqual(ringlane.OpKind.recv, queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.kind);
}

fn checkKqueuePollAllocationFailure(allocator: Allocator) !void {
    var queue = Kqueue.unopened(2);
    queue.allocator = allocator;
    // Enqueue only: no kernel call occurs, and cleanup never closes this
    // sentinel. This exercises register publication on every host.
    queue.fd = 99;
    defer {
        queue.fd = -1;
        queue.deinit();
    }
    const token = ringlane.FdToken{ .slot = 1, .gen = 3 };
    queue.enqueuePoll(token, 7, linux.POLL.IN | linux.POLL.OUT) catch |err| {
        try std.testing.expectEqual(@as(u16, 0), queue.n);
        try std.testing.expectEqual(@as(usize, 0), queue.regs.len);
        return err;
    };
    try std.testing.expectEqual(@as(u16, 2), queue.n);
    try std.testing.expectEqual(ringlane.OpKind.poll, queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.kind);
    try std.testing.expectEqual(ringlane.OpKind.poll, queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_write).?.kind);
}

test "kqueue: dual poll allocation failure is atomic" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkKqueuePollAllocationFailure, .{});
}

test "kqueue: colliding poll token cannot replace or cancel the original registration" {
    var queue = Kqueue.unopened(4);
    queue.allocator = std.testing.allocator;
    queue.fd = 99;
    defer {
        queue.fd = -1;
        queue.deinit();
    }
    const first = ringlane.FdToken{ .slot = 1, .gen = 3 };
    const second = ringlane.FdToken{ .slot = 2, .gen = 3 };
    try queue.enqueuePoll(first, 7, linux.POLL.IN);
    const saved = queue.findReg(Kqueue.packToken(first), Kqueue.evfilt_read).?.*;
    try std.testing.expectError(error.MissingOp, queue.enqueuePoll(first, 8, linux.POLL.IN | linux.POLL.OUT));
    try std.testing.expectError(error.MissingOp, queue.enqueueFilter(first, 8, Kqueue.evfilt_read, Kqueue.ev_add, 0, false, .poll, ""));
    try std.testing.expectError(error.MissingOp, queue.enqueuePoll(second, 7, linux.POLL.IN | linux.POLL.OUT));
    try std.testing.expectError(error.MissingOp, queue.enqueueCancel(.poll, second));
    try std.testing.expectEqual(@as(u16, 1), queue.n);
    try std.testing.expectEqual(saved, queue.findReg(Kqueue.packToken(first), Kqueue.evfilt_read).?.*);
    try std.testing.expect(queue.findReg(Kqueue.packToken(second), Kqueue.evfilt_read) == null);
    try std.testing.expect(queue.findReg(Kqueue.packToken(second), Kqueue.evfilt_write) == null);
    // Independent write readiness has its own native filter and remains valid.
    try queue.enqueuePoll(second, 7, linux.POLL.OUT);
    try std.testing.expectEqual(@as(u16, 2), queue.n);
    try queue.enqueueCancel(.poll, first);
    try std.testing.expect(queue.findReg(Kqueue.packToken(first), Kqueue.evfilt_read) == null);
    try std.testing.expect(queue.findReg(Kqueue.packToken(second), Kqueue.evfilt_write) != null);
}

fn awaitBsdEvent(backend: *IoBackend) !Reaped {
    var attempts: usize = 0;
    while (attempts < 10) : (attempts += 1) {
        var events: [1]Reaped = undefined;
        if (try backend.reap(&events, 100) == 1) return events[0];
    }
    return error.TestUnexpectedResult;
}

test "BSD kqueue: poll recv cancel and timeout preserve operation identities" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.kqueue, 32, .{});
    defer backend.deinit();
    try backend.requireAll();
    var pair: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &pair));
    defer closeSocket(pair[0]);
    defer closeSocket(pair[1]);
    const token = ringlane.FdToken{ .slot = 1, .gen = 3 };
    try backend.poll(token, pair[0], linux.POLL.IN | linux.POLL.OUT);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    const writable = try awaitBsdEvent(&backend);
    try std.testing.expectEqual(Op.poll, writable.op);
    try std.testing.expectEqual(token, writable.token);
    try std.testing.expectEqual(@as(i32, linux.POLL.OUT), writable.result);
    try std.testing.expectEqual(@as(isize, 1), std.c.send(pair[1], "x", 1, std.c.MSG.NOSIGNAL));
    try backend.poll(token, pair[0], linux.POLL.IN);
    const colliding = ringlane.FdToken{ .slot = 2, .gen = 3 };
    try std.testing.expectError(error.MissingOp, backend.poll(colliding, pair[0], linux.POLL.IN | linux.POLL.OUT));
    try std.testing.expectError(error.MissingOp, backend.cancel(.poll, colliding));
    _ = try backend.submit();
    const readable = try awaitBsdEvent(&backend);
    try std.testing.expectEqual(Op.poll, readable.op);
    try std.testing.expectEqual(token, readable.token);
    try std.testing.expectEqual(@as(i32, linux.POLL.IN), readable.result);
    // Readiness must not consume the byte or try to transfer a zero-length buffer.
    var buf: [4]u8 = undefined;
    try backend.recv(token, pair[0], &buf);
    _ = try backend.submit();
    const received = try awaitBsdEvent(&backend);
    try std.testing.expectEqual(Op.recv, received.op);
    try std.testing.expectEqual(@as(i32, 1), received.result);
    try std.testing.expectEqual(@as(u8, 'x'), buf[0]);
    try backend.cancel(.recv, token);
    _ = try backend.submit();
    try backend.poll(token, pair[0], linux.POLL.IN | linux.POLL.OUT);
    _ = try backend.submit();
    try backend.cancel(.poll, token);
    try std.testing.expectEqual(@as(u32, 2), try backend.submit());
    var no_events: [1]Reaped = undefined;
    try std.testing.expectEqual(@as(u32, 0), try backend.reap(&no_events, 0));
    try std.testing.expectError(error.MissingOp, backend.cancel(.poll, token));
    var ts = linux.kernel_timespec{ .sec = 0, .nsec = 1_000_000 };
    try backend.timeout(token, &ts);
    _ = try backend.submit();
    const expired = try awaitBsdEvent(&backend);
    try std.testing.expectEqual(Op.timeout, expired.op);
    try std.testing.expectEqual(token, expired.token);
    try std.testing.expect(backend.kq.?.findReg(Kqueue.packToken(token), Kqueue.evfilt_timer) == null);
    try std.testing.expectError(error.MissingOp, backend.cancel(.timeout, token));
    ts.sec = 10;
    try backend.timeout(token, &ts);
    _ = try backend.submit();
    try backend.cancel(.timeout, token);
    _ = try backend.submit();
    try std.testing.expectEqual(@as(u32, 0), try backend.reap(&no_events, 0));
}

const InterruptedWaitProbe = struct {
    var signals = std.atomic.Value(u32).init(0);

    fn onSignal(_: std.c.SIG) callconv(.c) void {
        _ = signals.fetchAdd(1, .monotonic);
    }

    fn child(control_fd: i32, data_fd: i32) !void {
        var action = std.mem.zeroes(std.c.Sigaction);
        action.handler.handler = onSignal;
        try std.testing.expectEqual(@as(c_int, 0), std.c.sigaction(.USR1, &action, null));
        const empty_mask = std.mem.zeroes(std.c.sigset_t);
        try std.testing.expectEqual(@as(c_int, 0), std.c.sigprocmask(std.c.SIG.SETMASK, &empty_mask, null));
        var queue = try Kqueue.open(8);
        defer queue.deinit();
        queue.stream_completions = true;
        const token = ringlane.FdToken{ .slot = 12, .gen = 31 };
        var byte = [_]u8{'?'};
        try queue.enqueueRecv(token, data_fd, &byte);
        _ = try queue.submit();
        try std.testing.expectEqual(@as(isize, 1), std.c.send(control_fd, "R", 1, std.c.MSG.NOSIGNAL));
        var start: std.c.timespec = undefined;
        var end: std.c.timespec = undefined;
        try std.testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &start));
        var events: [1]Reaped = undefined;
        try std.testing.expectEqual(@as(u32, 0), try queue.reap(&events, 2000));
        try std.testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &end));
        const elapsed = (end.sec - start.sec) * 1_000_000_000 + end.nsec - start.nsec;
        // A normal timeout is not evidence of EINTR handling.
        try std.testing.expect(signals.load(.monotonic) > 0 and elapsed < 1_000_000_000);
        const reg = queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@intFromPtr(&byte), reg.buf_ptr);
        try std.testing.expectEqual(@as(u8, '?'), byte[0]);
        try std.testing.expectEqual(@as(isize, 1), std.c.send(control_fd, "I", 1, std.c.MSG.NOSIGNAL));
        var received = false;
        for (0..20) |_| {
            if (try queue.reap(&events, 100) == 0) continue;
            try std.testing.expectEqual(Op.recv, events[0].op);
            try std.testing.expectEqual(token, events[0].token);
            try std.testing.expectEqual(@as(i32, 1), events[0].result);
            try std.testing.expectEqual(@as(u8, 'x'), byte[0]);
            received = true;
            break;
        }
        try std.testing.expect(received);
        try std.testing.expect(queue.findReg(Kqueue.packToken(token), Kqueue.evfilt_read) == null);
        try std.testing.expectEqual(@as(u32, 0), try queue.reap(&events, 0));
    }
};

test "BSD kqueue: interrupted wait preserves armed buffer and original completion" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    var control_pair: [2]std.c.fd_t = undefined;
    var data_pair: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &control_pair));
    defer for (control_pair) |fd| closeSocket(fd);
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &data_pair));
    defer for (data_pair) |fd| closeSocket(fd);
    const child = std.c.fork();
    try std.testing.expect(child >= 0);
    if (child == 0) {
        closeSocket(control_pair[0]);
        closeSocket(data_pair[0]);
        InterruptedWaitProbe.child(control_pair[1], data_pair[1]) catch |err| {
            std.debug.print("interrupted-wait child failed: {s}\n", .{@errorName(err)});
            std.c._exit(101);
        };
        std.c._exit(0);
    }
    var reaped = false;
    defer if (!reaped) {
        _ = std.c.kill(child, .KILL);
        var status: c_int = 0;
        while (std.c.waitpid(child, &status, 0) < 0 and std.c._errno().* == @intFromEnum(std.c.E.INTR)) {}
    };
    closeSocket(control_pair[1]);
    control_pair[1] = -1;
    closeSocket(data_pair[1]);
    data_pair[1] = -1;
    var poll = std.c.pollfd{ .fd = control_pair[0], .events = std.c.POLL.IN, .revents = 0 };
    try std.testing.expectEqual(@as(c_int, 1), std.c.poll(@ptrCast(&poll), 1, 2000));
    var marker: [1]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 1), std.c.recv(control_pair[0], &marker, 1, 0));
    try std.testing.expectEqual(@as(u8, 'R'), marker[0]);
    var interrupted = false;
    for (0..200) |_| {
        poll.revents = 0;
        const ready = std.c.poll(@ptrCast(&poll), 1, 5);
        try std.testing.expect(ready >= 0);
        if (ready != 0) {
            try std.testing.expectEqual(@as(isize, 1), std.c.recv(control_pair[0], &marker, 1, 0));
            try std.testing.expectEqual(@as(u8, 'I'), marker[0]);
            interrupted = true;
            break;
        }
        try std.testing.expectEqual(@as(c_int, 0), std.c.kill(child, .USR1));
    }
    try std.testing.expect(interrupted);
    try std.testing.expectEqual(@as(isize, 1), std.c.send(data_pair[0], "x", 1, std.c.MSG.NOSIGNAL));
    var status: c_int = 0;
    while (std.c.waitpid(child, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return error.TestUnexpectedResult;
    }
    reaped = true;
    const bits: u32 = @bitCast(status);
    try std.testing.expect(std.c.W.IFEXITED(bits));
    try std.testing.expectEqual(@as(u8, 0), std.c.W.EXITSTATUS(bits));
}

test "BSD kqueue: broken-peer send survives default SIGPIPE disposition" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    var pair: [2]std.c.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &pair));
    defer _ = std.c.close(pair[0]);
    // Close before fork so the child cannot accidentally retain a peer.
    try std.testing.expectEqual(@as(c_int, 0), std.c.close(pair[1]));
    const child = std.c.fork();
    try std.testing.expect(child >= 0);
    if (child == 0) {
        var action = std.mem.zeroes(std.c.Sigaction);
        action.handler.handler = std.c.SIG.DFL;
        if (std.c.sigaction(.PIPE, &action, null) != 0) std.c._exit(2);
        const empty_mask = std.mem.zeroes(std.c.sigset_t);
        if (std.c.sigprocmask(std.c.SIG.SETMASK, &empty_mask, null) != 0) std.c._exit(2);
        var byte = [_]u8{'x'};
        var reg = Kqueue.Reg{ .buf_ptr = @intFromPtr(&byte), .len = byte.len };
        const result = Kqueue.transfer(.send, @intCast(pair[0]), &reg);
        std.c._exit(if (result == -@as(i32, @intFromEnum(std.c.E.PIPE))) 0 else 3);
    }
    var status: c_int = 0;
    while (std.c.waitpid(child, &status, 0) < 0) {
        if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return error.TestUnexpectedResult;
    }
    const bits: u32 = @bitCast(status);
    try std.testing.expect(std.c.W.IFEXITED(bits));
    try std.testing.expectEqual(@as(u8, 0), std.c.W.EXITSTATUS(bits));
}

test "BSD kqueue: accepted socket is nonblocking and close-on-exec" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    var backend = try IoBackend.openOwned(.kqueue, 32, .{});
    defer backend.deinit();
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const client = try Kqueue.bsdStreamSocket();
    defer closeSocket(client);
    var addr = std.c.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listener.port),
        .addr = try ipv4Bits("127.0.0.1"),
    };
    try std.testing.expectEqual(@as(c_int, 0), std.c.connect(client, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)));
    const token = ringlane.FdToken{ .slot = 7, .gen = 3 };
    try backend.accept(token, listener.fd);
    try std.testing.expectEqual(@as(u32, 1), try backend.submit());
    var accepted: i32 = -1;
    defer closeSocket(accepted);
    var attempts: usize = 0;
    while (attempts < 10 and accepted < 0) : (attempts += 1) {
        var events: [1]Reaped = undefined;
        const n = try backend.reap(&events, 100);
        if (n == 0) continue;
        try std.testing.expectEqual(Op.accept, events[0].op);
        try std.testing.expectEqual(token, events[0].token);
        try std.testing.expect(events[0].result >= 0);
        accepted = events[0].result;
    }
    try std.testing.expect(accepted >= 0);
    const descriptor_flags = std.c.fcntl(accepted, std.c.F.GETFD, @as(c_int, 0));
    try std.testing.expect(descriptor_flags >= 0);
    try std.testing.expect(descriptor_flags & std.c.FD_CLOEXEC != 0);
    const file_flags = std.c.fcntl(accepted, std.c.F.GETFL, @as(c_int, 0));
    try std.testing.expect(file_flags >= 0);
    // O_NONBLOCK is 4 on every BSD served by this backend.
    try std.testing.expect(file_flags & 4 != 0);
}

test "GAP-X3 Windows RIO fails closed off Windows" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const ioc_inout: u32 = 0x80000000 | 0x40000000;
    const ioc_ws2: u32 = 0x08000000;
    try std.testing.expectEqual(ioc_inout | ioc_ws2 | 36, sio_get_multiple_rio);
    try std.testing.expectEqual(@as(u32, 0xC8000024), sio_get_multiple_rio);
    try std.testing.expectEqual(@as(u32, 0x01), wsa_flag_overlapped);
    try std.testing.expectEqual(@as(u32, 0x100), wsa_flag_registered_io);
    try std.testing.expectEqual(@as(u32, 0x101), wsa_flag_overlapped | wsa_flag_registered_io);
    try std.testing.expectEqual(@as(i32, 2), wsa_af_inet);
    try std.testing.expectEqual(@as(i32, 1), wsa_sock_stream);
    try std.testing.expectEqual(@as(i32, 6), wsa_ipproto_tcp);
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RioGuid));
    try std.testing.expectEqual(@as(usize, 112), @sizeOf(RioTable));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(RioBuf));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(RioResult));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), rio_corrupt_cq);
    var closed_rio = IoBackend.closed(.iocp, 32);
    defer closed_rio.deinit();
    const witness = closed_rio.dequeueRegistered();
    try std.testing.expect(!witness.ok);
    try std.testing.expectEqualStrings("off-windows", witness.stage);
    try std.testing.expectEqual(@as(u32, 0), witness.count);
    try std.testing.expectEqual(@as(u32, 0), witness.bytes);
    const guid_bytes = std.mem.asBytes(&rio_guid);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x81, 0xe0, 0x09, 0x85, 0xdd, 0x96, 0x05, 0x40,
        0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f,
    }, guid_bytes);

    const zero = RioTable{};
    try std.testing.expect(!rioTableUsable(&zero));
    const ptr: RioFn = @as(*anyopaque, @ptrFromInt(1));
    var full = RioTable{ .cb_size = @intCast(@sizeOf(RioTable)) };
    inline for (rio_fields) |name| @field(full, name) = ptr;
    try std.testing.expect(rioTableUsable(&full));
    inline for (rio_fields) |name| {
        const saved = @field(full, name);
        @field(full, name) = null;
        try std.testing.expect(!rioTableUsable(&full));
        @field(full, name) = saved;
    }
    try std.testing.expect(rioTableUsable(&full));
    full.cb_size = @intCast(@sizeOf(RioTable) - 1);
    try std.testing.expect(!rioTableUsable(&full));

    const unopened = Iocp.unopened(32);
    try std.testing.expectEqual(@as(usize, 0), unopened.port);
    try std.testing.expect(!rioTableUsable(&unopened.rio));
    try std.testing.expectError(error.MissingOp, Iocp.open(0));
    try std.testing.expectError(error.MissingOp, IoBackend.openOwned(.iocp, 32, .{}));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(0));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(std.math.maxInt(usize)));
    try std.testing.expectError(error.MissingOp, loadRegisteredIo(1));
    try std.testing.expectError(error.MissingOp, loadRioForDaemon());
    try std.testing.expectError(error.Unsupported, refusePortableReactor(.windows, 32));

    std.debug.print("GAP-X3 branch=windows RIO loads the function table with WSAIoctl SIO 0xC8000024 and GUID 8509e081-96dd-4005-b165-9e2ee8c79e3f on a WSA_FLAG_REGISTERED_IO socket during Iocp.open; dequeueRegistered calls that stored table; off Windows it returns stage off-windows before any pointer call; a null or short table is MissingOp and the port is closed; recv and send on the IOCP path are IOCTL_AFD_RECEIVE and IOCTL_AFD_SEND; this host did not execute WSAIoctl or RIODequeueCompletion; heading stays unmarked; whole-accept not claimed\n", .{});
}

test "kqueue: full-runtime canceled original is reserved before successful delete publication" {
    var kq = Kqueue.unopened(2);
    kq.fd = 123;
    kq.stream_completions = true;
    defer {
        kq.fd = -1;
        kq.deinit();
    }
    const token = ringlane.FdToken{ .slot = 7, .gen = 3 };
    var bytes: [1]u8 = undefined;
    try kq.enqueueRecv(token, 55, &bytes);
    try std.testing.expectEqual(Kqueue.ev_add | Kqueue.ev_enable | Kqueue.ev_oneshot, kq.changes[0].flags);
    try std.testing.expectError(error.MissingOp, kq.enqueueCancel(.send, token));
    try std.testing.expectEqual(@as(u16, 1), kq.n);
    try std.testing.expectError(error.MissingOp, kq.enqueueRecv(token, 55, &bytes));
    try std.testing.expectEqual(@intFromPtr(&bytes), kq.findReg(Kqueue.packToken(token), Kqueue.evfilt_read).?.buf_ptr);
    try kq.enqueueCancel(.recv, token);
    try std.testing.expectError(error.MissingOp, kq.enqueueCancel(.recv, token));
    try std.testing.expectEqual(@as(usize, 0), kq.pending_n);
    try std.testing.expectEqual(token, kq.changes[1].canceled.?.token);
    try std.testing.expectEqual(Op.recv, kq.changes[1].canceled.?.op);
    try std.testing.expectError(error.SubmissionQueueFull, kq.enqueueRecv(token, 55, &bytes));
    try std.testing.expect(kq.findReg(Kqueue.packToken(token), Kqueue.evfilt_read) != null);
}

test "BSD full reactor: connect accept exact cancel and refused connect preserve original outcomes" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    const reactor_backend = @import("reactor_backend.zig");
    var ring = try reactor_backend.Ring.init(16, .{});
    defer ring.deinit();
    const listener = try listenTcp("127.0.0.1", 0);
    defer closeSocket(listener.fd);
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    try std.testing.expect(fd >= 0);
    defer closeSocket(fd);
    var addr = std.mem.zeroes(std.c.sockaddr.in);
    addr.len = @sizeOf(std.c.sockaddr.in);
    addr.family = std.c.AF.INET;
    addr.port = std.mem.nativeToBig(u16, listener.port);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
    const accept_token = ringlane.FdToken{ .slot = 1, .gen = 1 };
    const connect_token = ringlane.FdToken{ .slot = 2, .gen = 1 };
    try ring.submitAccept(accept_token, listener.fd);
    var mapped = std.mem.zeroes(std.posix.sockaddr.in6);
    mapped.len = @sizeOf(@TypeOf(mapped));
    mapped.family = std.c.AF.INET6;
    mapped.port = addr.port;
    mapped.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
    try ring.submitConnect(connect_token, fd, @ptrCast(&mapped), @sizeOf(@TypeOf(mapped)));
    const Sink = struct {
        rows: [16]ringlane.Completion = undefined,
        n: usize = 0,
        pub fn onCompletion(self: *@This(), row: ringlane.Completion) void {
            std.debug.assert(self.n < self.rows.len);
            self.rows[self.n] = row;
            self.n += 1;
        }
    };
    var sink = Sink{};
    var scratch: [16]reactor_backend.CompletionBuffer = undefined;
    _ = try ring.submit();
    var accepted: i32 = -1;
    defer closeSocket(accepted);
    var connected = false;
    for (0..100) |_| {
        try ring.reapCompletions(&scratch, 0, &sink);
        for (sink.rows[0..sink.n]) |row| switch (row) {
            .accept => |ev| {
                try std.testing.expectEqual(accept_token, ev.token);
                try std.testing.expect(!ev.more);
                try std.testing.expect(ev.res >= 0);
                accepted = ev.res;
            },
            .connect => |ev| {
                try std.testing.expectEqual(connect_token, ev.token);
                try std.testing.expectEqual(@as(i32, 0), ev.res);
                connected = true;
            },
            else => return error.TestUnexpectedResult,
        };
        sink.n = 0;
        if (accepted >= 0 and connected) break;
        const pause = std.c.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = std.c.nanosleep(&pause, null);
    }
    try std.testing.expect(accepted >= 0 and connected);
    try std.testing.expect(std.c.fcntl(fd, @as(c_int, 1), @as(c_int, 0)) & 1 != 0);
    try std.testing.expect(std.c.fcntl(fd, @as(c_int, 3), @as(c_int, 0)) & 4 != 0);

    const recv_token = ringlane.FdToken{ .slot = 3, .gen = 7 };
    var bytes: [2]u8 = undefined;
    try ring.submitRecv(recv_token, accepted, &bytes);
    try std.testing.expectError(error.MissingOp, ring.submitRecv(recv_token, accepted, &bytes));
    _ = try ring.submit();
    try std.testing.expectError(error.MissingOp, ring.submitRecv(recv_token, accepted, &bytes));
    try std.testing.expectError(error.MissingOp, ring.submitExactCancel(.recv, .{ .slot = 3, .gen = 8 }));
    try ring.submitExactCancel(.recv, recv_token);
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.n);
    _ = try ring.submit();
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.n);
    try std.testing.expectEqual(recv_token, sink.rows[0].recv.token);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), sink.rows[0].recv.res);
    sink.n = 0;
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.n);

    // Canceling an accept publishes its original identity too; the listener
    // remains usable for the next generation after the completion was consumed.
    const next_accept = ringlane.FdToken{ .slot = 1, .gen = 2 };
    try ring.submitAccept(next_accept, listener.fd);
    try ring.submitExactCancel(.accept, next_accept);
    _ = try ring.submitAndWait(1);
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(next_accept, sink.rows[0].accept.token);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CANCELED)), sink.rows[0].accept.res);
    sink.n = 0;

    // A send is one-shot: after readiness consumes bytes, no checked delete
    // can discard its original outcome or retransmit the same buffer.
    const send_token = ringlane.FdToken{ .slot = 5, .gen = 1 };
    try ring.submitSend(send_token, fd, "ok");
    _ = try ring.submitAndWait(1);
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.n);
    try std.testing.expectEqual(send_token, sink.rows[0].send.token);
    try std.testing.expectEqual(@as(i32, 2), sink.rows[0].send.res);
    sink.n = 0;
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.n);
    var sent: [4]u8 = undefined;
    // A send CQE proves bytes were accepted by the local TCP stack; peer
    // delivery/read readiness can occur later, even for loopback TCP.
    var received: usize = 0;
    for (0..100) |_| {
        const rc = std.c.recv(accepted, sent[received..].ptr, sent.len - received, 0);
        if (rc > 0) {
            received += @intCast(rc);
            if (received >= 2) break;
        } else {
            try std.testing.expect(rc < 0);
            try std.testing.expectEqual(@as(i32, @intFromEnum(std.posix.E.AGAIN)), Kqueue.positiveErrno());
        }
        const pause = std.c.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = std.c.nanosleep(&pause, null);
    }
    try std.testing.expectEqual(@as(usize, 2), received);
    try std.testing.expectEqualStrings("ok", sent[0..2]);
    try std.testing.expectEqual(@as(isize, -1), std.c.recv(accepted, &sent, sent.len, 0));
    try std.testing.expectEqual(@as(i32, @intFromEnum(std.posix.E.AGAIN)), Kqueue.positiveErrno());

    const refused_listener = try listenTcp("127.0.0.1", 0);
    closeSocket(refused_listener.fd);
    const refused = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    try std.testing.expect(refused >= 0);
    defer closeSocket(refused);
    addr.port = std.mem.nativeToBig(u16, refused_listener.port);
    try ring.submitConnect(.{ .slot = 4, .gen = 1 }, refused, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    _ = try ring.submitAndWait(1);
    try ring.reapCompletions(&scratch, 0, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.n);
    try std.testing.expectEqual(-@as(i32, @intFromEnum(linux.E.CONNREFUSED)), sink.rows[0].connect.res);
}

test "BSD full reactor: mixed delete receipt failure closes queue before cancellation publication" {
    if (comptime !kqueueOs()) return error.SkipZigTest;
    var kq = try Kqueue.open(8);
    defer kq.deinit();
    kq.stream_completions = true;
    var pair: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &pair));
    defer closeSocket(pair[0]);
    defer closeSocket(pair[1]);
    var bytes: [1]u8 = undefined;
    const token = ringlane.FdToken{ .slot = 9, .gen = 4 };
    try kq.enqueueRecv(token, pair[0], &bytes);
    _ = try kq.submit();
    try kq.enqueueCancel(.recv, token);
    try kq.pushStored(.{ .ident = @intCast(pair[0]), .filter = -127, .flags = Kqueue.ev_add, .udata = 1 });
    try std.testing.expectError(error.BackendPoisoned, kq.submit());
    try std.testing.expectEqual(@as(i32, -1), kq.fd);
    try std.testing.expectEqual(@as(usize, 0), kq.pending_n);
    // The caller retains the original buffer until backend teardown. No
    // synthetic success escapes a partially applied kernel changelist.
    try std.testing.expect(kq.findReg(Kqueue.packToken(token), Kqueue.evfilt_read) != null);
    var rows: [4]Reaped = undefined;
    try std.testing.expectError(error.MissingOp, kq.reap(&rows, 0));
}
