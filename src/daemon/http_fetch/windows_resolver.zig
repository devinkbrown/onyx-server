// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows system DNS resolution and asynchronous callback custody.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const net = std.Io.net;
const Error = @import("contracts.zig").Error;
const HostFamilies = @import("contracts.zig").HostFamilies;
const win = @import("windows_abi.zig").win;

pub fn resolveHostFamiliesWindows(host: []const u8, timeout_ms: u31) Error!HostFamilies {
    if (comptime builtin.os.tag != .windows) return error.NoNameservers;
    if (timeout_ms == 0) return error.ResolveTimeout;
    if (host.len == 0 or host.len > 1024 or std.mem.indexOfScalar(u8, host, 0) != null) return error.HostNotFound;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, host) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HostNotFound,
    };
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) {
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    }
    const event = win.CreateEventW(null, 1, 0, null) orelse {
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    };
    const state = std.heap.page_allocator.create(WinResolveState) catch {
        _ = win.CloseHandle(event);
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.OutOfMemory;
    };
    state.* = .{
        .event = event,
        .name = wide,
        .family = 0,
        .port = 0,
        .both = true,
    };
    state.hints.family = 0;
    state.hints.socket_type = win.sock_stream;
    state.hints.protocol = win.ipproto_tcp;
    defer state.release();

    var cancel_handle: ?*anyopaque = null;
    const rc = win.GetAddrInfoExW(state.name.ptr, null, win.ns_dns, null, &state.hints, &state.result, null, &state.overlapped, winResolveCompleted, &cancel_handle);
    if (rc != win.io_pending) winResolveCompleted(@bitCast(rc), 0, &state.overlapped);
    const wait_ms: u32 = @min(timeout_ms, 2500);
    const waited = win.WaitForSingleObject(state.event, wait_ms);
    if (waited != win.wait_object_0) {
        if (cancel_handle != null) _ = win.GetAddrInfoExCancel(&cancel_handle);
        return if (waited == win.wait_timeout) error.ResolveTimeout else error.HostNotFound;
    }
    if (state.status.load(.acquire) != 0) return error.HostNotFound;
    var found = HostFamilies{ .v4 = state.v4, .v6 = state.v6 };
    if (found.v4 == null and found.v6 == null) {
        if (state.answer) |addr| switch (addr) {
            .ip4 => |a4| found.v4 = a4.bytes,
            .ip6 => |a6| found.v6 = a6.bytes,
        };
    }
    if (found.v4 == null and found.v6 == null) return error.HostNotFound;
    return found;
}

pub fn resolveHostWindows(host: []const u8, port: u16, timeout_ms: u31, want_v6: bool) Error!net.IpAddress {
    if (comptime builtin.os.tag != .windows) return error.NoNameservers;
    if (timeout_ms == 0) return error.ResolveTimeout;
    if (host.len == 0 or host.len > 1024 or std.mem.indexOfScalar(u8, host, 0) != null)
        return error.HostNotFound;
    const wide = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, host) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HostNotFound,
    };
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) {
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    }
    const event = win.CreateEventW(null, 1, 0, null) orelse {
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.SocketUnavailable;
    };
    const state = std.heap.page_allocator.create(WinResolveState) catch {
        _ = win.CloseHandle(event);
        _ = win.WSACleanup();
        std.heap.page_allocator.free(wide);
        return error.OutOfMemory;
    };
    state.* = .{
        .event = event,
        .name = wide,
        .family = if (want_v6) win.af_inet6 else win.af_inet,
        .port = port,
    };
    state.hints.family = state.family;
    state.hints.socket_type = win.sock_stream;
    state.hints.protocol = win.ipproto_tcp;
    defer state.release();

    // Callback owns one reference from the time the query is issued. On a
    // timeout, cancellation signals completion while some namespace providers
    // may continue internally; the caller can return without freeing storage
    // still reachable by Winsock. The callback frees the result and last ref.
    var cancel_handle: ?*anyopaque = null;
    const rc = win.GetAddrInfoExW(state.name.ptr, null, win.ns_dns, null, &state.hints, &state.result, null, &state.overlapped, winResolveCompleted, &cancel_handle);
    if (rc != win.io_pending) winResolveCompleted(@bitCast(rc), 0, &state.overlapped);

    const wait_ms: u32 = @min(timeout_ms, 2500);
    const waited = win.WaitForSingleObject(state.event, wait_ms);
    if (waited != win.wait_object_0) {
        if (cancel_handle != null) _ = win.GetAddrInfoExCancel(&cancel_handle);
        return if (waited == win.wait_timeout) error.ResolveTimeout else error.HostNotFound;
    }
    const status = state.status.load(.acquire);
    if (status == win.timed_out) return error.ResolveTimeout;
    if (status != 0) return error.HostNotFound;
    return state.answer orelse error.HostNotFound;
}

const WinResolveState = struct {
    // OVERLAPPED and all input/output storage must outlive GetAddrInfoExW.
    overlapped: win.Overlapped = .{},
    hints: win.AddrInfoExW = .{},
    result: ?*win.AddrInfoExW = null,
    event: *anyopaque,
    name: [:0]u16,
    family: i32,
    port: u16,
    both: bool = false,
    v4: ?[4]u8 = null,
    v6: ?[16]u8 = null,
    answer: ?net.IpAddress = null,
    status: std.atomic.Value(i32) = .init(win.io_pending),
    refs: std.atomic.Value(u32) = .init(2),

    fn release(self: *WinResolveState) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        _ = win.CloseHandle(self.event);
        std.heap.page_allocator.free(self.name);
        _ = win.WSACleanup();
        std.heap.page_allocator.destroy(self);
    }
};

fn winResolveCompleted(status: u32, _: u32, overlapped: *win.Overlapped) callconv(.winapi) void {
    const state: *WinResolveState = @fieldParentPtr("overlapped", overlapped);
    if (state.result) |result| {
        if (status == 0 and state.both) {
            const families = collectWinFamilies(result);
            state.v4 = families.v4;
            state.v6 = families.v6;
        } else if (status == 0) {
            state.answer = firstWinSystemAddress(result, state.family, state.port);
        }
        win.FreeAddrInfoExW(result);
        state.result = null;
    }
    state.status.store(@bitCast(status), .release);
    _ = win.SetEvent(state.event);
    state.release();
}

pub fn firstWinSystemAddress(head: ?*win.AddrInfoExW, family: i32, port: u16) ?net.IpAddress {
    var cursor = head;
    for (0..64) |_| {
        const entry = cursor orelse return null;
        cursor = entry.next;
        if (entry.family != family or entry.addr_len > 128) continue;
        const addr = entry.addr orelse continue;
        const raw: [*]const u8 = @ptrCast(addr);
        if (family == win.af_inet) {
            if (entry.addr_len < 16 or std.mem.readInt(u16, raw[0..2], .little) != win.af_inet) continue;
            var bytes: [4]u8 = undefined;
            @memcpy(&bytes, raw[4..8]);
            return .{ .ip4 = .{ .bytes = bytes, .port = port } };
        }
        if (family == win.af_inet6) {
            if (entry.addr_len < 28 or std.mem.readInt(u16, raw[0..2], .little) != win.af_inet6) continue;
            var bytes: [16]u8 = undefined;
            @memcpy(&bytes, raw[8..24]);
            const scope = std.mem.readInt(u32, raw[24..28], .little);
            return .{ .ip6 = .{ .bytes = bytes, .port = port, .interface = .{ .index = scope } } };
        }
    }
    return null;
}

fn collectWinFamilies(head: ?*win.AddrInfoExW) HostFamilies {
    var out = HostFamilies{};
    var cursor = head;
    for (0..64) |_| {
        const entry = cursor orelse break;
        cursor = entry.next;
        if (entry.addr == null or entry.addr_len > 128) continue;
        const raw: [*]const u8 = @ptrCast(entry.addr.?);
        if (entry.family == win.af_inet and out.v4 == null and entry.addr_len >= 16 and
            std.mem.readInt(u16, raw[0..2], .little) == win.af_inet)
        {
            var bytes: [4]u8 = undefined;
            @memcpy(&bytes, raw[4..8]);
            out.v4 = bytes;
            continue;
        }
        if (entry.family == win.af_inet6 and entry.addr_len >= 28 and
            std.mem.readInt(u16, raw[0..2], .little) == win.af_inet6)
        {
            var bytes: [16]u8 = undefined;
            @memcpy(&bytes, raw[8..24]);
            const mapped = bytes[0] == 0 and bytes[1] == 0 and bytes[2] == 0 and bytes[3] == 0 and
                bytes[4] == 0 and bytes[5] == 0 and bytes[6] == 0 and bytes[7] == 0 and
                bytes[8] == 0 and bytes[9] == 0 and bytes[10] == 0xff and bytes[11] == 0xff;
            if (mapped) {
                if (out.v4 == null) {
                    var v4_bytes: [4]u8 = undefined;
                    @memcpy(&v4_bytes, bytes[12..16]);
                    out.v4 = v4_bytes;
                }
            } else if (out.v6 == null) {
                out.v6 = bytes;
            }
        }
    }
    return out;
}
