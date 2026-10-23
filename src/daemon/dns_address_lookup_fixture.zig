// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only bounded POSIX DNS peer and exact-path in-memory config reader.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = if (builtin.os.tag == .linux) std.os.linux else posix.system;
const wire = @import("../proto/dns/wire.zig");
const transport = @import("../proto/dns/transport.zig");
const Deadline = @import("../proto/dns/deadline.zig").Deadline;
const Packet = @import("../proto/dns/test_packet.zig").Packet;

/// Exercises SystemResolver's actual config read, limit, allocation, and close
/// paths. Every other I/O operation fails; no host filesystem is consulted.
pub const ConfigFile = struct {
    text: []const u8,
    opens: usize = 0,
    closes: usize = 0,
    deny: bool = false,

    const vtable: std.Io.VTable = blk: {
        var result = std.Io.failing.vtable.*;
        result.dirOpenFile = open;
        result.fileReadPositional = read;
        result.fileClose = close;
        break :blk result;
    };

    pub fn io(self: *ConfigFile) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }

    fn open(ctx: ?*anyopaque, _: std.Io.Dir, path: []const u8, _: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        const self: *ConfigFile = @ptrCast(@alignCast(ctx.?));
        self.opens += 1;
        if (!std.mem.eql(u8, path, "/etc/resolv.conf") or self.deny) return error.AccessDenied;
        return .{ .handle = undefined, .flags = .{ .nonblocking = false } };
    }

    fn read(ctx: ?*anyopaque, _: std.Io.File, data: []const []u8, offset: u64) std.Io.File.ReadPositionalError!usize {
        const self: *ConfigFile = @ptrCast(@alignCast(ctx.?));
        var position: usize = @intCast(@min(offset, self.text.len));
        const start = position;
        for (data) |dest| {
            const count = @min(dest.len, self.text.len - position);
            @memcpy(dest[0..count], self.text[position..][0..count]);
            position += count;
        }
        return position - start;
    }

    fn close(ctx: ?*anyopaque, files: []const std.Io.File) void {
        const self: *ConfigFile = @ptrCast(@alignCast(ctx.?));
        self.closes += files.len;
    }
};

pub const Peer = struct {
    pub const Mode = enum { silent, nxdomain, nodata, wrong_qr, unrelated_owner, nxdomain_with_a };

    fd: transport.Socket,
    port: u16,
    mode: Mode,
    thread: ?std.Thread = null,
    queries: usize = 0,
    failure: ?anyerror = null,

    pub fn init(address: [4]u8, port: u16, mode: Mode) !Peer {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        const raw = sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
        if (posix.errno(raw) != .SUCCESS) return error.SocketUnavailable;
        const fd: transport.Socket = @intCast(raw);
        errdefer _ = sys.close(fd);
        var addr = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(address) };
        if (posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))) != .SUCCESS) return error.BindFailed;
        var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
        if (posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)) != .SUCCESS) return error.BindFailed;
        return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.port), .mode = mode };
    }

    pub fn start(self: *Peer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn join(self: *Peer) !void {
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.failure) |err| return err;
    }

    pub fn deinit(self: *Peer) void {
        if (self.thread) |thread| thread.join();
        if (comptime builtin.os.tag == .linux or builtin.os.tag == .openbsd) _ = sys.close(self.fd);
    }

    fn run(self: *Peer) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *Peer) !void {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        const deadline = Deadline.after(4500);
        var socket = transport.Connection{ .socket = self.fd, .protocol = .udp };
        try socket.wait(.read, deadline);
        var buffer: [wire.max_message_len]u8 = undefined;
        var peer: posix.sockaddr.in = undefined;
        var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));
        const count = sys.recvfrom(self.fd, &buffer, buffer.len, 0, @ptrCast(&peer), &peer_len);
        if (posix.errno(count) != .SUCCESS) return error.ReceiveFailed;
        const message = try wire.parseMessage(1, 0, buffer[0..@intCast(count)]);
        if (message.question_count != 1 or message.questions[0].qtype != .a or
            !std.mem.eql(u8, message.questions[0].name.slice(), "host.test")) return error.InvalidQuestion;
        self.queries += 1;
        if (self.mode == .silent) return;
        const name = message.questions[0].name.slice();
        var packet = try Packet.init(message.header.id, name, .a);
        switch (self.mode) {
            .silent => unreachable,
            .nxdomain, .nodata => {
                if (self.mode == .nxdomain) packet.flags(0x8183);
                try packet.soa("test", 30, 30);
            },
            .wrong_qr, .unrelated_owner, .nxdomain_with_a => {
                try packet.address(if (self.mode == .unrelated_owner) "unrelated.test" else name, 30, .{ .ipv4 = .{ 192, 0, 2, 99 } });
                if (self.mode == .wrong_qr) packet.flags(0x0180);
                if (self.mode == .nxdomain_with_a) packet.flags(0x8183);
            },
        }
        try self.send(packet.slice(), &peer, peer_len);
        if (self.mode == .nxdomain or self.mode == .nodata) return;
        var valid = try Packet.init(message.header.id, name, .a);
        try valid.address(name, 30, .{ .ipv4 = .{ 192, 0, 2, 7 } });
        try self.send(valid.slice(), &peer, peer_len);
    }

    fn send(self: *Peer, bytes: []const u8, peer: *const posix.sockaddr.in, len: posix.socklen_t) !void {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        const sent = sys.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(peer), len);
        if (posix.errno(sent) != .SUCCESS or sent != bytes.len) return error.SendFailed;
    }
};
