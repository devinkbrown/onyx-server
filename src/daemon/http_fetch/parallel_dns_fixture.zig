// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Finite local DNS peer that can require both families before answering either.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = if (builtin.os.tag == .windows) std.os.linux else posix.system;
const dns = @import("../../proto/dns.zig");
const transport = @import("../../proto/dns/transport.zig");
const Deadline = @import("../../proto/dns/deadline.zig").Deadline;
const Packet = @import("../../proto/dns/test_packet.zig").Packet;

pub const Peer = struct {
    pub const Reply = enum { positive, silent, negative, alias, wrong_id };
    const Request = struct {
        id: u16,
        question: dns.Question,
        peer: posix.sockaddr.storage,
        peer_len: posix.socklen_t,
    };

    fd: transport.Socket,
    port: u16,
    replies: [2]Reply = .{ .positive, .positive },
    expected: [2]usize = .{ 1, 1 },
    queries: [2]usize = .{ 0, 0 },
    delay_ms: [2]u32 = .{ 0, 0 },
    positive_last: u8 = 9,
    require_both: bool = true,
    answered_after_both: bool = false,
    fixture_timeout_ms: u32 = 1500,
    thread: ?std.Thread = null,
    failure: ?anyerror = null,

    pub fn init(address: dns.Address, port: u16) !Peer {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        const raw = sys.socket(if (address == .ipv4) posix.AF.INET else posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
        if (posix.errno(raw) != .SUCCESS) return error.SocketUnavailable;
        const fd: transport.Socket = @intCast(raw);
        errdefer _ = sys.close(fd);
        const bound_port = switch (address) {
            .ipv4 => |bytes| blk: {
                var bound = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bytes) };
                var len: posix.socklen_t = @sizeOf(@TypeOf(bound));
                if (posix.errno(sys.bind(fd, @ptrCast(&bound), len)) != .SUCCESS or posix.errno(sys.getsockname(fd, @ptrCast(&bound), &len)) != .SUCCESS) return error.BindFailed;
                break :blk std.mem.bigToNative(u16, bound.port);
            },
            .ipv6 => |bytes| blk: {
                var bound = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .addr = bytes, .scope_id = 0, .flowinfo = 0 };
                var len: posix.socklen_t = @sizeOf(@TypeOf(bound));
                if (posix.errno(sys.bind(fd, @ptrCast(&bound), len)) != .SUCCESS or posix.errno(sys.getsockname(fd, @ptrCast(&bound), &len)) != .SUCCESS) return error.BindFailed;
                break :blk std.mem.bigToNative(u16, bound.port);
            },
        };
        return .{ .fd = fd, .port = bound_port };
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
        const deadline = Deadline.after(self.fixture_timeout_ms);
        var pending: [2]?Request = .{ null, null };
        var barrier_open = !self.require_both;
        for (0..self.expected[0] + self.expected[1]) |_| {
            const request = try self.receive(deadline);
            const family: usize = switch (request.question.qtype) {
                .a => 0,
                .aaaa => 1,
                else => return error.InvalidQuestion,
            };
            self.queries[family] += 1;
            if (self.queries[family] > self.expected[family]) return error.DuplicateQuestion;
            const expected_name = if (self.replies[family] == .alias and self.queries[family] == 2) "canonical.test" else "lookup.test";
            if (!std.mem.eql(u8, request.question.name.slice(), expected_name)) return error.InvalidQuestion;
            if (!barrier_open) {
                if (pending[family] != null) return error.DuplicateQuestion;
                pending[family] = request;
                if (pending[0] == null or pending[1] == null) continue;
                // No reply is emitted until both real UDP questions arrive.
                self.answered_after_both = true;
                barrier_open = true;
                try self.reply(&pending[0].?, 0);
                try self.reply(&pending[1].?, 1);
            } else try self.reply(&request, family);
        }
    }

    fn receive(self: *Peer, deadline: Deadline) !Request {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        var connection = transport.Connection{ .socket = self.fd, .protocol = .udp };
        try connection.wait(.read, deadline);
        var buffer: [dns.max_message_len]u8 = undefined;
        var peer: posix.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));
        const count = sys.recvfrom(self.fd, &buffer, buffer.len, 0, @ptrCast(&peer), &peer_len);
        if (posix.errno(count) != .SUCCESS) return error.ReceiveFailed;
        const message = try dns.parseMessage(1, 0, buffer[0..@intCast(count)]);
        if (message.question_count != 1) return error.InvalidQuestion;
        return .{ .id = message.header.id, .question = message.questions[0], .peer = peer, .peer_len = peer_len };
    }

    fn reply(self: *Peer, request: *const Request, family: usize) !void {
        const mode = self.replies[family];
        if (mode == .silent) return;
        pause(self.delay_ms[family]);
        const question = request.question;
        const name = question.name.slice();
        var packet = try Packet.init(request.id, name, question.qtype);
        switch (mode) {
            .silent => unreachable,
            .negative => {
                packet.flags(0x8183);
                try packet.soa("test", 30, 30);
            },
            .alias => {
                if (std.mem.eql(u8, name, "lookup.test")) {
                    try packet.nameRecord(name, 5, 30, "canonical.test");
                } else try positive(&packet, name, family, self.positive_last);
            },
            .positive, .wrong_id => {
                if (mode == .wrong_id) {
                    var forged = try Packet.init(request.id +% 1, name, question.qtype);
                    try positive(&forged, name, family, 99);
                    try self.send(forged.slice(), request);
                }
                try positive(&packet, name, family, self.positive_last);
            },
        }
        try self.send(packet.slice(), request);
    }

    fn send(self: *Peer, bytes: []const u8, request: *const Request) !void {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
        const sent = sys.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&request.peer), request.peer_len);
        if (posix.errno(sent) != .SUCCESS or sent != bytes.len) return error.SendFailed;
    }
};

fn positive(packet: *Packet, name: []const u8, family: usize, last: u8) !void {
    if (family == 0) {
        try packet.address(name, 30, .{ .ipv4 = .{ 203, 0, 113, last } });
    } else {
        var address: [16]u8 = @splat(0);
        address[0] = 0x20;
        address[1] = 0x01;
        address[2] = 0x0d;
        address[3] = 0xb8;
        address[15] = last;
        try packet.address(name, 30, .{ .ipv6 = address });
    }
}

fn pause(ms: u32) void {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return;
    var remaining = sys.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    while (ms != 0) {
        var next: sys.timespec = undefined;
        switch (posix.errno(sys.nanosleep(&remaining, &next))) {
            .SUCCESS => return,
            .INTR => remaining = next,
            else => return,
        }
    }
}
