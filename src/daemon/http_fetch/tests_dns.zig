// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the outbound HTTP implementation.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const dns = @import("../../proto/dns.zig");
const tls_client = @import("../../crypto/tls_client.zig");
const resolveHostFamilies = @import("resolution.zig").resolveHostFamilies;
const queryFamilies = @import("resolution.zig").queryFamilies;
const udpSocket = @import("native_io.zig").udpSocket;
const setRecvTimeout = @import("native_io.zig").setRecvTimeout;
const closeFd = @import("native_io.zig").closeFd;

test "resolveHostFamilies keeps literals off the resolver" {
    const v4 = try resolveHostFamilies("127.0.0.1", 1);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &v4.v4.?);
    try std.testing.expect(v4.v6 == null);
    const v6 = try resolveHostFamilies("::1", 1);
    try std.testing.expect(v6.v4 == null);
    try std.testing.expectEqual(@as(u8, 1), v6.v6.?[15]);
}

test "dual dns query collects A and AAAA from one nameserver" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const Worker = struct {
        fd: sys.fd_t,
        replies: usize = 0,
        fn run(self: *@This()) void {
            setRecvTimeout(self.fd, 2000) catch return;
            while (self.replies < 2) {
                var packet: [dns.max_message_len]u8 = undefined;
                var from: posix.sockaddr.storage = undefined;
                var from_len: posix.socklen_t = @sizeOf(@TypeOf(from));
                const got = sys.recvfrom(self.fd, &packet, packet.len, 0, @ptrCast(&from), &from_len);
                if (posix.errno(got) != .SUCCESS or got < 12) return;
                const msg = dns.parseMessage(1, 0, packet[0..@intCast(got)]) catch return;
                if (msg.question_count != 1) return;
                const q = msg.questions[0];
                var out: [dns.max_message_len]u8 = undefined;
                const encoded = switch (q.qtype) {
                    .a => dns.encodeMessage(&out, .{
                        .id = msg.header.id,
                        .response = true,
                        .questions = &.{.{ .name = q.name.slice(), .qtype = .a }},
                        .answers = &.{.{ .name = q.name.slice(), .rr_type = .a, .ttl = 30, .data = .{ .a = .{ 203, 0, 113, 9 } } }},
                    }),
                    .aaaa => dns.encodeMessage(&out, .{
                        .id = msg.header.id,
                        .response = true,
                        .questions = &.{.{ .name = q.name.slice(), .qtype = .aaaa }},
                        .answers = &.{.{ .name = q.name.slice(), .rr_type = .aaaa, .ttl = 30, .data = .{ .aaaa = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 } } }},
                    }),
                    else => return,
                } catch return;
                const sent = sys.sendto(self.fd, encoded.ptr, encoded.len, 0, @ptrCast(&from), from_len);
                if (posix.errno(sent) != .SUCCESS) return;
                self.replies += 1;
            }
        }
    };
    const fd = try udpSocket();
    defer closeFd(fd);
    var bound = sys.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&bound), @sizeOf(@TypeOf(bound)))));
    var bound_len: posix.socklen_t = @sizeOf(@TypeOf(bound));
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&bound), &bound_len)));
    var worker = Worker{ .fd = fd };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    const found = queryFamilies(.{ .ipv4 = .{ 127, 0, 0, 1 } }, std.mem.bigToNative(u16, bound.port), "peer.example", 1000, true, true);
    thread.join();
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 9 }, found.v4.?);
    try std.testing.expectEqual([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }, found.v6.?);
    try std.testing.expectEqual(@as(usize, 2), worker.replies);
}
