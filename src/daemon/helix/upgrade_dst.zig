// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic self-test harness for the FULL Helix upgrade connection
//! migration round-trip, exercised entirely in-process WITHOUT the real server.
//!
//! The real upgrade flow serializes every live connection into a `ConnCapsule`,
//! batches the client descriptors plus the serialized blob over a SEQPACKET
//! conduit to the execve'd successor, and the successor decodes each capsule and
//! re-binds it to the matching descriptor. This file proves that fds and state
//! survive that exact handoff using a socket pair and a sender thread, with no
//! dependence on daemon internals.
//!
//! Multi-capsule payload framing (all integers big-endian):
//!
//!   count : u32                       number of capsules in the blob
//!   then `count` records, each:
//!     len    : u32                    byte length of the encoded capsule
//!     capsule: len bytes              `ConnCapsule.encode` output
//!
//! The `count` prefix lets the receiver pre-size its decode loop; the per-record
//! `len` prefix lets it slice each capsule exactly without re-parsing the codec's
//! internal layout. After decode, each `capsule.fd_index` selects the received
//! descriptor it pairs with.

const std = @import("std");
const builtin = @import("builtin");

const conn_capsule = @import("conn_capsule.zig");
const conduit = @import("conduit.zig");
const handoff = @import("handoff.zig");

const Allocator = std.mem.Allocator;

/// Width of the count prefix and of each per-capsule length prefix.
const count_prefix_len: usize = 4;
const record_len_prefix: usize = 4;

/// A connection that survived the handoff: its decoded state paired with the
/// freshly received descriptor it belongs to. The caller owns and must close
/// `fd`. The capsule's string slices borrow the conduit payload buffer, so they
/// must be consumed before that buffer is freed.
pub const MigratedConn = struct {
    fd: handoff.Fd,
    capsule: conn_capsule.ConnCapsule,
    /// Allocator-owned backing store for the capsule's string fields. The
    /// decoded `ConnCapsule` slices borrow the transient conduit payload, which
    /// is freed before `roundTrip` returns, so the strings are copied here and
    /// the capsule's slices are re-pointed at this buffer. Caller frees via
    /// `deinit`.
    backing: []u8,

    pub fn deinit(self: *MigratedConn, allocator: Allocator) void {
        allocator.free(self.backing);
        self.backing = &.{};
    }
};

pub const Error = conduit.Error || conn_capsule.Error || std.Thread.SpawnError || error{
    /// `out` was shorter than `conns`.
    OutputTooSmall,
    /// A capsule referenced an fd_index outside the received descriptor set.
    FdIndexOutOfRange,
    /// The received payload was malformed or its count did not match.
    Protocol,
};

/// Encode `conns` into a single framed payload buffer (see file header for the
/// layout). Caller frees the returned slice.
fn buildPayload(allocator: Allocator, conns: []const conn_capsule.ConnCapsule) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var count_prefix: [count_prefix_len]u8 = undefined;
    std.mem.writeInt(u32, &count_prefix, @intCast(conns.len), .big);
    try buf.appendSlice(allocator, &count_prefix);

    // Scratch large enough for any single capsule we expect to encode.
    var scratch: [4096]u8 = undefined;
    for (conns) |c| {
        const wire = try c.encode(&scratch);
        var len_prefix: [record_len_prefix]u8 = undefined;
        std.mem.writeInt(u32, &len_prefix, @intCast(wire.len), .big);
        try buf.appendSlice(allocator, &len_prefix);
        try buf.appendSlice(allocator, wire);
    }

    return buf.toOwnedSlice(allocator);
}

/// Copy `capsule`'s string fields into one allocator-owned buffer and re-point
/// the returned capsule's slices at that buffer, so it outlives `payload`.
fn dupeCapsule(
    allocator: Allocator,
    capsule: conn_capsule.ConnCapsule,
) Error!struct { capsule: conn_capsule.ConnCapsule, backing: []u8 } {
    const acct_len: usize = if (capsule.account) |a| a.len else 0;
    const total = capsule.nick.len + capsule.user.len +
        capsule.realname.len + capsule.host.len + acct_len;

    const backing = try allocator.alloc(u8, total);
    errdefer allocator.free(backing);

    var off: usize = 0;
    const take = struct {
        fn f(buf: []u8, o: *usize, src: []const u8) []const u8 {
            @memcpy(buf[o.* .. o.* + src.len], src);
            const slice = buf[o.* .. o.* + src.len];
            o.* += src.len;
            return slice;
        }
    }.f;

    const nick = take(backing, &off, capsule.nick);
    const user = take(backing, &off, capsule.user);
    const realname = take(backing, &off, capsule.realname);
    const host = take(backing, &off, capsule.host);
    const account: ?[]const u8 = if (capsule.account) |a| take(backing, &off, a) else null;

    return .{
        .capsule = .{
            .fd_index = capsule.fd_index,
            .caps = capsule.caps,
            .flags = capsule.flags,
            .nick = nick,
            .user = user,
            .realname = realname,
            .host = host,
            .account = account,
        },
        .backing = backing,
    };
}

/// Decode the framed payload, pairing each capsule with `recv_fds[fd_index]`,
/// writing results into `out`. Capsule strings are copied into allocator-owned
/// backing buffers so they survive the payload being freed; the caller frees
/// each result via `MigratedConn.deinit`. Returns the number of capsules.
fn decodePayload(
    allocator: Allocator,
    payload: []const u8,
    recv_fds: []const handoff.Fd,
    out: []MigratedConn,
) Error!usize {
    if (payload.len < count_prefix_len) return error.Protocol;
    const count = std.mem.readInt(u32, payload[0..count_prefix_len], .big);
    if (count > out.len) return error.OutputTooSmall;

    var pos: usize = count_prefix_len;
    var i: usize = 0;
    errdefer for (out[0..i]) |*m| m.deinit(allocator);
    while (i < count) : (i += 1) {
        if (pos + record_len_prefix > payload.len) return error.Protocol;
        const rec_len = std.mem.readInt(u32, payload[pos..][0..record_len_prefix], .big);
        pos += record_len_prefix;
        if (pos + rec_len > payload.len) return error.Protocol;

        const capsule = try conn_capsule.ConnCapsule.decode(payload[pos .. pos + rec_len]);
        pos += rec_len;

        if (capsule.fd_index >= recv_fds.len) return error.FdIndexOutOfRange;
        const owned = try dupeCapsule(allocator, capsule);
        out[i] = .{
            .fd = recv_fds[capsule.fd_index],
            .capsule = owned.capsule,
            .backing = owned.backing,
        };
    }

    return count;
}

/// Context for the sender thread. SEQPACKET sends can block until the peer
/// reads, so the send half runs on its own thread while the caller receives.
const SendCtx = struct {
    sock: handoff.Fd,
    fds: []const handoff.Fd,
    payload: []const u8,
    result: conduit.Error!void = undefined,

    fn run(self: *SendCtx) void {
        self.result = conduit.send(self.sock, self.fds, self.payload);
    }
};

/// Run the full encode -> conduit.send -> conduit.recv -> decode round-trip over
/// a fresh socket pair, pairing each decoded capsule with its received fd into
/// `out`. Returns the number of migrated connections.
///
/// The caller owns the descriptors in `out[*].fd` and must close them, and owns
/// each `out[i]`'s string backing buffer, freed via `MigratedConn.deinit`. The
/// capsule strings are copied into those buffers, so they remain valid after the
/// transient conduit payload is freed inside this function.
pub fn roundTrip(
    allocator: Allocator,
    conns: []const conn_capsule.ConnCapsule,
    fds: []const handoff.Fd,
    out: []MigratedConn,
) Error!usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (out.len < conns.len) return error.OutputTooSmall;

    const payload = try buildPayload(allocator, conns);
    defer allocator.free(payload);

    var sockets = try handoff.socketPair();
    defer sockets.close();

    var ctx = SendCtx{ .sock = sockets.supervisor, .fds = fds, .payload = payload };
    const thread = try std.Thread.spawn(.{}, SendCtx.run, .{&ctx});

    var received = conduit.recv(allocator, sockets.worker) catch |err| {
        thread.join();
        return err;
    };
    defer received.deinit(allocator);

    thread.join();
    try ctx.result;

    const decoded = decodePayload(allocator, received.payload, received.fds, out) catch |err| {
        for (received.fds) |fd| _ = std.os.linux.close(fd);
        return err;
    };

    return decoded;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const linux = std.os.linux;

/// Create `n` real, distinct descriptors by dup-ing a pipe read end.
fn makeFds(comptime n: usize) error{SkipZigTest}![n]handoff.Fd {
    var pipe_fds: [2]i32 = undefined;
    {
        const rc = linux.pipe(&pipe_fds);
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    }
    defer {
        _ = linux.close(pipe_fds[0]);
        _ = linux.close(pipe_fds[1]);
    }

    var fds: [n]handoff.Fd = undefined;
    var made: usize = 0;
    errdefer for (fds[0..made]) |fd| {
        _ = linux.close(fd);
    };
    while (made < n) : (made += 1) {
        const rc = linux.dup(pipe_fds[0]);
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
        fds[made] = @intCast(rc);
    }
    return fds;
}

/// A live descriptor answers F_GETFD; a closed/invalid one returns EBADF.
fn fdIsValid(fd: handoff.Fd) bool {
    const rc = linux.fcntl(fd, linux.F.GETFD, 0);
    return linux.errno(rc) == .SUCCESS;
}

test "full upgrade round-trip preserves state and descriptors" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const originals = [_]conn_capsule.ConnCapsule{
        .{
            .fd_index = 0,
            .caps = (@as(u128, 1) << 100) | 0xABCD,
            .flags = .{ .registered = true, .is_tls = true, .ircx = false },
            .nick = "Undertow",
            .user = "ident0",
            .realname = "Stream Vein",
            .host = "node0.onyx",
            .account = "acct-zero",
        },
        .{
            .fd_index = 1,
            .caps = 0,
            .flags = .{ .registered = false, .is_tls = false, .ircx = true },
            .nick = "Mooring",
            .user = "ident1",
            .realname = "Weaver",
            .host = "node1.onyx",
            .account = null, // null account variant
        },
        .{
            .fd_index = 2,
            .caps = (@as(u128, 1) << 127),
            .flags = .{ .registered = true, .is_tls = false, .ircx = true },
            .nick = "Sieve",
            .user = "ident2",
            .realname = "Spine",
            .host = "node2.onyx",
            .account = "acct-two",
        },
    };

    var orig_fds = try makeFds(3);
    defer for (orig_fds) |fd| {
        _ = linux.close(fd);
    };

    var migrated: [3]MigratedConn = undefined;
    const n = try roundTrip(allocator, &originals, &orig_fds, &migrated);
    defer for (migrated[0..n]) |*m| {
        _ = linux.close(m.fd);
        m.deinit(allocator);
    };

    try std.testing.expectEqual(@as(usize, 3), n);

    // State survived: each decoded capsule matches its original.
    for (originals, 0..) |orig, idx| {
        const got = migrated[idx].capsule;
        try std.testing.expectEqual(orig.fd_index, got.fd_index);
        try std.testing.expectEqual(orig.caps, got.caps);
        try std.testing.expectEqual(
            @as(u8, @bitCast(orig.flags)),
            @as(u8, @bitCast(got.flags)),
        );
        try std.testing.expectEqualStrings(orig.nick, got.nick);
        try std.testing.expectEqualStrings(orig.user, got.user);
        try std.testing.expectEqualStrings(orig.realname, got.realname);
        try std.testing.expectEqualStrings(orig.host, got.host);
        if (orig.account) |acct| {
            try std.testing.expect(got.account != null);
            try std.testing.expectEqualStrings(acct, got.account.?);
        } else {
            try std.testing.expect(got.account == null);
        }
    }

    // Descriptors survived: each is valid and distinct from the others and from
    // the originals (SCM_RIGHTS installs fresh fd numbers in the receiver).
    for (migrated[0..n]) |m| {
        try std.testing.expect(m.fd >= 0);
        try std.testing.expect(fdIsValid(m.fd));
        for (orig_fds) |of| {
            try std.testing.expect(m.fd != of);
        }
    }

    // All received descriptors are distinct from one another.
    var seen: usize = 0;
    while (seen < n) : (seen += 1) {
        var other: usize = seen + 1;
        while (other < n) : (other += 1) {
            try std.testing.expect(migrated[seen].fd != migrated[other].fd);
        }
    }
}

test "buildPayload then decodePayload framing is self-consistent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const conns = [_]conn_capsule.ConnCapsule{
        .{
            .fd_index = 0,
            .caps = 1,
            .flags = .{},
            .nick = "a",
            .user = "ua",
            .realname = "ra",
            .host = "ha",
            .account = null,
        },
        .{
            .fd_index = 1,
            .caps = 2,
            .flags = .{ .registered = true },
            .nick = "b",
            .user = "ub",
            .realname = "rb",
            .host = "hb",
            .account = "acct",
        },
    };

    const payload = try buildPayload(allocator, &conns);
    defer allocator.free(payload);

    // The leading u32 count must equal the capsule count.
    try std.testing.expectEqual(
        @as(u32, 2),
        std.mem.readInt(u32, payload[0..4], .big),
    );

    const fake_fds = [_]handoff.Fd{ 100, 101 };
    var out: [2]MigratedConn = undefined;
    const decoded = try decodePayload(allocator, payload, &fake_fds, &out);
    defer for (out[0..decoded]) |*m| m.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), decoded);
    try std.testing.expectEqualStrings("a", out[0].capsule.nick);
    try std.testing.expectEqual(@as(handoff.Fd, 100), out[0].fd);
    try std.testing.expectEqualStrings("b", out[1].capsule.nick);
    try std.testing.expect(out[1].capsule.account != null);
    try std.testing.expectEqualStrings("acct", out[1].capsule.account.?);
    try std.testing.expectEqual(@as(handoff.Fd, 101), out[1].fd);
}

test "decodePayload rejects an out-of-range fd_index" {
    const allocator = std.testing.allocator;

    const conns = [_]conn_capsule.ConnCapsule{
        .{
            .fd_index = 5, // no such received fd
            .caps = 0,
            .flags = .{},
            .nick = "x",
            .user = "x",
            .realname = "x",
            .host = "x",
            .account = null,
        },
    };

    const payload = try buildPayload(allocator, &conns);
    defer allocator.free(payload);

    const fake_fds = [_]handoff.Fd{42};
    var out: [1]MigratedConn = undefined;
    try std.testing.expectError(
        error.FdIndexOutOfRange,
        decodePayload(allocator, payload, &fake_fds, &out),
    );
}

test "decodePayload rejects a too-small output buffer" {
    const allocator = std.testing.allocator;

    const conns = [_]conn_capsule.ConnCapsule{
        .{
            .fd_index = 0,
            .caps = 0,
            .flags = .{},
            .nick = "x",
            .user = "x",
            .realname = "x",
            .host = "x",
            .account = null,
        },
        .{
            .fd_index = 1,
            .caps = 0,
            .flags = .{},
            .nick = "y",
            .user = "y",
            .realname = "y",
            .host = "y",
            .account = null,
        },
    };

    const payload = try buildPayload(allocator, &conns);
    defer allocator.free(payload);

    const fake_fds = [_]handoff.Fd{ 1, 2 };
    var out: [1]MigratedConn = undefined; // too small for 2 capsules
    try std.testing.expectError(
        error.OutputTooSmall,
        decodePayload(allocator, payload, &fake_fds, &out),
    );
}
