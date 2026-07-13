// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client WebSocket resume snapshot — carried across a Helix UPGRADE so an
//! ESTABLISHED wss browser client (Ruri and friends) keeps its socket instead
//! of being dropped and forced to reconnect on every hot upgrade.
//!
//! A wss client is layered TLS-then-WebSocket. The TLS crypto state rides its
//! own `.tls_session` capsule (see tls_snapshot.zig); THIS capsule carries the
//! WebSocket-adapter state that pairs with it. `fd` is the join key back to
//! the matching `.clients` session snapshot and `.tls_session`.
//!
//! v1 (historical) carried only `[i32 fd][u8 flags]` and the predecessor sealed
//! it ONLY at a clean framing boundary (handshake open, empty deframer, empty
//! tx accumulator). An active browser client is almost never at that boundary —
//! its deframer usually holds the first bytes of the next inbound frame — so in
//! practice every busy wss client was dropped on every upgrade (the live
//! "browsers reconnect on each deploy" symptom).
//!
//! v2 therefore ALSO serializes the adapter's partial framing state so the
//! successor rebuilds the adapter mid-frame with no lost bytes:
//!   * the deframer's buffered partial inbound frame wire bytes,
//!   * the deframer's cross-frame fragmentation state (fragmented + msg_binary),
//!   * the tx accumulator's partial outbound line.
//! A popped-but-unconsumed deframer event (or latent error) exists only
//! transiently INSIDE one drive turn, never between reactor turns, so it is not
//! serialized — the seal path refuses to carry that (pathological) state.
//!
//! Wire format (all integers little-endian):
//!   v1: [i32 fd][u8 flags]
//!   v2: [i32 fd][u8 flags][u32 dlen][dlen deframer bytes][u32 tlen][tlen tx bytes]
//! flags: bit0 = phase_open (required to adopt), bit1 = deframer fragmented,
//! bit2 = in-flight fragmented message is binary. A v1 capsule decodes with
//! empty partial state (it was sealed at a clean boundary by construction).
const std = @import("std");

pub const Error = error{ Truncated, TooLong, UnsupportedVersion };

/// flags bit0: the carried adapter had completed its HTTP Upgrade (phase=open).
/// A capsule without it is ignored on adopt (a handshake-phase WS is never
/// carried; it reconnects). Reserved higher bits stay zero for forward capsules.
pub const flag_phase_open: u8 = 1 << 0;
/// flags bit1: a fragmented DATA message was open at seal time (a non-FIN
/// text/binary frame was seen; its closing FIN continuation had not arrived).
pub const flag_fragmented: u8 = 1 << 1;
/// flags bit2: the in-flight fragmented DATA message's opcode was binary.
pub const flag_msg_binary: u8 = 1 << 2;

/// A plain view of one carried WebSocket adapter. Decoded slices borrow the
/// input buffer; the caller copies them into the rebuilt adapter immediately.
pub const Snapshot = struct {
    /// The client's socket fd (inherited across execve) — joins this WS snapshot
    /// to its `.clients` session snapshot and `.tls_session` capsule.
    fd: i32 = -1,
    /// The adapter had finished its Upgrade handshake and was framing IRC lines.
    /// Only an open adapter is ever sealed.
    phase_open: bool = true,
    /// Cross-frame fragmentation state (RFC 6455 §5.4) at seal time.
    fragmented: bool = false,
    msg_binary: bool = false,
    /// Buffered wire bytes of the (partial) next inbound frame in the deframer.
    deframer: []const u8 = &.{},
    /// Partial outbound IRC line accumulated in the tx seam (no CRLF seen yet).
    tx: []const u8 = &.{},
};

/// Encode `snap` (current version, v2) into a freshly-allocated buffer the
/// caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    if (snap.deframer.len > std.math.maxInt(u32) or snap.tx.len > std.math.maxInt(u32))
        return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var le: [4]u8 = undefined;
    std.mem.writeInt(i32, &le, snap.fd, .little);
    try out.appendSlice(allocator, &le);
    var flags: u8 = 0;
    if (snap.phase_open) flags |= flag_phase_open;
    if (snap.fragmented) flags |= flag_fragmented;
    if (snap.msg_binary) flags |= flag_msg_binary;
    try out.append(allocator, flags);
    inline for (.{ snap.deframer, snap.tx }) |bytes| {
        std.mem.writeInt(u32, &le, @intCast(bytes.len), .little);
        try out.appendSlice(allocator, &le);
        try out.appendSlice(allocator, bytes);
    }
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot sealed at capsule `version` (the `.ws_session` capsule
/// header version). v1 carries no partial state — it was sealed at a clean
/// framing boundary by construction, so the partials decode empty. Unknown
/// versions fail closed. Returned slices borrow `bytes`.
pub fn decode(bytes: []const u8, version: u16) Error!Snapshot {
    if (bytes.len < 5) return error.Truncated;
    const fd = std.mem.readInt(i32, bytes[0..4], .little);
    const flags = bytes[4];
    var snap = Snapshot{
        .fd = fd,
        .phase_open = (flags & flag_phase_open) != 0,
        .fragmented = (flags & flag_fragmented) != 0,
        .msg_binary = (flags & flag_msg_binary) != 0,
    };
    switch (version) {
        1 => {}, // clean-boundary seal: no partial state on the wire
        2 => {
            var p: usize = 5;
            inline for (.{ &snap.deframer, &snap.tx }) |dst| {
                if (bytes.len - p < 4) return error.Truncated;
                const n = std.mem.readInt(u32, bytes[p..][0..4], .little);
                p += 4;
                if (bytes.len - p < n) return error.Truncated;
                dst.* = bytes[p .. p + n];
                p += n;
            }
        },
        else => return error.UnsupportedVersion,
    }
    return snap;
}

const testing = std.testing;

test "ws snapshot v2 round-trips fd + flags + partial framing state" {
    const allocator = testing.allocator;
    const partial_frame = [_]u8{ 0x81, 0x8a, 1, 2, 3, 4, 'p' }; // masked frame head + 1 byte
    const partial_line = "@time=2026 PRIVMSG #root :hel";
    const bytes = try encode(allocator, .{
        .fd = 31,
        .phase_open = true,
        .fragmented = true,
        .msg_binary = true,
        .deframer = &partial_frame,
        .tx = partial_line,
    });
    defer allocator.free(bytes);
    const got = try decode(bytes, 2);
    try testing.expectEqual(@as(i32, 31), got.fd);
    try testing.expect(got.phase_open and got.fragmented and got.msg_binary);
    try testing.expectEqualSlices(u8, &partial_frame, got.deframer);
    try testing.expectEqualStrings(partial_line, got.tx);
}

test "ws snapshot v2 with empty partials round-trips (idle adapter)" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = true });
    defer allocator.free(bytes);
    const got = try decode(bytes, 2);
    try testing.expectEqual(@as(i32, 7), got.fd);
    try testing.expect(got.phase_open and !got.fragmented and !got.msg_binary);
    try testing.expectEqual(@as(usize, 0), got.deframer.len);
    try testing.expectEqual(@as(usize, 0), got.tx.len);
}

test "cross-version: a v1 capsule decodes with empty partial state" {
    // A v1 blob is exactly [i32 fd][u8 flags] — sealed only at a clean boundary,
    // so decoding it as v1 must yield an open adapter with NO partial state.
    var v1: [5]u8 = undefined;
    std.mem.writeInt(i32, v1[0..4], 42, .little);
    v1[4] = flag_phase_open;
    const got = try decode(&v1, 1);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expect(got.phase_open);
    try testing.expect(!got.fragmented and !got.msg_binary);
    try testing.expectEqual(@as(usize, 0), got.deframer.len);
    try testing.expectEqual(@as(usize, 0), got.tx.len);
}

test "ws snapshot carries a not-open marker distinctly" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .fd = 7, .phase_open = false });
    defer allocator.free(bytes);
    const got = try decode(bytes, 2);
    try testing.expectEqual(@as(i32, 7), got.fd);
    try testing.expect(!got.phase_open);
}

test "decode rejects truncation and unknown versions" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0, 0 }, 2));
    // v2 prefix without its length-prefixed tails is truncated.
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 0, 0, 0, 1 }, 2));
    // Declared deframer length overrunning the buffer is truncated.
    var bad: [13]u8 = @splat(0);
    bad[4] = flag_phase_open;
    std.mem.writeInt(u32, bad[5..9], 100, .little);
    try testing.expectError(error.Truncated, decode(&bad, 2));
    // Unknown future version fails closed.
    try testing.expectError(error.UnsupportedVersion, decode(&[_]u8{ 1, 0, 0, 0, 1 }, 3));
}
