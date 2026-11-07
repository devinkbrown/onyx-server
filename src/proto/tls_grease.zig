// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GREASE ("Generate Random Extensions And Sustain Extensibility", RFC 8701).
//!
//! RFC 8701 §2 reserves sixteen two-byte code points of the form `0xXAXA`
//! (0x0A0A, 0x1A1A, ..., 0xFAFA) in the cipher suite, supported group,
//! extension, signature algorithm and version registries, and the matching
//! two-byte strings `{0xXA, 0xXA}` in the ALPN registry. A client sprinkles
//! them into its ClientHello so that servers which choke on unknown values are
//! found early. RFC 8701 §3.2: a server MUST treat them like any other unknown
//! value (ignore them) and MUST NOT negotiate them; §3.1: a client MUST reject
//! any GREASE value a server negotiates.
//!
//! Pure logic, no I/O. A connection draws its GREASE values from a per-connection
//! random `Seed` (caller supplies the bytes from the DRBG / OS entropy), so the
//! values are unpredictable across connections but stable within one, which is
//! what RFC 8446 §4.1.2 needs for a ClientHello retried after HelloRetryRequest.
const std = @import("std");

/// True iff `value` is one of the RFC 8701 §2 reserved GREASE code points
/// (cipher suites, groups, extensions, signature schemes, versions).
pub fn isGrease(value: u16) bool {
    return (value & 0x0f0f) == 0x0a0a and (value >> 8) == (value & 0xff);
}

/// True iff `name` is an RFC 8701 §2 GREASE ALPN identifier `{0xXA, 0xXA}`.
pub fn isGreaseAlpn(name: []const u8) bool {
    return name.len == 2 and isGrease(std.mem.readInt(u16, name[0..2], .big));
}

/// Map any byte onto a GREASE code point: `0xXAXA` where X is the byte's high
/// nibble (the BoringSSL derivation, uniform over the 16 reserved values).
pub fn fromByte(b: u8) u16 {
    const v: u16 = (b & 0xf0) | 0x0a;
    return (v << 8) | v;
}

/// Positions in a ClientHello that carry a GREASE value.
pub const Slot = enum(u3) {
    cipher_suite,
    group,
    extension1,
    extension2,
    version,
    signature_algorithm,
    alpn,
};

/// Per-connection GREASE seed: one random byte per `Slot`.
pub const Seed = struct {
    bytes: [8]u8,

    /// The GREASE value for `slot`. The two extension slots are guaranteed
    /// distinct: RFC 8446 §4.2 forbids two extensions of one type in a block,
    /// so the second is nudged to the next reserved value on a collision
    /// (RFC 8701 §3.1 asks clients not to repeat a GREASE value in a list).
    pub fn value(self: Seed, slot: Slot) u16 {
        const v = fromByte(self.bytes[@backingInt(slot)]);
        if (slot == .extension2 and v == fromByte(self.bytes[@backingInt(Slot.extension1)])) {
            return v ^ 0x1010;
        }
        return v;
    }

    /// The GREASE ALPN identifier as its two wire bytes.
    pub fn alpn(self: Seed) [2]u8 {
        var out: [2]u8 = undefined;
        std.mem.writeInt(u16, &out, self.value(.alpn), .big);
        return out;
    }
};

test "isGrease accepts exactly the sixteen RFC 8701 values" {
    var count: usize = 0;
    var v: u32 = 0;
    while (v <= 0xffff) : (v += 1) {
        if (isGrease(@intCast(v))) {
            count += 1;
            try std.testing.expectEqual(@as(u32, 0x0a0a), v & 0x0f0f);
        }
    }
    try std.testing.expectEqual(@as(usize, 16), count);
    try std.testing.expect(isGrease(0x0a0a));
    try std.testing.expect(isGrease(0xfafa));
    try std.testing.expect(!isGrease(0x0a1a));
    try std.testing.expect(!isGrease(0x1301));
    try std.testing.expect(!isGrease(0x001d));
    try std.testing.expect(!isGrease(0x11ec));
}

test "fromByte always yields a GREASE value; Seed keeps the two extensions distinct" {
    for (0..256) |b| try std.testing.expect(isGrease(fromByte(@intCast(b))));
    for (0..256) |b| {
        const seed = Seed{ .bytes = .{ 0, 0, @intCast(b), @intCast(b), 0, 0, 0, 0 } };
        const e1 = seed.value(.extension1);
        const e2 = seed.value(.extension2);
        try std.testing.expect(isGrease(e1));
        try std.testing.expect(isGrease(e2));
        try std.testing.expect(e1 != e2);
    }
    const seed = Seed{ .bytes = .{ 0x3f, 0, 0, 0, 0, 0, 0x7c, 0 } };
    try std.testing.expectEqual(@as(u16, 0x3a3a), seed.value(.cipher_suite));
    try std.testing.expect(isGreaseAlpn(&seed.alpn()));
    try std.testing.expect(!isGreaseAlpn("h2"));
    try std.testing.expect(!isGreaseAlpn("\x0a\x0a\x0a"));
}
