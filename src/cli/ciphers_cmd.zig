// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor ciphers` — enumerate what the Armor TLS stack actually negotiates.
//! Suites come straight from the hardened allow-list (src/crypto/tls.zig
//! `isAllowed`), key-exchange groups from the client's real ClientHello offer
//! (src/crypto/tls_client.zig:1250: x25519mlkem768, x25519, secp256r1), and
//! signature schemes from src/proto/tls_signature_scheme.zig. Nothing here is
//! configuration — it reflects the compiled stack.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const tls = onyx_server.crypto.tls;
const supported_groups = onyx_server.proto.supported_groups;
const sig_scheme = onyx_server.proto.tls_signature_scheme;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor ciphers
        \\  lists the TLS 1.3/1.2 cipher suites, key-exchange groups, and
        \\  signature schemes the Armor stack supports (the hardened allow-list)
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!void {
    if (args.len != 0) return error.Usage;
}

pub fn run(out: *Writer) !void {
    inline for (.{ tls.ProtocolVersion.tls13, tls.ProtocolVersion.tls12 }) |version| {
        try out.print("{s} cipher suites:\n", .{@tagName(version)});
        const info = @typeInfo(tls.CipherSuite).@"enum";
        inline for (info.field_names, info.field_values) |name, value| {
            const suite: tls.CipherSuite = @fromBackingInt(@intCast(value));
            if (tls.isAllowed(version, suite)) {
                try out.print("  0x{x:0>4} {s}\n", .{ @as(u16, @intCast(value)), name });
            }
        }
    }

    try out.writeAll("key exchange groups (ClientHello offer order):\n");
    const groups = [_]supported_groups.NamedGroup{ .x25519mlkem768, .x25519, .secp256r1 };
    for (groups) |g| {
        try out.print("  0x{x:0>4} {s}\n", .{ g.toInt(), @tagName(g) });
    }

    try out.writeAll("signature schemes:\n");
    const sinfo = @typeInfo(sig_scheme.SignatureScheme).@"enum";
    inline for (sinfo.field_names, sinfo.field_values) |name, value| {
        try out.print("  0x{x:0>4} {s}\n", .{ @as(u16, @intCast(value)), name });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "armorcli ciphers reflects the hardened allow-list, no legacy suites" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try run(&aw.writer);
    const got = aw.written();

    // The three TLS 1.3 suites and the 1.2 ECDHE-GCM set are present.
    try testing.expect(std.mem.indexOf(u8, got, "tls_aes_128_gcm_sha256") != null);
    try testing.expect(std.mem.indexOf(u8, got, "tls_chacha20_poly1305_sha256") != null);
    try testing.expect(std.mem.indexOf(u8, got, "tls_ecdhe_ecdsa_with_aes_256_gcm_sha384") != null);

    // Deliberately-cut legacy never leaks into the listing.
    try testing.expect(std.mem.indexOf(u8, got, "cbc") == null);
    try testing.expect(std.mem.indexOf(u8, got, "rc4") == null);
    try testing.expect(std.mem.indexOf(u8, got, "ccm") == null);
    try testing.expect(std.mem.indexOf(u8, got, "tls_rsa_with") == null);

    // PQ hybrid group and the signature schemes are listed.
    try testing.expect(std.mem.indexOf(u8, got, "x25519mlkem768") != null);
    try testing.expect(std.mem.indexOf(u8, got, "ed25519") != null);
    try testing.expect(std.mem.indexOf(u8, got, "ecdsa_secp256r1_sha256") != null);
}
