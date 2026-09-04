// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Not-yet-implemented `armor` verbs, declared so the framework stays
//! extensible and users get a deterministic exit (3) instead of a confusing
//! "unknown command". Each names the substrate piece a future wiring would
//! sit on:
//!   * s_client / s_server — crypto/tls_client.zig + tls_server.zig exist and
//!     are fully tested; a standalone socket loop is AX-2/AX-3 follow-up.
//!   * enc — the substrate exposes AEADs only (aead.zig); there is no
//!     openssl-enc-compatible KDF/format, and inventing one is out of scope.
//!
//! `ocsp` and `crl` are implemented (`ocsp_cmd.zig` / `crl_cmd.zig`).

const std = @import("std");
const common = @import("common.zig");

const Writer = common.Writer;

pub const stubs = [_][]const u8{ "s_client", "s_server", "enc" };

pub fn isStub(cmd: []const u8) bool {
    for (stubs) |s| {
        if (std.mem.eql(u8, cmd, s)) return true;
    }
    return false;
}

pub fn run(cmd: []const u8, out: *Writer) !void {
    try out.print("armor {s}: not yet implemented\n", .{cmd});
    if (std.mem.eql(u8, cmd, "enc")) {
        try out.writeAll("  (no openssl-enc-compatible format in the substrate; AEAD-only by design)\n");
    } else {
        try out.writeAll("  (Armor TLS client/server exist; a standalone socket loop is follow-up work)\n");
    }
    return error.NotImplemented;
}

const testing = std.testing;

test "armorcli stubs answer deterministically" {
    try testing.expect(isStub("s_client"));
    try testing.expect(!isStub("x509"));
    try testing.expect(!isStub("ocsp"));
    try testing.expect(!isStub("crl"));

    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try testing.expectError(error.NotImplemented, run("enc", &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "not yet implemented") != null);
}
