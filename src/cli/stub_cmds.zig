// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Not-yet-implemented `armor` verbs, declared so the framework stays
//! extensible and users get a deterministic exit (3) instead of a confusing
//! "unknown command". Every verb that used to live here is now implemented:
//! `s_client` / `s_server` (live TLS 1.3 over TCP), `enc` (AEAD-only,
//! Argon2id passphrase file), `ocsp` (including `-fetch`) and `crl`.

const std = @import("std");
const common = @import("common.zig");

const Writer = common.Writer;

pub const stubs = [_][]const u8{};

pub fn isStub(cmd: []const u8) bool {
    for (stubs) |s| {
        if (std.mem.eql(u8, cmd, s)) return true;
    }
    return false;
}

pub fn run(cmd: []const u8, out: *Writer) !void {
    try out.print("armor {s}: not yet implemented\n", .{cmd});
    return error.NotImplemented;
}

const testing = std.testing;

test "armorcli stubs no longer shadow implemented verbs" {
    for ([_][]const u8{ "s_client", "s_server", "enc", "ocsp", "crl", "x509", "ech-gen", "dc" }) |cmd| {
        try testing.expect(!isStub(cmd));
    }
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try testing.expectError(error.NotImplemented, run("future", &aw.writer));
    try testing.expect(std.mem.indexOf(u8, aw.written(), "not yet implemented") != null);
}
