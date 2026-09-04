// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor` — the Armor crypto toolkit executable (openssl-parity verbs backed
//! by Onyx Server's pure-Zig substrate). Dispatches `armor <cmd> [opts]`, buffers
//! subcommand output, and maps failures to deterministic, scriptable exits:
//!   0 success · 1 operation failed · 2 usage error · 3 not implemented

const std = @import("std");
const cli = @import("root.zig");

const common = cli.common;
const Writer = common.Writer;

fn topUsage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\armor — pure-Zig crypto toolkit (openssl-parity, Armor substrate)
        \\
        \\usage: armor <command> [options]   (armor <command> --help for details)
        \\
        \\commands:
        \\  x509        display/convert certificates (-text, -fingerprint, PEM<->DER)
        \\  genpkey     generate a private key (ec = ECDSA P-256, ed25519); files 0600
        \\  pkey        inspect a private key
        \\  req         create a PKCS#10 CSR from a key
        \\  dgst        SHA-256/384/512 digest or HMAC (key from file, never argv)
        \\  verify      verify a certificate chain against a CA bundle
        \\  rand        cryptographically-random bytes (raw/-hex/-base64)
        \\  ciphers     list supported TLS suites, groups, signature schemes
        \\  asn1parse   dump a DER structure
        \\  ocsp        display/verify a stapled OCSP response (no HTTP fetch)
        \\  crl         display/verify an X.509 CRL (no HTTP fetch)
        \\  s_client    TLS client (loopback handshake; live -connect is follow-up)
        \\  s_server / enc   not yet implemented (exit 3)
        \\
        \\exit codes: 0 ok, 1 failed, 2 usage, 3 not implemented
        \\
    );
}

fn wantsHelp(args: []const []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "-help")) return true;
    }
    return false;
}

fn dispatch(gpa: std.mem.Allocator, io: std.Io, cmd: []const u8, args: []const []const u8, out: *Writer) !void {
    if (std.mem.eql(u8, cmd, "x509")) {
        if (wantsHelp(args)) return cli.x509_cmd.usage(out);
        return cli.x509_cmd.run(gpa, io, try cli.x509_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "genpkey")) {
        if (wantsHelp(args)) return cli.pkey_cmd.genUsage(out);
        return cli.pkey_cmd.runGen(gpa, io, try cli.pkey_cmd.parseGenArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "pkey")) {
        if (wantsHelp(args)) return cli.pkey_cmd.inspectUsage(out);
        return cli.pkey_cmd.runInspect(gpa, io, try cli.pkey_cmd.parseInspectArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "req")) {
        if (wantsHelp(args)) return cli.req_cmd.usage(out);
        return cli.req_cmd.run(gpa, io, try cli.req_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "dgst")) {
        if (wantsHelp(args)) return cli.dgst_cmd.usage(out);
        return cli.dgst_cmd.run(gpa, io, try cli.dgst_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "verify")) {
        if (wantsHelp(args)) return cli.verify_cmd.usage(out);
        return cli.verify_cmd.run(gpa, io, try cli.verify_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "rand")) {
        if (wantsHelp(args)) return cli.rand_cmd.usage(out);
        return cli.rand_cmd.run(gpa, io, try cli.rand_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "ciphers")) {
        if (wantsHelp(args)) return cli.ciphers_cmd.usage(out);
        try cli.ciphers_cmd.parseArgs(args);
        return cli.ciphers_cmd.run(out);
    }
    if (std.mem.eql(u8, cmd, "asn1parse")) {
        if (wantsHelp(args)) return cli.asn1parse_cmd.usage(out);
        return cli.asn1parse_cmd.run(gpa, io, try cli.asn1parse_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "ocsp")) {
        if (wantsHelp(args)) return cli.ocsp_cmd.usage(out);
        return cli.ocsp_cmd.run(gpa, io, try cli.ocsp_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "crl")) {
        if (wantsHelp(args)) return cli.crl_cmd.usage(out);
        return cli.crl_cmd.run(gpa, io, try cli.crl_cmd.parseArgs(args), out);
    }
    if (std.mem.eql(u8, cmd, "s_client")) {
        if (wantsHelp(args)) return cli.s_client_cmd.usage(out);
        return cli.s_client_cmd.run(gpa, io, try cli.s_client_cmd.parseArgs(args), out);
    }
    if (cli.stub_cmds.isStub(cmd)) return cli.stub_cmds.run(cmd, out);
    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        return topUsage(out);
    }
    return error.Usage;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var args_it = try std.process.Args.iterateAllocator(init.minimal.args, gpa);
    defer args_it.deinit();
    _ = args_it.next(); // argv[0]

    var rest: std.ArrayList([]const u8) = .empty;
    defer rest.deinit(gpa);
    const cmd = args_it.next() orelse {
        var aw = Writer.Allocating.init(gpa);
        defer aw.deinit();
        topUsage(&aw.writer) catch {};
        std.Io.File.stderr().writeStreamingAll(io, aw.written()) catch {};
        std.process.exit(2);
    };
    while (args_it.next()) |a| try rest.append(gpa, a);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();

    dispatch(gpa, io, cmd, rest.items, &aw.writer) catch |err| {
        // Flush whatever the subcommand produced (stub notices, partial help).
        std.Io.File.stdout().writeStreamingAll(io, aw.written()) catch {};
        switch (err) {
            error.Usage => {
                var uw = Writer.Allocating.init(gpa);
                defer uw.deinit();
                usageFor(cmd, &uw.writer) catch {};
                std.Io.File.stderr().writeStreamingAll(io, uw.written()) catch {};
                std.process.exit(2);
            },
            error.NotImplemented => std.process.exit(3),
            else => {
                std.debug.print("armor {s}: {s}\n", .{ cmd, @errorName(err) });
                std.process.exit(1);
            },
        }
    };
    try std.Io.File.stdout().writeStreamingAll(io, aw.written());
}

fn usageFor(cmd: []const u8, w: *Writer) Writer.Error!void {
    if (std.mem.eql(u8, cmd, "x509")) return cli.x509_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "genpkey")) return cli.pkey_cmd.genUsage(w);
    if (std.mem.eql(u8, cmd, "pkey")) return cli.pkey_cmd.inspectUsage(w);
    if (std.mem.eql(u8, cmd, "req")) return cli.req_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "dgst")) return cli.dgst_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "verify")) return cli.verify_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "rand")) return cli.rand_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "ciphers")) return cli.ciphers_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "asn1parse")) return cli.asn1parse_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "ocsp")) return cli.ocsp_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "crl")) return cli.crl_cmd.usage(w);
    if (std.mem.eql(u8, cmd, "s_client")) return cli.s_client_cmd.usage(w);
    return topUsage(w);
}

test {
    _ = @import("root.zig");
}

const testing = std.testing;

test "armor dispatch routes ciphers and rejects unknown commands" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try dispatch(testing.allocator, std.testing.io, "ciphers", &.{}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "x25519mlkem768") != null);

    aw.clearRetainingCapacity();
    try testing.expectError(error.Usage, dispatch(testing.allocator, std.testing.io, "nonsense", &.{}, &aw.writer));
    try testing.expectError(error.Usage, dispatch(testing.allocator, std.testing.io, "s_client", &.{}, &aw.writer));
    try testing.expectError(error.NotImplemented, dispatch(testing.allocator, std.testing.io, "enc", &.{}, &aw.writer));
    try testing.expectError(error.NotImplemented, dispatch(testing.allocator, std.testing.io, "s_server", &.{}, &aw.writer));

    aw.clearRetainingCapacity();
    try dispatch(testing.allocator, std.testing.io, "ocsp", &.{"--help"}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "usage: armor ocsp") != null);
    aw.clearRetainingCapacity();
    try dispatch(testing.allocator, std.testing.io, "crl", &.{"--help"}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "usage: armor crl") != null);
}

test "armor per-command --help renders without touching inputs" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try dispatch(testing.allocator, std.testing.io, "x509", &.{"--help"}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "usage: armor x509") != null);

    aw.clearRetainingCapacity();
    try dispatch(testing.allocator, std.testing.io, "genpkey", &.{"-h"}, &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "usage: armor genpkey") != null);
}
