// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCX AUTH package parser and reply builder.
//!
//! This module owns no authentication state. It parses caller-owned AUTH lines
//! into borrowed request views and renders the server-side AUTH negotiation
//! replies or IRCX error numerics into caller-provided buffers.
const std = @import("std");
const irc_line = @import("irc_line.zig");

pub const IRCERR_AUTHENTICATIONFAILED: u16 = 910;
pub const IRCERR_UNKNOWNPACKAGE: u16 = 912;

pub const ParseError = irc_line.ParseError || error{
    UnknownCommand,
    NeedMoreParams,
    BadSequence,
    UnknownPackage,
};

pub const BuildError = error{
    InvalidToken,
    OutputTooSmall,
};

/// Small set of IRCX/SASL package names understood by this parser.
pub const Package = enum {
    anon,
    plain,
    external,
    scram_sha_256,
    scram_sha_512,
    scram_sha_512_plus,
    session_token,
    oauthbearer,
    anonymous,
    gatekeeper,
    gatekeeper_passport,

    pub fn parse(raw: []const u8) ?Package {
        if (std.ascii.eqlIgnoreCase(raw, "ANON")) return .anon;
        if (std.ascii.eqlIgnoreCase(raw, "PLAIN")) return .plain;
        if (std.ascii.eqlIgnoreCase(raw, "EXTERNAL")) return .external;
        if (std.ascii.eqlIgnoreCase(raw, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.ascii.eqlIgnoreCase(raw, "SCRAM-SHA-512")) return .scram_sha_512;
        if (std.ascii.eqlIgnoreCase(raw, "SCRAM-SHA-512-PLUS")) return .scram_sha_512_plus;
        if (std.ascii.eqlIgnoreCase(raw, "SESSION-TOKEN")) return .session_token;
        if (std.ascii.eqlIgnoreCase(raw, "OAUTHBEARER")) return .oauthbearer;
        if (std.ascii.eqlIgnoreCase(raw, "ANONYMOUS")) return .anonymous;
        if (std.ascii.eqlIgnoreCase(raw, "GateKeeper")) return .gatekeeper;
        if (std.ascii.eqlIgnoreCase(raw, "GateKeeperPassport")) return .gatekeeper_passport;
        return null;
    }

    pub fn token(self: Package) []const u8 {
        return switch (self) {
            .anon => "ANON",
            .plain => "PLAIN",
            .external => "EXTERNAL",
            .scram_sha_256 => "SCRAM-SHA-256",
            .scram_sha_512 => "SCRAM-SHA-512",
            .scram_sha_512_plus => "SCRAM-SHA-512-PLUS",
            .session_token => "SESSION-TOKEN",
            .oauthbearer => "OAUTHBEARER",
            .anonymous => "ANONYMOUS",
            .gatekeeper => "GateKeeper",
            .gatekeeper_passport => "GateKeeperPassport",
        };
    }
};

/// SASL mechanism name for an IRCX AUTH package, or null when the package
/// parses and still has no authenticator. `handleIrcxAuth` answers null with
/// numeric 912.
pub fn saslMechanism(package: Package) ?[]const u8 {
    return switch (package) {
        .plain => "PLAIN",
        .external => "EXTERNAL",
        .scram_sha_256 => "SCRAM-SHA-256",
        .scram_sha_512 => "SCRAM-SHA-512",
        .scram_sha_512_plus => "SCRAM-SHA-512-PLUS",
        .session_token => "SESSION-TOKEN",
        .oauthbearer => "OAUTHBEARER",
        .anonymous => "ANONYMOUS",
        .anon, .gatekeeper, .gatekeeper_passport => null,
    };
}

/// Direction/sequence token on an AUTH line.
pub const Sequence = enum {
    initial,
    client,
    server,
    abort,

    pub fn parse(raw: []const u8) ?Sequence {
        if (std.ascii.eqlIgnoreCase(raw, "I")) return .initial;
        if (std.ascii.eqlIgnoreCase(raw, "C")) return .client;
        if (std.ascii.eqlIgnoreCase(raw, "S")) return .server;
        if (std.mem.eql(u8, raw, "*")) return .abort;
        return null;
    }

    pub fn token(self: Sequence) []const u8 {
        return switch (self) {
            .initial => "I",
            .client => "C",
            .server => "S",
            .abort => "*",
        };
    }
};

/// Parsed `AUTH <package> <seq> [:<data>]` request.
pub const Request = struct {
    package: Package,
    package_raw: []const u8,
    sequence: Sequence,
    data: ?[]const u8 = null,

    pub fn packageToken(self: Request) []const u8 {
        return self.package.token();
    }
};

pub const NumericContext = struct {
    server_name: []const u8,
    recipient_nick: []const u8,
};

/// Parse a raw IRC line whose command must be `AUTH`.
pub fn parse(line: []const u8) ParseError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "AUTH")) return error.UnknownCommand;
    return parseParams(parsed.paramSlice());
}

/// Parse AUTH parameters excluding the command name.
pub fn parseParams(params: []const []const u8) ParseError!Request {
    if (params.len < 2) return error.NeedMoreParams;

    const package = Package.parse(params[0]) orelse return error.UnknownPackage;
    const sequence = Sequence.parse(params[1]) orelse return error.BadSequence;

    return .{
        .package = package,
        .package_raw = params[0],
        .sequence = sequence,
        .data = if (params.len > 2) params[2] else null,
    };
}

/// Build `AUTH <package> S [:<data>]` for a server challenge.
pub fn buildChallenge(out: []u8, package: Package, data: ?[]const u8) BuildError![]const u8 {
    var writer = BufferWriter.init(out);
    try writer.append("AUTH ");
    try writer.append(package.token());
    try writer.append(" S");
    if (data) |payload| {
        try validateText(payload);
        try writer.append(" :");
        try writer.append(payload);
    }
    try writer.crlf();
    return writer.slice();
}

/// Build `AUTH <package> * <ident> <oid>` for successful authorization.
pub fn buildAck(out: []u8, package: Package, ident: []const u8, oid: []const u8) BuildError![]const u8 {
    try validateToken(ident);
    try validateToken(oid);

    var writer = BufferWriter.init(out);
    try writer.append("AUTH ");
    try writer.append(package.token());
    try writer.append(" * ");
    try writer.append(ident);
    try writer.append(" ");
    try writer.append(oid);
    try writer.crlf();
    return writer.slice();
}

pub fn buildUnknownPackageReply(
    out: []u8,
    context: NumericContext,
    package_name: []const u8,
) BuildError![]const u8 {
    return buildNumericReply(
        out,
        context,
        IRCERR_UNKNOWNPACKAGE,
        package_name,
        "Unsupported authentication package",
    );
}

pub fn buildAuthenticationFailedReply(
    out: []u8,
    context: NumericContext,
    package_name: []const u8,
) BuildError![]const u8 {
    return buildNumericReply(
        out,
        context,
        IRCERR_AUTHENTICATIONFAILED,
        package_name,
        "Authentication failed",
    );
}

fn buildNumericReply(
    out: []u8,
    context: NumericContext,
    code: u16,
    subject: []const u8,
    text: []const u8,
) BuildError![]const u8 {
    try validateToken(context.server_name);
    try validateToken(context.recipient_nick);
    try validateToken(subject);
    try validateText(text);

    var writer = BufferWriter.init(out);
    try writer.append(":");
    try writer.append(context.server_name);
    try writer.append(" ");
    const code_buf = formatCode(code);
    try writer.append(&code_buf);
    try writer.append(" ");
    try writer.append(context.recipient_nick);
    try writer.append(" ");
    try writer.append(subject);
    try writer.append(" :");
    try writer.append(text);
    try writer.crlf();
    return writer.slice();
}

fn validateToken(token_bytes: []const u8) BuildError!void {
    if (token_bytes.len == 0) return error.InvalidToken;
    for (token_bytes) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', ':' => return error.InvalidToken,
            else => {},
        }
    }
}

fn validateText(text: []const u8) BuildError!void {
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidToken,
            else => {},
        }
    }
}

fn formatCode(code: u16) [3]u8 {
    return .{
        @as(u8, '0') + @as(u8, @intCast((code / 100) % 10)),
        @as(u8, '0') + @as(u8, @intCast((code / 10) % 10)),
        @as(u8, '0') + @as(u8, @intCast(code % 10)),
    };
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn append(self: *BufferWriter, bytes: []const u8) BuildError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn crlf(self: *BufferWriter) BuildError!void {
        try self.append("\r\n");
    }
};

test "parse AUTH package forms" {
    const allocator = std.testing.allocator;
    const plain_line = try allocator.dupe(u8, "AUTH PLAIN C :AGthAGI=\r\n");
    defer allocator.free(plain_line);

    const plain = try parse(plain_line);
    try std.testing.expectEqual(.plain, plain.package);
    try std.testing.expectEqual(.client, plain.sequence);
    try std.testing.expectEqualStrings("AGthAGI=", plain.data.?);

    const anon = try parse("AUTH ANON S :+\n");
    try std.testing.expectEqual(.anon, anon.package);
    try std.testing.expectEqual(.server, anon.sequence);
    try std.testing.expectEqualStrings("+", anon.data.?);

    const gkp = try parse("AUTH GateKeeperPassport I :ticket profile");
    try std.testing.expectEqual(.gatekeeper_passport, gkp.package);
    try std.testing.expectEqual(.initial, gkp.sequence);
    try std.testing.expectEqualStrings("ticket profile", gkp.data.?);
}

test "GAP-P0c classic IRCX AUTH packages stay an unknown package" {
    const classic = [_][]const u8{ "ANON", "GateKeeper", "GateKeeperPassport" };
    for (classic) |name| {
        const req = try parseParams(&.{ name, "I" });
        try std.testing.expect(saslMechanism(req.package) == null);
        var buf: [160]u8 = undefined;
        const line = try buildUnknownPackageReply(&buf, .{
            .server_name = "irc.example",
            .recipient_nick = "alice",
        }, req.package_raw);
        try std.testing.expect(std.mem.indexOf(u8, line, " 912 ") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "Unsupported authentication package") != null);
        try std.testing.expect(std.mem.indexOf(u8, line, name) != null);
    }
    try std.testing.expectEqualStrings("PLAIN", saslMechanism(.plain).?);
    try std.testing.expectEqualStrings("ANONYMOUS", saslMechanism(.anonymous).?);
    std.debug.print("GAP-P0c branch=ANON GateKeeper and GateKeeperPassport reply 912 and stay off the SASL list\n", .{});
}

test "parse AUTH rejects unknown package" {
    const allocator = std.testing.allocator;
    const params = try allocator.alloc([]const u8, 3);
    defer allocator.free(params);
    params[0] = "NOPE";
    params[1] = "C";
    params[2] = "payload";

    try std.testing.expectError(error.UnknownPackage, parseParams(params));
    try std.testing.expectEqual(@as(u16, 912), IRCERR_UNKNOWNPACKAGE);
}

test "build challenge and ack exact bytes" {
    var buf: [128]u8 = undefined;

    const challenge = try buildChallenge(&buf, .gatekeeper_passport, "nonce");
    try std.testing.expectEqualStrings("AUTH GateKeeperPassport S :nonce\r\n", challenge);

    const empty_challenge = try buildChallenge(&buf, .plain, null);
    try std.testing.expectEqualStrings("AUTH PLAIN S\r\n", empty_challenge);

    const ack = try buildAck(&buf, .plain, "user@example.test", "0");
    try std.testing.expectEqualStrings("AUTH PLAIN * user@example.test 0\r\n", ack);
}

test "build unknown package numeric exact bytes" {
    var buf: [128]u8 = undefined;
    const reply = try buildUnknownPackageReply(
        &buf,
        .{ .server_name = "irc.example", .recipient_nick = "*" },
        "MAGIC",
    );
    try std.testing.expectEqualStrings(
        ":irc.example 912 * MAGIC :Unsupported authentication package\r\n",
        reply,
    );
}

test "build authentication failure numeric exact bytes" {
    var buf: [128]u8 = undefined;
    const reply = try buildAuthenticationFailedReply(
        &buf,
        .{ .server_name = "irc.example", .recipient_nick = "kain" },
        "PLAIN",
    );
    try std.testing.expectEqualStrings(
        ":irc.example 910 kain PLAIN :Authentication failed\r\n",
        reply,
    );
}
