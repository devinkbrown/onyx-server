// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extended ban parser and matcher.
//!
//! Ban masks are parsed once into a small fixed-node matcher. Matching borrows
//! the parsed pattern slices and the caller's client context, so the hot path is
//! allocation-free and bounded by the supplied pattern and channel list.
const std = @import("std");
const cloak_match = @import("cloak_match.zig");

/// Maximum bytes accepted for one ban mask.
pub const MAX_MASK_BYTES: usize = 512;

/// Default number of AST nodes for nested negation chains.
pub const DEFAULT_MAX_NODES: usize = 8;

pub const ParseError = error{
    EmptyMask,
    OversizeMask,
    InvalidByte,
    MissingType,
    MissingDelimiter,
    EmptyPattern,
    UnexpectedPattern,
    UnknownType,
    TooDeep,
};

/// Parsed matcher node kind.
pub const NodeKind = enum {
    hostmask,
    account,
    realname,
    country,
    channel,
    secure,
    mute,
    oper,
    negation,
};

/// Maximum bytes accepted for a `$z:<fingerprint>` certfp pattern. The daemon
/// renders certfps as a lowercase SHA-256 hex string (64 chars via
/// `certfp.certfpHex`); a small headroom guards against pasted whitespace-free
/// junk without admitting an unbounded pattern. Patterns over this length are
/// rejected at parse time.
pub const MAX_CERTFP_PATTERN_BYTES: usize = 128;

/// One client view used by extended-ban matching.
///
/// All slices are caller-owned. `host` is the normalized hostmask/host string
/// used for plain ban mask fallthrough.
pub const ClientContext = struct {
    cloak_context: ?cloak_match.Context = null,
    account: ?[]const u8 = null,
    realname: []const u8 = "",
    host: []const u8 = "",
    country: ?[]const u8 = null,
    channels: []const []const u8 = &.{},
    /// True when the client is connected over a secure (TLS) transport. Used by
    /// the bare `$z` secure-connection extban.
    secure: bool = false,
    /// The client's TLS certificate fingerprint as the daemon renders it
    /// (lowercase SHA-256 hex via `certfp.certfpHex`), or null when the client
    /// presented no certificate / is not on TLS. Used by the patterned
    /// `$z:<fingerprint>` extban. A null certfp NEVER matches a `$z:<fp>` ban.
    certfp: ?[]const u8 = null,
    /// True when the client holds IRC operator status. Used by the bare `$o`
    /// oper-status extban (most useful in `+e`/`+I` exception lists).
    is_oper: bool = false,
    /// The client's oper class/name (empty when not an oper or unknown). Used by
    /// the patterned `$o:<class>` extban. An empty class NEVER matches a
    /// `$o:<class>` ban.
    oper_class: []const u8 = "",
};

pub const Node = union(NodeKind) {
    hostmask: []const u8,
    account: []const u8,
    realname: []const u8,
    country: []const u8,
    channel: []const u8,
    /// `$z` secure-connection. An EMPTY pattern (bare `$z`) matches any client
    /// on a TLS transport. A NON-EMPTY pattern (`$z:<fingerprint>`) matches only
    /// a client whose TLS certfp equals the pattern (exact, case-insensitive
    /// hex); a non-TLS / null-certfp client never matches a patterned `$z`.
    secure: []const u8,
    /// `$m` mute (quiet): a hostmask-style pattern, but classified separately so
    /// the ban-check path can apply it as speech suppression rather than a join
    /// denial. Matching semantics are identical to a plain hostmask.
    mute: []const u8,
    /// `$o` oper-status. An EMPTY pattern (bare `$o`) matches any client holding
    /// IRC operator status. A NON-EMPTY pattern (`$o:<class>`) matches only an
    /// oper whose class/name equals the pattern (case-insensitive, glob-capable
    /// like other named patterns); a non-oper / empty-class client never matches
    /// a patterned `$o`.
    oper: []const u8,
    negation: usize,
};

/// Return a fixed-capacity matcher type.
pub fn Matcher(comptime max_nodes: usize) type {
    comptime {
        if (max_nodes == 0) @compileError("extban matcher needs at least one node");
    }

    return struct {
        const Self = @This();

        nodes: [max_nodes]Node = @splat(.{ .hostmask = "" }),
        node_count: usize = 0,
        root: usize = 0,

        /// Parse one plain hostmask or extended-ban mask.
        pub fn parse(input: []const u8) ParseError!Self {
            try validateInput(input);

            var matcher = Self{};
            matcher.root = try matcher.parseExpression(input);
            return matcher;
        }

        /// Match this parsed ban against a client context.
        pub fn matches(self: *const Self, ctx: ClientContext) bool {
            if (self.node_count == 0) return false;
            return self.matchNode(self.root, ctx);
        }

        /// Kind of the root node, useful for callers that need to classify bans.
        pub fn rootKind(self: *const Self) NodeKind {
            return nodeKind(self.nodes[self.root]);
        }

        /// Semantic kind after unwrapping root negation chains. Callers use this
        /// to keep `$m` quiet extbans out of join-denial paths even when negated.
        pub fn rootMatchKind(self: *const Self) NodeKind {
            if (self.node_count == 0) return .hostmask;
            return self.matchKind(self.root);
        }

        /// Pattern stored at the root node when it is a leaf matcher.
        pub fn rootPattern(self: *const Self) ?[]const u8 {
            return switch (self.nodes[self.root]) {
                .hostmask => |pattern| pattern,
                .account => |pattern| pattern,
                .realname => |pattern| pattern,
                .country => |pattern| pattern,
                .channel => |pattern| pattern,
                .secure => |pattern| pattern,
                .mute => |pattern| pattern,
                .oper => |pattern| pattern,
                .negation => null,
            };
        }

        fn parseExpression(self: *Self, input: []const u8) ParseError!usize {
            if (input.len == 0) return error.EmptyMask;
            if (input[0] != '$') return self.appendNode(.{ .hostmask = input });
            return self.parseDollar(input);
        }

        fn parseDollar(self: *Self, input: []const u8) ParseError!usize {
            if (input.len < 2) return error.MissingType;

            if (input[1] == '~') {
                if (input.len < 3) return error.EmptyPattern;

                const rest = input[2..];
                const child = if (rest[0] == ':') blk: {
                    if (rest.len == 1) return error.EmptyPattern;
                    break :blk try self.parseExpression(rest[1..]);
                } else if (rest[0] == '$') blk: {
                    break :blk try self.parseExpression(rest);
                } else blk: {
                    break :blk try self.parseTyped(rest);
                };

                return self.appendNode(.{ .negation = child });
            }

            return self.parseTyped(input[1..]);
        }

        fn parseTyped(self: *Self, typed: []const u8) ParseError!usize {
            if (typed.len == 0) return error.MissingType;

            // `$z` (secure connection). Bare `$z` (no pattern) matches any TLS
            // client. Patterned `$z:<fingerprint>` matches a specific TLS
            // certificate fingerprint: a bounded, non-empty string compared
            // exactly and case-insensitively against the client's rendered
            // certfp at match time. `$z:` with an empty pattern is rejected so a
            // stored mask cannot silently match everything or nothing.
            if (typed[0] == 'z') {
                if (typed.len == 1) return self.appendNode(.{ .secure = "" });
                if (typed[1] != ':') return error.MissingDelimiter;
                if (typed.len == 2) return error.EmptyPattern;
                const fingerprint = typed[2..];
                if (fingerprint.len > MAX_CERTFP_PATTERN_BYTES) return error.OversizeMask;
                return self.appendNode(.{ .secure = fingerprint });
            }

            // `$o` (oper status). Bare `$o` (no pattern) matches any oper.
            // Patterned `$o:<class>` matches an oper of a specific class/name:
            // a non-empty pattern compared against the client's oper class at
            // match time. `$o:` with an empty pattern is rejected.
            if (typed[0] == 'o') {
                if (typed.len == 1) return self.appendNode(.{ .oper = "" });
                if (typed[1] != ':') return error.MissingDelimiter;
                if (typed.len == 2) return error.EmptyPattern;
                return self.appendNode(.{ .oper = typed[2..] });
            }

            if (typed.len < 2 or typed[1] != ':') return error.MissingDelimiter;
            if (typed.len == 2) return error.EmptyPattern;

            const pattern = typed[2..];
            return switch (typed[0]) {
                'a' => self.appendNode(.{ .account = pattern }),
                'r' => self.appendNode(.{ .realname = pattern }),
                'g' => self.appendNode(.{ .country = pattern }),
                'c' => self.appendNode(.{ .channel = pattern }),
                'm' => self.appendNode(.{ .mute = pattern }),
                else => error.UnknownType,
            };
        }

        fn appendNode(self: *Self, node: Node) ParseError!usize {
            if (self.node_count >= max_nodes) return error.TooDeep;
            const index = self.node_count;
            self.nodes[index] = node;
            self.node_count += 1;
            return index;
        }

        fn matchNode(self: *const Self, index: usize, ctx: ClientContext) bool {
            if (index >= self.node_count) return false;

            return switch (self.nodes[index]) {
                .hostmask => |pattern| cloak_match.match(pattern, ctx.host, ctx.cloak_context),
                .account => |pattern| if (ctx.account) |account| patternMatch(pattern, account) else false,
                .realname => |pattern| patternMatch(pattern, ctx.realname),
                .country => |pattern| if (ctx.country) |country| patternMatch(pattern, country) else false,
                .channel => |pattern| matchAnyChannel(pattern, ctx.channels),
                .secure => |pattern| matchSecure(pattern, ctx),
                .mute => |pattern| cloak_match.match(pattern, ctx.host, ctx.cloak_context),
                .oper => |pattern| matchOper(pattern, ctx),
                .negation => |child| !self.matchNode(child, ctx),
            };
        }

        fn matchKind(self: *const Self, index: usize) NodeKind {
            if (index >= self.node_count) return .hostmask;
            return switch (self.nodes[index]) {
                .negation => |child| self.matchKind(child),
                else => nodeKind(self.nodes[index]),
            };
        }
    };
}

/// Default matcher used by simple callers and tests.
pub const ExtbanMatcher = Matcher(DEFAULT_MAX_NODES);

/// Parse using the default matcher capacity.
pub fn parse(input: []const u8) ParseError!ExtbanMatcher {
    return ExtbanMatcher.parse(input);
}

fn nodeKind(node: Node) NodeKind {
    return switch (node) {
        .hostmask => .hostmask,
        .account => .account,
        .realname => .realname,
        .country => .country,
        .channel => .channel,
        .secure => .secure,
        .mute => .mute,
        .oper => .oper,
        .negation => .negation,
    };
}

fn matchAnyChannel(pattern: []const u8, channels: []const []const u8) bool {
    for (channels) |channel| {
        if (patternMatch(pattern, channel)) return true;
    }
    return false;
}

/// Evaluate a `$z` secure-connection node.
///
/// - EMPTY pattern (bare `$z`): match any TLS client, independent of certfp.
/// - NON-EMPTY pattern (`$z:<fingerprint>`): match ONLY when the client
///   presented a certfp AND it equals the pattern. The compare is exact,
///   case-insensitive hex — no globbing — so the ban applies to exactly the
///   intended fingerprint and nothing else. A client with a null certfp (no
///   cert / non-TLS) never matches; absence cannot bypass nor falsely match.
fn matchSecure(pattern: []const u8, ctx: ClientContext) bool {
    if (pattern.len == 0) return ctx.secure;
    const presented = ctx.certfp orelse return false;
    if (presented.len == 0) return false;
    return constantTimeEqlAsciiFold(pattern, presented);
}

/// Evaluate a `$o` oper-status node.
///
/// - EMPTY pattern (bare `$o`): match any oper.
/// - NON-EMPTY pattern (`$o:<class>`): match ONLY when the client is an oper AND
///   the supplied oper class is non-empty AND matches the pattern
///   (case-insensitive, glob-capable like other named patterns). A non-oper or
///   a client with an unknown/empty class never matches a patterned `$o`.
fn matchOper(pattern: []const u8, ctx: ClientContext) bool {
    if (pattern.len == 0) return ctx.is_oper;
    if (!ctx.is_oper) return false;
    if (ctx.oper_class.len == 0) return false;
    return patternMatch(pattern, ctx.oper_class);
}

fn validateInput(input: []const u8) ParseError!void {
    if (input.len == 0) return error.EmptyMask;
    if (input.len > MAX_MASK_BYTES) return error.OversizeMask;

    for (input) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', '\t', 0x7f => return error.InvalidByte,
            else => {
                if (ch < 0x20) return error.InvalidByte;
            },
        }
    }
}

fn patternMatch(pattern: []const u8, value: []const u8) bool {
    if (hasGlobMeta(pattern)) return globMatch(pattern, value);
    return constantTimeEqlAsciiFold(pattern, value);
}

fn hasGlobMeta(pattern: []const u8) bool {
    for (pattern) |ch| {
        if (ch == '*' or ch == '?') return true;
    }
    return false;
}

/// Case-insensitive IRC-style glob. Supports `*` and `?`.
fn globMatch(pattern: []const u8, value: []const u8) bool {
    if (pattern.len == 0) return value.len == 0;

    var p: usize = 0;
    var v: usize = 0;
    var star: ?usize = null;
    var retry_v: usize = 0;

    while (v < value.len) {
        if (p < pattern.len and (pattern[p] == '?' or asciiLower(pattern[p]) == asciiLower(value[v]))) {
            p += 1;
            v += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry_v = v;
        } else if (star) |star_pos| {
            p = star_pos + 1;
            retry_v += 1;
            v = retry_v;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn constantTimeEqlAsciiFold(a: []const u8, b: []const u8) bool {
    const max_len = @max(a.len, b.len);
    var diff: usize = a.len ^ b.len;

    var idx: usize = 0;
    while (idx < max_len) : (idx += 1) {
        const ac: u8 = if (idx < a.len) asciiLower(a[idx]) else 0;
        const bc: u8 = if (idx < b.len) asciiLower(b[idx]) else 0;
        diff |= @as(usize, ac ^ bc);
    }

    return diff == 0;
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

test "parses each extended ban type" {
    const account = try parse("$a:alice");
    try std.testing.expectEqual(NodeKind.account, account.rootKind());
    try std.testing.expectEqualStrings("alice", account.rootPattern().?);

    const realname = try parse("$r:*Example*");
    try std.testing.expectEqual(NodeKind.realname, realname.rootKind());
    try std.testing.expectEqualStrings("*Example*", realname.rootPattern().?);

    const country = try parse("$g:DE");
    try std.testing.expectEqual(NodeKind.country, country.rootKind());
    try std.testing.expectEqualStrings("DE", country.rootPattern().?);

    const channel = try parse("$c:#ops");
    try std.testing.expectEqual(NodeKind.channel, channel.rootKind());
    try std.testing.expectEqualStrings("#ops", channel.rootPattern().?);

    const secure = try parse("$z");
    try std.testing.expectEqual(NodeKind.secure, secure.rootKind());

    const mute = try parse("$m:*!*@spam.example");
    try std.testing.expectEqual(NodeKind.mute, mute.rootKind());
    try std.testing.expectEqualStrings("*!*@spam.example", mute.rootPattern().?);

    const oper = try parse("$o");
    try std.testing.expectEqual(NodeKind.oper, oper.rootKind());
}

test "matches secure-connection extban" {
    const secure_ban = try parse("$z");
    try std.testing.expect(secure_ban.matches(.{ .secure = true }));
    try std.testing.expect(!secure_ban.matches(.{ .secure = false }));

    // Negation: ban everyone NOT on a secure connection.
    const insecure_ban = try parse("$~z");
    try std.testing.expect(!insecure_ban.matches(.{ .secure = true }));
    try std.testing.expect(insecure_ban.matches(.{ .secure = false }));

    // Bare `$z` must NOT require a fingerprint: a TLS client with no certfp
    // still matches.
    try std.testing.expect(secure_ban.matches(.{ .secure = true, .certfp = null }));
}

test "parses patterned certfp secure extban" {
    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const matcher = try parse("$z:" ++ fp);
    try std.testing.expectEqual(NodeKind.secure, matcher.rootKind());
    try std.testing.expectEqualStrings(fp, matcher.rootPattern().?);

    // Empty pattern after the delimiter is rejected (no silent match-all).
    try std.testing.expectError(error.EmptyPattern, parse("$z:"));

    // Pattern length is bounded.
    const oversize = &@as([(MAX_CERTFP_PATTERN_BYTES + 1)]u8, @splat('z'));
    try std.testing.expectError(error.OversizeMask, parse("$z:" ++ oversize));
}

test "matches certfp secure extban only on the exact fingerprint" {
    const fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const other = "0000000000000000000000000000000000000000000000000000000000000000";
    const ban = try parse("$z:" ++ fp);

    // Exact fingerprint match (client is TLS and presents the banned cert).
    try std.testing.expect(ban.matches(.{ .secure = true, .certfp = fp }));

    // Case-insensitive hex compare: an operator-entered uppercase fp still
    // matches the daemon's lowercase rendering and vice-versa.
    const fp_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    try std.testing.expect(ban.matches(.{ .secure = true, .certfp = fp_upper }));

    // A DIFFERENT certfp must NOT match (no over-broad ban).
    try std.testing.expect(!ban.matches(.{ .secure = true, .certfp = other }));

    // A non-TLS / null-certfp client must NOT match a `$z:<fp>` ban: absence
    // neither matches nor bypasses.
    try std.testing.expect(!ban.matches(.{ .secure = false, .certfp = null }));
    // Even a TLS client with no presented cert (null certfp) must NOT match.
    try std.testing.expect(!ban.matches(.{ .secure = true, .certfp = null }));
    // An empty-string certfp must NOT match either.
    try std.testing.expect(!ban.matches(.{ .secure = true, .certfp = "" }));
}

test "matches negated certfp secure extban" {
    const fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const other = "0000000000000000000000000000000000000000000000000000000000000000";
    // `$~z:<fp>` (e.g. +e exception): true for everyone EXCEPT the banned fp.
    const neg = try parse("$~z:" ++ fp);
    try std.testing.expectEqual(NodeKind.negation, neg.rootKind());
    try std.testing.expectEqual(NodeKind.secure, neg.rootMatchKind());

    try std.testing.expect(!neg.matches(.{ .secure = true, .certfp = fp }));
    try std.testing.expect(neg.matches(.{ .secure = true, .certfp = other }));
    // A null-certfp client does not match `$z:<fp>`, so the negation is true.
    try std.testing.expect(neg.matches(.{ .secure = true, .certfp = null }));
}

test "matches patterned oper-class extban" {
    const ban = try parse("$o:netadmin");
    try std.testing.expectEqual(NodeKind.oper, ban.rootKind());
    try std.testing.expectEqualStrings("netadmin", ban.rootPattern().?);

    // Matching class on an oper.
    try std.testing.expect(ban.matches(.{ .is_oper = true, .oper_class = "netadmin" }));
    // Case-insensitive.
    try std.testing.expect(ban.matches(.{ .is_oper = true, .oper_class = "NetAdmin" }));
    // Different class on an oper must NOT match.
    try std.testing.expect(!ban.matches(.{ .is_oper = true, .oper_class = "helper" }));
    // A non-oper must NOT match a `$o:<class>` ban even if the class string is
    // somehow set.
    try std.testing.expect(!ban.matches(.{ .is_oper = false, .oper_class = "netadmin" }));
    // An oper with an empty/unknown class must NOT match.
    try std.testing.expect(!ban.matches(.{ .is_oper = true, .oper_class = "" }));

    // Glob-capable like other named patterns.
    const glob = try parse("$o:net*");
    try std.testing.expect(glob.matches(.{ .is_oper = true, .oper_class = "netadmin" }));
    try std.testing.expect(!glob.matches(.{ .is_oper = true, .oper_class = "helper" }));

    // Empty pattern after the delimiter is rejected.
    try std.testing.expectError(error.EmptyPattern, parse("$o:"));
}

test "matches mute extban against host like a plain hostmask" {
    const mute = try parse("$m:*.spam.example");
    try std.testing.expectEqual(NodeKind.mute, mute.rootMatchKind());
    try std.testing.expect(mute.matches(.{ .host = "node.spam.example" }));
    try std.testing.expect(!mute.matches(.{ .host = "node.good.example" }));

    const negated_mute = try parse("$~m:*.trusted.example");
    try std.testing.expectEqual(NodeKind.negation, negated_mute.rootKind());
    try std.testing.expectEqual(NodeKind.mute, negated_mute.rootMatchKind());
}

test "matches positive and negative account extbans" {
    const matched = ClientContext{ .account = "alice" };
    const missed = ClientContext{ .account = "bob" };

    const exact = try parse("$a:ALICE");
    try std.testing.expect(exact.matches(matched));
    try std.testing.expect(!exact.matches(missed));

    const glob = try parse("$a:a*");
    try std.testing.expect(glob.matches(matched));
    try std.testing.expect(!glob.matches(missed));
}

test "matches realname country and channel extbans" {
    const chans = [_][]const u8{ "#opers", "#chat" };
    const ctx = ClientContext{
        .realname = "Alice Example",
        .country = "de",
        .channels = &chans,
    };

    const realname = try parse("$r:*example");
    try std.testing.expect(realname.matches(ctx));

    const country = try parse("$g:DE");
    try std.testing.expect(country.matches(ctx));

    const channel = try parse("$c:#OPERS");
    try std.testing.expect(channel.matches(ctx));
    const missed_channel = try parse("$c:#staff");
    try std.testing.expect(!missed_channel.matches(ctx));
}

test "matches negation and nested negation" {
    const alice = ClientContext{ .account = "alice", .host = "user.example" };
    const bob = ClientContext{ .account = "bob", .host = "user.example" };

    const negated_account = try parse("$~a:alice");
    try std.testing.expect(!negated_account.matches(alice));
    try std.testing.expect(negated_account.matches(bob));

    const nested_account = try parse("$~:$a:alice");
    try std.testing.expect(!nested_account.matches(alice));
    try std.testing.expect(nested_account.matches(bob));

    const nested_host = try parse("$~:bad*");
    try std.testing.expect(nested_host.matches(alice));
    const bad_host = ClientContext{ .account = "alice", .host = "bad.example" };
    try std.testing.expect(!nested_host.matches(bad_host));
}

test "rejects malformed masks" {
    try std.testing.expectError(error.EmptyMask, parse(""));
    try std.testing.expectError(error.MissingType, parse("$"));
    try std.testing.expectError(error.EmptyPattern, parse("$a:"));
    try std.testing.expectError(error.MissingDelimiter, parse("$aalice"));
    try std.testing.expectError(error.UnknownType, parse("$x:value"));
    try std.testing.expectError(error.InvalidByte, parse("$a:bad\nvalue"));
    try std.testing.expectError(error.EmptyPattern, parse("$~"));
    // Patterned `$z`/`$o` now parse; only an empty pattern after the delimiter
    // is rejected.
    try std.testing.expectError(error.EmptyPattern, parse("$z:"));
    try std.testing.expectError(error.EmptyPattern, parse("$o:"));
}

test "plain hostmask fallthrough uses host glob" {
    const matcher = try parse("*.example.net");
    try std.testing.expectEqual(NodeKind.hostmask, matcher.rootKind());
    try std.testing.expect(matcher.matches(.{ .host = "irc.example.net" }));
    try std.testing.expect(!matcher.matches(.{ .host = "irc.example.org" }));
}

test "caller can lower nesting capacity at comptime" {
    const SmallMatcher = Matcher(2);
    const matcher = try SmallMatcher.parse("$~a:alice");
    try std.testing.expect(matcher.matches(.{ .account = "bob" }));
    try std.testing.expectError(error.TooDeep, SmallMatcher.parse("$~$~a:alice"));
}

test "cloak extban nested host match survives epoch rotation" {
    const c = @import("cloak.zig");
    const key = c.SecretKey.init(@splat(7));
    var old: [253]u8 = undefined;
    const before = try c.cloakOpaqueEpochV4(&old, &key, "203.0.113.9", 1, 86400, .{});
    const matcher = try parse(before);
    const ctx: ClientContext = .{ .host = "current.onyx", .cloak_context = .{ .key = key, .suffix = "onyx", .address = "203.0.113.9" } };
    try std.testing.expect(matcher.matches(ctx));
    var mute_buf: [512]u8 = undefined;
    const muted = try parse(try std.fmt.bufPrint(&mute_buf, "$m:{s}", .{before}));
    try std.testing.expect(muted.matches(ctx));
    var negated_buf: [512]u8 = undefined;
    const negated = try parse(try std.fmt.bufPrint(&negated_buf, "$~:{s}", .{before}));
    try std.testing.expect(!negated.matches(ctx));
}
