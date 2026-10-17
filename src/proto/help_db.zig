// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Static HELP/HELPOP topic database and IRC help numeric builders.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const RPL_HELPSTART: u16 = 704;
pub const RPL_HELPTXT: u16 = 705;
pub const RPL_ENDOFHELP: u16 = 706;
pub const ERR_HELPNOTFOUND: u16 = @intFromEnum(numeric.Numeric.ERR_HELPNOTFOUND);

pub const HelpError = std.mem.Allocator.Error || error{
    InvalidParam,
    InvalidTrailing,
    InvalidNumeric,
};

pub const HelpTopic = struct {
    topic: []const u8,
    lines: []const []const u8,
};

pub const help_topics = [_]HelpTopic{
    .{
        .topic = "HELP",
        .lines = &[_][]const u8{
            "HELP [topic]",
            "Shows help for an IRC command or server topic.",
            "Use HELPOP [topic] for the same help text through the operator help path.",
            "IRCX topics include LISTX, PROP, ACCESS, WHISPER, and CREATE. Account topics include REGISTER, IDENTIFY, CHANNEL, and MEMO.",
        },
    },
    .{
        .topic = "JOIN",
        .lines = &[_][]const u8{
            "JOIN <channel>[,<channel>] [key[,key]]",
            "Joins one or more channels. Channel names normally begin with #.",
            "If keys are required, provide them in the same order as the channels.",
        },
    },
    .{
        .topic = "MODE",
        .lines = &[_][]const u8{
            "MODE <target> [modes] [mode parameters]",
            "Changes or displays user and channel modes.",
            "Channel modes such as +o, +v, +b, +k, and +l may require parameters.",
            "Operator user mode +j (override) enables audited channel override and SYSTEM kill attribution.",
            "User +D hides channel PRIVMSG, NOTICE, and TAGMSG. +T hides channel NOTICE. +G requires a shared channel or ACCEPT. +Z requires a TLS sender. +I hides idle. +V refuses invites. +W notifies on WHOIS. Channel +c rejects formatting, +B refuses bots, and +K limits kicks to the founder.",
        },
    },
    .{
        .topic = "PRIVMSG",
        .lines = &[_][]const u8{
            "PRIVMSG <target>{,<target>} :<text>",
            "Sends a private message to a user or channel.",
            "Messages to channels are delivered to channel members subject to channel modes.",
        },
    },
    .{
        .topic = "OPER",
        .lines = &[_][]const u8{
            "OPER <name> <password>",
            "Authenticates as an IRC operator when the supplied credentials match server config.",
            "Successful OPER grants operator privileges and may add user modes.",
        },
    },
    .{
        .topic = "CHATHISTORY",
        .lines = &[_][]const u8{
            "CHATHISTORY <subcommand> <target> [parameters]",
            "Retrieves IRCv3 message history for channels or conversations.",
            "Common subcommands include LATEST, BEFORE, AFTER, AROUND, and BETWEEN.",
        },
    },
    .{
        .topic = "IRCX",
        .lines = &[_][]const u8{
            "IRCX",
            "Enables IRCX mode and reports support, including before registration.",
        },
    },
    .{
        .topic = "ISIRCX",
        .lines = &[_][]const u8{
            "ISIRCX",
            "Queries IRCX support without changing whether IRCX is enabled.",
        },
    },
    .{
        .topic = "LISTX",
        .lines = &[_][]const u8{
            "LISTX [filter [limit]]",
            "A trailing whole-number limit caps 812 entries. 0 or a missing limit uses the server cap of 1024.",
            "816 means another match was cut.",
        },
    },
    .{
        .topic = "MODEX",
        .lines = &[_][]const u8{
            "MODEX <#channel[,nick]> [+|-<named-mode> ...]",
            "Lists named channel or member modes, or applies those named changes.",
        },
    },
    .{
        .topic = "PROP",
        .lines = &[_][]const u8{
            "PROP <entity> [<key[,key...]> [:<value>]]",
            "Lists, gets, sets, or deletes properties. LAG is 0, 1, or 2 seconds, applied to every member including voice and operators.",
            "ONJOIN is a PRIVMSG from the channel name to the joiner only. ONPART is a NOTICE from the channel name to the parter only. The stored characters \\ and n start another line.",
        },
    },
    .{
        .topic = "ACCESS",
        .lines = &[_][]const u8{
            "ACCESS <#channel> <ADD|DELETE|LIST|CLEAR> [level [mask [timeout] [:reason]]]",
            "Channel object access for FOUNDER, OWNER, HOST, VOICE, DENY, and GRANT. A bare timeout is seconds.",
        },
    },
    .{
        .topic = "SACCESS",
        .lines = &[_][]const u8{
            "SACCESS ADD <DENY|GAG|GRANT|NOCHANNEL|NONICK|HOLDNICK> <mask> [duration] [:reason] | SACCESS <DEL|DELETE> <type> <mask> | SACCESS LIST [type] | SACCESS CLEAR [type]",
            "Oper-only network access. ACCESS is the channel object form.",
        },
    },
    .{
        .topic = "AUTH",
        .lines = &[_][]const u8{
            "AUTH <package> [mechanism/payload]",
            "IRCX SASL authentication. Repeat with the package-specific exchange. A plaintext connection does not advertise or complete PLAIN or SCRAM.",
        },
    },
    .{
        .topic = "EVENT",
        .lines = &[_][]const u8{
            "EVENT <ADD|DEL|LIST|BROADCAST|OBSERVE|SEVERITY|REPLAY|STATS> ...",
            "Subscribes to named events. Operator use is broader.",
        },
    },
    .{
        .topic = "DATA",
        .lines = &[_][]const u8{
            "DATA <target> <tag> :<message>",
            "Sends a typed message to a nick or channel. A client line is prefixed nick!user@host. A line this server authors uses the server name and no nick.",
        },
    },
    .{
        .topic = "REQUEST",
        .lines = &[_][]const u8{
            "REQUEST <target> <tag> :<message>",
            "Same checks as DATA, and the relayed line keeps the REQUEST verb.",
        },
    },
    .{
        .topic = "REPLY",
        .lines = &[_][]const u8{
            "REPLY <target> <tag> :<message>",
            "Same checks as DATA, and the relayed line keeps the REPLY verb.",
        },
    },
    .{
        .topic = "WHISPER",
        .lines = &[_][]const u8{
            "WHISPER <#channel> <nick[,nick...]> :<text>",
            "Sends channel-scoped text to listed members. Channel mode +w blocks every whisper. Channel mode +x gives the same reply as a nick that is not on the channel when the sender cannot see that member.",
        },
    },
    .{
        .topic = "CREATE",
        .lines = &[_][]const u8{
            "CREATE <#channel> [modes] [clone-source]",
            "Creates the channel and joins the founder. The target must not already exist.",
        },
    },
    .{
        .topic = "REGISTER",
        .lines = &[_][]const u8{
            "REGISTER <account|*> <email|*> <password>",
            "Registers an account and logs this session in. * uses the current nick.",
        },
    },
    .{
        .topic = "VERIFY",
        .lines = &[_][]const u8{
            "VERIFY [account] <code>",
            "Confirms a pending account email verification code.",
        },
    },
    .{
        .topic = "IDENTIFY",
        .lines = &[_][]const u8{
            "IDENTIFY <account> <password> [<2fa-code>]",
            "Logs in to an existing account. TOTP accounts require a 6-digit code.",
        },
    },
    .{
        .topic = "TOTP",
        .lines = &[_][]const u8{
            "TOTP <ENROLL | CONFIRM <code> | DISABLE | STATUS>",
            "Manages two-factor authentication for the logged-in account. ENROLL requires TLS.",
        },
    },
    .{
        .topic = "RECOVERYCODES",
        .lines = &[_][]const u8{
            "RECOVERYCODES STATUS | GENERATE [password] | CLEAR [password] | LOGIN <account> <code>",
            "Manages single-use recovery codes or logs in with one. GENERATE requires TLS.",
        },
    },
    .{
        .topic = "LOGOUT",
        .lines = &[_][]const u8{
            "LOGOUT",
            "Ends the account login for this session.",
        },
    },
    .{
        .topic = "DROP",
        .lines = &[_][]const u8{
            "DROP <account> <password>",
            "Deletes an account after checking the password.",
        },
    },
    .{
        .topic = "SETPASS",
        .lines = &[_][]const u8{
            "SETPASS <current-password> <new-password>",
            "Changes the logged-in account password. A client-certificate-verified connection may use SETPASS <new-password>.",
        },
    },
    .{
        .topic = "RESETPASS",
        .lines = &[_][]const u8{
            "RESETPASS <account> [<code> <new-password>]",
            "Requests a reset or sets a new password with the emailed code. The request does not reveal whether the account exists.",
        },
    },
    .{
        .topic = "SUCCESSOR",
        .lines = &[_][]const u8{
            "SUCCESSOR <#channel> SHOW | SET <account> | CLEAR",
            "Shows, sets, or clears the registered channel founder's successor.",
            "A new successor replaces the armed one after 10 minutes. CLEAR before that cancels the change. SHOW shows the armed successor.",
        },
    },
    .{
        .topic = "ACCOUNTINFO",
        .lines = &[_][]const u8{
            "ACCOUNTINFO [account] | ACCOUNTINFO LOGINS [account]",
            "Reports account name and flags. With no account, uses the logged-in account.",
            "LOGINS lists recent sign-ins: time, mechanism, TLS, and a short prefix. Operators may name another account. The word LOGINS is the subcommand.",
        },
    },
    .{
        .topic = "ACCOUNTSET",
        .lines = &[_][]const u8{
            "ACCOUNTSET <account> <password> <email|flags|secure|enforce> <value>",
            "Updates one account setting after a password check.",
        },
    },
    .{
        .topic = "GHOST",
        .lines = &[_][]const u8{
            "GHOST <nick> <password>",
            "Disconnects another session logged in to your account after a password check.",
        },
    },
    .{
        .topic = "RECOVER",
        .lines = &[_][]const u8{
            "RECOVER <nick>",
            "Forces an unauthenticated holder off your registered nick.",
        },
    },
    .{
        .topic = "RELEASE",
        .lines = &[_][]const u8{
            "RELEASE <nick>",
            "Drops a server hold on your registered nick.",
        },
    },
    .{
        .topic = "CHANNEL",
        .lines = &[_][]const u8{
            "CHANNEL <REGISTER|DROP|INFO|ACCESS|AKICK|SET|TRANSFER> <#channel> ...",
            "Channel services on the server. TRANSFER and non-MLOCK SET reply as unavailable.",
        },
    },
    .{
        .topic = "SESSION",
        .lines = &[_][]const u8{
            "SESSION [LIST|TOKEN|RESUME <token>|DROP <#n|sid=<32-hex>>]",
            "Lists, resumes, or drops account attachments, or shows this session credential.",
            "These credentials resume an attachment; they are not SASL SESSION-TOKEN.",
        },
    },
    .{
        .topic = "MEMO",
        .lines = &[_][]const u8{
            "MEMO [LIST|CLEAR|SEND <account> :message|FORWARD [<account>|OFF|NONE]|IGNORE [ADD|DEL|LIST] [<account>]]",
            "Leaves an offline account message that is delivered at the next login.",
        },
    },
    .{
        .topic = "AUTOJOIN",
        .lines = &[_][]const u8{
            "AUTOJOIN <LIST|ADD|DEL|CLEAR> [#channel]",
            "Manages the logged-in account's autojoin list.",
        },
    },
    .{
        .topic = "WELCOME",
        .lines = &[_][]const u8{
            "WELCOME [topic]",
            "Sends welcome text to the caller.",
        },
    },
    .{
        .topic = "CERTADD",
        .lines = &[_][]const u8{
            "CERTADD",
            "Binds this connection's client-certificate fingerprint to the logged-in account.",
        },
    },
    .{
        .topic = "WEBAUTHN",
        .lines = &[_][]const u8{
            "WEBAUTHN STATUS | REGISTER [label] | REGISTER-FINISH <cred-id> <client-data-json> <authdata> [attestation] | AUTH <account> | AUTH-FINISH <cred-id> <client-data-json> <authdata> <signature> | LIST | REMOVE <cred-id> | RENAME <cred-id> :<label> | LOCK",
            "Registers a passkey, logs in with one, or locks out password login after a passkey is stored.",
        },
    },
    .{
        .topic = "E2EEKEY",
        .lines = &[_][]const u8{
            "E2EEKEY [STATUS|LIST [account]|ADD <device-id> <algorithm> <public-key>|DEL <device-id>]",
            "Adds, lists, or removes public E2EE device keys.",
        },
    },
    .{
        .topic = "HELPOP",
        .lines = &[_][]const u8{
            "HELPOP [topic]",
            "Alias of HELP.",
        },
    },
};

comptime {
    @setEvalBranchQuota(100_000);

    for (help_topics, 0..) |left, left_index| {
        if (left.lines.len == 0) @compileError("help topics need at least one line");
        validateComptimeParam(left.topic);
        for (left.lines) |line| validateComptimeTrailing(line);

        for (help_topics[left_index + 1 ..]) |right| {
            if (asciiEqlIgnoreCase(left.topic, right.topic)) {
                @compileError("duplicate help topic");
            }
        }
    }
}

pub fn topics() []const HelpTopic {
    return &help_topics;
}

pub fn lookup(topic: []const u8) ?*const HelpTopic {
    for (&help_topics) |*entry| {
        if (asciiEqlIgnoreCase(entry.topic, topic)) return entry;
    }
    return null;
}

pub fn buildHelpLookupReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    requested_topic: []const u8,
) HelpError![]u8 {
    if (lookup(requested_topic)) |entry| {
        return buildHelpTopicReply(allocator, server_name, requester, entry);
    }
    return buildErrHelpNotFound(allocator, server_name, requester, requested_topic);
}

pub fn buildHelpTopicReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    entry: *const HelpTopic,
) HelpError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try appendRplHelpStart(&out, allocator, server_name, requester, entry.topic, entry.lines[0]);
    for (entry.lines[1..]) |line| {
        try appendRplHelpTxt(&out, allocator, server_name, requester, entry.topic, line);
    }
    try appendRplEndOfHelp(&out, allocator, server_name, requester, entry.topic);

    return out.toOwnedSlice(allocator);
}

pub fn buildRplHelpStart(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_HELPSTART, requester, topic, text);
}

pub fn buildRplHelpTxt(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_HELPTXT, requester, topic, text);
}

pub fn buildRplEndOfHelp(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, RPL_ENDOFHELP, requester, topic, "End of /HELP.");
}

pub fn buildErrHelpNotFound(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError![]u8 {
    return buildNumericLine(allocator, server_name, ERR_HELPNOTFOUND, requester, topic, "Help not found");
}

pub fn appendRplHelpStart(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_HELPSTART, requester, topic, text);
}

pub fn appendRplHelpTxt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_HELPTXT, requester, topic, text);
}

pub fn appendRplEndOfHelp(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    topic: []const u8,
) HelpError!void {
    try appendNumericLine(out, allocator, server_name, RPL_ENDOFHELP, requester, topic, "End of /HELP.");
}

fn buildNumericLine(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    code: u16,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendNumericLine(&out, allocator, server_name, code, requester, topic, text);
    return out.toOwnedSlice(allocator);
}

fn appendNumericLine(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    server_name: []const u8,
    code: u16,
    requester: []const u8,
    topic: []const u8,
    text: []const u8,
) HelpError!void {
    try validateParam(server_name);
    try validateCode(code);
    try validateParam(requester);
    try validateParam(topic);
    try validateTrailing(text);

    try out.append(allocator, ':');
    try out.appendSlice(allocator, server_name);
    try out.append(allocator, ' ');
    try appendCode(out, allocator, code);
    try out.append(allocator, ' ');
    try out.appendSlice(allocator, requester);
    try out.append(allocator, ' ');
    try out.appendSlice(allocator, topic);
    try out.appendSlice(allocator, " :");
    try out.appendSlice(allocator, text);
    try out.appendSlice(allocator, "\r\n");
}

fn appendCode(out: *std.ArrayList(u8), allocator: std.mem.Allocator, code_value: u16) HelpError!void {
    var buf: [3]u8 = undefined;
    if (code_value > 999) return error.InvalidNumeric;
    buf[0] = @as(u8, '0') + @as(u8, @intCast(code_value / 100));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code_value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code_value % 10));
    try out.appendSlice(allocator, &buf);
}

fn validateCode(code_value: u16) HelpError!void {
    if (code_value < 100 or code_value > 999) return error.InvalidNumeric;
}

fn validateParam(param: []const u8) HelpError!void {
    if (param.len == 0) return error.InvalidParam;
    for (param) |ch| {
        if (!validParamByte(ch)) return error.InvalidParam;
    }
}

fn validateTrailing(text: []const u8) HelpError!void {
    for (text) |ch| {
        if (!validTrailingByte(ch)) return error.InvalidTrailing;
    }
}

fn validateComptimeParam(comptime param: []const u8) void {
    if (param.len == 0) @compileError("empty help topic");
    for (param) |ch| {
        if (!validParamByte(ch)) @compileError("invalid help topic byte");
    }
}

fn validateComptimeTrailing(comptime text: []const u8) void {
    for (text) |ch| {
        if (!validTrailingByte(ch)) @compileError("invalid help text byte");
    }
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => ch >= 0x21 and ch != 0x7f,
    };
}

fn validTrailingByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

fn asciiEqlIgnoreCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (asciiLower(a) != asciiLower(b)) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    return switch (ch) {
        'A'...'Z' => ch + ('a' - 'A'),
        else => ch,
    };
}

test "known topic returns 704, 705 lines, and 706 with exact bytes" {
    const allocator = std.testing.allocator;
    const entry = lookup("JOIN") orelse return error.TestUnexpectedResult;

    const bytes = try buildHelpTopicReply(allocator, "irc.example", "alice", entry);
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(
        ":irc.example 704 alice JOIN :JOIN <channel>[,<channel>] [key[,key]]\r\n" ++
            ":irc.example 705 alice JOIN :Joins one or more channels. Channel names normally begin with #.\r\n" ++
            ":irc.example 705 alice JOIN :If keys are required, provide them in the same order as the channels.\r\n" ++
            ":irc.example 706 alice JOIN :End of /HELP.\r\n",
        bytes,
    );
}

test "unknown topic returns 524" {
    const allocator = std.testing.allocator;

    const bytes = try buildHelpLookupReply(allocator, "irc.example", "alice", "NOPE");
    defer allocator.free(bytes);

    try std.testing.expectEqualStrings(
        ":irc.example 524 alice NOPE :Help not found\r\n",
        bytes,
    );
}

test "topic lookup is case-insensitive" {
    const allocator = std.testing.allocator;
    const entry = lookup("chAtHiStOrY") orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("CHATHISTORY", entry.topic);

    const bytes = try buildHelpLookupReply(allocator, "irc.example", "alice", "join");
    defer allocator.free(bytes);
    try std.testing.expect(std.mem.startsWith(u8, bytes, ":irc.example 704 alice JOIN :"));
}

test "HELP topics cover IRCX and services" {
    const required = [_][]const u8{
        "IRCX",
        "ISIRCX",
        "LISTX",
        "MODEX",
        "PROP",
        "ACCESS",
        "SACCESS",
        "AUTH",
        "EVENT",
        "DATA",
        "REQUEST",
        "REPLY",
        "WHISPER",
        "CREATE",
        "REGISTER",
        "VERIFY",
        "IDENTIFY",
        "TOTP",
        "RECOVERYCODES",
        "LOGOUT",
        "DROP",
        "SETPASS",
        "RESETPASS",
        "SUCCESSOR",
        "ACCOUNTINFO",
        "ACCOUNTSET",
        "GHOST",
        "RECOVER",
        "RELEASE",
        "CHANNEL",
        "SESSION",
        "MEMO",
        "AUTOJOIN",
        "WELCOME",
        "CERTADD",
        "WEBAUTHN",
        "E2EEKEY",
        "HELPOP",
    };

    for (required) |name| {
        const entry = lookup(name) orelse return error.TestUnexpectedResult;
        try std.testing.expect(entry.lines.len >= 2);
        try std.testing.expectEqualStrings(name, entry.topic);
    }

    const listx = lookup("listx") orelse return error.TestUnexpectedResult;
    const listx_upper = lookup("LISTX") orelse return error.TestUnexpectedResult;
    try std.testing.expect(listx == listx_upper);
    try std.testing.expectEqualStrings("LISTX", listx.topic);
    try std.testing.expect(lookup("NOPE") == null);

    const access = lookup("ACCESS") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, access.lines[1], "seconds") != null);
    const successor_help = lookup("SUCCESSOR") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, successor_help.lines[2], "10 minutes") != null);
    const accountinfo = lookup("ACCOUNTINFO") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, accountinfo.lines[0], "LOGINS") != null);
    const webauthn_help = lookup("WEBAUTHN") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, webauthn_help.lines[0], "LOCK") != null);

    const help = lookup("HELP") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(
        "IRCX topics include LISTX, PROP, ACCESS, WHISPER, and CREATE. Account topics include REGISTER, IDENTIFY, CHANNEL, and MEMO.",
        help.lines[help.lines.len - 1],
    );

    const allocator = std.testing.allocator;
    const bytes = try buildHelpLookupReply(allocator, "irc.example", "alice", "LISTX");
    defer allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "704") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "LISTX") != null);
}
