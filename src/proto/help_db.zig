// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Static HELP/HELPOP topic database and IRC help numeric builders.
const std = @import("std");
const numeric = @import("numeric.zig");
const live_caps = @import("live_cap_metadata.zig");
const chanserv_cmd = @import("chanserv_cmd.zig");

const history_latest_example = "CHATHISTORY LATEST #channel * 50";
const history_targets_example = "CHATHISTORY TARGETS * * 20";
const channel_register_example = "CHANNEL REGISTER #channel";
const channel_access_example = "CHANNEL ACCESS #channel LIST";
const session_list_example = "SESSION LIST MESH";
const session_revoke_example = "SESSION REVOKE group=0123456789abcdef0123456789abcdef";

pub const RPL_HELPSTART: u16 = 704;
pub const RPL_HELPTXT: u16 = 705;
pub const RPL_ENDOFHELP: u16 = 706;
pub const ERR_HELPNOTFOUND: u16 = @backingInt(numeric.Numeric.ERR_HELPNOTFOUND);

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
            "Use HELP ?query or HELPOP ?query to search topic names and help text (up to 64 bytes).",
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
            "Next step if denied: If a mode change is denied, ask a channel operator or the channel FOUNDER to apply it, or ask an oper whether oper_override applies.",
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
            "CHATHISTORY <subcommand> <target> <selector> [selector] <limit>",
            "Requires the draft/chathistory capability; use CAP LS to check availability and CAP REQ to request it.",
            "LATEST accepts * or a timestamp= or msgid= selector. BEFORE, AFTER and AROUND require a selector; AROUND accepts an optional second selector.",
            "BETWEEN needs two selectors. TARGETS uses two timestamp= selectors or * and a limit, with no target argument.",
            "Limits are positive numbers; result counts are bounded by server policy.",
            "Next step if denied: If history is denied, join the channel if you can, or ask a channel operator to review your access, then retry once draft/chathistory is negotiated.",
            "Examples:",
            history_latest_example,
            history_targets_example,
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
            "Next step if denied: If a property change is denied, ask a channel operator or the channel FOUNDER to set it for you.",
        },
    },
    .{
        .topic = "ACCESS",
        .lines = &[_][]const u8{
            "ACCESS <#channel> <ADD|DELETE|LIST|CLEAR> [level [mask [timeout] [:reason]]]",
            "Channel object access for FOUNDER, OWNER, HOST, VOICE, DENY, and GRANT. A bare timeout is seconds.",
            "ACCESS <#channel> EXPLAIN [nick|* [JOIN|SPEAK]]",
            "Read-only direct JOIN policy snapshot; no key supplied. Other subjects require audit_read.",
            "SPEAK explains channel PRIVMSG now; content rules (+c/+C/+T, E2EE) are not evaluated. Network silence is shown only to audit_read.",
            "ACCESS <#channel> PREVIEW <level> <mask> [timeout] <subject...>",
            "Read-only candidate preview; never stores the rule. Cloak and precedence are not evaluated.",
            "Self replies hide masks, issuers and reasons. Hidden named tracing also requires oper_spy.",
            "Private details retain source read gates: ACCESS channel manager; AKICK Services admin; SACCESS service_admin.",
            "Hidden or unknown channels return the same unavailable reply.",
            "ACCESS expiry is actual absolute Unix seconds. Nonzero legacy SACCESS duration has unknown expiry.",
            "Forwarding/clone destinations and later transaction availability are not certified.",
            "Next step if denied: If denied, ask a channel FOUNDER or OWNER for the needed ACCESS level, or an oper with audit_read to review; hidden tracing needs oper_spy.",
        },
    },
    .{
        .topic = "SACCESS",
        .lines = &[_][]const u8{
            "SACCESS ADD <DENY|GAG|GRANT|NOCHANNEL|NONICK|HOLDNICK> <mask> [duration] [:reason] | SACCESS <DEL|DELETE> <type> <mask> | SACCESS LIST [type] | SACCESS CLEAR [type]",
            "Oper-only network access. ACCESS is the channel object form.",
            "Next step if denied: If denied, ask an oper with service_admin to apply or review the SACCESS change for you.",
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
            "Next step if denied: If denied, ask a channel operator to check modes +w and +x and your membership, then retry WHISPER from inside the channel.",
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
            "ACCOUNTINFO [account] | ACCOUNTINFO LOGINS [account] | ACCOUNTINFO SESSIONS [account]",
            "Reports account name and flags. With no account, uses the logged-in account.",
            "LOGINS lists recent sign-ins: time, mechanism, TLS, and a short prefix. SESSIONS lists live attachments: nick, TLS or clear, and node id. Operators may name another account. LOGINS and SESSIONS are subcommands.",
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
            chanserv_cmd.fmtUsage(.register),
            chanserv_cmd.fmtUsage(.drop),
            chanserv_cmd.fmtUsage(.info),
            chanserv_cmd.fmtUsage(.access),
            chanserv_cmd.fmtUsage(.akick),
            chanserv_cmd.fmtUsage(.set),
            chanserv_cmd.fmtUsage(.transfer),
            "Channel services on the server. TRANSFER and non-MLOCK SET reply as unavailable.",
            "Next step if denied: If denied, log in with IDENTIFY, then ask the channel FOUNDER for CHANNEL ACCESS (FOUNDER, OP, or VOICE) or an oper with service_admin to review.",
            "Examples:",
            channel_register_example,
            channel_access_example,
        },
    },
    .{
        .topic = "SESSION",
        .lines = &[_][]const u8{
            "SESSION [LIST [MESH [cursor=<32-hex>]]|TOKEN|RESUME <token>|DROP <#n|sid=<32-hex>>|REVOKE group=<32-hex>]",
            "Lists, resumes, or drops account attachments, or shows this session credential.",
            "LIST MESH and REVOKE need durable accounts and a complete configured node set; unavailable otherwise.",
            "LIST MESH shows account groups and attachment observations; use its cursor on the same connection for subsequent pages.",
            "REVOKE group=<id> revokes the selected account group. Use an id from SESSION LIST MESH.",
            "These credentials resume an attachment; they are not SASL SESSION-TOKEN.",
            "Next step if denied: If denied, log in with IDENTIFY to your account, then retry using a group id from your own SESSION LIST MESH output.",
            "Examples (group id shown is illustrative):",
            session_list_example,
            session_revoke_example,
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
            "Registers a passkey, logs in with one, or locks out password login after a passkey is stored. After LOCK, a password or recovery session is not a network operator until a later passkey sign-in.",
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
    if (std.mem.startsWith(u8, requested_topic, "?")) {
        return buildHelpSearchReply(allocator, server_name, requester, requested_topic[1..]);
    }
    if (lookup(requested_topic)) |entry| {
        return buildHelpTopicReply(allocator, server_name, requester, entry);
    }
    for (live_caps.cap_specs) |spec| {
        if (asciiEqlIgnoreCase(spec.name, requested_topic)) {
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try appendRplHelpStart(&out, allocator, server_name, requester, spec.name, "Known capability definition.");
            try appendRplHelpTxt(&out, allocator, server_name, requester, spec.name, "Use CAP LS to check availability for this connection; configuration, transport or policy can disable it.");
            try appendRplEndOfHelp(&out, allocator, server_name, requester, spec.name);
            return out.toOwnedSlice(allocator);
        }
    }
    return buildErrHelpNotFound(allocator, server_name, requester, requested_topic);
}

// Search emits only static database text; the user's query never enters the wire.
fn buildHelpSearchReply(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    requester: []const u8,
    query: []const u8,
) HelpError![]u8 {
    try validateParam(server_name);
    try validateParam(requester);
    // Reject impossible framing before allocating. Each generated line is
    // checked below, and the fixed reply count bounds the aggregate.
    if (server_name.len > 512 or requester.len > 512 or
        !searchLineFits(server_name, requester, "Invalid search term; use 1 to 64 printable bytes.")) return error.InvalidParam;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPSTART, "Static help search results:");

    if (query.len == 0) {
        try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, "Enter a search term after ?.");
    } else if (query.len > 64 or !validSearchQuery(query)) {
        try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, "Invalid search term; use 1 to 64 printable bytes.");
    } else {
        var count: usize = 0;
        var truncated = false;
        var usage_omitted = false;
        for (help_topics) |entry| {
            var matches = asciiContainsIgnoreCase(entry.topic, query);
            if (!matches) {
                for (entry.lines) |line| {
                    if (asciiContainsIgnoreCase(line, query)) {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches) continue;
            if (count == 8) {
                truncated = true;
                break;
            }
            // Topic and first line are compile-time checked static strings.
            var text_buf: [512]u8 = undefined;
            const text = std.fmt.bufPrint(&text_buf, "{s}: {s}", .{ entry.topic, entry.lines[0] }) catch return error.InvalidTrailing;
            if (searchLineFits(server_name, requester, text)) {
                try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, text);
            } else {
                try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, entry.topic);
                usage_omitted = true;
            }
            count += 1;
        }
        for (live_caps.cap_specs) |spec| {
            if (!asciiContainsIgnoreCase(spec.name, query)) continue;
            if (count == 8) {
                truncated = true;
                break;
            }
            var text_buf: [512]u8 = undefined;
            const text = std.fmt.bufPrint(&text_buf, "Capability {s}; use CAP LS for current availability.", .{spec.name}) catch return error.InvalidTrailing;
            if (searchLineFits(server_name, requester, text)) {
                try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, text);
            } else {
                try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, spec.name);
                usage_omitted = true;
            }
            count += 1;
        }
        if (count == 0) try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, "No matching help topics.");
        if (truncated) try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, "More matches exist; refine the search.");
        if (usage_omitted) try appendSearchLine(&out, allocator, server_name, requester, RPL_HELPTXT, "Some usage lines omitted due to line length.");
    }
    try appendSearchLine(&out, allocator, server_name, requester, RPL_ENDOFHELP, "End of /HELP.");
    return out.toOwnedSlice(allocator);
}

fn searchLineFits(server_name: []const u8, requester: []const u8, text: []const u8) bool {
    // :server 704 requester SEARCH :text\r\n has 17 framing bytes.
    if (server_name.len > 495 or requester.len > 495 or text.len > 495) return false;
    return server_name.len + requester.len + text.len <= 495;
}

fn appendSearchLine(out: *std.ArrayList(u8), allocator: std.mem.Allocator, server_name: []const u8, requester: []const u8, code: u16, text: []const u8) HelpError!void {
    if (!searchLineFits(server_name, requester, text)) return error.InvalidParam;
    try appendNumericLine(out, allocator, server_name, code, requester, "SEARCH", text);
}

fn validSearchQuery(query: []const u8) bool {
    for (query) |ch| if (!validTrailingByte(ch)) return false;
    return true;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |i| {
        if (asciiEqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
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

test "help search matches names and body without echoing query" {
    const allocator = std.testing.allocator;
    const name = try buildHelpLookupReply(allocator, "irc.example", "alice", "?jOiN");
    defer allocator.free(name);
    try std.testing.expect(std.mem.indexOf(u8, name, "SEARCH :JOIN: JOIN <channel>") != null);
    const body = try buildHelpLookupReply(allocator, "irc.example", "alice", "?fInGeRpRiNt");
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "SEARCH :CERTADD: CERTADD") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "fInGeRpRiNt") == null);
}

test "help search bounds results and frames replies" {
    const allocator = std.testing.allocator;
    const reply = try buildHelpLookupReply(allocator, "irc.example", "alice", "?channel");
    defer allocator.free(reply);
    var lines = std.mem.splitSequence(u8, reply, "\r\n");
    var count: usize = 0;
    var results: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try std.testing.expect(line.len + 2 <= 512);
        try std.testing.expect(std.mem.indexOfScalar(u8, line, '\r') == null);
        try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
        if (std.mem.indexOf(u8, line, " 705 alice SEARCH :") != null and
            std.mem.indexOf(u8, line, "More matches exist") == null) results += 1;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 8), results);
    try std.testing.expectEqual(@as(usize, 11), count);
    try std.testing.expect(std.mem.indexOf(u8, reply, "More matches exist") != null);
    try std.testing.expect(std.mem.startsWith(u8, reply, ":irc.example 704 alice SEARCH :"));
    try std.testing.expect(std.mem.endsWith(u8, reply, ":irc.example 706 alice SEARCH :End of /HELP.\r\n"));
}

test "help search handles empty missing and invalid input safely" {
    const allocator = std.testing.allocator;
    const long_query = "?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const queries = [_][]const u8{ "?", "?zzzzzzzzzzzz", "?bad\r\nINJECT", long_query, "?bad\x7fvalue" };
    const messages = [_][]const u8{ "Enter a search term", "No matching help topics", "Invalid search term", "Invalid search term", "Invalid search term" };
    for (queries, messages) |query, message| {
        const reply = try buildHelpLookupReply(allocator, "irc.example", "alice", query);
        defer allocator.free(reply);
        try std.testing.expect(std.mem.indexOf(u8, reply, message) != null);
        try std.testing.expect(std.mem.indexOf(u8, reply, "INJECT") == null);
        var lines = std.mem.splitSequence(u8, reply, "\r\n");
        var count: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try std.testing.expect(line.len + 2 <= 512);
            try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);
            count += 1;
        }
        try std.testing.expectEqual(@as(usize, 3), count);
    }
    try std.testing.expectError(error.InvalidParam, buildHelpLookupReply(allocator, "bad\rserver", "alice", "?join"));
}

test "help search frees every allocation on failure" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const reply = try buildHelpLookupReply(allocator, "irc.example", "alice", "?channel");
            defer allocator.free(reply);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "help search accommodates long valid prefixes with topic-only fallback" {
    const allocator = std.testing.allocator;
    const server: [253]u8 = @splat('s');
    const requester: [64]u8 = @splat('n');
    const reply = try buildHelpLookupReply(allocator, &server, &requester, "?webauthn");
    defer allocator.free(reply);
    try std.testing.expect(std.mem.indexOf(u8, reply, " SEARCH :WEBAUTHN\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "Some usage lines omitted") != null);
    var lines = std.mem.splitSequence(u8, reply, "\r\n");
    while (lines.next()) |line| try std.testing.expect(line.len + 2 <= 512);
}

test "help derives searchable capabilities from live dispatch definitions" {
    const t = std.testing;
    const a = t.allocator;
    const direct = try buildHelpLookupReply(a, "irc.example", "alice", "DRAFT/SEARCH");
    defer a.free(direct);
    try t.expect(std.mem.indexOf(u8, direct, " 704 alice draft/search :Known capability definition.") != null);
    try t.expect(std.mem.indexOf(u8, direct, "Use CAP LS to check availability") != null);
    const search = try buildHelpLookupReply(a, "irc.example", "alice", "?draft/search");
    defer a.free(search);
    try t.expect(std.mem.indexOf(u8, search, "Capability draft/search; use CAP LS") != null);
    const absent = try buildHelpLookupReply(a, "irc.example", "alice", "file-upload");
    defer a.free(absent);
    try t.expect(std.mem.indexOf(u8, absent, " 524 ") != null);
    for (live_caps.cap_specs) |spec| {
        const reply = try buildHelpLookupReply(a, "irc.example", "alice", spec.name);
        defer a.free(reply);
        try t.expect(std.mem.indexOf(u8, reply, "Use CAP LS to check availability") != null or lookup(spec.name) != null);
    }
}

test "help capability lookup and search free allocations on failure" {
    const Sweep = struct {
        fn run(a: std.mem.Allocator, query: []const u8) !void {
            const reply = try buildHelpLookupReply(a, "irc.example", "alice", query);
            defer a.free(reply);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{"draft/search"});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{"?draft/search"});
}

test "Q04 ACCESS explanation HELP stays framed at supported server and live nick prefixes" {
    // Configured server-name budget reaches 255; live NICKLEN is capped at64.
    const server: [255]u8 = @splat('s');
    const nick: [64]u8 = @splat('n');
    const wire = try buildHelpLookupReply(std.testing.allocator, &server, &nick, "ACCESS");
    defer std.testing.allocator.free(wire);
    var lines = std.mem.splitSequence(u8, wire, "\r\n");
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try std.testing.expect(line.len + 2 <= 512);
        try std.testing.expect(line[0] == ':');
        try std.testing.expectEqualSlices(u8, &server, line[1 .. 1 + server.len]);
        count += 1;
    }
    const topic = lookup("ACCESS").?;
    try std.testing.expectEqual(topic.lines.len + 1, count);
}

test "help syntax examples match IRC and command family parsers" {
    const irc_line = @import("irc_line.zig");
    const history = @import("chathistory_cmd.zig");
    const targets = @import("chathistory_targets.zig");
    const t = std.testing;
    const latest_line = try irc_line.parseLine(history_latest_example);
    try t.expectEqualStrings("CHATHISTORY", latest_line.command);
    try t.expectEqual(@as(usize, 4), latest_line.paramSlice().len);
    const latest = try history.parse(history_latest_example);
    try t.expectEqualStrings("#channel", latest.latest.target);
    try t.expectEqual(@as(u16, 50), latest.latest.limit);
    try t.expect(latest.latest.lower_bound == null);
    const target_line = try irc_line.parseLine(history_targets_example);
    try t.expectEqualStrings("CHATHISTORY", target_line.command);
    try t.expectEqualStrings("TARGETS", target_line.paramSlice()[0]);
    const target_query = try targets.TargetsQuery.parse(history_targets_example);
    try t.expectEqual(@as(usize, 20), target_query.limit);
    for ([_][]const u8{ channel_register_example, channel_access_example }) |example| {
        const line = try irc_line.parseLine(example);
        var args: [16][]const u8 = undefined;
        args[0] = line.command;
        @memcpy(args[1 .. 1 + line.paramSlice().len], line.paramSlice());
        const request = try chanserv_cmd.parse(args[0 .. 1 + line.paramSlice().len]);
        if (std.mem.eql(u8, example, channel_register_example)) {
            try t.expectEqualStrings("#channel", request.register.channel);
        } else {
            try t.expectEqualStrings("#channel", request.access.channel);
            try t.expectEqual(chanserv_cmd.AccessAction.list, request.access.action);
        }
    }
}

test "help CHANNEL syntax is sourced from channel command usage" {
    const t = std.testing;
    const entry = lookup("CHANNEL").?;
    const subcommands = [_]chanserv_cmd.Subcommand{ .register, .drop, .info, .access, .akick, .set, .transfer };
    for (subcommands, 0..) |subcommand, i| try t.expectEqualStrings(chanserv_cmd.fmtUsage(subcommand), entry.lines[i]);
    const reply = try buildHelpLookupReply(t.allocator, "irc.example", "alice", "CHANNEL");
    defer t.allocator.free(reply);
    try t.expect(std.mem.indexOf(u8, reply, "TRANSFER and non-MLOCK SET reply as unavailable") != null);
    const history_reply = try buildHelpLookupReply(t.allocator, "irc.example", "alice", "CHATHISTORY");
    defer t.allocator.free(history_reply);
    try t.expect(std.mem.indexOf(u8, history_reply, "Requires the draft/chathistory capability") != null);
    try t.expect(std.mem.indexOf(u8, history_reply, history_latest_example) != null);
    try t.expect(std.mem.indexOf(u8, history_reply, history_targets_example) != null);
}

test "help SESSION examples match IRC and session command parser" {
    const irc_line = @import("irc_line.zig");
    const session_sid = @import("../daemon/session_sid.zig");
    const t = std.testing;
    const list_line = try irc_line.parseLine(session_list_example);
    try t.expectEqualStrings("SESSION", list_line.command);
    const list = try session_sid.parseCommand(list_line.paramSlice());
    try t.expect(list == .mesh_list);
    try t.expect(list.mesh_list == null);
    const revoke_line = try irc_line.parseLine(session_revoke_example);
    try t.expectEqualStrings("SESSION", revoke_line.command);
    const revoke = try session_sid.parseCommand(revoke_line.paramSlice());
    try t.expect(revoke == .revoke_group);
    try t.expectEqual(@as(usize, 16), revoke.revoke_group.len);
    const reply = try buildHelpLookupReply(t.allocator, "irc.example", "alice", "SESSION");
    defer t.allocator.free(reply);
    try t.expect(std.mem.indexOf(u8, reply, session_list_example) != null);
    try t.expect(std.mem.indexOf(u8, reply, session_revoke_example) != null);
    try t.expect(std.mem.indexOf(u8, reply, "group id shown is illustrative") != null);
}

test "help every topic usage first line parses via irc_line or is explicitly exempt" {
    const irc_line = @import("irc_line.zig");
    const t = std.testing;
    const Exempt = struct { topic: []const u8, reason: []const u8 };
    const exempt = [_]Exempt{
        .{ .topic = "SACCESS", .reason = "multi-alternative grammar in one usage line exceeds irc_line MAXPARA; not a single client line" },
        .{ .topic = "WEBAUTHN", .reason = "multi-alternative grammar in one usage line exceeds irc_line MAXPARA; not a single client line" },
    };
    var parsed: usize = 0;
    var exempted: usize = 0;
    var failures: usize = 0;
    for (help_topics) |entry| {
        try t.expect(lookup(entry.topic) != null);
        var is_exempt = false;
        for (exempt) |item| {
            if (asciiEqlIgnoreCase(item.topic, entry.topic)) is_exempt = true;
        }
        const line = irc_line.parseLine(entry.lines[0]) catch |err| {
            if (is_exempt) {
                // Exemption reason is pinned: only TooManyParams justifies it.
                if (err != error.TooManyParams) {
                    std.debug.print("help topic {s} exempt but fails with {s}, not TooManyParams\n", .{ entry.topic, @errorName(err) });
                    failures += 1;
                    continue;
                }
                exempted += 1;
                continue;
            }
            std.debug.print("help topic {s} usage does not parse: {s}\n", .{ entry.topic, @errorName(err) });
            failures += 1;
            continue;
        };
        if (is_exempt) {
            std.debug.print("help topic {s} is exempt but its usage parses; drop the exemption\n", .{entry.topic});
            failures += 1;
            continue;
        }
        if (!asciiEqlIgnoreCase(line.command, entry.topic)) {
            std.debug.print("help topic {s} usage dispatches as {s}\n", .{ entry.topic, line.command });
            failures += 1;
            continue;
        }
        parsed += 1;
    }
    for (exempt) |item| {
        try t.expect(item.reason.len > 0);
        try t.expect(lookup(item.topic) != null);
    }
    try t.expectEqual(@as(usize, 0), failures);
    try t.expectEqual(help_topics.len, parsed + exempted);
}

test "help denial topics carry conditional next-step lines without existence oracle" {
    const t = std.testing;
    const denial_topics = [_][]const u8{
        "ACCESS", "SACCESS", "CHANNEL", "SESSION", "MODE", "PROP", "WHISPER", "CHATHISTORY",
    };
    // Phrases that, in a next-step line, would confirm a channel/account/session
    // is absent. The conditional marker is asserted instead of relying only
    // on this blocklist.
    const forbidden = [_][]const u8{
        "does not exist",  "no such channel",   "no such account",
        "no such session", "is not registered", "not registered",
    };
    const marker = "Next step if denied: If ";
    for (denial_topics) |name| {
        const entry = lookup(name) orelse return error.TestUnexpectedResult;
        var next_step: ?[]const u8 = null;
        for (entry.lines) |line| {
            if (std.mem.startsWith(u8, line, marker)) next_step = line;
        }
        const line = next_step orelse {
            std.debug.print("help denial topic {s} lacks a next-step line\n", .{name});
            return error.TestUnexpectedResult;
        };
        try t.expect(line.len <= 200);
        for (forbidden) |phrase| {
            try t.expect(!asciiContainsIgnoreCase(line, phrase));
        }
    }
}
