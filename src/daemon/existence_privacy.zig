// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Existence/privacy leak guard for channel commands (roadmap Q01).
//!
//! Acceptance criterion: permission and privacy failures must not become
//! channel or account existence oracles. A concealed (secret, private, or
//! hidden) channel that the caller cannot see must answer every channel
//! command exactly the way a missing channel answers it at the same call
//! site — normally `403 ERR_NOSUCHCHANNEL "No such channel"` — rather than
//! leaking a more specific numeric (442 ERR_NOTONCHANNEL, 404
//! ERR_CANNOTSENDTOCHAN, 482 ERR_CHANOPRIVSNEEDED, 443 ERR_USERONCHANNEL,
//! a FAIL code such as E2EE_REQUIRED, ...) that only an existing channel
//! would ever produce. Silent success is an oracle too: a concealed channel
//! must not accept external (non-member) speech that a missing name would
//! reject.
//!
//! This module is a pure leaf: no allocation, no I/O, no world/session
//! access, no mutable state. `server.zig` (sole writer:
//! `onyx-server-integrator`) builds `ChannelFacts` from world/session state
//! at each call site and asks this module what to do before it picks a
//! numeric, spends a budget, publishes, or delivers. Keeping the decision
//! here, not inline at ~20 call sites, makes the fail-closed behavior
//! exhaustively testable and keeps every site answering the same way by
//! construction.
//!
//! Canonical concealment predicate mirrored here:
//! `LinuxServer.channelHiddenFromWhois` (src/daemon/server.zig) — secret,
//! private, or hidden, and the caller is not a member. `sees_concealed` and
//! `override_active` are the oper_spy-style and override carve-outs that
//! individual call sites already grant; they default to `false` so an
//! unfilled carve-out fails closed.
//!
//! Gated sites include every command that names a channel the caller may not
//! be on, not only the denial-producing ones: PART, KICK, INVITE,
//! PRIVMSG/NOTICE/TAGMSG, WHISPER, CLEAR, PINS, RENAME, DATA, and the
//! `CREATE <new> <modes> <clone_from>` source. A clone copies the source's
//! modes, key, topic and list masks to a channel the caller then founds, so a
//! success there is both an existence oracle and a state disclosure. The
//! source gate replaces the bare existence test at the same position, so a
//! concealed source and a missing one share one check and one reply order.
//! CREATE grants no visibility carve-out, so both carve-outs stay `false`
//! there.
const std = @import("std");
const numeric_mod = @import("../proto/numeric.zig");

/// The three channel properties that hide a channel from non-members. Every
/// field is required at construction (no defaults) so a call site cannot
/// silently omit one and fail open.
pub const Concealment = struct {
    /// Channel mode +s.
    secret: bool,
    /// Channel mode +p.
    private: bool,
    /// IRCX hidden (+h) channel.
    hidden: bool,

    pub fn any(c: Concealment) bool {
        return c.secret or c.private or c.hidden;
    }
};

/// Caller-computed facts about one channel relative to one connection —
/// exactly enough to decide whether a reply must collapse into the
/// missing-channel case. `exists`, `concealment` and `member` are required;
/// only the privilege carve-outs default, and they default closed.
pub const ChannelFacts = struct {
    /// The channel exists in the world model.
    exists: bool,
    /// Which concealing properties the channel carries.
    concealment: Concealment,
    /// The caller is a member of the channel.
    member: bool,
    /// The caller has oper_spy-style visibility into concealed channels.
    /// Set true only where the call site already extends that carve-out
    /// (e.g. the named-other-subject form of ACCESS EXPLAIN); never merely
    /// because the caller is an operator.
    sees_concealed: bool = false,
    /// The caller acts under an override the call site already honors for
    /// this action (e.g. `overrideActive(conn)` for KICK/DATA,
    /// `hasPriv(.oper_override)` for INVITE, `isOper()` for CLEAR/PINS).
    override_active: bool = false,
};

/// Outcome of the up-front existence/concealment gate.
pub const ChannelGate = enum { proceed, no_such_channel };

/// A structured denial a channel command would otherwise emit to a caller
/// who already has standing to know the channel's state: a member, a
/// carve-out holder, or any caller of a channel that is not concealed.
pub const Denial = enum {
    /// ERR_NOTONCHANNEL (442): the caller is not a member (PART, KICK,
    /// INVITE inviter, WHISPER, RENAME, PINS, ...).
    not_on_channel,
    /// ERR_CANNOTSENDTOCHAN (404): a speech gate rejected the message
    /// (+n/+m/+M/+b/+Z/+c/+C, slowmode, ...).
    cannot_send,
    /// ERR_CHANOPRIVSNEEDED (482): the action needs channel-operator rank.
    chanop_needed,
    /// ERR_USERONCHANNEL (443): the named other party is already on the
    /// channel (INVITE target).
    user_on_channel,

    /// Reference numeric/text for this denial class. Call sites that carry
    /// more specific wording (e.g. "Cannot send to channel (+n)") may keep
    /// their own text as long as it is only reached on the `.specific`
    /// branch of `Outcome` — never for a concealed non-member.
    pub fn defaultReply(self: Denial) Reply {
        return switch (self) {
            .not_on_channel => .{ .code = .ERR_NOTONCHANNEL, .text = "You're not on that channel" },
            .cannot_send => .{ .code = .ERR_CANNOTSENDTOCHAN, .text = "Cannot send to channel" },
            .chanop_needed => .{ .code = .ERR_CHANOPRIVSNEEDED, .text = "You're not channel operator" },
            .user_on_channel => .{ .code = .ERR_USERONCHANNEL, .text = "is already on channel" },
        };
    }

    /// Short, actionable next-step line for this denial class. Carries no
    /// phrase that would confirm or deny that a channel/account/session is
    /// absent (see the forbidden-phrase test, mirroring
    /// src/proto/help_db.zig's existence-oracle blocklist).
    pub fn nextStep(self: Denial) []const u8 {
        return switch (self) {
            .not_on_channel => next_step_not_on_channel,
            .cannot_send => next_step_cannot_send,
            .chanop_needed => next_step_chanop_needed,
            .user_on_channel => next_step_user_on_channel,
        };
    }
};

/// Numeric + text pair for the caller's own numeric builder. Carries no
/// channel/nick parameters: the call site formats those itself from the
/// caller-supplied name, exactly as for a missing channel, so the echoed
/// name is byte-identical in both cases.
pub const Reply = struct {
    code: numeric_mod.Numeric,
    text: []const u8,
};

/// Result of folding a would-be denial through the concealment gate.
pub const Outcome = union(enum) {
    /// The caller may see the channel: send the specific denial.
    specific: Denial,
    /// The caller must not learn the channel exists: send the same reply a
    /// missing channel gets.
    no_such_channel,
};

/// Exact text used at every `ERR_NOSUCHCHANNEL` site this slice touches
/// (grep `"No such channel"` in server.zig).
pub const no_such_channel_text: []const u8 = "No such channel";

/// The canonical "no such channel" reply shared by every collapsed path, so
/// a concealed-non-member denial is byte-identical to a missing channel.
pub const no_such_channel_reply: Reply = .{ .code = .ERR_NOSUCHCHANNEL, .text = no_such_channel_text };

/// Next-step line for the 403 collapse (missing or concealed channel).
/// Deliberately silent on which of the two applies.
pub const next_step_channel_denied: []const u8 = "Check the channel name and your access, then retry";

pub const next_step_not_on_channel: []const u8 = "Join the channel, or ask a member to act for you, then retry";
pub const next_step_cannot_send: []const u8 = "Check the channel's send restrictions and your membership, then retry";
pub const next_step_chanop_needed: []const u8 = "Ask a channel operator to perform this, or gain operator status, then retry";
pub const next_step_user_on_channel: []const u8 = "Pick a different target or action, then retry";

/// Up-front gate for a channel command: `no_such_channel` for a missing
/// channel, or a concealed one the caller cannot see; `proceed` otherwise.
/// Call it before any other channel-state check, budget spend, publication
/// or delivery. A missing channel is never overridden into existing:
/// `exists` short-circuits before any carve-out is consulted.
pub fn gateChannel(f: ChannelFacts) ChannelGate {
    if (!f.exists) return .no_such_channel;
    if (concealedFromCaller(f)) return .no_such_channel;
    return .proceed;
}

/// Fold a would-be structured denial through the same test as
/// `gateChannel`. A concealed channel the caller cannot see answers every
/// denial with the `no_such_channel` outcome a missing channel gets; a
/// member, carve-out holder, or caller of a non-concealed channel keeps the
/// specific denial. `exists = false` also collapses, so a site that skipped
/// the `gateChannel` prologue by mistake fails closed rather than leaking.
pub fn concealNonMemberDenial(f: ChannelFacts, denial: Denial) Outcome {
    if (gateChannel(f) == .no_such_channel) return .no_such_channel;
    return .{ .specific = denial };
}

/// Resolve an `Outcome` to the wire reply it must produce.
pub fn outcomeReply(outcome: Outcome) Reply {
    return switch (outcome) {
        .no_such_channel => no_such_channel_reply,
        .specific => |d| d.defaultReply(),
    };
}

/// Resolve an `Outcome` to its next-step line. The `no_such_channel` branch
/// always uses the generic line: it must not distinguish missing from
/// concealed.
pub fn outcomeNextStep(outcome: Outcome) []const u8 {
    return switch (outcome) {
        .no_such_channel => next_step_channel_denied,
        .specific => |d| d.nextStep(),
    };
}

/// Decision for a channel-targeted speech command (PRIVMSG, NOTICE, TAGMSG).
/// There is deliberately no "null means proceed" encoding: NOTICE to a
/// hidden channel must be dropped, not silently treated as visible.
pub const SendGate = enum {
    /// Channel is visible to the caller: run the usual E2EE/speech gates.
    proceed,
    /// Send `no_such_channel_reply` and stop: no E2EE check, no speech
    /// gate, no history, no event identity, no delivery.
    reply_no_such_channel,
    /// NOTICE to a missing or concealed channel: stop with no reply and no
    /// delivery (NOTICE never emits error replies).
    drop_silently,
};

/// Speech gate evaluated once, before `E2EE_REQUIRED` (itself an oracle) and
/// before any +n/+m/+b/+Z/+c/+C/slowmode check. A non-member without a
/// carve-out never reaches delivery on a concealed channel, even when the
/// channel is -n: accepting that message would answer differently from a
/// missing name and so reveal the channel.
pub fn gateSend(f: ChannelFacts, is_notice: bool) SendGate {
    if (gateChannel(f) == .proceed) return .proceed;
    return if (is_notice) .drop_silently else .reply_no_such_channel;
}

fn concealedFromCaller(f: ChannelFacts) bool {
    if (!f.concealment.any()) return false;
    if (f.member) return false;
    if (f.sees_concealed) return false;
    if (f.override_active) return false;
    return true;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

const all_denials = std.enums.values(Denial);

/// Every concealing combination: each flavor alone plus all mixes.
const concealed_flavors = [_]Concealment{
    .{ .secret = true, .private = false, .hidden = false },
    .{ .secret = false, .private = true, .hidden = false },
    .{ .secret = false, .private = false, .hidden = true },
    .{ .secret = true, .private = true, .hidden = false },
    .{ .secret = true, .private = false, .hidden = true },
    .{ .secret = false, .private = true, .hidden = true },
    .{ .secret = true, .private = true, .hidden = true },
};
const not_concealed: Concealment = .{ .secret = false, .private = false, .hidden = false };

/// Render `<code> <channel> :<text>` — the caller-visible tail of a numeric
/// line after the server prefix and nick, which `queueNumeric` fills
/// identically for both cases.
fn renderTail(buf: []u8, reply: Reply, channel: []const u8) ![]const u8 {
    var code_buf: [3]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s} {s} :{s}", .{ numeric_mod.formatCode(reply.code, &code_buf), channel, reply.text });
}

test "Q01 concealed non-member denial is byte-equivalent to missing channel" {
    const t = std.testing;
    const channel = "#Hideout";
    var missing_buf: [128]u8 = undefined;
    const missing = ChannelFacts{ .exists = false, .concealment = not_concealed, .member = false };
    try t.expectEqual(ChannelGate.no_such_channel, gateChannel(missing));
    const missing_tail = try renderTail(&missing_buf, outcomeReply(concealNonMemberDenial(missing, .not_on_channel)), channel);
    try t.expectEqualStrings("403 #Hideout :No such channel", missing_tail);

    for (concealed_flavors) |flavor| {
        for (all_denials) |denial| {
            errdefer std.debug.print("flavor={any} denial={s}\n", .{ flavor, @tagName(denial) });
            const hostile = ChannelFacts{ .exists = true, .concealment = flavor, .member = false };
            try t.expectEqual(ChannelGate.no_such_channel, gateChannel(hostile));
            const outcome = concealNonMemberDenial(hostile, denial);
            try t.expectEqual(Outcome.no_such_channel, outcome);

            var buf: [128]u8 = undefined;
            const tail = try renderTail(&buf, outcomeReply(outcome), channel);
            try t.expectEqualSlices(u8, missing_tail, tail);
            try t.expectEqualStrings(outcomeNextStep(.no_such_channel), outcomeNextStep(outcome));

            // The specific numeric must actually differ, or this table
            // would pass vacuously.
            var specific_buf: [128]u8 = undefined;
            const specific_tail = try renderTail(&specific_buf, denial.defaultReply(), channel);
            try t.expect(!std.mem.eql(u8, missing_tail, specific_tail));
        }
    }
}

test "Q01 members and public-channel non-members keep specific denial" {
    const t = std.testing;
    for (all_denials) |denial| {
        for (concealed_flavors) |flavor| {
            const member = ChannelFacts{ .exists = true, .concealment = flavor, .member = true };
            try t.expectEqual(ChannelGate.proceed, gateChannel(member));
            const outcome = concealNonMemberDenial(member, denial);
            try t.expectEqual(Outcome{ .specific = denial }, outcome);
            const reply = outcomeReply(outcome);
            const expected = denial.defaultReply();
            try t.expectEqual(expected.code, reply.code);
            try t.expectEqualStrings(expected.text, reply.text);
            try t.expectEqualStrings(denial.nextStep(), outcomeNextStep(outcome));
        }
        // Public-channel membership is already visible (NAMES, WHOIS), so a
        // specific denial there reveals nothing new.
        const public_non_member = ChannelFacts{ .exists = true, .concealment = not_concealed, .member = false };
        try t.expectEqual(ChannelGate.proceed, gateChannel(public_non_member));
        try t.expectEqual(Outcome{ .specific = denial }, concealNonMemberDenial(public_non_member, denial));
    }
}

test "Q01 oper_spy visibility and active override pass the concealment gate" {
    const t = std.testing;
    for (concealed_flavors) |flavor| {
        const spy = ChannelFacts{ .exists = true, .concealment = flavor, .member = false, .sees_concealed = true };
        try t.expectEqual(ChannelGate.proceed, gateChannel(spy));
        try t.expectEqual(Outcome{ .specific = .not_on_channel }, concealNonMemberDenial(spy, .not_on_channel));
        try t.expectEqual(SendGate.proceed, gateSend(spy, false));

        const overridden = ChannelFacts{ .exists = true, .concealment = flavor, .member = false, .override_active = true };
        try t.expectEqual(ChannelGate.proceed, gateChannel(overridden));
        try t.expectEqual(Outcome{ .specific = .cannot_send }, concealNonMemberDenial(overridden, .cannot_send));
        try t.expectEqual(SendGate.proceed, gateSend(overridden, true));

        // A carve-out never fabricates a channel that is not there, and
        // membership claimed for a missing channel is ignored.
        const missing_but_privileged = ChannelFacts{
            .exists = false,
            .concealment = flavor,
            .member = true,
            .sees_concealed = true,
            .override_active = true,
        };
        try t.expectEqual(ChannelGate.no_such_channel, gateChannel(missing_but_privileged));
        for (all_denials) |denial| {
            try t.expectEqual(Outcome.no_such_channel, concealNonMemberDenial(missing_but_privileged, denial));
        }
        try t.expectEqual(SendGate.reply_no_such_channel, gateSend(missing_but_privileged, false));
        try t.expectEqual(SendGate.drop_silently, gateSend(missing_but_privileged, true));
    }
}

test "Q01 next-step strings are short and carry no existence phrase" {
    const t = std.testing;
    // Mirrors the forbidden-phrase list in src/proto/help_db.zig ("help
    // denial topics carry conditional next-step lines without existence
    // oracle"): phrases that would confirm a channel/account/session is
    // absent.
    const forbidden = [_][]const u8{
        "does not exist",  "no such channel",   "no such account",
        "no such session", "is not registered", "not registered",
    };
    var lines: [all_denials.len + 1][]const u8 = undefined;
    lines[0] = next_step_channel_denied;
    for (all_denials, 1..) |denial, i| lines[i] = denial.nextStep();

    for (lines) |line| {
        try t.expect(line.len > 0);
        try t.expect(line.len <= 80);
        try t.expect(std.mem.endsWith(u8, line, "then retry"));
        for (forbidden) |phrase| {
            errdefer std.debug.print("next-step \"{s}\" contains \"{s}\"\n", .{ line, phrase });
            try t.expect(!asciiContainsIgnoreCase(line, phrase));
        }
    }
    // The shared 403 line also must not hint why the name was refused:
    // naming a concealing mode or membership would split missing from
    // concealed.
    const concealment_hints = [_][]const u8{ "secret", "private", "hidden", "member", "invite", "join", "exist" };
    for (concealment_hints) |hint| {
        errdefer std.debug.print("403 next-step hints \"{s}\"\n", .{hint});
        try t.expect(!asciiContainsIgnoreCase(next_step_channel_denied, hint));
    }
}

test "Q01 gateSend rejects PRIVMSG and drops NOTICE to concealed channel without delivery" {
    const t = std.testing;
    for (concealed_flavors) |flavor| {
        // Hostile: a -n concealed channel would otherwise accept external
        // speech, a silent success a missing name never gives.
        const hostile = ChannelFacts{ .exists = true, .concealment = flavor, .member = false };
        try t.expectEqual(SendGate.reply_no_such_channel, gateSend(hostile, false));
        try t.expectEqual(SendGate.drop_silently, gateSend(hostile, true));

        const member = ChannelFacts{ .exists = true, .concealment = flavor, .member = true };
        try t.expectEqual(SendGate.proceed, gateSend(member, false));
        try t.expectEqual(SendGate.proceed, gateSend(member, true));
    }
    const missing = ChannelFacts{ .exists = false, .concealment = not_concealed, .member = false };
    try t.expectEqual(SendGate.reply_no_such_channel, gateSend(missing, false));
    try t.expectEqual(SendGate.drop_silently, gateSend(missing, true));

    const public_channel = ChannelFacts{ .exists = true, .concealment = not_concealed, .member = false };
    try t.expectEqual(SendGate.proceed, gateSend(public_channel, false));
    try t.expectEqual(SendGate.proceed, gateSend(public_channel, true));
}

test "Q01 exhaustive fact table matches independent concealment spec" {
    const t = std.testing;
    var hidden_count: usize = 0;
    var bits: u8 = 0;
    while (bits < (1 << 7)) : (bits += 1) {
        const f = ChannelFacts{
            .exists = bits & 1 != 0,
            .concealment = .{ .secret = bits & 2 != 0, .private = bits & 4 != 0, .hidden = bits & 8 != 0 },
            .member = bits & 16 != 0,
            .sees_concealed = bits & 32 != 0,
            .override_active = bits & 64 != 0,
        };
        errdefer std.debug.print("facts bits=0b{b:0>7}\n", .{bits});
        // Independent spec: visible iff it exists and either nothing hides
        // it or the caller has standing through membership or a carve-out.
        const concealing = (bits & 0b1110) != 0;
        const standing = (bits & 0b111_0000) != 0;
        const visible = (bits & 1 != 0) and (!concealing or standing);
        if (!visible) hidden_count += 1;

        try t.expectEqual(if (visible) ChannelGate.proceed else ChannelGate.no_such_channel, gateChannel(f));
        try t.expectEqual(if (visible) SendGate.proceed else SendGate.reply_no_such_channel, gateSend(f, false));
        try t.expectEqual(if (visible) SendGate.proceed else SendGate.drop_silently, gateSend(f, true));
        for (all_denials) |denial| {
            const outcome = concealNonMemberDenial(f, denial);
            const reply = outcomeReply(outcome);
            if (visible) {
                try t.expectEqual(denial.defaultReply().code, reply.code);
            } else {
                try t.expectEqual(numeric_mod.Numeric.ERR_NOSUCHCHANNEL, reply.code);
                try t.expectEqualStrings(no_such_channel_text, reply.text);
                try t.expectEqualStrings(next_step_channel_denied, outcomeNextStep(outcome));
            }
        }
    }
    // 64 missing rows + 7 concealing flavors with no standing = 71.
    try t.expectEqual(@as(usize, 64 + 7), hidden_count);
}

test "Q01 CREATE clone source concealed from non-member equals missing source" {
    const t = std.testing;
    const missing_source = "#Nope";
    const concealed_source = "#Hideout";
    // Facts as CREATE builds them: no carve-out, even for an operator, since
    // that site grants none.
    const missing = ChannelFacts{ .exists = false, .concealment = not_concealed, .member = false };
    try t.expectEqual(ChannelGate.no_such_channel, gateChannel(missing));

    var missing_buf: [128]u8 = undefined;
    const missing_tail = try renderTail(&missing_buf, no_such_channel_reply, missing_source);
    try t.expectEqualStrings("403 #Nope :No such channel", missing_tail);

    for (concealed_flavors) |flavor| {
        errdefer std.debug.print("clone source flavor={any}\n", .{flavor});
        const non_member = ChannelFacts{ .exists = true, .concealment = flavor, .member = false };
        try t.expectEqual(ChannelGate.no_such_channel, gateChannel(non_member));

        // Apart from the echoed source name, the replies match byte for byte.
        var buf: [128]u8 = undefined;
        const tail = try renderTail(&buf, no_such_channel_reply, concealed_source);
        try t.expectEqualSlices(u8, missing_tail["403 ".len + missing_source.len ..], tail["403 ".len + concealed_source.len ..]);
        try t.expectEqualStrings("403 #Hideout :No such channel", tail);

        // A member of the source may still clone it.
        const member = ChannelFacts{ .exists = true, .concealment = flavor, .member = true };
        try t.expectEqual(ChannelGate.proceed, gateChannel(member));
    }
    // A public source stays cloneable by anyone, as before.
    const public_non_member = ChannelFacts{ .exists = true, .concealment = not_concealed, .member = false };
    try t.expectEqual(ChannelGate.proceed, gateChannel(public_non_member));
}

test "Q01 asciiContainsIgnoreCase matches case-insensitively and handles edges" {
    const t = std.testing;
    try t.expect(asciiContainsIgnoreCase("No Such Channel", "no such channel"));
    try t.expect(asciiContainsIgnoreCase("prefix NOT REGISTERED suffix", "not registered"));
    try t.expect(asciiContainsIgnoreCase("tail match", "MATCH"));
    try t.expect(!asciiContainsIgnoreCase("short", "much longer needle"));
    try t.expect(asciiContainsIgnoreCase("anything", ""));
    try t.expect(asciiContainsIgnoreCase("", ""));
    try t.expect(!asciiContainsIgnoreCase("", "x"));
}
