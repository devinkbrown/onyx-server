// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Permission explanation (roadmap Q04): `ACCESS <#chan> EXPLAIN` request
//! parsing plus the channel SPEAK (PRIVMSG) decision and its redaction.
//!
//! Acceptance criterion: a user or an authorized operator can ask why an
//! action is allowed or denied without leaking unauthorized details.
//!
//! Pure leaf: no allocation, no I/O, no World/session access. `server.zig`
//! (sole writer: `onyx-server-integrator`) samples read-only facts, calls
//! `explainSpeak`, and emits the lines from `formatSpeakLine`. Every gate and
//! every redaction decision lives here so it can be tested exhaustively.
//!
//! The decision mirrors the live send path in `LinuxServer.handleMessage`:
//! `senderSilenced` runs first, then `channelSpeechGate` checks override,
//! +n, +m, +M, +b, +Z, content rules (+c/+C/+T) and finally slowmode/LAG.
//! Content rules depend on the message body, so this module reports them as
//! not evaluated and never as a denial. The E2EE-required room policy also
//! depends on the message, so it is reported the same way.
//!
//! Redaction contract (same as the JOIN explanation):
//!   * Masks, issuers and reasons are shown only for a named other subject,
//!     and only when the requester passes the rule's source read gate.
//!   * Expiry is shown to the subject itself and to source readers. A named
//!     other subject without source read sees `expiry=unknown`.
//!   * Network silence (GAG, quarantine, SHUN) is disclosed only to an
//!     `audit_read` requester. Everyone else gets the constant
//!     `silence=not_disclosed` and a decision computed without silence, so a
//!     stealth SHUN cannot be detected through EXPLAIN.
const std = @import("std");

/// The explained action. JOIN is the legacy default.
pub const Action = enum { join, speak };

pub const Subject = union(enum) {
    /// The requester explains its own permissions.
    self,
    /// A nick supplied by the requester. It may still name the requester.
    named: []const u8,
};

pub const Request = struct {
    channel: []const u8,
    subject: Subject,
    action: Action,

    /// True when the request names someone other than `requester_nick`.
    /// Uses the same ASCII case fold as the legacy handler.
    pub fn namedOther(self: Request, requester_nick: []const u8) bool {
        return switch (self.subject) {
            .self => false,
            .named => |nick| !std.ascii.eqlIgnoreCase(nick, requester_nick),
        };
    }
};

/// Parses `ACCESS` params `[channel, "EXPLAIN", ...]`.
///
///   `#c EXPLAIN`               self, JOIN (legacy)
///   `#c EXPLAIN <nick>`        nick, JOIN (legacy; a nick named SPEAK is a nick)
///   `#c EXPLAIN <nick|*> <JOIN|SPEAK>`  `*` means self
///
/// Anything else is null and must produce the single unavailable reply.
pub fn parseExplainRequest(params: []const []const u8) ?Request {
    if (params.len < 2 or params.len > 4) return null;
    if (!std.ascii.eqlIgnoreCase(params[1], "EXPLAIN")) return null;
    const channel = params[0];
    if (channel.len == 0) return null;
    if (params.len == 2) return .{ .channel = channel, .subject = .self, .action = .join };
    const who = params[2];
    if (who.len == 0) return null;
    if (params.len == 3) return .{ .channel = channel, .subject = .{ .named = who }, .action = .join };
    const action: Action = if (std.ascii.eqlIgnoreCase(params[3], "JOIN"))
        .join
    else if (std.ascii.eqlIgnoreCase(params[3], "SPEAK"))
        .speak
    else
        return null;
    const subject: Subject = if (std.mem.eql(u8, who, "*")) .self else .{ .named = who };
    return .{ .channel = channel, .subject = subject, .action = action };
}

pub const Expiry = union(enum) {
    none_recorded,
    permanent,
    absolute_seconds: u64,
    absolute_millis: i64,
    unknown,
};

/// Source of a matched +b or +Z entry. Present means the subject matched.
/// Every field is optional because the live matcher may only report a bool.
pub const RuleSource = struct {
    mask: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    reason: ?[]const u8 = null,
    expiry: Expiry = .none_recorded,
};

/// Network silence kind, in `senderSilenced` order.
pub const Silence = enum { none, gag, restricted, shun };

/// Previous send timing used by slowmode/LAG.
pub const LastSend = union(enum) {
    /// No recorded send: the live limiter allows.
    none,
    /// Milliseconds since the recorded send.
    elapsed_ms: u64,
    /// Unusable key or clock regression: the live limiter denies.
    unknown,
};

pub const Pacing = struct {
    /// SLOWMODE gap before exemptions.
    slowmode_gap_ms: u64 = 0,
    /// Draft LAG gap; applies to every member.
    lag_gap_ms: u64 = 0,
    /// SLOWVOICE is absent or "1" (voice and ops skip SLOWMODE).
    slowvoice_exempt: bool = true,
    last_send: LastSend = .none,
};

/// Read-only facts about the subject in one channel, sampled by the caller.
pub const SpeakFacts = struct {
    /// `overrideActive(subject)`: +j umode and oper_override privilege.
    override_active: bool = false,
    silence: Silence = .none,
    member: bool = false,
    /// `MemberModes.canSpeakModerated()` (voice or higher).
    can_speak_moderated: bool = false,
    /// `MemberModes.isOperator()`.
    channel_operator: bool = false,
    /// `session.isOper()`.
    network_oper: bool = false,
    has_account: bool = false,
    /// Subject has a nonempty `nick!user@host` prefix (ban checks run only
    /// then in the live gate).
    has_prefix: bool = true,
    no_external: bool = false,
    moderated: bool = false,
    mod_reg: bool = false,
    /// Extended flag +opmoderate: +m/+M/+Z route to ops instead of denying.
    opmoderate: bool = false,
    /// `isBannedCtx` matched (raw; oper exemption is applied here).
    ban: ?RuleSource = null,
    /// `isMutedCtx` matched (raw; voice and oper exemption applied here).
    quiet: ?RuleSource = null,
    nocolor: bool = false,
    no_ctcp: bool = false,
    no_notice: bool = false,
    e2ee_required: bool = false,
    pacing: Pacing = .{},
};

/// What the requester may see.
pub const Viewer = struct {
    /// The subject is not the requester.
    named_other: bool,
    /// The requester passes the matched rule's source read gate.
    source_read: bool = false,
    /// The requester holds `audit_read`.
    audit_read: bool = false,
};

pub const Result = enum { policy_allow, policy_deny, conditional_opmoderate };

pub const Rule = enum {
    allow,
    oper_override,
    silenced,
    no_external,
    moderated,
    registered_only,
    ban,
    quiet,
    slowmode,
    lag,
};

pub const SilenceView = enum { none, gag, restricted, shun, not_disclosed };

pub const ContentRules = packed struct(u8) {
    nocolor: bool = false,
    no_ctcp: bool = false,
    no_notice: bool = false,
    e2ee: bool = false,
    _pad: u4 = 0,

    fn empty(self: ContentRules) bool {
        return !(self.nocolor or self.no_ctcp or self.no_notice or self.e2ee);
    }
};

/// The redacted explanation. Only data the viewer may see is retained.
pub const SpeakView = struct {
    result: Result,
    rule: Rule,
    expiry: Expiry = .none_recorded,
    not_evaluated: ContentRules = .{},
    silence: SilenceView,
    private_details: bool = false,
    mask: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    reason: ?[]const u8 = null,
};

const Decision = struct {
    result: Result,
    rule: Rule,
    source: ?RuleSource = null,
};

fn decideSpeak(facts: SpeakFacts, honor_silence: bool) Decision {
    if (honor_silence and facts.silence != .none) return .{ .result = .policy_deny, .rule = .silenced };
    if (facts.override_active) {
        const bypass = (!facts.member and facts.no_external) or
            (facts.moderated and !facts.can_speak_moderated) or
            (facts.mod_reg and !facts.has_account and !facts.can_speak_moderated) or
            (facts.has_prefix and facts.ban != null) or
            (facts.has_prefix and !facts.can_speak_moderated and facts.quiet != null);
        return .{ .result = .policy_allow, .rule = if (bypass) .oper_override else .allow };
    }
    if (!facts.member and facts.no_external) return .{ .result = .policy_deny, .rule = .no_external };

    var routed: ?Rule = null;
    if (facts.moderated and !facts.can_speak_moderated) {
        if (!facts.opmoderate) return .{ .result = .policy_deny, .rule = .moderated };
        routed = routed orelse .moderated;
    }
    if (facts.mod_reg and !facts.has_account and !facts.can_speak_moderated) {
        if (!facts.opmoderate) return .{ .result = .policy_deny, .rule = .registered_only };
        routed = routed orelse .registered_only;
    }
    var routed_source: ?RuleSource = null;
    if (!facts.network_oper and facts.has_prefix) {
        if (facts.ban) |source| return .{ .result = .policy_deny, .rule = .ban, .source = source };
        if (facts.quiet) |source| {
            if (!facts.can_speak_moderated) {
                if (!facts.opmoderate) return .{ .result = .policy_deny, .rule = .quiet, .source = source };
                if (routed == null) {
                    routed = .quiet;
                    routed_source = source;
                }
            }
        }
    }

    const pacing = facts.pacing;
    const slow_exempt = facts.network_oper or (pacing.slowvoice_exempt and facts.can_speak_moderated);
    const slow = if (slow_exempt) 0 else pacing.slowmode_gap_ms;
    const gap = @max(slow, pacing.lag_gap_ms);
    if (gap != 0) {
        const too_soon = switch (pacing.last_send) {
            .none => false,
            .elapsed_ms => |elapsed| elapsed < gap,
            .unknown => true,
        };
        if (too_soon) return .{ .result = .policy_deny, .rule = if (slow == 0) .lag else .slowmode };
    }

    if (routed) |rule| return .{ .result = .conditional_opmoderate, .rule = rule, .source = routed_source };
    return .{ .result = .policy_allow, .rule = .allow };
}

/// Explains whether the subject may PRIVMSG the channel now, redacted for
/// `viewer`.
pub fn explainSpeak(facts: SpeakFacts, viewer: Viewer) SpeakView {
    const decision = decideSpeak(facts, viewer.audit_read);
    const content_exempt = facts.override_active or facts.channel_operator or facts.network_oper;
    var view: SpeakView = .{
        .result = decision.result,
        .rule = decision.rule,
        .silence = if (viewer.audit_read) switch (facts.silence) {
            .none => .none,
            .gag => .gag,
            .restricted => .restricted,
            .shun => .shun,
        } else .not_disclosed,
        .not_evaluated = .{
            .nocolor = facts.nocolor and !content_exempt,
            .no_ctcp = facts.no_ctcp and !content_exempt,
            .no_notice = facts.no_notice and !content_exempt,
            .e2ee = facts.e2ee_required,
        },
    };
    const source = decision.source orelse return view;
    const private_details = viewer.named_other and viewer.source_read;
    view.expiry = if (!viewer.named_other or private_details) source.expiry else .unknown;
    if (private_details) {
        view.private_details = true;
        view.mask = source.mask;
        view.issuer = source.issuer;
        view.reason = source.reason;
    }
    return view;
}

/// One IRC line, CRLF included.
pub const max_line_bytes = 512;

/// Framing of the NOTICE that carries each explanation line.
pub const Wire = struct {
    server_name: []const u8,
    nick: []const u8,
};

pub const LineKind = enum { summary, context, mask, issuer, reason };

fn fieldSafe(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn tokenSafe(value: []const u8) bool {
    if (value.len == 0 or !fieldSafe(value)) return false;
    return std.mem.indexOfScalar(u8, value, ' ') == null and value[0] != ':';
}

fn expiryText(buf: []u8, expiry: Expiry) []const u8 {
    return switch (expiry) {
        .absolute_seconds => |s| std.fmt.bufPrint(buf, "absolute_unix_seconds:{d}", .{s}) catch unreachable,
        .absolute_millis => |ms| std.fmt.bufPrint(buf, "absolute_store_millis:{d}", .{ms}) catch unreachable,
        else => @tagName(expiry),
    };
}

fn contentText(buf: []u8, rules: ContentRules) []const u8 {
    if (rules.empty()) return "none";
    var len: usize = 0;
    inline for (.{ "nocolor", "no_ctcp", "no_notice", "e2ee" }) |name| {
        if (@field(rules, name)) {
            if (len != 0) {
                buf[len] = ',';
                len += 1;
            }
            @memcpy(buf[len .. len + name.len], name);
            len += name.len;
        }
    }
    return buf[0..len];
}

/// Formats one complete `:<server> NOTICE <nick> :ACCESS EXPLAIN ...\r\n`
/// line into `buf`. Returns null when the line kind has nothing to show,
/// when a detail field is unsafe (control byte) or would not fit, or when
/// the framing itself is unsafe. The returned line never exceeds 512 bytes
/// and never contains a control byte other than the final CRLF.
pub fn formatSpeakLine(buf: *[max_line_bytes]u8, wire: Wire, view: SpeakView, kind: LineKind) ?[]const u8 {
    if (!tokenSafe(wire.server_name) or !tokenSafe(wire.nick)) return null;
    var w: std.Io.Writer = .fixed(buf[0 .. max_line_bytes - 2]);
    w.print(":{s} NOTICE {s} :ACCESS EXPLAIN ", .{ wire.server_name, wire.nick }) catch return null;
    switch (kind) {
        .summary => {
            var expiry_buf: [64]u8 = undefined;
            w.print("action=speak result={s} rule={s} expiry={s} details={s}", .{
                @tagName(view.result),
                @tagName(view.rule),
                expiryText(&expiry_buf, view.expiry),
                if (view.private_details) "authorized" else "redacted",
            }) catch return null;
        },
        .context => {
            var content_buf: [64]u8 = undefined;
            w.print("action=speak not_evaluated={s} silence={s}", .{
                contentText(&content_buf, view.not_evaluated),
                @tagName(view.silence),
            }) catch return null;
        },
        .mask, .issuer, .reason => {
            if (!view.private_details) return null;
            const value = switch (kind) {
                .mask => view.mask,
                .issuer => view.issuer,
                .reason => view.reason,
                else => unreachable,
            } orelse return null;
            if (!fieldSafe(value)) return null;
            w.print("{s}={s}", .{ @tagName(kind), value }) catch return null;
        },
    }
    const len = w.end;
    buf[len] = '\r';
    buf[len + 1] = '\n';
    return buf[0 .. len + 2];
}

const t = std.testing;

test "permission_explain: parse keeps legacy 2/3-param forms and a nick named SPEAK stays a nick" {
    const self_join = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN" }).?;
    try t.expectEqualStrings("#c", self_join.channel);
    try t.expect(self_join.subject == .self);
    try t.expectEqual(Action.join, self_join.action);
    try t.expect(!self_join.namedOther("alice"));

    const named = parseExplainRequest(&[_][]const u8{ "#c", "explain", "bob" }).?;
    try t.expectEqualStrings("bob", named.subject.named);
    try t.expectEqual(Action.join, named.action);
    try t.expect(named.namedOther("alice"));
    try t.expect(!named.namedOther("BOB"));

    const speak_nick = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "SPEAK" }).?;
    try t.expectEqualStrings("SPEAK", speak_nick.subject.named);
    try t.expectEqual(Action.join, speak_nick.action);

    // Legacy 3-param `*` stays a literal nick (unchanged unavailable path).
    const star3 = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*" }).?;
    try t.expectEqualStrings("*", star3.subject.named);
}

test "permission_explain: parse 4-param '*' means self and an unknown action or extra params is unavailable" {
    const self_speak = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*", "speak" }).?;
    try t.expect(self_speak.subject == .self);
    try t.expectEqual(Action.speak, self_speak.action);
    try t.expect(!self_speak.namedOther("alice"));

    const other = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "bob", "SPEAK" }).?;
    try t.expectEqualStrings("bob", other.subject.named);
    try t.expectEqual(Action.speak, other.action);

    const self_join = parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*", "Join" }).?;
    try t.expectEqual(Action.join, self_join.action);

    try t.expect(parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*", "KICK" }) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*", "" }) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "*", "SPEAK", "x" }) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{"#c"}) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{ "#c", "PREVIEW" }) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{ "", "EXPLAIN" }) == null);
    try t.expect(parseExplainRequest(&[_][]const u8{ "#c", "EXPLAIN", "" }) == null);
    try t.expect(parseExplainRequest(&.{}) == null);
}

const self_view: Viewer = .{ .named_other = false };

fn decide(facts: SpeakFacts) Rule {
    return explainSpeak(facts, .{ .named_other = false, .audit_read = true }).rule;
}

test "permission_explain: explainSpeak precedence matches channelSpeechGate order (silenced > override > +n > +m > +M > +b > +Z > slowmode)" {
    const ban: RuleSource = .{};
    var all: SpeakFacts = .{
        .silence = .shun,
        .member = false,
        .no_external = true,
        .moderated = true,
        .mod_reg = true,
        .ban = ban,
        .quiet = ban,
        .pacing = .{ .slowmode_gap_ms = 1000, .last_send = .{ .elapsed_ms = 1 } },
    };
    // Live order: senderSilenced runs before channelSpeechGate, so silence
    // outranks even an active override.
    try t.expectEqual(Rule.silenced, decide(all));
    all.override_active = true;
    try t.expectEqual(Rule.silenced, decide(all));
    all.silence = .none;
    try t.expectEqual(Rule.oper_override, decide(all));
    try t.expectEqual(Result.policy_allow, explainSpeak(all, self_view).result);
    all.override_active = false;
    try t.expectEqual(Rule.no_external, decide(all));
    all.member = true;
    try t.expectEqual(Rule.moderated, decide(all));
    all.moderated = false;
    try t.expectEqual(Rule.registered_only, decide(all));
    all.has_account = true;
    try t.expectEqual(Rule.ban, decide(all));
    all.ban = null;
    try t.expectEqual(Rule.quiet, decide(all));
    all.quiet = null;
    try t.expectEqual(Rule.slowmode, decide(all));
    all.pacing.last_send = .{ .elapsed_ms = 1000 };
    try t.expectEqual(Rule.allow, decide(all));
    try t.expectEqual(Result.policy_allow, explainSpeak(all, self_view).result);

    // Override with nothing to bypass is a plain allow.
    try t.expectEqual(Rule.allow, decide(.{ .override_active = true, .member = true }));
    // Voice clears +m/+M/+Z but never +n or +b.
    try t.expectEqual(Rule.allow, decide(.{ .member = true, .can_speak_moderated = true, .moderated = true, .mod_reg = true, .quiet = .{} }));
    try t.expectEqual(Rule.ban, decide(.{ .member = true, .can_speak_moderated = true, .ban = .{} }));
    try t.expectEqual(Rule.no_external, decide(.{ .can_speak_moderated = true, .no_external = true }));
    // An empty prefix skips ban checks exactly as the live gate does.
    try t.expectEqual(Rule.allow, decide(.{ .member = true, .has_prefix = false, .ban = .{}, .quiet = .{} }));
    // LAG spaces every sender; SLOWMODE only non-exempt ones.
    try t.expectEqual(Rule.lag, decide(.{ .member = true, .network_oper = true, .pacing = .{ .slowmode_gap_ms = 9000, .lag_gap_ms = 500, .last_send = .{ .elapsed_ms = 10 } } }));
    try t.expectEqual(Rule.slowmode, decide(.{ .member = true, .pacing = .{ .slowmode_gap_ms = 9000, .lag_gap_ms = 500, .last_send = .{ .elapsed_ms = 1000 } } }));
    try t.expectEqual(Rule.allow, decide(.{ .member = true, .pacing = .{ .slowmode_gap_ms = 9000, .last_send = .none } }));
    // Unusable key or clock regression denies, like slowmodeTooSoon.
    try t.expectEqual(Rule.slowmode, decide(.{ .member = true, .pacing = .{ .slowmode_gap_ms = 1, .last_send = .unknown } }));
    // SLOWVOICE=0 removes the voice exemption.
    try t.expectEqual(Rule.slowmode, decide(.{ .member = true, .can_speak_moderated = true, .pacing = .{ .slowmode_gap_ms = 50, .slowvoice_exempt = false, .last_send = .{ .elapsed_ms = 0 } } }));
    try t.expectEqual(Rule.allow, decide(.{ .member = true, .can_speak_moderated = true, .pacing = .{ .slowmode_gap_ms = 50, .last_send = .{ .elapsed_ms = 0 } } }));
}

test "permission_explain: opmoderate turns +m/+M/+Z denial into conditional_opmoderate but never +b or +n" {
    const m = explainSpeak(.{ .member = true, .opmoderate = true, .moderated = true }, self_view);
    try t.expectEqual(Result.conditional_opmoderate, m.result);
    try t.expectEqual(Rule.moderated, m.rule);
    const big_m = explainSpeak(.{ .member = true, .opmoderate = true, .mod_reg = true }, self_view);
    try t.expectEqual(Result.conditional_opmoderate, big_m.result);
    try t.expectEqual(Rule.registered_only, big_m.rule);
    const z = explainSpeak(.{ .member = true, .opmoderate = true, .quiet = .{ .expiry = .permanent } }, self_view);
    try t.expectEqual(Result.conditional_opmoderate, z.result);
    try t.expectEqual(Rule.quiet, z.rule);
    try t.expect(z.expiry == .permanent);
    // The first routed gate names the rule.
    const both = explainSpeak(.{ .member = true, .opmoderate = true, .moderated = true, .mod_reg = true, .quiet = .{} }, self_view);
    try t.expectEqual(Rule.moderated, both.rule);

    const b = explainSpeak(.{ .member = true, .opmoderate = true, .moderated = true, .ban = .{} }, self_view);
    try t.expectEqual(Result.policy_deny, b.result);
    try t.expectEqual(Rule.ban, b.rule);
    const n = explainSpeak(.{ .opmoderate = true, .no_external = true, .moderated = true }, self_view);
    try t.expectEqual(Result.policy_deny, n.result);
    try t.expectEqual(Rule.no_external, n.rule);
    // A later slowmode denial beats an earlier opmoderate route.
    const slow = explainSpeak(.{ .member = true, .opmoderate = true, .moderated = true, .pacing = .{ .slowmode_gap_ms = 10, .last_send = .{ .elapsed_ms = 1 } } }, self_view);
    try t.expectEqual(Result.policy_deny, slow.result);
    try t.expectEqual(Rule.slowmode, slow.rule);
}

test "permission_explain: opers are exempt from ban/quiet and slowmode as in the live gate" {
    const oper: SpeakFacts = .{
        .member = true,
        .network_oper = true,
        .ban = .{ .mask = "*!*@x" },
        .quiet = .{},
        .pacing = .{ .slowmode_gap_ms = 5000, .last_send = .{ .elapsed_ms = 1 } },
    };
    const view = explainSpeak(oper, self_view);
    try t.expectEqual(Result.policy_allow, view.result);
    try t.expectEqual(Rule.allow, view.rule);
    // Opers are not exempt from +n, +m or +M without an active override.
    try t.expectEqual(Rule.no_external, decide(.{ .network_oper = true, .no_external = true }));
    try t.expectEqual(Rule.moderated, decide(.{ .member = true, .network_oper = true, .moderated = true }));
    try t.expectEqual(Rule.registered_only, decide(.{ .member = true, .network_oper = true, .mod_reg = true }));
}

test "permission_explain: content rules (+c/+C/+T) are reported not_evaluated, never denied" {
    const facts: SpeakFacts = .{ .member = true, .nocolor = true, .no_ctcp = true, .no_notice = true, .e2ee_required = true };
    const view = explainSpeak(facts, self_view);
    try t.expectEqual(Result.policy_allow, view.result);
    try t.expectEqual(Rule.allow, view.rule);
    try t.expect(view.not_evaluated.nocolor and view.not_evaluated.no_ctcp and view.not_evaluated.no_notice and view.not_evaluated.e2ee);
    // Channel and network operators are exempt from +c/+C/+T, but not E2EE.
    inline for (.{ "channel_operator", "network_oper", "override_active" }) |field| {
        var exempt = facts;
        @field(exempt, field) = true;
        const ev = explainSpeak(exempt, self_view);
        try t.expectEqual(Result.policy_allow, ev.result);
        try t.expect(!ev.not_evaluated.nocolor and !ev.not_evaluated.no_ctcp and !ev.not_evaluated.no_notice);
        try t.expect(ev.not_evaluated.e2ee);
    }
    var buf: [max_line_bytes]u8 = undefined;
    const line = formatSpeakLine(&buf, .{ .server_name = "irc.test", .nick = "alice" }, view, .context).?;
    try t.expectEqualStrings(":irc.test NOTICE alice :ACCESS EXPLAIN action=speak not_evaluated=nocolor,no_ctcp,no_notice,e2ee silence=not_disclosed\r\n", line);
    const none = formatSpeakLine(&buf, .{ .server_name = "irc.test", .nick = "alice" }, explainSpeak(.{ .member = true }, self_view), .context).?;
    try t.expectEqualStrings(":irc.test NOTICE alice :ACCESS EXPLAIN action=speak not_evaluated=none silence=not_disclosed\r\n", none);
}

test "permission_explain: other-subject explanation without source read redacts expiry and masks; self keeps expiry" {
    const source: RuleSource = .{ .mask = "*!*@bad.example", .issuer = "OpAlice", .reason = "spam", .expiry = .{ .absolute_millis = 1_900_000_000_000 } };
    const facts: SpeakFacts = .{ .member = true, .ban = source, .silence = .shun };

    // Self without audit_read: expiry kept, no source fields, silence hidden
    // and the decision computed without it (no stealth-SHUN oracle).
    const self_v = explainSpeak(facts, self_view);
    try t.expectEqual(Rule.ban, self_v.rule);
    try t.expectEqual(@as(i64, 1_900_000_000_000), self_v.expiry.absolute_millis);
    try t.expect(!self_v.private_details);
    try t.expect(self_v.mask == null and self_v.issuer == null and self_v.reason == null);
    try t.expectEqual(SilenceView.not_disclosed, self_v.silence);
    const unsilenced = explainSpeak(.{ .member = true, .ban = source }, self_view);
    try t.expectEqual(self_v.rule, unsilenced.rule);
    try t.expectEqual(self_v.silence, unsilenced.silence);

    // Named other, audit_read but no source read: expiry and source redacted.
    const other = explainSpeak(.{ .member = true, .ban = source }, .{ .named_other = true, .audit_read = true });
    try t.expectEqual(Rule.ban, other.rule);
    try t.expect(other.expiry == .unknown);
    try t.expect(!other.private_details);
    try t.expect(other.mask == null and other.issuer == null and other.reason == null);
    try t.expectEqual(SilenceView.none, other.silence);

    // Named other with source read: everything.
    const full = explainSpeak(.{ .member = true, .ban = source }, .{ .named_other = true, .audit_read = true, .source_read = true });
    try t.expect(full.private_details);
    try t.expectEqualStrings("*!*@bad.example", full.mask.?);
    try t.expectEqualStrings("OpAlice", full.issuer.?);
    try t.expectEqualStrings("spam", full.reason.?);
    try t.expectEqual(@as(i64, 1_900_000_000_000), full.expiry.absolute_millis);

    // Source read never unlocks details for a self query.
    const self_src = explainSpeak(.{ .member = true, .ban = source }, .{ .named_other = false, .source_read = true });
    try t.expect(!self_src.private_details and self_src.mask == null);

    // audit_read discloses silence kind and decides on it.
    const audited = explainSpeak(facts, .{ .named_other = true, .audit_read = true });
    try t.expectEqual(Rule.silenced, audited.rule);
    try t.expectEqual(SilenceView.shun, audited.silence);
    try t.expect(audited.mask == null and audited.expiry == .none_recorded);

    var buf: [max_line_bytes]u8 = undefined;
    const wire: Wire = .{ .server_name = "irc.test", .nick = "op" };
    try t.expectEqualStrings(":irc.test NOTICE op :ACCESS EXPLAIN action=speak result=policy_deny rule=ban expiry=unknown details=redacted\r\n", formatSpeakLine(&buf, wire, other, .summary).?);
    inline for (.{ LineKind.mask, LineKind.issuer, LineKind.reason }) |kind| {
        try t.expect(formatSpeakLine(&buf, wire, other, kind) == null);
        try t.expect(formatSpeakLine(&buf, wire, self_v, kind) == null);
    }
    try t.expectEqualStrings(":irc.test NOTICE op :ACCESS EXPLAIN mask=*!*@bad.example\r\n", formatSpeakLine(&buf, wire, full, .mask).?);
    try t.expectEqualStrings(":irc.test NOTICE op :ACCESS EXPLAIN action=speak result=policy_deny rule=ban expiry=absolute_store_millis:1900000000000 details=authorized\r\n", formatSpeakLine(&buf, wire, full, .summary).?);
}

test "permission_explain: formatSpeakLine drops control-byte fields and fits a 512-byte line with a 255-byte server name" {
    const server: [255]u8 = @splat('s');
    const nick: [64]u8 = @splat('n');
    const wire: Wire = .{ .server_name = &server, .nick = &nick };
    const long: [600]u8 = @splat('m');
    // Widest summary and context tokens.
    const view: SpeakView = .{
        .result = .conditional_opmoderate,
        .rule = .registered_only,
        .expiry = .{ .absolute_millis = std.math.minInt(i64) },
        .not_evaluated = .{ .nocolor = true, .no_ctcp = true, .no_notice = true, .e2ee = true },
        .silence = .not_disclosed,
        .private_details = true,
        .mask = "bad\r\nPRIVMSG #x :pwn",
        .issuer = &long,
        .reason = "fine reason",
    };
    var buf: [max_line_bytes]u8 = undefined;
    for (std.enums.values(LineKind)) |kind| {
        const line = formatSpeakLine(&buf, wire, view, kind) orelse {
            // Unsafe mask and oversized issuer are dropped, never truncated.
            try t.expect(kind == .mask or kind == .issuer);
            continue;
        };
        try t.expect(kind != .mask and kind != .issuer);
        try t.expect(line.len <= max_line_bytes);
        try t.expect(std.mem.endsWith(u8, line, "\r\n"));
        for (line[0 .. line.len - 2]) |byte| try t.expect(byte >= 0x20 and byte != 0x7f);
        try t.expectEqualSlices(u8, &server, line[1 .. 1 + server.len]);
    }
    // A detail that exactly fills the line fits; one more byte is dropped.
    const head = ":" ++ server ++ " NOTICE " ++ nick ++ " :ACCESS EXPLAIN reason=";
    const room = max_line_bytes - 2 - head.len;
    var exact = view;
    exact.reason = long[0..room];
    try t.expectEqual(max_line_bytes, formatSpeakLine(&buf, wire, exact, .reason).?.len);
    exact.reason = long[0 .. room + 1];
    try t.expect(formatSpeakLine(&buf, wire, exact, .reason) == null);
    // DEL is a control byte too.
    exact.reason = "a\x7fb";
    try t.expect(formatSpeakLine(&buf, wire, exact, .reason) == null);
    // Unsafe framing yields nothing at all.
    try t.expect(formatSpeakLine(&buf, .{ .server_name = "irc.test", .nick = "a b" }, view, .summary) == null);
    try t.expect(formatSpeakLine(&buf, .{ .server_name = "irc\r\n", .nick = "a" }, view, .summary) == null);
    try t.expect(formatSpeakLine(&buf, .{ .server_name = "", .nick = "a" }, view, .summary) == null);
    try t.expect(formatSpeakLine(&buf, .{ .server_name = "irc.test", .nick = ":a" }, view, .summary) == null);
}
